"""
Database layer for DHRUVA.
PostgreSQL via psycopg v3 for agent decisions, feedback tracking, and operational metrics.
Schema lifecycle is owned by Alembic — see src/database/migrations/.
"""

import contextlib
import contextvars
import ipaddress
import os
import json
import structlog
import threading
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, asdict

import psycopg
from psycopg import errors as pg_errors
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

_store_logger = structlog.get_logger("store")

# Per-task tenant context — safe for async code (unlike threading.local)
_tenant_ctx: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "_tenant_ctx", default=None
)

# Sentinel value for explicit cross-tenant access (admin, migrations, scheduler)
_CROSS_TENANT = "__CROSS_TENANT__"

# Multi-tenant mode flag — set during startup based on tenant count / license.
# When True, all tenant-scoped paths MUST have a tenant context or fail closed.
_multi_tenant_mode: bool = False


def is_multi_tenant() -> bool:
    """Return True if the platform is running in multi-tenant mode."""
    return _multi_tenant_mode


def set_multi_tenant_mode(enabled: bool):
    """Set multi-tenant mode flag. Called during platform startup."""
    global _multi_tenant_mode
    _multi_tenant_mode = enabled
    _store_logger.info("multi_tenant_mode_set", enabled=enabled)


def _parse_json_obj(raw, default):
    """Defensively parse a value that may be a JSON string, an already-parsed
    object, None, or malformed. Never raises — returns ``default`` on any
    failure. Only dict/list results are accepted; scalars fall back to default.
    """
    if raw is None:
        return default
    if isinstance(raw, (dict, list)):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError, ValueError):
            return default
        if isinstance(parsed, (dict, list)):
            return parsed
    return default


# ---------------------------------------------------------------------------
# Campaign (attack-chain) aggregation helpers — WO-B5
# ---------------------------------------------------------------------------
# Severity ranking shared with the incident engine (src/incidents/engine.py,
# ``sev_order``). Higher rank = worse; used to pick a campaign's worst member.
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Display p-scale + label derived from the incident severity string. The
# backend has NO independent p-scale — this is presentation only, matching the
# Overview mockup (critical=P0 … low=P3).
_SEVERITY_P = {"critical": "P0", "high": "P1", "medium": "P2", "low": "P3"}
_SEVERITY_LABEL = {
    "critical": "Critical", "high": "High", "medium": "Medium", "low": "Low",
}

_OPEN_STATES = frozenset({"open", "investigating"})


def _parse_iso(ts) -> "Optional[datetime]":
    """Parse an ISO timestamp string to an aware UTC datetime. Defensive:
    returns None on null/non-string/malformed input (never raises)."""
    if not ts or not isinstance(ts, str):
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _dedup_preserve(seq: list) -> list:
    """De-duplicate a list preserving first-seen order."""
    seen = []
    for x in seq:
        if x not in seen:
            seen.append(x)
    return seen


def _humanize_seconds(secs: "Optional[int]") -> "Optional[str]":
    """Render a duration in seconds as a compact ``6h 12m`` / ``2d 3h`` string.
    Matches the Overview mockup's dwell labels. None -> None."""
    if secs is None:
        return None
    secs = max(0, int(secs))
    days, rem = divmod(secs, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def build_campaigns_from_incident_rows(rows: list, now: datetime) -> list:
    """Group incident rows (each a dict) sharing an ``attack_chain_id`` into
    campaign dicts. Pure + fully defensive — never raises on malformed JSON
    columns or bad timestamps.

    ``now`` is an aware datetime used to compute dwell (passed in by the
    caller / route — this function does NOT read the clock itself).

    NULL/empty ``attack_chain_id`` rows are ignored here (the SQL already
    excludes them; this is a belt-and-suspenders guard). Standalone incidents
    are NOT campaigns — see the WO-B5 null-chain decision in campaigns.py.

    Canonical kill-chain tactic ordering is REUSED from src/mitre/matrix.py
    (``MITRE_TACTICS`` / ``order_tactics`` / ``tactic_index``) — the same
    ordering the M5 engine uses — not a second copy.
    """
    from src.mitre.matrix import order_tactics, tactic_index, MITRE_TACTICS

    groups: dict = {}
    for r in rows:
        chain_id = r.get("attack_chain_id")
        if not chain_id:
            continue
        groups.setdefault(chain_id, []).append(r)

    campaigns = []
    for chain_id, members in groups.items():
        # Worst (max) severity across members.
        worst = max(
            (m.get("severity") or "low" for m in members),
            key=lambda s: _SEVERITY_RANK.get(s, 0),
        )

        # Status rollup: "active" if any member is open/investigating, else
        # "contained".
        any_open = any((m.get("status") or "") in _OPEN_STATES for m in members)
        status = "active" if any_open else "contained"

        # Tactic sequence: union of members' ordered attack_chain_tactics,
        # de-duped and re-sorted by canonical kill-chain order.
        all_tactics = []
        for m in members:
            all_tactics.extend(_parse_json_obj(m.get("attack_chain_tactics"), []))
        tactic_sequence = order_tactics(all_tactics)
        furthest_tactic = tactic_sequence[-1] if tactic_sequence else None

        # Heuristic projection ONLY (PM decision #4): next unseen tactic in
        # canonical order after the furthest reached. Clearly labelled — never
        # observed/actioned.
        projected_next = None
        if furthest_tactic is not None:
            idx = tactic_index(furthest_tactic)
            if idx is not None and idx + 1 < len(MITRE_TACTICS):
                projected_next = MITRE_TACTICS[idx + 1]

        # Assets: union across members (order-preserving de-dup).
        hosts, users, ips = [], [], []
        for m in members:
            hosts.extend(_parse_json_obj(m.get("affected_hosts"), []))
            users.extend(_parse_json_obj(m.get("affected_users"), []))
            ips.extend(_parse_json_obj(m.get("affected_ips"), []))
        hosts, users, ips = (
            _dedup_preserve(hosts), _dedup_preserve(users), _dedup_preserve(ips),
        )

        alert_count = sum(int(m.get("alert_count") or 0) for m in members)

        first_seens = [d for d in (_parse_iso(m.get("first_seen")) for m in members)
                       if d is not None]
        last_seens = [d for d in (_parse_iso(m.get("last_seen")) for m in members)
                      if d is not None]
        earliest = min(first_seens) if first_seens else None
        latest = max(last_seens) if last_seens else None
        dwell_seconds = None
        if earliest is not None and now is not None:
            dwell_seconds = max(0, int((now - earliest).total_seconds()))

        # Member list ordered by first_seen ascending (kill-chain order); rows
        # with an unparseable first_seen sort last but are still included.
        def _fs_key(m):
            d = _parse_iso(m.get("first_seen"))
            return (d is None, d or now)

        member_incidents = [
            {
                "id": m.get("id"),
                "title": m.get("title"),
                "severity": m.get("severity"),
                "status": m.get("status"),
                "first_seen": m.get("first_seen"),
                "last_seen": m.get("last_seen"),
                "alert_count": int(m.get("alert_count") or 0),
            }
            for m in sorted(members, key=_fs_key)
        ]

        # Display name: highest-severity member, tie-broken by earliest
        # first_seen (falls back to the raw title).
        def _name_key(m):
            d = _parse_iso(m.get("first_seen"))
            # worst severity first; among equals, earliest first_seen first.
            return (_SEVERITY_RANK.get(m.get("severity"), 0),
                    -(d.timestamp() if d else 0.0))

        name_member = max(members, key=_name_key)
        name = name_member.get("title") or f"Campaign {chain_id}"

        campaigns.append({
            "attack_chain_id": chain_id,
            "name": name,
            "title": name,
            "severity": worst,
            "severity_rank": _SEVERITY_RANK.get(worst, 0),
            "p": _SEVERITY_P.get(worst),
            "severity_label": _SEVERITY_LABEL.get(worst),
            "status": status,
            "member_count": len(members),
            "member_incidents": member_incidents,
            "tactic_sequence": tactic_sequence,
            "furthest_tactic": furthest_tactic,
            "projected_next_tactic": projected_next,
            "projection_basis": "kill_chain_order_heuristic",
            "assets": {"hosts": hosts, "users": users, "ips": ips},
            "alert_count": alert_count,
            "first_seen": earliest.isoformat() if earliest else None,
            "last_seen": latest.isoformat() if latest else None,
            "dwell_seconds": dwell_seconds,
            "dwell": _humanize_seconds(dwell_seconds),
        })

    # Worst severity first, then longest dwell first — matches the mockup's
    # "2 advancing · 1 contained" worst-first campaign map ordering.
    campaigns.sort(
        key=lambda c: (c["severity_rank"], c.get("dwell_seconds") or 0),
        reverse=True,
    )
    return campaigns


def parse_glass_box(trail: dict) -> dict:
    """Build the WO-B4 ``glass_box`` view from a decision audit-trail row.

    Surfaces the risk-score math (``risk_breakdown`` as a parsed object) and
    provenance (playbook version, guidance hash, model backend, latency) so the
    Incident/decision case view doesn't have to stitch the audit trail together
    itself. Pure + defensive: a null/empty/malformed trail yields the stable
    default shape (``risk_breakdown={}`` and all-null provenance) and never
    raises. Model/latency are read from the stored ``model_backend`` /
    ``latency_ms`` columns (both are persisted at triage time); they are null
    only when the trail predates them or is absent.
    """
    # Guard the full contract: any non-dict trail (None, scalar, list) yields
    # the default shape, so this truly never raises for any caller input.
    if not isinstance(trail, dict):
        trail = {}
    return {
        "risk_breakdown": _parse_json_obj(trail.get("risk_breakdown"), {}),
        "provenance": {
            "playbook_version": trail.get("playbook_name"),
            "guidance_hash": _parse_json_obj(trail.get("guidance_version"), None),
            "model": trail.get("model_backend"),
            "latency_ms": trail.get("latency_ms"),
        },
    }


# WO-B9: identity field CATEGORIES the AlertAnonymizer tokenizes before every
# LLM call → their display labels. Kept in sync with AlertAnonymizer's three
# tokenized categories (hostnames, internal IPs, usernames). Stable order for
# the UI. Deliberately field-level ONLY — this module never carries token
# strings, the token↔real map, or raw client identifiers.
_ANON_FIELD_LABELS = [
    ("host", "Host"),
    ("internal_ip", "Internal IP"),
    ("user", "User"),
]

# Usernames the anonymizer treats as non-identifying (never tokenized) — mirror
# AlertAnonymizer's skip list so the derived view agrees with what was sent.
_NON_IDENTIFYING_USERS = {"N/A", "", "SYSTEM", "LOCAL SERVICE"}


def _is_internal_ip_default(ip_str) -> bool:
    """Best-effort check that an IP is in a private/internal range, mirroring
    AlertAnonymizer's DEFAULT internal networks (RFC1918 + loopback +
    link-local, v4 and v6 — the ranges the anonymizer anonymizes; external /
    attacker IPs are preserved and return False).

    Pure + defensive: never raises; unparseable or external addresses return
    False. Custom ``anonymization.internal_ip_ranges`` from tenant config are
    NOT consulted here — this only knows the defaults, so a non-default internal
    range is under-counted (never leaked).
    """
    try:
        addr = ipaddress.ip_address(str(ip_str))
    except (ValueError, TypeError):
        return False
    return bool(addr.is_private or addr.is_loopback or addr.is_link_local)


def anonymized_fields_for(decision: dict) -> list[dict]:
    """WO-B9: return WHICH identity field CATEGORIES were anonymized before this
    decision's alert was sent to the LLM — **field-level ONLY**.

    Backs the Incident case-view "what the AI saw vs what you see" panel
    (WO-U4). The return value NEVER contains token strings (e.g. HOST-…,
    INT-IP-…, USER-…), the token↔real mapping, or raw client identifiers
    (hostnames, IPs, usernames) — only the category ``field`` + human ``label``.

    Categories are the three the AlertAnonymizer tokenizes:
      * ``host``        — the alert's hostname (``agent_name``).
      * ``internal_ip`` — ``src_ip`` when it is an INTERNAL/private address
                          (external/attacker IPs are preserved, not anonymized,
                          so they are NOT reported here).
      * ``user``        — ``src_user`` / ``dst_user`` when a real username
                          (anonymizer's non-identifying skips excluded).

    A category is reported only when it is actually PRESENT on the decision
    (parsed defensively from top-level flattened fields and/or the
    ``enrichment_summary`` JSON blob). Per-field enable flags in the anonymizer
    config are not cheaply knowable here, so they are treated as enabled
    (the anonymizer default). Pure + defensive: any bad input yields ``[]``.
    """
    if not isinstance(decision, dict):
        return []

    enr = _parse_json_obj(decision.get("enrichment_summary"), {})
    if not isinstance(enr, dict):
        enr = {}

    def _first(*keys):
        """First non-empty value for any of ``keys``, checking the flattened
        top-level decision fields before the parsed enrichment blob."""
        for src in (decision, enr):
            for k in keys:
                v = src.get(k)
                if v not in (None, ""):
                    return v
        return None

    present: set = set()

    # -- Host (hostname) --
    if _first("host", "agent_name"):
        present.add("host")

    # -- Internal IP (external/attacker IPs are preserved, never anonymized) --
    src_ip = _first("src_ip")
    if src_ip is not None and _is_internal_ip_default(src_ip):
        present.add("internal_ip")

    # -- Username (any real src_user/dst_user across either source) --
    user_vals = []
    for k in ("src_user", "dst_user"):
        for src in (decision, enr):
            v = src.get(k)
            if v not in (None, ""):
                user_vals.append(str(v))
    if any(v not in _NON_IDENTIFYING_USERS for v in user_vals):
        present.add("user")

    # Emit ONLY the constant field/label pairs — never a value from `decision`.
    return [{"field": f, "label": lbl}
            for f, lbl in _ANON_FIELD_LABELS if f in present]


class TenantContextRequired(PermissionError):
    """Raised when a tenant-scoped query runs without tenant context."""
    pass

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class AgentDecision:
    id: str
    alert_id: str
    rule_id: int
    rule_description: str
    agent_type: str          # "triage", "detection", "hunt"
    verdict: str             # "true_positive", "false_positive", "needs_investigation", "auto_close"
    confidence: float
    risk_score: float
    reasoning: str
    enrichment_summary: str
    playbook_used: Optional[str]
    actions_taken: str       # JSON list
    escalated: bool
    human_override: Optional[str]   # null until human reviews
    human_verdict: Optional[str]
    feedback_applied: bool
    created_at: str
    resolved_at: Optional[str]
    client_id: Optional[str]
    # AIS2: evidence-derived grounding assessment (JSON blob) — independent of
    # the model's self-reported confidence. Nullable/defaulted for backward
    # compatibility with historical rows and non-triage callers.
    grounding: Optional[str] = None

@dataclass
class DetectionProposal:
    id: str
    rule_id: int
    rule_file: str
    change_type: str         # "tune", "disable", "new_rule", "modify"
    original_xml: str
    proposed_xml: str
    reasoning: str
    fp_count_trigger: int
    fp_window_days: int
    status: str              # "proposed", "approved", "rejected", "deployed"
    proposed_at: str
    reviewed_by: Optional[str]
    reviewed_at: Optional[str]

@dataclass
class FeedbackPattern:
    id: str
    pattern_type: str        # "recurring_fp", "missed_tp", "noise_source"
    rule_id: int
    description: str
    occurrence_count: int
    first_seen: str
    last_seen: str
    auto_action_taken: Optional[str]
    status: str              # "active", "resolved", "tuned"

@dataclass
class RuleTuningOverride:
    id: str
    rule_id: int
    action_type: str         # "auto_tuned", "threshold_raised", "baselined", "monitoring"
    confidence_override: Optional[float]  # per-rule auto-close threshold override
    fp_pattern_signature: Optional[str]   # JSON: learned FP pattern for baseline matching
    reason: str
    created_at: str
    expires_at: Optional[str]

@dataclass
class Incident:
    id: str
    title: str
    severity: str            # "low", "medium", "high", "critical"
    status: str              # "open", "investigating", "resolved", "closed"
    grouping_key: str
    alert_count: int
    first_seen: str
    last_seen: str
    assigned_to: Optional[str]
    created_at: str
    updated_at: str
    resolved_at: Optional[str]
    summary: str
    mitre_tactics: str       # JSON list
    mitre_techniques: str    # JSON list
    affected_hosts: str      # JSON list
    affected_users: str      # JSON list
    affected_ips: str        # JSON list
    client_id: Optional[str]
    attack_chain_id: Optional[str] = None       # M5: links incidents in a chain
    attack_chain_tactics: str = "[]"            # M5: ordered JSON kill-chain list

@dataclass
class IncidentAlert:
    incident_id: str
    decision_id: str
    added_at: str

@dataclass
class IncidentTimeline:
    id: str
    incident_id: str
    event_type: str          # "alert_added", "status_changed", "assigned", "note_added", "escalated"
    description: str
    actor: str               # "system" or username
    created_at: str

@dataclass
class PlatformUser:
    id: str
    username: str
    password_hash: str
    salt: str
    display_name: str
    email: str
    role: str                # "admin", "senior_analyst", "analyst", "read_only"
    is_active: int           # 1=active, 0=deactivated
    created_at: str
    updated_at: str

@dataclass
class AuditLogEntry:
    id: str
    actor: str
    action: str              # "login", "review", "assign", "status_change", etc.
    target_type: str         # "decision", "incident", "proposal", "user", "system"
    target_id: str
    details: str             # JSON
    ip_address: str
    created_at: str

@dataclass
class OperationalMetric:
    id: str
    metric_name: str
    metric_value: float
    dimensions: str          # JSON dict: {"client_id": "x", "rule_group": "y"}
    recorded_at: str


# ---------------------------------------------------------------------------
# Database Store
# ---------------------------------------------------------------------------

class SOCDatabase:
    # Tables that must be scoped by client_id in all queries
    TENANT_SCOPED_TABLES = frozenset({
        "agent_decisions", "incidents", "detection_proposals",
        "feedback_patterns", "behavioral_baselines", "rule_tuning_overrides",
        "hunt_findings", "operational_metrics", "soar_executions",
        "mitre_coverage", "audit_log", "anon_mappings",
        "decision_audit_trail", "sla_breaches", "alert_enrichment_cache",
        "processed_alerts", "tickets", "ticket_sync_log",
        "kb_documents",
        "post_incident_reviews", "hunt_hypothesis_library",
        "shift_handoffs", "compliance_mappings", "llm_usage_metrics",
        "buffered_alerts",
        "assets", "identities", "local_iocs",
    })

    # Tables scoped via FK join to a scoped parent (no direct client_id filter)
    FK_SCOPED_TABLES = frozenset({"incident_alerts", "incident_timeline"})

    # Tables that are intentionally shared across tenants
    SHARED_TABLES = frozenset({
        "tenants", "platform_users", "schema_migrations", "revoked_tokens",
        "threat_intel_iocs", "threat_intel_cve", "threat_intel_feeds",
        "soar_playbooks",  # NULL client_id = shared default
    })

    def __init__(self, dsn_or_path: str | None = None, *, pool_size: int = 20):
        """Open a connection pool to Postgres.

        DSN resolution order:
          1) ``DATABASE_URL`` env var (always wins if set).
          2) The positional argument, if it looks like a libpq URI.
          3) Hard fail with a v4.9.0 cutover pointer — SQLite is gone.

        ``dsn_or_path`` is kept as a loose first arg so existing callers don't
        break at import time before Phase 4 threads a ``database.dsn`` config
        field through. Operators on Phase 2 must export ``DATABASE_URL``.
        """
        self.dsn = self._resolve_dsn(dsn_or_path)
        # ``db_path`` retained for backwards-compat with code that logs it.
        self.db_path = self.dsn
        self._local = threading.local()  # per-thread cached connection
        # min_size=2 keeps the platform responsive on a cold path; max_size
        # caps connection fan-out so a thread storm can't exhaust Postgres
        # max_connections (default 100). The per-thread caching layer means
        # we usually hold one conn per worker thread, well under the cap.
        self._pool = ConnectionPool(
            conninfo=self.dsn,
            min_size=2,
            max_size=pool_size,
            kwargs={"row_factory": dict_row, "autocommit": False},
            open=True,
        )
        self._verify_schema()

    @staticmethod
    def _iso_ago(*, days: float = 0, hours: float = 0, minutes: float = 0) -> str:
        """Return an ISO timestamp ``days/hours/minutes`` ago in UTC.

        Replaces SQLite's ``datetime('now', '-N days')`` modifier — Postgres
        doesn't have an equivalent that mixes well with bound parameters, so
        we compute the cutoff in Python and bind a plain timestamp.
        """
        delta = timedelta(days=days, hours=hours, minutes=minutes)
        return (datetime.now(timezone.utc) - delta).isoformat()

    @staticmethod
    def _resolve_dsn(provided: str | None) -> str:
        env_dsn = os.environ.get("DATABASE_URL")
        candidate = env_dsn or provided
        if not candidate:
            raise RuntimeError(
                "No Postgres DSN configured. Set DATABASE_URL or pass a "
                "libpq URI. SQLite was retired in v4.9.0 — see "
                "docs/MIGRATION-FROM-SQLITE.md."
            )
        if not candidate.startswith(("postgres://", "postgresql://", "postgresql+psycopg://")):
            raise RuntimeError(
                f"Refusing to start SOCDatabase with non-Postgres DSN {candidate!r}. "
                "SQLite was retired in v4.9.0 — set DATABASE_URL to a "
                "postgresql:// URI. See docs/MIGRATION-FROM-SQLITE.md."
            )
        # psycopg accepts the plain libpq form; strip the SQLAlchemy +psycopg suffix.
        if candidate.startswith("postgresql+psycopg://"):
            candidate = "postgresql://" + candidate[len("postgresql+psycopg://"):]
        return candidate

    def _verify_schema(self):
        """Refuse to start if Alembic hasn't been run.

        Alembic owns the schema in v4.9.0 — operators must run
        ``alembic upgrade head`` (wired into install.sh in Phase 5) before
        SOCDatabase will open. Failing closed here is intentional: an empty
        database silently accepting INSERTs has bitten us before.
        """
        try:
            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT version_num FROM alembic_version")
                    row = cur.fetchone()
                    if not row:
                        raise RuntimeError(
                            "alembic_version table is empty — run "
                            "`alembic upgrade head` before starting Dhruva."
                        )
                    _store_logger.info("schema_verified", version=row["version_num"])
        except pg_errors.UndefinedTable as e:
            raise RuntimeError(
                "alembic_version table missing — run `alembic upgrade head` "
                "from the repo root before starting Dhruva. See "
                "docs/MIGRATION-FROM-SQLITE.md."
            ) from e

    def set_tenant(self, tenant_id: str):
        """Set the active tenant for query scoping. Called by middleware.
        Uses contextvars for proper async isolation."""
        _tenant_ctx.set(tenant_id)

    def get_tenant_id(self) -> str:
        """Get the current tenant ID."""
        return _tenant_ctx.get()

    def _tenant_filter(self) -> tuple:
        """Return (sql_fragment, params) for tenant scoping.

        Fail-closed: raises TenantContextRequired when no context is set.
        Use cross_tenant() context manager for legitimate global operations.
        """
        tenant_id = _tenant_ctx.get()
        if tenant_id == _CROSS_TENANT:
            return "", []
        if not tenant_id:
            raise TenantContextRequired(
                "Tenant context not set — refusing unscoped query. "
                "Use db.set_tenant() or db.cross_tenant() first."
            )
        return " AND client_id = %s", [tenant_id]

    def _tenant_value(self) -> str:
        """Return current tenant_id for INSERT statements."""
        val = _tenant_ctx.get()
        return None if val == _CROSS_TENANT else val

    @contextlib.contextmanager
    def cross_tenant(self):
        """Context manager for legitimate cross-tenant operations.

        Usage:
            with self.db.cross_tenant():
                rows = self.db.get_all_incidents()  # returns ALL tenants
        """
        token = _tenant_ctx.set(_CROSS_TENANT)
        try:
            yield
        finally:
            _tenant_ctx.reset(token)

    def _get_conn(self) -> psycopg.Connection:
        """Return a per-thread cached psycopg connection drawn from the pool.

        psycopg connections are not thread-safe, so each thread holds its own
        long-lived pooled conn. The pool gates max fan-out and gives us liveness
        checks; the per-thread cache avoids getconn/putconn round-trips on every
        query.
        """
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                return conn
            except pg_errors.InFailedSqlTransaction:
                # The conn is alive on the server side but a prior query
                # raised mid-transaction without a rollback, so PG is
                # rejecting every subsequent command. Roll back, re-probe,
                # and reuse the same conn if it now works. Falls through
                # to the fresh-conn path if rollback itself fails.
                #
                # Surfaced on the first real-deployment smoke (v4.9.0,
                # 2026-06-01): an alert-loop query crashed without a
                # rollback, leaving the per-thread cached conn poisoned
                # forever — every dashboard request then 500'd with
                # "current transaction is aborted, commands ignored…".
                try:
                    conn.rollback()
                    with conn.cursor() as cur:
                        cur.execute("SELECT 1")
                    return conn
                except Exception:
                    pass
                try:
                    self._pool.putconn(conn)
                except Exception:
                    pass
                self._local.conn = None
            except (pg_errors.OperationalError, pg_errors.InterfaceError):
                # Connection died (server restart, network blip). Drop it and
                # let the pool hand us a fresh one below.
                try:
                    self._pool.putconn(conn)
                except Exception:
                    pass
                self._local.conn = None
        conn = self._pool.getconn()
        self._local.conn = conn
        return conn


    def get_schema_version(self) -> str:
        """Return the current Alembic revision, or '' if unset.

        Alembic owns the schema in v4.9.0+; the historical integer-keyed
        ``schema_migrations`` table is gone. Callers expecting an int should
        be updated as they're touched.
        """
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT version_num FROM alembic_version")
                row = cur.fetchone()
                return row["version_num"] if row else ""
        except Exception:
            return ""

    # -- Agent Decisions --
    
    def save_decision(self, decision: AgentDecision) -> str:
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO agent_decisions
            (id, alert_id, rule_id, rule_description, agent_type, verdict,
             confidence, risk_score, reasoning, enrichment_summary, playbook_used,
             actions_taken, escalated, human_override, human_verdict,
             feedback_applied, created_at, resolved_at, client_id, grounding)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET
                alert_id          = EXCLUDED.alert_id,
                rule_id           = EXCLUDED.rule_id,
                rule_description  = EXCLUDED.rule_description,
                agent_type        = EXCLUDED.agent_type,
                verdict           = EXCLUDED.verdict,
                confidence        = EXCLUDED.confidence,
                risk_score        = EXCLUDED.risk_score,
                reasoning         = EXCLUDED.reasoning,
                enrichment_summary= EXCLUDED.enrichment_summary,
                playbook_used     = EXCLUDED.playbook_used,
                actions_taken     = EXCLUDED.actions_taken,
                escalated         = EXCLUDED.escalated,
                human_override    = EXCLUDED.human_override,
                human_verdict     = EXCLUDED.human_verdict,
                feedback_applied  = EXCLUDED.feedback_applied,
                created_at        = EXCLUDED.created_at,
                resolved_at       = EXCLUDED.resolved_at,
                client_id         = EXCLUDED.client_id,
                grounding         = EXCLUDED.grounding
        """, (
            decision.id, decision.alert_id, decision.rule_id,
            decision.rule_description, decision.agent_type, decision.verdict,
            decision.confidence, decision.risk_score, decision.reasoning,
            decision.enrichment_summary, decision.playbook_used,
            decision.actions_taken, int(decision.escalated),
            decision.human_override, decision.human_verdict,
            int(decision.feedback_applied), decision.created_at,
            decision.resolved_at,
            # Tenant safety net: fall back to the current tenant context if the
            # decision carries no client_id, so a decision is never saved with a
            # NULL tenant (which would make it invisible to every tenant query).
            # Matches save_proposal + the other insert methods. Fail-closed:
            # _tenant_value() returns None only under cross_tenant().
            decision.client_id or self._tenant_value(),
            # AIS2 grounding assessment JSON (nullable for non-triage/legacy).
            getattr(decision, "grounding", None),
        ))
        conn.commit()

        return decision.id

    def save_decision_audit_trail(self, trail: dict) -> str:
        """Save an AI decision audit trail record."""
        conn = self._get_conn()
        trail_id = trail.get("id", str(__import__("uuid").uuid4()))
        try:
            conn.execute("""
                INSERT INTO decision_audit_trail
                (id, decision_id, prompt_version, guidance_version,
                 playbook_name, risk_breakdown, enrichment_inputs,
                 model_backend, latency_ms, created_at, client_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    decision_id       = EXCLUDED.decision_id,
                    prompt_version    = EXCLUDED.prompt_version,
                    guidance_version  = EXCLUDED.guidance_version,
                    playbook_name     = EXCLUDED.playbook_name,
                    risk_breakdown    = EXCLUDED.risk_breakdown,
                    enrichment_inputs = EXCLUDED.enrichment_inputs,
                    model_backend     = EXCLUDED.model_backend,
                    latency_ms        = EXCLUDED.latency_ms,
                    created_at        = EXCLUDED.created_at,
                    client_id         = EXCLUDED.client_id
            """, (
                trail_id,
                trail["decision_id"],
                trail.get("prompt_version", "unknown"),
                trail.get("guidance_version", "{}"),
                trail.get("playbook_name"),
                trail.get("risk_breakdown", "{}"),
                trail.get("enrichment_inputs", "{}"),
                trail.get("model_backend"),
                trail.get("latency_ms"),
                trail.get("created_at", __import__("datetime").datetime.now(
                    __import__("datetime").timezone.utc).isoformat()),
                trail.get("client_id") or self._tenant_value(),
            ))
            conn.commit()
        except Exception as e:
            # Table may not exist yet on older schemas — don't crash triage
            structlog.get_logger(__name__).warning(
                "audit_trail_save_failed", error=str(e))
        return trail_id

    def get_decision(self, decision_id: str) -> Optional[dict]:
        """Fetch a single agent decision by id, TENANT-SCOPED.

        Returns ``None`` when the decision does not exist OR belongs to another
        tenant (the ``_tenant_filter()`` clause makes cross-tenant reads a
        no-match, never a leak). Used by the WO-B10 override check to read the
        existing ``human_verdict`` before applying a review.
        """
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        row = conn.execute(
            f"SELECT * FROM agent_decisions WHERE id = %s {tf}",
            [decision_id] + tp,
        ).fetchone()
        return dict(row) if row else None

    def get_decision_audit_trail(self, decision_id: str) -> dict:
        """Get the audit trail for a specific decision."""
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            row = conn.execute(
                f"SELECT * FROM decision_audit_trail WHERE decision_id = %s {tf}",
                [decision_id] + tp
            ).fetchone()
            if row:
                return dict(row)
        except Exception:
            pass
        return {}

    def get_decision_glass_box(self, decision_id: str) -> dict:
        """Return the parsed WO-B4 ``glass_box`` (risk_breakdown + provenance)
        for a decision, reusing the tenant-scoped audit-trail read.

        Always returns the stable default shape even when no audit trail exists
        for the decision (older rows), so callers get a consistent object.
        """
        return parse_glass_box(self.get_decision_audit_trail(decision_id))

    def get_decisions_by_rule(self, rule_id: int, days: int = 7,
                              verdict: Optional[str] = None) -> list[dict]:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        query = """
            SELECT * FROM agent_decisions
            WHERE rule_id = %s
            AND created_at >= %s
        """
        params = [rule_id, self._iso_ago(days=days)]
        if tf:
            query += tf
            params.extend(tp)
        if verdict:
            query += " AND verdict = %s"
            params.append(verdict)
        query += " ORDER BY created_at DESC"
        rows = conn.execute(query, params).fetchall()

        return [dict(r) for r in rows]

    def get_fp_rate_for_rule(self, rule_id: int, days: int = 7) -> dict:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        row = conn.execute(f"""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN verdict = 'false_positive' THEN 1 ELSE 0 END) as fp_count,
                SUM(CASE WHEN verdict = 'true_positive' THEN 1 ELSE 0 END) as tp_count,
                SUM(CASE WHEN verdict = 'auto_close' THEN 1 ELSE 0 END) as auto_closed,
                AVG(confidence) as avg_confidence
            FROM agent_decisions
            WHERE rule_id = %s AND created_at >= %s {tf}
        """, [rule_id, self._iso_ago(days=days)] + tp).fetchone()

        total = row['total'] or 0
        return {
            'rule_id': rule_id,
            'total': total,
            'fp_count': row['fp_count'] or 0,
            'tp_count': row['tp_count'] or 0,
            'auto_closed': row['auto_closed'] or 0,
            'fp_rate': (row['fp_count'] or 0) / total if total > 0 else 0,
            'avg_confidence': row['avg_confidence'] or 0
        }

    # Whitelist of allowed orderings → fixed ORDER BY clauses. Caller input is
    # only ever used to look up a key here; it is NEVER interpolated into SQL.
    _DECISION_ORDER_CLAUSES = {
        "recent": "created_at DESC",
        "risk": "risk_score DESC NULLS LAST, created_at DESC",
    }

    def get_recent_decisions(self, limit: int = 50,
                             agent_type: Optional[str] = None,
                             since: Optional[str] = None,
                             until: Optional[str] = None,
                             order_by: str = "recent") -> list[dict]:
        conn = self._get_conn()
        query = "SELECT * FROM agent_decisions WHERE 1=1"
        params = []
        tf, tp = self._tenant_filter()
        if tf:
            query += tf
            params.extend(tp)
        if agent_type:
            query += " AND agent_type = %s"
            params.append(agent_type)
        if since:
            query += " AND created_at >= %s"
            params.append(since)
        if until:
            query += " AND created_at <= %s"
            params.append(until)
        # Map the (untrusted) order_by to a fixed clause; default preserves the
        # historical created_at DESC behaviour for unknown values.
        order_clause = self._DECISION_ORDER_CLAUSES.get(
            order_by, self._DECISION_ORDER_CLAUSES["recent"])
        query += f" ORDER BY {order_clause} LIMIT %s"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()

        return [dict(r) for r in rows]

    def apply_human_override(self, decision_id: str, human_verdict: str,
                              reviewer: str, reason: Optional[str] = None) -> bool:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        cursor = conn.execute(f"""
            UPDATE agent_decisions
            SET human_override = %s, human_verdict = %s,
                review_reason = %s,
                resolved_at = CURRENT_TIMESTAMP::text
            WHERE id = %s {tf}
        """, [reviewer, human_verdict, reason, decision_id] + tp)
        conn.commit()

        return cursor.rowcount > 0

    # -- Detection Proposals --

    def save_proposal(self, proposal: DetectionProposal) -> str:
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO detection_proposals
            (id, rule_id, rule_file, change_type, original_xml, proposed_xml,
             reasoning, fp_count_trigger, fp_window_days, status, proposed_at,
             reviewed_by, reviewed_at, client_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            proposal.id, proposal.rule_id, proposal.rule_file,
            proposal.change_type, proposal.original_xml, proposal.proposed_xml,
            proposal.reasoning, proposal.fp_count_trigger, proposal.fp_window_days,
            proposal.status, proposal.proposed_at, proposal.reviewed_by,
            proposal.reviewed_at, getattr(proposal, 'client_id', None) or self._tenant_value(),
        ))
        conn.commit()

        return proposal.id

    def get_pending_proposals(self) -> list[dict]:
        """Get proposed proposals (awaiting review)."""
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        rows = conn.execute(f"""
            SELECT * FROM detection_proposals
            WHERE status = 'proposed' {tf}
            ORDER BY proposed_at DESC
        """, tp).fetchall()

        return [dict(r) for r in rows]

    def get_all_proposals(self, limit: int = 100) -> list[dict]:
        """Get all proposals (proposed, approved, deployed, rejected, rolled_back)."""
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        rows = conn.execute(f"""
            SELECT * FROM detection_proposals WHERE 1=1 {tf}
            ORDER BY proposed_at DESC
            LIMIT %s
        """, tp + [limit]).fetchall()

        return [dict(r) for r in rows]

    def update_proposal_status(self, proposal_id: str, status: str,
                                reviewer: str = None,
                                notes: str = None) -> bool:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        if status == "deployed":
            conn.execute(f"""
                UPDATE detection_proposals
                SET status = %s, deployed_at = CURRENT_TIMESTAMP::text
                WHERE id = %s {tf}
            """, [status, proposal_id] + tp)
        elif status == "rejected":
            conn.execute(f"""
                UPDATE detection_proposals
                SET status = %s, reviewed_by = %s, reviewed_at = CURRENT_TIMESTAMP::text,
                    rejection_notes = %s
                WHERE id = %s {tf}
            """, [status, reviewer, notes, proposal_id] + tp)
        else:
            conn.execute(f"""
                UPDATE detection_proposals
                SET status = %s, reviewed_by = %s, reviewed_at = CURRENT_TIMESTAMP::text
                WHERE id = %s {tf}
            """, [status, reviewer, proposal_id] + tp)
        conn.commit()

        return True

    def set_proposal_backup(self, proposal_id: str, backup_xml: str):
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        conn.execute(f"""
            UPDATE detection_proposals SET backup_xml = %s WHERE id = %s {tf}
        """, [backup_xml, proposal_id] + tp)
        conn.commit()


    def get_proposal(self, proposal_id: str) -> dict | None:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        row = conn.execute(
            f"SELECT * FROM detection_proposals WHERE id = %s {tf}",
            [proposal_id] + tp
        ).fetchone()

        return dict(row) if row else None

    # -- Feedback Patterns --

    def upsert_feedback_pattern(self, pattern: FeedbackPattern) -> str:
        """Atomic upsert: increment occurrence if active pattern exists for
        this (pattern_type, rule_id, client_id), otherwise insert new row."""
        conn = self._get_conn()
        client_id = self._tenant_value()
        conn.execute("""
            INSERT INTO feedback_patterns
            (id, pattern_type, rule_id, description, occurrence_count,
             first_seen, last_seen, auto_action_taken, status, client_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT(pattern_type, rule_id, client_id) WHERE status = 'active'
            DO UPDATE SET
                occurrence_count = feedback_patterns.occurrence_count + 1,
                last_seen = excluded.last_seen,
                description = excluded.description
        """, (
            pattern.id, pattern.pattern_type, pattern.rule_id,
            pattern.description, pattern.occurrence_count,
            pattern.first_seen, pattern.last_seen,
            pattern.auto_action_taken, pattern.status,
            client_id,
        ))
        conn.commit()
        return pattern.id

    def get_active_patterns(self, min_occurrences: int = 5) -> list[dict]:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        rows = conn.execute(f"""
            SELECT * FROM feedback_patterns
            WHERE status = 'active' AND occurrence_count >= %s {tf}
            ORDER BY occurrence_count DESC
        """, [min_occurrences] + tp).fetchall()

        return [dict(r) for r in rows]

    # -- Rule Tuning Overrides --

    def upsert_tuning_override(self, override: RuleTuningOverride) -> str:
        conn = self._get_conn()
        client_id = self._tenant_value()
        conn.execute("""
            INSERT INTO rule_tuning_overrides
            (id, rule_id, action_type, confidence_override,
             fp_pattern_signature, reason, created_at, expires_at, client_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT(rule_id, client_id) DO UPDATE SET
                action_type = excluded.action_type,
                confidence_override = excluded.confidence_override,
                fp_pattern_signature = excluded.fp_pattern_signature,
                reason = excluded.reason,
                created_at = excluded.created_at,
                expires_at = excluded.expires_at
        """, (
            override.id, override.rule_id, override.action_type,
            override.confidence_override, override.fp_pattern_signature,
            override.reason, override.created_at, override.expires_at,
            client_id
        ))
        conn.commit()

        return override.id

    def get_tuning_override(self, rule_id: int) -> Optional[dict]:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        row = conn.execute(f"""
            SELECT * FROM rule_tuning_overrides
            WHERE rule_id = %s
              AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP::text) {tf}
        """, [rule_id] + tp).fetchone()

        return dict(row) if row else None

    def get_override_stats_for_rule(self, rule_id: int,
                                     days: int = 30) -> Optional[dict]:
        """Get human override statistics for a rule within a time window.

        Returns None if fewer than 3 overrides exist (not enough signal).
        Used by triage agent to adjust confidence based on accumulated
        human feedback for the same rule_id.
        """
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        window = self._iso_ago(days=days)

        # Override breakdown
        row = conn.execute(f"""
            SELECT
                COUNT(*) as total_overrides,
                SUM(CASE WHEN verdict IN ('false_positive','auto_close')
                         AND human_verdict = 'true_positive' THEN 1 ELSE 0 END) as fp_to_tp,
                SUM(CASE WHEN verdict = 'true_positive'
                         AND human_verdict IN ('false_positive','auto_close') THEN 1 ELSE 0 END) as tp_to_fp
            FROM agent_decisions
            WHERE rule_id = %s
              AND human_verdict IS NOT NULL
              AND human_verdict != verdict
              AND created_at >= %s {tf}
        """, [rule_id, window] + tp).fetchone()

        total_overrides = row["total_overrides"] or 0
        if total_overrides < 3:
            return None

        # Total decisions in window for override rate
        total_row = conn.execute(f"""
            SELECT COUNT(*) as total_decisions
            FROM agent_decisions
            WHERE rule_id = %s
              AND created_at >= %s {tf}
        """, [rule_id, window] + tp).fetchone()

        total_decisions = total_row["total_decisions"] or 1
        fp_to_tp = row["fp_to_tp"] or 0
        tp_to_fp = row["tp_to_fp"] or 0

        override_rate = total_overrides / total_decisions
        dominant = max(fp_to_tp, tp_to_fp)
        direction_strength = dominant / total_overrides if total_overrides else 0

        if fp_to_tp > tp_to_fp:
            direction = "upgrade"
        elif tp_to_fp > fp_to_tp:
            direction = "downgrade"
        else:
            direction = "mixed"

        raw_delta = override_rate * direction_strength * 0.15
        confidence_delta = min(raw_delta, 0.10)

        return {
            "total_overrides": total_overrides,
            "total_decisions": total_decisions,
            "override_rate": round(override_rate, 4),
            "fp_to_tp": fp_to_tp,
            "tp_to_fp": tp_to_fp,
            "direction": direction,
            "confidence_delta": round(confidence_delta, 4),
            "window_days": days,
        }

    def get_all_tuning_overrides(self) -> list[dict]:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        rows = conn.execute(f"""
            SELECT * FROM rule_tuning_overrides
            WHERE (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP::text) {tf}
            ORDER BY created_at DESC
        """, tp).fetchall()

        return [dict(r) for r in rows]

    # -- Rule Deployment History --

    def save_deployment_history(self, entry: dict) -> str:
        """Record a rule deployment for multi-version rollback."""
        conn = self._get_conn()
        entry_id = entry.get("id", str(uuid.uuid4()))
        conn.execute("""
            INSERT INTO rule_deployment_history
            (id, proposal_id, rule_id, rule_file, version,
             xml_before, xml_after, deployed_by, deployed_at, client_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            entry_id, entry["proposal_id"], entry["rule_id"],
            entry["rule_file"], entry["version"],
            entry.get("xml_before"), entry["xml_after"],
            entry.get("deployed_by"), entry["deployed_at"],
            self._tenant_value()
        ))
        conn.commit()
        return entry_id

    def get_deployment_history(self, rule_file: str = None,
                               rule_id: int = None,
                               limit: int = 50) -> list[dict]:
        """Get deployment history, optionally filtered by rule_file or rule_id."""
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        conditions = ["1=1"]
        params = []
        if rule_file:
            conditions.append("rule_file = %s")
            params.append(rule_file)
        if rule_id:
            conditions.append("rule_id = %s")
            params.append(rule_id)
        where = " AND ".join(conditions)
        rows = conn.execute(f"""
            SELECT * FROM rule_deployment_history
            WHERE {where} {tf}
            ORDER BY deployed_at DESC
            LIMIT %s
        """, params + tp + [limit]).fetchall()
        return [dict(r) for r in rows]

    def get_next_deployment_version(self, rule_file: str) -> int:
        """Get the next version number for a rule file deployment."""
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        row = conn.execute(f"""
            SELECT MAX(version) as max_ver FROM rule_deployment_history
            WHERE rule_file = %s {tf}
        """, [rule_file] + tp).fetchone()
        return (row["max_ver"] or 0) + 1

    def get_deployment_at_version(self, rule_file: str,
                                   version: int) -> dict | None:
        """Get a specific version of a rule file deployment."""
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        row = conn.execute(f"""
            SELECT * FROM rule_deployment_history
            WHERE rule_file = %s AND version = %s {tf}
        """, [rule_file, version] + tp).fetchone()
        return dict(row) if row else None

    def mark_deployment_rolled_back(self, deployment_id: str):
        """Mark a deployment as rolled back."""
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        conn.execute(f"""
            UPDATE rule_deployment_history
            SET rolled_back_at = CURRENT_TIMESTAMP::text
            WHERE id = %s {tf}
        """, [deployment_id] + tp)
        conn.commit()

    # -- Operational Metrics --

    def record_metric(self, name: str, value: float,
                       dimensions: dict = None):
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO operational_metrics (id, metric_name, metric_value,
                                             dimensions, recorded_at, client_id)
            VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP::text, %s)
        """, (str(uuid.uuid4()), name, value,
              json.dumps(dimensions or {}), self._tenant_value()))
        conn.commit()

    def get_metric_count(self, metric_name: str, since_date: str = None) -> int:
        """Count metric occurrences, optionally filtered by date."""
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        if since_date:
            row = conn.execute(
                f"SELECT COUNT(*) AS cnt FROM operational_metrics "
                f"WHERE metric_name = %s AND DATE(recorded_at) = %s {tf}",
                [metric_name, since_date] + tp
            ).fetchone()
        else:
            row = conn.execute(
                f"SELECT COUNT(*) AS cnt FROM operational_metrics WHERE metric_name = %s {tf}",
                [metric_name] + tp
            ).fetchone()
        return row["cnt"] if row else 0


    # -- MTT Metrics Computation --

    def compute_mtt_metrics(self, days: int = 30) -> dict:
        """Compute MTTD/MTTA/MTTR from incident timestamps.

        Returns averages in minutes, plus per-severity breakdown and SLA compliance.
        """
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            rows = conn.execute(f"""
                SELECT id, severity, first_seen, created_at, first_response_at,
                       resolved_at, sla_response_due, sla_resolution_due,
                       status, tier
                FROM incidents
                WHERE created_at >= %s {tf}
            """, [self._iso_ago(days=days)] + tp).fetchall()
        except Exception:
            return {"mttd_min": 0, "mtta_min": 0, "mttr_min": 0,
                    "sla_response_compliance": 0, "sla_resolution_compliance": 0,
                    "sample_count": 0, "by_severity": {}}

        from datetime import datetime, timezone

        def _delta_min(start_str, end_str):
            if not start_str or not end_str:
                return None
            try:
                s = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
                e = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
                if s.tzinfo is None:
                    s = s.replace(tzinfo=timezone.utc)
                if e.tzinfo is None:
                    e = e.replace(tzinfo=timezone.utc)
                return max(0, (e - s).total_seconds() / 60.0)
            except (ValueError, TypeError):
                return None

        mttd_vals, mtta_vals, mttr_vals = [], [], []
        sla_resp_met, sla_resp_total = 0, 0
        sla_res_met, sla_res_total = 0, 0
        by_severity = {}

        for r in rows:
            row = dict(r)
            sev = row.get("severity", "medium")
            if sev not in by_severity:
                by_severity[sev] = {"mttd": [], "mtta": [], "mttr": [], "count": 0}
            by_severity[sev]["count"] += 1

            # MTTD: created_at - first_seen
            d = _delta_min(row["first_seen"], row["created_at"])
            if d is not None:
                mttd_vals.append(d)
                by_severity[sev]["mttd"].append(d)

            # MTTA: first_response_at - created_at
            d = _delta_min(row["created_at"], row.get("first_response_at"))
            if d is not None:
                mtta_vals.append(d)
                by_severity[sev]["mtta"].append(d)

            # MTTR: resolved_at - created_at (only for resolved incidents)
            if row.get("resolved_at"):
                d = _delta_min(row["created_at"], row["resolved_at"])
                if d is not None:
                    mttr_vals.append(d)
                    by_severity[sev]["mttr"].append(d)

            # SLA compliance
            if row.get("sla_response_due"):
                sla_resp_total += 1
                if row.get("first_response_at"):
                    resp_d = _delta_min(row["first_response_at"],
                                         row["sla_response_due"])
                    if resp_d is not None and resp_d > 0:
                        sla_resp_met += 1

            if row.get("sla_resolution_due") and row.get("resolved_at"):
                sla_res_total += 1
                res_d = _delta_min(row["resolved_at"],
                                    row["sla_resolution_due"])
                if res_d is not None and res_d > 0:
                    sla_res_met += 1

        def _avg(vals):
            return round(sum(vals) / len(vals), 1) if vals else 0

        sev_summary = {}
        for sev, data in by_severity.items():
            sev_summary[sev] = {
                "count": data["count"],
                "mttd_min": _avg(data["mttd"]),
                "mtta_min": _avg(data["mtta"]),
                "mttr_min": _avg(data["mttr"]),
            }

        return {
            "mttd_min": _avg(mttd_vals),
            "mtta_min": _avg(mtta_vals),
            "mttr_min": _avg(mttr_vals),
            "sla_response_compliance": round(
                (sla_resp_met / sla_resp_total * 100) if sla_resp_total else 0, 1),
            "sla_resolution_compliance": round(
                (sla_res_met / sla_res_total * 100) if sla_res_total else 0, 1),
            "sample_count": len(rows),
            "by_severity": sev_summary,
        }

    def get_mtt_daily_trend(self, days: int = 30) -> list[dict]:
        """Get daily MTTD/MTTA/MTTR averages for trend charting."""
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            rows = conn.execute(f"""
                SELECT date(created_at) as day,
                       AVG(
                         CASE WHEN first_seen IS NOT NULL THEN
                           EXTRACT(EPOCH FROM (created_at::timestamptz - first_seen::timestamptz)) / 60
                         END
                       ) as avg_mttd,
                       AVG(
                         CASE WHEN first_response_at IS NOT NULL THEN
                           EXTRACT(EPOCH FROM (first_response_at::timestamptz - created_at::timestamptz)) / 60
                         END
                       ) as avg_mtta,
                       AVG(
                         CASE WHEN resolved_at IS NOT NULL THEN
                           EXTRACT(EPOCH FROM (resolved_at::timestamptz - created_at::timestamptz)) / 60
                         END
                       ) as avg_mttr,
                       COUNT(*) as incident_count,
                       SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as critical,
                       SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) as high,
                       SUM(CASE WHEN severity='medium' THEN 1 ELSE 0 END) as medium,
                       SUM(CASE WHEN severity='low' THEN 1 ELSE 0 END) as low
                FROM incidents
                WHERE created_at >= %s {tf}
                GROUP BY date(created_at)
                ORDER BY day ASC
            """, [self._iso_ago(days=days)] + tp).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def get_analyst_performance(self, days: int = 30) -> list[dict]:
        """Get per-analyst performance stats from incident timeline."""
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            rows = conn.execute(f"""
                SELECT t.actor,
                       COUNT(DISTINCT CASE WHEN t.event_type IN ('assigned','status_changed','note_added') THEN t.incident_id END) as incidents_touched,
                       COUNT(CASE WHEN t.event_type='status_changed' AND t.description LIKE '%%resolved%%' THEN 1 END) as resolved_count,
                       COUNT(*) as total_actions
                FROM incident_timeline t
                JOIN incidents i ON t.incident_id = i.id
                WHERE t.actor != 'system'
                  AND t.actor != 'ai_summary'
                  AND t.created_at >= %s {tf}
                GROUP BY t.actor
                ORDER BY total_actions DESC
            """, [self._iso_ago(days=days)] + tp).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    # -- SOAR Playbooks & Executions --

    def save_soar_playbook(self, pb: dict):
        conn = self._get_conn()
        try:
            # Conflict target is (name): callers (guidance YAML loader, admin
            # UI) generate a fresh UUID id every time, but reload the same
            # logical playbook by name. UPDATE leaves id unchanged so
            # soar_executions FKs survive a reload.
            conn.execute("""
                INSERT INTO soar_playbooks
                (id, name, display_name, description, enabled, trigger_verdicts,
                 trigger_min_confidence, trigger_min_risk_score,
                 trigger_mitre_techniques, trigger_rule_groups, trigger_ti_required,
                 actions, rollback_actions, require_approval,
                 cooldown_minutes, max_executions_per_hour, priority,
                 created_at, updated_at, client_id)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (name) DO UPDATE SET
                    display_name              = EXCLUDED.display_name,
                    description               = EXCLUDED.description,
                    enabled                   = EXCLUDED.enabled,
                    trigger_verdicts          = EXCLUDED.trigger_verdicts,
                    trigger_min_confidence    = EXCLUDED.trigger_min_confidence,
                    trigger_min_risk_score    = EXCLUDED.trigger_min_risk_score,
                    trigger_mitre_techniques  = EXCLUDED.trigger_mitre_techniques,
                    trigger_rule_groups       = EXCLUDED.trigger_rule_groups,
                    trigger_ti_required       = EXCLUDED.trigger_ti_required,
                    actions                   = EXCLUDED.actions,
                    rollback_actions          = EXCLUDED.rollback_actions,
                    require_approval          = EXCLUDED.require_approval,
                    cooldown_minutes          = EXCLUDED.cooldown_minutes,
                    max_executions_per_hour   = EXCLUDED.max_executions_per_hour,
                    priority                  = EXCLUDED.priority,
                    updated_at                = EXCLUDED.updated_at,
                    client_id                 = EXCLUDED.client_id
            """, (
                pb["id"], pb["name"], pb["display_name"], pb.get("description", ""),
                int(pb.get("enabled", 1)),
                pb.get("trigger_verdicts", "[]"),
                pb.get("trigger_min_confidence", 0.90),
                pb.get("trigger_min_risk_score", 75),
                pb.get("trigger_mitre_techniques", "[]"),
                pb.get("trigger_rule_groups", "[]"),
                int(pb.get("trigger_ti_required", 0)),
                pb.get("actions", "[]"),
                pb.get("rollback_actions", "[]"),
                int(pb.get("require_approval", 1)),
                pb.get("cooldown_minutes", 30),
                pb.get("max_executions_per_hour", 5),
                pb.get("priority", 50),
                pb.get("created_at", datetime.now(timezone.utc).isoformat()),
                pb.get("updated_at", datetime.now(timezone.utc).isoformat()),
                pb["client_id"] if "client_id" in pb else self._tenant_value(),
            ))
            conn.commit()
        except Exception as e:
            _store_logger.warning("save_soar_playbook_failed", error=str(e))

    def get_soar_playbooks(self, enabled_only: bool = False) -> list[dict]:
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            q = "SELECT * FROM soar_playbooks WHERE 1=1"
            params = []
            if tf:
                # Include shared playbooks (client_id IS NULL) alongside tenant-specific ones
                q += " AND (client_id = %s OR client_id IS NULL)"
                params.extend(tp)
            if enabled_only:
                q += " AND enabled = 1"
            q += " ORDER BY priority ASC"
            return [dict(r) for r in conn.execute(q, params).fetchall()]
        except Exception as e:
            _store_logger.warning("get_soar_playbooks_failed", error=str(e))
            return []

    def get_soar_playbook(self, playbook_id: str) -> dict:
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            # Include shared playbooks (client_id IS NULL)
            scope = " AND (client_id = %s OR client_id IS NULL)" if tf else ""
            row = conn.execute(
                f"SELECT * FROM soar_playbooks WHERE id = %s {scope}",
                [playbook_id] + tp
            ).fetchone()
            return dict(row) if row else {}
        except Exception:
            return {}

    def toggle_soar_playbook(self, playbook_id: str, enabled: bool):
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            conn.execute(
                f"UPDATE soar_playbooks SET enabled = %s, updated_at = CURRENT_TIMESTAMP::text WHERE id = %s {tf}",
                [int(enabled), playbook_id] + tp)
            conn.commit()
        except Exception:
            pass

    def save_soar_execution(self, ex: dict):
        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT INTO soar_executions
                (id, playbook_id, playbook_name, incident_id, decision_id,
                 status, trigger_data, actions_planned, actions_completed,
                 current_step, total_steps, approved_by, approved_at,
                 created_at, updated_at, client_id)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                ex["id"], ex["playbook_id"], ex["playbook_name"],
                ex.get("incident_id"), ex["decision_id"],
                ex.get("status", "pending_approval"),
                ex.get("trigger_data", "{}"),
                ex.get("actions_planned", "[]"),
                ex.get("actions_completed", "[]"),
                ex.get("current_step", 0),
                ex.get("total_steps", 0),
                ex.get("approved_by"),
                ex.get("approved_at"),
                ex.get("created_at", datetime.now(timezone.utc).isoformat()),
                ex.get("updated_at", datetime.now(timezone.utc).isoformat()),
                ex.get("client_id") or self._tenant_value(),
            ))
            conn.commit()
        except Exception as e:
            structlog.get_logger(__name__).warning("soar_exec_save_failed", error=str(e))

    def get_soar_execution(self, execution_id: str) -> dict:
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            row = conn.execute(
                f"SELECT * FROM soar_executions WHERE id = %s {tf}",
                [execution_id] + tp
            ).fetchone()
            return dict(row) if row else {}
        except Exception:
            return {}

    def get_soar_executions(self, status: str = None, limit: int = 100) -> list[dict]:
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            q = "SELECT * FROM soar_executions WHERE 1=1"
            params = list(tp)
            if tf:
                q += tf
            if status:
                q += " AND status = %s"
                params.append(status)
            q += " ORDER BY created_at DESC LIMIT %s"
            params.append(limit)
            return [dict(r) for r in conn.execute(q, params).fetchall()]
        except Exception:
            return []

    _SOAR_EXEC_UPDATE_COLS = frozenset({
        "status", "actions_completed", "current_step", "total_steps",
        "result", "error", "completed_at", "approved_by", "approved_at",
    })

    def update_soar_execution(self, execution_id: str, **kwargs):
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            sets = ["updated_at = CURRENT_TIMESTAMP::text"]
            params = []
            for k, v in kwargs.items():
                if k not in self._SOAR_EXEC_UPDATE_COLS:
                    continue
                sets.append(f"{k} = %s")
                params.append(v)
            params.append(execution_id)
            params.extend(tp)
            conn.execute(
                f"UPDATE soar_executions SET {', '.join(sets)} WHERE id = %s {tf}",
                params)
            conn.commit()
        except Exception:
            pass

    def count_recent_soar_executions(self, playbook_id: str, hours: int = 1) -> int:
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            row = conn.execute(f"""
                SELECT COUNT(*) AS cnt FROM soar_executions
                WHERE playbook_id = %s AND created_at >= %s
                AND status NOT IN ('cancelled') {tf}
            """, [playbook_id, self._iso_ago(hours=hours)] + tp).fetchone()
            return row["cnt"] if row else 0
        except Exception:
            return 0

    def get_soar_stats(self) -> dict:
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            pb_scope = " AND (client_id = %s OR client_id IS NULL)" if tf else ""
            total_pb = conn.execute(f"SELECT COUNT(*) AS cnt FROM soar_playbooks WHERE 1=1 {pb_scope}", tp).fetchone()["cnt"]
            active_pb = conn.execute(f"SELECT COUNT(*) AS cnt FROM soar_playbooks WHERE enabled=1 {pb_scope}", tp).fetchone()["cnt"]
            pending = conn.execute(f"SELECT COUNT(*) AS cnt FROM soar_executions WHERE status='pending_approval' {tf}", tp).fetchone()["cnt"]
            today_exec = conn.execute(f"SELECT COUNT(*) AS cnt FROM soar_executions WHERE created_at >= CURRENT_DATE::text {tf}", tp).fetchone()["cnt"]
            completed = conn.execute(f"SELECT COUNT(*) AS cnt FROM soar_executions WHERE status='completed' AND created_at::timestamptz >= CURRENT_TIMESTAMP - INTERVAL '30 days' {tf}", tp).fetchone()["cnt"]
            total_exec = conn.execute(f"SELECT COUNT(*) AS cnt FROM soar_executions WHERE status IN ('completed','partial','failed') AND created_at::timestamptz >= CURRENT_TIMESTAMP - INTERVAL '30 days' {tf}", tp).fetchone()["cnt"]
            return {
                "total_playbooks": total_pb, "active_playbooks": active_pb,
                "pending_approvals": pending, "executions_today": today_exec,
                "success_rate": round((completed / total_exec * 100) if total_exec else 0, 1),
            }
        except Exception:
            return {"total_playbooks": 0, "active_playbooks": 0,
                    "pending_approvals": 0, "executions_today": 0, "success_rate": 0}

    # -- Multi-Tenancy --

    def save_tenant(self, tenant: dict):
        """Create a new tenant.

        Plain INSERT (NOT INSERT OR REPLACE / ON CONFLICT) so a UNIQUE-constraint
        violation on ``slug`` or ``name`` raises ``psycopg.errors.UniqueViolation``
        instead of silently overwriting the existing row. The previous behavior caused
        a real data-loss incident on 2026-05-07: a duplicate-slug create
        request silently destroyed the prior tenant's encrypted config.

        Callers that legitimately need upsert semantics (e.g. seeding
        scripts) must use the explicit upsert path or handle the conflict
        themselves — `src/setup/deployment_wizard.py` already pre-checks
        for existence before calling this method.

        Raises ``psycopg.errors.UniqueViolation`` on UNIQUE conflict; the route
        handler should translate to HTTP 409.
        """
        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT INTO tenants
                (id, name, slug, config_encrypted, active, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                tenant["id"], tenant["name"], tenant["slug"],
                tenant.get("config_encrypted", ""),
                int(tenant.get("active", 1)),
                tenant.get("created_at", datetime.now(timezone.utc).isoformat()),
                tenant.get("updated_at", datetime.now(timezone.utc).isoformat()),
            ))
            conn.commit()
        except Exception as e:
            structlog.get_logger(__name__).error(
                "tenant_save_failed",
                tenant_id=tenant.get("id"),
                slug=tenant.get("slug"),
                error=str(e))
            raise

    def get_tenant(self, tenant_id: str) -> dict:
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM tenants WHERE id = %s", (tenant_id,)
            ).fetchone()
            return dict(row) if row else {}
        except Exception:
            return {}

    def get_tenant_by_slug(self, slug: str) -> dict:
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM tenants WHERE slug = %s", (slug,)
            ).fetchone()
            return dict(row) if row else {}
        except Exception:
            return {}

    def get_active_tenants(self) -> list[dict]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM tenants WHERE active = 1 ORDER BY name"
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def get_all_tenants(self) -> list[dict]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM tenants ORDER BY name"
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def get_tenant_agent_ids(self, client_id: str) -> list[str] | None:
        """Return the list of Wazuh agent IDs mapped to a tenant.

        Returns None (not empty list) when the tenant_agents table has no
        rows for this tenant, which signals "no mapping configured" so the
        caller can fall back to showing all agents (single-tenant mode).
        """
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT agent_id FROM tenant_agents WHERE client_id = %s",
                (client_id,),
            ).fetchall()
            if not rows:
                return None
            return [r["agent_id"] for r in rows]
        except Exception:
            # Table may not exist yet (pre-migration) — treat as unconfigured
            return None

    def add_tenant_agent(self, client_id: str, agent_id: str) -> bool:
        """Map a Wazuh agent ID to a tenant.

        Returns True if inserted, False if the agent is already mapped
        to another tenant (unique constraint on agent_id).
        Raises on unexpected errors.
        """
        conn = self._get_conn()
        now = __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat()
        try:
            conn.execute(
                "INSERT INTO tenant_agents (client_id, agent_id, added_at) "
                "VALUES (%s, %s, %s)",
                (client_id, agent_id, now))
            conn.commit()
            return True
        except Exception as e:
            if "UNIQUE constraint" in str(e):
                return False
            raise

    def remove_tenant_agent(self, client_id: str, agent_id: str) -> bool:
        """Remove a Wazuh agent mapping from a tenant. Returns True if deleted."""
        conn = self._get_conn()
        cursor = conn.execute(
            "DELETE FROM tenant_agents WHERE client_id = %s AND agent_id = %s",
            (client_id, agent_id))
        conn.commit()
        return cursor.rowcount > 0

    def get_all_tenant_agents(self, client_id: str) -> list[dict]:
        """Return all agent mappings for a tenant with metadata."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT agent_id, added_at FROM tenant_agents WHERE client_id = %s "
                "ORDER BY added_at",
                (client_id,)).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    _TENANT_UPDATE_COLS = frozenset({
        "name", "display_name", "active", "config_encrypted",
        "contact_email", "notes",
    })

    def update_tenant(self, tenant_id: str, **kwargs):
        """Update tenant fields. Raises on DB failure."""
        conn = self._get_conn()
        try:
            sets = ["updated_at = CURRENT_TIMESTAMP::text"]
            params = []
            for k, v in kwargs.items():
                if k not in self._TENANT_UPDATE_COLS:
                    continue
                sets.append(f"{k} = %s")
                params.append(v)
            params.append(tenant_id)
            conn.execute(
                f"UPDATE tenants SET {', '.join(sets)} WHERE id = %s",
                params)
            conn.commit()
        except Exception as e:
            structlog.get_logger(__name__).error(
                "tenant_update_failed",
                tenant_id=tenant_id,
                fields=list(kwargs.keys()),
                error=str(e))
            raise

    def deactivate_tenant(self, tenant_id: str):
        self.update_tenant(tenant_id, active=0)

    def tenant_exists(self) -> bool:
        """Check if any tenants exist (for first-startup seeding)."""
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT COUNT(*) AS cnt FROM tenants").fetchone()
            return row["cnt"] > 0
        except Exception:
            return False

    def backfill_null_client_ids(self, tenant_id: str):
        """Backfill NULL client_id rows across all tenant-scoped tables.

        Needed when migration 7 ran before the default tenant was seeded,
        leaving all pre-existing rows with client_id = NULL.
        """
        conn = self._get_conn()
        tables = [
            "agent_decisions", "incidents", "detection_proposals",
            "feedback_patterns", "behavioral_baselines", "rule_tuning_overrides",
            "hunt_findings", "operational_metrics", "soar_executions",
            "mitre_coverage", "audit_log", "anon_mappings",
            "decision_audit_trail", "sla_breaches", "platform_users",
        ]
        # Validate table names against known set (defense against f-string SQL)
        known = self.TENANT_SCOPED_TABLES | self.SHARED_TABLES | self.FK_SCOPED_TABLES
        for t in tables:
            assert t in known, f"Unknown table in backfill: {t}"
        total = 0
        for table in tables:
            try:
                cursor = conn.execute(
                    f"UPDATE {table} SET client_id = %s WHERE client_id IS NULL",
                    (tenant_id,),
                )
                total += cursor.rowcount
            except Exception as e:
                _store_logger.debug("backfill_table_skip", table=table, error=str(e))
        if total > 0:
            conn.commit()
            import structlog
            structlog.get_logger(__name__).info(
                "backfill_null_client_ids", tenant_id=tenant_id, rows_updated=total)

    def set_user_tenant(self, username: str, client_id: str):
        """Associate a user with a tenant."""
        conn = self._get_conn()
        try:
            conn.execute(
                "UPDATE platform_users SET client_id = %s WHERE username = %s",
                (client_id, username))
            conn.commit()
        except Exception:
            pass

    # -- MITRE ATT&CK Coverage --

    def get_technique_counts_from_decisions(self, days: int = 90) -> dict:
        """Aggregate MITRE technique detection counts from agent decisions."""
        conn = self._get_conn()
        result = {}
        try:
            tf, tp = self._tenant_filter()
            rows = conn.execute(f"""
                SELECT enrichment_summary, verdict, rule_id, created_at
                FROM agent_decisions
                WHERE created_at >= %s
                AND enrichment_summary IS NOT NULL {tf}
            """, [self._iso_ago(days=days)] + tp).fetchall()

            for row in rows:
                try:
                    enr = json.loads(row["enrichment_summary"] or "{}")
                except (json.JSONDecodeError, TypeError):
                    continue

                # Extract techniques from enrichment or try rule_mitre fields
                techniques = enr.get("rule_mitre_techniques", [])
                if not techniques:
                    continue

                verdict = row["verdict"]
                rule_id = row["rule_id"]

                for tech_id in techniques:
                    # Map sub-techniques (T1110.001) to parent (T1110)
                    parent_id = tech_id.split(".")[0] if "." in tech_id else tech_id
                    for tid in set([tech_id, parent_id]):
                        if tid not in result:
                            result[tid] = {"total": 0, "tp": 0, "fp": 0,
                                           "rule_ids": set(), "last_seen": None}
                        result[tid]["total"] += 1
                        if verdict == "true_positive":
                            result[tid]["tp"] += 1
                        elif verdict == "false_positive":
                            result[tid]["fp"] += 1
                        result[tid]["rule_ids"].add(str(rule_id))
                        result[tid]["last_seen"] = row["created_at"]

        except Exception as e:
            structlog.get_logger(__name__).warning(
                "mitre_technique_count_failed", error=str(e))
        return result

    def save_mitre_coverage(self, cov: dict):
        """Upsert a MITRE coverage record."""
        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT INTO mitre_coverage
                (technique_id, technique_name, tactic, detection_count,
                 tp_count, fp_count, last_seen, rule_ids,
                 coverage_status, updated_at, client_id)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (technique_id, tactic) DO UPDATE SET
                    technique_name   = EXCLUDED.technique_name,
                    detection_count  = EXCLUDED.detection_count,
                    tp_count         = EXCLUDED.tp_count,
                    fp_count         = EXCLUDED.fp_count,
                    last_seen        = EXCLUDED.last_seen,
                    rule_ids         = EXCLUDED.rule_ids,
                    coverage_status  = EXCLUDED.coverage_status,
                    updated_at       = EXCLUDED.updated_at,
                    client_id        = EXCLUDED.client_id
            """, (
                cov["technique_id"], cov["technique_name"], cov["tactic"],
                cov.get("detection_count", 0), cov.get("tp_count", 0),
                cov.get("fp_count", 0), cov.get("last_seen"),
                cov.get("rule_ids", "[]"), cov.get("coverage_status", "not_detected"),
                cov.get("updated_at"),
                cov.get("client_id") or self._tenant_value(),
            ))
            conn.commit()
        except Exception:
            pass

    def get_mitre_coverage(self, tactic: str = None) -> list[dict]:
        """Get all MITRE coverage records, optionally filtered by tactic."""
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            # Include shared rows (client_id IS NULL) like playbooks
            scope = " AND (client_id = %s OR client_id IS NULL)" if tf else ""
            if tactic:
                rows = conn.execute(
                    f"SELECT * FROM mitre_coverage WHERE tactic = %s {scope} ORDER BY technique_id",
                    [tactic] + tp).fetchall()
            else:
                rows = conn.execute(
                    f"SELECT * FROM mitre_coverage WHERE 1=1 {scope} ORDER BY tactic, technique_id",
                    tp).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def get_mitre_technique_detail(self, technique_id: str) -> list[dict]:
        """Get coverage records for a specific technique across all tactics."""
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            scope = " AND (client_id = %s OR client_id IS NULL)" if tf else ""
            rows = conn.execute(
                f"SELECT * FROM mitre_coverage WHERE technique_id = %s {scope}",
                [technique_id] + tp).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    # -- Anonymization Mapping Ledger --

    def save_anon_mapping(self, token: str, original: str, field_type: str):
        """Persist a token ↔ original mapping for audit/correlation."""
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        client_id = self._tenant_value()
        conn.execute("""
            INSERT INTO anon_mappings (token, original_value, field_type,
                                       first_seen, last_seen, hit_count, client_id)
            VALUES (%s, %s, %s, %s, %s, 1, %s)
            ON CONFLICT(token, client_id) DO UPDATE SET
                last_seen = EXCLUDED.last_seen,
                hit_count = anon_mappings.hit_count + 1
        """, (token, original, field_type, now, now, client_id))
        conn.commit()

    def lookup_anon_token(self, token: str) -> Optional[dict]:
        """Resolve a single anonymized token to its original value."""
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        row = conn.execute(
            f"SELECT * FROM anon_mappings WHERE token = %s {tf}",
            [token] + tp
        ).fetchone()
        return dict(row) if row else None

    def lookup_anon_original(self, original: str) -> Optional[dict]:
        """Find the token for a given original value."""
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        row = conn.execute(
            f"SELECT * FROM anon_mappings WHERE original_value = %s {tf}",
            [original] + tp
        ).fetchone()
        return dict(row) if row else None

    def get_anon_mappings(self, field_type: str = None,
                          limit: int = 100) -> list[dict]:
        """List anonymization mappings, optionally filtered by type."""
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        if field_type:
            rows = conn.execute(f"""
                SELECT * FROM anon_mappings WHERE field_type = %s {tf}
                ORDER BY last_seen DESC LIMIT %s
            """, [field_type] + tp + [limit]).fetchall()
        else:
            rows = conn.execute(f"""
                SELECT * FROM anon_mappings WHERE 1=1 {tf}
                ORDER BY last_seen DESC LIMIT %s
            """, tp + [limit]).fetchall()
        return [dict(r) for r in rows]

    # -- Token Revocation --

    def revoke_token(self, token_hash: str, expires_at_epoch: int,
                     client_id: str = None):
        """Persist a revoked token hash so it survives restarts."""
        conn = self._get_conn()
        import time
        now_epoch = int(time.time())
        conn.execute("""
            INSERT INTO revoked_tokens
            (token_hash, expires_at, revoked_at, client_id)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT DO NOTHING
        """, (token_hash, expires_at_epoch, now_epoch, client_id))
        conn.commit()

    def is_token_revoked(self, token_hash: str) -> bool:
        """Check if a token hash is in the revocation list."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT 1 FROM revoked_tokens WHERE token_hash = %s", (token_hash,)
        ).fetchone()
        return row is not None

    def load_revoked_tokens(self) -> set[str]:
        """Load all non-expired revoked token hashes (for startup cache)."""
        conn = self._get_conn()
        import time
        now_epoch = int(time.time())
        rows = conn.execute("""
            SELECT token_hash FROM revoked_tokens WHERE expires_at > %s
        """, (now_epoch,)).fetchall()
        return {r["token_hash"] for r in rows}

    def prune_expired_revocations(self):
        """Remove expired tokens from the revocation table."""
        conn = self._get_conn()
        import time
        now_epoch = int(time.time())
        conn.execute(
            "DELETE FROM revoked_tokens WHERE expires_at <= %s", (now_epoch,)
        )
        conn.commit()

    def get_metrics_timeseries(self, name: str, days: int = 30) -> list[dict]:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        rows = conn.execute(f"""
            SELECT metric_value, dimensions, recorded_at
            FROM operational_metrics
            WHERE metric_name = %s AND recorded_at >= %s {tf}
            ORDER BY recorded_at ASC
        """, [name, self._iso_ago(days=days)] + tp).fetchall()

        return [dict(r) for r in rows]

    def get_dashboard_stats(self) -> dict:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        stats = {}

        # Today's decisions (using effective verdict: human override if present)
        row = conn.execute(f"""
            SELECT COUNT(*) as total,
                   SUM(CASE WHEN COALESCE(human_verdict, verdict)='false_positive' THEN 1 ELSE 0 END) as fps,
                   SUM(CASE WHEN COALESCE(human_verdict, verdict)='true_positive' THEN 1 ELSE 0 END) as tps,
                   SUM(CASE WHEN COALESCE(human_verdict, verdict) IN ('auto_close','auto_closed') THEN 1 ELSE 0 END) as auto_closed,
                   SUM(CASE WHEN escalated=1 THEN 1 ELSE 0 END) as escalated,
                   AVG(confidence) as avg_confidence
            FROM agent_decisions
            WHERE created_at::timestamptz >= CURRENT_TIMESTAMP - INTERVAL '1 day' {tf}
        """, tp).fetchone()
        stats['today'] = dict(row)
        
        # 7-day trend
        rows = conn.execute(f"""
            SELECT DATE(created_at) as day,
                   COUNT(*) as total,
                   SUM(CASE WHEN COALESCE(human_verdict, verdict)='false_positive' THEN 1 ELSE 0 END) as fps,
                   SUM(CASE WHEN COALESCE(human_verdict, verdict)='true_positive' THEN 1 ELSE 0 END) as tps,
                   AVG(confidence) as avg_confidence
            FROM agent_decisions
            WHERE created_at::timestamptz >= CURRENT_TIMESTAMP - INTERVAL '7 days' {tf}
            GROUP BY DATE(created_at)
            ORDER BY day ASC
        """, tp).fetchall()
        stats['weekly_trend'] = [dict(r) for r in rows]
        
        # Top noisy rules with tuning action tags
        # Check both rule_tuning_overrides AND deployed detection proposals
        rows = conn.execute(f"""
            SELECT ad.rule_id, ad.rule_description,
                   COUNT(*) as total_alerts,
                   SUM(CASE WHEN COALESCE(ad.human_verdict, ad.verdict)='false_positive' THEN 1 ELSE 0 END) as fp_count,
                   CAST(SUM(CASE WHEN COALESCE(ad.human_verdict, ad.verdict)='false_positive' THEN 1 ELSE 0 END) AS REAL)
                   / COUNT(*) as fp_rate,
                   MAX(COALESCE(rto.action_type,
                            CASE WHEN dp.status = 'deployed' THEN 'auto_tuned'
                                 WHEN dp.status = 'approved' THEN 'approved'
                                 WHEN dp.status = 'proposed' THEN 'monitoring'
                            END)) as tuning_action
            FROM agent_decisions ad
            LEFT JOIN rule_tuning_overrides rto
                ON ad.rule_id = rto.rule_id
                AND rto.client_id IS NOT DISTINCT FROM ad.client_id
                AND (rto.expires_at IS NULL OR rto.expires_at > CURRENT_TIMESTAMP::text)
            LEFT JOIN detection_proposals dp
                ON ad.rule_id = dp.rule_id
                AND dp.client_id IS NOT DISTINCT FROM ad.client_id
                AND dp.status IN ('proposed', 'approved', 'deployed')
                AND dp.proposed_at::timestamptz >= CURRENT_TIMESTAMP - INTERVAL '30 days'
            WHERE ad.created_at::timestamptz >= CURRENT_TIMESTAMP - INTERVAL '7 days'
            {"AND ad.client_id = %s" if tf else ""}
            GROUP BY ad.rule_id, ad.rule_description
            HAVING COUNT(*) >= 3
            ORDER BY fp_rate DESC
            LIMIT 10
        """, tp).fetchall()
        stats['noisy_rules'] = [dict(r) for r in rows]

        # Pending human reviews — must match the Triage tab's Pending filter
        row = conn.execute(f"""
            SELECT COUNT(*) as pending
            FROM agent_decisions
            WHERE human_verdict IS NULL
              AND escalated = 1
              AND created_at::timestamptz >= CURRENT_TIMESTAMP - INTERVAL '1 day' {tf}
        """, tp).fetchone()
        stats['pending_reviews'] = row['pending']

        # Pending detection proposals
        row = conn.execute(f"""
            SELECT COUNT(*) as pending FROM detection_proposals
            WHERE status = 'proposed' {tf}
        """, tp).fetchone()
        stats['pending_proposals'] = row['pending']

        # Open incidents
        row = conn.execute(f"""
            SELECT COUNT(*) as open_incidents,
                   SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_incidents
            FROM incidents
            WHERE status IN ('open', 'investigating') {tf}
        """, tp).fetchone()
        stats['open_incidents'] = row['open_incidents'] or 0
        stats['critical_incidents'] = row['critical_incidents'] or 0


        return stats

    # -- Processed Alerts (survives restarts) --

    def mark_alert_processed(self, alert_id: str, rule_id: int = None,
                              rule_description: str = None, verdict: str = None):
        """Mark an alert as processed so it's not re-triaged on restart."""
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO processed_alerts
            (alert_id, rule_id, rule_description, processed_at, verdict, client_id)
            VALUES (%s, %s, %s, CURRENT_TIMESTAMP::text, %s, %s)
            ON CONFLICT DO NOTHING
        """, (alert_id, rule_id, rule_description, verdict, self._tenant_value()))
        conn.commit()


    def is_alert_processed(self, alert_id: str) -> bool:
        """Check if an alert was already processed."""
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        row = conn.execute(
            f"SELECT 1 FROM processed_alerts WHERE alert_id = %s {tf}",
            [alert_id] + tp
        ).fetchone()

        return row is not None

    def get_processed_ids(self, hours: int = 48) -> set:
        """Load recently processed alert IDs (for in-memory cache on startup)."""
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        rows = conn.execute(f"""
            SELECT alert_id FROM processed_alerts
            WHERE processed_at::timestamptz >= %s::timestamptz {tf}
        """, [self._iso_ago(hours=hours)] + tp).fetchall()

        return {r['alert_id'] for r in rows}

    def cleanup_old_processed(self, days: int = 7):
        """Remove old processed records to keep the table lean."""
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        conn.execute(f"""
            DELETE FROM processed_alerts
            WHERE processed_at::timestamptz < %s::timestamptz {tf}
        """, [self._iso_ago(days=days)] + tp)
        conn.commit()


    # -- Behavioral Baselines --

    def save_baseline(self, dimension: str, dimension_value: str,
                      metric: str, mean: float, std_dev: float,
                      sample_count: int, window_days: int):
        """Upsert a behavioral baseline for a dimension/metric pair."""
        conn = self._get_conn()
        client_id = self._tenant_value()
        conn.execute("""
            INSERT INTO behavioral_baselines
            (id, dimension, dimension_value, metric, mean, std_dev,
             sample_count, window_days, computed_at, client_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP::text, %s)
            ON CONFLICT(dimension, dimension_value, metric, client_id) DO UPDATE SET
                mean = excluded.mean,
                std_dev = excluded.std_dev,
                sample_count = excluded.sample_count,
                window_days = excluded.window_days,
                computed_at = excluded.computed_at
        """, (str(uuid.uuid4()), dimension, dimension_value, metric,
              mean, std_dev, sample_count, window_days, client_id))
        conn.commit()


    def get_baseline(self, dimension: str, dimension_value: str,
                     metric: str) -> Optional[dict]:
        """Look up a single baseline."""
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        row = conn.execute(f"""
            SELECT mean, std_dev, sample_count, window_days, computed_at
            FROM behavioral_baselines
            WHERE dimension = %s AND dimension_value = %s AND metric = %s {tf}
        """, [dimension, dimension_value, metric] + tp).fetchone()

        return dict(row) if row else None

    def get_baselines_for_alert(self, agent_name: str = None,
                                src_ip: str = None,
                                src_user: str = None) -> dict:
        """Batch-lookup baselines for all dimensions relevant to an alert."""
        baselines = {}
        lookups = []
        if agent_name:
            lookups.append(("agent", agent_name))
        if src_ip:
            lookups.append(("src_ip", src_ip))
        if src_user:
            lookups.append(("src_user", src_user))

        if not lookups:
            return baselines

        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        for dimension, value in lookups:
            rows = conn.execute(f"""
                SELECT metric, mean, std_dev, sample_count
                FROM behavioral_baselines
                WHERE dimension = %s AND dimension_value = %s {tf}
            """, [dimension, value] + tp).fetchall()
            for row in rows:
                key = f"{dimension}_{row['metric']}"
                baselines[key] = {
                    "mean": row["mean"],
                    "std_dev": row["std_dev"],
                    "sample_count": row["sample_count"]
                }

        return baselines

    # -- Hunt Findings --

    def save_hunt_finding(self, finding: dict):
        """Save a single hunt finding."""
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO hunt_findings
            (id, hunt_cycle_id, hypothesis, mitre_technique, priority,
             query_index, query_body, result_count, results_summary,
             status, confirmed, analyst_notes, created_at, reviewed_at,
             client_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET
                hunt_cycle_id    = EXCLUDED.hunt_cycle_id,
                hypothesis       = EXCLUDED.hypothesis,
                mitre_technique  = EXCLUDED.mitre_technique,
                priority         = EXCLUDED.priority,
                query_index      = EXCLUDED.query_index,
                query_body       = EXCLUDED.query_body,
                result_count     = EXCLUDED.result_count,
                results_summary  = EXCLUDED.results_summary,
                status           = EXCLUDED.status,
                confirmed        = EXCLUDED.confirmed,
                analyst_notes    = EXCLUDED.analyst_notes,
                created_at       = EXCLUDED.created_at,
                reviewed_at      = EXCLUDED.reviewed_at,
                client_id        = EXCLUDED.client_id
        """, (
            finding["id"], finding["hunt_cycle_id"], finding["hypothesis"],
            finding.get("mitre_technique"), finding.get("priority", "medium"),
            finding.get("query_index"), finding.get("query_body"),
            finding.get("result_count", 0), finding.get("results_summary"),
            finding.get("status", "open"), finding.get("confirmed", 0),
            finding.get("analyst_notes"), finding["created_at"],
            finding.get("reviewed_at"),
            finding.get("client_id") or self._tenant_value(),
        ))
        conn.commit()


    def get_hunt_findings(self, status: str = None,
                          limit: int = 50) -> list[dict]:
        """Get hunt findings, optionally filtered by status."""
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        query = "SELECT * FROM hunt_findings WHERE 1=1"
        params = []
        params.extend(tp)
        if tf:
            query += tf
        if status:
            query += " AND status = %s"
            params.append(status)
        query += " ORDER BY created_at DESC LIMIT %s"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()

        return [dict(r) for r in rows]

    def review_hunt_finding(self, finding_id: str, status: str,
                            confirmed: bool, notes: str = None) -> bool:
        """Mark a hunt finding as reviewed."""
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        conn.execute(f"""
            UPDATE hunt_findings
            SET status = %s, confirmed = %s, analyst_notes = %s,
                reviewed_at = CURRENT_TIMESTAMP::text
            WHERE id = %s {tf}
        """, [status, int(confirmed), notes, finding_id] + tp)
        conn.commit()

        return True

    # -- Incidents --

    def save_incident(self, incident: Incident) -> str:
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO incidents
            (id, title, severity, status, grouping_key, alert_count,
             first_seen, last_seen, assigned_to, created_at, updated_at,
             resolved_at, summary, mitre_tactics, mitre_techniques,
             affected_hosts, affected_users, affected_ips, client_id,
             attack_chain_id, attack_chain_tactics)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET
                title             = EXCLUDED.title,
                severity          = EXCLUDED.severity,
                status            = EXCLUDED.status,
                grouping_key      = EXCLUDED.grouping_key,
                alert_count       = EXCLUDED.alert_count,
                first_seen        = EXCLUDED.first_seen,
                last_seen         = EXCLUDED.last_seen,
                assigned_to       = EXCLUDED.assigned_to,
                created_at        = EXCLUDED.created_at,
                updated_at        = EXCLUDED.updated_at,
                resolved_at       = EXCLUDED.resolved_at,
                summary           = EXCLUDED.summary,
                mitre_tactics     = EXCLUDED.mitre_tactics,
                mitre_techniques  = EXCLUDED.mitre_techniques,
                affected_hosts    = EXCLUDED.affected_hosts,
                affected_users    = EXCLUDED.affected_users,
                affected_ips      = EXCLUDED.affected_ips,
                client_id         = EXCLUDED.client_id,
                attack_chain_id      = EXCLUDED.attack_chain_id,
                attack_chain_tactics = EXCLUDED.attack_chain_tactics
        """, (
            incident.id, incident.title, incident.severity, incident.status,
            incident.grouping_key, incident.alert_count,
            incident.first_seen, incident.last_seen, incident.assigned_to,
            incident.created_at, incident.updated_at, incident.resolved_at,
            incident.summary, incident.mitre_tactics, incident.mitre_techniques,
            incident.affected_hosts, incident.affected_users,
            incident.affected_ips, incident.client_id,
            incident.attack_chain_id, incident.attack_chain_tactics
        ))
        conn.commit()

        return incident.id

    def get_incident(self, incident_id: str) -> Optional[dict]:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        row = conn.execute(
            f"SELECT * FROM incidents WHERE id = %s {tf}", [incident_id] + tp
        ).fetchone()

        return dict(row) if row else None

    def get_incidents(self, status: str = None, severity: str = None,
                      assigned_to: str = None, limit: int = 100,
                      offset: int = 0) -> list[dict]:
        conn = self._get_conn()
        query = "SELECT * FROM incidents WHERE 1=1"
        params = []
        tf, tp = self._tenant_filter()
        if tf:
            query += tf
            params.extend(tp)
        if status:
            query += " AND status = %s"
            params.append(status)
        if severity:
            query += " AND severity = %s"
            params.append(severity)
        if assigned_to:
            query += " AND assigned_to = %s"
            params.append(assigned_to)
        query += " ORDER BY last_seen DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        rows = conn.execute(query, params).fetchall()

        return [dict(r) for r in rows]

    # ── Campaigns (attack-chain aggregation) — WO-B5 ────────────────────────
    # Read-only grouping of M5-linked incidents (shared ``attack_chain_id``)
    # into cross-host kill-chain campaigns. No new correlation logic. Tenant
    # isolation is enforced by ``_tenant_filter()`` on the incident read — a
    # campaign can NEVER aggregate across tenants.

    _CAMPAIGN_COLS = (
        "id, title, severity, status, first_seen, last_seen, alert_count, "
        "attack_chain_id, attack_chain_tactics, "
        "affected_hosts, affected_users, affected_ips"
    )

    def get_campaigns(self, status: str = None, active_only: bool = False,
                      limit: int = 100, now: datetime = None) -> list[dict]:
        """Return attack-chain campaigns for the current tenant.

        Groups incidents that carry a non-null ``attack_chain_id`` into
        campaign dicts (see ``build_campaigns_from_incident_rows``). Incidents
        with a NULL chain id are EXCLUDED — standalone incidents are not
        campaigns in the Overview.

        Filters (applied to the campaign rollup):
          * ``active_only`` — keep only campaigns whose rollup status is
            "active" (any member open/investigating).
          * ``status`` — keep only campaigns whose rollup status equals this.
          * ``limit`` — cap the number of campaigns returned (after sorting
            worst-severity / longest-dwell first).

        ``now`` (aware datetime) is used for dwell; defaults to
        ``datetime.now(timezone.utc)`` — the same clock accessor used elsewhere
        in this store.
        """
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        # tf is generated by _tenant_filter() (always " AND client_id = %s" or
        # "") — NOT user input. Safe f-string pattern used project-wide.
        rows = conn.execute(f"""
            SELECT {self._CAMPAIGN_COLS}
            FROM incidents
            WHERE attack_chain_id IS NOT NULL {tf}
            ORDER BY first_seen ASC
        """, tp).fetchall()

        if now is None:
            now = datetime.now(timezone.utc)
        campaigns = build_campaigns_from_incident_rows([dict(r) for r in rows], now)

        if active_only:
            campaigns = [c for c in campaigns if c["status"] == "active"]
        if status:
            campaigns = [c for c in campaigns if c["status"] == status]

        _store_logger.info("campaigns_read", count=len(campaigns),
                            active_only=active_only, status=status)
        return campaigns[:limit]

    def get_campaign(self, attack_chain_id: str,
                     now: datetime = None) -> Optional[dict]:
        """Return a single campaign by ``attack_chain_id`` (tenant-scoped), or
        None if no chained incidents match for this tenant."""
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        rows = conn.execute(f"""
            SELECT {self._CAMPAIGN_COLS}
            FROM incidents
            WHERE attack_chain_id = %s {tf}
            ORDER BY first_seen ASC
        """, [attack_chain_id] + tp).fetchall()
        if not rows:
            return None
        if now is None:
            now = datetime.now(timezone.utc)
        campaigns = build_campaigns_from_incident_rows([dict(r) for r in rows], now)
        return campaigns[0] if campaigns else None

    def find_open_incident_by_grouping_key(self, grouping_key: str) -> Optional[dict]:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        row = conn.execute(f"""
            SELECT * FROM incidents
            WHERE grouping_key = %s AND status IN ('open', 'investigating')
            {tf}
            ORDER BY last_seen DESC LIMIT 1
        """, [grouping_key] + tp).fetchone()

        return dict(row) if row else None

    def find_open_attack_chain_candidate(self, host: str = None,
                                         user: str = None) -> Optional[dict]:
        """Find the most-recent open incident on the same host or user (M5).

        Returns the single most-recent (ORDER BY last_seen DESC LIMIT 1) open
        incident ('open'|'investigating') whose ``affected_hosts`` JSON array
        contains ``host`` (when given) OR whose ``affected_users`` JSON array
        contains ``user`` (when given). When both are given, a host match is
        preferred; only if no host candidate exists do we fall back to user.

        Tenant-scoped via ``_tenant_filter()`` exactly like
        ``find_open_incident_by_grouping_key`` — a chain MUST NEVER link
        incidents across tenants. Uses Postgres JSONB containment
        (``affected_hosts::jsonb @> %s::jsonb``) on the TEXT columns.
        """
        conn = self._get_conn()
        tf, tp = self._tenant_filter()

        def _lookup(column: str, value: str) -> Optional[dict]:
            row = conn.execute(f"""
                SELECT * FROM incidents
                WHERE status IN ('open', 'investigating')
                  AND {column}::jsonb @> %s::jsonb
                {tf}
                ORDER BY last_seen DESC LIMIT 1
            """, [json.dumps([value])] + tp).fetchone()
            return dict(row) if row else None

        if host:
            candidate = _lookup("affected_hosts", host)
            if candidate:
                return candidate
        if user:
            return _lookup("affected_users", user)
        return None

    def update_incident_status(self, incident_id: str, status: str,
                                actor: str = "system", reason: Optional[str] = None) -> bool:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        if status == "resolved":
            conn.execute(f"""
                UPDATE incidents
                SET status = %s, status_reason = %s,
                    updated_at = CURRENT_TIMESTAMP::text,
                    resolved_at = CURRENT_TIMESTAMP::text
                WHERE id = %s {tf}
            """, [status, reason, incident_id] + tp)
        else:
            conn.execute(f"""
                UPDATE incidents
                SET status = %s, status_reason = %s,
                    updated_at = CURRENT_TIMESTAMP::text
                WHERE id = %s {tf}
            """, [status, reason, incident_id] + tp)
        description = f"Status changed to {status}"
        if reason:
            description += f" — {reason}"
        conn.execute("""
            INSERT INTO incident_timeline (id, incident_id, event_type, description, actor, created_at)
            VALUES (%s, %s, 'status_changed', %s, %s, CURRENT_TIMESTAMP::text)
        """, (str(uuid.uuid4()), incident_id, description, actor))
        conn.commit()

        return True

    def assign_incident(self, incident_id: str, assigned_to: str,
                         actor: str = "system") -> bool:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        conn.execute(f"""
            UPDATE incidents SET assigned_to = %s, updated_at = CURRENT_TIMESTAMP::text
            WHERE id = %s {tf}
        """, [assigned_to, incident_id] + tp)
        conn.execute("""
            INSERT INTO incident_timeline (id, incident_id, event_type, description, actor, created_at)
            VALUES (%s, %s, 'assigned', %s, %s, CURRENT_TIMESTAMP::text)
        """, (str(uuid.uuid4()), incident_id, f"Assigned to {assigned_to}", actor))
        conn.commit()

        return True

    def set_incident_sla(self, incident_id: str, tier: str,
                         sla_response_due: str, sla_resolution_due: str):
        """Set SLA deadlines on an incident."""
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            conn.execute(f"""
                UPDATE incidents SET tier = %s, sla_response_due = %s,
                    sla_resolution_due = %s, updated_at = CURRENT_TIMESTAMP::text
                WHERE id = %s {tf}
            """, [tier, sla_response_due, sla_resolution_due, incident_id] + tp)
            conn.commit()
        except Exception:
            pass  # columns may not exist on older schema

    def record_first_response(self, incident_id: str):
        """Record the first analyst response time (if not already set)."""
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            conn.execute(f"""
                UPDATE incidents SET first_response_at = CURRENT_TIMESTAMP::text,
                    updated_at = CURRENT_TIMESTAMP::text
                WHERE id = %s AND first_response_at IS NULL {tf}
            """, [incident_id] + tp)
            conn.commit()
        except Exception:
            pass

    def escalate_incident_tier(self, incident_id: str, new_tier: str,
                                handoff_notes: str, actor: str,
                                sla_response_due: str = None,
                                sla_resolution_due: str = None):
        """Escalate an incident to a higher tier with handoff notes."""
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            conn.execute(f"""
                UPDATE incidents SET tier = %s, handoff_notes = %s,
                    escalation_count = escalation_count + 1,
                    sla_response_due = COALESCE(%s, sla_response_due),
                    sla_resolution_due = COALESCE(%s, sla_resolution_due),
                    first_response_at = NULL,
                    updated_at = CURRENT_TIMESTAMP::text
                WHERE id = %s {tf}
            """, [new_tier, handoff_notes, sla_response_due,
                  sla_resolution_due, incident_id] + tp)
            conn.execute("""
                INSERT INTO incident_timeline
                (id, incident_id, event_type, description, actor, created_at)
                VALUES (%s, %s, 'escalated', %s, %s, CURRENT_TIMESTAMP::text)
            """, (str(uuid.uuid4()), incident_id,
                  f"Escalated to {new_tier}: {handoff_notes[:200]}",
                  actor))
            conn.commit()
        except Exception:
            pass

    def add_incident_evidence(self, incident_id: str, evidence: dict):
        """Append an evidence entry to the incident's evidence chain."""
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            row = conn.execute(
                f"SELECT evidence_chain FROM incidents WHERE id = %s {tf}",
                [incident_id] + tp
            ).fetchone()
            chain = json.loads((row["evidence_chain"] if row else None) or "[]")
            chain.append(evidence)
            conn.execute(f"""
                UPDATE incidents SET evidence_chain = %s, updated_at = CURRENT_TIMESTAMP::text
                WHERE id = %s {tf}
            """, [json.dumps(chain), incident_id] + tp)
            conn.commit()
        except Exception:
            pass

    def save_sla_breach(self, breach: dict):
        """Record an SLA breach."""
        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT INTO sla_breaches
                (id, incident_id, sla_type, severity, tier, due_at, breached_at, client_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
            """, (
                breach["id"], breach["incident_id"], breach["sla_type"],
                breach["severity"], breach.get("tier", "L1"),
                breach["due_at"], breach["breached_at"],
                breach.get("client_id") or self._tenant_value(),
            ))
            conn.commit()
        except Exception:
            pass

    def get_open_incidents_with_sla(self) -> list[dict]:
        """Get open/investigating incidents that have SLA deadlines."""
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        try:
            rows = conn.execute(f"""
                SELECT * FROM incidents
                WHERE status IN ('open', 'investigating')
                AND (sla_response_due IS NOT NULL OR sla_resolution_due IS NOT NULL)
                {tf}
            """, tp).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def get_sla_breaches(self, incident_id: str) -> list[dict]:
        """Get SLA breaches for an incident."""
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            rows = conn.execute(
                f"SELECT * FROM sla_breaches WHERE incident_id = %s {tf} ORDER BY breached_at",
                [incident_id] + tp
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def add_alert_to_incident(self, incident_id: str, decision_id: str) -> bool:
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO incident_alerts (incident_id, decision_id, added_at)
            VALUES (%s, %s, CURRENT_TIMESTAMP::text)
            ON CONFLICT DO NOTHING
        """, (incident_id, decision_id))
        # Update alert count only (engine manages last_seen via save_incident)
        conn.execute("""
            UPDATE incidents SET
                alert_count = (SELECT COUNT(*) FROM incident_alerts WHERE incident_id = %s),
                updated_at = CURRENT_TIMESTAMP::text
            WHERE id = %s
        """, (incident_id, incident_id))
        conn.execute("""
            INSERT INTO incident_timeline (id, incident_id, event_type, description, actor, created_at)
            VALUES (%s, %s, 'alert_added', %s, 'system', CURRENT_TIMESTAMP::text)
        """, (str(uuid.uuid4()), incident_id, f"Alert {decision_id[:8]} added"))
        conn.commit()

        return True

    def add_incident_note(self, incident_id: str, note: str,
                           actor: str = "system") -> str:
        note_id = str(uuid.uuid4())
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO incident_timeline (id, incident_id, event_type, description, actor, created_at)
            VALUES (%s, %s, 'note_added', %s, %s, CURRENT_TIMESTAMP::text)
        """, (note_id, incident_id, note, actor))
        conn.execute("""
            UPDATE incidents SET updated_at = CURRENT_TIMESTAMP::text WHERE id = %s
        """, (incident_id,))
        conn.commit()

        return note_id

    def add_timeline_entry(self, incident_id: str, event_type: str,
                           description: str, actor: str = "system") -> str:
        """Add a generic timeline entry to an incident."""
        entry_id = str(uuid.uuid4())
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO incident_timeline (id, incident_id, event_type, description, actor, created_at)
            VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP::text)
        """, (entry_id, incident_id, event_type, description, actor))
        conn.execute("""
            UPDATE incidents SET updated_at = CURRENT_TIMESTAMP::text WHERE id = %s
        """, (incident_id,))
        conn.commit()
        return entry_id

    def get_incident_alerts(self, incident_id: str) -> list[dict]:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        rows = conn.execute(f"""
            SELECT ad.* FROM agent_decisions ad
            JOIN incident_alerts ia ON ia.decision_id = ad.id
            WHERE ia.incident_id = %s {tf}
            ORDER BY ad.created_at ASC
        """, [incident_id] + tp).fetchall()

        return [dict(r) for r in rows]

    def get_incident_timeline(self, incident_id: str) -> list[dict]:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        rows = conn.execute(f"""
            SELECT * FROM incident_timeline
            WHERE incident_id = %s
            AND incident_id IN (SELECT id FROM incidents WHERE 1=1 {tf})
            ORDER BY created_at ASC
        """, [incident_id] + tp).fetchall()

        return [dict(r) for r in rows]

    def merge_incidents(self, target_id: str, source_ids: list[str],
                         actor: str = "system") -> bool:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        placeholders = ",".join("%s" for _ in source_ids)
        # Move all alerts from sources to target (FK-scoped via parent incident)
        # Verify source incidents belong to tenant before moving alerts
        conn.execute(f"""
            UPDATE incident_alerts SET incident_id = %s
            WHERE incident_id IN (
                SELECT id FROM incidents WHERE id IN ({placeholders}) {tf}
            )
        """, [target_id] + source_ids + tp)
        # Recompute target stats — use explicit alias instead of brittle string replace
        ad_tf = " AND ad.client_id = %s" if tf else ""
        row = conn.execute(f"""
            SELECT COUNT(*) as cnt,
                   MIN(ad.created_at) as first,
                   MAX(ad.created_at) as last
            FROM incident_alerts ia
            JOIN agent_decisions ad ON ad.id = ia.decision_id
            WHERE ia.incident_id = %s {ad_tf}
        """, [target_id] + tp).fetchone()
        if row['cnt'] and row['cnt'] > 0:
            conn.execute(f"""
                UPDATE incidents SET alert_count = %s, first_seen = %s,
                    last_seen = %s, updated_at = CURRENT_TIMESTAMP::text
                WHERE id = %s {tf}
            """, [row['cnt'], row['first'], row['last'], target_id] + tp)
        else:
            conn.execute(f"""
                UPDATE incidents SET updated_at = CURRENT_TIMESTAMP::text WHERE id = %s {tf}
            """, [target_id] + tp)
        # Close source incidents
        conn.execute(f"""
            UPDATE incidents SET status = 'closed', updated_at = CURRENT_TIMESTAMP::text
            WHERE id IN ({placeholders}) {tf}
        """, source_ids + tp)
        # Timeline entries
        for sid in source_ids:
            conn.execute("""
                INSERT INTO incident_timeline (id, incident_id, event_type, description, actor, created_at)
                VALUES (%s, %s, 'status_changed', %s, %s, CURRENT_TIMESTAMP::text)
            """, (str(uuid.uuid4()), sid, f"Merged into incident {target_id[:8]}", actor))
        conn.execute("""
            INSERT INTO incident_timeline (id, incident_id, event_type, description, actor, created_at)
            VALUES (%s, %s, 'note_added', %s, %s, CURRENT_TIMESTAMP::text)
        """, (str(uuid.uuid4()), target_id,
              f"Merged {len(source_ids)} incident(s): {', '.join(s[:8] for s in source_ids)}", actor))
        conn.commit()

        return True

    # -- Platform Users --

    def save_user(self, user: PlatformUser) -> str:
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO platform_users
            (id, username, password_hash, salt, display_name, email, role,
             is_active, created_at, updated_at, client_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (user.id, user.username, user.password_hash, user.salt,
              user.display_name, user.email, user.role, user.is_active,
              user.created_at, user.updated_at, self._tenant_value()))
        conn.commit()

        return user.id

    def get_user_by_username(self, username: str,
                             allow_unscoped: bool = False) -> Optional[dict]:
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
        except TenantContextRequired:
            if allow_unscoped:
                # Login flow: tenant context not yet available
                structlog.get_logger(__name__).warning(
                    "unscoped_user_lookup",
                    username=username,
                    message="Falling back to unscoped query — "
                            "login before tenant context is set")
                tf, tp = "", []
            else:
                raise
        row = conn.execute(
            f"SELECT * FROM platform_users WHERE username = %s {tf}",
            [username] + tp
        ).fetchone()

        return dict(row) if row else None

    def get_user_by_id(self, user_id: str) -> Optional[dict]:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        row = conn.execute(
            f"SELECT * FROM platform_users WHERE id = %s {tf}",
            [user_id] + tp
        ).fetchone()

        return dict(row) if row else None

    def get_all_users(self, include_inactive: bool = False) -> list[dict]:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        query = ("SELECT id, username, display_name, email, role, is_active, "
                 "created_at, updated_at FROM platform_users")
        if not include_inactive:
            query += f" WHERE is_active = 1 {tf}"
        else:
            query += f" WHERE 1=1 {tf}"
        query += " ORDER BY created_at ASC"
        rows = conn.execute(query, tp).fetchall()

        return [dict(r) for r in rows]

    def update_user(self, user_id: str, fields: dict) -> bool:
        allowed = {"display_name", "email", "role", "is_active",
                   "password_hash", "salt"}
        filtered = {k: v for k, v in fields.items() if k in allowed}
        if not filtered:
            return False
        filtered["updated_at"] = datetime.now(timezone.utc).isoformat()
        set_clause = ", ".join(f"{k} = %s" for k in filtered)
        tf, tp = self._tenant_filter()
        values = list(filtered.values()) + [user_id] + tp
        conn = self._get_conn()
        conn.execute(
            f"UPDATE platform_users SET {set_clause} WHERE id = %s {tf}", values)
        conn.commit()

        return True

    def get_user_count(self) -> int:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        row = conn.execute(
            f"SELECT COUNT(*) as cnt FROM platform_users WHERE 1=1 {tf}", tp).fetchone()

        return row["cnt"] if row else 0

    # -- Audit Log --

    def log_audit(self, actor: str, action: str, target_type: str = "",
                  target_id: str = "", details: dict = None,
                  ip_address: str = "") -> str:
        entry_id = str(uuid.uuid4())
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO audit_log
            (id, actor, action, target_type, target_id, details,
             ip_address, created_at, client_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP::text, %s)
        """, (entry_id, actor, action, target_type, target_id,
              json.dumps(details or {}), ip_address, self._tenant_value()))
        conn.commit()

        return entry_id

    def get_audit_log(self, actor: str = None, action: str = None,
                      limit: int = 200, since: str = None) -> list[dict]:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        query = "SELECT * FROM audit_log WHERE 1=1"
        params = []
        if tf:
            query += tf
            params.extend(tp)
        if actor:
            query += " AND actor = %s"
            params.append(actor)
        if action:
            query += " AND action = %s"
            params.append(action)
        if since:
            query += " AND created_at >= %s"
            params.append(since)
        query += " ORDER BY created_at DESC LIMIT %s"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()

        return [dict(r) for r in rows]

    # -- Active Response Audit (M3) --

    def record_ar_action(self, *, mode: str, action: str, status: str,
                         actor: str = "", target_ip: str = None,
                         agent_id: str = None, alert_id: str = None,
                         decision_id: str = None, incident_id: str = None,
                         ti_evidence: dict = None, gate_snapshot: dict = None,
                         reason: str = "", ttl_seconds: int = None,
                         expires_at: str = None) -> str:
        """Record an active-response action (auto OR manual) for audit.

        Tenant-scoped: client_id comes from the current tenant context.
        Every auto and manual AR action MUST write a row here capturing
        who/what/why/when + the triggering alert/decision + TI evidence.
        """
        entry_id = str(uuid.uuid4())
        # M3 fix: store created_at as an ISO timestamp (T separator), matching
        # _iso_ago() and the rest of the store family. CURRENT_TIMESTAMP::text
        # renders a SPACE separator, which broke string/timestamptz comparisons
        # against ISO values in the rate-cap count (' ' < 'T' lexically).
        created_at = datetime.now(timezone.utc).isoformat()
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO active_response_audit
            (id, client_id, mode, action, status, actor, target_ip, agent_id,
             alert_id, decision_id, incident_id, ti_evidence, gate_snapshot,
             reason, ttl_seconds, expires_at, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s)
        """, (entry_id, self._tenant_value(), mode, action, status, actor,
              target_ip, agent_id, alert_id, decision_id, incident_id,
              json.dumps(ti_evidence or {}), json.dumps(gate_snapshot or {}),
              reason, ttl_seconds, expires_at, created_at))
        conn.commit()
        return entry_id

    def count_auto_blocks_in_window(self, since: str) -> int:
        """Count durable, executed auto-blocks for the current tenant since
        ``since`` (ISO timestamp). Backs the gate's rolling rate cap so the
        count survives a process restart (table-based, not in-memory)."""
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        row = conn.execute(f"""
            SELECT COUNT(*) AS cnt FROM active_response_audit
            WHERE mode = 'auto' AND action = 'block_ip'
              AND status = 'executed'
              AND created_at::timestamptz >= %s::timestamptz {tf}
        """, [since] + tp).fetchone()
        return row["cnt"] if row else 0

    def get_ar_audit(self, limit: int = 200, status: str = None,
                     mode: str = None, active_only: bool = False) -> list[dict]:
        """List active-response audit rows for the current tenant."""
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        query = "SELECT * FROM active_response_audit WHERE 1=1"
        params = []
        if tf:
            query += tf
            params.extend(tp)
        if status:
            query += " AND status = %s"
            params.append(status)
        if mode:
            query += " AND mode = %s"
            params.append(mode)
        if active_only:
            # Active = executed or pending and not yet reversed. NOTE: the auto
            # QUEUE_FOR_HUMAN path writes status 'pending_approval' (not the
            # never-written 'queued_for_human' literal), so we match that here.
            query += (" AND status IN ('executed', 'pending_approval')"
                      " AND reversed_at IS NULL")
        query += " ORDER BY created_at DESC LIMIT %s"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_ar_action(self, action_id: str) -> dict | None:
        """Fetch a single AR audit row (tenant-scoped)."""
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        row = conn.execute(
            f"SELECT * FROM active_response_audit WHERE id = %s {tf}",
            [action_id] + tp).fetchone()
        return dict(row) if row else None

    def mark_ar_reversed(self, action_id: str, reversed_by: str) -> bool:
        """Mark an AR action reversed (tenant-scoped). Returns True if a row
        was updated."""
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        # M3 fix: write reversed_at as an ISO timestamp (T separator) to keep
        # all AR timestamps consistent for any future timestamptz comparison.
        reversed_at = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(f"""
            UPDATE active_response_audit
            SET status = 'reversed', reversed_at = %s,
                reversed_by = %s
            WHERE id = %s {tf}
        """, [reversed_at, reversed_by, action_id] + tp)
        conn.commit()
        return cur.rowcount > 0

    def get_analyst_stats(self, username: str, hours: int = 24) -> dict:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        cutoff = self._iso_ago(hours=hours)
        row = conn.execute(f"""
            SELECT COUNT(*) as reviews_done FROM agent_decisions
            WHERE human_override = %s
              AND resolved_at >= %s {tf}
        """, [username, cutoff] + tp).fetchone()
        reviews = row["reviews_done"] if row else 0

        row2 = conn.execute(f"""
            SELECT COUNT(*) as resolved FROM incident_timeline t
            JOIN incidents i ON t.incident_id = i.id
            WHERE t.actor = %s AND t.event_type = 'status_changed'
              AND t.description LIKE '%%resolved%%'
              AND t.created_at >= %s
              {"AND i.client_id = %s" if tf else ""}
        """, [username, cutoff] + tp).fetchone()
        resolved = row2["resolved"] if row2 else 0

        row3 = conn.execute(f"""
            SELECT COUNT(*) as assigned FROM incidents
            WHERE assigned_to = %s AND status IN ('open', 'investigating') {tf}
        """, [username] + tp).fetchone()
        assigned = row3["assigned"] if row3 else 0

        return {
            "reviews_today": reviews,
            "incidents_resolved_today": resolved,
            "assigned_open": assigned,
        }

    # -- Threat Intelligence --

    def upsert_ioc(self, ioc: dict) -> str:
        """Insert or update a single IOC. Returns the IOC id."""
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        ioc_id = ioc.get("id", str(uuid.uuid4()))
        conn.execute("""
            INSERT INTO threat_intel_iocs
            (id, ioc_type, ioc_value, source, severity, confidence, category,
             malware_family, description, reference_url, tags,
             first_seen, last_seen, expires_at, is_active, raw_data,
             created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT(ioc_type, ioc_value, source) DO UPDATE SET
                severity = excluded.severity,
                confidence = GREATEST(threat_intel_iocs.confidence, EXCLUDED.confidence),
                category = COALESCE(excluded.category, threat_intel_iocs.category),
                malware_family = COALESCE(excluded.malware_family, threat_intel_iocs.malware_family),
                description = COALESCE(excluded.description, threat_intel_iocs.description),
                reference_url = COALESCE(excluded.reference_url, threat_intel_iocs.reference_url),
                tags = excluded.tags,
                last_seen = excluded.last_seen,
                expires_at = excluded.expires_at,
                is_active = 1,
                raw_data = excluded.raw_data,
                updated_at = excluded.updated_at
        """, (
            ioc_id, ioc["ioc_type"], ioc["ioc_value"], ioc["source"],
            ioc.get("severity", "medium"), ioc.get("confidence", 50),
            ioc.get("category"), ioc.get("malware_family"),
            ioc.get("description"), ioc.get("reference_url"),
            json.dumps(ioc.get("tags", [])),
            ioc.get("first_seen", now), ioc.get("last_seen", now),
            ioc.get("expires_at"), 1,
            json.dumps(ioc.get("raw_data", {})),
            now, now
        ))
        conn.commit()
        return ioc_id

    def upsert_iocs_batch(self, iocs: list) -> int:
        """Batch insert/update IOCs in a single transaction. Returns count."""
        if not iocs:
            return 0
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        rows = []
        for ioc in iocs:
            rows.append((
                ioc.get("id", str(uuid.uuid4())),
                ioc["ioc_type"], ioc["ioc_value"], ioc["source"],
                ioc.get("severity", "medium"), ioc.get("confidence", 50),
                ioc.get("category"), ioc.get("malware_family"),
                ioc.get("description"), ioc.get("reference_url"),
                json.dumps(ioc.get("tags", [])),
                ioc.get("first_seen", now), ioc.get("last_seen", now),
                ioc.get("expires_at"), 1,
                json.dumps(ioc.get("raw_data", {})),
                now, now
            ))
        # psycopg v3 Connection has no executemany — only Cursor does.
        with conn.cursor() as cur:
            cur.executemany("""
                INSERT INTO threat_intel_iocs
                (id, ioc_type, ioc_value, source, severity, confidence, category,
                 malware_family, description, reference_url, tags,
                 first_seen, last_seen, expires_at, is_active, raw_data,
                 created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(ioc_type, ioc_value, source) DO UPDATE SET
                    severity = EXCLUDED.severity,
                    confidence = GREATEST(threat_intel_iocs.confidence, EXCLUDED.confidence),
                    category = COALESCE(EXCLUDED.category, threat_intel_iocs.category),
                    malware_family = COALESCE(EXCLUDED.malware_family, threat_intel_iocs.malware_family),
                    description = COALESCE(EXCLUDED.description, threat_intel_iocs.description),
                    reference_url = COALESCE(EXCLUDED.reference_url, threat_intel_iocs.reference_url),
                    tags = EXCLUDED.tags,
                    last_seen = EXCLUDED.last_seen,
                    expires_at = EXCLUDED.expires_at,
                    is_active = 1,
                    raw_data = EXCLUDED.raw_data,
                    updated_at = EXCLUDED.updated_at
            """, rows)
        conn.commit()
        return len(rows)

    def lookup_ioc(self, value: str) -> list:
        """Look up an IOC value across all types and sources."""
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM threat_intel_iocs
            WHERE ioc_value = %s AND is_active = 1
            ORDER BY confidence DESC
        """, (value,)).fetchall()
        return [dict(r) for r in rows]

    def lookup_iocs_batch(self, values: list) -> dict:
        """Batch lookup multiple IOC values. Returns {value: [matches]}.

        Queries both the global threat_intel_iocs table and the
        tenant-scoped local_iocs table so admin-added IOCs are matched.
        """
        if not values:
            return {}
        conn = self._get_conn()
        placeholders = ",".join("%s" for _ in values)
        rows = conn.execute(f"""
            SELECT * FROM threat_intel_iocs
            WHERE ioc_value IN ({placeholders}) AND is_active = 1
            ORDER BY confidence DESC
        """, values).fetchall()
        result = {}
        for r in rows:
            d = dict(r)
            result.setdefault(d["ioc_value"], []).append(d)
        # Also check tenant-scoped local_iocs
        try:
            tf, tp = self._tenant_filter()
            local_rows = conn.execute(f"""
                SELECT * FROM local_iocs
                WHERE value IN ({placeholders}) {tf}
            """, list(values) + tp).fetchall()
            for r in local_rows:
                d = dict(r)
                result.setdefault(d["value"], []).append({
                    "ioc_value": d["value"],
                    "ioc_type": d["ioc_type"],
                    "source": "local",
                    "severity": d.get("severity", "medium"),
                    "confidence": 100,
                    "description": d.get("description", ""),
                })
        except Exception:
            pass  # local_iocs table may not exist on older schemas
        return result

    def get_ioc_stats(self) -> dict:
        """Get aggregate IOC statistics for the dashboard."""
        conn = self._get_conn()
        total = conn.execute(
            "SELECT COUNT(*) as c FROM threat_intel_iocs WHERE is_active = 1"
        ).fetchone()["c"]

        by_source = conn.execute("""
            SELECT source, COUNT(*) as count FROM threat_intel_iocs
            WHERE is_active = 1 GROUP BY source ORDER BY count DESC
        """).fetchall()

        by_type = conn.execute("""
            SELECT ioc_type, COUNT(*) as count FROM threat_intel_iocs
            WHERE is_active = 1 GROUP BY ioc_type ORDER BY count DESC
        """).fetchall()

        by_severity = conn.execute("""
            SELECT severity, COUNT(*) as count FROM threat_intel_iocs
            WHERE is_active = 1 GROUP BY severity ORDER BY count DESC
        """).fetchall()

        return {
            "total_iocs": total,
            "by_source": [dict(r) for r in by_source],
            "by_type": [dict(r) for r in by_type],
            "by_severity": [dict(r) for r in by_severity],
        }

    def update_feed_status(self, feed_name: str, *,
                           status: str = None, error: str = None,
                           ioc_count: int = None, feed_url: str = None,
                           feed_type: str = None, tier: int = None,
                           requires_api_key: bool = None,
                           interval_minutes: int = None):
        """Update or create a feed status record."""
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        existing = conn.execute(
            "SELECT id FROM threat_intel_feeds WHERE feed_name = %s",
            (feed_name,)
        ).fetchone()

        if existing:
            updates = ["updated_at = %s"]
            params = [now]
            if status is not None:
                updates.append("status = %s")
                params.append(status)
            if error is not None:
                updates.append("last_error = %s")
                params.append(error)
                updates.append("error_count = error_count + 1")
            if ioc_count is not None:
                updates.append("last_ioc_count = %s")
                params.append(ioc_count)
                updates.append("total_ioc_count = total_ioc_count + %s")
                params.append(ioc_count)
                updates.append("last_fetch_at = %s")
                params.append(now)
                updates.append("last_success_at = %s")
                params.append(now)
                updates.append("error_count = 0")
            params.append(feed_name)
            conn.execute(
                f"UPDATE threat_intel_feeds SET {', '.join(updates)} WHERE feed_name = %s",
                params
            )
        else:
            conn.execute("""
                INSERT INTO threat_intel_feeds
                (id, feed_name, feed_url, feed_type, tier, enabled,
                 requires_api_key, collection_interval_minutes,
                 status, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, 1, %s, %s, %s, %s, %s)
            """, (
                str(uuid.uuid4()), feed_name,
                feed_url or "", feed_type or "bulk_json",
                tier or 1, int(requires_api_key or False),
                interval_minutes or 360,
                status or "pending", now, now
            ))
        conn.commit()

    def get_feed_statuses(self) -> list:
        """Get all feed status records."""
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM threat_intel_feeds ORDER BY feed_name
        """).fetchall()
        return [dict(r) for r in rows]

    def upsert_cve(self, cve: dict):
        """Insert or update a CVE record."""
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        conn.execute("""
            INSERT INTO threat_intel_cve
            (cve_id, description, severity, cvss_score, epss_score,
             epss_percentile, in_cisa_kev, kev_date_added, kev_due_date,
             kev_ransomware, vendor, product, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT(cve_id) DO UPDATE SET
                description = COALESCE(excluded.description, threat_intel_cve.description),
                severity = COALESCE(excluded.severity, threat_intel_cve.severity),
                cvss_score = COALESCE(excluded.cvss_score, threat_intel_cve.cvss_score),
                epss_score = COALESCE(excluded.epss_score, threat_intel_cve.epss_score),
                epss_percentile = COALESCE(excluded.epss_percentile, threat_intel_cve.epss_percentile),
                in_cisa_kev = GREATEST(threat_intel_cve.in_cisa_kev, EXCLUDED.in_cisa_kev),
                kev_date_added = COALESCE(excluded.kev_date_added, threat_intel_cve.kev_date_added),
                kev_due_date = COALESCE(excluded.kev_due_date, threat_intel_cve.kev_due_date),
                kev_ransomware = GREATEST(threat_intel_cve.kev_ransomware, EXCLUDED.kev_ransomware),
                vendor = COALESCE(excluded.vendor, threat_intel_cve.vendor),
                product = COALESCE(excluded.product, threat_intel_cve.product),
                updated_at = excluded.updated_at
        """, (
            cve["cve_id"], cve.get("description"), cve.get("severity"),
            cve.get("cvss_score"), cve.get("epss_score"),
            cve.get("epss_percentile"), int(cve.get("in_cisa_kev", False)),
            cve.get("kev_date_added"), cve.get("kev_due_date"),
            int(cve.get("kev_ransomware", False)),
            cve.get("vendor"), cve.get("product"), now
        ))
        conn.commit()

    def lookup_cve(self, cve_id: str) -> dict:
        """Look up a single CVE record."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM threat_intel_cve WHERE cve_id = %s", (cve_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_kev_cves(self, limit: int = 100) -> list:
        """Get CISA KEV entries."""
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM threat_intel_cve WHERE in_cisa_kev = 1
            ORDER BY kev_date_added DESC LIMIT %s
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_all_cves(self, limit: int = 100) -> list:
        """Get all CVE entries (KEV and non-KEV)."""
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM threat_intel_cve
            ORDER BY updated_at DESC LIMIT %s
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    def cleanup_expired_iocs(self) -> int:
        """Deactivate IOCs past their expiry date. Returns count."""
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        cursor = conn.execute("""
            UPDATE threat_intel_iocs SET is_active = 0, updated_at = %s
            WHERE expires_at IS NOT NULL AND expires_at < %s AND is_active = 1
        """, (now, now))
        conn.commit()
        return cursor.rowcount

    # -- Ticketing Integration --

    def save_ticket(self, ticket: dict) -> str:
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        ticket_id = ticket.get("id", str(uuid.uuid4()))
        try:
            conn.execute("""
                INSERT INTO tickets
                (id, incident_id, provider, external_id, external_url,
                 external_status, platform_status, summary, description,
                 priority, assigned_to_external, metadata, sync_direction,
                 last_synced_at, sync_error, retry_count, created_by,
                 created_at, updated_at, client_id)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (id) DO UPDATE SET
                    incident_id          = EXCLUDED.incident_id,
                    provider             = EXCLUDED.provider,
                    external_id          = EXCLUDED.external_id,
                    external_url         = EXCLUDED.external_url,
                    external_status      = EXCLUDED.external_status,
                    platform_status      = EXCLUDED.platform_status,
                    summary              = EXCLUDED.summary,
                    description          = EXCLUDED.description,
                    priority             = EXCLUDED.priority,
                    assigned_to_external = EXCLUDED.assigned_to_external,
                    metadata             = EXCLUDED.metadata,
                    sync_direction       = EXCLUDED.sync_direction,
                    last_synced_at       = EXCLUDED.last_synced_at,
                    sync_error           = EXCLUDED.sync_error,
                    retry_count          = EXCLUDED.retry_count,
                    created_by           = EXCLUDED.created_by,
                    created_at           = EXCLUDED.created_at,
                    updated_at           = EXCLUDED.updated_at,
                    client_id            = EXCLUDED.client_id
            """, (
                ticket_id, ticket["incident_id"], ticket["provider"],
                ticket.get("external_id"), ticket.get("external_url"),
                ticket.get("external_status"),
                ticket.get("platform_status", "pending"),
                ticket["summary"], ticket.get("description", ""),
                ticket.get("priority", "medium"),
                ticket.get("assigned_to_external"),
                json.dumps(ticket.get("metadata", {})),
                ticket.get("sync_direction", "outbound"),
                ticket.get("last_synced_at"),
                ticket.get("sync_error"),
                ticket.get("retry_count", 0),
                ticket.get("created_by", "system"),
                ticket.get("created_at", now),
                now,
                ticket.get("client_id") or self._tenant_value(),
            ))
            conn.commit()
            return ticket_id
        except Exception as e:
            structlog.get_logger(__name__).warning(
                "ticket_save_failed", error=str(e))
            return ticket_id

    def get_ticket(self, ticket_id: str) -> dict:
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            row = conn.execute(
                f"SELECT * FROM tickets WHERE id = %s {tf}", [ticket_id] + tp
            ).fetchone()
            return dict(row) if row else {}
        except Exception:
            return {}

    def get_ticket_by_external_id(self, provider: str,
                                  external_id: str) -> Optional[dict]:
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            row = conn.execute(
                f"SELECT * FROM tickets WHERE provider = %s AND external_id = %s {tf}",
                [provider, external_id] + tp
            ).fetchone()
            return dict(row) if row else None
        except Exception:
            return None

    def get_tickets(self, incident_id: str = None, provider: str = None,
                    status: str = None, limit: int = 100) -> list[dict]:
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            q = "SELECT * FROM tickets WHERE 1=1"
            params = list(tp)
            if tf:
                q += tf
            if incident_id:
                q += " AND incident_id = %s"
                params.append(incident_id)
            if provider:
                q += " AND provider = %s"
                params.append(provider)
            if status:
                q += " AND platform_status = %s"
                params.append(status)
            q += " ORDER BY created_at DESC LIMIT %s"
            params.append(limit)
            return [dict(r) for r in conn.execute(q, params).fetchall()]
        except Exception:
            return []

    def get_tickets_for_incident(self, incident_id: str) -> list[dict]:
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            rows = conn.execute(
                f"SELECT * FROM tickets WHERE incident_id = %s {tf} ORDER BY created_at DESC",
                [incident_id] + tp
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    _TICKET_UPDATE_COLS = frozenset({
        "external_id", "external_url", "platform_status", "external_status",
        "priority", "assigned_to_external", "metadata", "sync_direction",
        "last_synced_at", "sync_error", "retry_count", "summary",
    })

    def update_ticket(self, ticket_id: str, **kwargs):
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            sets = ["updated_at = CURRENT_TIMESTAMP::text"]
            params = []
            for k, v in kwargs.items():
                if k not in self._TICKET_UPDATE_COLS:
                    continue
                sets.append(f"{k} = %s")
                params.append(v)
            params.append(ticket_id)
            params.extend(tp)
            conn.execute(
                f"UPDATE tickets SET {', '.join(sets)} WHERE id = %s {tf}",
                params)
            conn.commit()
        except Exception:
            pass

    def get_tickets_needing_sync(self) -> list[dict]:
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            q = """SELECT * FROM tickets
                   WHERE platform_status IN ('created','synced')
                   AND external_id IS NOT NULL"""
            params = list(tp)
            if tf:
                q += tf
            q += " ORDER BY last_synced_at ASC LIMIT 100"
            return [dict(r) for r in conn.execute(q, params).fetchall()]
        except Exception:
            return []

    def get_tickets_needing_retry(self, max_retries: int = 3) -> list[dict]:
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            q = """SELECT * FROM tickets
                   WHERE platform_status = 'error'
                   AND retry_count < %s"""
            params: list = [max_retries]
            params.extend(tp)
            if tf:
                q += tf
            q += " ORDER BY updated_at ASC LIMIT 50"
            return [dict(r) for r in conn.execute(q, params).fetchall()]
        except Exception:
            return []

    def save_ticket_sync_log(self, entry: dict) -> str:
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        entry_id = entry.get("id", str(uuid.uuid4()))
        try:
            conn.execute("""
                INSERT INTO ticket_sync_log
                (id, ticket_id, direction, event_type, old_value, new_value,
                 details, created_at, client_id)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                entry_id, entry["ticket_id"], entry["direction"],
                entry["event_type"], entry.get("old_value"),
                entry.get("new_value"),
                json.dumps(entry.get("details", {})),
                entry.get("created_at", now),
                entry.get("client_id") or self._tenant_value(),
            ))
            conn.commit()
            return entry_id
        except Exception as e:
            structlog.get_logger(__name__).warning(
                "ticket_sync_log_save_failed", error=str(e))
            return entry_id

    def get_ticket_sync_log(self, ticket_id: str,
                            limit: int = 50) -> list[dict]:
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            rows = conn.execute(
                f"SELECT * FROM ticket_sync_log WHERE ticket_id = %s {tf} "
                "ORDER BY created_at DESC LIMIT %s",
                [ticket_id] + tp + [limit]
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def get_ticket_stats(self) -> dict:
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            total = conn.execute(
                f"SELECT COUNT(*) AS cnt FROM tickets WHERE 1=1 {tf}", tp
            ).fetchone()["cnt"]
            synced = conn.execute(
                f"SELECT COUNT(*) AS cnt FROM tickets WHERE platform_status IN ('created','synced') {tf}", tp
            ).fetchone()["cnt"]
            pending = conn.execute(
                f"SELECT COUNT(*) AS cnt FROM tickets WHERE platform_status = 'pending' {tf}", tp
            ).fetchone()["cnt"]
            errors = conn.execute(
                f"SELECT COUNT(*) AS cnt FROM tickets WHERE platform_status = 'error' {tf}", tp
            ).fetchone()["cnt"]
            closed = conn.execute(
                f"SELECT COUNT(*) AS cnt FROM tickets WHERE platform_status = 'closed' {tf}", tp
            ).fetchone()["cnt"]
            by_provider = {}
            for row in conn.execute(
                f"SELECT provider, COUNT(*) AS cnt FROM tickets WHERE 1=1 {tf} GROUP BY provider", tp
            ).fetchall():
                by_provider[row["provider"]] = row["cnt"]
            return {
                "total": total, "synced": synced, "pending": pending,
                "errors": errors, "closed": closed,
                "by_provider": by_provider,
            }
        except Exception:
            return {"total": 0, "synced": 0, "pending": 0,
                    "errors": 0, "closed": 0, "by_provider": {}}

    # -- Knowledge Base --

    def save_kb_document(self, doc: dict) -> str:
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        doc_id = doc.get("id", str(uuid.uuid4()))
        try:
            conn.execute("""
                INSERT INTO kb_documents
                (id, doc_type, title, content, tags, mitre_techniques,
                 source_id, source_type, created_by,
                 created_at, updated_at, client_id)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (id) DO UPDATE SET
                    doc_type         = EXCLUDED.doc_type,
                    title            = EXCLUDED.title,
                    content          = EXCLUDED.content,
                    tags             = EXCLUDED.tags,
                    mitre_techniques = EXCLUDED.mitre_techniques,
                    source_id        = EXCLUDED.source_id,
                    source_type      = EXCLUDED.source_type,
                    created_by       = EXCLUDED.created_by,
                    created_at       = EXCLUDED.created_at,
                    updated_at       = EXCLUDED.updated_at,
                    client_id        = EXCLUDED.client_id
            """, (
                doc_id, doc["doc_type"], doc["title"], doc["content"],
                json.dumps(doc.get("tags", [])),
                json.dumps(doc.get("mitre_techniques", [])),
                doc.get("source_id"), doc.get("source_type"),
                doc.get("created_by", "system"),
                doc.get("created_at", now), now,
                doc.get("client_id") or self._tenant_value(),
            ))
            conn.commit()
            return doc_id
        except Exception as e:
            structlog.get_logger(__name__).warning(
                "kb_doc_save_failed", error=str(e))
            return doc_id

    def get_kb_document(self, doc_id: str) -> Optional[dict]:
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            row = conn.execute(
                f"SELECT * FROM kb_documents WHERE id = %s {tf}", [doc_id] + tp
            ).fetchone()
            return dict(row) if row else None
        except Exception:
            return None

    def get_kb_documents(self, doc_type: str = None,
                         limit: int = 50) -> list[dict]:
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            q = "SELECT * FROM kb_documents WHERE 1=1"
            params = list(tp)
            if tf:
                q += tf
            if doc_type:
                q += " AND doc_type = %s"
                params.append(doc_type)
            q += " ORDER BY updated_at DESC LIMIT %s"
            params.append(limit)
            return [dict(r) for r in conn.execute(q, params).fetchall()]
        except Exception:
            return []

    _KB_UPDATE_COLS = frozenset({
        "title", "content", "doc_type", "severity", "tags",
        "mitre_techniques", "source_id", "source_type",
    })

    def update_kb_document(self, doc_id: str, **kwargs) -> bool:
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            sets = ["updated_at = CURRENT_TIMESTAMP::text"]
            params = []
            for k, v in kwargs.items():
                if k not in self._KB_UPDATE_COLS:
                    continue
                if k == "tags" and isinstance(v, list):
                    v = json.dumps(v)
                if k == "mitre_techniques" and isinstance(v, list):
                    v = json.dumps(v)
                sets.append(f"{k} = %s")
                params.append(v)
            params.append(doc_id)
            params.extend(tp)
            conn.execute(
                f"UPDATE kb_documents SET {', '.join(sets)} WHERE id = %s {tf}",
                params)
            conn.commit()
            return True
        except Exception:
            return False

    def delete_kb_document(self, doc_id: str) -> bool:
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            conn.execute(f"DELETE FROM kb_documents WHERE id = %s {tf}", [doc_id] + tp)
            conn.commit()
            return True
        except Exception:
            return False

    def delete_kb_by_type(self, doc_type: str) -> int:
        """Delete all KB documents of a given type (for guidance refresh)."""
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            q = "DELETE FROM kb_documents WHERE doc_type = %s"
            params = [doc_type]
            if tf:
                q += tf
                params.extend(tp)
            cursor = conn.execute(q, params)
            conn.commit()
            return cursor.rowcount
        except Exception:
            return 0

    @staticmethod
    def _escape_tsquery(query: str) -> str:
        """Escape user input for safe ``to_tsquery`` calls.

        tsquery's grammar is different from FTS5 MATCH: it has its own
        operators ``& | ! ( ) : *`` and treats most punctuation as
        token boundaries. We strip the operator characters, drop empty
        tokens, and join multi-word input with ``&`` (AND semantics —
        matches the FTS5 default we were getting through the wrapping
        double-quote phrase form).
        """
        # Strip tsquery operators and quoting marks before tokenizing.
        for ch in '&|!():*"\'\\':
            query = query.replace(ch, " ")
        words = [w for w in query.split() if w]
        # Empty input — to_tsquery rejects '', return a no-match sentinel.
        return " & ".join(words) if words else "_no_match_token_"

    def search_kb(self, query: str, doc_type: str = None,
                  tags: list = None, limit: int = 10) -> list[dict]:
        """Full-text search via Postgres tsvector with ts_rank ordering."""
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            sql = """
                SELECT kb.*, ts_rank(kb.search_tsv, q) AS rank
                FROM kb_documents kb, to_tsquery('english', %s) q
                WHERE kb.search_tsv @@ q
            """
            params: list = [self._escape_tsquery(query)]
            if tf:
                sql += " AND kb.client_id = %s"
                params.extend(tp)
            if doc_type:
                sql += " AND kb.doc_type = %s"
                params.append(doc_type)
            if tags:
                for tag in tags:
                    safe_tag = tag.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                    sql += " AND kb.tags LIKE %s ESCAPE '\\'"
                    params.append(f"%{safe_tag}%")
            sql += " ORDER BY rank DESC LIMIT %s"
            params.append(limit)
            return [dict(r) for r in conn.execute(sql, params).fetchall()]
        except Exception as e:
            _store_logger.warning("search_kb_failed", query=query[:50], error=str(e))
            return []

    def get_kb_by_source(self, source_type: str,
                         source_id: str) -> Optional[dict]:
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            row = conn.execute(
                f"SELECT * FROM kb_documents WHERE source_type = %s AND source_id = %s {tf}",
                [source_type, source_id] + tp
            ).fetchone()
            return dict(row) if row else None
        except Exception:
            return None

    def get_kb_stats(self) -> dict:
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            total = conn.execute(
                f"SELECT COUNT(*) AS cnt FROM kb_documents WHERE 1=1 {tf}", tp
            ).fetchone()["cnt"]
            by_type = {}
            for row in conn.execute(
                f"SELECT doc_type, COUNT(*) AS cnt FROM kb_documents WHERE 1=1 {tf} GROUP BY doc_type", tp
            ).fetchall():
                by_type[row["doc_type"]] = row["cnt"]
            return {"total": total, "by_type": by_type}
        except Exception:
            return {"total": 0, "by_type": {}}

    def get_hunt_finding(self, finding_id: str) -> Optional[dict]:
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            row = conn.execute(
                f"SELECT * FROM hunt_findings WHERE id = %s {tf}",
                [finding_id] + tp
            ).fetchone()
            return dict(row) if row else None
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Settings panel: Assets
    # ------------------------------------------------------------------

    def save_asset(self, asset: dict) -> str:
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        asset_id = asset.get("id", str(uuid.uuid4()))
        # Conflict target is (hostname, client_id): callers generate a fresh
        # UUID id every save, so de-duplication has to ride on the business
        # unique index. UPDATE leaves id unchanged so downstream FKs survive.
        conn.execute("""
            INSERT INTO assets
            (id, hostname, tier, owner, environment, criticality_multiplier,
             tags, services, created_at, updated_at, client_id)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (hostname, client_id) DO UPDATE SET
                tier                   = EXCLUDED.tier,
                owner                  = EXCLUDED.owner,
                environment            = EXCLUDED.environment,
                criticality_multiplier = EXCLUDED.criticality_multiplier,
                tags                   = EXCLUDED.tags,
                services               = EXCLUDED.services,
                updated_at             = EXCLUDED.updated_at
        """, (
            asset_id, asset["hostname"], asset.get("tier", "unknown"),
            asset.get("owner", "unknown"), asset.get("environment", "unknown"),
            asset.get("criticality_multiplier", 1.0),
            json.dumps(asset.get("tags", [])),
            json.dumps(asset.get("services", [])),
            asset.get("created_at", now), now,
            asset.get("client_id") or self._tenant_value(),
        ))
        conn.commit()
        return asset_id

    def get_assets(self, limit: int = 500) -> list[dict]:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        q = f"SELECT * FROM assets WHERE 1=1 {tf} ORDER BY hostname ASC LIMIT %s"
        params = list(tp) + [limit]
        rows = conn.execute(q, params).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["tags"] = json.loads(d.get("tags") or "[]")
            d["services"] = json.loads(d.get("services") or "[]")
            result.append(d)
        return result

    _ASSET_UPDATE_COLS = frozenset({
        "tier", "owner", "environment", "criticality_multiplier",
        "tags", "services",
    })

    def update_asset(self, asset_id: str, **kwargs) -> bool:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        sets = ["updated_at = CURRENT_TIMESTAMP::text"]
        params = []
        for k, v in kwargs.items():
            if k not in self._ASSET_UPDATE_COLS:
                continue
            if k in ("tags", "services") and isinstance(v, list):
                v = json.dumps(v)
            sets.append(f"{k} = %s")
            params.append(v)
        if len(sets) == 1:
            return False
        params.append(asset_id)
        params.extend(tp)
        conn.execute(
            f"UPDATE assets SET {', '.join(sets)} WHERE id = %s {tf}", params)
        conn.commit()
        return True

    def delete_asset(self, asset_id: str) -> bool:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        conn.execute(f"DELETE FROM assets WHERE id = %s {tf}", [asset_id] + tp)
        conn.commit()
        return True

    def get_assets_as_dict(self) -> dict:
        """Return {hostname: asset_dict} for enricher reload."""
        assets = self.get_assets(limit=10000)
        return {a["hostname"]: a for a in assets}

    # ------------------------------------------------------------------
    # Settings panel: Identities
    # ------------------------------------------------------------------

    def save_identity(self, identity: dict) -> str:
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        identity_id = identity.get("id", str(uuid.uuid4()))
        # Conflict target is (username, client_id) — same dedup rationale as
        # save_asset.
        conn.execute("""
            INSERT INTO identities
            (id, username, risk_level, risk_multiplier, is_admin,
             is_service_account, roles, department, known_ips,
             onboarded_date, created_at, updated_at, client_id)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (username, client_id) DO UPDATE SET
                risk_level         = EXCLUDED.risk_level,
                risk_multiplier    = EXCLUDED.risk_multiplier,
                is_admin           = EXCLUDED.is_admin,
                is_service_account = EXCLUDED.is_service_account,
                roles              = EXCLUDED.roles,
                department         = EXCLUDED.department,
                known_ips          = EXCLUDED.known_ips,
                onboarded_date     = EXCLUDED.onboarded_date,
                updated_at         = EXCLUDED.updated_at
        """, (
            identity_id, identity["username"],
            identity.get("risk_level", "standard"),
            identity.get("risk_multiplier", 1.0),
            1 if identity.get("is_admin") else 0,
            1 if identity.get("is_service_account") else 0,
            json.dumps(identity.get("roles", [])),
            identity.get("department", "unknown"),
            json.dumps(identity.get("known_ips", [])),
            identity.get("onboarded_date"),
            identity.get("created_at", now), now,
            identity.get("client_id") or self._tenant_value(),
        ))
        conn.commit()
        return identity_id

    def get_identities(self, limit: int = 500) -> list[dict]:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        q = f"SELECT * FROM identities WHERE 1=1 {tf} ORDER BY username ASC LIMIT %s"
        params = list(tp) + [limit]
        rows = conn.execute(q, params).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["roles"] = json.loads(d.get("roles") or "[]")
            d["known_ips"] = json.loads(d.get("known_ips") or "[]")
            d["is_admin"] = bool(d.get("is_admin"))
            d["is_service_account"] = bool(d.get("is_service_account"))
            result.append(d)
        return result

    _IDENTITY_UPDATE_COLS = frozenset({
        "risk_level", "risk_multiplier", "is_admin", "is_service_account",
        "roles", "department", "known_ips", "onboarded_date",
    })

    def update_identity(self, identity_id: str, **kwargs) -> bool:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        sets = ["updated_at = CURRENT_TIMESTAMP::text"]
        params = []
        for k, v in kwargs.items():
            if k not in self._IDENTITY_UPDATE_COLS:
                continue
            if k in ("roles", "known_ips") and isinstance(v, list):
                v = json.dumps(v)
            if k in ("is_admin", "is_service_account"):
                v = 1 if v else 0
            sets.append(f"{k} = %s")
            params.append(v)
        if len(sets) == 1:
            return False
        params.append(identity_id)
        params.extend(tp)
        conn.execute(
            f"UPDATE identities SET {', '.join(sets)} WHERE id = %s {tf}", params)
        conn.commit()
        return True

    def delete_identity(self, identity_id: str) -> bool:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        conn.execute(
            f"DELETE FROM identities WHERE id = %s {tf}", [identity_id] + tp)
        conn.commit()
        return True

    def get_identities_as_dict(self) -> dict:
        """Return {username: identity_dict} for enricher reload."""
        identities = self.get_identities(limit=10000)
        return {i["username"]: i for i in identities}

    # ------------------------------------------------------------------
    # Settings panel: Local IOCs
    # ------------------------------------------------------------------

    def save_local_ioc(self, ioc: dict) -> str:
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        ioc_id = ioc.get("id", str(uuid.uuid4()))
        # Conflict target is (value, ioc_type, client_id) — same dedup
        # rationale as save_asset.
        conn.execute("""
            INSERT INTO local_iocs
            (id, ioc_type, value, severity, description,
             created_at, updated_at, client_id)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (value, ioc_type, client_id) DO UPDATE SET
                severity    = EXCLUDED.severity,
                description = EXCLUDED.description,
                updated_at  = EXCLUDED.updated_at
        """, (
            ioc_id, ioc["ioc_type"], ioc["value"],
            ioc.get("severity", "medium"),
            ioc.get("description", ""),
            ioc.get("created_at", now), now,
            ioc.get("client_id") or self._tenant_value(),
        ))
        conn.commit()
        return ioc_id

    def get_local_iocs(self, ioc_type: str = None,
                       limit: int = 500) -> list[dict]:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        q = "SELECT * FROM local_iocs WHERE 1=1"
        params = list(tp)
        if tf:
            q += tf
        if ioc_type:
            q += " AND ioc_type = %s"
            params.append(ioc_type)
        q += " ORDER BY updated_at DESC LIMIT %s"
        params.append(limit)
        return [dict(r) for r in conn.execute(q, params).fetchall()]

    def delete_local_ioc(self, ioc_id: str) -> bool:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        conn.execute(
            f"DELETE FROM local_iocs WHERE id = %s {tf}", [ioc_id] + tp)
        conn.commit()
        return True

    def get_local_iocs_as_dict(self) -> dict:
        """Return {value: ioc_dict} for enricher reload."""
        iocs = self.get_local_iocs(limit=10000)
        return {
            i["value"]: {
                "source": "local",
                "type": i["ioc_type"],
                "severity": i.get("severity", "medium"),
                "description": i.get("description", ""),
            }
            for i in iocs
        }

    def lookup_local_iocs_batch(self, values: list) -> dict:
        """Batch lookup local IOCs. Returns {value: [matches]}."""
        if not values:
            return {}
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        placeholders = ",".join("%s" for _ in values)
        rows = conn.execute(f"""
            SELECT * FROM local_iocs
            WHERE value IN ({placeholders}) {tf}
        """, list(values) + tp).fetchall()
        result = {}
        for r in rows:
            d = dict(r)
            result.setdefault(d["value"], []).append({
                "source": "local",
                "ioc_value": d["value"],
                "ioc_type": d["ioc_type"],
                "severity": d.get("severity", "medium"),
                "confidence": 100,
                "description": d.get("description", ""),
            })
        return result
