"""
Database layer for DHRUVA.
PostgreSQL via psycopg v3 for agent decisions, feedback tracking, and operational metrics.
Schema lifecycle is owned by Alembic — see src/database/migrations/.
"""

import contextlib
import contextvars
import hashlib
import ipaddress
import os
import json
import re
import structlog
import threading
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, asdict

import psycopg
from psycopg import errors as pg_errors
from psycopg.pq import TransactionStatus
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from src.timestamps import parse_iso8601, parse_iso8601_or_none

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


# N3 (2026-07-10 re-audit): the WO-H12-followup RLS boot gate only runs at
# STARTUP. Multi-tenant mode can also flip on at RUNTIME when a 2nd tenant is
# added (see admin._recompute_multi_tenant_mode). If the DB role is a
# superuser/BYPASSRLS one, that runtime flip would enter multi-tenant operation
# with the RLS backstop silently inactive until the next restart. This flag is
# set by the runtime recompute when it detects that condition, logged loudly, and
# surfaced (informationally) by /api/health — WITHOUT flipping health to 503,
# because a 503 would trigger a pod restart that the startup gate would then
# crash-loop on.
_rls_backstop_degraded: bool = False


def set_rls_backstop_degraded(degraded: bool):
    """Record whether the RLS tenant backstop is inactive while in multi-tenant
    mode (runtime detection). Idempotent; logs on transition to degraded."""
    global _rls_backstop_degraded
    if degraded and not _rls_backstop_degraded:
        _store_logger.error("rls_backstop_degraded",
                            detail="multi-tenant mode is active but Postgres RLS "
                                   "is NOT in effect (superuser/BYPASSRLS role or "
                                   "FORCE RLS missing) — the DB-layer tenant "
                                   "backstop is inactive. App-layer isolation "
                                   "still applies. Fix: connect DHRUVA as a "
                                   "NON-superuser, NON-BYPASSRLS role (see "
                                   "docs/MULTI-TENANT.md) and restart.")
    _rls_backstop_degraded = degraded


def is_rls_backstop_degraded() -> bool:
    """True if multi-tenant mode is active but RLS is not actually enforcing."""
    return _rls_backstop_degraded


def _advisory_key(name: str) -> int:
    """Map a job/lock name to a stable signed 64-bit key for Postgres
    ``pg_advisory_lock`` family functions (they take a ``bigint``).

    blake2b(8-byte digest) -> signed 64-bit int. Deterministic across
    processes/replicas so the SAME name always contends for the SAME lock,
    which is what makes it a distributed leader-election / mutex key.
    """
    digest = hashlib.blake2b(name.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big", signed=True)


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
            # WO-H90: left silent on purpose. This is the documented default of a
            # parse helper (see the docstring): malformed JSON in one column is a
            # data shape, not an incident, and it is read per row on every list
            # endpoint. Logging it would say nothing an on-call person can act on.
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
    returns None on null/non-string/malformed input (never raises).

    WO-H116: delegates to the shared version-independent parser. These rows are
    written by several producers — our own ``isoformat()``, Postgres'
    ``CURRENT_TIMESTAMP::text`` (two-digit offset) and Wazuh (``+0000``) — and
    the last two are rejected by ``fromisoformat`` on Python < 3.11.

    WO-H90: still silent on purpose. Documented pure/defensive parse: a
    malformed timestamp yields None and the caller already treats None as
    'unknown'. Runs per row on every campaign/incident read.
    """
    if not ts:
        return None
    return parse_iso8601_or_none(ts)


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

    # ACTIVE first, then worst severity, then longest dwell — matches the
    # mockup's "2 advancing · 1 contained" worst-first campaign map ordering.
    #
    # WO-H47: status leads the sort key. It previously sorted on
    # (severity, dwell) ALONE, so a CONTAINED critical campaign outranked an
    # ACTIVE medium one. Callers truncate this list (the API defaults to
    # limit=100), so on a real install with 930 campaigns / 3 active, the
    # active ones landed at ranks 10, 244 and 440 — two of them fell outside
    # the window entirely and became invisible. Ranking active first means a
    # live campaign can never be pushed off the end by closed history, whatever
    # limit the caller passes.
    campaigns.sort(
        key=lambda c: (
            c.get("status") == "active",
            c["severity_rank"],
            c.get("dwell_seconds") or 0,
        ),
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
        # WO-H90: left silent on purpose. Documented pure/defensive parse: an
        # unparseable address is simply not internal. Runs per field per alert,
        # and there is nothing to do about a junk IP in a log line.
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


#: DEFAULT ``application_name`` reported to Postgres on every connection DHRUVA
#: opens — pooled and advisory-lock alike. Operators filter pg_stat_activity on
#: it before running a migration (docs/DB-MAINTENANCE.md); on a shared cluster
#: that is the difference between "DHRUVA is holding a transaction open" and
#: "some other application is".
#:
#: A DEFAULT, not an override: see ``SOCDatabase._application_name``. An
#: operator running two DHRUVA processes against one cluster (which two of our
#: own installs do) needs to tell them apart, and forcing this value would take
#: that away.
_APPLICATION_NAME = "dhruva"


class TenantContextRequired(PermissionError):
    """Raised when a tenant-scoped query runs without tenant context."""
    pass


class TransactionConnectionLost(RuntimeError):
    """The connection carrying an open ``SOCDatabase._txn`` block died mid-block.

    Raised INSTEAD of transparently swapping in a fresh pooled connection
    (WO-H98 follow-up). ``_get_conn`` normally recovers from a dead session by
    retiring the connection and drawing another — correct for a standalone
    statement, and the PR #119 behaviour that must stay. But a store method may
    call ``_get_conn`` again from INSIDE a ``_txn`` block (``save_decision`` ->
    ``mark_alert_processed`` is the live example), and there a silent swap hands
    the callee a DIFFERENT connection, outside the transaction: the first write
    dies with the old session while the second commits on the new one.

    QA reproduced exactly that with a real ``pg_terminate_backend`` between
    ``save_decision``'s two writes — the decision was rolled back, the
    ``processed_alerts`` checkpoint committed, and ``save_decision`` RETURNED
    NORMALLY. That alert is marked handled forever and is never triaged again,
    which is the outcome the WO-H9 comment in ``save_decision`` says is
    impossible.

    Failing loudly is the safe half of that trade: the caller retries the alert.
    """


class SOARRateLimitUnavailable(Exception):
    """We could not establish how many times a playbook has run recently.

    Raised to FAIL CLOSED by ``count_recent_soar_executions``, and deliberately
    distinct from a count of ``0`` (which is a real answer: nothing ran).

    The two used to collapse into the same ``0`` (WO-H90 made the failure
    audible but left the value alone; WO-H91 changes it). That count IS the
    per-playbook rate limit in ``src/soar/engine.py``:
    ``if recent >= max_executions_per_hour: continue``. A failed count read as
    "nothing ran recently", so the ceiling lifted and playbooks could keep
    triggering with no limit — under the standing rule that active response is
    human-approved by default and every action must be auditable.

    A caller holding this exception knows only that the ceiling is UNKNOWN. It
    must not treat that as headroom. There is deliberately no numeric sentinel:
    the caller has to be able to tell "we counted N" from "we could not count".
    """


class TenantListUnavailable(Exception):
    """We could not establish which tenants are active.

    Raised to FAIL CLOSED by ``get_active_tenants``, and deliberately distinct
    from an empty list (a real answer: no tenant is active).

    Same collapse as ``TenantRecordUnavailable``, one method away (WO-H91 QA
    D2). It became load-bearing when ``_seed_default_tenant`` started deciding
    whether to boot WITHOUT tenant context based on that list: a failed read
    presented as "no tenants exist" would be acted on as fact.

    Callers that legitimately treat an empty list as "nothing to do" keep doing
    that on ``[]``. They must NOT treat this exception the same way.

    Every existing caller already sits inside a ``try/except``, and MOST of
    them degrade to the safe side ("no tenants processed" / "lookup failed" /
    a narrowed cycle). Two do not, and they are named here so the next person
    does not take this paragraph as a clean bill of health:

      * ``main.py:294`` — ``except Exception: set_multi_tenant_mode(False)``.
        Degrades to the UNSAFE side: it turns multi-tenant isolation OFF and
        skips the WO-H12 RLS boot gate immediately below it. This is NOT new
        and NOT caused by the raise — the pre-existing ``[]`` return produced
        ``len([]) > 1 == False`` and the identical call, so reachability is
        byte-equivalent. Left alone deliberately: it is a security default,
        which is the operator's call, and it is filed as its own gated WO.
      * ``src/api/routes/llm_usage.py:186`` — degrades to a 500. No leak, but
        not "safe" either; it is an mssp_admin reporting endpoint.
    """


class TenantRecordUnavailable(Exception):
    """We could not establish whether a tenant exists.

    Raised to FAIL CLOSED by ``get_tenant``, and deliberately distinct from a
    tenant that is genuinely not there (``get_tenant`` returns ``{}`` for that,
    and only when the database positively said so).

    The two used to collapse into the same ``{}`` (WO-H91). That empty dict
    walked straight past the fail-closed guard in
    ``TenantServiceRegistry._get_config`` — which exists precisely because an
    empty config "would flow into get_wazuh_client and silently fall back to
    GLOBAL creds, breaking tenant isolation". The guard covered the DECRYPT
    failure path; a failed READ went around it.

    Callers that legitimately treat absence as "no such tenant" / "start fresh"
    keep doing that on ``{}``. They must NOT treat this exception the same way.
    """

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

#: WO-H124 QA (M-2). `normalize_alert` defaults a missing host to the literal
#: string "unknown" (src/enrichment/service.py) — the line above it uses the
#: correct `or None` pattern for agent_ip, and this one does not. Persisting
#: "unknown" would make it a CORRELATION KEY: every agentless alert on the
#: estate buckets together under one host in idx_decisions_agent_name_created,
#: and "did anything else happen on this host?" starts corroborating unrelated
#: syslog and API alerts. That is the WO-H123 failure shape arriving through a
#: default string. Fixing it at source is a platform-wide behaviour change and
#: is filed separately; the COLUMN refuses the sentinel here.
_HOST_SENTINELS = frozenset({"", "unknown", "none", "null", "n/a", "-"})


def _coerce_host(value):
    """The host, or None — never a placeholder that can act as a join key."""
    if value is None:
        return None
    text = str(value).strip()
    return None if text.casefold() in _HOST_SENTINELS else text


def _coerce_rule_level(value):
    """WO-H124. An int, or None — never 0 as a stand-in for "unknown".

    Wazuh levels are 0..16 and a real 0 exists (informational), so a bad value
    cannot be squashed into the valid range. Anything unparseable becomes NULL,
    which the schema and every consumer read as "not recorded".
    """
    if value is None:
        return None
    try:
        level = int(value)
    except (TypeError, ValueError):
        _store_logger.warning("rule_level_unparseable", value=str(value)[:40])
        return None
    if not 0 <= level <= 16:
        # Not clamped — clamping 99 to 16 would invent a vendor severity.
        _store_logger.warning("rule_level_out_of_range", value=level)
        return None
    return level


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
    # WO-H46-b: True when the LLM call failed and this row is the fail-closed
    # escalation rather than a real verdict. The verdict/escalated fields are
    # deliberately unchanged (still needs_investigation + escalated) so the
    # safety behaviour is identical — this flag only makes the failure
    # queryable, alertable, and excludable from FP statistics.
    llm_failed: bool = False
    # WO-H97 Phase 1 — SHADOW FIELDS. The model has been answering both of
    # these on every alert since the prompt was written
    # (src/agents/prompts/__init__.py); nothing ever read them, so nobody knows
    # whether the answers are any good. They are stored now, WIRED TO NOTHING,
    # so the question can be settled on real production traffic instead of
    # opinion — the same discipline WO-H71 applied to enrichment multipliers.
    #
    # NULL means "we asked before we were listening" (or the model omitted the
    # key, or it answered something outside the schema). It NEVER means "low
    # urgency" / "recon". Do not coalesce these to a default.
    #
    # Severity does NOT read them: src/incidents/severity.py takes the risk
    # score and structured alert facts only. Deriving severity from
    # response_urgency is Phase 2, and only if a measurement earns it.
    response_urgency: Optional[str] = None
    kill_chain_stage: Optional[str] = None
    # WO-H124. The Wazuh rule level, and the host, as COLUMNS.
    #
    # Both were already known at triage time and neither was persisted: the
    # level was dropped outright, and the host survived only inside the
    # `enrichment_summary` JSON blob. That cost a build — WO-H123 wanted "did
    # another level-10+ alert fire on this host?", could not ask it,
    # substituted DHRUVA's own `escalated` flag, and measured a 0.94 base rate.
    #
    # NULL on `rule_level` means "recorded before we listened". It does NOT
    # mean level 0 — coalescing it to 0 makes every historical alert the
    # quietest possible rule, which is the opposite of the truth for the loud
    # ones. Same discipline as the shadow fields above.
    rule_level: Optional[int] = None
    agent_name: Optional[str] = None

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
# WO-H8 — structural tenant-isolation backstop
# ---------------------------------------------------------------------------
# Tenant separation is otherwise 100% developer discipline: every DAO query must
# manually append ``{tf}`` from ``_tenant_filter()``. A future ``conn.execute(
# "SELECT * FROM incidents")`` with no filter would silently return ALL tenants'
# rows — no error, no failing test. This backstop closes that hole structurally:
# every ``conn.execute()`` (DAO methods AND the ~20 raw-SQL routes, all of which
# go through ``_get_conn()``) is intercepted, and a SELECT/UPDATE/DELETE that
# touches a tenant-scoped table without a tenant predicate — and without the
# explicit cross-tenant sentinel — is refused fail-closed.
#
# This is a query-wrapper/assertion backstop at the APP layer — fail-LOUD: it
# raises so a forgotten filter surfaces in tests/logs. It is a regex heuristic,
# so it treats any ``*_id = X`` as tenant-confining and CANNOT catch a query
# filtered only on a SHARED id (technique_id, rule_id, …). WO-H12 adds Postgres
# Row-Level Security (migration 0006 + the ``app.tenant_id`` session GUC applied
# in _get_conn) as the DB-layer safety net that DOES close that class — even a
# raw ``SELECT * FROM incidents`` returns only the session tenant's rows. Both
# layers are active: H8 fail-loud in the app, RLS fail-silent-but-safe in the
# engine. RLS only takes effect when DHRUVA connects as a NON-superuser,
# non-BYPASSRLS role (see migration 0006 / docs/MULTI-TENANT.md §RLS).

# Identifiers named right after FROM / JOIN / UPDATE / INTO — the tables a
# statement reads or writes. Deliberately simple: it over-matches harmlessly
# (only the intersection with TENANT_SCOPED_TABLES is acted on).
_SQL_TABLE_RE = re.compile(
    r'\b(?:FROM|JOIN|UPDATE|INTO)\s+"?([a-z_][a-z0-9_]*)"?', re.IGNORECASE)

# A tenant-scoping predicate: an equality / IN / IS on ``client_id`` /
# ``tenant_id`` or on any globally-unique ``id`` / ``*_id`` column. A UUID PK/FK
# equality confines a statement to rows transitively owned by one tenant, so it
# counts as scoped — this mirrors the DAO's real patterns (``WHERE id = %s`` PK
# writes, ``{tf}`` = ``AND client_id = %s``, ``kb.client_id = %s`` joins).
_SQL_TENANT_PREDICATE_RE = re.compile(
    r'(?<![\w.])(?:[a-z_][a-z0-9_]*\.)?(?:id|[a-z0-9_]*_id)\s*(?:=|\bin\b|\bis\b)',
    re.IGNORECASE)

# INSERT is out of scope: it writes a single tenant's row and cannot leak a
# cross-tenant READ; tenant assignment on write is handled by the DAO's
# ``_tenant_value()`` safety net. Skipping it also avoids false-positives on
# ``INSERT ... ON CONFLICT DO UPDATE`` upserts.
_SQL_IS_INSERT_RE = re.compile(r'\s*INSERT\b', re.IGNORECASE)


def _assert_tenant_scoped_query(sql) -> None:
    """Fail-closed backstop run before every ``conn.execute()`` (WO-H8).

    Raises :class:`TenantContextRequired` when a SELECT/UPDATE/DELETE touches a
    tenant-scoped table (``SOCDatabase.TENANT_SCOPED_TABLES``) but carries no
    tenant predicate and is not running under the explicit cross-tenant sentinel
    (``cross_tenant()``). Non-tenant / global tables, INSERTs, the sentinel path,
    and non-string queries all pass through untouched.
    """
    if not isinstance(sql, str):
        return  # psycopg.sql.Composed etc. — DAO never uses these for tenant IO
    if _tenant_ctx.get() == _CROSS_TENANT:
        return  # explicit, audited cross-tenant access (admin / scheduler)
    scoped = {t.lower() for t in _SQL_TABLE_RE.findall(sql)} \
        & SOCDatabase.TENANT_SCOPED_TABLES
    if not scoped:
        return  # no direct tenant-scoped table in play
    if _SQL_IS_INSERT_RE.match(sql):
        return  # single-row write, not a cross-tenant read/mutate-by-filter
    if _SQL_TENANT_PREDICATE_RE.search(sql):
        return  # carries a client_id / tenant_id / id-equality predicate
    _store_logger.error(
        "tenant_backstop_blocked_query",
        tables=sorted(scoped),
        sql=" ".join(sql.split())[:200],
    )
    raise TenantContextRequired(
        f"Tenant-scoped query on {sorted(scoped)} has no tenant predicate and "
        "no cross-tenant context — refusing to run it (it could return or "
        "modify other tenants' rows). Add a client_id filter via "
        "_tenant_filter(), scope by a UUID id, or wrap the call in "
        "db.cross_tenant() for a deliberate global operation."
    )


class _GuardedConnection:
    """Thin proxy over a psycopg connection that runs the WO-H8 tenant backstop
    on every ``.execute()`` before delegating.

    Everything else (``cursor``, ``transaction``, ``close``, attribute access,
    context-manager) passes straight through to the wrapped connection, so the
    ~130 existing ``conn.execute(...).fetchall()`` call sites and the raw-SQL
    routes are unaffected except for the guard.

    ``commit`` and ``rollback`` are the one exception (WO-H98). psycopg REFUSES
    an explicit ``commit()``/``rollback()`` inside a ``conn.transaction()``
    block — it raises ``ProgrammingError`` — and a store method that commits is
    now sometimes called from inside one (``mark_alert_processed`` from
    ``save_decision``, for instance). Rather than audit every one of the ~80
    commit call sites for who might one day call them, the guard drops the call
    when a ``SOCDatabase._txn`` block is open ON THIS CONNECTION: that block
    owns the transaction boundary and will commit or roll back on the way out.

    "On this connection", not merely "on this thread": if the two ever differ,
    this connection is NOT the one the block will commit, so dropping its commit
    would lose the write outright. Identity is the safe test — with no block
    open on it, the call goes straight through, unchanged.
    """

    __slots__ = ("_conn", "_store")

    def __init__(self, conn, store=None):
        object.__setattr__(self, "_conn", conn)
        object.__setattr__(self, "_store", store)

    def _in_txn_block(self) -> bool:
        store = self._store
        if store is None:
            return False
        return store._txn_open_on(self._conn)

    def execute(self, query, params=None, *args, **kwargs):
        _assert_tenant_scoped_query(query)
        if params is None:
            return self._conn.execute(query, *args, **kwargs)
        return self._conn.execute(query, params, *args, **kwargs)

    def commit(self):
        if self._in_txn_block():
            return
        return self._conn.commit()

    def rollback(self):
        if self._in_txn_block():
            return
        return self._conn.rollback()

    def cursor(self, *args, **kwargs):
        # Cursor-level execute bypasses the guard by design: the only cursor
        # paths are non-tenant (liveness probes, alembic_version, the shared
        # threat_intel_iocs executemany bulk-load).
        return self._conn.cursor(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def __enter__(self):
        self._conn.__enter__()
        return self

    def __exit__(self, *exc):
        return self._conn.__exit__(*exc)


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
        "llm_budget_reservations",
        "decision_cache",
    })

    # Tables scoped via FK join to a scoped parent (no direct client_id filter).
    # WO-H85 adds decision_reviews — scoped through decision_id →
    # agent_decisions (migration 0013 installs the matching subquery RLS policy).
    FK_SCOPED_TABLES = frozenset({
        "incident_alerts", "incident_timeline", "decision_reviews",
    })

    # Tables that are intentionally shared across tenants
    SHARED_TABLES = frozenset({
        "tenants", "platform_users", "schema_migrations", "revoked_tokens",
        "threat_intel_iocs", "threat_intel_cve", "threat_intel_feeds",
        "soar_playbooks",  # NULL client_id = shared default
    })

    # Fallback pool size when neither the constructor arg, config, nor the
    # DB_POOL_SIZE env var provides one.
    DEFAULT_POOL_SIZE = 20

    def __init__(self, dsn_or_path: str | None = None, *,
                 pool_size: int | None = None):
        """Open a connection pool to Postgres.

        DSN resolution order:
          1) ``DATABASE_URL`` env var (always wins if set).
          2) The positional argument, if it looks like a libpq URI.
          3) Hard fail with a v4.9.0 cutover pointer — SQLite is gone.

        ``dsn_or_path`` is kept as a loose first arg so existing callers don't
        break at import time before Phase 4 threads a ``database.dsn`` config
        field through. Operators on Phase 2 must export ``DATABASE_URL``.

        Pool-size resolution order (WO-H28): explicit ``pool_size`` arg (from
        ``database.pool_size`` in config.yaml) → ``DB_POOL_SIZE`` env var →
        ``DEFAULT_POOL_SIZE``. Sizing arithmetic — the pool must cover every
        thread that can hold a checkout at once:

            triage workers + scheduler jobs running concurrently
            + API threadpool (FastAPI sync routes, default 40 for anyio,
              but in practice bounded by concurrent dashboard/API requests)
            ≤ pool_size ≤ Postgres max_connections − headroom

        Advisory-lock connections (job_lock / serialized_section) are NOT
        drawn from this pool — they open short dedicated sessions — but they
        DO count against Postgres ``max_connections``, so leave headroom of
        roughly 2 × concurrently-running leader jobs when sizing
        ``max_connections`` (see docs/DB-MAINTENANCE.md).
        """
        self.dsn = self._resolve_dsn(dsn_or_path)
        # ``db_path`` retained for backwards-compat with code that logs it.
        self.db_path = self.dsn
        self._local = threading.local()  # per-thread cached connection
        resolved_pool_size = self._resolve_pool_size(pool_size)
        # min_size=2 keeps the platform responsive on a cold path; max_size
        # caps connection fan-out so a thread storm can't exhaust Postgres
        # max_connections (default 100). The per-thread caching layer means
        # we usually hold one conn per worker thread, well under the cap.
        #
        # WO-H98 — autocommit=True. This pool used to open autocommit=False,
        # and NOTHING closed the transaction that every statement then opened:
        # `_get_conn` caches one connection per THREAD (API threadpool workers,
        # APScheduler workers, triage workers all outlive any single request),
        # and there is no per-request teardown anywhere that could commit or
        # roll back. So a thread's connection went back to resting state INSIDE
        # an open transaction and stayed there, holding an ACCESS SHARE lock on
        # whatever table its last SELECT read. Measured on a live tenant:
        # five connections `idle in transaction`, and three still there with no
        # request in flight, the oldest 54 seconds old. Two consequences:
        #
        #   * `ALTER TABLE` could not get ACCESS EXCLUSIVE, so an Alembic
        #     migration hung — and the blocked DDL then queued every later query
        #     on that table behind itself, degrading the live service. Schema
        #     changes became stop-the-service operations.
        #   * Postgres' `idle_in_transaction_session_timeout` (10min on that server)
        #     killed those sessions server-side, and the next request on that
        #     thread 500'd (the PR #119 symptom; that recovery path stays, it is
        #     correct for server-side kills that happen for other reasons).
        #
        # Under autocommit each statement commits on its own and the connection
        # returns to `idle`, holding no locks. The tenant GUC is UNAFFECTED, and
        # a real hazard goes with it: `set_config('app.tenant_id', …, is_local
        # => false)` is a *transactional* setting, so a ROLLBACK does not clear
        # it — it restores the last COMMITTED value. Measured in psql:
        #
        #   BEGIN; set_config('app.tenant_id','tenant-a',false); COMMIT;
        #   BEGIN; set_config('app.tenant_id','tenant-b',false); ROLLBACK;
        #     -> current_setting('app.tenant_id') = 'tenant-a'   (NOT '')
        #
        # And a committed value was the NORMAL state on the old pool: every
        # write path ended in `conn.commit()`, which committed whatever GUC
        # `_checkout` had set alongside the write. So a pooled connection that
        # had served tenant-a, then been re-scoped to tenant-b, then hit any
        # rollback, went back to enforcing tenant-a's RLS scope while the
        # contextvar still said tenant-b.
        #
        # That did not leak through the store methods — `_tenant_filter` reads
        # the contextvar, not the GUC, so the WHERE clause stayed correct. What
        # it silently misaimed was the RLS BACKSTOP, which exists precisely for
        # the paths the app-level filter does not cover. With no transaction to
        # roll back, the applied scope is simply the scope.
        #
        # Multi-statement writes that need all-or-nothing now say so explicitly
        # via `_txn()` below — they are enumerated there.
        #
        # This also reconciles the two halves of the connection layer: the
        # advisory-lock sessions (`_lock_conn`) have always been autocommit=True
        # for exactly this reason ("no idle-in-transaction while the body runs").
        #
        # prepare_threshold=None disables psycopg's automatic server-side
        # PREPARE (default: prepare a statement after its 5th execution). That
        # cache is per SESSION, and Postgres invalidates a prepared plan when
        # the shape of a table it reads changes — the next execution then fails
        # with
        #
        #   psycopg.errors.FeatureNotSupported: cached plan must not change
        #   result type
        #
        # and KEEPS failing: nothing here deallocates the statement and
        # `_get_conn`'s liveness probe (`SELECT 1`) still succeeds, so the
        # poisoned connection is never retired. FeatureNotSupported is a
        # NotSupportedError, outside every handler in `_get_conn`.
        #
        # That was unreachable before, because DDL could never get its lock.
        # Making migrations possible against a live install is exactly what
        # makes it reachable: measured on the REAL 0015 migration with traffic
        # reading the table it alters, 18 consecutive request failures and the
        # thread never recovered. On an APScheduler triage worker that is triage
        # silently stopping on that thread until the process restarts.
        #
        # The cost is real and was measured, not waved away: every execution
        # re-parses and re-plans. On `get_incidents(limit=20)` against a
        # 20 000-row table, median of 5 x 3000 queries on a local socket:
        #
        #   prepare_threshold=5     403.7 us/query
        #   prepare_threshold=None  572.3 us/query   (+168.6 us, +41.8%)
        #
        # Accepted deliberately. The percentage is the scary-looking number and
        # the absolute one is the relevant one: ~169 us per query means roughly
        # 6 000 queries to lose one second, while a dashboard request issues a
        # handful and a triage decision is dominated by an LLM call measured in
        # hundreds of milliseconds. Against that, a triage worker whose thread
        # stops processing alerts until someone restarts the process is not a
        # trade worth making. On a remote database the RTT dominates further and
        # the relative cost falls.
        #
        # The better fix keeps prepares AND survives DDL: teach the connection
        # layer to retire a connection on FeatureNotSupported and retry once
        # (the statement never executed — the error is raised while revalidating
        # the plan — so a retry is safe). That needs care around `_txn`, where
        # the surrounding transaction is already aborted and the retry must fail
        # the block instead. Filed as follow-up with these numbers attached; it
        # is the thing to do before anyone turns prepares back on.
        # WO-H98: so an operator on a SHARED cluster can tell DHRUVA's backends
        # from everyone else's. The pre-migration check in
        # docs/DB-MAINTENANCE.md filters pg_stat_activity on this; without it a
        # FOREIGN application's idle transaction reads as ours and blocks a
        # migration that was perfectly safe to run. Deferred to
        # `_application_name` so an operator who already set one keeps it.
        self._app_name = self._application_name(self.dsn)
        pool_kwargs = {"row_factory": dict_row, "autocommit": True,
                       "prepare_threshold": None}
        if self._app_name:
            pool_kwargs["application_name"] = self._app_name
        self._pool = ConnectionPool(
            conninfo=self.dsn,
            min_size=2,
            max_size=resolved_pool_size,
            kwargs=pool_kwargs,
            open=True,
        )
        _store_logger.info("db_pool_opened", pool_size=resolved_pool_size)
        self._verify_schema()

    @classmethod
    def _resolve_pool_size(cls, explicit: int | None = None) -> int:
        """Resolve the pool max_size: explicit arg → DB_POOL_SIZE env →
        DEFAULT_POOL_SIZE. Invalid/non-positive values fall through to the
        next source (logged, never fatal — a bad value must not stop boot)."""
        for source, raw in (("config", explicit),
                            ("env:DB_POOL_SIZE", os.environ.get("DB_POOL_SIZE"))):
            if raw in (None, ""):
                continue
            try:
                value = int(raw)
            except (TypeError, ValueError):
                _store_logger.warning("db_pool_size_invalid",
                                      source=source, value=raw)
                continue
            if value <= 0:
                _store_logger.warning("db_pool_size_non_positive",
                                      source=source, value=value)
                continue
            return value
        return cls.DEFAULT_POOL_SIZE

    def assert_pool_covers_threads(self, *, api_threadpool: int,
                                   triage_workers: int,
                                   scheduler_workers: int,
                                   headroom: int = 4) -> dict:
        """Verify the pool can cover every thread that can hold a connection.

        WO-H78. ``_get_conn`` draws a connection from the pool, caches it in
        thread-local storage, and does NOT return it on the happy path — so a
        thread that touches the database owns a connection for its lifetime.
        Saturation is therefore ARITHMETIC, not load: if more threads can touch
        the DB than ``pool_size``, exhaustion is guaranteed and only the timing
        varies.

        The sizing rule was already written in this class's docstring and then
        left to hope — "in practice bounded by concurrent dashboard/API
        requests". In practice it was not. ``db_pool_saturated`` fired
        repeatedly on a live tenant at pool_size=50, because anyio's
        threadpool alone reaches 40 before the scheduler's 21 registered jobs
        and the triage workers are counted.

        This does NOT fix the underlying design; the real fix is moving hot
        paths to ``with pool.connection()`` so connections are returned. What
        it does is convert a silent, intermittent outage — which surfaces as an
        unrelated feature failing with "couldn't get a connection" — into a
        loud, actionable line in the boot log.

        Returns the computed budget so callers can log or surface it.
        """
        needed = api_threadpool + triage_workers + scheduler_workers + headroom
        actual = self._pool.max_size
        budget = {
            "api_threadpool": api_threadpool,
            "triage_workers": triage_workers,
            "scheduler_workers": scheduler_workers,
            "headroom": headroom,
            "required_pool_size": needed,
            "configured_pool_size": actual,
            "sufficient": actual >= needed,
        }
        if actual >= needed:
            _store_logger.info("db_pool_budget_ok", **budget)
        else:
            _store_logger.error(
                "db_pool_budget_insufficient", **budget,
                detail=(
                    "More threads can hold a connection than the pool can "
                    "supply, so exhaustion is guaranteed under load — see "
                    f"WO-H78. Raise database.pool_size to at least {needed} "
                    "(staying under Postgres max_connections), or lower "
                    "api.threadpool_size / the triage max_workers. Until then "
                    "expect 'couldn't get a connection' to surface as "
                    "unrelated features failing."))
        return budget

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
    def _application_name(dsn: str) -> str | None:
        """The ``application_name`` to set on connections, or ``None`` to leave
        whatever the operator already chose.

        Passing it as a psycopg kwarg SILENTLY OVERRIDES a value in the DSN —
        verified: ``DATABASE_URL=...?application_name=operator_set`` still
        reported ``dhruva``. So only supply it when nothing else has. Both the
        libpq ways of setting it are honoured: the DSN itself, and ``PGAPPNAME``.

        Returning ``None`` rather than the DSN's own value keeps this a pure
        "don't touch it" — psycopg then resolves it the normal libpq way.
        """
        try:
            if psycopg.conninfo.conninfo_to_dict(dsn).get("application_name"):
                return None
        except Exception as e:                       # noqa: BLE001
            # An unparseable DSN is not this method's problem to report — the
            # connection attempt right after will say so far more clearly. Fall
            # through to the default rather than failing boot over a label.
            _store_logger.debug("conninfo_parse_failed_for_appname",
                                error=str(e)[:200])
        if os.environ.get("PGAPPNAME"):
            return None
        return _APPLICATION_NAME

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
        """Refuse to start if Alembic hasn't been run, or if the SERVER is too old.

        Alembic owns the schema in v4.9.0 — operators must run
        ``alembic upgrade head`` (wired into install.sh in Phase 5) before
        SOCDatabase will open. Failing closed here is intentional: an empty
        database silently accepting INSERTs has bitten us before.

        WO-H129 adds the server-version floor beside it, deliberately in the
        same place and the same shape. The two failures are the same failure:
        something structural about the database is wrong, and the only reason
        anyone found out late is that nothing checked at boot.

        The version check runs FIRST. On a fresh install against an unsupported
        server, "your PostgreSQL is too old" is the useful message; "run alembic
        upgrade head" would send the operator off to run migrations that cannot
        do their job on that server anyway.
        """
        try:
            with self._pool.connection() as conn:
                self._verify_server_version(conn)
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

    def _verify_server_version(self, conn):
        """WO-H129: enforce the minimum PostgreSQL server version.

        Below the floor and the database is EMPTY -> raise, so a fresh install
        never reaches the state a below-floor tenant did (0018 skipping its host
        backfill, and nothing downstream saying so).

        Below the floor and the database is POPULATED -> record the condition,
        log it at error level, and START. Refusing here would take a live SOC
        offline over a database version, which is a worse outcome than running
        on an old one; ``log_if_unsupported`` (alert loop) and the
        ``db_server_version`` field in ``/api/health`` make sure it stays
        visible instead of scrolling past.

        There is no env-var bypass, on purpose.
        """
        from src.database import pg_version

        verdict = pg_version.check_connection(conn)
        if verdict.ok:
            pg_version.set_unsupported(None)
            _store_logger.info("postgres_version_ok",
                               server_version=verdict.version_text,
                               required_major=verdict.required_major)
            return
        if verdict.action == pg_version.ACTION_REFUSE:
            pg_version.set_unsupported(None)
            _store_logger.error("postgres_version_below_floor_refusing",
                                server_version=verdict.version_text,
                                server_major=verdict.major,
                                required_major=verdict.required_major,
                                has_history=False)
            raise RuntimeError(verdict.message)
        pg_version.set_unsupported(verdict)
        _store_logger.error("postgres_version_unsupported",
                            server_version=verdict.version_text,
                            server_major=verdict.major,
                            required_major=verdict.required_major,
                            has_history=True,
                            runbook=pg_version.UPGRADE_RUNBOOK,
                            detail=verdict.message)

    def set_tenant(self, tenant_id: str):
        """Set the active tenant for query scoping. Called by middleware.
        Uses contextvars for proper async isolation.

        Also pushes the tenant onto this thread's cached connection's
        ``app.tenant_id`` session GUC so Postgres RLS (WO-H12) reflects the
        change immediately. This is best-effort: ``_get_conn`` re-applies the
        GUC on EVERY checkout, and that re-application — not this one — is what
        actually prevents a pooled connection from leaking one tenant's GUC to
        the next request.
        """
        _tenant_ctx.set(tenant_id)
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                self._apply_tenant_guc(conn)
            except Exception:
                # Couldn't re-scope the cached conn — return it to the pool and
                # drop the thread cache so the next _get_conn draws a fresh
                # session (unset GUC = fail-closed), never a stale-GUC leak.
                self._release_cached_conn()

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
        # Keep the cached conn's RLS GUC in step with the contextvar on entry
        # (→ '__CROSS_TENANT__' bypass) and, in finally, back to the restored
        # tenant. _get_conn re-applies on every checkout regardless.
        cur = getattr(self._local, "conn", None)
        if cur is not None:
            try:
                self._apply_tenant_guc(cur)
            except Exception:
                self._release_cached_conn()
        try:
            yield
        finally:
            _tenant_ctx.reset(token)
            cur = getattr(self._local, "conn", None)
            if cur is not None:
                try:
                    self._apply_tenant_guc(cur)
                except Exception:
                    self._release_cached_conn()

    # ── WO-H9: distributed locking (leader election + critical sections) ──
    #
    # These issue raw ``pg_advisory_*`` SELECTs on a DEDICATED connection.
    # They touch NO tenant table, so the WO-H8 tenant-predicate query guard
    # does not apply — advisory locks are GLOBAL by design (leader election
    # and cross-process mutexes are inherently cross-tenant). A dedicated
    # connection is used (not the per-thread cached ``_get_conn``) because a
    # *session* advisory lock lives for the life of its connection; holding it
    # on a throwaway conn keeps the lock scoped exactly to the ``with`` body
    # and never entangles a worker's normal query connection.
    #
    # WO-H28: the lock connection is opened DIRECTLY (psycopg.connect), NOT
    # drawn from the pool. A session advisory lock must keep its connection
    # open for the whole locked body, and leader-job bodies (triage cycle,
    # hunt, TI collection) run for minutes — holding a pool slot hostage that
    # long starves request/worker checkouts under load. Direct sessions keep
    # the pool free; they still count against Postgres max_connections, which
    # is why the pool-sizing arithmetic (see __init__) leaves headroom of
    # ~2 × concurrently-running leader jobs. autocommit=True means no
    # idle-in-transaction while the body runs and no commit choreography;
    # closing the session releases the lock even if the explicit unlock fails.

    def _lock_conn(self):
        """Open a short-lived dedicated session for advisory-lock use."""
        kwargs = {}
        if self._app_name:
            kwargs["application_name"] = self._app_name
        return psycopg.connect(self.dsn, autocommit=True,
                               row_factory=dict_row, **kwargs)

    @contextlib.contextmanager
    def job_lock(self, name: str):
        """Non-blocking leader-election lock via ``pg_try_advisory_lock``.

        Yields ``True`` when THIS process acquired the lock (it is the leader
        for ``name`` and should run the job body) or ``False`` when another
        process/replica already holds it — in which case the caller MUST skip
        the job (do NOT block-then-run, or a second replica double-runs the
        cycle). Exactly-one-runner semantics across replicas.

        Usage:
            with db.job_lock("dhruva:job:triage") as is_leader:
                if not is_leader:
                    return
                ...run the job once...
        """
        key = _advisory_key(name)
        conn = self._lock_conn()
        acquired = False
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_try_advisory_lock(%s) AS locked", (key,))
                acquired = bool(cur.fetchone()["locked"])
            yield acquired
        finally:
            try:
                if acquired:
                    with conn.cursor() as cur:
                        cur.execute("SELECT pg_advisory_unlock(%s)", (key,))
            except Exception as e:                   # noqa: BLE001
                # WO-H90: was a bare `except: pass`. The explicit unlock did not go
                # through. Closing the session just below still releases the lock, so
                # the job is not stuck yet — but if that close fails too, this named
                # job stops running on EVERY replica until Postgres reaps the session,
                # and it looks exactly like a quiet night.
                _store_logger.warning("advisory_unlock_failed",
                                      lock=name,
                                      error=str(e)[:200])
            try:
                # Session end releases the advisory lock even when the
                # explicit unlock above failed.
                conn.close()
            except Exception as e:                   # noqa: BLE001
                # WO-H90: was a bare `except: pass`. Closing this short-lived session
                # IS the backstop that releases the advisory lock, so a failure here is
                # the second half of a job that silently stops running everywhere.
                # debug: on its own it is unremarkable (the session is usually already
                # gone) — the warning above is the one that names the job.
                _store_logger.debug("lock_session_close_failed",
                                    lock=name,
                                    error=str(e)[:200])

    @contextlib.contextmanager
    def serialized_section(self, name: str):
        """Blocking mutex via ``pg_advisory_lock`` for a critical section that
        MUST run one-at-a-time across all threads/processes/replicas.

        Unlike :meth:`job_lock` (which skips when contended), this BLOCKS until
        the lock is granted, so the body always runs — just never concurrently
        with another holder of the same ``name``. Used to make the
        active-response check-then-record sequence atomic so a block cannot
        fire twice for one decision under concurrency (WO-H9 no-double-fire).
        """
        key = _advisory_key(name)
        conn = self._lock_conn()
        locked = False
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_lock(%s)", (key,))
            locked = True
            yield
        finally:
            try:
                if locked:
                    with conn.cursor() as cur:
                        cur.execute("SELECT pg_advisory_unlock(%s)", (key,))
            except Exception as e:                   # noqa: BLE001
                # WO-H90: was a bare `except: pass`. This mutex is what makes the
                # active-response check-then-record atomic. The session close below
                # still releases it; if that fails too, the next active-response
                # decision waits on a lock nobody is holding.
                # The lock NAME is deliberately not logged: serialized_section
                # keys embed a target IP (src/soar/engine.py), which is client
                # data and does not belong in a shared store log. The advisory
                # key hash is enough to correlate two ends of the same lock.
                _store_logger.warning("serialized_section_unlock_failed",
                                      lock_key=key, error=str(e)[:200])
            try:
                # Session end releases the advisory lock even when the
                # explicit unlock above failed.
                conn.close()
            except Exception as e:                   # noqa: BLE001
                # WO-H90: was a bare `except: pass`. Same pair as job_lock: this close
                # is the release backstop for the active-response mutex.
                # Lock name withheld for the same reason as above.
                _store_logger.debug("serialized_section_close_failed",
                                    lock_key=key, error=str(e)[:200])

    def _apply_tenant_guc(self, raw_conn) -> None:
        """Push the current tenant context onto ``raw_conn``'s ``app.tenant_id``
        session GUC so Postgres RLS (WO-H12) scopes every subsequent statement.

        Called on EVERY connection checkout (``_get_conn``) so a pooled
        connection reused across tenants never carries a previous tenant's GUC —
        the value is overwritten to match the live contextvar before any query
        runs. Mapping (mirrors the WO-H8 app-guard semantics):

          * a tenant id           → RLS shows only that tenant's rows
          * ``__CROSS_TENANT__``  → audited cross-tenant bypass (cross_tenant())
          * '' when no context    → RLS matches nothing → fail-closed

        Runs ``set_config('app.tenant_id', <value>, is_local => false)`` (session
        scope, so it persists past the current txn) on the RAW connection: the
        statement touches no tenant table, so it is NOT subject to the WO-H8
        query guard. Raises on failure so the caller (``_checkout``) can fail
        closed by swapping to a fresh, un-scoped session rather than reusing a
        connection that might still hold a prior tenant's committed GUC.
        """
        tid = _tenant_ctx.get()
        if tid == _CROSS_TENANT:
            value = _CROSS_TENANT
        elif not tid:
            value = ""
        else:
            value = tid
        raw_conn.execute("SELECT set_config('app.tenant_id', %s, false)", (value,))

    def verify_rls_active(self, *, probe_table: str = "incidents") -> tuple[bool, str]:
        """Verify Postgres Row-Level Security (WO-H12) can ACTUALLY take effect.

        RLS is silently bypassed when DHRUVA connects as a Postgres SUPERUSER or a
        role with BYPASSRLS — even under ``FORCE ROW LEVEL SECURITY``. This is a
        deterministic, side-effect-free check (WO-H12-followup) that the live
        connection role (a) is neither superuser nor BYPASSRLS, and (b) that FORCE
        RLS is actually enabled on a representative tenant-scoped table (i.e.
        migration 0006 has run). Returns ``(active, reason)``; ``active`` is True
        only if RLS will enforce tenant isolation for this role. Fail-closed: any
        error resolving the state returns ``(False, ...)`` so the startup boot gate
        refuses to run a silently-inactive backstop in multi-tenant mode.
        """
        try:
            conn = self._get_conn()
            row = conn.execute(
                "SELECT rolsuper, rolbypassrls FROM pg_roles "
                "WHERE rolname = current_user"
            ).fetchone()
            if row is None:
                return False, "could not resolve current_user in pg_roles"
            if bool(row["rolsuper"]):
                return False, (
                    "DHRUVA is connected as a Postgres SUPERUSER — superusers BYPASS "
                    "Row-Level Security, so the WO-H12 tenant backstop is INACTIVE. "
                    "Connect as a NON-superuser, NON-BYPASSRLS role."
                )
            if bool(row["rolbypassrls"]):
                return False, (
                    "DHRUVA's DB role has the BYPASSRLS attribute — it skips Row-Level "
                    "Security, so the WO-H12 tenant backstop is INACTIVE. Use a role "
                    "without BYPASSRLS."
                )
            frow = conn.execute(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE relname = %s",
                (probe_table,),
            ).fetchone()
            if frow is None:
                return False, (
                    f"tenant-scoped table {probe_table!r} not found — schema not "
                    "migrated? Run migration 0006."
                )
            if not (bool(frow["relrowsecurity"]) and bool(frow["relforcerowsecurity"])):
                return False, (
                    f"FORCE ROW LEVEL SECURITY is not enabled on {probe_table!r} "
                    f"(enabled={bool(frow['relrowsecurity'])}, "
                    f"forced={bool(frow['relforcerowsecurity'])}) — run migration 0006."
                )
            return True, "RLS active (non-superuser role + FORCE RLS on scoped tables)"
        except Exception as e:  # fail-closed: cannot verify => treat as inactive
            return False, f"could not verify RLS state: {e}"

    def _release_cached_conn(self) -> None:
        """Return this thread's cached raw connection to the pool and clear the
        cache. Used when the GUC could not be (re)applied — the next
        ``_get_conn`` then draws a fresh session with no ``app.tenant_id`` set
        (RLS fail-closed), so a broken conn is never reused with a stale GUC.

        WO-H98: this is the FOURTH retire-and-swap path, and it needs the same
        guard as the three in ``_get_conn``/``_checkout``. Handing a connection
        with an OPEN transaction back to the pool is worse than the others:
        another thread draws it and psycopg_pool rolls it back underneath the
        block that still thinks it owns it.

        Not reachable today — it is called only from ``set_tenant`` and both
        arms of ``cross_tenant`` when ``_apply_tenant_guc`` raises, and none of
        the 14 ``_txn`` bodies (nor ``mark_alert_processed``,
        ``_cascade_resolve_alerts``, ``_count_held_for_human``,
        ``_record_decision_review``) switches tenant. The guard is here because
        the first ``_txn`` body that needs a tenant switch would make it
        reachable silently, and this failure has no symptom until data is wrong.
        """
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            self._refuse_swap_inside_txn(conn, "tenant_guc_reapply_failed")
            try:
                self._pool.putconn(conn)
            except Exception as e:                   # noqa: BLE001
                # WO-H90: was a bare `except: pass`. A connection never made it back
                # to the pool. One is invisible; a steady trickle ends as pool
                # exhaustion, which presents as the whole dashboard hanging rather than
                # as a database error anyone can read.
                _store_logger.warning("pool_putconn_failed",
                                      error=str(e)[:200])
        self._local.conn = None

    # ── WO-H98: explicit transactions on an autocommit pool ──────────────
    #
    # The pool is autocommit (see __init__ for why), so a lone statement is
    # already atomic and needs nothing. What DOES need help is a method that
    # must land two or more writes all-or-nothing — those used to ride the
    # implicit transaction that autocommit=False opened. Every one of them is
    # now wrapped in `_txn()`, which issues a real BEGIN … COMMIT/ROLLBACK.
    #
    # The wrapped write paths (nothing else in the codebase issues 2+ writes
    # under one commit — audited across src/ for this work order):
    #   store.py   save_decision               decision INSERT + processed_alerts
    #                                          checkpoint (commit delegated to
    #                                          mark_alert_processed)
    #              apply_human_override        verdict UPDATE + decision_reviews INSERT
    #              update_incident_status      incidents UPDATE + cascade + timeline INSERT
    #              propagate_incident_verdict   decisions UPDATE + reviews + timeline
    #              assign_incident              incidents UPDATE + timeline INSERT
    #              escalate_incident_tier       incidents UPDATE + timeline INSERT
    #              add_alert_to_incident        incident_alerts INSERT + recount + timeline
    #              add_incident_note            timeline INSERT + incidents touch
    #              add_timeline_entry           timeline INSERT + incidents touch
    #              merge_incidents              6 statements across 3 tables
    #              update_feed_status           UPDATE-else-INSERT upsert
    #              upsert_iocs_batch            one executemany, documented as one txn
    #   pipeline/alert_buffer.py  _quarantine   dead-letter INSERT + buffered DELETE
    #   api/routes/incidents.py   create_or_update_review   read-then-upsert
    #
    # Two multi-write paths are deliberately NOT wrapped, and say why in place:
    # `backfill_null_client_ids` and `prune_expired_rows` both want each
    # statement to stand alone so one bad table does not abort the rest.
    #
    # Each of those keeps its trailing `conn.commit()`. Under autocommit that
    # is a no-op (psycopg's commit() returns immediately when the connection is
    # IDLE), and it means the method is still correct if the pool is ever put
    # back to autocommit=False — where `conn.transaction()` degrades to a
    # SAVEPOINT that would otherwise never be committed.

    @contextlib.contextmanager
    def _txn(self, conn):
        """Run a block of statements as ONE all-or-nothing transaction.

        Delegates to psycopg's own transaction block, and additionally records,
        per thread, that a block is open AND which raw connection it is open on.
        Three things read that:

          * ``_settle_leaked_txn`` — so the transaction this block legitimately
            holds is not mistaken for a leaked one and rolled back;
          * ``_GuardedConnection.commit``/``rollback`` — so a store method that
            commits (``mark_alert_processed``) can be called from inside a block
            without psycopg raising "Explicit commit() forbidden within a
            Transaction context";
          * ``_retire_conn`` — so a connection death inside a block RAISES
            instead of silently swapping in a fresh connection outside it.

        The connection identity matters, not just the depth: a swapped-in
        connection is not the one the block is open on, and dropping ITS commit
        would lose a write outright. Nesting is safe — psycopg turns an inner
        block into a SAVEPOINT.

        ⚠️  NEVER ``await`` inside a ``_txn`` block, and never call one from an
        ``async def`` route body that also awaits. ``txn_depth``/``txn_conn``
        are ``threading.local`` and ``_get_conn`` caches ONE connection per
        thread, so every coroutine running on the event-loop thread shares both.
        Suspending inside a block would let a second coroutine join the first's
        transaction and have its ``commit()`` dropped. Routes that open a block
        must be plain ``def`` (FastAPI then runs them on the threadpool, one
        thread each) — see ``create_or_update_review`` in
        ``src/api/routes/incidents.py``.
        """
        raw = self._raw_conn(conn)
        depth = getattr(self._local, "txn_depth", 0)
        prev = getattr(self._local, "txn_conn", None)
        self._local.txn_depth = depth + 1
        self._local.txn_conn = raw
        try:
            with conn.transaction():
                yield
        finally:
            self._local.txn_depth = depth
            self._local.txn_conn = prev

    @staticmethod
    def _raw_conn(conn):
        """The underlying psycopg connection behind a possible WO-H8 guard.

        An explicit isinstance, NOT ``getattr(conn, "_conn", conn)``: that would
        also unwrap anything else that happens to carry a ``_conn`` attribute
        (a test double, a future wrapper), and silently comparing the wrong
        object is how an identity check turns into a coin flip.
        """
        return conn._conn if isinstance(conn, _GuardedConnection) else conn

    def _txn_open_on(self, conn) -> bool:
        """True when a ``_txn`` block is open on THIS thread AND on THIS raw
        connection. Identity, not just depth — see ``_txn``."""
        if not getattr(self._local, "txn_depth", 0):
            return False
        return getattr(self._local, "txn_conn", None) is self._raw_conn(conn)

    def _refuse_swap_inside_txn(self, conn, reason: str) -> None:
        """Guard in front of every "retire this connection and draw a fresh
        one" path. A no-op in the normal case; raises when the connection
        carries an open ``_txn`` block.

        The retire-and-swap itself is PR #119's recovery and is left exactly
        where and as it was — this only refuses the ONE case where swapping is
        data loss rather than recovery: a fresh connection is outside the
        transaction, so the writes either side of the death land independently.

        The dead connection is deliberately left cached and NOT handed back to
        the pool: the ``_txn`` block on the way out may still issue a ROLLBACK
        against it, and a connection another thread has already checked out is
        not ours to talk to. The next ``_get_conn`` on this thread, outside any
        block, retires it normally.
        """
        if not self._txn_open_on(conn):
            return
        _store_logger.error("txn_connection_lost", reason=reason)
        raise TransactionConnectionLost(
            f"the connection carrying an open transaction was lost ({reason}) "
            f"— refusing to continue on a different connection, which would "
            f"split this transaction in two. Retry the operation."
        )

    def _settle_leaked_txn(self, conn) -> None:
        """Close a transaction nobody is inside any more.

        This is the WO-H98 invariant, enforced rather than assumed: at the top
        of ``_get_conn`` — i.e. at the start of a fresh operation on this
        thread, with no ``_txn()`` block open — the cached connection must be
        ``IDLE``. If it is not, some path left a transaction open, and that is
        precisely what blocks ``ALTER TABLE`` and trips
        ``idle_in_transaction_session_timeout``. Roll it back and say so.

        Deliberately a rollback, not a commit: an unclaimed transaction at this
        point is by definition one that nothing chose to commit, so discarding
        it is the safe reading. It is also, under the autocommit pool, supposed
        to be unreachable — the ``warning`` is there to make a regression
        visible instead of quiet.

        No-ops while a ``_txn()`` block is open ON THIS CONNECTION (a store
        method may legitimately call ``_get_conn`` again from inside one).
        """
        if self._txn_open_on(conn):
            return
        try:
            status = conn.pgconn.transaction_status
        except Exception as e:                       # noqa: BLE001
            # Cannot even read the libpq transaction state — the connection is
            # already gone. Not silence: the liveness probe immediately below
            # is what retires it, and that path logs, but a failure HERE means
            # the invariant this whole work order exists to enforce could not
            # be checked at all, so it gets its own line.
            _store_logger.debug("txn_status_unreadable", error=str(e)[:200])
            return
        if status in (TransactionStatus.INTRANS, TransactionStatus.INERROR):
            # The one condition WO-H98 exists to detect. Under the autocommit
            # pool this is supposed to be unreachable, so reaching it means a
            # write path lost its transaction boundary and DDL is about to
            # start blocking again. Loud on purpose.
            _store_logger.warning("pooled_conn_left_in_transaction",
                                  status=int(status))
            try:
                conn.rollback()
            except Exception as e:                   # noqa: BLE001
                # Could not settle it, so this connection is STILL holding
                # locks. The liveness probe below retires it, but say so at
                # warning: a rollback that fails here is the difference between
                # "detected and fixed" and "detected and still blocking".
                _store_logger.warning("leaked_txn_rollback_failed",
                                      error=str(e)[:200])

    def _checkout(self, conn) -> "_GuardedConnection":
        """Apply the tenant GUC to ``conn`` and wrap it in the WO-H8 guard.

        If applying the GUC fails on a REUSED connection (which could otherwise
        leave a previous tenant's committed session GUC in place → cross-tenant
        leak), discard it and draw a FRESH pool connection: a new session has no
        ``app.tenant_id`` set at all, so RLS fail-closes even if the re-apply on
        the fresh conn also fails.

        The ONE case that is not recoverable by swapping is a connection with an
        open ``_txn`` block on it: a fresh connection is outside that
        transaction, so the writes either side of the death would land
        independently. ``_retire_conn`` raises ``TransactionConnectionLost``
        there instead of swapping.
        """
        try:
            self._apply_tenant_guc(conn)
            return _GuardedConnection(conn, self)
        except TransactionConnectionLost:
            raise
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except:` with no message. The RLS tenant GUC
            # could not be applied to a pooled connection, so it is dropped and a
            # fresh one drawn — recovery is complete and fail-closed.
            # debug, not warning, on purpose: `_checkout` runs on EVERY query, and
            # this is the normal shape of a session Postgres killed server-side.
            # The fresh-conn failure a few lines down is the one worth waking up
            # for, and it already logs.
            _store_logger.debug("tenant_guc_apply_failed_on_reused_conn",
                                error=str(e)[:200])
            # Raises rather than swapping if a _txn block is open on this conn.
            self._refuse_swap_inside_txn(conn, "tenant_guc_apply_failed")
            try:
                self._pool.putconn(conn)
            except Exception as e2:                  # noqa: BLE001
                # WO-H90: was a bare `except: pass`. Handing a connection we already
                # know is unusable back to the pool failed, so that pool slot is gone.
                # Named `e2`: the enclosing handler's `e` must stay bound.
                _store_logger.debug("pool_putconn_failed_on_guc_discard",
                                    error=str(e2)[:200])
            self._local.conn = None
            fresh = self._pool.getconn()
            self._local.conn = fresh
            try:
                self._apply_tenant_guc(fresh)
            except Exception:
                _store_logger.warning("tenant_guc_apply_failed_on_fresh_conn")
            return _GuardedConnection(fresh, self)

    def _get_conn(self) -> psycopg.Connection:
        """Return a per-thread cached psycopg connection drawn from the pool.

        psycopg connections are not thread-safe, so each thread holds its own
        long-lived pooled conn. The pool gates max fan-out and gives us liveness
        checks; the per-thread cache avoids getconn/putconn round-trips on every
        query.

        The raw pooled connection is cached in ``self._local.conn`` (liveness
        probes and ``putconn`` operate on it directly), but callers always get it
        wrapped in a :class:`_GuardedConnection` so the WO-H8 tenant backstop
        runs on every ``.execute()``. Every checkout also (re)applies the WO-H12
        ``app.tenant_id`` RLS GUC via ``_checkout`` so RLS scoping tracks the
        current tenant context and never leaks across pooled reuse.

        Raises :class:`TransactionConnectionLost` — never swaps silently — when
        the connection dies while a ``_txn`` block is open on it. Store methods
        DO call this from inside a block (``save_decision`` ->
        ``mark_alert_processed``), and there a swap is data loss, not recovery.
        """
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            # WO-H98: the cached connection must be resting IDLE between
            # operations, holding no locks. Enforce it before touching it.
            self._settle_leaked_txn(conn)
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                return self._checkout(conn)
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
                #
                # WO-H98: the guard runs FIRST, before the rollback — not after
                # it, where it used to sit. A `_txn` block open on this
                # connection owns the transaction boundary, so rolling back
                # underneath it destroys the block's work with the block still
                # running, and the success branch below returns via `_checkout`
                # without ever reaching the guard.
                #
                # That ordering was safe only by accident: psycopg happens to
                # raise `ProgrammingError: Explicit rollback() forbidden within
                # a Transaction context`, so the rollback always failed and
                # execution always fell through to the guard. Correctness that
                # depends on an undocumented library invariant breaks silently
                # on a version bump. Ordering makes it true by construction, and
                # `test_a_poisoned_conn_inside_a_txn_raises_before_rolling_back`
                # pins it with a rollback that SUCCEEDS.
                self._refuse_swap_inside_txn(conn, "poisoned_transaction")
                try:
                    conn.rollback()
                    with conn.cursor() as cur:
                        cur.execute("SELECT 1")
                    return self._checkout(conn)
                except Exception as e:               # noqa: BLE001
                    # WO-H90: was a bare `except: pass`. Rolling back a connection stuck
                    # in a failed transaction did not rescue it, so it is dropped and a
                    # fresh one drawn. Behaviour deliberately unchanged (this is the PR
                    # #119 recovery path) — this only leaves a trail. debug because
                    # `_get_conn` runs on every request.
                    _store_logger.debug("poisoned_conn_rollback_failed",
                                        error=str(e)[:200])
                try:
                    self._pool.putconn(conn)
                except Exception as e:               # noqa: BLE001
                    # WO-H90: was a bare `except: pass`. Returning the poisoned connection
                    # to the pool failed, so that pool slot leaks.
                    _store_logger.debug("pool_putconn_failed_on_poisoned_conn",
                                        error=str(e)[:200])
                self._local.conn = None
            except (pg_errors.OperationalError, pg_errors.InterfaceError,
                    pg_errors.IdleInTransactionSessionTimeout,
                    pg_errors.IdleSessionTimeout):
                # Connection died (server restart, network blip, or the server
                # timed the session out). Drop it and let the pool hand us a
                # fresh one below.
                #
                # IdleInTransactionSessionTimeout is listed EXPLICITLY because
                # psycopg files it under InternalError, NOT OperationalError:
                #
                #   IdleInTransactionSessionTimeout -> psycopg.InternalError
                #   IdleSessionTimeout              -> psycopg.OperationalError
                #
                # so neither this handler nor the InFailedSqlTransaction one
                # above caught it, the dead connection stayed cached on the
                # thread, and the error escaped to the caller as a 500.
                #
                # IdleSessionTimeout is already covered by OperationalError and
                # is named here only so the pair reads together — if psycopg
                # ever reparents it, this keeps working. The test pins the
                # actual hierarchy so a future change surfaces rather than
                # silently reopening the hole.
                #
                # Live on a tenant, 2026-08-15/16 — Postgres there runs
                # idle_in_transaction_session_timeout = 10min, and `_get_conn`
                # caches a connection per thread inside an OPEN transaction
                # between requests. Any request thread idle for ten minutes had
                # its connection killed server-side, and the NEXT request on
                # that thread failed:
                #
                #   psycopg.errors.IdleInTransactionSessionTimeout:
                #     terminating connection due to idle-in-transaction timeout
                #     store.py:1255 in _get_conn
                #
                # Surfaced as 500s on GET /api/incidents, the incident detail
                # view and POST /api/auth/login, plus an intermittent
                # "db": "unreachable" from /api/health — four symptoms, one
                # cause. An analyst hit it while working the queue.
                # PR #119's recovery, unchanged for the standalone case: retire
                # the dead connection and draw a fresh one below. The single
                # exception is a connection with an open `_txn` block on it,
                # where the guard raises instead — swapping there would split
                # one transaction across two connections (QA reproduced exactly
                # that with pg_terminate_backend between save_decision's two
                # writes: the decision was lost, the processed_alerts checkpoint
                # committed, and the call returned normally, silently dropping
                # the alert forever).
                self._refuse_swap_inside_txn(conn, "dead_session")
                try:
                    self._pool.putconn(conn)
                except Exception as e:               # noqa: BLE001
                    # WO-H90: was a bare `except: pass`. This is the server-side-timeout
                    # recovery path from PR #119 (IdleInTransactionSessionTimeout). The
                    # recovery is correct and is NOT being changed here; the only thing
                    # added is a trail for when the pool starts leaking slots after a
                    # Postgres restart. debug — every request thread can hit this at once.
                    _store_logger.debug("pool_putconn_failed_on_dead_conn",
                                        error=str(e)[:200])
                self._local.conn = None
        conn = self._pool.getconn()
        self._local.conn = conn
        return self._checkout(conn)


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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return ""`. An empty schema version
            # reads as 'nothing migrated yet', which is indistinguishable from a
            # read that simply failed. An undeployed migration hid behind exactly
            # this shape for days.
            _store_logger.error("schema_version_read_failed",
                                error=str(e)[:200])
            return ""

    # -- Agent Decisions --
    
    def save_decision(self, decision: AgentDecision) -> str:
        conn = self._get_conn()
        # WO-H98: the decision row and its processed_alerts checkpoint are one
        # transaction, as the WO-H9 comment below has always claimed. That used
        # to rest on the implicit transaction the non-autocommit pool opened;
        # on the autocommit pool it has to be said. Getting this wrong is not
        # cosmetic — a checkpoint without its decision silently DROPS an alert,
        # and a decision without its checkpoint re-triages it into a duplicate.
        with self._txn(conn):
            conn.execute("""
                INSERT INTO agent_decisions
                (id, alert_id, rule_id, rule_description, agent_type, verdict,
                 confidence, risk_score, reasoning, enrichment_summary, playbook_used,
                 actions_taken, escalated, human_override, human_verdict,
                 feedback_applied, created_at, resolved_at, client_id, grounding,
                 llm_failed, response_urgency, kill_chain_stage,
                 rule_level, agent_name)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                    grounding         = EXCLUDED.grounding,
                    llm_failed        = EXCLUDED.llm_failed,
                    response_urgency  = EXCLUDED.response_urgency,
                    kill_chain_stage  = EXCLUDED.kill_chain_stage,
                    rule_level        = EXCLUDED.rule_level,
                    agent_name        = EXCLUDED.agent_name
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
                # WO-H46-b: fail-closed-on-LLM-error marker. getattr keeps callers
                # constructing AgentDecision without the field working unchanged.
                bool(getattr(decision, "llm_failed", False)),
                # WO-H97 shadow fields. Stored, read by nothing. getattr for the
                # same reason as above; None stays None — never defaulted.
                getattr(decision, "response_urgency", None),
                getattr(decision, "kill_chain_stage", None),
                # WO-H124. getattr for the same reason: callers constructing an
                # AgentDecision without these keep working. NULL stays NULL —
                # `rule_level` is never defaulted to 0, because "we did not
                # record it" and "this rule is the quietest possible" are
                # different facts and only one of them is true.
                _coerce_rule_level(getattr(decision, "rule_level", None)),
                _coerce_host(getattr(decision, "agent_name", None)),
            ))
            # WO-H9 crash-safe checkpoint: mark this alert HANDLED in the SAME
            # transaction as the decision insert. Every save_decision caller is a
            # triage decision for a real alert, so "a decision exists" ≡ "this alert
            # is processed". mark_alert_processed runs on the same per-thread
            # connection, inside the `_txn` block opened above (its own
            # `conn.commit()` is dropped by the guard while a block is open), so
            # the decision row and the checkpoint commit ATOMICALLY: a crash can never leave
            # a saved decision without its checkpoint (which would re-triage into a
            # duplicate on restart) nor a checkpoint without its decision (which
            # would silently drop the alert). Enrichment no longer marks processed.
            if decision.alert_id:
                self.mark_alert_processed(
                    alert_id=decision.alert_id,
                    rule_id=decision.rule_id,
                    rule_description=decision.rule_description,
                    verdict=decision.verdict,
                )
            else:
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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: pass` before `return {}`. The glass-box
            # panel then tells an analyst there is no recorded reasoning for a
            # decision that may well have some — they lose the ability to check why
            # the AI called it the way it did.
            _store_logger.warning("decision_audit_trail_read_failed",
                                  error=str(e)[:200])
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
        """False-positive statistics for a rule.

        WO-H46-b: un-analyzed rows are EXCLUDED — specifically those where
        ``llm_failed`` is true AND no human has since supplied a verdict.
        Those are fail-closed escalations written when the LLM was unreachable,
        so they carry no verdict signal. Counting them inflates ``total`` and
        depresses ``fp_rate``, and this number is injected into the triage
        prompt as ``historical_fp_rate`` and mined by the feedback loop for
        tuning proposals. An LLM outage would otherwise silently make every
        rule look cleaner than it is.

        A failure row that a human HAS since reviewed still counts: the human
        did the analysis the agent could not, so their verdict is real signal.

        WO-H60: counts ``COALESCE(human_verdict, verdict)`` — the ANALYST's
        disposition where one exists, falling back to the agent's own call.

        This previously counted the bare ``verdict`` column, i.e. the agent's
        own past guesses, and ignored every human correction. Because this
        number is injected into the triage prompt as ``historical_fp_rate``,
        the compounding loop the product is built on never closed: the agent
        saw FP-rate ~0, had no basis to call a false positive, returned
        ``needs_investigation``, an analyst overrode it to ``false_positive``,
        that override landed in ``human_verdict`` — which this query ignored —
        and the next alert for the same rule showed FP-rate ~0 again.

        Measured on the live install before the fix: rule 40101 was dispositioned
        a false positive by analysts 588 times out of 588, and the agent was
        told its FP rate was 0.2%. Rule 5502: 99.7% actual, 16.5% shown. 7,149
        human FP dispositions had produced zero change in what the agent saw.

        ``src/feedback/loop.py`` already used the COALESCE form in six places —
        the correct pattern existed in the codebase and had simply never been
        applied to the one query that feeds the agent's own reasoning.
        """
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        row = conn.execute(f"""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN COALESCE(human_verdict, verdict) = 'false_positive'
                         THEN 1 ELSE 0 END) as fp_count,
                SUM(CASE WHEN COALESCE(human_verdict, verdict) = 'true_positive'
                         THEN 1 ELSE 0 END) as tp_count,
                SUM(CASE WHEN COALESCE(human_verdict, verdict) IN ('auto_close', 'auto_closed')
                         THEN 1 ELSE 0 END) as auto_closed,
                AVG(confidence) as avg_confidence
            FROM agent_decisions
            WHERE rule_id = %s AND created_at >= %s
              AND NOT (llm_failed AND human_verdict IS NULL) {tf}
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

    # Reviewer names whose verdicts must NOT feed the score.
    #
    # OPERATOR DECISION, 2026-08-13: emptied at the operator's explicit
    # instruction, so ``dhruva-ai-analyst`` verdicts now count as ground truth
    # alongside human ones. The consequences were put to them in writing before
    # the change and they confirmed. Recording them here because this default
    # exists for a reason and whoever reads it next deserves the reason, not
    # just the value:
    #
    #   * An AI-assisted reviewer writes to the same columns a person does. With
    #     nothing excluded, the scorer learns from the platform's own
    #     dispositions — the loop closing on itself, the defect WO-H72
    #     describes for ``historical_fp_rate``.
    #   * It bites harder here than there. AI-assisted review tends to be
    #     applied per RULE, so one afternoon's judgement freezes into the score
    #     permanently and becomes unfalsifiable.
    #   * Measured accuracy stops measuring anything. The 0.967 AUC recorded on
    #     2026-08-13 was computed against genuinely human labels; once agent
    #     verdicts are mixed in, agreement with itself is indistinguishable
    #     from agreement with reality.
    #
    # This was originally caught by contaminated arithmetic rather than by
    # review: a track record built without the exclusion reported rule 5501 at
    # 2/868 and an estate base rate of 0.281, against 0.659 on the 305
    # genuinely human labels.
    #
    # TO RESTORE the previous behaviour, put "dhruva-ai-analyst" back in the
    # tuple. The reviews written under this decision are tagged in
    # ``review_reason`` with the marker below, so they can still be identified
    # and filtered after the fact.
    AI_REVIEW_MARKER = "[ai-analyst-backlog-2026-08-13]"
    _NON_HUMAN_REVIEWERS = ()

    def get_rule_human_outcomes(self, rule_id: int, days: int = 90,
                                exclude_reviewers: tuple = None) -> dict:
        """A rule's track record from HUMAN verdicts only — no agent guesses.

        Distinct from ``get_fp_rate_for_rule``, which coalesces
        ``human_verdict`` with the agent's own ``verdict``. That coalesce is
        correct for the triage prompt (some signal beats none), but it is the
        wrong input for scoring: on a rule where analysts have labelled five
        alerts and the agent has guessed at five thousand, the agent's guesses
        set the number and the humans are noise in it.

        Measured on a live tenant 2026-08-12 against 305
        reviewer-attributed human labels: the coalesced ``historical_fp_rate``
        separates true from false positives at **AUC 0.499** — indistinguishable
        from a coin flip. The same rules scored on human verdicts alone reach
        **AUC 0.970** leave-one-out, and that signal transfers across analysts
        (mean 0.982 building the record on one reviewer and testing on another),
        so it is a property of the rule rather than of one person's habits.

        ``reviewer`` is required to be non-empty: a ``human_verdict`` with no
        ``human_override`` is a bulk action, not a per-alert judgement. On this
        estate 12,436 of 12,740 labels came from two bulk closures; counting
        them makes every rule look like whatever the last bulk action was.

        WHAT A LABEL IN HERE MEANS, AND WHAT IT DOES NOT (WO-H97).
        ``human_verdict = 'true_positive'`` means **the rule fired correctly**.
        It does NOT mean "this was dangerous", and the two are routinely
        different. Rule 31516 ("Suspicious URL access") carries 443 of 443
        true_positive labels from named analysts whose own review notes read
        *"confirms an automated web reconnaissance"* — every one of those
        requests was answered 404. Rule 110129 ("agent disconnected") carries 0
        of 11, because a host going dark genuinely is not an attack. Both sets
        of analysts were telling the truth.

        So ``tp_rate`` is a measure of RULE PRECISION and nothing else, and the
        score built from it (WO-H71) answers "how often is this rule right?".
        The existing 22,655 labels are NOT reinterpreted by WO-H97 and keep
        meaning exactly this. Consequence is handled separately and
        deterministically, in ``src/incidents/severity.py`` plus the
        ``severity_policy`` block of ``config/guidance/escalation_logic.yaml``;
        do not try to recover it from these counts.

        Returns ``{'rule_id', 'total', 'tp_count', 'fp_count', 'tp_rate'}``
        with ``total`` 0 when the rule has no human history — callers must treat
        that as *unknown*, never as a confident zero.
        """
        excluded = list(exclude_reviewers
                        if exclude_reviewers is not None
                        else self._NON_HUMAN_REVIEWERS)
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        row = conn.execute(f"""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN human_verdict = 'true_positive'
                         THEN 1 ELSE 0 END) as tp_count,
                SUM(CASE WHEN human_verdict = 'false_positive'
                         THEN 1 ELSE 0 END) as fp_count
            FROM agent_decisions
            WHERE rule_id = %s AND created_at >= %s
              AND human_verdict IN ('true_positive', 'false_positive')
              AND human_override IS NOT NULL AND human_override <> ''
              AND NOT (human_override = ANY(%s)) {tf}
        """, [rule_id, self._iso_ago(days=days), excluded] + tp).fetchone()

        total = row['total'] or 0
        tp_count = row['tp_count'] or 0
        return {
            'rule_id': rule_id,
            'total': total,
            'tp_count': tp_count,
            'fp_count': row['fp_count'] or 0,
            'tp_rate': (tp_count / total) if total > 0 else None,
        }

    #: WO-H113 bounds. The precedent block rides on every triaged alert, so it
    #: is capped rather than trusted to be small.
    PRECEDENT_MAX_DISAGREEMENTS = 5
    PRECEDENT_NOTE_CHARS = 240

    def get_rule_precedent(self, rule_id: int, days: int = 30,
                           max_disagreements: int = None) -> dict:
        """What happened last time this rule fired — for the triage prompt.

        WO-H113. The triage prompt's ENTIRE historical context today is one
        float, ``historical_fp_rate``. It does not see what analysts decided,
        what they wrote, or where the AI got this same rule wrong last week —
        even though ``FeedbackLoopEngine.analyze_human_overrides`` has computed
        that last part all along and sent it to the Detection Agent instead.

        A plain query, deliberately, not an agent: the answer is a fixed shape
        with one variable, so reasoning about it would cost tokens and add
        nondeterminism for nothing.

        ``state`` IS PART OF THE ANSWER. "this rule has no history" and "the
        history query failed" are different facts and neither may render as
        "this rule is always benign". A failure returns ``unavailable`` and the
        prompt says so.

        THE NOTES ARE ANALYST FREE TEXT AND ARE NOT ANONYMIZED HERE. They carry
        hostnames, usernames and IPs. ``build_triage_prompt`` runs them through
        ``anonymize_free_text`` at the LLM boundary, where every other
        outbound field is handled. Any new caller that sends this dict to a
        model must do the same.
        """
        limit = int(max_disagreements
                    if max_disagreements is not None
                    else self.PRECEDENT_MAX_DISAGREEMENTS)
        out = {"state": "unavailable", "rule_id": rule_id,
               "window_days": int(days), "human_tp": 0, "human_fp": 0,
               "disagreements": [], "closures": {}}
        try:
            conn = self._get_conn()
            tf, tp = self._tenant_filter()
            since = self._iso_ago(days=days)

            row = conn.execute(f"""
                SELECT
                    SUM(CASE WHEN human_verdict = 'true_positive'
                             THEN 1 ELSE 0 END) AS tp,
                    SUM(CASE WHEN human_verdict = 'false_positive'
                             THEN 1 ELSE 0 END) AS fp
                FROM agent_decisions
                WHERE rule_id = %s AND created_at >= %s
                  AND human_verdict IN ('true_positive', 'false_positive')
                  AND human_override IS NOT NULL AND human_override <> ''
                  {tf}
            """, [rule_id, since] + tp).fetchone()
            out["human_tp"] = int(row["tp"] or 0)
            out["human_fp"] = int(row["fp"] or 0)

            # Where the AI and the person disagreed. This is the part that can
            # actually change a verdict: "you called this benign on 14 Aug and
            # an analyst overturned it, and here is why".
            rows = conn.execute(f"""
                SELECT verdict, human_verdict, review_reason, created_at
                FROM agent_decisions
                WHERE rule_id = %s AND created_at >= %s
                  AND human_verdict IS NOT NULL
                  AND human_verdict <> verdict
                  AND human_override IS NOT NULL AND human_override <> ''
                  {tf}
                ORDER BY created_at DESC
                LIMIT {limit}
            """, [rule_id, since] + tp).fetchall()
            for r in rows:
                note = (r["review_reason"] or "")[:self.PRECEDENT_NOTE_CHARS]
                out["disagreements"].append({
                    "agent_said": r["verdict"],
                    "human_said": r["human_verdict"],
                    "note": note,
                    "when": str(r["created_at"])[:10],
                })

            # WO-H112 structured closures for cases this rule appeared in.
            # Empty until analysts start using them — which must read as "no
            # closures recorded", never as agreement.
            crows = conn.execute(f"""
                SELECT i.closure_reason AS cr, COUNT(*) AS n
                FROM incidents i
                JOIN incident_alerts ia ON ia.incident_id = i.id
                JOIN agent_decisions ad ON ad.id = ia.decision_id
                WHERE ad.rule_id = %s AND i.closure_reason IS NOT NULL
                  -- QA L4: closure_recorded_at is written as
                  -- CURRENT_TIMESTAMP::text ('2026-08-31 09:50:08+00') but
                  -- compared against _iso_ago() ('2026-08-01T09:50:08+00:00').
                  -- ' ' < 'T', so a TEXT comparison drops every row on the
                  -- boundary day. Cast both sides and compare as timestamps.
                  AND i.closure_recorded_at::timestamptz >= %s::timestamptz
                  {tf.replace("client_id", "i.client_id")}
                GROUP BY 1 ORDER BY 2 DESC
            """, [rule_id, since] + tp).fetchall()
            out["closures"] = {r["cr"]: int(r["n"]) for r in crows}

            has_any = (out["human_tp"] or out["human_fp"]
                       or out["disagreements"] or out["closures"])
            out["state"] = "ok" if has_any else "no_history"
            return out
        except Exception as e:                                  # noqa: BLE001
            # Never take triage down for want of context, and never let the
            # failure masquerade as an empty history.
            _store_logger.warning("rule_precedent_unavailable",
                                  rule_id=rule_id, error=str(e)[:200])
            out["state"] = "unavailable"
            return out

    def get_rule_label_tiers(self, rule_id: int, days: int = 90,
                             machine_reviewers=None) -> dict:
        """A rule's track record SPLIT BY WHO WROTE IT.

        WO-H115. ``get_rule_human_outcomes`` answers "what did reviewers say?"
        and treats every reviewer identity alike. That is fine while every
        reviewer is a person and wrong the moment one is not.

        THE PROBLEM THIS EXISTS FOR IS GENERIC, NOT ONE CLIENT'S.
        Every new deployment starts with zero labels, so every rule is
        unlearned, so every alert takes the cold-start prior and lands in
        `high`. The only way out is for somebody to label alerts — and the
        obvious shortcut is to let the platform label its own backlog. Do that
        and the machine's opinion becomes indistinguishable from a person's:
        it can make a rule QUIET with exactly the authority of an analyst who
        looked. That is the failure this split prevents.

        ``machine_reviewers`` is a per-client list from
        ``risk_criteria.yaml → scoring.machine_reviewers``. It is EMPTY by
        default, so a deployment that has never used machine review behaves
        exactly as before.

        Returns::

            {"human":   {"n": int, "k": int},   # k = true_positive count
             "machine": {"n": int, "k": int}}

        ``n == 0`` on both sides means the rule has no record at all — which
        callers must treat as UNKNOWN, never as a confident zero.
        """
        machine = [str(m) for m in (machine_reviewers or []) if str(m).strip()]
        empty = {"human": {"n": 0, "k": 0}, "machine": {"n": 0, "k": 0}}
        try:
            conn = self._get_conn()
            tf, tp = self._tenant_filter()
            row = conn.execute(f"""
                SELECT
                    COUNT(*) FILTER (WHERE NOT (human_override = ANY(%s)))
                        AS h_n,
                    COUNT(*) FILTER (WHERE NOT (human_override = ANY(%s))
                        AND human_verdict = 'true_positive') AS h_k,
                    COUNT(*) FILTER (WHERE human_override = ANY(%s)) AS m_n,
                    COUNT(*) FILTER (WHERE human_override = ANY(%s)
                        AND human_verdict = 'true_positive') AS m_k
                FROM agent_decisions
                WHERE rule_id = %s AND created_at >= %s
                  AND human_verdict IN ('true_positive', 'false_positive')
                  AND human_override IS NOT NULL AND human_override <> ''
                  {tf}
            """, [machine, machine, machine, machine, rule_id,
                  self._iso_ago(days=days)] + tp).fetchone()
            return {
                "human": {"n": int(row["h_n"] or 0), "k": int(row["h_k"] or 0)},
                "machine": {"n": int(row["m_n"] or 0), "k": int(row["m_k"] or 0)},
            }
        except Exception as e:                                  # noqa: BLE001
            # A scoring input must never take triage down, and a failed read
            # must not read as "this rule has no record" — the caller marks the
            # score unconfident either way, which is the safe direction.
            _store_logger.warning("rule_label_tiers_failed",
                                  rule_id=rule_id, error=str(e)[:200])
            return empty

    def get_llm_failure_rate(self, hours: int = 1) -> dict:
        """WO-H46-b: LLM-failure health signal over a recent window.

        A triage failure fails CLOSED — it writes needs_investigation +
        escalated, which is indistinguishable from a real escalation in the
        verdict column. This surfaces the failure count directly so an LLM
        outage reads as an outage rather than as a busy escalation queue.

        Intended as the source for an operator-facing health indicator/alert:
        a non-zero (or rising) ``failure_rate`` means the platform is queueing
        un-analyzed alerts for humans, not triaging them.
        """
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        row = conn.execute(f"""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN llm_failed THEN 1 ELSE 0 END) as failed
            FROM agent_decisions
            WHERE created_at >= %s AND agent_type = 'triage' {tf}
        """, [self._iso_ago(hours=hours)] + tp).fetchone()

        total = row['total'] or 0
        failed = row['failed'] or 0
        return {
            'window_hours': hours,
            'total': total,
            'failed': failed,
            'succeeded': total - failed,
            'failure_rate': (failed / total) if total > 0 else 0.0,
        }

    # Whitelist of allowed orderings → fixed ORDER BY clauses. Caller input is
    # only ever used to look up a key here; it is NEVER interpolated into SQL.
    # WO-H33: `id` is the final tiebreak so OFFSET pages are stable when many
    # rows share the same risk_score/created_at.
    _DECISION_ORDER_CLAUSES = {
        "recent": "created_at DESC, id",
        "risk": "risk_score DESC NULLS LAST, created_at DESC, id",
    }

    def get_recent_decisions(self, limit: int = 50,
                             offset: int = 0,
                             agent_type: Optional[str] = None,
                             verdict: Optional[str] = None,
                             escalated_only: bool = False,
                             pending_only: bool = False,
                             llm_failed: Optional[bool] = None,
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
        # WO-H33: verdict/escalated filter in SQL (both are real, indexed
        # columns) so LIMIT/OFFSET paginate the FULL filtered set — filtering
        # after the LIMIT hid every match beyond the first window.
        if verdict:
            query += " AND verdict = %s"
            params.append(verdict)
        if escalated_only:
            query += " AND escalated = 1"
        # WO-H37: the pending-review read ("escalated, no human verdict yet")
        # filters in SQL too, so its LIMIT/OFFSET pages the FULL pending set —
        # the old read Python-filtered the 200 most-recent rows, hiding every
        # pending decision beyond that window.
        if pending_only:
            query += (" AND escalated = 1"
                      " AND COALESCE(human_verdict, '') = ''")
        # WO-H46-c: let the queue separate un-analyzed LLM failures from real
        # escalations. Both carry verdict='needs_investigation' + escalated, so
        # without this an operator cannot tell a backend outage from a busy
        # queue. llm_failed=True shows only failures; False hides them.
        if llm_failed is not None:
            query += " AND llm_failed" if llm_failed else " AND NOT llm_failed"
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
        query += f" ORDER BY {order_clause} LIMIT %s OFFSET %s"
        params.append(limit)
        params.append(max(0, int(offset)))
        rows = conn.execute(query, params).fetchall()

        return [dict(r) for r in rows]

    # -- Append-only alert review history (WO-H85) --
    #
    # `apply_human_override` is a bare overwrite of human_verdict /
    # review_reason. When a second analyst overrode a colleague, the FIRST
    # reviewer and their reason were GONE — not archived, not versioned. That is
    # the one thing a SOC most needs to keep: the disagreement, and (since the
    # operator ruled `dhruva-ai-analyst` verdicts count as ground truth) the
    # evidence of a human correcting an AI label.
    #
    # `decision_reviews` (migration 0013) is the alert-level equivalent of
    # `incident_timeline`: APPEND-ONLY. Every write path below only ever INSERTs;
    # nothing in the DAO updates or deletes an existing entry.

    #: entry written when a person reviewed THIS alert directly.
    REVIEW_SOURCE_HUMAN = "human_review"
    #: entry written by the opt-in incident-level verdict propagation, which
    #: only ever fills an EMPTY verdict — kept distinguishable so the Feedback
    #: Loop can tell an individually-judged alert from an inherited label.
    REVIEW_SOURCE_PROPAGATED = "incident_verdict_propagation"

    @staticmethod
    def _record_decision_review(conn, decision_id: str, reviewer: str,
                                human_verdict: Optional[str],
                                reason: Optional[str],
                                previous_verdict: Optional[str],
                                source: str) -> str:
        """APPEND one immutable review entry. Never mutates a prior entry.

        Takes the caller's ``conn`` so the entry lands in the SAME transaction
        as the verdict write it records — a committed verdict can never end up
        without its history row, and a rolled-back one leaves no orphan.
        """
        entry_id = str(uuid.uuid4())
        conn.execute("""
            INSERT INTO decision_reviews
            (id, decision_id, reviewer, human_verdict, reason,
             previous_verdict, source, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP::text)
        """, (entry_id, decision_id, reviewer, human_verdict, reason,
              previous_verdict, source))
        return entry_id

    def get_decision_reviews(self, decision_id: str) -> list[dict]:
        """Every review ever recorded on a decision, OLDEST FIRST, TENANT-SCOPED.

        Ordered by the ``seq`` BIGSERIAL rather than ``created_at``: the latter
        is ``CURRENT_TIMESTAMP::text`` (transaction start time) and can tie for
        two reviews in the same instant, whereas ``seq`` is strictly monotonic.

        The ``{tf}`` filter resolves to ``agent_decisions.client_id`` (the join
        parent) — ``decision_reviews`` itself carries no ``client_id``, so there
        is no column ambiguity and a foreign tenant's history reads as empty.
        """
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        rows = conn.execute(f"""
            SELECT dr.* FROM decision_reviews dr
            JOIN agent_decisions ad ON ad.id = dr.decision_id
            WHERE dr.decision_id = %s {tf}
            ORDER BY dr.seq ASC
        """, [decision_id] + tp).fetchall()
        return [dict(r) for r in rows]

    def get_incident_alert_reviews(self, incident_id: str) -> dict[str, list[dict]]:
        """Review history for ALL of an incident's member alerts, in ONE query.

        Returns ``{decision_id: [entry, ...]}`` with each list oldest-first, so
        the case view can show every member alert's history without an N+1 read.
        Tenant-scoped identically to ``get_incident_alerts``.
        """
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        rows = conn.execute(f"""
            SELECT dr.* FROM decision_reviews dr
            JOIN agent_decisions ad ON ad.id = dr.decision_id
            JOIN incident_alerts ia ON ia.decision_id = ad.id
            WHERE ia.incident_id = %s {tf}
            ORDER BY dr.seq ASC
        """, [incident_id] + tp).fetchall()
        grouped: dict[str, list[dict]] = {}
        for r in rows:
            grouped.setdefault(r["decision_id"], []).append(dict(r))
        return grouped

    def apply_human_override(self, decision_id: str, human_verdict: str,
                              reviewer: str, reason: Optional[str] = None) -> bool:
        """Record a human verdict on a decision, TENANT-SCOPED.

        WO-H85: the overwrite of ``human_verdict``/``review_reason`` is kept (the
        columns remain "the CURRENT verdict"), but the verdict being replaced is
        read FIRST and an append-only ``decision_reviews`` entry is written in
        the SAME transaction. A second override therefore no longer destroys the
        first — both are readable, in order, with reviewer and reason.

        RBAC is unchanged and lives in the route (``/api/triage/review``):
        analyst+ may set the FIRST verdict, admin+ to override an existing one.

        WO-H98: "the SAME transaction" above is now stated explicitly via
        ``_txn`` — the pool is autocommit, so the verdict UPDATE and its
        history INSERT would otherwise commit separately and a failure between
        them would leave a verdict with no record of what it replaced.
        """
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        with self._txn(conn):
            # Read what this review is about to replace, tenant-scoped, so the
            # history entry records the disagreement. A foreign/unknown decision
            # reads as no row and the UPDATE below writes nothing.
            prev_row = conn.execute(
                f"SELECT human_verdict FROM agent_decisions WHERE id = %s {tf}",
                [decision_id] + tp).fetchone()
            cursor = conn.execute(f"""
                UPDATE agent_decisions
                SET human_override = %s, human_verdict = %s,
                    review_reason = %s,
                    resolved_at = CURRENT_TIMESTAMP::text
                WHERE id = %s {tf}
            """, [reviewer, human_verdict, reason, decision_id] + tp)
            applied = cursor.rowcount > 0
            if applied:
                previous = (prev_row["human_verdict"] or None) if prev_row else None
                self._record_decision_review(
                    conn, decision_id, reviewer, human_verdict, reason,
                    previous, self.REVIEW_SOURCE_HUMAN)
        if applied:
            _store_logger.info("decision_review_recorded",
                               decision_id=decision_id, reviewer=reviewer,
                               verdict=human_verdict,
                               previous_verdict=previous,
                               source=self.REVIEW_SOURCE_HUMAN)
        conn.commit()

        return applied

    # -- Alert-level claim (WO-H25) --
    #
    # Ownership of the INDIVIDUAL triage decision, mirroring the WO-H24
    # incident self-claim semantics one level down: claim is self-claim,
    # unowned-only (or an idempotent re-claim of your own), and release is
    # owner-only. Both writes are single atomic UPDATEs whose WHERE clause
    # carries the ownership precondition AND the tenant filter, so a lost
    # race / foreign owner / foreign tenant is a rowcount-0 no-write — the
    # route re-reads to tell conflict (409) from not-found (404).

    def claim_decision(self, decision_id: str, actor: str) -> bool:
        """Claim a decision for ``actor``, TENANT-SCOPED and unowned-only.

        Sets ``claimed_by``/``claimed_at`` ONLY when the decision is currently
        unclaimed (NULL/empty ``claimed_by``) or already claimed by ``actor``
        (idempotent re-claim — the original ``claimed_at`` is preserved).
        Returns ``True`` when the claim landed; ``False`` when nothing was
        written (owned by a DIFFERENT user, unknown id, or another tenant's
        row) — the caller distinguishes those via ``get_decision``.
        """
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        cursor = conn.execute(f"""
            UPDATE agent_decisions
            SET claimed_by = %s,
                claimed_at = COALESCE(NULLIF(claimed_at, ''),
                                      CURRENT_TIMESTAMP::text)
            WHERE id = %s
              AND (claimed_by IS NULL OR claimed_by = '' OR claimed_by = %s)
              {tf}
        """, [actor, decision_id, actor] + tp)
        conn.commit()

        return cursor.rowcount > 0

    def unclaim_decision(self, decision_id: str, actor: str) -> bool:
        """Release ``actor``'s own claim on a decision, TENANT-SCOPED.

        Clears ``claimed_by``/``claimed_at`` ONLY when ``actor`` currently
        owns the claim. Returns ``True`` when the release happened; ``False``
        when nothing was written (not the owner, already unclaimed, unknown
        id, or another tenant's row).
        """
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        cursor = conn.execute(f"""
            UPDATE agent_decisions
            SET claimed_by = NULL, claimed_at = NULL
            WHERE id = %s AND claimed_by = %s {tf}
        """, [decision_id, actor] + tp)
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

    def get_proposal_claimed_rule_ids(self, exclude_id: str = "") -> set[int]:
        """Rule IDs claimed by proposals that are not yet on the manager (WO-H84).

        ``_reassign_colliding_rule_ids`` checks a generated ID against the LIVE
        ruleset only. A proposal awaiting review is not live, so three separate
        cycles can each be told 100001 is free — and each be right, by that
        measure.

        Observed on a live tenant, 2026-08-13, within two hours of
        re-enabling detection:

            claimed_id  proposals  for_rules
            100001          3      5501, 5740, 5715
            110108          2      110101, 110103

        Approving any two of the first group writes a duplicate rule ID. The
        Wazuh ruleset then fails to compile, ``wazuh-analysisd`` will not load
        rules, and ALERT PROCESSING STOPS — the outage WO-H65 exists to prevent,
        reached by a route that guard was never written to cover: not
        model-versus-live, but model-versus-model.

        ``proposed``, ``approved`` and ``needs_manual_tuning`` all count. An
        approved-but-undeployed proposal has a reviewer's sign-off on a specific
        ID and must not have it taken by a later cycle. A parked one still holds
        its ID and can be re-queued at any time — leaving those out was a real
        hole in the first version of this method, found on 2026-08-14 when a
        second proposal claimed 100001 while the first sat unseen.

        ``exclude_id`` lets a proposal being re-checked ignore its own claim.
        Returns an empty set on failure, matching ``get_used_rule_ids``: callers
        treat empty as UNKNOWN, never as "nothing is taken".
        """
        import re as _re
        ids: set[int] = set()
        try:
            conn = self._get_conn()
            tf, tp = self._tenant_filter()
            params = list(tp)
            extra = ""
            if exclude_id:
                extra = " AND id <> %s"
                params.append(exclude_id)
            rows = conn.execute(f"""
                SELECT proposed_xml FROM detection_proposals
                WHERE status IN ('proposed', 'approved',
                                 'needs_manual_tuning') {tf}{extra}
            """, params).fetchall()
            for r in rows:
                xml = (dict(r).get("proposed_xml") or "")
                for m in _re.findall(r'<rule\s[^>]*id="(\d+)"', xml):
                    try:
                        ids.add(int(m))
                    except (TypeError, ValueError):
                        continue
        except Exception as e:                      # noqa: BLE001
            _store_logger.error("proposal_claimed_ids_lookup_failed",
                                error=str(e)[:200],
                                detail="treating as UNKNOWN, not as empty")
            return set()
        return ids

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

    def set_proposal_backup(self, proposal_id: str, backup_xml: str,
                            backup_file: str = None):
        """Store the pre-deploy snapshot AND which file it is a snapshot OF.

        ``backup_file`` is not decoration (WO-H94): the rollback path may only
        write a snapshot back into the file it was taken from, and before this
        column existed the snapshot was read from the rule's ORIGINATING file
        while the deploy wrote ``ai-soc-tuned.xml``. Rows written before the
        column existed have it NULL and are read back as ``rule_file``, which
        is the file the old code read — see ``rollback_proposal``.
        """
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        conn.execute(f"""
            UPDATE detection_proposals
               SET backup_xml = %s, backup_file = %s
             WHERE id = %s {tf}
        """, [backup_xml, backup_file, proposal_id] + tp)
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
        """Count metric occurrences, optionally filtered by date.

        WO-H28: the day filter is a sargable half-open range
        (``recorded_at >= day AND recorded_at < day+1``) instead of the old
        ``DATE(recorded_at) = day``, which wrapped the column in a function
        and forced a full scan. ``recorded_at`` is TEXT in ISO-8601, so the
        lexicographic range compare is day-accurate for both stored formats
        (``YYYY-MM-DD hh:mm...`` and ``YYYY-MM-DDThh:mm...``) and can use the
        0009 composite index (metric_name, recorded_at).
        """
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        if since_date:
            # WO-H116 / qa-audit F7: ``since_date`` is a caller-supplied
            # string. Both callers today pass a date-only
            # ``strftime("%Y-%m-%d")`` for the licence quota window
            # (``src/api/feature_gates.py``, ``main.py``), which every
            # interpreter parses — so this conversion fixed no live defect, and
            # the earlier comment claiming it "arrives from an API query
            # string" was wrong. It stays because the parameter is a plain
            # ``str`` on a public method with no format contract, and the day
            # floor below is derived from whatever arrives; the shared parser
            # means a caller passing a full Wazuh/Postgres timestamp gets the
            # right day instead of a ``ValueError`` on 3.10.
            day = parse_iso8601(since_date).date()
            next_day = (day + timedelta(days=1)).isoformat()
            row = conn.execute(
                f"SELECT COUNT(*) AS cnt FROM operational_metrics "
                f"WHERE metric_name = %s AND recorded_at >= %s "
                f"AND recorded_at < %s {tf}",
                [metric_name, day.isoformat(), next_day] + tp
            ).fetchone()
        else:
            row = conn.execute(
                f"SELECT COUNT(*) AS cnt FROM operational_metrics WHERE metric_name = %s {tf}",
                [metric_name] + tp
            ).fetchone()
        return row["cnt"] if row else 0

    # -- Retention / prune (WO-H28) --

    # Ever-growing tables the daily retention job may prune → their age
    # column. ORDER MATTERS: FK children (decision_audit_trail,
    # soar_executions, decision_reviews) are pruned before their
    # agent_decisions parent.
    #
    # WO-H85: `decision_reviews` is in this list for two reasons. It is itself
    # ever-growing (one row per human review, forever), and — because its
    # `decision_id` FK has no ON DELETE clause — a review row BLOCKS the
    # deletion of its parent decision. Since the `agent_decisions` batch is a
    # single `DELETE ... WHERE ctid IN (... LIMIT n)`, one blocked row aborts
    # the WHOLE batch, and the same row is re-selected on every subsequent run:
    # agent_decisions would stop pruning permanently, with only a warning that
    # the per-table `except` below swallows. So the review rows must age out on
    # their own schedule AND shield their parent until they do (see the
    # NOT EXISTS list in the agent_decisions branch).
    # Shipped retention windows, in DAYS. These are the code-level defaults for
    # every prunable table; `config/config.yaml` carries the same values as
    # documentation, and an operator's setting always wins.
    #
    # They exist because the config is NOT merged with the shipped file on
    # upgrade — `scripts/upgrade.sh` only adds whole missing top-level sections,
    # so an install that already has a `retention.days` block keeps it verbatim.
    # A table added in a later release is therefore simply ABSENT from that
    # operator's map, and `days_by_table.get(table)` returned None → treated as
    # "keep forever".
    #
    # Harmless for a standalone table. Not harmless for `decision_reviews`
    # (WO-H85): a review row holds its parent decision back from the prune (its
    # FK has no ON DELETE), so "keep forever" there silently pins EVERY reviewed
    # decision against `agent_decisions` pruning, permanently, on exactly the
    # installs where analysts actually review things. Flagged by qa-auditor on
    # 2026-08-16 as an upgrade-path defect.
    #
    # ABSENT takes the default; an explicit 0 still means keep forever. Those
    # are different intentions and must stay distinguishable.
    # These MUST match config/config.yaml's `retention.days` block — an install
    # with the shipped config and one without must behave identically. Pinned by
    # test_retention_defaults_match_the_shipped_config.
    RETENTION_DEFAULT_DAYS = {
        "operational_metrics": 90,
        "agent_decisions": 365,
        "decision_audit_trail": 365,
        "decision_reviews": 365,
        "soar_executions": 180,
        "llm_usage_metrics": 400,
        "webhook_requests": 14,
        "sla_breaches": 365,
        "llm_budget_reservations": 1,
    }

    @classmethod
    def resolve_retention_days(cls, configured: dict | None) -> dict:
        """Operator config layered over the shipped defaults.

        A key the operator set — including 0 — wins. A key they never set takes
        the default, so a table introduced by a release does not silently become
        keep-forever on an install whose config predates it.
        """
        resolved = dict(cls.RETENTION_DEFAULT_DAYS)
        for table, days in (configured or {}).items():
            if days is None:
                continue          # present-but-null is not an intention
            try:
                resolved[table] = int(days)
            except (TypeError, ValueError):
                _store_logger.warning(
                    "retention_days_unparseable", table=table, value=repr(days),
                    detail="ignoring; the shipped default applies")
        return resolved

    RETENTION_PRUNABLE = (
        ("decision_audit_trail", "created_at"),
        ("soar_executions", "created_at"),
        ("decision_reviews", "created_at"),
        ("llm_usage_metrics", "created_at"),
        ("operational_metrics", "recorded_at"),
        ("webhook_requests", "created_at"),
        # WO-H87: one row per breached SLA, kept forever otherwise. Even
        # deduplicated it only grows, and nothing else reclaims it.
        ("sla_breaches", "breached_at"),
        ("llm_budget_reservations", "created_at"),
        ("agent_decisions", "created_at"),
    )

    def prune_expired_rows(self, days_by_table: dict,
                           batch_size: int = 10000) -> dict:
        """Delete rows older than the per-table retention window (WO-H28).

        ``days_by_table`` maps table name → retention days; a value <= 0 (or
        a missing table) means keep forever. Only tables in
        ``RETENTION_PRUNABLE`` are ever touched. Deletes run in ``batch_size``
        chunks (ctid subselect) so no single statement holds locks on a large
        range, and each batch commits independently — WO-H98 makes that literal
        rather than aspirational: on the autocommit pool each batch DELETE is
        its own transaction, so the ``conn.commit()`` in the loop is a no-op
        and no batch can leave a long-running transaction sitting on the table
        it is pruning. Deliberately NOT wrapped in ``_txn``, for the same reason
        the per-table ``except`` exists: one failing table must not abort the
        batches already deleted from the others.

        Tenant safety: retention is a uniform, age-based platform policy that
        must span all tenants, so this REQUIRES the explicit cross-tenant
        context (fail-closed otherwise) — the same audited posture as the
        other cross-tenant maintenance jobs.

        ``agent_decisions`` rows still referenced by ``incident_alerts``,
        ``decision_audit_trail``, ``soar_executions`` or ``decision_reviews``
        (WO-H85) are skipped (FK children first; a referenced decision survives
        until its last referencing row ages out — never an FK violation, never
        a dangling reference).

        The ``decision_reviews`` shield is not optional. Its FK carries no
        ``ON DELETE``, and the batch DELETE is all-or-nothing, so a single
        human-reviewed decision whose audit trail had already been pruned would
        raise on every run and permanently stop ``agent_decisions`` from being
        pruned at all — silently, because the per-table ``except`` below only
        logs a warning.

        Returns {table: rows_deleted}.
        """
        if _tenant_ctx.get() != _CROSS_TENANT:
            raise TenantContextRequired(
                "prune_expired_rows must run under db.cross_tenant() — it is "
                "a deliberate all-tenant maintenance operation."
            )
        batch_size = max(int(batch_size), 1)
        deleted: dict = {}
        for table, age_col in self.RETENTION_PRUNABLE:
            days = days_by_table.get(table)
            try:
                days = float(days) if days is not None else 0
            except (TypeError, ValueError):
                days = 0
            if days <= 0:
                continue  # keep forever
            cutoff = self._iso_ago(days=days)
            if table == "agent_decisions":
                batch_sql = f"""
                    DELETE FROM agent_decisions WHERE ctid IN (
                        SELECT a.ctid FROM agent_decisions a
                        WHERE a.{age_col} < %s
                          AND NOT EXISTS (SELECT 1 FROM incident_alerts ia
                                          WHERE ia.decision_id = a.id)
                          AND NOT EXISTS (SELECT 1 FROM decision_audit_trail dat
                                          WHERE dat.decision_id = a.id)
                          AND NOT EXISTS (SELECT 1 FROM soar_executions se
                                          WHERE se.decision_id = a.id)
                          AND NOT EXISTS (SELECT 1 FROM decision_reviews dr
                                          WHERE dr.decision_id = a.id)
                        LIMIT %s)
                """
            else:
                batch_sql = f"""
                    DELETE FROM {table} WHERE ctid IN (
                        SELECT ctid FROM {table}
                        WHERE {age_col} < %s LIMIT %s)
                """
            total = 0
            try:
                conn = self._get_conn()
                while True:
                    cur = conn.execute(batch_sql, (cutoff, batch_size))
                    conn.commit()
                    n = cur.rowcount or 0
                    total += n
                    if n < batch_size:
                        break
            except Exception as e:
                # Per-table isolation: one missing/locked table must not
                # abort the rest of the prune run.
                try:
                    self._get_conn().rollback()
                except Exception:
                    pass
                _store_logger.warning("retention_prune_table_failed",
                                      table=table, error=str(e))
            if total:
                _store_logger.info("retention_pruned", table=table,
                                   rows=total, cutoff=cutoff)
            deleted[table] = total
        return deleted


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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except:` returning all zeros. The dashboard then
            # shows MTTD/MTTA/MTTR of zero and 0% SLA compliance, which reads as
            # real (terrible) data rather than as a broken query.
            _store_logger.warning("mtt_metrics_query_failed",
                                  error=str(e)[:200])
            return {"mttd_min": 0, "mtta_min": 0, "mttr_min": 0,
                    "sla_response_compliance": 0, "sla_resolution_compliance": 0,
                    "sample_count": 0, "by_severity": {}}

        def _delta_min(start_str, end_str):
            if not start_str or not end_str:
                return None
            try:
                # WO-H116: version-independent — these columns hold a mix of
                # our ``isoformat()`` and ``CURRENT_TIMESTAMP::text``.
                s = parse_iso8601(start_str)
                e = parse_iso8601(end_str)
                return max(0, (e - s).total_seconds() / 60.0)
            except (ValueError, TypeError):
                # WO-H90: left silent on purpose. Per-row timestamp parse inside the
                # MTT loop with a documented None default; the caller skips None. One
                # malformed row must not take the metric down, and 500 log lines for
                # 500 bad rows helps nobody.
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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return []`. The response-time trend
            # chart goes empty, which looks like a quiet week rather than a failed
            # read.
            _store_logger.warning("mtt_daily_trend_query_failed",
                                  error=str(e)[:200])
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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return []`. Per-analyst stats come back
            # empty, so the whole team looks like it did nothing.
            _store_logger.warning("analyst_performance_query_failed",
                                  error=str(e)[:200])
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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return {}`. A playbook reads as missing
            # when it is merely unreadable, so a response action quietly does not
            # run and nothing says why.
            _store_logger.warning("get_soar_playbook_failed",
                                  error=str(e)[:200])
            return {}

    def toggle_soar_playbook(self, playbook_id: str, enabled: bool):
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            conn.execute(
                f"UPDATE soar_playbooks SET enabled = %s, updated_at = CURRENT_TIMESTAMP::text WHERE id = %s {tf}",
                [int(enabled), playbook_id] + tp)
            conn.commit()
            return True
        except Exception as e:                       # noqa: BLE001
            # WO-H88: was a bare `except: pass`. A failure here means
            # an operator believing they disabled an automated response while it stays live.
            # Returns False so callers can tell, instead of every
            # caller assuming it worked.
            _store_logger.error("toggle_soar_playbook_failed", error=str(e)[:200])
            return False

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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return {}`. A SOAR run looks like it
            # never existed, so its status page is blank and nobody chases it.
            _store_logger.warning("get_soar_execution_failed",
                                  error=str(e)[:200])
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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return []`. The SOAR queue looks empty —
            # including any run sitting in pending_approval waiting for a human.
            _store_logger.warning("get_soar_executions_failed",
                                  error=str(e)[:200])
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
            return True
        except Exception as e:                       # noqa: BLE001
            # WO-H88: was a bare `except: pass`. A failure here means
            # a SOAR run's recorded state drifting from what actually happened.
            # Returns False so callers can tell, instead of every
            # caller assuming it worked.
            _store_logger.error("update_soar_execution_failed", error=str(e)[:200])
            return False

    def count_recent_soar_executions(self, playbook_id: str, hours: int = 1) -> int:
        """Executions of one playbook in the last ``hours`` — the rate limit.

        Returns:
            ``int`` — the count. ``0`` is a real answer: nothing ran.

        Raises:
            SOARRateLimitUnavailable — we could not find out. This is never the
            same answer as ``0``: see WO-H91. The caller must fail closed and
            withhold the trigger, not read an unknown ceiling as headroom.
        """
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            row = conn.execute(f"""
                SELECT COUNT(*) AS cnt FROM soar_executions
                WHERE playbook_id = %s AND created_at >= %s
                AND status NOT IN ('cancelled') {tf}
            """, [playbook_id, self._iso_ago(hours=hours)] + tp).fetchone()
            return row["cnt"] if row else 0
        except Exception as e:                       # noqa: BLE001
            # WO-H90 made this audible but deliberately kept `return 0`.
            # WO-H91 changes the behaviour: this count IS the SOAR per-playbook
            # rate limit, and zero read as 'nothing ran recently', so the
            # throttle opened and automation could fire without a ceiling.
            # Raise instead, so the caller can tell an unknown ceiling from an
            # empty one. No numeric sentinel — a big number would still be a
            # count, and the caller could not tell it apart from a real one.
            _store_logger.error("soar_rate_limit_count_failed",
                                error=str(e)[:200],
                                detail="could not establish the per-playbook "
                                       "execution count; raising rather than "
                                       "reporting it as zero")
            raise SOARRateLimitUnavailable(
                f"could not count recent SOAR executions: {str(e)[:200]}") from e

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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except:` returning zeros. The SOAR panel then
            # reads 'pending approvals: 0' while runs are actually waiting for a
            # human to approve them.
            _store_logger.warning("get_soar_stats_failed", error=str(e)[:200])
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
        """Look up one tenant row.

        Returns:
            ``dict`` — the row, or
            ``{}`` — the database answered and there is NO SUCH TENANT.

        Raises:
            TenantRecordUnavailable — we could not find out whether the tenant
            exists. This is never the same answer as ``{}``: see WO-H91. An
            empty dict flowed past the fail-closed guard in
            ``TenantServiceRegistry._get_config`` and ended up as a silent
            fallback to GLOBAL Wazuh credentials.
        """
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM tenants WHERE id = %s", (tenant_id,)
            ).fetchone()
            return dict(row) if row else {}
        except Exception as e:                       # noqa: BLE001
            # WO-H90 made this audible but deliberately kept `return {}`.
            # WO-H91 changes the behaviour: a read failure and an honest
            # absence must not be the same value. Escalated to error — a failed
            # tenant read now stops that tenant's work rather than quietly
            # running it on platform defaults.
            # No tenant_id in the log line: shared store logger, multi-tenant.
            _store_logger.error("get_tenant_read_failed", error=str(e)[:200],
                                detail="could not establish whether the tenant "
                                       "exists; raising rather than reporting "
                                       "it as absent")
            raise TenantRecordUnavailable(
                f"could not read tenant record: {str(e)[:200]}") from e

    def get_tenant_by_slug(self, slug: str) -> dict:
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM tenants WHERE slug = %s", (slug,)
            ).fetchone()
            return dict(row) if row else {}
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return {}`. A slug lookup comes back
            # empty, which callers read as 'no such tenant' and turn into a 404 or
            # a rejected login.
            _store_logger.warning("get_tenant_by_slug_read_failed",
                                  error=str(e)[:200])
            return {}

    def get_active_tenants(self) -> list[dict]:
        """Every tenant with ``active = 1``.

        Returns:
            ``list[dict]`` — the rows. ``[]`` is a real answer: nothing is
            active (e.g. every tenant was deactivated from the admin UI).

        Raises:
            TenantListUnavailable — we could not find out. This is never the
            same answer as ``[]``: see WO-H91. ``_seed_default_tenant`` decides
            whether to boot without tenant context off this list, so an empty
            list has to mean what it says.
        """
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM tenants WHERE active = 1 ORDER BY name"
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:                       # noqa: BLE001
            # WO-H90 made this audible but deliberately kept `return []`. The
            # scheduler read it as no tenants to process, so triage, feedback
            # and hunt cycles did nothing for everybody at once and it looked
            # like a quiet night. WO-H91 (QA D2) raises instead: every caller
            # already sits inside a try/except that degrades safely, and the
            # one caller that does NOT is the startup path this WO rewrote.
            _store_logger.error("get_active_tenants_failed",
                                error=str(e)[:200],
                                detail="could not establish the active-tenant "
                                       "list; raising rather than reporting it "
                                       "as empty")
            raise TenantListUnavailable(
                f"could not read the active tenant list: {str(e)[:200]}") from e

    def get_all_tenants(self) -> list[dict]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM tenants ORDER BY name"
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return []`. The admin tenant list renders
            # empty, which looks like a fresh install.
            _store_logger.warning("get_all_tenants_failed", error=str(e)[:200])
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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return None`. None means 'no mapping
            # configured'. In multi-tenant mode callers fail CLOSED on that, so
            # every alert for this tenant is rejected as not-owned — and without
            # this line that is indistinguishable from a tenant whose agents were
            # genuinely never mapped. Same cadence as the caller's existing
            # per-rejection warning, so this adds no new order of magnitude.
            _store_logger.warning("tenant_agent_map_read_failed",
                                  error=str(e)[:200])
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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return []`. The tenant's agent list shows
            # empty in Settings, so someone re-maps agents that are already mapped.
            _store_logger.warning("tenant_agent_list_read_failed",
                                  error=str(e)[:200])
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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return False`. The platform then
            # concludes there are no tenants yet and takes the first-startup
            # seeding path on an install that already has them.
            _store_logger.warning("tenant_exists_check_failed",
                                  error=str(e)[:200])
            return False

    def backfill_null_client_ids(self, tenant_id: str):
        """Backfill NULL client_id rows across all tenant-scoped tables.

        Needed when migration 7 ran before the default tenant was seeded,
        leaving all pre-existing rows with client_id = NULL.

        WO-H98: deliberately NOT wrapped in ``_txn``. The per-table
        ``except: skip`` below only means what it says if each UPDATE stands
        alone — inside one transaction the first failure aborts the whole
        block and every later table fails too, silently, which is what the old
        autocommit=False pool actually did. Independent statements make the
        documented skip-and-continue behaviour real. The backfill is idempotent
        (``WHERE client_id IS NULL``), so a partial run is safe to repeat.
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
            return True
        except Exception as e:                       # noqa: BLE001
            # WO-H88: was a bare `except: pass`. A failure here means
            # a user left attached to the wrong tenant.
            # Returns False so callers can tell, instead of every
            # caller assuming it worked.
            _store_logger.error("set_user_tenant_failed", error=str(e)[:200])
            return False

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
                    # WO-H90: left silent on purpose. Per-row parse of one decision's
                    # enrichment JSON inside a loop over the whole retention window. A
                    # malformed row is skipped by design, and this is exactly the hot loop
                    # the logging rule warns about.
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
            return True
        except Exception as e:                       # noqa: BLE001
            # WO-H88: was a bare `except: pass`. A failure here means
            # the MITRE coverage map going stale — the dashboard keeps showing yesterday's
            # picture of what you can and cannot detect.
            _store_logger.error("save_mitre_coverage_failed", error=str(e)[:200])
            return False

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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return []`. The ATT&CK coverage grid
            # renders as no coverage at all, which reads as 'we detect nothing'
            # rather than 'the query broke'.
            _store_logger.warning("get_mitre_coverage_failed",
                                  error=str(e)[:200])
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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return []`. Drilling into a technique
            # shows no detections for it even when there are some.
            _store_logger.warning("get_mitre_technique_detail_failed",
                                  error=str(e)[:200])
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

    def get_fp_rate_trend(self, granularity: str = "week",
                          buckets: int = 8) -> list[dict]:
        """Multi-period false-alarm-rate trend — the compounding-loop curve (WO-H31).

        Returns one point per ``granularity`` bucket (``'day'`` or ``'week'``)
        over the trailing window, oldest → newest. Each point::

            {"period": <label>, "fp_rate": <int 0-100>, "total": <int>, "fp": <int>}

        ``fp_rate`` is override-aware: the effective verdict is the analyst's
        correction (``COALESCE(NULLIF(human_verdict, ''), verdict)``) — so a
        human reclassification is the ground truth, matching the current-period
        fp_rate the report already shows. Only triage decisions are counted.

        Honesty: buckets with zero decisions are OMITTED (no fabricated points),
        so a quiet or newly-connected box yields a short or empty series and the
        report keeps its "accumulating" placeholder until periods pile up.
        Nothing is backfilled.

        Tenant-scoped via ``_tenant_filter()`` — cross-tenant only inside an
        explicit ``cross_tenant()`` context, matching the report data path.
        """
        if granularity not in ("day", "week"):
            raise ValueError(
                f"granularity must be 'day' or 'week', got {granularity!r}"
            )
        if buckets <= 0:
            return []

        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        span_days = buckets * (7 if granularity == "week" else 1)
        cutoff = self._iso_ago(days=span_days)
        rows = conn.execute(f"""
            SELECT date_trunc(%s, created_at::timestamptz) AS bucket,
                   COUNT(*) AS total,
                   SUM(CASE WHEN COALESCE(NULLIF(human_verdict, ''), verdict)
                                 = 'false_positive'
                            THEN 1 ELSE 0 END) AS fp
            FROM agent_decisions
            WHERE agent_type = 'triage'
              AND created_at::timestamptz >= %s {tf}
            GROUP BY bucket
            ORDER BY bucket ASC
        """, [granularity, cutoff] + tp).fetchall()

        label_fmt = "Wk of %d %b" if granularity == "week" else "%d %b"
        trend: list[dict] = []
        for r in rows:
            total = int(r["total"] or 0)
            if total <= 0:
                continue  # honesty: never emit a bucket with no decisions
            fp = int(r["fp"] or 0)
            bucket = r["bucket"]
            label = (bucket.strftime(label_fmt)
                     if hasattr(bucket, "strftime") else str(bucket))
            trend.append({
                "period": label,
                "fp_rate": round(100 * fp / total),
                "total": total,
                "fp": fp,
            })
        # date_trunc on a mid-window cutoff can admit a partial oldest bucket,
        # yielding N+1 — keep only the trailing N.
        trend = trend[-buckets:]
        _store_logger.debug("fp_rate_trend_computed",
                     granularity=granularity, buckets=len(trend))
        return trend

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

    # How the incident queue is ordered. ``newest`` sorts by when DHRUVA
    # CREATED the incident; ``event_time`` by the alert's own timestamp.
    _INCIDENT_SORTS = {
        "newest": "created_at DESC",
        "event_time": "last_seen DESC",
        "oldest": "created_at ASC",
    }
    _DEFAULT_INCIDENT_SORT = "newest"

    def get_incidents(self, status: str = None, severity: str = None,
                      assigned_to: str = None, limit: int = 100,
                      offset: int = 0, sort: str = None) -> list[dict]:
        """List incidents, newest-first by DHRUVA's own clock by default.

        This used to order by ``last_seen`` — the ALERT's timestamp — with no
        way to change it. That is the right axis for "when did this happen" and
        the wrong one for a work queue, and the difference only shows when
        triage falls behind.

        It did. On a live tenant on 2026-08-12, triage was ~15 hours
        behind: 666 incidents were created in five hours, every one of them
        carrying an alert timestamp from the previous evening, so all 666 sorted
        BELOW older incidents and never reached the top of the list. The team
        reported "no new alerts are coming in" — the alerts were arriving and
        being triaged; the queue was simply ordering them out of sight.

        ``newest`` is therefore the default: an analyst opening the queue wants
        what arrived most recently for THEM, not what happened most recently on
        the estate. ``event_time`` keeps the old behaviour for anyone who wants
        it, and the alert time is still on every row either way.
        """
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
        # Whitelist lookup, never interpolation — `sort` reaches this from a
        # query string. An unknown value falls back to the default rather than
        # erroring: a bad sort key should not empty an analyst's queue.
        order_by = self._INCIDENT_SORTS.get(
            (sort or self._DEFAULT_INCIDENT_SORT).lower(),
            self._INCIDENT_SORTS[self._DEFAULT_INCIDENT_SORT])
        query += f" ORDER BY {order_by} LIMIT %s OFFSET %s"
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

    # ── WO-H85: incident closure cascades WORK-ITEM state, never the verdict ──
    #
    # Two different things were conflated on this seam:
    #   * the INCIDENT is the WORK ITEM — closing it means "this investigation
    #     is finished", and that state SHOULD cascade to its constituent alerts.
    #     Nobody should hand-close 935 alerts after closing the incident that
    #     grouped them. Before this, `update_incident_status` never touched
    #     `agent_decisions`, so every member alert kept `resolved_at IS NULL`
    #     forever and sat in the unreviewed backlog.
    #   * `human_verdict` on each alert is EVIDENCE — what the Feedback Loop
    #     mines for noisy rules and what accuracy is measured against. It MUST
    #     NOT cascade silently: an incident groups alerts nobody individually
    #     judged (one observed attack chain carried 24 distinct source addresses
    #     — operational access, staff ranges and genuine attackers — correlated
    #     only because they touched the same host), so a blanket verdict would
    #     mislabel most of them.
    #
    # So: closing/resolving an incident sets `resolved_at` and NOTHING else.
    # Verdict propagation is a SEPARATE, EXPLICIT, opt-in call
    # (`propagate_incident_verdict`) that refuses to overwrite.

    #: incident states that mean "this investigation is finished".
    _WORK_ITEM_TERMINAL_STATUSES = frozenset({"resolved", "closed"})

    @staticmethod
    def _cascade_resolve_alerts(conn, incident_id: str, tf: str,
                                tp: list) -> int:
        """Mark an incident's still-open member alerts resolved AS WORK ITEMS.

        Touches ``resolved_at`` ONLY. ``human_verdict``, ``human_override`` and
        ``review_reason`` are deliberately NOT in the SET clause — closing a case
        is not a judgement on each alert inside it.

        AN ALERT DELIBERATELY HELD FOR A HUMAN IS NEVER SWEPT UP. Members that
        are ``escalated`` and still carry no ``human_verdict`` are excluded,
        because those are precisely the alerts the platform decided a person
        must look at. Two live triage paths produce exactly that shape with a
        TERMINAL-looking verdict (``src/agents/triage_agent.py``: the WO-H60
        ``auto_close_enabled=false`` hold, and the low-confidence auto-dismiss
        hold) — both write ``verdict='false_positive', escalated=True,
        human_verdict=NULL``. ``get_incident_verdict_mix`` buckets those as
        terminal, so ``rollup_incident_for_decision`` will auto-resolve an
        incident made entirely of them after a human reviews ONE OTHER alert.
        Without this exclusion the cascade would then stamp ``resolved_at`` on
        work nobody reviewed — asserting a review that never happened, which is
        the exact failure mode this work order exists to stop.

        That exclusion is also what keeps the cascade coherent with the pending
        review queue, which selects on ``escalated = 1 AND human_verdict = ''``
        (``get_recent_decisions``): the rows this skips are precisely the rows
        in that queue, so closing an incident can never quietly empty an
        analyst's queue. An analyst who HAS looked at those alerts records that
        through ``propagate_incident_verdict`` — the explicit, opt-in path.

        ``resolved_at IS NULL`` keeps the write idempotent (an already-resolved
        alert keeps its original timestamp). Runs on the caller's ``conn`` so it
        commits atomically with the incident's own status change. The ``{tf}``
        filter is on ``agent_decisions.client_id``, so a foreign incident's
        alerts can never be swept in.
        """
        cursor = conn.execute(f"""
            UPDATE agent_decisions
            SET resolved_at = CURRENT_TIMESTAMP::text
            WHERE resolved_at IS NULL
              AND NOT (escalated = 1 AND COALESCE(human_verdict, '') = '')
              AND id IN (SELECT decision_id FROM incident_alerts
                         WHERE incident_id = %s)
              {tf}
        """, [incident_id] + tp)
        return cursor.rowcount or 0

    @staticmethod
    def _count_held_for_human(conn, incident_id: str, tf: str,
                              tp: list) -> int:
        """How many members the cascade deliberately LEFT OPEN — escalated and
        still unjudged. Reported so the timeline says what was not done, rather
        than letting a partial cascade look complete."""
        row = conn.execute(f"""
            SELECT COUNT(*) AS cnt FROM agent_decisions
            WHERE resolved_at IS NULL
              AND escalated = 1 AND COALESCE(human_verdict, '') = ''
              AND id IN (SELECT decision_id FROM incident_alerts
                         WHERE incident_id = %s)
              {tf}
        """, [incident_id] + tp).fetchone()
        return (row["cnt"] if row else 0) or 0

    #: WO-H112 — statuses that END an investigation. Mirrors CLOSING_STATUSES
    #: in src/api/models.py.
    _CLOSING_STATUSES = ("resolved", "closed")

    def _ai_majority_verdict(self, conn, incident_id: str, tf: str,
                             tp: list) -> Optional[str]:
        """The AI's majority verdict on this case's members, ignoring humans.

        Deliberately NOT ``get_incident_verdict_mix``, which returns the
        EFFECTIVE verdict (human override wins). For WO-H112 we need what the
        AI said, so a later comparison against the analyst's closure reason is
        between two independent things rather than a value against itself.

        Returns None when the case has no member decisions — which marks an
        UNANCHORED closure, the only kind where agreement means anything.
        """
        try:
            rows = conn.execute(f"""
                SELECT ad.verdict AS v, COUNT(*) AS n
                FROM agent_decisions ad
                JOIN incident_alerts ia ON ia.decision_id = ad.id
                WHERE ia.incident_id = %s AND ad.verdict IS NOT NULL {tf}
                GROUP BY ad.verdict
                ORDER BY n DESC, v ASC
                LIMIT 1
            """, [incident_id] + tp).fetchone()
        except Exception as e:                                  # noqa: BLE001
            # Never block a closure over a metrics snapshot. NULL here means
            # "not captured", and the dashboard must not read it as "no AI
            # verdict existed" — see the migration note.
            _store_logger.warning("ai_verdict_snapshot_failed",
                                  incident_id=incident_id, error=str(e)[:200])
            return None
        return rows["v"] if rows else None

    def update_incident_status(self, incident_id: str, status: str,
                                actor: str = "system", reason: Optional[str] = None,
                                closure_reason: Optional[str] = None,
                                ai_was_wrong: Optional[bool] = None,
                                ai_wrong_detail: Optional[str] = None) -> bool:
        # WO-H98: status write + timeline entry + the WO-H85 member-alert
        # cascade are ONE transaction. `_cascade_resolve_alerts` documents that
        # it "commits atomically with the incident's own status change"; on the
        # autocommit pool that is only true inside `_txn`.
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        cascaded = 0
        held = 0
        closing = status in self._CLOSING_STATUSES
        with self._txn(conn):
            # WO-H112: snapshot what the AI said BEFORE the row changes, and
            # only when the investigation is actually ending. Captured inside
            # the same transaction as the status write so the pair cannot
            # disagree.
            ai_verdict = (self._ai_majority_verdict(conn, incident_id, tf, tp)
                          if closing else None)
            # WO-H112 QA (BLOCK, B2): COALESCE, NOT OVERWRITE.
            #
            # The first cut wrote all five columns on ANY transition into
            # resolved/closed. `src/ticketing/service.py` calls this with no
            # closure arguments on the ordinary ServiceNow/Jira
            # `resolved -> closed` lifecycle — so an analyst recorded
            # `true_positive`, the ticket system auto-closed the case an hour
            # later, and the label was silently replaced with NULL. The erased
            # row was then indistinguishable from one nobody ever labelled,
            # which is precisely the thing this work order exists to create.
            #
            # A caller that supplies nothing now changes nothing, and
            # `closure_recorded_at` is stamped only when a structured closure
            # actually arrives — otherwise a machine-driven close inflates
            # `without_structured_reason` in the metric.
            if closing:
                conn.execute(f"""
                    UPDATE incidents
                    SET closure_reason = COALESCE(%s, closure_reason),
                        ai_was_wrong = COALESCE(%s, ai_was_wrong),
                        ai_wrong_detail = COALESCE(%s, ai_wrong_detail),
                        -- DELIBERATELY WRITE-ONCE (QA re-audit, LOW).
                        -- Unlike closure_reason, which an analyst must be able
                        -- to correct, this is a SNAPSHOT of what the AI said at
                        -- the moment the case was first closed. Refreshing it on
                        -- a reopen-and-reclose would compare the analyst's final
                        -- answer against a verdict produced AFTER they had
                        -- already seen the first one — which is the anchoring
                        -- the field exists to detect.
                        ai_verdict_at_close = COALESCE(%s, ai_verdict_at_close),
                        closure_recorded_at = CASE WHEN %s::text IS NOT NULL
                            THEN CURRENT_TIMESTAMP::text
                            ELSE closure_recorded_at END
                    WHERE id = %s {tf}
                """, [closure_reason,
                      None if ai_was_wrong is None else int(bool(ai_was_wrong)),
                      ai_wrong_detail, ai_verdict, closure_reason,
                      incident_id] + tp)
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
            # WO-H85: finishing the investigation closes the WORK ITEMS it grouped.
            # Verdicts are untouched, and alerts still HELD for a human are left
            # open — see _cascade_resolve_alerts.
            if status in self._WORK_ITEM_TERMINAL_STATUSES:
                cascaded = self._cascade_resolve_alerts(conn, incident_id, tf, tp)
                held = self._count_held_for_human(conn, incident_id, tf, tp)
                if cascaded or held:
                    held_note = (
                        f" {held} alert(s) were left open because they are "
                        f"escalated and still awaiting a human verdict — closing "
                        f"the case does not review them." if held else "")
                    conn.execute("""
                        INSERT INTO incident_timeline
                        (id, incident_id, event_type, description, actor, created_at)
                        VALUES (%s, %s, 'alerts_resolved', %s, %s,
                                CURRENT_TIMESTAMP::text)
                    """, (str(uuid.uuid4()), incident_id,
                          f"{cascaded} member alert(s) marked resolved with the "
                          f"incident. Analyst verdicts were NOT changed — recording "
                          f"a verdict on an alert stays a separate, explicit action."
                          + held_note,
                          actor))
        conn.commit()
        _store_logger.info("incident_status_updated", incident_id=incident_id,
                           status=status, actor=actor,
                           alerts_resolved=cascaded,
                           alerts_held_for_human=held,
                           closure_reason=closure_reason,
                           ai_was_wrong=ai_was_wrong)

        return True

    def propagate_incident_verdict(self, incident_id: str, human_verdict: str,
                                   reviewer: str,
                                   reason: Optional[str] = None) -> dict:
        """Apply ONE human verdict to an incident's member alerts — OPT-IN, and
        REFUSED wherever a human verdict already exists.

        This is the deliberate, separate action that incident closure must NOT
        do implicitly (see ``_cascade_resolve_alerts``). Callers reach it only
        through an explicit confirmed request; it is never invoked by a status
        change, by triage, or by any scheduled cycle.

        The refusal is enforced IN THE WRITE, not just by a pre-read: every
        UPDATE carries ``AND (human_verdict IS NULL OR human_verdict = '')`` so
        a verdict recorded between the read and the write still survives. That
        guard is what preserved one analyst's three brute-force labels through
        four bulk passes; it is not decorative.

        Returns::

            {"total": N, "applied": a, "skipped": s,
             "applied_ids": [...], "skipped_ids": [...]}

        where ``skipped`` counts members left alone because a human had already
        judged them.

        SET-BASED, not a per-member loop (WO-H85 follow-up): the observed
        935-alert incident would otherwise issue ~1870 statements on one pooled
        connection. This is a bounded 3 statements — one member read, one
        `UPDATE ... WHERE id = ANY(...) RETURNING id`, and one multi-row INSERT
        of the history entries — regardless of incident size. The refusal guard
        lives in that single UPDATE's WHERE clause, so batching does not weaken
        it: the rows it declines to touch simply do not come back in RETURNING.
        """
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        with self._txn(conn):
            members = conn.execute(f"""
                SELECT ad.id, ad.human_verdict FROM agent_decisions ad
                JOIN incident_alerts ia ON ia.decision_id = ad.id
                WHERE ia.incident_id = %s {tf}
                ORDER BY ad.created_at ASC, ad.id ASC
            """, [incident_id] + tp).fetchall()
            member_ids = [r["id"] for r in members]
            # The pre-read narrows the candidate set so the UPDATE does not scan
            # members it obviously cannot touch. It is NOT the safeguard — a verdict
            # recorded between this read and the write below would slip past it. The
            # WHERE clause is the safeguard; see the race test in
            # tests/test_incident_closure_and_review_history.py.
            candidates = [r["id"] for r in members
                          if not (r["human_verdict"] or "").strip()]

            applied_ids: list[str] = []
            if candidates:
                rows = conn.execute(f"""
                    UPDATE agent_decisions
                    SET human_override = %s, human_verdict = %s,
                        review_reason = %s,
                        resolved_at = COALESCE(resolved_at, CURRENT_TIMESTAMP::text)
                    WHERE id = ANY(%s)
                      AND (human_verdict IS NULL OR human_verdict = '')
                      {tf}
                    RETURNING id
                """, [reviewer, human_verdict, reason, candidates] + tp).fetchall()
                applied_ids = [r["id"] for r in rows]
            if applied_ids:
                # Append-only history, same transaction as the verdict write,
                # tagged as PROPAGATED so an inherited label is never mistaken for
                # an individually-judged one. One statement for the whole batch;
                # ids are generated here rather than in SQL to match the uuid4
                # convention every other insert in this module uses.
                conn.execute("""
                    INSERT INTO decision_reviews
                    (id, decision_id, reviewer, human_verdict, reason,
                     previous_verdict, source, created_at)
                    SELECT x.rid, x.did, %s, %s, %s, NULL, %s,
                           CURRENT_TIMESTAMP::text
                    FROM unnest(%s::text[], %s::text[]) AS x(rid, did)
                """, (reviewer, human_verdict, reason,
                      self.REVIEW_SOURCE_PROPAGATED,
                      [str(uuid.uuid4()) for _ in applied_ids], applied_ids))
            # Anything not returned by the UPDATE was refused — either it already
            # carried a human verdict at read time, or it acquired one before the
            # write landed and the guard held.
            applied_set = set(applied_ids)
            skipped_ids = [i for i in member_ids if i not in applied_set]

            if applied_ids or skipped_ids:
                conn.execute("""
                    INSERT INTO incident_timeline
                    (id, incident_id, event_type, description, actor, created_at)
                    VALUES (%s, %s, 'verdict_propagated', %s, %s,
                            CURRENT_TIMESTAMP::text)
                """, (str(uuid.uuid4()), incident_id,
                      f"Verdict '{human_verdict}' applied to {len(applied_ids)} "
                      f"member alert(s); {len(skipped_ids)} left unchanged because "
                      f"a human verdict already existed."
                      + (f" — {reason}" if reason else ""),
                      reviewer))
        conn.commit()
        _store_logger.info("incident_verdict_propagated",
                           incident_id=incident_id, reviewer=reviewer,
                           verdict=human_verdict, total=len(members),
                           applied=len(applied_ids), skipped=len(skipped_ids))
        return {
            "total": len(members),
            "applied": len(applied_ids),
            "skipped": len(skipped_ids),
            "applied_ids": applied_ids,
            "skipped_ids": skipped_ids,
        }

    def get_incident_verdict_propagation_preview(self, incident_id: str) -> dict:
        """What an opt-in verdict propagation WOULD do — read-only (WO-H85).

        Backs the UI control's honesty requirements: it shows the alert count it
        would touch, and warns when the incident's alerts do not already agree
        with each other (``agree`` is False when the members carry more than one
        distinct effective verdict).

        Shape::

            {"total": N, "eligible": e, "protected": p,
             "distinct_verdicts": [...], "agree": bool}

        ``protected`` = members a human has already judged; propagation refuses
        those. Tenant-scoped like ``get_incident_alerts``.
        """
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        rows = conn.execute(f"""
            SELECT ad.human_verdict AS hv,
                   COALESCE(ad.human_verdict, ad.verdict) AS eff
            FROM agent_decisions ad
            JOIN incident_alerts ia ON ia.decision_id = ad.id
            WHERE ia.incident_id = %s {tf}
        """, [incident_id] + tp).fetchall()
        total = len(rows)
        protected = sum(1 for r in rows if (r["hv"] or "").strip())
        distinct = sorted({(r["eff"] or "unknown") for r in rows})
        return {
            "total": total,
            "eligible": total - protected,
            "protected": protected,
            "distinct_verdicts": distinct,
            "agree": len(distinct) <= 1,
        }

    def assign_incident(self, incident_id: str, assigned_to: str,
                         actor: str = "system") -> bool:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        # WO-H98: assignment + its timeline entry land together or not at all.
        with self._txn(conn):
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
            return True
        except Exception as e:                       # noqa: BLE001
            # WO-H88: was `pass  # columns may not exist on older schema`. That
            # excuse is stale — tier / sla_response_due / sla_resolution_due are
            # all in the incidents table and the schema is enforced by alembic.
            # A failure here means an incident with no SLA deadlines, so it can
            # never breach and never escalate. Silence made that indistinguishable
            # from an incident that is simply within its SLA.
            _store_logger.error("set_incident_sla_failed",
                                incident_id=incident_id, error=str(e)[:200])
            return False

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
            return True
        except Exception as e:                       # noqa: BLE001
            # WO-H88: was a bare `except: pass`. A failure here means
            # response-time SLA measured from the wrong moment, or never satisfied.
            # Returns False so callers can tell, instead of every
            # caller assuming it worked.
            _store_logger.error("record_first_response_failed", error=str(e)[:200])
            return False

    def escalate_incident_tier(self, incident_id: str, new_tier: str,
                                handoff_notes: str, actor: str,
                                sla_response_due: str = None,
                                sla_resolution_due: str = None):
        """Escalate an incident to a higher tier with handoff notes."""
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            # WO-H98: the tier bump (which also resets first_response_at and
            # the SLA clock) and its handoff timeline entry are one unit — a
            # half-applied escalation is an incident whose SLA restarted with
            # no record of why.
            with self._txn(conn):
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
            return True
        except Exception as e:                       # noqa: BLE001
            # WO-H88: was a bare `except: pass`. A failure here means
            # an escalation the analyst believes happened and did not.
            # Returns False so callers can tell, instead of every
            # caller assuming it worked.
            _store_logger.error("escalate_incident_tier_failed", error=str(e)[:200])
            return False

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
            return True
        except Exception as e:                       # noqa: BLE001
            # WO-H88: was a bare `except: pass`. A failure here means
            # evidence an analyst typed and believes is saved, silently discarded.
            # Returns False so callers can tell, instead of every
            # caller assuming it worked.
            _store_logger.error("add_incident_evidence_failed", error=str(e)[:200])
            return False

    def save_sla_breach(self, breach: dict):
        """Record an SLA breach. One row per (incident, sla_type) — WO-H87.

        The `ON CONFLICT` clause here READ as dedup protection and was not: the
        caller mints a fresh uuid4() for `id` on every run
        (src/incidents/sla.py:133,158) and `id` is the primary key, so there was
        never a conflict to do nothing about. Every SLA check re-recorded every
        still-open breach as a NEW row.

        A live tenant, 2026-08-18, before migration 0014:

            3,577,852 rows / 1,052 MB   - the largest table in the database
            8,284 incidents             - ~430 breach rows per incident
            1,709 copies of one incident's single breach
            growing 3,000-4,700 rows/day, and not in RETENTION_PRUNABLE

        `agent_decisions` - every triage decision ever made - is 27,407 rows.

        Migration 0014 adds a UNIQUE index on
        (client_id, incident_id, sla_type), so the conflict target below is now
        real. The FIRST detection wins: that is when the SLA actually breached,
        and a later re-check must not overwrite it with a later timestamp.
        """
        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT INTO sla_breaches
                (id, incident_id, sla_type, severity, tier, due_at, breached_at, client_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (client_id, incident_id, sla_type) DO NOTHING
            """, (
                breach["id"], breach["incident_id"], breach["sla_type"],
                breach["severity"], breach.get("tier", "L1"),
                breach["due_at"], breach["breached_at"],
                breach.get("client_id") or self._tenant_value(),
            ))
            conn.commit()
        except Exception as e:                       # noqa: BLE001 - never fatal
            # Was a bare `except: pass`. An SLA breach failing to record is a
            # gap in the compliance record, and silence is how this table grew
            # to a gigabyte without anyone noticing.
            _store_logger.warning("sla_breach_save_failed",
                                  incident_id=breach.get("incident_id"),
                                  sla_type=breach.get("sla_type"),
                                  error=str(e)[:200])

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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return []`. The SLA monitor then finds
            # nothing to check, so response and resolution deadlines stop being
            # enforced and no breach is ever raised.
            _store_logger.error("open_sla_incidents_query_failed",
                                error=str(e)[:200])
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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return []`. An incident shows a clean SLA
            # record when it may in fact have breached.
            _store_logger.warning("get_sla_breaches_failed",
                                  error=str(e)[:200])
            return []

    def get_notified_breach_keys(self, incident_ids: list) -> set:
        """``(incident_id, sla_type)`` pairs already recorded as DELIVERED.

        One query for a whole scheduler pass. This replaces a per-incident
        ``get_sla_breaches`` call, which was an N+1: on 2,000 open breached
        incidents it cost 4,001 execute calls and 1.69s per pass, and the SLA
        checker runs every 5 minutes for every tenant.

        Scoped to the incidents actually being examined rather than selecting
        every notified row, so the result set stays bounded by the open-incident
        count instead of growing with the table (3.5M rows on one live tenant).

        **Deliberately does not swallow its exceptions.** Every other read in
        this file returns a safe-looking default on failure; here that default
        would be "nothing has been delivered", which makes the caller announce
        breaches that were already announced. The caller decides what a failure
        means and logs it — see SLAManager._delivered_breach_keys.
        """
        if not incident_ids:
            return set()
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        rows = conn.execute(
            f"""SELECT incident_id, sla_type FROM sla_breaches
                WHERE notified = 1 AND incident_id = ANY(%s) {tf}""",
            [list(incident_ids)] + tp).fetchall()
        return {(r["incident_id"], r["sla_type"]) for r in rows}

    def mark_sla_breach_notified(self, incident_id: str, sla_type: str) -> bool:
        """Record that a breach notification was actually DELIVERED.

        WO-H101. ``notified`` shipped in the 0001 baseline and no code path ever
        set it: all 13,980 rows on a live tenant read 0, so the column said
        "nobody was told" whether or not anybody was. It now means exactly one
        thing, and it is written from exactly one place — after
        ``notify_sla_breach()`` returns True.

        This distinction is the whole point of the work order. The EXISTENCE of
        a row means "we detected this breach". ``notified = 1`` means "a channel
        accepted the message". Collapsing those two is how a caller ends up
        believing a breach was announced when it was recorded and discarded.

        Returns True only when a row was actually updated, so the caller can
        tell a successful write from a no-op. A False return is deliberately
        NOT fatal: the notification already went out, and the worst case of a
        failed write here is that the breach is announced a second time — which
        is recoverable, unlike losing the page.
        """
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            cur = conn.execute(
                f"""UPDATE sla_breaches SET notified = 1
                    WHERE incident_id = %s AND sla_type = %s {tf}""",
                [incident_id, sla_type] + tp)
            conn.commit()
            return (cur.rowcount or 0) > 0
        except Exception as e:                       # noqa: BLE001 — never fatal
            _store_logger.warning("mark_sla_breach_notified_failed",
                                  incident_id=incident_id, sla_type=sla_type,
                                  error=str(e)[:200])
            return False

    def add_alert_to_incident(self, incident_id: str, decision_id: str) -> bool:
        conn = self._get_conn()
        # WO-H98: membership row, the recount it feeds, and the timeline entry
        # are one transaction — otherwise a failure between the first two
        # leaves `incidents.alert_count` disagreeing with `incident_alerts`,
        # which is the number the triage queue and the case view both show.
        with self._txn(conn):
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
        # WO-H98: note + the incident's updated_at touch are one transaction.
        with self._txn(conn):
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
        # WO-H98: entry + the incident's updated_at touch are one transaction.
        with self._txn(conn):
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

    # ── WO-H17: verdict roll-up → incident state ────────────────────────────
    # Terminal dispositions = an analyst/AI has made a final call. Anything
    # else (needs_investigation / unknown / NULL) is still "open" for the
    # purpose of the incident roll-up. Benign = the two FP-flavoured terminals.
    _TERMINAL_VERDICTS = frozenset({"false_positive", "auto_close", "true_positive"})
    _BENIGN_VERDICTS = frozenset({"false_positive", "auto_close"})

    @staticmethod
    def _verdict_bucket(effective_verdict: Optional[str]) -> str:
        """Map an effective verdict to one of the four roll-up buckets:
        ``false_positive`` / ``true_positive`` / ``auto_close`` / ``open``.
        Non-terminal or unknown verdicts (incl. ``needs_investigation`` and
        NULL) collapse to ``open``."""
        if effective_verdict in ("false_positive", "true_positive", "auto_close"):
            return effective_verdict
        return "open"

    def get_incident_verdict_mix(self, incident_id: str) -> dict:
        """Return the CURRENT effective-verdict mix of an incident's member
        decisions (WO-H17 read-side reflection).

        Effective verdict per member = ``human_verdict`` when set, else the AI
        ``verdict`` — so the mix reflects human overrides, not a stale snapshot.
        Shape (additive to the incident-detail response)::

            {"total": N, "open": z, "false_positive": x,
             "true_positive": y, "auto_close": w}

        Tenant-scoped exactly like ``get_incident_alerts`` (the ``{tf}`` filter
        resolves to ``agent_decisions.client_id``), so it can never count
        another tenant's decisions.
        """
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        rows = conn.execute(f"""
            SELECT COALESCE(ad.human_verdict, ad.verdict) AS eff
            FROM agent_decisions ad
            JOIN incident_alerts ia ON ia.decision_id = ad.id
            WHERE ia.incident_id = %s {tf}
        """, [incident_id] + tp).fetchall()
        mix = {"total": 0, "open": 0, "false_positive": 0,
               "true_positive": 0, "auto_close": 0}
        for r in rows:
            mix["total"] += 1
            mix[self._verdict_bucket(r["eff"])] += 1
        return mix

    def count_triaged_incident_alerts(self, incident_id: str) -> int:
        """How many of an incident's member alerts were actually ANALYSED.

        A row where ``llm_failed`` is true and no human has since supplied a
        verdict is not a judgement — it is a triage attempt that errored (LLM
        timeout, no backend, malformed response) and was escalated by default.
        It carries a verdict field, but nothing decided it.

        This is the same rule WO-H46-b applies to detection-rule evidence
        (``AND NOT (llm_failed AND human_verdict IS NULL)``), reused here so
        the attack-chain builder cannot assert a kill chain out of alerts that
        were never triaged.

        Tenant-scoped identically to ``get_incident_alerts``.
        """
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        row = conn.execute(f"""
            SELECT COUNT(*) AS n
            FROM agent_decisions ad
            JOIN incident_alerts ia ON ia.decision_id = ad.id
            WHERE ia.incident_id = %s {tf}
              AND NOT (ad.llm_failed AND ad.human_verdict IS NULL)
        """, [incident_id] + tp).fetchone()
        return int(row["n"]) if row else 0

    def _incidents_for_decision(self, decision_id: str) -> list[dict]:
        """Tenant-scoped lookup of the incident(s) that group ``decision_id``.

        Joins ``incident_alerts`` back to its parent ``incidents`` row and
        applies the tenant filter on ``incidents.client_id`` (the only
        ``client_id`` in the join — ``incident_alerts`` is FK-scoped), so a
        decision can only ever surface incidents owned by the current tenant.
        """
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        rows = conn.execute(f"""
            SELECT i.id, i.status
            FROM incidents i
            JOIN incident_alerts ia ON ia.incident_id = i.id
            WHERE ia.decision_id = %s {tf}
        """, [decision_id] + tp).fetchall()
        return [dict(r) for r in rows]

    def rollup_incident_for_decision(self, decision_id: str,
                                     actor: str = "system",
                                     auto_resolve: bool = True) -> list[dict]:
        """WO-H17 — after a human override on ``decision_id``, recompute the
        verdict roll-up of every incident that groups this decision and, when
        configured, conservatively auto-resolve incidents that are now fully
        dispositioned false-positive/benign.

        Conservative rule (per incident):
          * ALL members terminal (none still ``open``) AND none ``true_positive``
            → transition to ``resolved`` via ``update_incident_status`` (reuses
            the existing timeline + ``resolved_at`` audit path).
          * ANY member ``true_positive`` → stays open (NEVER auto-close a
            TP/mixed incident).
          * ANY member still ``open`` (non-terminal) → stays open.
        A single member verdict can therefore never close a multi-alert
        incident that still has open or TP members.

        Only incidents currently ``open``/``investigating`` are touched — a
        resolved/closed incident is never reopened or re-resolved.

        ``auto_resolve`` mirrors the ``incidents.auto_resolve_on_all_fp`` config
        flag: when False the status transition is skipped (the read-side mix in
        ``get_incident_verdict_mix`` still reflects the override).

        Tenant-scoped end to end: incident lookup, verdict mix, and the
        ``update_incident_status`` transition all fail-closed on the tenant
        filter — an override in one tenant can NEVER resolve another tenant's
        incident. Active-response posture untouched: resolving an incident
        triggers NO response action.

        Returns a per-incident summary list (for logging/tests).
        """
        results = []
        for inc in self._incidents_for_decision(decision_id):
            inc_id = inc["id"]
            status = inc.get("status")
            mix = self.get_incident_verdict_mix(inc_id)
            summary = {"incident_id": inc_id, "status": status,
                       "mix": mix, "action": "none"}
            if status not in ("open", "investigating"):
                # Never reopen / re-resolve a settled incident.
                summary["action"] = "skipped_not_open"
                results.append(summary)
                continue
            total = mix["total"]
            all_terminal = total > 0 and mix["open"] == 0
            no_tp = mix["true_positive"] == 0
            if all_terminal and no_tp:
                if auto_resolve:
                    reason = (f"Auto-resolved: all {total} alerts dispositioned "
                              f"false-positive/benign")
                    self.update_incident_status(
                        inc_id, status="resolved", actor=actor, reason=reason)
                    summary["action"] = "resolved"
                else:
                    summary["action"] = "resolve_suppressed_by_config"
            # else: TP present or members still open → leave open.
            _store_logger.info("incident_verdict_rollup",
                               incident_id=inc_id, action=summary["action"],
                               total=total, open=mix["open"],
                               false_positive=mix["false_positive"],
                               true_positive=mix["true_positive"],
                               auto_close=mix["auto_close"],
                               auto_resolve=auto_resolve)
            results.append(summary)
        return results

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
        # WO-H98: a merge is six statements across three tables — alerts move,
        # the target is recounted, the sources are closed, and both sides get a
        # timeline entry. Half of that is a corrupted case: alerts orphaned onto
        # an incident that was never recounted, or sources closed with their
        # alerts still attached. One transaction.
        with self._txn(conn):
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

    def auto_block_already_executed(self, decision_id: str,
                                    target_ip: str = None) -> bool:
        """Return True if an auto ``block_ip`` was already EXECUTED for this
        decision (WO-H9 active-response idempotency).

        Tenant-scoped. Paired with :meth:`serialized_section` in the auto-block
        path so the check-then-execute-then-record sequence is atomic: even if
        two workers/replicas reach EXECUTE for the same decision concurrently,
        the second observes the recorded executed row here and skips — the
        block fires exactly once.
        """
        if not decision_id:
            return False
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        params = [decision_id]
        ip_clause = ""
        if target_ip:
            ip_clause = " AND target_ip = %s"
            params.append(target_ip)
        row = conn.execute(f"""
            SELECT 1 FROM active_response_audit
            WHERE mode = 'auto' AND action = 'block_ip'
              AND status = 'executed'
              AND decision_id = %s{ip_clause} {tf}
            LIMIT 1
        """, params + tp).fetchone()
        return row is not None

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

    def claim_ar_proposal(self, action_id: str, approver: str) -> bool:
        """Atomically claim a pending AR proposal for execution (WO-S6).

        Transitions ``pending_approval`` -> ``approving`` in a single
        conditional UPDATE and returns True ONLY if this caller won. Returns
        False if the row does not exist, is not pending, or another request
        already claimed it.

        This makes approval genuinely one-shot. Previously ``approve`` did a
        read (``get_ar_action``), checked ``status == "pending_approval"``, and
        dispatched — but never transitioned the row. The same ``action_id``
        could therefore be re-approved repeatedly, re-dispatching a destructive
        action (isolate_host, kill_process, disable_user) each time and
        defeating the per-action cooldown. The read-then-check was also a TOCTOU
        window between two concurrent approvals.

        The approver is appended to ``reason`` rather than written to dedicated
        columns: ``active_response_audit`` has no ``approved_by``/``approved_at``
        (migration 0002), and the approving analyst is already recorded as the
        ``actor`` of the separate execution row this approval writes.
        """
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        claimed_at = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(f"""
            UPDATE active_response_audit
            SET status = 'approving',
                reason = COALESCE(reason, '') || %s
            WHERE id = %s AND status = 'pending_approval' {tf}
        """, [f"|claimed_by:{approver}@{claimed_at}", action_id] + tp)
        conn.commit()
        return cur.rowcount > 0

    def set_ar_status(self, action_id: str, status: str) -> bool:
        """Set an AR audit row's status (tenant-scoped). Returns True if updated.

        Used by WO-S6 to release a proposal claimed by ``claim_ar_proposal``
        when dispatch does not happen (validation failure) or to record the
        terminal outcome after it does.
        """
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        cur = conn.execute(f"""
            UPDATE active_response_audit SET status = %s WHERE id = %s {tf}
        """, [status, action_id] + tp)
        conn.commit()
        return cur.rowcount > 0

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
        # WO-H85: an INHERITED label does not count as a review. One opt-in
        # incident-level propagation stamps `human_override` on every
        # unreviewed member, so without this a single click reported as five
        # reviews. Excluded by the LATEST decision_reviews entry, so an alert
        # that was propagated and later individually re-reviewed counts again.
        row = conn.execute(f"""
            SELECT COUNT(*) as reviews_done FROM agent_decisions
            WHERE human_override = %s
              AND resolved_at >= %s
              AND NOT EXISTS (
                  SELECT 1 FROM decision_reviews dr
                  WHERE dr.decision_id = agent_decisions.id
                    AND dr.source = %s
                    AND dr.seq = (SELECT MAX(dr2.seq) FROM decision_reviews dr2
                                  WHERE dr2.decision_id = agent_decisions.id)
              )
              {tf}
        """, [username, cutoff, self.REVIEW_SOURCE_PROPAGATED] + tp).fetchone()
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
        # WO-H98: "in a single transaction" (docstring) is now explicit.
        # This PRESERVES the old behaviour rather than changing it: under the
        # non-autocommit pool a mid-batch failure aborted the implicit
        # transaction and the trailing `conn.commit()` degraded to a rollback,
        # so the whole batch was already all-or-nothing. Without `_txn` the
        # autocommit pool would commit each row of the executemany on its own
        # and a feed failing halfway would leave a partially-ingested IOC set.
        with self._txn(conn), conn.cursor() as cur:
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
        except Exception as e:
            # local_iocs may legitimately not exist on older schemas, so this
            # stays non-fatal. But it previously swallowed EVERY failure in
            # silence, including a real query error — which reads downstream as
            # "no operator-added IOC matched" and is indistinguishable from a
            # clean result. Log it so a genuine failure is visible; the caller's
            # threat_intel_lookup_ok flag still reflects the feed-store lookup
            # that did complete above.
            _store_logger.warning("local_ioc_lookup_failed", error=str(e)[:200],
                           detail="Operator-added IOCs were not consulted for "
                                  "this batch. Expected on pre-local_iocs "
                                  "schemas; investigate otherwise.")
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
        # WO-H98: read-then-UPDATE-else-INSERT, kept as one unit of work.
        # NOT what stops a duplicate row — READ COMMITTED lets two collectors
        # both read 'no row', and it is the `threat_intel_feeds_feed_name_key`
        # UNIQUE constraint that refuses the second INSERT. The transaction is
        # here so the existence check and the write it decides between cannot be
        # committed apart.
        with self._txn(conn):
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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return {}`. A ticket reads as missing, so
            # an analyst is told there is no ticket for work that has one.
            _store_logger.warning("get_ticket_read_failed", error=str(e)[:200])
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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return None`. An inbound update from
            # Jira/ServiceNow finds no matching ticket and is dropped, so the
            # external status never lands here.
            _store_logger.warning("get_ticket_by_external_id_failed",
                                  error=str(e)[:200])
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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return []`. The ticket list renders
            # empty, which reads as 'no tickets' rather than 'read failed'.
            _store_logger.warning("get_tickets_failed", error=str(e)[:200])
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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return []`. An incident shows no linked
            # tickets, so someone raises a duplicate in Jira/ServiceNow.
            _store_logger.warning("get_tickets_for_incident_failed",
                                  error=str(e)[:200])
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
            return True
        except Exception as e:                       # noqa: BLE001
            # WO-H88: was a bare `except: pass`. A failure here means
            # DHRUVA's copy of a ticket drifting from the real one in Jira/ServiceNow,
            # so an analyst reads a status that is no longer true.
            _store_logger.error("update_ticket_failed", error=str(e)[:200])
            return False

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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return []`. The sync worker finds nothing
            # to sync, so DHRUVA and the ticketing system drift apart while both
            # sides look healthy.
            _store_logger.warning("tickets_needing_sync_query_failed",
                                  error=str(e)[:200])
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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return []`. Tickets already sitting in
            # error state stop being retried, and nothing says so.
            _store_logger.warning("tickets_needing_retry_query_failed",
                                  error=str(e)[:200])
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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return []`. The sync history shows blank
            # to whoever is trying to work out why a ticket will not sync.
            _store_logger.warning("get_ticket_sync_log_failed",
                                  error=str(e)[:200])
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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except:` returning zeros. The ticket panel then
            # reads 'errors: 0' while tickets are actually failing to sync.
            _store_logger.warning("get_ticket_stats_failed",
                                  error=str(e)[:200])
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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return None`. A runbook reads as missing,
            # so the analyst works the alert without it.
            _store_logger.warning("get_kb_document_read_failed",
                                  error=str(e)[:200])
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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return []`. The knowledge base looks
            # empty, which reads as 'nobody wrote anything yet'.
            _store_logger.warning("get_kb_documents_failed",
                                  error=str(e)[:200])
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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return False`. The caller can already see
            # the False; nobody could see WHY an edit to a runbook did not stick.
            _store_logger.error("update_kb_document_failed",
                                error=str(e)[:200])
            return False

    def delete_kb_document(self, doc_id: str) -> bool:
        conn = self._get_conn()
        try:
            tf, tp = self._tenant_filter()
            conn.execute(f"DELETE FROM kb_documents WHERE id = %s {tf}", [doc_id] + tp)
            conn.commit()
            return True
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return False`. A document someone
            # deliberately removed is still there, and the reason was invisible.
            _store_logger.error("delete_kb_document_failed",
                                error=str(e)[:200])
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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return 0`. Zero is indistinguishable from
            # 'there were none to delete', so a guidance reload believes it cleared
            # the old documents and leaves stale runbooks in place.
            _store_logger.error("delete_kb_by_type_failed", error=str(e)[:200])
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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return None`. A document that already
            # exists for this source looks absent, so the next sync writes a
            # duplicate of it.
            _store_logger.warning("get_kb_by_source_failed",
                                  error=str(e)[:200])
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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except:` returning zeros. The knowledge-base
            # counters read as an empty KB.
            _store_logger.warning("get_kb_stats_failed", error=str(e)[:200])
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
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: return None`. A hunt finding reads as
            # missing, so the analyst cannot open something the hunt actually
            # found.
            _store_logger.warning("get_hunt_finding_read_failed",
                                  error=str(e)[:200])
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

    def upsert_discovered_asset(self, hostname: str,
                                ip: Optional[str] = None,
                                os_name: Optional[str] = None) -> bool:
        """WO-H51: seed one asset from the enrolled Wazuh agent list.

        NON-CLOBBERING BY DESIGN. save_asset() upserts
        ``ON CONFLICT DO UPDATE SET tier = EXCLUDED.tier, owner = …`` — so
        reusing it for discovery would ERASE any tier/owner an analyst set. This
        method instead INSERTs a stub for a NEW host (tier/owner default to
        ``unknown``/1.0 for the operator to classify) and, for an EXISTING host,
        touches ONLY ``updated_at`` — never the human-owned classification, and
        never even the tags (so a hand-curated tag list survives too).

        Returns True if a new asset row was inserted, False if the host already
        existed (``xmax = 0`` is Postgres's insert-vs-update tell on the
        RETURNING row).
        """
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        tags = ["discovered:wazuh"]
        if ip:
            tags.append(f"ip:{ip}")
        if os_name:
            tags.append(f"os:{os_name}")
        cur = conn.execute("""
            INSERT INTO assets
            (id, hostname, tier, owner, environment, criticality_multiplier,
             tags, services, created_at, updated_at, client_id)
            VALUES (%s, %s, 'unknown', 'unknown', 'unknown', 1.0,
                    %s, '[]', %s, %s, %s)
            ON CONFLICT (hostname, client_id) DO UPDATE
                SET updated_at = EXCLUDED.updated_at
            RETURNING (xmax = 0) AS inserted
        """, (
            str(uuid.uuid4()), hostname, json.dumps(tags), now, now,
            self._tenant_value(),
        ))
        row = cur.fetchone()
        conn.commit()
        return bool(row and row.get("inserted"))

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
    # Persistent decision cache (WO-H57)
    # ------------------------------------------------------------------
    # Durable backing store behind the in-memory AlertDeduplicator: a recurring
    # alert reuses its stored verdict for $0 instead of re-paying the LLM. The
    # NO-SUPPRESSION safety invariant lives in the triage path (the cache is
    # consulted ONLY after the always-escalate + positive-signal disqualifiers
    # have run against the incoming alert); these methods are just storage.
    #
    # Tenant scoping mirrors the rest of the DAO: writes stamp client_id from the
    # session tenant context (like record_metric); reads/mutations carry an
    # explicit client_id / id predicate so both the WO-H8 app guard and the
    # WO-H12 RLS policy confine them to one tenant. The triage-facing reads fail
    # SAFE (a lookup error → cache miss → LLM), never raising into the hot path.

    def decision_cache_lookup(self, fingerprint: str) -> Optional[dict]:
        """Return the reusable verdict snapshot for ``fingerprint`` in the
        current tenant, or None. Only live entries (``enabled`` and unexpired)
        are returned. Fails safe: any error → None (→ the alert goes to the LLM).
        """
        try:
            conn = self._get_conn()
            now = datetime.now(timezone.utc).isoformat()
            row = conn.execute(
                "SELECT id, origin_alert_id, verdict, confidence, risk_score, "
                "       reasoning, grounding, escalated, actions_taken, "
                "       fingerprint "
                "FROM decision_cache "
                "WHERE client_id = %s AND fingerprint = %s AND enabled = TRUE "
                "  AND (expires_at IS NULL OR expires_at > %s) "
                "LIMIT 1",
                (self._tenant_value(), fingerprint, now),
            ).fetchone()
            if not row:
                return None
            d = dict(row)
            # Shape it exactly like AlertDeduplicator's in-memory rep so the
            # triage fan-out path is identical for dedup and cache reuse.
            return {
                "cache_id": d["id"],
                "alert_id": d.get("origin_alert_id"),
                "verdict": d["verdict"],
                "confidence": d.get("confidence", 0.0),
                "risk_score": d.get("risk_score", 0.0),
                "reasoning": d.get("reasoning", ""),
                "grounding": d.get("grounding"),
                "escalated": bool(d.get("escalated")),
                "actions_taken": d.get("actions_taken", "[]"),
                "fingerprint": d.get("fingerprint"),
            }
        except Exception as e:  # noqa: BLE001 — cache must never break triage
            _store_logger.warning("decision_cache_lookup_failed", error=str(e))
            return None

    def decision_cache_upsert(self, fingerprint: str, decision,
                              *, rule_description: str = "",
                              entity_summary: str = "",
                              source: str = "llm_cached",
                              expires_at: Optional[str] = None,
                              created_by: str = "triage") -> None:
        """Write-through a fresh verdict for ``fingerprint`` (current tenant).

        ON CONFLICT refreshes the stored verdict/expiry but deliberately does
        NOT touch ``enabled`` or ``source`` — an admin's disable survives a later
        re-triage, and a human-confirmed entry is never downgraded to
        ``llm_cached``. Fails safe: a write error is logged, never raised.
        """
        try:
            conn = self._get_conn()
            now = datetime.now(timezone.utc).isoformat()
            grounding = getattr(decision, "grounding", None)
            if grounding is not None and not isinstance(grounding, str):
                grounding = json.dumps(grounding, default=str)
            conn.execute(
                """
                INSERT INTO decision_cache
                (id, client_id, fingerprint, rule_id, rule_description,
                 entity_summary, verdict, confidence, risk_score, reasoning,
                 grounding, escalated, actions_taken, origin_alert_id, source,
                 enabled, hit_count, tokens_saved_est, created_at, created_by,
                 last_hit_at, expires_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                        TRUE,0,0,%s,%s,NULL,%s)
                ON CONFLICT (client_id, fingerprint) DO UPDATE SET
                    verdict          = EXCLUDED.verdict,
                    confidence       = EXCLUDED.confidence,
                    risk_score       = EXCLUDED.risk_score,
                    reasoning        = EXCLUDED.reasoning,
                    grounding        = EXCLUDED.grounding,
                    escalated        = EXCLUDED.escalated,
                    actions_taken    = EXCLUDED.actions_taken,
                    origin_alert_id  = EXCLUDED.origin_alert_id,
                    rule_description = EXCLUDED.rule_description,
                    entity_summary   = EXCLUDED.entity_summary,
                    expires_at       = EXCLUDED.expires_at
                """,
                (
                    str(uuid.uuid4()), self._tenant_value(), fingerprint,
                    getattr(decision, "rule_id", 0), rule_description,
                    entity_summary, decision.verdict, decision.confidence,
                    decision.risk_score, decision.reasoning, grounding,
                    bool(getattr(decision, "escalated", False)),
                    getattr(decision, "actions_taken", "[]"),
                    decision.alert_id, source, now, created_by, expires_at,
                ),
            )
            conn.commit()
        except Exception as e:  # noqa: BLE001 — write-through must never break triage
            _store_logger.warning("decision_cache_upsert_failed", error=str(e))

    def decision_cache_record_hit(self, cache_id: str,
                                  tokens_saved: int = 0) -> None:
        """Account one reuse: bump hit_count + estimated tokens saved. Fail-safe."""
        try:
            conn = self._get_conn()
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "UPDATE decision_cache "
                "SET hit_count = hit_count + 1, "
                "    tokens_saved_est = tokens_saved_est + %s, "
                "    last_hit_at = %s "
                "WHERE id = %s AND client_id = %s",
                (int(tokens_saved or 0), now, cache_id, self._tenant_value()),
            )
            conn.commit()
        except Exception as e:  # noqa: BLE001
            _store_logger.warning("decision_cache_record_hit_failed", error=str(e))

    # -- admin governance surface (WO-H57 Decision Cache tab) --

    def decision_cache_list(self, limit: int = 500,
                            include_disabled: bool = True) -> list[dict]:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        enabled_clause = "" if include_disabled else " AND enabled = TRUE"
        rows = conn.execute(
            "SELECT id, fingerprint, rule_id, rule_description, entity_summary, "
            "       verdict, confidence, risk_score, source, enabled, hit_count, "
            "       tokens_saved_est, created_at, created_by, last_hit_at, "
            "       expires_at "
            f"FROM decision_cache WHERE 1=1 {tf}{enabled_clause} "
            "ORDER BY hit_count DESC, created_at DESC LIMIT %s",
            tp + [limit],
        ).fetchall()
        return [dict(r) for r in rows]

    def decision_cache_summary(self) -> dict:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        row = conn.execute(
            "SELECT COUNT(*) AS total, "
            "       COUNT(*) FILTER (WHERE enabled) AS enabled, "
            "       COALESCE(SUM(hit_count), 0) AS total_hits, "
            "       COALESCE(SUM(tokens_saved_est), 0) AS tokens_saved "
            f"FROM decision_cache WHERE 1=1 {tf}",
            tp,
        ).fetchone()
        d = dict(row) if row else {}
        return {
            "total": d.get("total", 0),
            "enabled": d.get("enabled", 0),
            "disabled": (d.get("total", 0) - d.get("enabled", 0)),
            "total_hits": d.get("total_hits", 0),
            "tokens_saved": d.get("tokens_saved", 0),
        }

    _DECISION_CACHE_UPDATE_COLS = frozenset({"enabled", "verdict", "reasoning"})

    def decision_cache_update(self, cache_id: str, **kwargs) -> bool:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        sets, params = [], []
        for k, v in kwargs.items():
            if k not in self._DECISION_CACHE_UPDATE_COLS or v is None:
                continue
            sets.append(f"{k} = %s")
            params.append(v)
        if not sets:
            return False
        params.append(cache_id)
        params.extend(tp)
        conn.execute(
            f"UPDATE decision_cache SET {', '.join(sets)} WHERE id = %s {tf}",
            params,
        )
        conn.commit()
        return True

    def decision_cache_delete(self, cache_id: str) -> bool:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        conn.execute(
            f"DELETE FROM decision_cache WHERE id = %s {tf}", [cache_id] + tp)
        conn.commit()
        return True

    def decision_cache_purge_expired(self) -> int:
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        now = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(
            "DELETE FROM decision_cache "
            f"WHERE expires_at IS NOT NULL AND expires_at <= %s {tf}",
            [now] + tp,
        )
        conn.commit()
        return cur.rowcount if cur.rowcount is not None else 0

    def decision_cache_clear(self) -> int:
        """Delete every cache entry for the current tenant (admin 'clear all')."""
        conn = self._get_conn()
        tf, tp = self._tenant_filter()
        # A WHERE with an explicit tenant predicate keeps the WO-H8 guard happy.
        cur = conn.execute(
            f"DELETE FROM decision_cache WHERE 1=1 {tf}", tp)
        conn.commit()
        return cur.rowcount if cur.rowcount is not None else 0

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
