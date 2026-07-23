"""
WO-H5 — LLM cost controls for the triage path.

Three deterministic, opt-in cost-control primitives that sit in front of the
expensive triage LLM call. All three are **per-tenant fail-closed**: no spend,
dedup state, or verdict ever crosses a tenant boundary.

  1. ``BudgetGuard``       — hard per-tenant spend cap that BLOCKS the LLM call
                             once the period spend reaches the configured cap.
                             The fail-safe path in the triage agent ESCALATES a
                             budget-exhausted alert (verdict ``needs_investigation``,
                             ``escalated=True``) — it is *never* auto-closed on
                             budget grounds. Configurable headroom warnings
                             (e.g. 80% / 95%) log before the hard stop.

  2. ``AlertDeduplicator`` — a structural fingerprint (rule_id + normalized key
                             entities: src_ip / dst_ip / src_user / agent_id,
                             normalized the same way the incident engine keys on
                             them, PLUS a stable hash of the raw event body —
                             full_log/data — per WO-H29 NEW-4 so two genuinely
                             different events under the same rule+entities don't
                             collapse, while identical retries still do)
                             collapses structurally-identical alerts within
                             a short window to ONE LLM call. The verdict is fanned
                             out to the duplicates by the triage agent (each still
                             gets its own persisted decision). Fingerprints are
                             keyed by tenant so duplicates never collapse across
                             tenants.

  3. ``NoisePreFilter``    — a cheap, deterministic rules-only pre-filter that
                             dismisses obviously-benign noise *before* the
                             expensive LLM call. It is opt-in and conservative by
                             default. It can NEVER suppress an always-escalate
                             (critical) alert because the triage agent runs the
                             deterministic always-escalate gate first and returns
                             before the pre-filter is ever consulted — and the
                             pre-filter additionally refuses to dismiss anything
                             carrying a positive signal (TI hit, known-malicious,
                             baseline anomaly).

None of these primitives introduce a new provider dependency — the pre-filter is
purely rules-based. Everything degrades gracefully: when a control is disabled
or unconfigured it is a no-op, and the triage path behaves exactly as before.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)


def _cost_control_cfg(config: dict) -> dict:
    """Resolve the ``agents.triage.cost_controls`` config section (or {})."""
    return (
        (config or {})
        .get("agents", {})
        .get("triage", {})
        .get("cost_controls", {})
        or {}
    )


class BudgetGuard:
    """Enforce a hard per-tenant LLM spend cap for the current billing period.

    ``check(tenant_id)`` returns a small status dict:

        {
          "allowed": bool,          # False => caller MUST NOT make the LLM call
          "spend": float,           # period spend so far (USD)
          "cap": float,             # effective cap for this tenant (USD)
          "utilization": float,     # spend / cap (0.0 when no cap configured)
          "warn": bool,             # crossed a headroom warning threshold
          "warn_threshold": float | None,
        }

    Spend is summed from ``llm_usage_metrics`` filtered by ``tenant_id`` — never
    across tenants. Reads are cached briefly so a large batch does not re-query
    per alert. If the spend read fails (transient DB error) the guard fails
    OPEN (allows the call): the cap is a cost optimization, not a security
    control, and self-inflicting a triage outage on a DB blip is worse than a
    small budget overshoot. The escalate-never-auto-close invariant is enforced
    independently in the triage agent regardless of this.
    """

    def __init__(self, db, config: dict, tenant_registry=None):
        self.db = db
        self.tenant_registry = tenant_registry
        cc = _cost_control_cfg(config)
        bc = cc.get("budget", {}) or {}
        self.enabled = bool(bc.get("enabled", True))
        # Default cap applies to any tenant without a per-tenant override.
        # 0 (or missing) means "no cap" — the guard never blocks.
        self.default_cap = float(bc.get("monthly_cap_usd", 0) or 0)
        raw_thresholds = bc.get("warn_thresholds", [0.80, 0.95]) or []
        self.warn_thresholds = sorted(
            {float(t) for t in raw_thresholds if 0 < float(t) < 1.0}
        )
        self._cache_ttl = float(bc.get("spend_cache_seconds", 30) or 0)
        self._spend_cache: dict = {}  # tenant_id -> (monotonic_ts, spend)
        self._lock = threading.Lock()
        # ── WO-H28: atomic debit (reserve/release) ──
        # Cost counted against the cap for an in-flight LLM call before its
        # real usage row lands in llm_usage_metrics. Deliberately generous —
        # over-reserving briefly under-admits; under-reserving overshoots the
        # cap, which is exactly the race this closes.
        self.estimated_call_cost_usd = float(
            bc.get("estimated_call_cost_usd", 0.05) or 0)
        # Reservations older than this are treated as leaked (worker died
        # mid-call) and purged on the next reserve() for that tenant.
        self.reservation_ttl_seconds = float(
            bc.get("reservation_ttl_seconds", 600) or 600)

    def _resolve_cap(self, tenant_id: str) -> float:
        """Per-tenant cap: registry ``usage_tracking.monthly_budget`` overrides
        the global default. Mirrors how ``monthly_budget`` is already read in
        ``src/metrics/llm_usage.py``."""
        if self.tenant_registry is not None:
            try:
                llm_config = self.tenant_registry.get_llm_config(tenant_id) or {}
                cap = (llm_config.get("usage_tracking", {}) or {}).get(
                    "monthly_budget")
                if cap is not None:
                    return float(cap)
            except Exception as e:  # pragma: no cover - defensive
                logger.debug("budget_cap_resolve_failed",
                             tenant_id=tenant_id, error=str(e))
        return self.default_cap

    def _query_spend(self, tenant_id: str) -> float:
        """Sum current-period (calendar-month) spend for ONE tenant."""
        now = datetime.now(timezone.utc)
        month_start = now.replace(day=1, hour=0, minute=0, second=0,
                                  microsecond=0)
        conn = self.db._get_conn()
        row = conn.execute(
            """
            SELECT COALESCE(SUM(cost_usd), 0) AS spend
            FROM llm_usage_metrics
            WHERE tenant_id = %s
              AND created_at >= %s
            """,
            (tenant_id, month_start.isoformat()),
        ).fetchone()
        try:
            return float(row["spend"] or 0)
        except (KeyError, TypeError):
            # tuple-style row fallback
            return float((row[0] if row else 0) or 0)

    def _current_spend(self, tenant_id: str) -> float:
        """Cached spend read (fails open to 0.0 on error)."""
        if self._cache_ttl > 0:
            with self._lock:
                cached = self._spend_cache.get(tenant_id)
                if cached and (time.monotonic() - cached[0]) <= self._cache_ttl:
                    return cached[1]
        try:
            spend = self._query_spend(tenant_id)
        except Exception as e:
            logger.error("budget_spend_query_failed",
                         tenant_id=tenant_id, error=str(e))
            return 0.0  # fail OPEN — do not block triage on a DB blip
        if self._cache_ttl > 0:
            with self._lock:
                self._spend_cache[tenant_id] = (time.monotonic(), spend)
        return spend

    def check(self, tenant_id: str) -> dict:
        """Return the budget status for ``tenant_id`` (see class docstring)."""
        cap = self._resolve_cap(tenant_id)
        if not self.enabled or cap <= 0:
            return {"allowed": True, "spend": 0.0, "cap": cap,
                    "utilization": 0.0, "warn": False, "warn_threshold": None}

        spend = self._current_spend(tenant_id)
        utilization = spend / cap if cap > 0 else 0.0
        allowed = spend < cap

        warn = False
        warn_threshold = None
        if allowed:
            # Highest crossed headroom threshold below the hard stop.
            for t in self.warn_thresholds:
                if utilization >= t:
                    warn = True
                    warn_threshold = t
        return {
            "allowed": allowed,
            "spend": spend,
            "cap": cap,
            "utilization": utilization,
            "warn": warn,
            "warn_threshold": warn_threshold,
        }

    # ── WO-H28: atomic reserve/release debit ──
    #
    # ``check()`` alone is check-then-act: N parallel workers all read the
    # same (possibly ~30s-cached) spend below the cap and ALL proceed — the
    # cap can be overshot by N × call-cost. ``reserve()`` closes that race at
    # the DB: it serializes per tenant on a Postgres advisory lock
    # (db.serialized_section — blocking, cross-process) and, while holding
    # it, counts month-to-date spend PLUS the estimated cost of every
    # in-flight reservation before inserting its own reservation row into
    # ``llm_budget_reservations`` (migration 0009). The caller releases the
    # reservation after the call's real usage row lands in
    # ``llm_usage_metrics`` (success or failure — the tracker records both).
    #
    # Cap semantics are preserved: the call is allowed while
    # (spend + in-flight reservations) < cap, blocked at/over — same
    # escalate-never-auto-close fail-safe downstream. Fail-open posture is
    # also preserved: a DB error during reserve allows the call (cost cap is
    # an optimization, not a security control).

    def _query_reserved(self, tenant_id: str) -> float:
        """Sum estimated cost of live (non-stale) reservations for a tenant,
        purging stale ones (leaked by a crashed worker) first."""
        conn = self.db._get_conn()
        stale_cutoff = (
            datetime.now(timezone.utc)
            - timedelta(seconds=self.reservation_ttl_seconds)
        ).isoformat()
        conn.execute(
            "DELETE FROM llm_budget_reservations "
            "WHERE tenant_id = %s AND created_at < %s",
            (tenant_id, stale_cutoff))
        row = conn.execute(
            "SELECT COALESCE(SUM(estimated_cost_usd), 0) AS reserved "
            "FROM llm_budget_reservations WHERE tenant_id = %s",
            (tenant_id,)).fetchone()
        conn.commit()
        try:
            return float(row["reserved"] or 0)
        except (KeyError, TypeError):
            return float((row[0] if row else 0) or 0)

    def reserve(self, tenant_id: str) -> dict:
        """Atomically check the cap AND reserve headroom for one LLM call.

        Returns the same status dict as :meth:`check` plus
        ``reservation_id`` (set only when a reservation row was created —
        the caller MUST pass it to :meth:`release` after the call settles).
        """
        cap = self._resolve_cap(tenant_id)
        if not self.enabled or cap <= 0:
            return {"allowed": True, "spend": 0.0, "cap": cap,
                    "utilization": 0.0, "warn": False,
                    "warn_threshold": None, "reservation_id": None}

        section = getattr(self.db, "serialized_section", None)
        try:
            if section is not None:
                with section(f"dhruva:budget:{tenant_id}"):
                    return self._reserve_locked(tenant_id, cap)
            # No advisory-lock support (stub db in tests) — fall back to the
            # process-local lock; still closes the in-process race.
            with self._lock:
                return self._reserve_locked(tenant_id, cap)
        except Exception as e:
            logger.error("budget_reserve_failed", tenant_id=tenant_id,
                         error=str(e))
            # Fail OPEN, mirroring check(): never block triage on a DB blip.
            return {"allowed": True, "spend": 0.0, "cap": cap,
                    "utilization": 0.0, "warn": False,
                    "warn_threshold": None, "reservation_id": None}

    def _reserve_locked(self, tenant_id: str, cap: float) -> dict:
        """Cap check + reservation insert. MUST be called under the
        per-tenant lock. Spend is read uncached — the cache exists to soften
        batch reads in check(); the enforcement path must see fresh totals."""
        import uuid
        spend = self._query_spend(tenant_id) + self._query_reserved(tenant_id)
        utilization = spend / cap if cap > 0 else 0.0
        allowed = spend < cap

        reservation_id = None
        if allowed:
            reservation_id = str(uuid.uuid4())
            conn = self.db._get_conn()
            conn.execute(
                "INSERT INTO llm_budget_reservations "
                "(id, tenant_id, estimated_cost_usd, created_at, client_id) "
                "VALUES (%s, %s, %s, %s, %s)",
                (reservation_id, tenant_id, self.estimated_call_cost_usd,
                 datetime.now(timezone.utc).isoformat(), tenant_id))
            conn.commit()

        warn = False
        warn_threshold = None
        if allowed:
            for t in self.warn_thresholds:
                if utilization >= t:
                    warn = True
                    warn_threshold = t
        return {
            "allowed": allowed,
            "spend": spend,
            "cap": cap,
            "utilization": utilization,
            "warn": warn,
            "warn_threshold": warn_threshold,
            "reservation_id": reservation_id,
        }

    def release(self, tenant_id: str, reservation_id: str | None) -> None:
        """Release a reservation once the call settled (its real cost — or
        failure — is now recorded in llm_usage_metrics by the usage tracker).
        Safe to call with None; never raises (a leaked row is purged by the
        TTL sweep in the next reserve())."""
        if not reservation_id:
            return
        try:
            conn = self.db._get_conn()
            conn.execute(
                "DELETE FROM llm_budget_reservations "
                "WHERE id = %s AND tenant_id = %s",
                (reservation_id, tenant_id))
            conn.commit()
        except Exception as e:
            logger.warning("budget_release_failed", tenant_id=tenant_id,
                           reservation_id=reservation_id, error=str(e))


class AlertDeduplicator:
    """Collapse structurally-identical alerts within a window to one LLM call.

    A fingerprint is ``rule_id`` plus the normalized key entities the incident
    engine correlates on (src_ip / dst_ip / src_user / agent_id). Duplicates
    seen within ``window_seconds`` of the representative reuse its verdict.
    State is keyed by ``(tenant_id, fingerprint)`` so nothing collapses across
    tenants.
    """

    def __init__(self, config: dict):
        cc = _cost_control_cfg(config)
        dc = cc.get("dedup", {}) or {}
        self.enabled = bool(dc.get("enabled", True))
        self.window_seconds = float(dc.get("window_seconds", 300) or 0)
        self._seen: dict = {}  # (tenant_id, fingerprint) -> (ts, rep_snapshot)
        self._lock = threading.Lock()

    @staticmethod
    def _norm(value) -> str:
        """Normalize an entity value the way the incident engine keys on it:
        stringify, strip, lowercase; empty/None collapse to ''."""
        if value is None:
            return ""
        return str(value).strip().lower()

    @classmethod
    def _event_discriminator(cls, alert: dict) -> str:
        """Stable short hash of the salient RAW event content (WO-H29 NEW-4).

        The old fingerprint keyed only on rule_id + entities, so two GENUINELY
        DIFFERENT events under the same rule + same entities (both lacking a
        positive enrichment signal) collapsed to ONE shared verdict. This adds a
        discriminator over the raw event body — ``full_log`` and the decoded
        ``data`` dict — which are properties of the event itself:

          * a real Wazuh RETRY of the SAME alert carries an identical full_log +
            data → identical hash → still dedups (retries must still collapse);
          * two DIFFERENT events differ in full_log/data → different hash →
            distinct fingerprints → each gets its own verdict.

        Deliberately hashes ONLY the raw event (never ``enrichment``, which can
        vary run-to-run and would break legitimate retry dedup). Empty/absent
        body → '' so the fingerprint degrades to the pre-H29 key (no behaviour
        change for events carrying neither field)."""
        parts = []
        full_log = alert.get("full_log")
        if full_log:
            parts.append(str(full_log))
        data = alert.get("data")
        if isinstance(data, dict) and data:
            try:
                parts.append(json.dumps(
                    data, sort_keys=True, separators=(",", ":"), default=str))
            except (TypeError, ValueError):
                parts.append(repr(sorted(
                    ((str(k), str(v)) for k, v in data.items()))))
        elif data:
            parts.append(str(data))
        if not parts:
            return ""
        blob = "\x1e".join(parts)
        return hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()[:16]

    @classmethod
    def fingerprint(cls, alert: dict) -> str:
        """Structural fingerprint = rule_id + normalized key entities + a stable
        hash of the raw event body (full_log/data — WO-H29 NEW-4). The event-body
        discriminator prevents two genuinely different events under the same rule
        + entities from collapsing to one verdict, while identical retries (same
        body) still dedup."""
        rule_id = alert.get("rule_id", 0)
        return "|".join([
            f"rule:{rule_id}",
            f"src_ip:{cls._norm(alert.get('src_ip'))}",
            f"dst_ip:{cls._norm(alert.get('dst_ip'))}",
            f"src_user:{cls._norm(alert.get('src_user'))}",
            f"agent_id:{cls._norm(alert.get('agent_id'))}",
            f"data:{cls._event_discriminator(alert)}",
        ])

    def lookup(self, tenant_id: str, fingerprint: str) -> Optional[dict]:
        """Return the representative decision snapshot if a live (in-window)
        duplicate exists for this tenant, else None."""
        key = (tenant_id, fingerprint)
        with self._lock:
            entry = self._seen.get(key)
            if not entry:
                return None
            ts, rep = entry
            if self.window_seconds > 0 and (time.monotonic() - ts) > self.window_seconds:
                # Expired — drop it so the next alert becomes a fresh
                # representative (and gets its own LLM call).
                del self._seen[key]
                return None
            return rep

    def register(self, tenant_id: str, fingerprint: str, decision) -> None:
        """Record ``decision`` as the representative for its fingerprint."""
        snapshot = {
            "alert_id": decision.alert_id,
            "verdict": decision.verdict,
            "confidence": decision.confidence,
            "risk_score": decision.risk_score,
            "reasoning": decision.reasoning,
            "actions_taken": decision.actions_taken,
            "escalated": decision.escalated,
            "grounding": getattr(decision, "grounding", None),
            "fingerprint": fingerprint,
        }
        with self._lock:
            self._seen[(tenant_id, fingerprint)] = (time.monotonic(), snapshot)


class PersistentDecisionCache:
    """WO-H57 — durable, per-tenant, admin-governed verdict cache.

    Sits BELOW ``AlertDeduplicator``'s in-memory window: when the in-memory rep
    has expired (or the process restarted), a recurring structurally-identical
    alert can still reuse its stored verdict for $0 instead of re-paying the LLM.

    SAFETY (the no-suppression invariant) is enforced by the caller, NOT here:
    the triage agent only consults this cache for alerts that already passed the
    dedup-eligibility gate (``not has_positive_signal`` and NOT always-escalate),
    re-evaluated against THE INCOMING alert — so a stored benign verdict can
    never be reused for a freshly-signalled threat. This class only decides
    *whether a verdict is worth storing* and *how long it stays fresh*.

    Conservative by default (disabled; only high-confidence benign dismissals or
    human-confirmed verdicts are written) and it never overrides the always-
    escalate path. Storage lives in ``SOCDatabase.decision_cache_*``.
    """

    # Verdicts we are willing to REUSE without a fresh LLM read. A benign
    # disposition is safe to memoize; anything that would escalate/contain is
    # not (and, in practice, escalate-eligible alerts never reach the cache).
    _DEFAULT_CACHEABLE = frozenset({
        "auto_close", "benign", "false_positive", "closed", "resolved",
        "needs_investigation",
    })

    def __init__(self, config: dict):
        cc = _cost_control_cfg(config)
        dcfg = cc.get("decision_cache", {}) or {}
        # Off by default — operator opts in (WO-H57 DoD item 7).
        self.enabled = bool(dcfg.get("enabled", False))
        self.write_through = bool(dcfg.get("write_through", True))
        self.min_confidence = float(dcfg.get("min_confidence", 0.7) or 0)
        self.max_age_hours = float(dcfg.get("max_age_hours", 168) or 0)  # 7d
        cacheable = dcfg.get("cacheable_verdicts")
        self.cacheable_verdicts = (
            {str(v).lower() for v in cacheable} if cacheable
            else set(self._DEFAULT_CACHEABLE))
        # Rough per-reuse token saving used only for the savings estimate shown
        # in the Decision Cache tab (an averted triage call). Real metering
        # (WO-H50) covers actual spend; this is a display-only estimate.
        self.tokens_saved_per_hit = int(dcfg.get("tokens_saved_per_hit", 1500))

    def expires_at(self) -> Optional[str]:
        """ISO timestamp at which a freshly-written entry goes stale, or None
        for no expiry (``max_age_hours <= 0``)."""
        if self.max_age_hours <= 0:
            return None
        return (datetime.now(timezone.utc)
                + timedelta(hours=self.max_age_hours)).isoformat()

    def lookup(self, db, fingerprint: str) -> Optional[dict]:
        """Return a reusable verdict snapshot for ``fingerprint`` (current
        tenant) or None. No-op (None) when disabled — so an operator who turns
        the cache off gets zero cache reuse without a code change."""
        if not self.enabled or db is None:
            return None
        return db.decision_cache_lookup(fingerprint)

    def should_cache(self, decision) -> bool:
        """True only for a verdict we are willing to memoize: write-through on,
        confident enough, a benign/non-escalating disposition, and NOT escalated.
        Human-confirmed verdicts bypass this via ``store(..., source=...)``."""
        if not (self.enabled and self.write_through):
            return False
        if getattr(decision, "escalated", False):
            return False
        try:
            if float(decision.confidence or 0) < self.min_confidence:
                return False
        except (TypeError, ValueError):
            return False
        return str(decision.verdict).lower() in self.cacheable_verdicts

    def store(self, db, fingerprint: str, decision, *,
              rule_description: str = "", entity_summary: str = "",
              source: str = "llm_cached", created_by: str = "triage") -> None:
        """Write-through a verdict (no-op when disabled or db missing)."""
        if not self.enabled or db is None:
            return
        db.decision_cache_upsert(
            fingerprint, decision,
            rule_description=rule_description, entity_summary=entity_summary,
            source=source, expires_at=self.expires_at(), created_by=created_by)

    def record_hit(self, db, cache_id: str) -> None:
        """Account one reuse for the savings estimate (no-op when disabled)."""
        if not self.enabled or db is None or not cache_id:
            return
        db.decision_cache_record_hit(cache_id, self.tokens_saved_per_hit)


class NoisePreFilter:
    """Cheap, deterministic rules-only pre-filter for obvious benign noise.

    Opt-in and conservative by default (disabled; and even when enabled it only
    dismisses alerts whose rule_id / rule_group is on an operator-supplied
    known-noise allowlist). It NEVER dismisses anything carrying a positive
    signal, and — because the triage agent runs the always-escalate gate first
    and returns before consulting the pre-filter — it can never be reached for a
    critical always-escalate alert.
    """

    def __init__(self, config: dict):
        cc = _cost_control_cfg(config)
        pf = cc.get("prefilter", {}) or {}
        self.enabled = bool(pf.get("enabled", False))
        self.max_rule_level = int(pf.get("max_rule_level", 5))
        self.max_risk_score = float(pf.get("max_risk_score", 15))
        self.noise_rule_ids = {int(r) for r in (pf.get("noise_rule_ids") or [])}
        self.noise_rule_groups = set(pf.get("noise_rule_groups") or [])
        self.require_allowlist = bool(pf.get("require_allowlist", True))
        self.verdict = pf.get("verdict", "auto_close")
        self.confidence = float(pf.get("confidence", 0.6))
        # WO-H54: deterministic-CATEGORY skip — dismiss REGARDLESS of rule level
        # / risk score. For a category like `vulnerability-detector` the rule
        # "level" is CVSS severity, not triage priority: a level-13 CVE is still
        # just "CVE affects package", deterministic vuln data the LLM adds
        # nothing to, and re-emitted every scan. The level/risk caps below would
        # otherwise force the expensive high-CVSS CVEs (23505 level 10, 23506
        # level 13) through the LLM — the exact opposite of the intent. The vuln
        # stays fully visible + remediable via the Wazuh vuln index and the
        # Vulnerabilities tab; only the redundant LLM triage call is skipped.
        self.skip_rule_ids = {int(r) for r in (pf.get("skip_rule_ids") or [])}
        self.skip_rule_groups = set(pf.get("skip_rule_groups") or [])

    def is_noise(self, alert: dict, enrichment: dict) -> bool:
        """True only when the alert is confidently benign noise and safe to
        dismiss without an LLM call."""
        if not self.enabled:
            return False

        enrichment = enrichment or {}
        # Hard safety guards — any positive signal disqualifies dismissal.
        # These apply to EVERY path below, including the category skip.
        if enrichment.get("threat_intel_hits", 0):
            return False
        if enrichment.get("is_known_malicious"):
            return False
        if enrichment.get("baseline_anomaly"):
            return False

        rule_id = alert.get("rule_id", 0)
        rule_groups = set(alert.get("rule_groups", []) or [])

        # WO-H54: deterministic-category skip — BEFORE the level/risk caps, so a
        # high-CVSS CVE (level 10/13) is still skipped. Guarded by the safety
        # checks above; disabled unless the operator lists a group/id.
        if (rule_id in self.skip_rule_ids
                or bool(rule_groups & self.skip_rule_groups)):
            return True

        try:
            rule_level = float(alert.get("rule_level", 0) or 0)
        except (TypeError, ValueError):
            rule_level = 0.0
        try:
            risk_score = float(enrichment.get("risk_score", 0) or 0)
        except (TypeError, ValueError):
            risk_score = 0.0
        if rule_level > self.max_rule_level:
            return False
        if risk_score > self.max_risk_score:
            return False

        in_allowlist = (
            rule_id in self.noise_rule_ids
            or bool(rule_groups & self.noise_rule_groups)
        )
        if self.require_allowlist and not in_allowlist:
            return False
        return True
