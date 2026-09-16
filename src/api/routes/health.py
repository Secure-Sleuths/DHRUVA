"""Health check and guidance reload routes."""

import structlog
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request, Response

from src.api.auth import require_admin, require_role
from src.api.dependencies import limiter
from src.api.feature_gates import require_license_feature

router = APIRouter()
logger = structlog.get_logger(__name__)

# Default staleness window for the alert-loop heartbeat. If the loop hasn't
# ticked within this many seconds, health goes degraded. Overridable via
# config ``health.alert_loop_staleness_seconds``. Generous relative to the
# default 10s poll interval so a merely-busy cycle never trips it.
_DEFAULT_LOOP_STALENESS_SECONDS = 300


@router.get("/api/health")
async def health_check(response: Response):
    """Public health check — DB pool round-trip + alert-loop liveness.

    Returns **HTTP 200** with ``status=healthy`` only when the platform can
    ``SELECT 1`` from Postgres via its pool AND the alert loop has ticked
    recently. Returns **HTTP 503** with ``status=degraded`` (JSON body
    preserved) when the DB probe fails OR the alert-loop heartbeat is
    stale/absent — so container orchestrators (compose/k8s) restart a wedged
    instance instead of leaving a healthy HTTP responder masking a broken DB
    pool or a dead loop thread.

    Liveness is enforced only ONCE the loop has ticked at least once: an ABSENT
    heartbeat (fresh start still in its grace window, or an API-only process
    with no loop) does NOT by itself force 503 while the DB is healthy —
    otherwise every instance would 503 at startup and API-only deployments
    would be permanently unhealthy. A heartbeat that WAS recorded but is now
    older than the staleness window (a wedged loop) DOES flip 503.
    """
    payload = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # ── DB pool round-trip ───────────────────────────────────────────────
    try:
        from src.api.dependencies import get_db
        db = get_db()
        if db is not None:
            conn = db._get_conn()
            cur = conn.execute("SELECT 1 AS ok")
            row = cur.fetchone()
            if not row or row.get("ok") != 1:
                payload["status"] = "degraded"
                payload["error"] = "db_probe_unexpected_result"
            payload["db"] = "reachable"
    except Exception as e:  # noqa: BLE001 — surface any pool/network error
        payload["status"] = "degraded"
        payload["db"] = "unreachable"
        # Don't leak the exception class to unauthenticated callers (qa-audit F6);
        # the degraded/unreachable signal is enough for orchestrators. Log the
        # real error server-side for operators.
        logger.warning("health_db_probe_failed",
                       error=str(e), error_type=type(e).__name__)
        payload["error"] = "db_unreachable"

    # ── Alert-loop liveness (WO-H10) ─────────────────────────────────────
    # A dead/wedged loop thread is invisible to a DB-only probe. Expose the age
    # of the last-completed-cycle heartbeat and flip degraded ONLY when a
    # heartbeat that was previously recorded has since gone STALE (loop wedged).
    # An ABSENT heartbeat (never recorded — fresh start still in its grace
    # window, or an API-only process with no loop) is intentionally NOT treated
    # as degraded here; the DB probe governs health until the loop starts
    # ticking, after which the stale check takes over.
    try:
        from src.api.liveness import last_cycle_age_seconds, last_cycle_iso
        staleness = _DEFAULT_LOOP_STALENESS_SECONDS
        try:
            from src.api.dependencies import get_config
            cfg = get_config() or {}
            staleness = int(
                (cfg.get("health", {}) or {}).get(
                    "alert_loop_staleness_seconds",
                    _DEFAULT_LOOP_STALENESS_SECONDS))
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: pass`. A failure here means the
            # operator's configured alert-loop staleness threshold is quietly
            # ignored and the built-in default is used instead, so the loop is
            # called stale earlier or later than the operator asked for. `debug`
            # because /health is polled by orchestrator healthchecks every few
            # seconds and the effective value is already published in the
            # response as `alert_loop_staleness_seconds`.
            logger.debug("health_staleness_config_read_failed",
                         fallback_seconds=staleness, error=str(e)[:200])

        age = last_cycle_age_seconds()
        payload["last_cycle_age_seconds"] = (
            round(age, 1) if age is not None else None)
        payload["last_cycle_at"] = last_cycle_iso()
        payload["alert_loop_staleness_seconds"] = staleness

        if age is None:
            # Never ticked yet — do not degrade on this alone (startup grace /
            # API-only). Surfaced for observability without affecting status.
            payload["alert_loop"] = "no_heartbeat_yet"
        elif age > staleness:
            payload["status"] = "degraded"
            payload.setdefault("error", "alert_loop_stale")
            logger.warning("health_alert_loop_stale",
                           last_cycle_age_seconds=round(age, 1),
                           staleness_seconds=staleness)
    except Exception as e:  # noqa: BLE001 — liveness check must never 500 the probe
        logger.warning("health_liveness_check_failed",
                       error=str(e), error_type=type(e).__name__)

    # ── RLS tenant-backstop state (N3) ───────────────────────────────────
    # Informational ONLY — surfaces whether the DB-layer RLS backstop is inactive
    # while in multi-tenant mode (a runtime superuser/BYPASSRLS misconfig). We do
    # NOT flip status to 503 here: a 503 would restart the pod, and the startup
    # RLS boot gate would then SystemExit → crash-loop. App-layer isolation still
    # applies; this field lets monitoring alarm without destabilising the deploy.
    try:
        from src.database.store import is_rls_backstop_degraded
        payload["rls_backstop"] = (
            "degraded" if is_rls_backstop_degraded() else "ok")
    except Exception as e:                       # noqa: BLE001
        # WO-H88: was a bare `except: pass`. Swallowing left the field ABSENT,
        # which monitoring cannot distinguish from "not degraded" — so the
        # tenant-isolation alarm goes quiet exactly when the check that feeds it
        # breaks. Say "unknown" instead, which is the truth.
        payload["rls_backstop"] = "unknown"
        logger.warning("rls_backstop_check_failed", error=str(e)[:200])

    # ── PostgreSQL server-version floor (WO-H129) ────────────────────────
    # Informational ONLY, same posture as rls_backstop above: it never flips
    # status to 503. A below-floor server that is ALREADY POPULATED is allowed
    # to boot on purpose (refusing would take a live SOC offline over a database
    # version), so a 503 here would only produce a restart loop against a
    # condition a restart cannot fix. A below-floor server with an EMPTY
    # database never reaches this endpoint at all — the store refuses to open.
    #   ok           — at or above the enforced floor
    #   unsupported  — below it. Migration 0018 cannot backfill
    #                  agent_decisions.host on this server, so host correlation
    #                  over existing decisions is incomplete and NOTHING else
    #                  says so. That silence is what this field exists to break.
    #   unknown      — the check itself failed; say so rather than imply "ok"
    #
    # WHAT IS DELIBERATELY *NOT* HERE: the detected server version string.
    # /api/health is unauthenticated (no auth dependency on the route, and
    # exempted in src/api/middleware.py), and the exact build string is
    # "14.24 (Ubuntu 14.24-1.pgdg22.04+2)" — patch level plus distro, disclosed
    # ONLY when the host is below the floor, i.e. precisely on the end-of-life
    # servers most likely to have a known unpatched issue. That is a free
    # targeting hint for an anonymous caller, and it walks back the same
    # route's earlier fix at the top of this function ("don't leak the
    # exception class to unauthenticated callers", qa-audit F6). The operator
    # who needs the version has it in the `postgres_version_unsupported` ERROR
    # line, which carries server_version and server_major. This endpoint says
    # THAT it is unsupported and WHAT the floor is; that is the actionable part.
    try:
        from src.database import pg_version
        payload[pg_version.HEALTH_FIELD] = pg_version.health_state()
        payload["db_server_version_required_major"] = pg_version.MIN_PG_MAJOR
    except Exception as e:                       # noqa: BLE001 — never 500 /health
        payload["db_server_version"] = "unknown"
        logger.warning("db_server_version_check_failed", error=str(e)[:200])

    # ── Notification channel state (WO-H101) ─────────────────────────────
    # Informational ONLY, same posture as rls_backstop above: this never flips
    # status to 503, because a Slack misconfiguration is not a reason to restart
    # a pod. "misconfigured" means notifications are switched ON and every one
    # of them is being discarded — 13,980 SLA breaches went that way on a live
    # tenant, with one boot-time INFO line as the only trace. This field does
    # not scroll.
    #   ok            — enabled, a usable channel, sends are landing
    #   misconfigured — enabled, ZERO usable channels (alerts reach nobody)
    #   failing       — a channel IS configured but its last N sends all failed
    #                   (WO-H101 QA finding 5: this field used to report
    #                   CONFIGURATION only, so a bot token that failed 100% of
    #                   its sends — the likeliest post-deploy state, because the
    #                   bot was never invited to the channel — still read "ok")
    #   disabled      — notifications.enabled is false (a deliberate choice)
    #   unavailable   — no notification service wired: a Community build (where
    #                   src/notifications is stripped) or a license without
    #                   notifications_full
    #   unknown       — the check itself failed; say so rather than imply "ok"
    try:
        from src.api.dependencies import get_notifications
        _notifier = get_notifications()
        payload["notifications"] = (
            _notifier.health_state() if _notifier is not None
            else "unavailable")
    except Exception as e:                       # noqa: BLE001 — never 500 /health
        payload["notifications"] = "unknown"
        logger.warning("notifications_health_check_failed", error=str(e)[:200])

    # HTTP status code mirrors the payload status so orchestrator healthchecks
    # (curl -sf) restart a degraded instance. 200 only when genuinely healthy.
    if payload["status"] != "healthy":
        response.status_code = 503
    return payload


@router.get("/api/health/pipeline")
async def get_pipeline_health(
    user: dict = Depends(require_role("mssp_admin")),
    _gate: None = Depends(require_license_feature("pipeline_health")),
):
    """Get pipeline health status — heartbeats, EPS, parser failures.
    Restricted to mssp_admin as it exposes global infrastructure telemetry."""
    from src.api.dependencies import get_pipeline_monitor, get_metrics_calculator
    monitor = get_pipeline_monitor()
    if not monitor:
        return {"status": "unavailable", "message": "Pipeline monitor not initialized"}
    status = monitor.get_pipeline_status()
    calc = get_metrics_calculator()
    if calc:
        try:
            status["automation_health"] = calc.get_automation_health(days=7)
        except Exception as e:                       # noqa: BLE001
            # WO-H90: was a bare `except: pass`. A failure here means the
            # automation-health block vanishes from the pipeline response, and
            # the dashboard panel that shows "how much is DHRUVA actually
            # automating" renders empty — which reads as "nothing was
            # automated" rather than "we could not measure it". NOTE: unlike the
            # rls_backstop check this field is a typed OBJECT the SPA indexes
            # into, so it is left ABSENT rather than set to "unknown"; making it
            # self-describing is a behaviour change, flagged not taken.
            logger.warning("automation_health_probe_failed",
                           error=str(e)[:200])
    return status


@router.get("/api/health/llm")
async def get_llm_health(
    hours: int = 1,
    user: dict = Depends(require_role("analyst")),
):
    """WO-H46-c: LLM-backend health — is triage actually producing verdicts?

    When the LLM is unreachable, triage fails CLOSED: it escalates the alert
    with ``verdict='needs_investigation'`` WITHOUT analyzing it. That is the
    correct safety behaviour, but it means a backend outage is invisible in the
    verdict column — the platform looks BUSY rather than BROKEN. On one install
    that masquerade ran long enough to accumulate 1398 un-analyzed rows (20% of
    its decision history).

    This endpoint makes the outage legible:

    * ``healthy``   — no failures in the window
    * ``degraded``  — some calls failing (partial outage / rate limiting)
    * ``critical``  — every triage call in the window failed; the platform is
      queueing un-analyzed alerts for humans, not triaging them

    Available to any analyst: knowing whether the AI is actually working is
    not privileged infrastructure telemetry, it is a precondition for trusting
    anything in the queue.
    """
    from src.api.dependencies import get_db

    hours = max(1, min(int(hours), 168))  # clamp to 1h..7d
    stats = get_db().get_llm_failure_rate(hours=hours)

    if stats["total"] == 0:
        status = "idle"
        detail = "No triage decisions in this window — nothing to report."
    elif stats["failed"] == 0:
        status = "healthy"
        detail = "All triage calls completed normally."
    elif stats["failed"] == stats["total"]:
        status = "critical"
        detail = ("EVERY triage call failed. Alerts are being escalated "
                  "WITHOUT analysis. Check the LLM backend "
                  "(expired CLI auth, missing API key, provider outage).")
    else:
        status = "degraded"
        detail = (f"{stats['failed']} of {stats['total']} triage calls failed. "
                  "Those alerts were escalated without analysis.")

    logger.info("llm_health_served", status=status,
                failed=stats["failed"], total=stats["total"])
    return {**stats, "status": status, "detail": detail}


@router.get("/api/health/log-sources")
async def get_log_sources(
    user: dict = Depends(require_role("mssp_admin")),
    _gate: None = Depends(require_license_feature("pipeline_health")),
):
    """Get log source inventory with live heartbeat status.
    Restricted to mssp_admin — exposes global infrastructure inventory."""
    from src.api.dependencies import get_pipeline_monitor
    monitor = get_pipeline_monitor()
    if not monitor:
        return {"sources": [], "message": "Pipeline monitor not initialized"}
    try:
        return {"sources": monitor.get_log_source_inventory()}
    except Exception as e:                               # noqa: BLE001
        # WO-H90: was a silent `return {..., "error": str(e)}` with nothing
        # written server-side. A failure here means the log-source inventory
        # shows ZERO sources — which looks exactly like a total ingest outage,
        # and the only trace of the difference was in one admin's browser.
        logger.warning("log_source_inventory_failed", error=str(e)[:200])
        return {"sources": [], "error": str(e)}


@router.post("/api/guidance/reload")
@limiter.limit("2/minute")
async def reload_guidance(
    request: Request,
    user: dict = Depends(require_admin),
):
    """Reload guidance documents from disk. Requires admin role.

    WO-H76: risk_criteria.yaml has two independent consumers — the triage
    agent's guidance text AND the enrichment service's scoring config (asset
    criticality, user risk profiles, time context). Only the first was reloaded
    here, so editing any risk multiplier still needed a service restart.

    The outer ``status`` REFLECTS EVERY consumer's reload: reporting a flat
    ``"ok"`` with a nested error made a half-applied edit look applied, and the
    operator's next action would be to trust a multiplier — or a severity floor
    — that the running service is not using. Like the rest of this endpoint, a
    failure is reported in the body rather than raised.
    """
    from src.api.dependencies import (get_triage_agent, get_enrichment,
                                       get_incident_engine)
    triage_agent = get_triage_agent()
    if not triage_agent:
        return {"status": "error", "message": "Triage agent not initialized"}

    # WO-H97 QA (D3): this call was UNGUARDED. ``GuidanceLoader`` raises
    # SystemExit when a required guidance file is missing or will not decrypt —
    # refusing to START on that is correct, but an admin pressing "reload" after
    # a bad edit would have killed the running process, taking triage down with
    # it. Refusing to start and refusing to keep running are different
    # decisions. The failure is now reported like every other one here.
    guidance_status, guidance_detail = "ok", ""
    try:
        triage_agent.guidance.reload()
    except (Exception, SystemExit) as e:
        logger.error("guidance_documents_reload_failed", error=str(e))
        guidance_status, guidance_detail = "error", str(e)[:300]

    enrichment = get_enrichment()
    enrichment_detail = ""
    if enrichment is None:
        enrichment_status = "not_initialized"
    else:
        try:
            result = enrichment.reload_risk_criteria()
            status = result.get("status") if isinstance(result, dict) else None
            enrichment_status = status if isinstance(status, str) else "ok"
            detail = result.get("message") if isinstance(result, dict) else None
            enrichment_detail = detail if isinstance(detail, str) else ""
        except Exception as e:
            logger.error("enrichment_risk_criteria_reload_failed", error=str(e))
            enrichment_status = "error"
            enrichment_detail = str(e)

    # WO-H97: escalation_logic.yaml now also carries `severity_policy` (the
    # deterministic severity floors and ceilings). That block is read by the
    # incident engine, which holds its own GuidanceLoader — so, exactly like
    # the enrichment risk criteria above, editing it without this call would
    # need a service restart while the endpoint reported success.
    incident_engine = get_incident_engine()
    severity_detail = ""
    severity_counts: dict = {}
    if incident_engine is None:
        severity_status = "not_initialized"
    else:
        try:
            result = incident_engine.reload_severity_policy()
            result = result if isinstance(result, dict) else {}
            severity_counts = result
            status = result.get("status")
            severity_status = status if isinstance(status, str) else "ok"
            detail = result.get("message")
            severity_detail = detail if isinstance(detail, str) else ""
        except Exception as e:
            logger.error("incident_severity_policy_reload_failed", error=str(e))
            severity_status = "error"
            severity_detail = str(e)

    # WO-H111 QA (M2): the per-rule guidance file has its own load state, and
    # a parse failure there silently removes every `escalate` signal in it. The
    # endpoint used to answer {"status":"ok","message":"Guidance reloaded"} in
    # exactly that case — the invariant the WO-H97 comment below says must hold.
    rule_guidance_state = "not_initialized"
    rule_guidance_rejected = []
    try:
        _loader = getattr(triage_agent, "guidance", None) if triage_agent else None
        _rg = getattr(_loader, "get_rule_guidance", None)
        _rg = _rg() if callable(_rg) else None
        if _rg is not None:
            rule_guidance_state = getattr(_rg, "state", "not_initialized")
            rule_guidance_rejected = list(getattr(_rg, "rejected", []) or [])
        elif _loader is not None and callable(getattr(
                _loader, "get_rule_guidance", None)):
            # QA re-audit (LOW): `loader._load_rule_guidance` sets the object to
            # None when CONSTRUCTION itself failed. That was landing in
            # "not_initialized", which reads as healthy — the one failure mode
            # left answering ok, which is precisely what M2 exists to stop.
            rule_guidance_state = "init_failed"
    except Exception as e:                                      # noqa: BLE001
        logger.warning("rule_guidance_state_unreadable", error=str(e)[:200])
        rule_guidance_state = "failed"

    ok = all(s in ("ok", "not_initialized")
             for s in (guidance_status, enrichment_status, severity_status))
    # `absent` is fine — the platform ran without this file for its whole life.
    # `failed` is not, and neither is a file that loaded with entries thrown away.
    if rule_guidance_state in ("failed", "init_failed") or rule_guidance_rejected:
        ok = False
    message = "Guidance reloaded"
    rule_guidance_note = ""
    if rule_guidance_state in ("failed", "init_failed"):
        rule_guidance_note = ("Per-rule guidance FAILED TO LOAD — "
                   "every deterministic signal in rule_guidance.yaml is "
                   "currently inactive.")
    elif rule_guidance_rejected:
        rule_guidance_note = ("%d per-rule signal(s) were rejected "
                   "and are NOT active: %s"
                   % (len(rule_guidance_rejected),
                      "; ".join("%s: %s" % (r.get("what"), r.get("why"))
                                for r in rule_guidance_rejected[:5])))
    if guidance_status != "ok":
        message = ("Guidance documents were NOT reloaded: %s"
                   % (guidance_detail or guidance_status))
    elif enrichment_status not in ("ok", "not_initialized"):
        message = ("Guidance reloaded, but enrichment risk criteria were NOT "
                   "applied: %s" % (enrichment_detail or enrichment_status))
    elif severity_status not in ("ok", "not_initialized"):
        # The engine's own message is used VERBATIM. It is the only thing that
        # knows whether the new policy was discarded (and the old one kept) or
        # applied without its unusable entries — and after WO-H97 QA D3-round-3
        # those are different sentences that must not be papered over with a
        # generic "NOT applied" from out here.
        message = ("Guidance reloaded, but the incident severity policy did "
                   "not update cleanly: %s"
                   % (severity_detail or severity_status))
    # QA re-audit (LOW): APPEND, never replace. The chain above used to
    # overwrite this line, so when two things were broken at once the operator
    # was told about the other one and never learned that every deterministic
    # signal was inactive.
    if rule_guidance_note:
        message = "%s | %s" % (message, rule_guidance_note)

    logger.info("guidance_reloaded_via_api", actor=user.get("sub", "unknown"),
                guidance_documents=guidance_status,
                enrichment_risk_criteria=enrichment_status,
                incident_severity_policy=severity_status,
                severity_floors=severity_counts.get("floors"),
                severity_ceilings=severity_counts.get("ceilings"),
                severity_rejected=len(severity_counts.get("rejected") or []))
    return {"status": "ok" if ok else "error", "message": message,
            "rule_guidance_state": rule_guidance_state,
            "rule_guidance_rejected": rule_guidance_rejected,
            "guidance_documents": guidance_status,
            "guidance_detail": guidance_detail,
            "enrichment_risk_criteria": enrichment_status,
            "enrichment_detail": enrichment_detail,
            "incident_severity_policy": severity_status,
            "incident_severity_detail": severity_detail,
            # WO-H97 QA (D2): the COUNTS, not just a status word. "floors: 0"
            # is the difference between a working loss-of-visibility floor and
            # a typo that silently deleted it, and the endpoint used to throw
            # that number away.
            "incident_severity_floors": severity_counts.get("floors"),
            "incident_severity_ceilings": severity_counts.get("ceilings"),
            "incident_severity_rejected": severity_counts.get("rejected") or []}
