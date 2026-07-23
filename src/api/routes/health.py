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
        except Exception:
            pass

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
    except Exception:
        pass

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
        except Exception:
            pass
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
    except Exception as e:
        return {"sources": [], "error": str(e)}


@router.post("/api/guidance/reload")
@limiter.limit("2/minute")
async def reload_guidance(
    request: Request,
    user: dict = Depends(require_admin),
):
    """Reload guidance documents from disk. Requires admin role."""
    from src.api.dependencies import get_triage_agent
    triage_agent = get_triage_agent()
    if not triage_agent:
        return {"status": "error", "message": "Triage agent not initialized"}
    triage_agent.guidance.reload()
    logger.info("guidance_reloaded_via_api", actor=user.get("sub", "unknown"))
    return {"status": "ok", "message": "Guidance reloaded"}
