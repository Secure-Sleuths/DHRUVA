"""Health check and guidance reload routes."""

import structlog
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request

from src.api.auth import require_admin, require_role
from src.api.dependencies import limiter
from src.api.feature_gates import require_license_feature

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.get("/api/health")
async def health_check():
    """Public health check — verifies DB pool round-trip.

    Returns 200 with ``status=healthy`` when the platform can SELECT 1
    from Postgres via its pool. Returns 200 with ``status=degraded``
    and an ``error`` field when the pool round-trip fails — this
    flips container orchestrators (compose/k8s) onto a restart path
    for cross-host installs where a healthy HTTP responder but
    broken DB pool would otherwise look fine.
    """
    payload = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
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
