"""Dashboard statistics routes."""

import json
import re
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query

from src.api.auth import verify_jwt
from src.api.dependencies import get_db

router = APIRouter(prefix="/api/dashboard")
logger = structlog.get_logger(__name__)


@router.get("/stats")
async def get_dashboard_stats(user: dict = Depends(verify_jwt)):
    """Get comprehensive dashboard statistics."""
    _db = get_db()
    stats = _db.get_dashboard_stats()
    recent = _db.get_recent_decisions(limit=200)
    anomaly_count = 0
    for dec in recent:
        try:
            enr = json.loads(dec.get("enrichment_summary") or "{}")
            if enr.get("baseline_anomaly"):
                anomaly_count += 1
        except (json.JSONDecodeError, TypeError):
            pass
    stats["anomaly_count"] = anomaly_count
    return stats


@router.get("/metrics/{metric_name}")
async def get_metric_timeseries(
    metric_name: str, days: int = Query(30, ge=1, le=365),
    user: dict = Depends(verify_jwt),
):
    """Get timeseries data for a specific metric."""
    if not re.match(r"^[a-zA-Z0-9_-]+$", metric_name):
        raise HTTPException(status_code=400, detail="Invalid metric name")
    _db = get_db()
    return _db.get_metrics_timeseries(metric_name, days=days)
