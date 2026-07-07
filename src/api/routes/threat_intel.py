"""Threat intelligence routes."""

import structlog
from fastapi import APIRouter, Depends, Query, Request

from src.api.auth import verify_jwt, require_role
from src.api.dependencies import get_db, get_ti_collector, limiter
from src.api.feature_gates import require_license_feature

router = APIRouter(prefix="/api/threat-intel")
logger = structlog.get_logger(__name__)


@router.get("/stats")
async def get_ti_stats(
    user: dict = Depends(verify_jwt),
    _gate: None = Depends(require_license_feature("ti_feeds_tier1")),
):
    """Get TI module statistics: IOC counts by source/type/severity + feed status."""
    _db = get_db()
    stats = _db.get_ioc_stats()
    feeds = _db.get_feed_statuses()
    kev_count = len(_db.get_kev_cves(limit=10000))
    return {"stats": stats, "feeds": feeds, "kev_count": kev_count}


@router.get("/feeds")
async def get_ti_feeds(
    user: dict = Depends(verify_jwt),
    _gate: None = Depends(require_license_feature("ti_feeds_tier1")),
):
    """Get all feed statuses."""
    _db = get_db()
    return {"feeds": _db.get_feed_statuses()}


@router.post("/collect")
@limiter.limit("2/minute")
async def trigger_ti_collection(
    request: Request,
    user: dict = Depends(require_role("admin", "senior_analyst")),
    _gate: None = Depends(require_license_feature("ti_feeds_tier1")),
):
    """Manually trigger a TI collection cycle."""
    _ti_collector = get_ti_collector()
    if not _ti_collector:
        return {"status": "error", "message": "TI collector not initialized"}
    import threading
    threading.Thread(target=_ti_collector.collect_all, daemon=True).start()
    return {"status": "collection_started"}


@router.get("/ioc/{ioc_value:path}")
async def lookup_ioc(
    ioc_value: str, user: dict = Depends(verify_jwt),
    _gate: None = Depends(require_license_feature("ti_feeds_tier1")),
):
    """Look up a specific IOC value in the local database."""
    _db = get_db()
    results = _db.lookup_ioc(ioc_value)
    return {"ioc_value": ioc_value, "matches": results, "total": len(results)}


@router.get("/cve")
async def get_cve_data(
    kev_only: bool = False,
    limit: int = Query(100, ge=1, le=1000),
    user: dict = Depends(verify_jwt),
    _gate: None = Depends(require_license_feature("ti_feeds_tier1")),
):
    """Get CVE/EPSS/KEV data."""
    _db = get_db()
    cves = _db.get_kev_cves(limit=limit) if kev_only else _db.get_all_cves(limit=limit)
    return {"cves": cves, "total": len(cves)}
