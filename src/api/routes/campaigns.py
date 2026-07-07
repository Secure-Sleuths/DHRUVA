"""Campaign (attack-chain) read routes — WO-B5.

A *campaign* is the set of incidents the M5 correlation engine
(``src/incidents/engine.py``) has linked by a shared ``attack_chain_id``,
presented as one cross-host kill-chain for the redesigned Overview
("Campaign Command"). These endpoints are pure read-only aggregation over
existing incident data — NO new correlation logic, NO schema changes.

Null-chain decision: incidents with a NULL ``attack_chain_id`` (standalone
incidents) are EXCLUDED. The Overview mockup ("CAMPAIGNS" data + ``tOverview``)
treats the campaign map strictly as attack-chain groups ("groups alerts by
attack_chain_id · 3 distinct chains live now") — standalone incidents live on
the Incidents tab, not the campaign map.

Projection: kept minimal per PM decision #4. Each campaign carries
``furthest_tactic`` plus a single ``projected_next_tactic`` computed as the
next unseen tactic in canonical kill-chain order, marked
``projection_basis: "kill_chain_order_heuristic"``. It is a heuristic hunt
hint, never an observed/actioned step and never a probability.

Auth: mirrors the incidents read gate — ``GET /api/incidents`` uses
``verify_jwt``; these read endpoints use the same (no widening/narrowing).
"""

import structlog
from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from src.api.auth import verify_jwt
from src.api.dependencies import get_db, limiter

router = APIRouter(prefix="/api/campaigns")
logger = structlog.get_logger(__name__)


@router.get("")
@limiter.limit("200/minute")
async def get_campaigns(
    request: Request,
    status: Optional[str] = None,
    active_only: bool = False,
    limit: int = Query(100, ge=1, le=500),
    user: dict = Depends(verify_jwt),
):
    """List attack-chain campaigns (M5-linked incident groups) for the tenant.

    Optional ``status`` / ``active_only`` filter the campaign rollup status;
    ``limit`` caps the result (worst-severity / longest-dwell first).
    """
    _db = get_db()
    now = datetime.now(timezone.utc)
    campaigns = _db.get_campaigns(
        status=status, active_only=active_only, limit=limit, now=now,
    )
    logger.info("campaigns_served", count=len(campaigns),
                active_only=active_only, status=status)
    return {"campaigns": campaigns, "total": len(campaigns)}


@router.get("/{attack_chain_id}")
@limiter.limit("200/minute")
async def get_campaign_detail(
    request: Request,
    attack_chain_id: str,
    user: dict = Depends(verify_jwt),
):
    """Get a single campaign by its ``attack_chain_id`` (tenant-scoped)."""
    _db = get_db()
    now = datetime.now(timezone.utc)
    campaign = _db.get_campaign(attack_chain_id, now=now)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    logger.info("campaign_detail_served", attack_chain_id=attack_chain_id,
                member_count=campaign.get("member_count"))
    return campaign
