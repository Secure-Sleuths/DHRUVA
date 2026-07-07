"""Overview / KPI summary read route — WO-B7.

Backs the redesigned Overview page ("Campaign Command", WO-U3) KPI strip.
Each tile "expands to its math", so every KPI is returned with the supporting
detail the UI needs to show *how* the number was derived.

This is pure read-only aggregation over data other helpers already compute:

  * KPIs 1-4 are derived from ``SOCDatabase.get_campaigns(...)`` (WO-B5) — the
    SAME campaign rollups the Campaign Command map renders. We call it ONCE and
    fold the tiles out of the result. NO correlation logic is recomputed here.
  * KPI 5 (open incidents) reuses ``get_dashboard_stats()`` — which already
    counts ``status IN ('open','investigating')`` incidents for the tenant — so
    no duplicate count query is issued.

Tenant isolation: both ``get_campaigns`` and ``get_dashboard_stats`` are scoped
by ``_tenant_filter()``. This route issues NO raw query of its own, so the
Overview can only ever reflect the caller's tenant.

Canonical kill-chain tactic ordering for "furthest tactic reached" is REUSED
from ``src/mitre/matrix.py`` (``tactic_index`` / ``MITRE_TACTICS``) — not a
second copy.

Auth: mirrors the campaigns/incidents read gate — ``verify_jwt`` (no
widening/narrowing). Available across tiers (the Overview tab is un-gated per
the mockup), so no license gate is added.

``hosts_on_chain.of_total`` is returned as ``null``: there is no cheap
tenant-scoped "monitored agents" count in the DB (agent inventory comes from
the Wazuh Manager API / the ``tenant_agents`` mapping). Per the WO we do NOT
fabricate a total.
"""

import structlog
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request

from src.api.auth import verify_jwt
from src.api.dependencies import get_db, limiter
from src.mitre.matrix import tactic_index

router = APIRouter(prefix="/api/overview")
logger = structlog.get_logger(__name__)

# Tactics whose presence as the furthest-reached step means an attacker has
# reached the "endgame" of the kill chain. Used for the furthest-tactic tile's
# ``exfil_or_impact_reached`` flag.
_ENDGAME_TACTICS = {"Exfiltration", "Impact"}


def _campaign_ref(c: dict) -> dict:
    """Minimal campaign reference for a KPI tile's supporting detail."""
    return {
        "attack_chain_id": c.get("attack_chain_id"),
        "name": c.get("name"),
    }


def build_overview_summary(
    campaigns: list,
    open_incidents: int,
    critical_incidents: int = 0,
    of_total: "int | None" = None,
) -> dict:
    """Fold the KPI tiles out of the campaign rollups + incident counts.

    Pure function (no DB, no clock) so it is unit-testable without a Postgres
    container. ``campaigns`` is the list of campaign dicts from
    ``get_campaigns(...)``; the KPIs 1-4 are derived from it. ``open_incidents``
    / ``critical_incidents`` come from ``get_dashboard_stats()``.

    Each returned tile is ``{ value, ...supporting detail }`` so the UI can
    expand-to-math.
    """
    active = [c for c in campaigns if c.get("status") == "active"]
    contained = [c for c in campaigns if c.get("status") == "contained"]

    # KPI 1 — Active campaigns: total tracked campaigns, split advancing (active)
    # vs contained. Mirrors the mockup's "2 advancing · 1 contained" tile.
    active_campaigns = {
        "value": len(campaigns),
        "advancing": len(active),
        "contained": len(contained),
    }

    # KPI 2 — Estate dwell (worst): the largest dwell among ACTIVE campaigns,
    # plus which campaign it is.
    worst_dwell = None
    if active:
        worst_dwell = max(active, key=lambda c: c.get("dwell_seconds") or 0)
    estate_dwell_worst = {
        "value_seconds": worst_dwell.get("dwell_seconds") if worst_dwell else None,
        "value": worst_dwell.get("dwell") if worst_dwell else None,
        "campaign": _campaign_ref(worst_dwell) if worst_dwell else None,
    }

    # KPI 3 — Hosts on a chain: DISTINCT hosts across active campaigns (order-
    # preserving union), plus the list. ``of_total`` is null (see module doc).
    hosts: list = []
    for c in active:
        for h in (c.get("assets") or {}).get("hosts") or []:
            if h not in hosts:
                hosts.append(h)
    hosts_on_chain = {
        "value": len(hosts),
        "hosts": hosts,
        "of_total": of_total,
    }

    # KPI 4 — Furthest tactic reached: the furthest-along ATT&CK tactic across
    # active campaigns, by canonical kill-chain order, plus which campaign.
    furthest_campaign = None
    furthest_idx = -1
    for c in active:
        ft = c.get("furthest_tactic")
        if not ft:
            continue
        idx = tactic_index(ft)
        if idx is None:
            continue
        if idx > furthest_idx:
            furthest_idx = idx
            furthest_campaign = c
    furthest_value = (
        furthest_campaign.get("furthest_tactic") if furthest_campaign else None
    )
    furthest_tactic = {
        "value": furthest_value,
        "campaign": _campaign_ref(furthest_campaign) if furthest_campaign else None,
        "exfil_or_impact_reached": furthest_value in _ENDGAME_TACTICS,
    }

    # KPI 5 — Open incidents: open/investigating count (from get_dashboard_stats).
    open_incidents_tile = {
        "value": open_incidents,
        "critical": critical_incidents,
    }

    return {
        "active_campaigns": active_campaigns,
        "estate_dwell_worst": estate_dwell_worst,
        "hosts_on_chain": hosts_on_chain,
        "furthest_tactic": furthest_tactic,
        "open_incidents": open_incidents_tile,
    }


@router.get("/summary")
@limiter.limit("200/minute")
async def get_overview_summary(
    request: Request,
    user: dict = Depends(verify_jwt),
):
    """Return the Overview KPI strip — one call, each tile with its math.

    KPIs 1-4 derive from ``get_campaigns`` (tenant-scoped campaign rollups);
    KPI 5 reuses ``get_dashboard_stats`` (tenant-scoped open-incident count).
    """
    _db = get_db()
    now = datetime.now(timezone.utc)
    campaigns = _db.get_campaigns(now=now)
    stats = _db.get_dashboard_stats()

    summary = build_overview_summary(
        campaigns,
        open_incidents=stats.get("open_incidents", 0) or 0,
        critical_incidents=stats.get("critical_incidents", 0) or 0,
        of_total=None,
    )

    logger.info(
        "overview_summary_served",
        total_campaigns=summary["active_campaigns"]["value"],
        advancing=summary["active_campaigns"]["advancing"],
        hosts_on_chain=summary["hosts_on_chain"]["value"],
        furthest_tactic=summary["furthest_tactic"]["value"],
        open_incidents=summary["open_incidents"]["value"],
    )
    return summary
