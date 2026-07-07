"""
License Feature Gates — FastAPI dependencies for tier-based access control.

Usage in routes:

    from src.api.feature_gates import (
        require_license_feature, require_triage_quota,
        require_nl_query_quota, require_active_response,
        require_tab_access,
    )

    @router.post("/run")
    async def run_hunt(
        request: Request,
        user: dict = Depends(verify_jwt),
        _gate: None = Depends(require_license_feature("hunt")),
    ):
        ...

    @router.post("/api/query")
    async def nl_query(
        request: Request,
        _gate: None = Depends(require_nl_query_quota()),
    ):
        ...
"""

import structlog
from datetime import datetime, timezone
from fastapi import Depends, HTTPException
from functools import lru_cache

from src.api.dependencies import get_db, get_license_info

logger = structlog.get_logger(__name__)


# -- Feature gate --------------------------------------------------------------

def require_license_feature(feature: str, label: str = None):
    """Dependency that blocks access if the license doesn't include a feature.

    Usage: _gate = Depends(require_license_feature("detection"))
    """
    async def _check():
        lic = get_license_info()
        if lic is None:
            raise HTTPException(503, "License not loaded")
        if not lic.has_feature(feature):
            display = label or feature.replace("_", " ").title()
            raise HTTPException(
                403,
                detail={
                    "error": "feature_not_available",
                    "feature": feature,
                    "tier": lic.tier,
                    "message": (
                        f"{display} is not available on the "
                        f"{lic.tier.replace('_', ' ').title()} plan. "
                        f"Contact SecureSleuths to upgrade."
                    ),
                    "upgrade_url": "https://securesleuths.in/pricing",
                },
            )
    return _check


# -- Daily triage quota --------------------------------------------------------

def require_triage_quota():
    """Dependency that enforces daily AI triage call limits."""
    async def _check():
        lic = get_license_info()
        if lic is None:
            raise HTTPException(503, "License not loaded")

        if lic.max_triage_daily == 0:
            return  # unlimited

        db = get_db()
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        count = db.get_metric_count("triage_call", since_date=today)

        if not lic.check_triage_limit(count):
            raise HTTPException(
                429,
                detail={
                    "error": "triage_limit_exceeded",
                    "tier": lic.tier,
                    "limit": lic.max_triage_daily,
                    "used": count,
                    "message": (
                        f"Daily AI triage limit reached "
                        f"({lic.max_triage_daily}/day on "
                        f"{lic.tier.replace('_', ' ').title()} plan). "
                        f"Resets at midnight UTC."
                    ),
                    "upgrade_url": "https://securesleuths.in/pricing",
                },
            )
    return _check


# -- Daily NL query quota ------------------------------------------------------

def require_nl_query_quota():
    """Dependency that enforces daily NL investigation query limits."""
    async def _check():
        lic = get_license_info()
        if lic is None:
            raise HTTPException(503, "License not loaded")

        if not lic.has_feature("nl_query"):
            raise HTTPException(
                403,
                detail={
                    "error": "feature_not_available",
                    "feature": "nl_query",
                    "tier": lic.tier,
                    "message": (
                        "Natural language investigation is not available on "
                        f"the {lic.tier.replace('_', ' ').title()} plan."
                    ),
                },
            )

        if lic.max_nl_queries_daily == 0:
            return  # unlimited

        db = get_db()
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        count = db.get_metric_count("nl_query", since_date=today)

        if not lic.check_nl_query_limit(count):
            raise HTTPException(
                429,
                detail={
                    "error": "nl_query_limit_exceeded",
                    "tier": lic.tier,
                    "limit": lic.max_nl_queries_daily,
                    "used": count,
                    "message": (
                        f"Daily investigation query limit reached "
                        f"({lic.max_nl_queries_daily}/day). "
                        f"Resets at midnight UTC."
                    ),
                },
            )
    return _check


# -- Active response action gate -----------------------------------------------

def require_active_response(action: str):
    """Dependency that checks if a specific AR action is allowed."""
    async def _check():
        lic = get_license_info()
        if lic is None:
            raise HTTPException(503, "License not loaded")

        if not lic.check_active_response(action):
            raise HTTPException(
                403,
                detail={
                    "error": "action_not_available",
                    "action": action,
                    "tier": lic.tier,
                    "allowed_actions": lic.active_response_actions,
                    "message": (
                        f"'{action}' is not available on the "
                        f"{lic.tier.replace('_', ' ').title()} plan. "
                        f"Allowed actions: "
                        f"{', '.join(lic.active_response_actions) or 'none'}."
                    ),
                },
            )
    return _check


# -- Dashboard tab gate --------------------------------------------------------

def require_tab_access(tab: str):
    """Dependency that checks if a dashboard tab is accessible."""
    async def _check():
        lic = get_license_info()
        if lic is None:
            raise HTTPException(503, "License not loaded")

        if not lic.check_tab_access(tab):
            raise HTTPException(
                403,
                detail={
                    "error": "tab_not_available",
                    "tab": tab,
                    "tier": lic.tier,
                    "allowed_tabs": lic.allowed_tabs,
                    "message": (
                        f"The '{tab}' tab is not available on the "
                        f"{lic.tier.replace('_', ' ').title()} plan."
                    ),
                },
            )
    return _check


# -- User creation gate --------------------------------------------------------

def require_user_quota():
    """Dependency that enforces max user limits per tier."""
    async def _check():
        lic = get_license_info()
        if lic is None:
            raise HTTPException(503, "License not loaded")

        if lic.max_users in (None, 0):
            return  # unlimited (None treated as unset → unlimited)

        db = get_db()
        current = len(db.get_all_users(include_inactive=False))

        if not lic.check_user_limit(current):
            raise HTTPException(
                403,
                detail={
                    "error": "user_limit_exceeded",
                    "tier": lic.tier,
                    "limit": lic.max_users,
                    "current": current,
                    "message": (
                        f"User limit reached ({lic.max_users} users on "
                        f"{lic.tier.replace('_', ' ').title()} plan). "
                        f"Contact SecureSleuths to upgrade."
                    ),
                },
            )
    return _check


# -- Notification channel gate -------------------------------------------------

def require_notification_channel(channel: str):
    """Dependency that checks if a notification channel is allowed."""
    async def _check():
        lic = get_license_info()
        if lic is None:
            logger.warning("notification_gate_no_license",
                           channel=channel,
                           msg="No license loaded — blocking notification channel")
            raise HTTPException(
                403,
                detail={
                    "error": "license_not_loaded",
                    "channel": channel,
                },
            )

        if not lic.check_notification_channel(channel):
            logger.warning("notification_channel_blocked",
                           channel=channel, tier=lic.tier)
            raise HTTPException(
                403,
                detail={
                    "error": "notification_channel_not_available",
                    "channel": channel,
                    "tier": lic.tier,
                },
            )
    return _check


# -- Multi-tenant gate ---------------------------------------------------------

async def require_multi_tenant():
    """Dependency that blocks multi-tenant operations on non-MT licenses."""
    lic = get_license_info()
    if lic is None:
        raise HTTPException(503, "License not loaded")

    if not lic.multi_tenant:
        raise HTTPException(
            403,
            detail={
                "error": "multi_tenant_not_available",
                "tier": lic.tier,
                "message": (
                    "Multi-tenant operations require an Enterprise license."
                ),
            },
        )


# -- Helper: get license summary for dashboard ---------------------------------

def get_license_tier_info() -> dict:
    """Returns tier info for the dashboard UI to show/hide tabs and features."""
    lic = get_license_info()
    if lic is None:
        return {"tier": "unknown", "tabs": [], "features": []}

    return {
        "tier": lic.tier,
        "tier_display": lic.tier.replace("_", " ").title(),
        "is_free": lic.is_free_tier,
        "tabs": lic.allowed_tabs,
        "features": lic.features,
        "limits": {
            "agents": {"max": lic.max_agents, "label": "Unlimited" if lic.max_agents == 0 else str(lic.max_agents)},
            "users": {"max": lic.max_users, "label": "Unlimited" if lic.max_users == 0 else str(lic.max_users)},
            "triage_daily": {"max": lic.max_triage_daily, "label": "Unlimited" if lic.max_triage_daily == 0 else str(lic.max_triage_daily)},
            "nl_queries_daily": {"max": lic.max_nl_queries_daily, "label": "Unlimited" if lic.max_nl_queries_daily == 0 else str(lic.max_nl_queries_daily)},
        },
        "active_response_actions": lic.active_response_actions,
        "days_remaining": lic.days_remaining,
        "upgrade_url": "https://securesleuths.in/pricing",
    }
