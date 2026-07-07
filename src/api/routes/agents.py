"""Agent inventory and compliance routes.

Multi-tenant architecture (shared Wazuh backend model):

All tenants share a single Wazuh manager and OpenSearch cluster.  Tenant
isolation is enforced by mapping Wazuh agent IDs to tenants via the
``tenant_agents`` DB table.  This mapping MUST be configured for each
tenant before enabling multi-tenant mode.  The platform does NOT
currently support per-tenant Wazuh manager/OpenSearch instances at
runtime — ``TenantServiceRegistry.get_wazuh_client()`` exists for
future use but is not wired into agent/response/polling paths.

Role-based rules:
  - mssp_admin:  always sees every agent (cross-tenant operational view).
  - admin / analyst / read_only:  sees only agents mapped to their client_id.
    In multi-tenant mode, unmapped tenants see zero agents (fail-closed).
    In single-tenant mode, unmapped tenants see all agents (backward-compat).
"""

import structlog
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query

from src.api.auth import verify_jwt, require_role
from src.api.dependencies import get_db, get_enrichment, get_tenant_registry
from src.api.feature_gates import require_license_feature
from src.database.store import is_multi_tenant, _tenant_ctx

router = APIRouter()
logger = structlog.get_logger(__name__)


def get_allowed_agent_ids(user: dict) -> list[str] | None:
    """Return the list of agent IDs the user's tenant may access.

    Returns None when there is no agent-to-tenant mapping (single-tenant
    backward compat).  In multi-tenant mode with no mapping, returns an
    empty list (fail-closed) so the tenant sees zero agents rather than all.
    mssp_admin always returns None (all agents).
    """
    if user.get("role") == "mssp_admin":
        return None

    client_id = user.get("client_id")
    if not client_id:
        if is_multi_tenant():
            return []  # no tenant context in MT mode → zero agents
        return None

    db = get_db()
    allowed_ids = db.get_tenant_agent_ids(client_id)
    if allowed_ids is None:
        if is_multi_tenant():
            logger.warning("tenant_has_no_agent_mapping",
                           client_id=client_id,
                           detail="Returning zero agents (multi-tenant fail-closed)")
            return []
        return None  # single-tenant fallback
    return allowed_ids


def _filter_agents_for_tenant(agents: list[dict], user: dict) -> list[dict]:
    """Filter agent list based on the caller's tenant context.

    - mssp_admin role bypasses filtering (sees all agents).
    - Other roles are restricted to agents mapped to their client_id via the
      ``tenant_agents`` table.
    - In multi-tenant mode, unmapped tenants see zero agents (fail-closed).
    - In single-tenant mode, unmapped tenants see all agents (backward compat).
    """
    allowed_ids = get_allowed_agent_ids(user)
    if allowed_ids is None:
        return agents

    allowed_set = set(allowed_ids)
    return [a for a in agents if a.get("id") in allowed_set]


def _verify_agent_access(agent_id: str, user: dict) -> None:
    """Raise 404 if the caller's tenant is not allowed to access this agent."""
    allowed_ids = get_allowed_agent_ids(user)
    if allowed_ids is None:
        return  # mssp_admin or single-tenant (no mapping)

    if agent_id not in set(allowed_ids):
        raise HTTPException(status_code=404, detail="Agent not found")


def _get_wazuh_for_user(user: dict):
    """Resolve the Wazuh client for the caller's tenant context.

    Uses the effective tenant from _tenant_ctx (which reflects X-Tenant-ID
    overrides set by middleware) rather than the JWT's client_id, so
    mssp_admin users viewing a different tenant get that tenant's Wazuh client.
    Falls back to the global client from the enrichment service.
    """
    # Prefer the middleware-resolved tenant context over the JWT client_id
    effective_tenant = _tenant_ctx.get()
    if not effective_tenant or effective_tenant == "__CROSS_TENANT__":
        effective_tenant = user.get("client_id")
    if effective_tenant and is_multi_tenant():
        registry = get_tenant_registry()
        if registry:
            client = registry.get_wazuh_client(effective_tenant)
            if client:
                return client
    return get_enrichment().wazuh


@router.get("/api/agents")
async def get_agents(
    status: Optional[str] = None,
    user: dict = Depends(verify_jwt),
):
    """Get Wazuh agents visible to the caller's tenant."""
    wazuh_client = _get_wazuh_for_user(user)
    agents = wazuh_client.get_all_agents()
    agents = _filter_agents_for_tenant(agents, user)
    if status:
        agents = [a for a in agents if a.get("status") == status]
    return {"agents": agents, "total": len(agents)}


@router.get("/api/agents/{agent_id}")
async def get_agent_detail(agent_id: str, user: dict = Depends(verify_jwt)):
    """Get full agent info including OS details."""
    _verify_agent_access(agent_id, user)
    wazuh = _get_wazuh_for_user(user)
    agent = wazuh.get_agent_info(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    os_info = wazuh.get_agent_os(agent_id)
    return {"agent": agent, "os": os_info}


@router.get("/api/agents/{agent_id}/processes")
async def get_agent_processes(
    agent_id: str,
    limit: int = Query(200, ge=1, le=500),
    user: dict = Depends(verify_jwt),
):
    """Get running processes for an agent."""
    _verify_agent_access(agent_id, user)
    wazuh = _get_wazuh_for_user(user)
    procs = wazuh.get_agent_processes(agent_id, limit=limit)
    return {"processes": procs, "total": len(procs)}


@router.get("/api/agents/{agent_id}/ports")
async def get_agent_ports(
    agent_id: str,
    limit: int = Query(200, ge=1, le=500),
    user: dict = Depends(verify_jwt),
):
    """Get open ports for an agent."""
    _verify_agent_access(agent_id, user)
    wazuh = _get_wazuh_for_user(user)
    ports = wazuh.get_agent_ports(agent_id, limit=limit)
    return {"ports": ports, "total": len(ports)}


@router.get("/api/agents/{agent_id}/packages")
async def get_agent_packages(
    agent_id: str,
    limit: int = Query(200, ge=1, le=500),
    user: dict = Depends(verify_jwt),
):
    """Get installed packages for an agent."""
    _verify_agent_access(agent_id, user)
    wazuh = _get_wazuh_for_user(user)
    pkgs = wazuh.get_agent_packages(agent_id, limit=limit)
    return {"packages": pkgs, "total": len(pkgs)}


# ---------------------------------------------------------------------------
# Compliance / SCA
#
# These per-agent SCA routes are namespaced under /api/agents/{agent_id}/sca
# (matching their /syscheck, /rootcheck, /registry siblings) so they do NOT
# shadow the paid compliance router mounted at prefix /api/compliance
# (/matrix, /{framework}/coverage). Starlette matches in registration order,
# and agents_router is included before the compliance router in app.py.
# ---------------------------------------------------------------------------

@router.get("/api/agents/{agent_id}/sca")
async def get_compliance_policies(
    agent_id: str, user: dict = Depends(verify_jwt),
):
    """Get SCA policies and their pass/fail summary for an agent."""
    _verify_agent_access(agent_id, user)
    wazuh = _get_wazuh_for_user(user)
    policies = wazuh.get_sca_list(agent_id)
    return {"policies": policies, "total": len(policies)}


@router.get("/api/agents/{agent_id}/sca/{policy_id}")
async def get_compliance_checks(
    agent_id: str, policy_id: str,
    result_filter: Optional[str] = None,
    limit: int = Query(200, ge=1, le=500),
    user: dict = Depends(verify_jwt),
):
    """Get individual SCA check results for a policy."""
    _verify_agent_access(agent_id, user)
    wazuh = _get_wazuh_for_user(user)
    checks = wazuh.get_sca_checks(
        agent_id, policy_id, result_filter=result_filter, limit=limit
    )
    return {"checks": checks, "total": len(checks)}


# ---------------------------------------------------------------------------
# Host Integrity (M6) — FIM / rootcheck / registry / groups (read-only)
#
# All four endpoints are paid (license feature "host_integrity"). The three
# agent-scoped endpoints enforce the non-negotiable tenant-isolation chain:
#   require_role(analyst+)  → require_license_feature → _verify_agent_access
#   (fail-closed 404 BEFORE any Wazuh egress) → _get_wazuh_for_user (tenant
#   resolved solely from _tenant_ctx, never the JWT client_id).
# The groups endpoint is Manager-GLOBAL (a group list would leak other
# tenants' group names/membership), so it is a structural mssp_admin-only
# boundary with no per-tenant filtering.
# ---------------------------------------------------------------------------

@router.get("/api/agents/{agent_id}/syscheck")
async def get_agent_syscheck(
    agent_id: str,
    limit: int = Query(500, ge=1, le=2000),
    user: dict = Depends(require_role("analyst", "senior_analyst", "admin")),
    _feat: None = Depends(require_license_feature("host_integrity")),
):
    """Get FIM/syscheck results for an agent (analyst+, host_integrity)."""
    _verify_agent_access(agent_id, user)          # fail-closed 404 on cross-tenant
    wazuh = _get_wazuh_for_user(user)             # tenant strictly from _tenant_ctx
    data = wazuh.get_agent_syscheck(agent_id, limit=limit)
    return {"syscheck": data, "total": len(data)}


@router.get("/api/agents/{agent_id}/rootcheck")
async def get_agent_rootcheck(
    agent_id: str,
    limit: int = Query(500, ge=1, le=2000),
    user: dict = Depends(require_role("analyst", "senior_analyst", "admin")),
    _feat: None = Depends(require_license_feature("host_integrity")),
):
    """Get rootcheck (policy monitoring) results for an agent."""
    _verify_agent_access(agent_id, user)
    wazuh = _get_wazuh_for_user(user)
    data = wazuh.get_agent_rootcheck(agent_id, limit=limit)
    return {"rootcheck": data, "total": len(data)}


@router.get("/api/agents/{agent_id}/registry")
async def get_agent_registry(
    agent_id: str,
    limit: int = Query(500, ge=1, le=2000),
    user: dict = Depends(require_role("analyst", "senior_analyst", "admin")),
    _feat: None = Depends(require_license_feature("host_integrity")),
):
    """Get Windows registry FIM entries for an agent."""
    _verify_agent_access(agent_id, user)
    wazuh = _get_wazuh_for_user(user)
    data = wazuh.get_agent_registry(agent_id, limit=limit)
    return {"registry": data, "total": len(data)}


@router.get("/api/groups")
async def get_agent_groups(
    limit: int = Query(500, ge=1, le=2000),
    user: dict = Depends(require_role("mssp_admin")),
    _feat: None = Depends(require_license_feature("host_integrity")),
):
    """Get the Manager's agent group list (mssp_admin only — Manager-global).

    Wazuh groups are Manager-GLOBAL, so a group list would leak other
    tenants' group names/membership. This is a structural mssp_admin-only
    boundary with no per-tenant filtering.
    """
    wazuh = _get_wazuh_for_user(user)
    groups = wazuh.get_agent_groups(limit=limit)
    return {"groups": groups, "total": len(groups)}
