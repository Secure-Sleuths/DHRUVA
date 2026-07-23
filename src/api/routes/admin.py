"""Admin, user management, audit log, and workspace routes."""

import uuid
import structlog
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from src.api.auth import verify_jwt, require_admin, require_role, hash_password
from src.api.dependencies import get_db, get_config, get_license_info, get_enrichment, limiter
from src.api.feature_gates import require_user_quota, require_multi_tenant, get_license_tier_info
from src.database.tenant_crypto import encrypt_config, decrypt_config
from src.api.models import (
    CreateUserRequest, UpdateUserRequest, CreateTenantRequest,
    CreateAssetRequest, UpdateAssetRequest,
    CreateIdentityRequest, UpdateIdentityRequest,
    CreateLocalIOCRequest, UpdateDecisionCacheRequest,
)
from src.database.store import PlatformUser

router = APIRouter()
logger = structlog.get_logger(__name__)


def _recompute_multi_tenant_mode(db):
    """Recompute is_multi_tenant() from the current active tenant count.

    Called after tenant create/activate/deactivate to ensure multi-tenant
    protections enable dynamically without requiring a restart.
    """
    from src.database.store import set_multi_tenant_mode
    try:
        from src.api.dependencies import get_tenant_registry
        registry = get_tenant_registry()
        if registry:
            active = registry.get_active_tenant_ids()
            is_mt = len(active) > 1
            set_multi_tenant_mode(is_mt)
            logger.info("multi_tenant_mode_recomputed",
                        active_tenants=len(active),
                        multi_tenant=is_mt)
        else:
            # Fallback: count directly from DB
            tenants = db.get_all_tenants()
            active = [t for t in tenants if t.get("active")]
            is_mt = len(active) > 1
            set_multi_tenant_mode(is_mt)
        # N3 (re-audit): the startup RLS boot gate (WO-H12-followup) does NOT cover
        # this runtime flip. When multi-tenant mode turns on, verify RLS is actually
        # in effect; if not, alarm loudly + mark the backstop degraded (surfaced via
        # /api/health) instead of silently entering MT mode without the DB backstop.
        # We do NOT SystemExit here (would kill a live server) and keep MT mode on so
        # the app-layer isolation engages regardless.
        _recompute_rls_backstop_state(db, is_mt)
    except Exception as e:
        logger.warning("multi_tenant_mode_recompute_failed", error=str(e))


def _recompute_rls_backstop_state(db, is_mt: bool):
    """Set/clear the RLS-backstop-degraded flag for the current tenant mode."""
    from src.database.store import set_rls_backstop_degraded
    if not is_mt:
        set_rls_backstop_degraded(False)
        return
    try:
        active_ok, reason = db.verify_rls_active()
    except Exception as e:
        active_ok, reason = False, f"could not verify RLS: {e}"
    if active_ok:
        set_rls_backstop_degraded(False)
    else:
        logger.error("rls_backstop_inactive_at_runtime_multi_tenant_flip",
                     reason=reason)
        set_rls_backstop_degraded(True)


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------

@router.get("/api/admin/users")
@limiter.limit("30/minute")
async def list_users(
    request: Request,
    include_inactive: bool = False,
    user: dict = Depends(require_role("admin")),
):
    _db = get_db()
    users = _db.get_all_users(include_inactive=include_inactive)
    return {"users": users, "total": len(users)}


# Role hierarchy — defines which roles each actor can assign
_ASSIGNABLE_ROLES = {
    "mssp_admin": {"admin", "senior_analyst", "analyst", "read_only"},
    "admin": {"senior_analyst", "analyst", "read_only"},
}

_COMMUNITY_ASSIGNABLE_ROLES = {"analyst", "read_only"}


def _get_assignable_roles(actor_role: str) -> set[str]:
    """Return the roles an actor can assign under the current license."""
    allowed = set(_ASSIGNABLE_ROLES.get(actor_role, set()))
    lic = get_license_info()
    if lic and lic.tier == "community":
        return allowed & _COMMUNITY_ASSIGNABLE_ROLES
    return allowed


def _validate_role_assignment(actor_role: str, target_role: str):
    """Enforce role hierarchy: prevent privilege escalation."""
    allowed = _get_assignable_roles(actor_role)
    if target_role not in allowed:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Role '{actor_role}' cannot assign role '{target_role}'. "
                f"Allowed roles: {', '.join(sorted(allowed)) or 'none'}"
            ))


@router.post("/api/admin/users")
@limiter.limit("10/minute")
async def create_user(
    request: Request, body: CreateUserRequest,
    user: dict = Depends(require_role("admin")),
    _gate: None = Depends(require_user_quota()),
):
    _validate_role_assignment(user.get("role", ""), body.role)
    _db = get_db()
    # allow_unscoped=True: username is globally UNIQUE so the lookup is
    # unambiguous, and env-seeded admins may have no tenant in their JWT.
    existing = _db.get_user_by_username(body.username, allow_unscoped=True)
    if existing:
        raise HTTPException(status_code=409, detail="Username already exists")
    pw_hash, salt = hash_password(body.password)
    now = datetime.now(timezone.utc).isoformat()
    new_user = PlatformUser(
        id=str(uuid.uuid4()), username=body.username,
        password_hash=pw_hash, salt=salt,
        display_name=body.display_name or body.username,
        email=body.email, role=body.role, is_active=1,
        created_at=now, updated_at=now,
    )
    _db.save_user(new_user)
    actor = user.get("sub", "unknown")
    _db.log_audit(actor, "user_create", "user", new_user.id,
                  details={"username": body.username, "role": body.role},
                  ip_address=request.client.host if request.client else "")
    return {"status": "created", "user_id": new_user.id, "username": body.username}


@router.post("/api/admin/users/{user_id}")
@limiter.limit("10/minute")
async def update_user(
    request: Request, user_id: str, body: UpdateUserRequest,
    user: dict = Depends(require_role("admin")),
):
    _db = get_db()
    target = _db.get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    fields = {}
    if body.display_name is not None:
        fields["display_name"] = body.display_name
    if body.email is not None:
        fields["email"] = body.email
    if body.role is not None:
        _validate_role_assignment(user.get("role", ""), body.role)
        fields["role"] = body.role
    if body.is_active is not None:
        fields["is_active"] = 1 if body.is_active else 0
    if body.password is not None:
        pw_hash, salt = hash_password(body.password)
        fields["password_hash"] = pw_hash
        fields["salt"] = salt
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    _db.update_user(user_id, fields)
    actor = user.get("sub", "unknown")
    _db.log_audit(actor, "user_update", "user", user_id,
                  details={"changed": list(fields.keys()),
                           "target": target["username"]},
                  ip_address=request.client.host if request.client else "")
    return {"status": "updated", "user_id": user_id}


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

@router.get("/api/admin/audit-log")
@limiter.limit("30/minute")
async def get_full_audit_log(
    request: Request,
    actor: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = Query(200, ge=1, le=1000),
    user: dict = Depends(require_role("admin")),
):
    _db = get_db()
    entries = _db.get_audit_log(actor=actor, action=action, limit=limit)
    return {"entries": entries, "total": len(entries)}


@router.get("/api/my/audit-log")
async def get_my_audit_log(
    limit: int = Query(100, ge=1, le=500),
    user: dict = Depends(verify_jwt),
):
    _db = get_db()
    username = user.get("sub", "")
    entries = _db.get_audit_log(actor=username, limit=limit)
    return {"entries": entries, "total": len(entries)}


# ---------------------------------------------------------------------------
# Analyst workspace
# ---------------------------------------------------------------------------

@router.get("/api/my/workspace")
async def get_my_workspace(user: dict = Depends(verify_jwt)):
    _db = get_db()
    username = user.get("sub", "")
    assigned = _db.get_incidents(assigned_to=username, limit=50)
    assigned = [i for i in assigned
                if i.get("status") in ("open", "investigating")]
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    assigned.sort(key=lambda i: sev_order.get(i.get("severity", "low"), 9))

    stats = _db.get_analyst_stats(username, hours=24)

    since_8h = (datetime.now(timezone.utc) - timedelta(hours=8)).isoformat()
    recent = _db.get_incidents(limit=100)
    new_since = [i for i in recent if i.get("created_at", "") >= since_8h]
    resolved_since = [i for i in recent
                      if i.get("status") == "resolved"
                      and (i.get("resolved_at") or "") >= since_8h]

    return {
        "assigned_incidents": assigned,
        "stats": stats,
        "shift_summary": {
            "new_incidents": len(new_since),
            "resolved_incidents": len(resolved_since),
        },
    }


# ---------------------------------------------------------------------------
# System config (read-only, admin only)
# ---------------------------------------------------------------------------

@router.get("/api/admin/config")
@limiter.limit("20/minute")
async def get_system_config(request: Request, user: dict = Depends(require_role("admin"))):
    _config = get_config()
    if not _config:
        return {"config": {}}
    # Only expose operational tuning parameters — no infra details
    safe = {
        "auto_close_threshold": _config.get("agents", {}).get("triage", {}).get("auto_close_confidence_threshold", ""),
        "escalation_threshold": _config.get("agents", {}).get("triage", {}).get("escalation_confidence_threshold", ""),
        "poll_interval_seconds": _config.get("wazuh", {}).get("alerts", {}).get("poll_interval_seconds", ""),
        "grouping_window_minutes": _config.get("incidents", {}).get("grouping_window_minutes", ""),
        "notifications_enabled": _config.get("notifications", {}).get("enabled", False),
    }
    return {"config": safe}


# ---------------------------------------------------------------------------
# Anonymization mapping ledger (audit / correlation)
# ---------------------------------------------------------------------------

@router.get("/api/admin/anon-mappings")
@limiter.limit("20/minute")
async def list_anon_mappings(
    request: Request,
    field_type: Optional[str] = Query(None, description="Filter by type: HOST, INT-IP, USER, OWNER"),
    limit: int = Query(100, ge=1, le=500),
    user: dict = Depends(require_role("admin")),
):
    """List anonymization token ↔ original value mappings."""
    _db = get_db()
    mappings = _db.get_anon_mappings(field_type=field_type, limit=limit)
    return {"mappings": mappings, "total": len(mappings)}


@router.get("/api/admin/anon-mappings/lookup")
@limiter.limit("30/minute")
async def lookup_anon_mapping(
    request: Request,
    token: Optional[str] = Query(None, description="Anonymized token (e.g. HOST-3cd510c8)"),
    original: Optional[str] = Query(None, description="Original value (e.g. prod-db-01)"),
    user: dict = Depends(require_role("admin")),
):
    """Resolve an anonymized token to its original value, or vice versa."""
    if not token and not original:
        raise HTTPException(status_code=400, detail="Provide either 'token' or 'original'")
    _db = get_db()
    if token:
        result = _db.lookup_anon_token(token)
    else:
        result = _db.lookup_anon_original(original)
    if not result:
        raise HTTPException(status_code=404, detail="Mapping not found")
    return result


# ---------------------------------------------------------------------------
# License status
# ---------------------------------------------------------------------------

@router.get("/api/license/status")
async def get_license_status(user: dict = Depends(require_admin)):
    """Return license status for admin dashboard."""
    _license_info = get_license_info()
    if _license_info is None:
        return {"status": "unknown"}
    return {"status": "valid", **_license_info.to_dict()}


@router.get("/api/license/tier-info")
async def tier_info(user: dict = Depends(verify_jwt)):
    """Return tier info for dashboard tab visibility and feature gating."""
    return get_license_tier_info()


# ---------------------------------------------------------------------------
# Tenant management (mssp_admin only)
# ---------------------------------------------------------------------------

@router.get("/api/admin/tenants")
@limiter.limit("20/minute")
async def list_tenants(
    request: Request,
    user: dict = Depends(require_role("mssp_admin")),
):
    """List all tenants (mssp_admin only)."""
    _db = get_db()
    tenants = _db.get_all_tenants()
    # Strip encrypted config, return metadata only
    result = []
    for t in tenants:
        decrypted = decrypt_config(t.get("config_encrypted", ""))
        result.append({
            "id": t["id"],
            "name": t["name"],
            "slug": t["slug"],
            "active": bool(t.get("active", 1)),
            "created_at": t.get("created_at"),
            "updated_at": t.get("updated_at"),
            # Return config keys (not values) so admin knows what's configured
            "config_keys": list(decrypted.keys()) if decrypted else [],
            "has_wazuh": "wazuh" in decrypted,
            "has_claude": "claude" in decrypted,
            "has_notifications": "notifications" in decrypted,
        })
    return {"tenants": result}


@router.get("/api/admin/tenants/{tenant_id}")
@limiter.limit("20/minute")
async def get_tenant(
    request: Request,
    tenant_id: str,
    user: dict = Depends(require_role("mssp_admin")),
):
    """Get tenant detail with decrypted config (mssp_admin only)."""
    _db = get_db()
    tenant = _db.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    decrypted = decrypt_config(tenant.get("config_encrypted", ""))
    # Mask secrets in the response (show first 4 chars only)
    masked = _mask_secrets(decrypted)
    return {
        "id": tenant["id"],
        "name": tenant["name"],
        "slug": tenant["slug"],
        "active": bool(tenant.get("active", 1)),
        "config": masked,
        "created_at": tenant.get("created_at"),
        "updated_at": tenant.get("updated_at"),
    }


@router.post("/api/admin/tenants")
@limiter.limit("10/minute")
async def create_tenant(
    request: Request,
    body: CreateTenantRequest,
    user: dict = Depends(require_role("mssp_admin")),
    _gate: None = Depends(require_multi_tenant),
):
    """Create a new tenant (mssp_admin only)."""
    _db = get_db()

    name = body.name.strip()
    slug = body.slug
    config = body.config.model_dump(exclude_none=True)

    tenant_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    from psycopg import errors as _pg_errors
    try:
        _db.save_tenant({
            "id": tenant_id,
            "name": name,
            "slug": slug,
            "config_encrypted": encrypt_config(config),
            "active": 1,
            "created_at": now,
            "updated_at": now,
        })
    except _pg_errors.UniqueViolation as e:
        # UNIQUE-constraint violation on slug or name. Don't reveal which
        # tenant the conflict is with — just identify the offending field
        # so the operator can pick a different value. (The previous
        # behavior was INSERT OR REPLACE, which silently overwrote the
        # existing tenant's config — a real data-loss incident on 2026-05-07.)
        cname = (e.diag.constraint_name or "").lower()
        if "slug" in cname or "name" in cname:
            field = "slug" if "slug" in cname else "name"
            raise HTTPException(
                status_code=409,
                detail=f"A tenant with this {field} already exists. Choose a different {field}.")
        raise

    # Recompute multi-tenant mode — adding a second active tenant enables it
    _recompute_multi_tenant_mode(_db)

    actor = user.get("sub", "unknown")
    _db.log_audit(actor, "tenant_create", "tenant", tenant_id,
                  details={"name": name, "slug": slug},
                  ip_address=request.client.host if request.client else "")

    return {"status": "ok", "tenant_id": tenant_id, "name": name, "slug": slug}


@router.put("/api/admin/tenants/{tenant_id}")
@limiter.limit("10/minute")
async def update_tenant(
    request: Request, tenant_id: str,
    user: dict = Depends(require_role("mssp_admin")),
):
    """Update a tenant's config or status (mssp_admin only)."""
    _db = get_db()
    tenant = _db.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    updates = {}

    if "name" in body:
        # Strip and re-validate — Pydantic's min_length=1 lets " " through.
        new_name = (body["name"] or "").strip()
        if not new_name:
            raise HTTPException(status_code=400, detail="name cannot be empty or whitespace-only")
        if len(new_name) > 200:
            raise HTTPException(status_code=400, detail="name must be at most 200 characters")
        updates["name"] = new_name
    if "active" in body:
        updates["active"] = int(bool(body["active"]))
    if "config" in body:
        # Merge new config into existing (don't overwrite fields not provided)
        existing_config = decrypt_config(tenant.get("config_encrypted", ""))
        existing_config.update(body["config"])
        updates["config_encrypted"] = encrypt_config(existing_config)

    if updates:
        from psycopg import errors as _pg_errors
        try:
            _db.update_tenant(tenant_id, **updates)
        except _pg_errors.UniqueViolation as e:
            # Rename collision — admin tried to rename to a name another
            # tenant already has.
            cname = (e.diag.constraint_name or "").lower()
            if "name" in cname or "slug" in cname:
                field = "name" if "name" in cname else "slug"
                raise HTTPException(
                    status_code=409,
                    detail=f"A tenant with this {field} already exists. Choose a different {field}.")
            raise

    # Recompute multi-tenant mode if active status changed
    if "active" in body:
        _recompute_multi_tenant_mode(_db)

    # Reload tenant services if config changed (webhook secrets, LLM, etc.)
    if "config" in body:
        try:
            from src.api.dependencies import get_tenant_registry
            registry = get_tenant_registry()
            if registry:
                registry.reload_tenant(tenant_id)
        except Exception as e:
            logger.warning("tenant_registry_reload_failed",
                           tenant_id=tenant_id, error=str(e))

    actor = user.get("sub", "unknown")
    _db.log_audit(actor, "tenant_update", "tenant", tenant_id,
                  details={"fields_updated": list(body.keys())},
                  ip_address=request.client.host if request.client else "")

    return {"status": "ok", "tenant_id": tenant_id}


# ---------------------------------------------------------------------------
# Tenant-agent mapping management (shared Wazuh backend model)
# ---------------------------------------------------------------------------

@router.get("/api/admin/tenants/{tenant_id}/agents")
async def list_tenant_agents(
    tenant_id: str,
    user: dict = Depends(require_role("mssp_admin")),
):
    """List Wazuh agent IDs mapped to a tenant (mssp_admin only)."""
    _db = get_db()
    agents = _db.get_all_tenant_agents(tenant_id)
    return {"tenant_id": tenant_id, "agents": agents, "total": len(agents)}


@router.post("/api/admin/tenants/{tenant_id}/agents")
@limiter.limit("30/minute")
async def assign_tenant_agents(
    request: Request, tenant_id: str,
    user: dict = Depends(require_role("mssp_admin")),
):
    """Assign Wazuh agent IDs to a tenant (mssp_admin only).

    Body: {"agent_ids": ["001", "002", "003"]}
    Agent IDs must be numeric (Wazuh format).
    """
    _db = get_db()
    tenant = _db.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(404, "Tenant not found")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON body")

    agent_ids = body.get("agent_ids", [])
    if not isinstance(agent_ids, list) or not agent_ids:
        raise HTTPException(400, "agent_ids must be a non-empty list")

    import re as _re
    added = []
    conflicts = []
    for aid in agent_ids:
        aid = str(aid).strip()
        if not _re.match(r"^\d{1,5}$", aid):
            raise HTTPException(400, f"Invalid agent ID: {aid}. Must be 1-5 digits.")
        if _db.add_tenant_agent(tenant_id, aid):
            added.append(aid)
        else:
            conflicts.append(aid)

    if conflicts and not added:
        raise HTTPException(409, detail={
            "error": "All agents are already mapped to other tenants",
            "conflicts": conflicts,
        })

    actor = user.get("sub", "unknown")
    _db.log_audit(actor, "tenant_agents_assign", "tenant", tenant_id,
                  details={"assigned": added, "conflicts": conflicts},
                  ip_address=request.client.host if request.client else "")
    logger.info("tenant_agents_assigned",
                tenant_id=tenant_id, added=added, conflicts=conflicts, actor=actor)
    result = {"status": "ok", "tenant_id": tenant_id, "assigned": added}
    if conflicts:
        result["conflicts"] = conflicts
        result["message"] = f"{len(conflicts)} agent(s) already mapped to other tenants"
    return result


@router.delete("/api/admin/tenants/{tenant_id}/agents/{agent_id}")
async def remove_tenant_agent(
    tenant_id: str, agent_id: str,
    request: Request,
    user: dict = Depends(require_role("mssp_admin")),
):
    """Remove a Wazuh agent mapping from a tenant (mssp_admin only)."""
    _db = get_db()
    removed = _db.remove_tenant_agent(tenant_id, agent_id)
    if not removed:
        raise HTTPException(404, "Agent mapping not found")

    actor = user.get("sub", "unknown")
    _db.log_audit(actor, "tenant_agents_remove", "tenant", tenant_id,
                  details={"agent_id": agent_id},
                  ip_address=request.client.host if request.client else "")
    return {"status": "ok", "tenant_id": tenant_id, "removed": agent_id}


@router.get("/api/admin/governance/charter")
@limiter.limit("20/minute")
async def get_soc_charter(
    request: Request,
    user: dict = Depends(verify_jwt),
):
    """Get the SOC charter document."""
    import yaml
    from src.api.dependencies import get_config
    config = get_config()
    if not config:
        return {"charter": None}
    try:
        with open("config/governance/soc_charter.yaml") as f:
            data = yaml.safe_load(f) or {}
        return {"charter": data.get("charter", {})}
    except FileNotFoundError:
        return {"charter": None, "message": "SOC charter not configured"}


@router.get("/api/admin/governance/data-access")
@limiter.limit("20/minute")
async def get_data_access_policy(
    request: Request,
    user: dict = Depends(require_role("admin", "senior_analyst")),
):
    """Get the data access governance policy."""
    import yaml
    try:
        with open("config/governance/data_access_policy.yaml") as f:
            data = yaml.safe_load(f) or {}
        return data
    except FileNotFoundError:
        return {"error": "Data access policy not configured"}


# =========================================================================
# Settings Panel — Assets, Identities, Local IOCs
# =========================================================================

# -- Assets ---------------------------------------------------------------

@router.get("/api/admin/settings/assets")
@limiter.limit("30/minute")
async def list_assets(request: Request, user: dict = Depends(require_role("admin"))):
    _db = get_db()
    assets = _db.get_assets()
    return {"assets": assets}


@router.post("/api/admin/settings/assets/discover")
@limiter.limit("6/minute")
async def discover_assets(
    request: Request, user: dict = Depends(require_role("admin")),
):
    """WO-H51: seed asset context from the enrolled Wazuh agents.

    Reads the Wazuh Manager agent inventory (which DHRUVA already pulls and
    surfaces at /api/agents) and pre-fills an asset stub per host, so the
    operator classifies a KNOWN LIST instead of hand-transcribing hostnames —
    the friction that left asset context empty and every alert `asset_tier:
    unknown`.

    Safe by construction: it NEVER overwrites a tier/owner an analyst already
    set (see store.upsert_discovered_asset), and it never wipes the existing
    asset list if the Wazuh pull fails or returns nothing.
    """
    from src.api.routes.agents import _get_wazuh_for_user

    _db = get_db()
    try:
        wazuh = _get_wazuh_for_user(user)
        agents = wazuh.get_all_agents() or []
    except Exception as e:  # noqa: BLE001
        logger.warning("asset_discover_wazuh_unavailable", error=str(e))
        raise HTTPException(
            502, "Could not reach the Wazuh manager to list agents. The "
                 "existing asset list is unchanged.")

    if not agents:
        # Fail SAFE: a healthy manager with zero agents (or a silent empty
        # response) must not be treated as "clear the list" — we only ever
        # add/refresh, never delete, so this is already non-destructive.
        return {"status": "ok", "discovered": 0, "new": 0, "existing": 0}

    new = existing = 0
    for a in agents:
        hostname = a.get("name") or a.get("hostname")
        if not hostname or hostname == "000":  # 000 is the manager itself
            continue
        os_name = (a.get("os") or {}).get("name") if isinstance(a.get("os"), dict) else None
        inserted = _db.upsert_discovered_asset(
            hostname=hostname, ip=a.get("ip"), os_name=os_name)
        new += 1 if inserted else 0
        existing += 0 if inserted else 1

    # The AssetEnricher reloads assets from the DB on its own cycle (and via the
    # settings-panel reload path), so newly-seeded rows take effect without a
    # restart. No direct enricher handle here by design — the route only writes.

    actor = user.get("sub", "unknown")
    _db.log_audit(actor, "asset_discover", "asset", "-",
                  details={"discovered": new + existing, "new": new},
                  ip_address=request.client.host if request.client else "")
    logger.info("assets_discovered", new=new, existing=existing, actor=actor)
    return {"status": "ok", "discovered": new + existing,
            "new": new, "existing": existing}


@router.post("/api/admin/settings/assets")
@limiter.limit("30/minute")
async def create_asset(
    request: Request, body: CreateAssetRequest,
    user: dict = Depends(require_role("admin")),
):
    _db = get_db()
    asset_id = _db.save_asset(body.model_dump())
    actor = user.get("sub", "unknown")
    _db.log_audit(actor, "asset_create", "asset", asset_id,
                  details={"hostname": body.hostname},
                  ip_address=request.client.host if request.client else "")
    return {"status": "created", "asset_id": asset_id}


@router.put("/api/admin/settings/assets/{asset_id}")
@limiter.limit("30/minute")
async def update_asset(
    request: Request, asset_id: str,
    body: UpdateAssetRequest,
    user: dict = Depends(require_role("admin")),
):
    _db = get_db()
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(400, "No fields to update")
    _db.update_asset(asset_id, **updates)
    actor = user.get("sub", "unknown")
    _db.log_audit(actor, "asset_update", "asset", asset_id,
                  details={"fields": list(updates.keys())},
                  ip_address=request.client.host if request.client else "")
    return {"status": "updated"}


@router.delete("/api/admin/settings/assets/{asset_id}")
@limiter.limit("30/minute")
async def delete_asset(
    request: Request, asset_id: str,
    user: dict = Depends(require_role("admin")),
):
    _db = get_db()
    _db.delete_asset(asset_id)
    actor = user.get("sub", "unknown")
    _db.log_audit(actor, "asset_delete", "asset", asset_id,
                  ip_address=request.client.host if request.client else "")
    return {"status": "deleted"}


# ---------------------------------------------------------------------------
# Decision cache (WO-H57) — view / disable / edit / delete the persistent
# verdict cache. Senior-analyst-and-above (mssp_admin superuser bypasses).
# Every mutation is audit-logged; every read/write is tenant-scoped by the DAO.
# ---------------------------------------------------------------------------

@router.get("/api/admin/decision-cache")
@limiter.limit("30/minute")
async def list_decision_cache(
    request: Request,
    include_disabled: bool = True,
    limit: int = Query(500, ge=1, le=2000),
    user: dict = Depends(require_role("senior_analyst", "admin")),
):
    """List cached verdicts + a savings summary for the Decision Cache tab."""
    _db = get_db()
    entries = _db.decision_cache_list(
        limit=limit, include_disabled=include_disabled)
    summary = _db.decision_cache_summary()
    return {"entries": entries, "summary": summary}


@router.patch("/api/admin/decision-cache/{cache_id}")
@limiter.limit("30/minute")
async def update_decision_cache(
    request: Request, cache_id: str,
    body: UpdateDecisionCacheRequest,
    user: dict = Depends(require_role("senior_analyst", "admin")),
):
    """Disable (stop reuse), or edit the verdict/reasoning of a cached entry."""
    _db = get_db()
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(400, "No fields to update")
    ok = _db.decision_cache_update(cache_id, **updates)
    if not ok:
        raise HTTPException(404, "Cache entry not found or nothing to update")
    actor = user.get("sub", "unknown")
    _db.log_audit(actor, "decision_cache_update", "decision_cache", cache_id,
                  details={"fields": list(updates.keys())},
                  ip_address=request.client.host if request.client else "")
    return {"status": "updated"}


@router.delete("/api/admin/decision-cache/{cache_id}")
@limiter.limit("30/minute")
async def delete_decision_cache(
    request: Request, cache_id: str,
    user: dict = Depends(require_role("senior_analyst", "admin")),
):
    """Remove a cached entry — the next matching alert goes back to the LLM."""
    _db = get_db()
    _db.decision_cache_delete(cache_id)
    actor = user.get("sub", "unknown")
    _db.log_audit(actor, "decision_cache_delete", "decision_cache", cache_id,
                  ip_address=request.client.host if request.client else "")
    return {"status": "deleted"}


@router.post("/api/admin/decision-cache/purge")
@limiter.limit("6/minute")
async def purge_decision_cache(
    request: Request,
    scope: str = Query("expired", pattern="^(expired|all)$"),
    user: dict = Depends(require_role("senior_analyst", "admin")),
):
    """Bulk cleanup: drop expired entries (default) or clear the whole cache."""
    _db = get_db()
    removed = (_db.decision_cache_clear() if scope == "all"
               else _db.decision_cache_purge_expired())
    actor = user.get("sub", "unknown")
    _db.log_audit(actor, "decision_cache_purge", "decision_cache", scope,
                  details={"scope": scope, "removed": removed},
                  ip_address=request.client.host if request.client else "")
    return {"status": "purged", "scope": scope, "removed": removed}


# -- Identities -----------------------------------------------------------

@router.get("/api/admin/settings/identities")
@limiter.limit("30/minute")
async def list_identities(request: Request, user: dict = Depends(require_role("admin"))):
    _db = get_db()
    identities = _db.get_identities()
    return {"identities": identities}


@router.post("/api/admin/settings/identities")
@limiter.limit("30/minute")
async def create_identity(
    request: Request, body: CreateIdentityRequest,
    user: dict = Depends(require_role("admin")),
):
    _db = get_db()
    identity_id = _db.save_identity(body.model_dump())
    actor = user.get("sub", "unknown")
    _db.log_audit(actor, "identity_create", "identity", identity_id,
                  details={"username": body.username},
                  ip_address=request.client.host if request.client else "")
    return {"status": "created", "identity_id": identity_id}


@router.put("/api/admin/settings/identities/{identity_id}")
@limiter.limit("30/minute")
async def update_identity(
    request: Request, identity_id: str,
    body: UpdateIdentityRequest,
    user: dict = Depends(require_role("admin")),
):
    _db = get_db()
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(400, "No fields to update")
    _db.update_identity(identity_id, **updates)
    actor = user.get("sub", "unknown")
    _db.log_audit(actor, "identity_update", "identity", identity_id,
                  details={"fields": list(updates.keys())},
                  ip_address=request.client.host if request.client else "")
    return {"status": "updated"}


@router.delete("/api/admin/settings/identities/{identity_id}")
@limiter.limit("30/minute")
async def delete_identity(
    request: Request, identity_id: str,
    user: dict = Depends(require_role("admin")),
):
    _db = get_db()
    _db.delete_identity(identity_id)
    actor = user.get("sub", "unknown")
    _db.log_audit(actor, "identity_delete", "identity", identity_id,
                  ip_address=request.client.host if request.client else "")
    return {"status": "deleted"}


# -- Local IOCs -----------------------------------------------------------

@router.get("/api/admin/settings/local-iocs")
@limiter.limit("30/minute")
async def list_local_iocs(
    request: Request,
    ioc_type: Optional[str] = None,
    user: dict = Depends(require_role("admin")),
):
    _db = get_db()
    iocs = _db.get_local_iocs(ioc_type=ioc_type)
    return {"iocs": iocs}


@router.post("/api/admin/settings/local-iocs")
@limiter.limit("30/minute")
async def create_local_ioc(
    request: Request, body: CreateLocalIOCRequest,
    user: dict = Depends(require_role("admin")),
):
    _db = get_db()
    ioc_id = _db.save_local_ioc(body.model_dump())
    actor = user.get("sub", "unknown")
    _db.log_audit(actor, "local_ioc_create", "local_ioc", ioc_id,
                  details={"ioc_type": body.ioc_type, "value": body.value},
                  ip_address=request.client.host if request.client else "")
    return {"status": "created", "ioc_id": ioc_id}


@router.delete("/api/admin/settings/local-iocs/{ioc_id}")
@limiter.limit("30/minute")
async def delete_local_ioc(
    request: Request, ioc_id: str,
    user: dict = Depends(require_role("admin")),
):
    _db = get_db()
    _db.delete_local_ioc(ioc_id)
    actor = user.get("sub", "unknown")
    _db.log_audit(actor, "local_ioc_delete", "local_ioc", ioc_id,
                  ip_address=request.client.host if request.client else "")
    return {"status": "deleted"}


# -- Enricher Reload ------------------------------------------------------

@router.post("/api/admin/settings/reload-enrichers")
@limiter.limit("5/minute")
async def reload_enrichers(
    request: Request,
    user: dict = Depends(require_role("admin")),
):
    enrichment_svc = get_enrichment()
    if not enrichment_svc:
        raise HTTPException(503, "Enrichment service not available")
    _db = get_db()
    counts = enrichment_svc.reload_enrichers(_db)
    actor = user.get("sub", "unknown")
    _db.log_audit(actor, "enrichers_reload", "system", "enrichers",
                  details=counts,
                  ip_address=request.client.host if request.client else "")
    return {"status": "ok", **counts}


# -- Diagnostics: backfill stale triage failures --------------------------
#
# When the v4.8.4 string-table patcher corrupted "LLMBackend", the triage
# agent ran with self.claude=None for every alert until the runtime
# monkey-patch (_dhruva_probe.py) was applied. Each failed triage saved
# the literal "Triage agent error: No LLM backend configured. Escalating
# for manual review." into agent_decisions.reasoning. Those rows are
# permanent — the dashboard's plain-summary "Refresh" button regenerates
# the summary view but pulls reasoning straight from the saved decision.
#
# These endpoints let an admin (a) count the affected rows and (b) rewrite
# the bad reasoning to a clear remediation note so the dashboard stops
# replaying the v4.8.4 error message.

_TRIAGE_FAILURE_MARKERS = (
    "No LLM backend configured",
    "Triage agent error: No LLM backend",
)
_REMEDIATED_REASONING = (
    "Triage was skipped during a v4.8.4 LLM-backend incident "
    "(remediated in v4.8.5). The original reasoning is unavailable. "
    "Use the manual retrigger if you need a fresh AI verdict."
)


@router.get("/api/admin/diagnostics/triage-failures")
@limiter.limit("10/minute")
async def count_triage_failures(
    request: Request,
    user: dict = Depends(require_role("admin")),
):
    """Count agent_decisions rows whose reasoning matches the v4.8.4
    LLM-backend failure marker. Read-only — does not modify any rows.
    """
    _db = get_db()
    conn = _db._get_conn()
    # Admin diagnostic: this deliberately scans agent_decisions across ALL
    # tenants (the v4.8.4 corruption was tenant-agnostic). Declare the intent
    # explicitly so the WO-H8 tenant backstop allows the unscoped read.
    with _db.cross_tenant():
        cur = conn.execute(
            "SELECT COUNT(*) AS cnt FROM agent_decisions "
            "WHERE reasoning LIKE %s OR reasoning LIKE %s",
            (f"%{_TRIAGE_FAILURE_MARKERS[0]}%",
             f"%{_TRIAGE_FAILURE_MARKERS[1]}%"),
        )
        count = cur.fetchone()["cnt"]

        sample_cur = conn.execute(
            "SELECT id, alert_id, rule_id, created_at, client_id "
            "FROM agent_decisions "
            "WHERE reasoning LIKE %s OR reasoning LIKE %s "
            "ORDER BY created_at DESC LIMIT 10",
            (f"%{_TRIAGE_FAILURE_MARKERS[0]}%",
             f"%{_TRIAGE_FAILURE_MARKERS[1]}%"),
        )
        sample = [dict(row) for row in sample_cur.fetchall()]

    return {
        "affected_count": count,
        "sample": sample,
        "remediation": (
            "POST /api/admin/diagnostics/triage-failures/clear to rewrite "
            "the reasoning field on all affected rows. Original reasoning "
            "cannot be recovered (it was the v4.8.4 corruption error string)."
        ),
    }


@router.post("/api/admin/diagnostics/triage-failures/clear")
@limiter.limit("2/minute")
async def clear_triage_failures(
    request: Request,
    user: dict = Depends(require_role("admin")),
):
    """Replace the v4.8.4 failure marker in agent_decisions.reasoning with
    a clear remediation note. Idempotent — re-running has no effect on
    rows already cleared.
    """
    _db = get_db()
    conn = _db._get_conn()
    # Admin repair across ALL tenants (tenant-agnostic v4.8.4 corruption) —
    # declared explicitly so the WO-H8 tenant backstop allows the unscoped write.
    with _db.cross_tenant():
        cur = conn.execute(
            "UPDATE agent_decisions SET reasoning = %s "
            "WHERE reasoning LIKE %s OR reasoning LIKE %s",
            (_REMEDIATED_REASONING,
             f"%{_TRIAGE_FAILURE_MARKERS[0]}%",
             f"%{_TRIAGE_FAILURE_MARKERS[1]}%"),
        )
        updated = cur.rowcount
        conn.commit()

    actor = user.get("sub", "unknown")
    _db.log_audit(actor, "triage_failures_cleared", "system",
                  "agent_decisions",
                  details={"rows_updated": updated},
                  ip_address=request.client.host if request.client else "")

    return {"rows_updated": updated, "remediation_text": _REMEDIATED_REASONING}


def _mask_secrets(config: dict) -> dict:
    """Mask secret values in config for API responses."""
    SECRET_KEYS = {"password", "api_key", "webhook_url", "smtp_password",
                   "secret", "token"}
    masked = {}
    for k, v in config.items():
        if isinstance(v, dict):
            masked[k] = _mask_secrets(v)
        elif isinstance(v, str) and any(sk in k.lower() for sk in SECRET_KEYS):
            masked[k] = v[:4] + "****" if len(v) > 4 else "****"
        else:
            masked[k] = v
    return masked
