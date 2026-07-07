"""Authentication routes — login and logout."""

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from src.api.auth import (
    verify_jwt, create_token, verify_password, revoke_token,
    LoginRequest, TokenResponse,
)
from src.api.dependencies import get_db, get_platform_users, get_platform_roles, limiter

router = APIRouter(prefix="/api/auth")
security = HTTPBearer()
logger = structlog.get_logger(__name__)


# Brute-force control is a per-source-IP throttle (5/min) — correct for the
# current direct-Tailscale exposure. Deliberately NO hard per-username account
# lockout: it would let an attacker lock out legit users by spamming a username
# (lockout-DoS). (qa-audit F5.) OPERATIONAL NOTE: if a reverse proxy is ever
# fronted, run uvicorn with --proxy-headers + a trusted-hosts list, else every
# client collapses to the proxy IP and the throttle mis-fires.
@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
async def login(request: Request, body: LoginRequest):
    """Authenticate and receive a JWT token."""
    client_ip = request.client.host if request.client else ""
    _db = get_db()
    _platform_users = get_platform_users()
    _platform_roles = get_platform_roles()
    # Dummy hash for constant-time response when user not found (timing-safe)
    _DUMMY_HASH = "0" * 64
    _DUMMY_SALT = "0" * 64

    # DB-backed authentication
    if _db:
        user_row = _db.get_user_by_username(body.username, allow_unscoped=True)
        if user_row and user_row.get("is_active"):
            if verify_password(body.password, user_row["password_hash"],
                               user_row["salt"]):
                role = user_row["role"]
                client_id = user_row.get("client_id") or None
                tenant_name = None
                if client_id and _db:
                    tenant = _db.get_tenant(client_id)
                    if tenant:
                        tenant_name = tenant.get("name")
                token = create_token(body.username, role=role,
                                     client_id=client_id,
                                     tenant_name=tenant_name)
                _db.log_audit(body.username, "login", "user",
                              body.username, ip_address=client_ip)
                logger.info("login_success", username=body.username, role=role,
                            client_id=client_id or "none")
                return token
        else:
            # Constant-time: compute dummy hash even when user not found
            verify_password(body.password, _DUMMY_HASH, _DUMMY_SALT)
    # Fallback to in-memory users (backward compat during migration)
    stored = _platform_users.get(body.username)
    if stored:
        stored_hash, stored_salt = stored
        if stored_hash and verify_password(body.password, stored_hash, stored_salt):
            role = _platform_roles.get(body.username, "analyst")
            token = create_token(body.username, role=role)
            logger.info("login_success_legacy", username=body.username, role=role)
            return token
    else:
        # Constant-time in the in-memory-only path too (qa-audit F4): compute a
        # dummy hash when the username isn't found so a miss costs the same as a
        # hit and can't be used as a username-enumeration timing oracle.
        verify_password(body.password, _DUMMY_HASH, _DUMMY_SALT)
    logger.warning("login_failed", username=body.username, ip=client_ip)
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
    )


@router.post("/logout")
async def logout(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    user: dict = Depends(verify_jwt),
):
    """Revoke the current JWT token, preventing further use."""
    revoke_token(credentials.credentials)
    analyst = user.get("sub", "unknown")
    _db = get_db()
    if _db:
        client_ip = request.client.host if request.client else ""
        _db.log_audit(analyst, "logout", "user", analyst, ip_address=client_ip)
    logger.info("logout_success", username=analyst)
    return {"detail": "Token revoked successfully"}
