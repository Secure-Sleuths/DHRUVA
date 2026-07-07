"""
Authentication module for the DHRUVA API.
Implements JWT-based authentication with secure defaults.
"""

import hashlib
import os as _os
import secrets
import structlog
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

logger = structlog.get_logger(__name__)

# Use PyJWT (not python-jose which has CVE-2024-33664)
import jwt as pyjwt

security = HTTPBearer()

# Module-level config — set by init_auth()
_jwt_secret: str = ""
_token_expiry_hours: int = 8
_auth_enabled: bool = True
_revoked_hashes: set[str] = set()  # In-memory cache of revoked token hashes
_db = None  # SOCDatabase reference for persistent revocation


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


def init_auth(config: dict, db=None) -> None:
    """Initialize auth module from config. Called at startup."""
    global _jwt_secret, _token_expiry_hours, _auth_enabled, _db

    _db = db
    api_cfg = config.get("api", {})
    auth_cfg = api_cfg.get("auth", {})

    _auth_enabled = auth_cfg.get("enabled", True)
    _token_expiry_hours = auth_cfg.get("token_expiry_hours", 8)
    _jwt_secret = auth_cfg.get("jwt_secret", "")

    if not _auth_enabled:
        import os as _auth_os
        _dev_mode = _auth_os.environ.get("DEV_MODE", "").lower() in ("1", "true", "yes")
        _bind_host = api_cfg.get("host", "0.0.0.0")
        if _bind_host != "127.0.0.1" and not _dev_mode:
            raise RuntimeError(
                "FATAL: Authentication is disabled (api.auth.enabled=false) "
                "on a public bind address. Either:\n"
                "  1. Set api.auth.enabled=true (recommended)\n"
                "  2. Bind to 127.0.0.1 only (api.host=127.0.0.1)\n"
                "  3. Set DEV_MODE=true in .env (lab/dev environments only)"
            )
        logger.critical(
            "AUTH_DISABLED",
            message="Authentication is DISABLED (api.auth.enabled=false). "
                    "All routes are accessible without login. Anonymous users "
                    "get read_only access. This mode is for lab/dev environments "
                    "only — NEVER use in production.",
        )

    # Enforce secure JWT secret
    import re as _re
    _weak_patterns = _re.compile(
        r"(test|default|change|secret|example|placeholder|fixme|todo|dummy)",
        _re.IGNORECASE,
    )
    is_weak = (
        not _jwt_secret
        or len(_jwt_secret) < 32
        or _weak_patterns.search(_jwt_secret)
    )
    if _auth_enabled and is_weak:
        import sys
        # Generate a strong secret and persist it to .env
        generated = secrets.token_hex(32)
        _jwt_secret = generated

        env_path = __import__("pathlib").Path(__file__).parent.parent.parent / ".env"
        try:
            if env_path.exists():
                lines = env_path.read_text().splitlines()
                updated = False
                for i, line in enumerate(lines):
                    if line.startswith("JWT_SECRET="):
                        lines[i] = f"JWT_SECRET={generated}"
                        updated = True
                        break
                if not updated:
                    lines.append(f"JWT_SECRET={generated}")
                env_path.write_text("\n".join(lines) + "\n")
                logger.warning(
                    "jwt_secret_rotated",
                    message="Weak JWT_SECRET detected and auto-rotated. "
                            "New strong secret has been persisted to .env. "
                            "Restart is safe — the same secret will be loaded.",
                )
            else:
                logger.critical(
                    "jwt_secret_weak_no_env",
                    message="JWT_SECRET is weak/predictable and .env file not found. "
                            "Set a strong secret: python -c "
                            "\"import secrets; print(secrets.token_hex(32))\"",
                )
                sys.exit(1)
        except PermissionError:
            logger.critical(
                "jwt_secret_weak_cannot_persist",
                message="JWT_SECRET is weak and .env is not writable. "
                        "Refusing to start. Set JWT_SECRET manually.",
            )
            sys.exit(1)

    # Load persisted token revocations from DB (survives restarts)
    if _db is not None:
        try:
            _db.prune_expired_revocations()
            loaded = _db.load_revoked_tokens()
            _revoked_hashes.update(loaded)
            if loaded:
                logger.info("revoked_tokens_loaded", count=len(loaded))
        except Exception as e:
            logger.warning("revoked_tokens_load_failed", error=str(e))


def create_token(username: str, role: str = "analyst",
                 client_id: str = None,
                 tenant_name: str = None) -> TokenResponse:
    """Create a signed JWT token with optional tenant context."""
    now = datetime.now(timezone.utc)
    expiry = now + timedelta(hours=_token_expiry_hours)
    import uuid
    payload = {
        "sub": username,
        "role": role,
        "jti": str(uuid.uuid4()),
        "iat": int(now.timestamp()),
        "exp": int(expiry.timestamp()),
    }
    if client_id:
        payload["client_id"] = client_id
    if tenant_name:
        payload["tenant_name"] = tenant_name
    token = pyjwt.encode(payload, _jwt_secret, algorithm="HS256")
    return TokenResponse(
        access_token=token,
        expires_in=_token_expiry_hours * 3600,
    )


def _hash_token(token: str) -> str:
    """SHA-256 hash a token for safe storage in the revocation table."""
    return hashlib.sha256(token.encode()).hexdigest()


def revoke_token(token: str) -> None:
    """Add a token to the revocation blacklist (in-memory + DB).

    Tokens are stored as SHA-256 hashes, not raw JWTs.
    Persisted to Postgres so revocations survive process restarts.
    """
    token_hash = _hash_token(token)
    _revoked_hashes.add(token_hash)

    # Persist to DB with expiry for auto-pruning
    if _db is not None:
        try:
            payload = pyjwt.decode(token, _jwt_secret, algorithms=["HS256"])
            _db.revoke_token(token_hash, int(payload["exp"]))
        except Exception:
            import time
            fallback_exp = int(time.time()) + (_token_expiry_hours * 3600)
            _db.revoke_token(token_hash, fallback_exp)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token. Raises on failure."""
    if _hash_token(token) in _revoked_hashes:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
        )
    try:
        payload = pyjwt.decode(token, _jwt_secret, algorithms=["HS256"])
        return payload
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except pyjwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )


async def verify_jwt(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    """FastAPI dependency — verifies JWT and returns the decoded payload.
    Use as: Depends(verify_jwt) on any protected route.
    """
    if not _auth_enabled:
        return {"sub": "anonymous", "role": "read_only"}

    return decode_token(credentials.credentials)


async def require_admin(user: dict = Depends(verify_jwt)) -> dict:
    """FastAPI dependency — requires admin or mssp_admin role.

    When ``api.auth.enabled`` is ``false`` (lab/dev mode), the role check
    is bypassed: verify_jwt returns an anonymous read_only user, and
    forcing 403 here would make every action button in the dashboard
    fail with a misleading 'Admin access required' message.
    """
    if not _auth_enabled:
        return user
    if user.get("role") not in ("admin", "mssp_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user


# ─── Password Hashing (PBKDF2-SHA256, stdlib) ────────────────────

HASH_ITERATIONS = 260000  # OWASP 2023 recommendation

def hash_password(password: str) -> tuple[str, str]:
    """Hash a password with PBKDF2-SHA256. Returns (hash_hex, salt_hex)."""
    salt = _os.urandom(32)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, HASH_ITERATIONS
    )
    return pw_hash.hex(), salt.hex()

def verify_password(password: str, stored_hash: str, salt_hex: str) -> bool:
    """Verify a password against stored hash + salt."""
    salt = bytes.fromhex(salt_hex)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, HASH_ITERATIONS
    )
    return secrets.compare_digest(pw_hash.hex(), stored_hash)


# ─── Role-Based Access ───────────────────────────────────────────

def require_role(*roles: str):
    """Factory returning a FastAPI dependency that requires one of the given roles.

    Usage: Depends(require_role("admin", "senior_analyst"))

    DESIGN NOTES — read before adding analyst-only routes:

    * ``mssp_admin`` is intentionally a superuser role and passes EVERY
      ``require_role(...)`` check, even ones that don't list it. This is
      because MSSP admins manage tenants on behalf of customers and need
      full operational access. The bypass is logged so accidental
      privileged actions remain visible in the audit trail.

      If you ever need a role gate that mssp_admin must NOT pass (e.g.,
      a self-service analyst flow), do not call require_role — implement
      the explicit check inline so the intent is unambiguous.

    * When ``api.auth.enabled`` is ``false`` (lab/dev mode), all role
      checks are bypassed. verify_jwt returns an anonymous read_only
      user; without this bypass, every action button in the dashboard
      would fail with a misleading 403.
    """
    async def _check(user: dict = Depends(verify_jwt)) -> dict:
        if not _auth_enabled:
            return user
        # mssp_admin is a superuser role — passes all role checks
        if user.get("role") == "mssp_admin":
            logger.info("mssp_admin_role_bypass",
                        actor=user.get("sub"),
                        required_roles=roles)
            return user
        if user.get("role") not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of: {', '.join(roles)}",
            )
        return user
    return _check
