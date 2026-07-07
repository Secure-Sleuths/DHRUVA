"""
Tenant context middleware — extracts client_id from JWT and sets it
on the database instance for automatic query scoping.

mssp_admin can override tenant via X-Tenant-ID header (validated + audited).

Uses contextvars (via db.set_tenant) for proper per-request isolation
in async code — threading.local is NOT safe when multiple requests
share the same event-loop thread.
"""

import re
import time
import structlog
from collections import defaultdict
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from src.database.store import _tenant_ctx

logger = structlog.get_logger(__name__)

# Rate limiting for tenant overrides: max 10 switches per 60 seconds per user
_TENANT_SWITCH_WINDOW = 60
_TENANT_SWITCH_MAX = 10
_tenant_switch_log: dict = defaultdict(list)  # {username: [timestamps]}

# Tenant IDs are UUID4 strings (see admin.create_tenant). Reject any
# X-Tenant-ID header that doesn't match — prevents log injection via
# newlines/control characters and bounds the value before audit-logging.
_TENANT_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


class TenantContextMiddleware(BaseHTTPMiddleware):
    """Sets tenant context on DB for every authenticated request."""

    def __init__(self, app, db=None):
        super().__init__(app)
        self.db = db

    async def dispatch(self, request: Request, call_next):
        # Skip tenant context for unauthenticated paths
        path = request.url.path
        if path in ("/api/auth/login", "/api/health", "/health") or \
                path.startswith("/static") or path == "/" or \
                path.startswith("/api/webhooks/"):
            return await call_next(request)

        # Extract tenant from JWT (already decoded by auth layer)
        # The JWT payload is available after verify_jwt runs in the route
        # We set tenant from the Authorization header proactively
        tenant_id = None

        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            try:
                import jwt as pyjwt
                from src.api.auth import _jwt_secret
                payload = pyjwt.decode(token, _jwt_secret, algorithms=["HS256"])
                tenant_id = payload.get("client_id")

                # Only mssp_admin can override tenant via X-Tenant-ID
                override = request.headers.get("x-tenant-id")
                if override and not _TENANT_ID_RE.match(override):
                    # Header is present but malformed — drop it before
                    # log/audit emission so we don't propagate attacker-
                    # controlled bytes (newlines, control chars).
                    logger.warning("malformed_tenant_override_header",
                                   actor=payload.get("sub", "unknown"),
                                   header_length=len(override))
                    override = None
                if override and override != tenant_id:
                    if payload.get("role") != "mssp_admin":
                        logger.warning("unauthorized_tenant_override",
                                       actor=payload.get("sub", "unknown"),
                                       role=payload.get("role"),
                                       requested_tenant=override)
                        # Ignore the header — use JWT tenant
                        override = None

                if payload.get("role") == "mssp_admin" and override and override != tenant_id:
                    actor = payload.get("sub", "unknown")
                    ip_addr = request.client.host if request.client else ""

                    # Rate limit tenant switches — only count actual CHANGES
                    # (not repeated requests to the same override tenant)
                    now = time.monotonic()
                    last_override_key = f"_last_{actor}"
                    last_override = _tenant_switch_log.get(last_override_key)
                    is_new_switch = (last_override != override)

                    if is_new_switch:
                        switches = _tenant_switch_log[actor]
                        switches[:] = [t for t in switches if now - t < _TENANT_SWITCH_WINDOW]
                        if len(switches) >= _TENANT_SWITCH_MAX:
                            logger.warning("tenant_switch_rate_limited",
                                           actor=actor, ip=ip_addr,
                                           switches=len(switches))
                            from starlette.responses import JSONResponse
                            return JSONResponse(
                                status_code=429,
                                content={"detail": "Tenant switch rate limit exceeded. "
                                         "Try again later."}
                            )
                        else:
                            switches.append(now)
                        _tenant_switch_log[last_override_key] = override

                    if self.db:
                        tenant = self.db.get_tenant(override)
                        if tenant and tenant.get("active"):
                            if is_new_switch:
                                logger.info("tenant_override_applied",
                                            actor=actor,
                                            original_tenant=tenant_id,
                                            override_tenant=override,
                                            ip=ip_addr)
                                try:
                                    self.db.log_audit(
                                        actor, "tenant_override",
                                        "tenant", override,
                                        {"original": tenant_id, "override": override},
                                        ip_addr)
                                except Exception:
                                    pass
                            tenant_id = override
                        else:
                            logger.warning("invalid_tenant_override",
                                           requested=override, actor=actor)
            except Exception:
                pass  # Auth errors handled by route-level verify_jwt

        # Set tenant context via contextvars (token allows safe reset)
        token = _tenant_ctx.set(tenant_id)

        try:
            response = await call_next(request)
            return response
        finally:
            # Reset to previous value — safe even with concurrent requests
            _tenant_ctx.reset(token)
