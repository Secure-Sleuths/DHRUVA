"""
Central FastAPI application — creates app, middleware, rate limiter,
and includes all route modules.
"""

import os
import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from starlette.datastructures import MutableHeaders

from src.api.auth import init_auth
from src.api.dependencies import limiter  # shared across all route modules
from src.build_profile import resolve_build_profile

logger = structlog.get_logger(__name__)
_BUILD_PROFILE = resolve_build_profile()
_COMMUNITY_BUILD = _BUILD_PROFILE == "community"

# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="SecureSleuths DHRUVA",
    description="AI-Augmented Security Operations Platform",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded. Try again later."},
    )


from fastapi.exceptions import RequestValidationError

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    """Return generic error in production to prevent data model disclosure."""
    import os
    if os.environ.get("DEV_MODE", "").lower() in ("1", "true", "yes"):
        # In Pydantic v2, exc.errors() entries contain a 'ctx' dict that may
        # hold an actual Exception object (e.g. the ValueError raised by a
        # field_validator). JSONResponse can't serialize Exception, so we
        # need exc.errors(include_url=False) plus stringify any ctx values.
        safe_errors = []
        for err in exc.errors():
            ctx = err.get("ctx") or {}
            safe_ctx = {k: (str(v) if isinstance(v, Exception) else v) for k, v in ctx.items()}
            safe_errors.append({**err, "ctx": safe_ctx} if ctx else err)
        return JSONResponse(status_code=422, content={"detail": safe_errors})
    return JSONResponse(status_code=422, content={"detail": "Invalid request body"})


from src.database.tenant_registry import TenantConfigUnavailable


@app.exception_handler(TenantConfigUnavailable)
async def tenant_config_unavailable_handler(
        request: Request, exc: TenantConfigUnavailable):
    """A tenant's config couldn't be decrypted — fail closed at the API edge.

    Surface a GENERIC 503 to the client (no internal detail leak) while the
    full context is logged server-side. Never falls through to global config.
    """
    logger.error("tenant_config_unavailable",
                 tenant_id=getattr(exc, "tenant_id", None),
                 path=request.url.path)
    return JSONResponse(
        status_code=503,
        content={"detail": "Service temporarily unavailable"},
    )


class _BodyTooLarge(Exception):
    """Internal signal raised when a streamed request exceeds the size cap."""


class RequestSizeLimitMiddleware:
    """Reject requests whose body exceeds 10 MB, even without Content-Length."""
    MAX_BODY_SIZE = 10 * 1024 * 1024  # 10 MB

    def __init__(self, app):
        self.app = app

    async def _reject(self, scope, receive, send):
        response = JSONResponse(
            status_code=413,
            content={"detail": "Request body too large (max 10 MB)"},
        )
        await response(scope, receive, send)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_length = None
        for key, value in scope.get("headers", []):
            if key == b"content-length":
                content_length = value
                break

        if content_length:
            try:
                if int(content_length) > self.MAX_BODY_SIZE:
                    await self._reject(scope, receive, send)
                    return
            except ValueError:
                pass

        body_size = 0
        response_started = False

        async def send_wrapper(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        async def limited_receive():
            nonlocal body_size
            message = await receive()
            if message["type"] == "http.request":
                body_size += len(message.get("body", b""))
                if body_size > self.MAX_BODY_SIZE:
                    raise _BodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send_wrapper)
        except _BodyTooLarge:
            if not response_started:
                await self._reject(scope, receive, send)


class SecurityHeadersMiddleware:
    """Add security headers to all responses (Fix H4)."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(raw=message.setdefault("headers", []))
                headers["X-Content-Type-Options"] = "nosniff"
                headers["X-Frame-Options"] = "DENY"
                headers["X-XSS-Protection"] = "1; mode=block"
                headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
                headers["Cache-Control"] = "no-store"
                headers["Strict-Transport-Security"] = (
                    "max-age=31536000; includeSubDomains"
                )
                # script-src carries 'unsafe-inline': the redesigned UI is a
                # Next.js App Router SPA served as a static export, which emits
                # nonce-less inline bootstrap/hydration scripts (the same
                # tradeoff declared in web/next.config.mjs). Without it the SPA
                # cannot hydrate at all. Hardening to a nonce-based policy needs
                # a per-request server (not static export) — tracked follow-up.
                # style-src keeps 'unsafe-inline' for inline style attributes.
                # No external origins: the SPA is fully self-contained (system
                # fonts, no CDN, same-origin /api only), so script/style/font/
                # connect are locked to 'self' — this shrinks any future-XSS
                # blast radius (qa-audit F1). NOTE: the legacy dashboard fallback
                # loaded chart.js + google-fonts from a CDN; if that fallback is
                # ever re-served, restore the CDN origins here.
                headers["Content-Security-Policy"] = (
                    "default-src 'self'; "
                    "script-src 'self' 'unsafe-inline'; "
                    "style-src 'self' 'unsafe-inline'; "
                    "font-src 'self' data:; "
                    "img-src 'self' data:; "
                    "connect-src 'self'; "
                    "frame-ancestors 'none'; "
                    "base-uri 'self'; "
                    "form-action 'self'"
                )
                if "server" in headers:
                    del headers["server"]
            await send(message)

        await self.app(scope, receive, send_wrapper)


# RequestSizeLimit is added FIRST so SecurityHeaders (added after) wraps it as
# the outer layer — this way even a 413 (request-too-large) response carries the
# security headers/CSP (qa-audit F2). Starlette runs the last-added middleware
# outermost.
app.add_middleware(RequestSizeLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)


# ---------------------------------------------------------------------------
# CORS configuration (called by init_api)
# ---------------------------------------------------------------------------
_cors_origins: list[str] = []


def _configure_cors(config: dict):
    """Configure CORS from config. Called at startup by init_api."""
    global _cors_origins
    api_cfg = config.get("api", {})
    _cors_origins = api_cfg.get("cors_origins", [])
    if not _cors_origins:
        _cors_origins = ["https://soc.securesleuths.local"]
        logger.warning("cors_origins_not_configured",
                       message="No cors_origins in config. Using default.")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Tenant-ID"],
    )


# ---------------------------------------------------------------------------
# Include all route modules — paid routes loaded conditionally
# ---------------------------------------------------------------------------
from src.api.routes.frontend import router as frontend_router
from src.api.routes.auth import router as auth_router
from src.api.routes.dashboard import router as dashboard_router
from src.api.routes.triage import router as triage_router
from src.api.routes.incidents import router as incidents_router
from src.api.routes.campaigns import router as campaigns_router
from src.api.routes.overview import router as overview_router
from src.api.routes.admin import router as admin_router
from src.api.routes.agents import router as agents_router
from src.api.routes.mitre import router as mitre_router
from src.api.routes.knowledge_base import router as kb_router
from src.api.routes.health import router as health_router
from src.api.routes.threat_intel import router as threat_intel_router

# Core routes (always available)
app.include_router(frontend_router)
app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(triage_router)
app.include_router(incidents_router)
app.include_router(campaigns_router)
app.include_router(overview_router)
app.include_router(admin_router)
app.include_router(agents_router)
app.include_router(mitre_router)
app.include_router(kb_router)
app.include_router(health_router)
app.include_router(threat_intel_router)

# Paid routes — only loaded if modules are present (stripped in Community build).
# Uses ModuleNotFoundError (not broad ImportError) so transitive dependency
# failures surface loudly instead of silently disabling routes.
_PAID_ROUTES = [
    "src.api.routes.detection",
    "src.api.routes.hunt",
    "src.api.routes.feedback",
    "src.api.routes.query",
    "src.api.routes.response",
    "src.api.routes.metrics",
    "src.api.routes.soar",
    "src.api.routes.sigma",
    "src.api.routes.compliance",
    "src.api.routes.llm_usage",
    "src.api.routes.webhooks",
    "src.api.routes.shifts",
    "src.api.routes.ti_strategic",
]
if not _COMMUNITY_BUILD:
    for _mod_path in _PAID_ROUTES:
        try:
            _mod = __import__(_mod_path, fromlist=["router"])
            app.include_router(_mod.router)
        except ModuleNotFoundError as _e:
            if _e.name and _e.name != _mod_path and not _mod_path.startswith(_e.name + "."):
                raise  # transitive dependency broken — surface the error
            pass

# Ticketing routes (has both router and webhook_router)
if not _COMMUNITY_BUILD:
    try:
        from src.api.routes.tickets import router as tickets_router
        from src.api.routes.tickets import webhook_router as tickets_webhook_router
        app.include_router(tickets_router)
        app.include_router(tickets_webhook_router)
    except ModuleNotFoundError as _e:
        if _e.name and not "src.api.routes.tickets".startswith(_e.name):
            raise
        pass

# Serve the redesigned SPA (web/ static export) if it was built into
# static/app/. Registered LAST so every /api/* router above takes precedence
# over the SPA client-route catch-all. No-op (legacy dashboard) when absent.
from src.api.routes.frontend import register_spa
register_spa(app)


# ---------------------------------------------------------------------------
# init_api — called by main.py at startup
# ---------------------------------------------------------------------------

def init_api(db, enrichment, triage_agent, detection_agent, feedback_engine,
             hunt_agent=None, query_agent=None, notifications=None,
             config: dict = None, license_info=None, ti_collector=None,
             sla_manager=None, metrics_calculator=None,
             soar_engine=None, mitre_analyzer=None,
             ticketing_service=None, knowledge_base=None,
             pipeline_monitor=None, alert_buffer=None, tenant_registry=None,
             incident_engine=None):
    """Initialize all dependencies and wire up the application."""
    import os
    from src.api import dependencies as deps

    # Register tenant context middleware
    from src.api.middleware import TenantContextMiddleware
    app.add_middleware(TenantContextMiddleware, db=db)

    deps._db = db
    deps._enrichment = enrichment
    deps._triage_agent = triage_agent
    deps._detection_agent = detection_agent
    deps._feedback_engine = feedback_engine
    deps._hunt_agent = hunt_agent
    deps._query_agent = query_agent
    deps._notifications = notifications
    deps._sla_manager = sla_manager
    deps._metrics_calculator = metrics_calculator
    deps._soar_engine = soar_engine
    deps._mitre_analyzer = mitre_analyzer
    deps._ticketing_service = ticketing_service
    deps._knowledge_base = knowledge_base
    deps._config = config
    deps._license_info = license_info
    deps._ti_collector = ti_collector
    deps._pipeline_monitor = pipeline_monitor
    deps._alert_buffer = alert_buffer
    deps._tenant_registry = tenant_registry

    # Initialize webhook system for real-time alert ingestion (optional module)
    if tenant_registry:
        try:
            from src.api.routes.webhooks import init_webhook_system
            init_webhook_system(
                db=db,
                enrichment_service=enrichment,
                tenant_registry=tenant_registry,
                triage_agent=triage_agent,
                incident_engine=incident_engine,
                config=config
            )
        except ModuleNotFoundError as e:
            if e.name and not "src.api.routes.webhooks".startswith(e.name):
                raise

    if config:
        init_auth(config, db=db)
        _configure_cors(config)
        # Load platform users from config or env
        users_cfg = config.get("api", {}).get("auth", {}).get("users", {})
        admin_user = os.getenv("SOC_ADMIN_USER", "admin")
        from src.api.auth import hash_password as _hash_pw
        _raw_users = users_cfg if users_cfg else {
            admin_user: os.getenv("SOC_ADMIN_PASSWORD", ""),
        }
        # Pre-hash plaintext passwords for in-memory auth (defense in depth)
        deps._platform_users = {}
        for _u, _p in _raw_users.items():
            if _p:
                _h, _s = _hash_pw(_p)
                deps._platform_users[_u] = (_h, _s)
            else:
                deps._platform_users[_u] = ("", "")
        # Role mapping: users from env get admin, config can specify roles
        roles_cfg = config.get("api", {}).get("auth", {}).get("roles", {})
        deps._platform_roles = roles_cfg if roles_cfg else {admin_user: "admin"}
        # Remove users with empty passwords from in-memory auth (defense in depth)
        empty_pw_users = [u for u, (h, s) in deps._platform_users.items() if not h]
        for u in empty_pw_users:
            del deps._platform_users[u]
            logger.error(
                "user_removed_empty_password",
                username=u,
                message=f"User '{u}' removed from in-memory auth: no password set. "
                        "Set SOC_ADMIN_PASSWORD in .env or configure api.auth.users in config.",
            )
