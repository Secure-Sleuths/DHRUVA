"""Frontend route — serves the analyst dashboard.

Two modes, chosen automatically:

* **Redesigned SPA (preferred):** if the Next.js app has been built and its
  static export copied to ``static/app/`` (``index.html`` present), FastAPI
  serves that single-page app at ``/`` and as a client-route fallback, with the
  hashed assets under ``/_next``. This is the monolith cutover — one service,
  one origin: the UI and the ``/api/*`` routes share the same host, so there is
  no CORS and no second server. Build with ``output: 'export'`` +
  ``trailingSlash: true`` (see ``web/next.config.mjs``).
* **Legacy dashboard (fallback):** when the SPA build is absent, the original
  vanilla-JS ``dashboard.html`` is served, so existing installs are unaffected.

``register_spa(app)`` must be called AFTER every API router is included so the
``/api/*`` routes take precedence over the SPA catch-all.
"""

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse

router = APIRouter()

_STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
_DASHBOARD_PATH = _STATIC_DIR / "dashboard.html"
_LOGO_PATH = _STATIC_DIR / "logo.png"
_APP_JS_PATH = _STATIC_DIR / "js" / "app.js"
_APP_CSS_PATH = _STATIC_DIR / "css" / "app.css"

# Redesigned SPA static export (web/out) is copied here by the deploy step.
_WEB_DIST = _STATIC_DIR / "app"
_WEB_INDEX = _WEB_DIST / "index.html"

_NO_CACHE = {
    "Cache-Control": "no-cache, no-store, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}


def spa_enabled() -> bool:
    """True when the redesigned SPA has been built into ``static/app/``."""
    return _WEB_INDEX.is_file()


def _resolve_spa_file(full_path: str) -> Path:
    """Map a request path to a file inside the SPA export, safely.

    Returns the exact file if it exists (assets like ``_next/...``), else the
    directory's ``index.html`` (trailingSlash export route, e.g.
    ``dashboard/index.html``), else the root ``index.html`` (client-side-routing
    fallback). Path traversal outside ``_WEB_DIST`` always falls back to the
    root index — a request can never escape the export dir.
    """
    base = _WEB_DIST.resolve()
    candidate = (_WEB_DIST / full_path).resolve()
    if not str(candidate).startswith(str(base) + "/") and candidate != base:
        return _WEB_INDEX
    if candidate.is_file():
        return candidate
    index = candidate / "index.html"
    if candidate.is_dir() and index.is_file():
        return index
    return _WEB_INDEX


@router.get("/")
async def serve_dashboard():
    """Serve the SPA shell if built, otherwise the legacy dashboard."""
    if spa_enabled():
        return FileResponse(str(_WEB_INDEX), media_type="text/html",
                            headers=_NO_CACHE)
    return FileResponse(
        str(_DASHBOARD_PATH), media_type="text/html", headers=_NO_CACHE,
    )


@router.get("/static/logo.png")
async def serve_logo():
    """Serve the platform logo."""
    return FileResponse(str(_LOGO_PATH), media_type="image/png")


@router.get("/static/js/app.js")
async def serve_app_js():
    """Serve the externalized legacy dashboard JavaScript."""
    return FileResponse(
        str(_APP_JS_PATH), media_type="application/javascript", headers=_NO_CACHE,
    )


@router.get("/static/css/app.css")
async def serve_app_css():
    """Serve the externalized legacy dashboard CSS."""
    return FileResponse(
        str(_APP_CSS_PATH), media_type="text/css", headers=_NO_CACHE,
    )


def register_spa(app) -> None:
    """Register the SPA client-route fallback on ``app``.

    MUST be called after all API routers are included: FastAPI matches routes in
    registration order, so ``/api/*`` (and every other real route) is resolved
    before this catch-all, which only serves the SPA's own assets/routes. No-op
    when the SPA build is absent (legacy dashboard stays in effect).
    """
    if not spa_enabled():
        return

    # Long-cache the immutable hashed SPA assets; index/html stays no-cache.
    @app.get("/{full_path:path}", include_in_schema=False)
    async def _spa_fallback(full_path: str):  # noqa: ANN001
        target = _resolve_spa_file(full_path)
        headers = None if target != _WEB_INDEX and "/_next/" in f"/{full_path}" \
            else _NO_CACHE
        return FileResponse(str(target), headers=headers)
