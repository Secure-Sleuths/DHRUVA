"""
API Server — backward-compatibility shim.

All logic has been moved to src/api/app.py and src/api/routes/.
This module re-exports `app` and `init_api` so that existing imports
(e.g. ``from src.api.server import app, init_api``) continue to work.
"""

from src.api.app import app, init_api  # noqa: F401

__all__ = ["app", "init_api"]
