"""Helpers for resolving the effective DHRUVA build profile."""

from __future__ import annotations

import os
from pathlib import Path


def resolve_build_profile(
    configured: str | None = None,
    *,
    license_path: str | None = None,
) -> str:
    """Resolve the runtime build profile.

    Supported profiles:
    - ``community``: Community-safe route/module surface only
    - ``full``: full route/module surface; license gates still apply
    - ``auto``: community when no license file exists, full otherwise
    """
    raw = (configured or os.environ.get("DHRUVA_BUILD_PROFILE", "full")).strip().lower()
    if raw not in {"auto", "community", "full"}:
        raw = "full"

    if raw == "auto":
        candidate = license_path or os.environ.get("LICENSE_FILE", "license.key")
        return "full" if candidate and Path(candidate).exists() else "community"

    return raw
