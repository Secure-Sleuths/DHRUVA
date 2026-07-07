"""Single source of truth for the DHRUVA version string.

Canonical value lives in the repo-root ``VERSION`` file (plaintext, no leading
``v``). This module exposes it as ``__version__`` for Python callers.

Resolution order (so it works in every shipping shape):
  1. ``DHRUVA_VERSION`` env var — stamped into the Docker image at build time,
     so the compiled ``.pyc`` runtime resolves a version even though the build
     context is stripped.
  2. The ``VERSION`` file next to the package root (source tarball) or COPY'd
     into the image.
  3. ``"unknown"`` fallback — never raises, so a missing file cannot crash boot.
"""

from __future__ import annotations

import os
from pathlib import Path


def _read() -> str:
    # Treat empty OR the literal "unknown" as "not set" so a Dockerfile/compose
    # build that forgot to pass DHRUVA_VERSION (ENV would be empty or "unknown")
    # falls through to the COPY'd VERSION file instead of reporting "unknown".
    env = os.environ.get("DHRUVA_VERSION", "").strip()
    if env and env.lower() != "unknown":
        return env
    for base in (Path(__file__).resolve().parent.parent, Path.cwd()):
        vf = base / "VERSION"
        try:
            if vf.exists():
                text = vf.read_text().strip()
                if text:
                    return text
        except OSError:
            pass
    return "unknown"


__version__ = _read()
