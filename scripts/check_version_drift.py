#!/usr/bin/env python3
"""Guard: the version must be identical across every in-repo source of truth.

Canonical value = the repo-root ``VERSION`` file. This check fails CI if any of
the following disagree with it:

  * ``config/config.yaml`` ``platform.version`` (scripts/upgrade.sh greps this
    out of shipped tarballs, so it must track VERSION).
  * ``src/__version__.__version__`` (what the running platform reports).

Stdlib-only so it runs as a fast CI step without installing requirements.
Repointing every other consumer (main.py, ticketing UA, build scripts,
Dockerfile) to read from these means this three-way check covers the whole
surface.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def canonical() -> str:
    return (REPO / "VERSION").read_text().strip()


def config_version() -> str:
    text = (REPO / "config" / "config.yaml").read_text()
    m = re.search(r"^\s*version:\s*[\"']?([^\"'\s#]+)", text, re.MULTILINE)
    if not m:
        raise SystemExit("ERROR: no `version:` line found in config/config.yaml")
    return m.group(1)


def module_version() -> str:
    # Import without pulling the whole src package (stdlib-only module).
    sys.path.insert(0, str(REPO))
    from src.__version__ import __version__  # noqa: E402

    return __version__


def main() -> int:
    want = canonical()
    checks = {
        "VERSION": want,
        "config/config.yaml": config_version(),
        "src.__version__": module_version(),
    }
    bad = {k: v for k, v in checks.items() if v != want}
    if bad:
        print(f"VERSION DRIFT: canonical VERSION={want!r}, but:")
        for k, v in bad.items():
            print(f"  - {k} = {v!r}")
        print("Fix: update the VERSION file (single source of truth) and re-run.")
        return 1
    print(f"OK: version {want!r} consistent across VERSION, config.yaml, src.__version__.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
