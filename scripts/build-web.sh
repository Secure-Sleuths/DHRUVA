#!/usr/bin/env bash
# =============================================================================
# Build the redesigned Next.js SPA and stage it for the FastAPI backend.
#
# `main` carries the full SPA SOURCE under web/ (web/src, next.config.mjs with
# output: "export"). This script performs the missing build step: it runs
# `next build` (which emits a static export to web/out) and copies that export
# to src/api/static/app/ — the exact path frontend.py's spa_enabled() probes
# for index.html. No build artifacts are committed (Option 1: build at release
# time); .gitignore ignores both web/out/ and src/api/static/app/.
#
# Usage: bash scripts/build-web.sh
# Output: src/api/static/app/index.html (+ hashed _next assets)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
WEB_DIR="${PROJECT_DIR}/web"
WEB_OUT="${WEB_DIR}/out"
SPA_DEST="${PROJECT_DIR}/src/api/static/app"

echo "============================================================"
echo "  DHRUVA — Frontend SPA build (Next.js static export)"
echo "============================================================"

if ! command -v npm &>/dev/null; then
    echo "ERROR: npm is required to build the SPA (install Node 20+)."
    exit 1
fi

if [ ! -d "${WEB_DIR}" ]; then
    echo "ERROR: web/ source directory not found at ${WEB_DIR}."
    exit 1
fi

cd "${WEB_DIR}"

echo "[1/3] Installing web dependencies (npm ci)..."
npm ci

echo "[2/3] Building static export (next build -> web/out)..."
# Next 15.5 intermittently fails the FIRST build immediately after a clean
# `npm ci` with "Cannot find module 'styled-jsx/package.json'" during the
# page-data collection worker phase — a retry on the (now-warm) node_modules
# tree succeeds deterministically. Retry once before giving up so a release
# build never fails on this known flake.
if ! npm run build; then
    echo "[2/3] First build failed (known styled-jsx worker flake) — retrying once..."
    npm run build
fi

# next build with output: "export" writes the static site to web/out. Fail hard
# if it is missing — a silent-empty export must not slip through to packaging.
if [ ! -d "${WEB_OUT}" ] || [ ! -f "${WEB_OUT}/index.html" ]; then
    echo "ERROR: expected static export at ${WEB_OUT}/index.html — build did not produce it."
    exit 1
fi

echo "[3/3] Staging export -> src/api/static/app ..."
rm -rf "${SPA_DEST}"
mkdir -p "$(dirname "${SPA_DEST}")"
cp -r "${WEB_OUT}" "${SPA_DEST}"

# Post-condition: frontend.py's spa_enabled() keys off this exact file.
if [ ! -f "${SPA_DEST}/index.html" ]; then
    echo "ERROR: ${SPA_DEST}/index.html missing after copy — SPA staging failed."
    exit 1
fi

echo ""
echo "============================================================"
echo "  SPA built and staged: src/api/static/app/index.html"
echo "  spa_enabled() will now return true at runtime."
echo "============================================================"
