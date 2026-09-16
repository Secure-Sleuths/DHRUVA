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
# WO-H132 — WHY THIS BUILDS FROM A STAGED COPY AND NOT FROM web/ IN PLACE
# ========================================================================
# The Next App Router routes on the DIRECTORY, so every page under web/src/app
# becomes a route in the static export whether or not git has ever heard of it.
# web/.gitignore line 42 ignores /src/app/shotharness — a screenshot-only dev
# harness — and on the working repo those pages exist on disk and are filled
# with realistic data. Measured: `next build` compiled them into
# out/_next/static/chunks/app/shotharness/h86/page-*.js, carrying a live
# client's hostname, and that export is staged into src/api/static/app and
# packaged by BOTH tarball lanes and the Docker image. A dev-only route is not
# a shipped route, and a git-ignored file is not project content.
#
# So the build runs against a tracked-files-only copy of web/. node_modules is
# not copied (npm ci recreates it from the tracked package-lock.json, which is
# what npm ci does anyway), so this costs nothing it was not already paying.
#
# Usage: bash scripts/build-web.sh
# Output: src/api/static/app/index.html (+ hashed _next assets)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
WEB_DIR="${PROJECT_DIR}/web"
SPA_DEST="${PROJECT_DIR}/src/api/static/app"

# shellcheck source=lib/tracked_copy.sh
source "${SCRIPT_DIR}/lib/tracked_copy.sh"

# Staged under DHRUVA_BUILD_DIR for the same reason the packagers are: /tmp is
# a 1.9 GB tmpfs on this build host and a node_modules tree does not always fit.
# mktemp, not a fixed name: the community and full tarballs are built
# back-to-back in CI and a shared staging path would have them racing.
STAGE_ROOT="${DHRUVA_BUILD_DIR:-/tmp}"; mkdir -p "${STAGE_ROOT}"
WEB_STAGE="$(mktemp -d -p "${STAGE_ROOT}" dhruva-web-build.XXXXXXXX)"
WEB_SRC="${WEB_STAGE}/web"
WEB_OUT="${WEB_SRC}/out"

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

echo "[0/3] Staging tracked web/ sources -> ${WEB_SRC} ..."
# node_modules under the stage is ~0.5 GB and DHRUVA_BUILD_DIR defaults to a
# 1.9 GB tmpfs. Reclaim it however this script exits.
trap 'rm -rf "${WEB_STAGE}"' EXIT
tracked_copy_skipped "${PROJECT_DIR}" web
tracked_copy "${PROJECT_DIR}" "${WEB_STAGE}" web

cd "${WEB_SRC}"

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
