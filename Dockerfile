# =============================================================================
# SecureSleuths DHRUVA — Docker Image
# Compiles Python source to bytecode (.pyc) to reduce image size and
# discourage casual modification. NOTE: .pyc is obfuscation only — it
# can be decompiled. Do not rely on it for IP protection or integrity.
# Use signed releases and license verification for enforceable security.
# Config and guidance files are mounted as volumes at runtime.
# =============================================================================

# ── Stage 0: Build the SPA ───────────────────────────────────────────────────
# The redesigned Next.js dashboard SOURCE lives in web/; next.config.mjs uses
# output: "export" so `npm run build` emits a static site to web/out. That
# export is copied into the Python builder below (src/api/static/app) so
# frontend.py's spa_enabled() serves the SPA. No build artifact is committed —
# the image regenerates it at build time (Option 1: build at release time).
FROM node:20-slim AS web
WORKDIR /web
COPY web/ ./
RUN npm ci && npm run build
# Fail hard if the static export is missing — a silent-empty export must not
# slip through into the image.
RUN test -f /web/out/index.html

# ── Stage 1: Compile ─────────────────────────────────────────────────────────
FROM python:3.13-slim AS builder

WORKDIR /build
ARG BUILD_TIER=full

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Copy platform code (may be .py source, .pyc bytecode, or .so native binaries)
COPY main.py* .
COPY src/ src/

# Strip paid codepaths for Community images so the artifact only ships
# Community-safe modules and routes.
RUN if [ "$BUILD_TIER" = "community" ]; then \
      rm -rf \
        src/agents/detection_agent.py \
        src/agents/hunt_agent.py \
        src/agents/hunt_techniques \
        src/agents/query_agent.py \
        src/detection \
        src/feedback \
        src/soar \
        src/ticketing \
        src/reports \
        src/notifications \
        src/pipeline \
        src/ingestion \
        src/team \
        src/setup \
        src/threat_intel && \
      rm -f \
        src/api/routes/detection.py \
        src/api/routes/hunt.py \
        src/api/routes/query.py \
        src/api/routes/soar.py \
        src/api/routes/tickets.py \
        src/api/routes/sigma.py \
        src/api/routes/compliance.py \
        src/api/routes/feedback.py \
        src/api/routes/metrics.py \
        src/api/routes/llm_usage.py \
        src/api/routes/webhooks.py \
        src/api/routes/response.py \
        src/api/routes/shifts.py \
        src/api/routes/ti_strategic.py; \
    fi

# Stage the built SPA static export into the served location. Placed AFTER the
# tier-strip (which only removes paid *.py backend modules/routes, never the
# static app) and BEFORE compileall (which deletes only *.py, so the SPA's
# .html/.js/.css survive untouched). The Community image still ships this shell;
# paid *backend* is stripped and paid tabs gate/404 at runtime.
COPY --from=web /web/out ./src/api/static/app

# If source .py files exist, compile to .pyc and strip them
# (no-op if already pre-compiled by build-client-package.sh).
#
# EXCEPTION: src/database/migrations/versions/*.py — Alembic discovers
# migrations by scanning the versions/ directory for *.py files; with
# only *.pyc present, ScriptDirectory.walk_revisions() finds nothing
# and `alembic upgrade head` silently exits 0 without applying the
# schema (verified bug). Migrations are schema-as-code (no IP concern)
# so we ship them as plain .py. env.py in the same directory is also
# loaded as plain Python by Alembic and must remain unstripped.
RUN if find . -name "*.py" -not -name "__init__.py" | grep -q .; then \
        python -m compileall -b -f -q . 2>/dev/null; \
        find . -name "*.py" -not -name "__init__.py" \
             -not -path "./src/database/migrations/*" \
             -delete; \
        find . -name "__init__.py" -exec sh -c \
          'if [ -f "${1}c" ]; then rm "$1"; fi' _ {} \; ; \
    fi

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM python:3.13-slim
ARG BUILD_TIER=full
# Version single source of truth: passed in from the VERSION file at build time
# (`--build-arg DHRUVA_VERSION=$(cat VERSION)`). Also exported as ENV below so
# the compiled .pyc runtime resolves the version without the VERSION file.
# Default is deliberately EMPTY (not "unknown"): if a build forgets to pass it,
# src/__version__.py treats empty/"unknown" ENV as not-set and falls through to
# the COPY'd VERSION file, so the runtime version is still correct.
ARG DHRUVA_VERSION=

LABEL maintainer="SecureSleuths <info@securesleuths.in>"
LABEL description="DHRUVA — AI-Augmented Security Operations on Wazuh"
LABEL version="${DHRUVA_VERSION}"
LABEL org.securesleuths.tier="${BUILD_TIER}"

# Runtime dependencies only (openssl: self-signed dashboard cert at first start)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl openssl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r soc && useradd -r -g soc -d /opt/ai-soc -s /sbin/nologin soc

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy compiled platform (.pyc bytecode — obfuscation only, not security)
WORKDIR /opt/ai-soc
COPY --from=builder /build/main.pyc ./
COPY --from=builder /build/src/ src/
# alembic.ini lets operators run plain `alembic …` CLI commands from
# inside the container (status checks, manual revisions). Boot-time
# --migrate sets script_location programmatically and does NOT depend
# on this file being present.
COPY alembic.ini ./
# VERSION file — src/__version__.py reads it as a fallback when DHRUVA_VERSION
# env is unset. Cheap belt-and-suspenders alongside the ENV below.
COPY VERSION ./

# Copy scripts and entrypoint
COPY scripts/backfill_incidents.py scripts/
COPY docker-entrypoint.sh .

# Create directories for mounted volumes
RUN mkdir -p /opt/ai-soc/config/guidance/playbooks \
             /opt/ai-soc/data \
             /var/lib/ai-soc && \
    chown -R soc:soc /opt/ai-soc /var/lib/ai-soc

# Default config — will be overridden by volume mount
COPY config/ config/

EXPOSE 8443

# Health check — tries HTTPS first (production), falls back to HTTP (dev)
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -sfk https://localhost:8443/api/health 2>/dev/null || curl -sf http://localhost:8443/api/health || exit 1

USER soc

# Entry point auto-generates secrets if missing, then runs the platform
ENV DHRUVA_BUILD_PROFILE=${BUILD_TIER}
ENV DHRUVA_VERSION=${DHRUVA_VERSION}
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["config/config.yaml"]
