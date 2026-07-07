#!/usr/bin/env bash
# =============================================================================
# SecureSleuths DHRUVA — Upgrade Script
#
# Upgrades the platform to a new version without losing any customer data.
#
# What is PRESERVED (never touched):
#   - /var/lib/ai-soc/          (database, assets, identities, IOCs)
#   - .env                      (credentials, API keys, JWT secret)
#   - license.key               (customer license)
#   - config/config.yaml        (customer configuration)
#   - config/guidance/          (customized playbooks, risk criteria)
#
# What is REPLACED (code only):
#   - src/                      (compiled platform code)
#   - main.py / main.pyc        (entry point)
#   - requirements.txt          (dependencies)
#   - Dockerfile, docker-compose.yml
#   - scripts/                  (install/build scripts)
#
# Usage:
#   bash upgrade.sh /path/to/securesleuths-ai-soc-NEW-VERSION.tar.gz
#
# The platform auto-applies database schema migrations on first startup
# after upgrade — no manual SQL is needed.
# =============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "  ${CYAN}[*]${NC} $*"; }
ok()      { echo -e "  ${GREEN}[+]${NC} $*"; }
warn()    { echo -e "  ${YELLOW}[!]${NC} $*"; }
fail()    { echo -e "  ${RED}[-]${NC} $*"; exit 1; }

# ── Arguments ───────────────────────────────────────────────────────────────

PACKAGE="${1:-}"
if [[ -z "$PACKAGE" || ! -f "$PACKAGE" ]]; then
    echo ""
    echo -e "${CYAN}${BOLD}SecureSleuths DHRUVA — Upgrade${NC}"
    echo ""
    echo "Usage: bash upgrade.sh <path-to-new-package.tar.gz>"
    echo ""
    echo "Example:"
    echo "  bash upgrade.sh securesleuths-ai-soc-1.20.8.tar.gz"
    echo ""
    exit 1
fi

# ── Detect install directory ────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DATA_DIR="/var/lib/ai-soc"
SERVICE_NAME="ai-soc"
BACKUP_DIR="${DATA_DIR}/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo ""
echo -e "${CYAN}${BOLD}  ┌─────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}${BOLD}  │       SecureSleuths DHRUVA                       │${NC}"
echo -e "${CYAN}${BOLD}  │       Upgrade Script                             │${NC}"
echo -e "${CYAN}${BOLD}  └─────────────────────────────────────────────────┘${NC}"
echo ""

# ── Pre-flight checks ──────────────────────────────────────────────────────

info "Install directory: ${INSTALL_DIR}"
info "Data directory:    ${DATA_DIR}"
info "Package:           ${PACKAGE}"

# Check install dir looks like our platform
if [[ ! -f "${INSTALL_DIR}/config/config.yaml" ]]; then
    fail "Cannot find config/config.yaml in ${INSTALL_DIR}. Are you running this from the platform directory?"
fi

# Get current version. Use `|| true` so a missing `version:` line in a
# thin operator overlay doesn't trip `set -euo pipefail` — pipefail
# propagates grep's exit=1 (no match) through the pipeline and aborts
# the whole upgrade. Reported by cheersin install 2026-05-13.
CURRENT_VERSION="unknown"
if [[ -f "${INSTALL_DIR}/config/config.yaml" ]]; then
    PARSED=$(grep 'version:' "${INSTALL_DIR}/config/config.yaml" 2>/dev/null | head -1 | sed 's/.*"\(.*\)".*/\1/' || true)
    [ -n "$PARSED" ] && CURRENT_VERSION="$PARSED"
fi
info "Current version:   ${CURRENT_VERSION}"

# ── Step 1: Stop the service ───────────────────────────────────────────────

echo ""
echo -e "${GREEN}${BOLD}[STEP 1/6]${NC} ${BOLD}Stopping platform${NC}"
echo -e "${GREEN}$(printf '%.0s─' {1..50})${NC}"

if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    info "Stopping ${SERVICE_NAME} service..."
    sudo systemctl stop "$SERVICE_NAME"
    ok "Service stopped"
elif systemctl is-active --quiet "${SERVICE_NAME}-platform" 2>/dev/null; then
    SERVICE_NAME="${SERVICE_NAME}-platform"
    info "Stopping ${SERVICE_NAME} service..."
    sudo systemctl stop "$SERVICE_NAME"
    ok "Service stopped"
else
    warn "Service not running (or not installed as systemd). Continuing..."
fi

# ── Step 2: Backup ─────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}${BOLD}[STEP 2/6]${NC} ${BOLD}Backing up data${NC}"
echo -e "${GREEN}$(printf '%.0s─' {1..50})${NC}"

mkdir -p "${BACKUP_DIR}"
BACKUP_FILE="${BACKUP_DIR}/pre-upgrade_${CURRENT_VERSION}_${TIMESTAMP}.tar.gz"

# Backup database
#
# Legacy SQLite layout (pre-v4.9.0): a single ai-soc.db file in DATA_DIR.
# v4.9.0+ uses Postgres — there is no file to copy. Operators on Postgres
# must take a pg_dump out-of-band (`pg_dump -Fc dhruva > backup.dump`)
# before invoking upgrade.sh; that's documented in MIGRATION-FROM-SQLITE.md.
if [[ -f "${DATA_DIR}/ai-soc.db" ]]; then
    cp "${DATA_DIR}/ai-soc.db" "${DATA_DIR}/ai-soc.db.pre-upgrade-${TIMESTAMP}"
    warn "Legacy SQLite file found — v4.9.0 retired SQLite. Backed up;"
    warn "see docs/MIGRATION-FROM-SQLITE.md for the one-time conversion."
fi

# Backup config + env + license (Postgres backups handled out-of-band)
tar czf "$BACKUP_FILE" \
    -C "${INSTALL_DIR}" \
    config/config.yaml \
    .env \
    $(test -f "${INSTALL_DIR}/license.key" && echo "license.key") \
    -C "${DATA_DIR}" \
    $(test -f "${DATA_DIR}/ai-soc.db" && echo "ai-soc.db") \
    $(test -f "${DATA_DIR}/assets.yaml" && echo "assets.yaml") \
    $(test -f "${DATA_DIR}/identities.yaml" && echo "identities.yaml") \
    $(test -f "${DATA_DIR}/local_iocs.yaml" && echo "local_iocs.yaml") \
    2>/dev/null || true

ok "Backup saved: ${BACKUP_FILE}"
info "To restore if needed: tar xzf ${BACKUP_FILE}"

# ── Step 3: Extract new code ──────────────────────────────────────────────

echo ""
echo -e "${GREEN}${BOLD}[STEP 3/6]${NC} ${BOLD}Extracting new version${NC}"
echo -e "${GREEN}$(printf '%.0s─' {1..50})${NC}"

# Extract to temp directory first
TEMP_DIR=$(mktemp -d)
tar xzf "$PACKAGE" -C "$TEMP_DIR"

# Find the extracted directory (could be nested)
NEW_DIR=$(find "$TEMP_DIR" -maxdepth 1 -type d ! -name "$(basename $TEMP_DIR)" | head -1)
if [[ -z "$NEW_DIR" ]]; then
    NEW_DIR="$TEMP_DIR"
fi

# Get new version. Same `|| true` guard as CURRENT_VERSION above —
# in principle the new tarball always ships a version line, but the
# guard costs nothing and removes a class of upgrade-abort failures.
NEW_VERSION="unknown"
if [[ -f "${NEW_DIR}/config/config.yaml" ]]; then
    PARSED=$(grep 'version:' "${NEW_DIR}/config/config.yaml" 2>/dev/null | head -1 | sed 's/.*"\(.*\)".*/\1/' || true)
    [ -n "$PARSED" ] && NEW_VERSION="$PARSED"
fi
info "New version: ${NEW_VERSION}"

# ── Step 4: Replace code, preserve data ───────────────────────────────────

echo ""
echo -e "${GREEN}${BOLD}[STEP 4/6]${NC} ${BOLD}Upgrading code (preserving your data)${NC}"
echo -e "${GREEN}$(printf '%.0s─' {1..50})${NC}"

# Replace code directories
for dir in src scripts; do
    if [[ -d "${NEW_DIR}/${dir}" ]]; then
        rm -rf "${INSTALL_DIR}/${dir}"
        cp -r "${NEW_DIR}/${dir}" "${INSTALL_DIR}/${dir}"
        ok "Replaced ${dir}/"
    fi
done

# Replace single code files
for file in main.py main.pyc requirements.txt Dockerfile docker-compose.yml .dockerignore .env.template; do
    if [[ -f "${NEW_DIR}/${file}" ]]; then
        cp "${NEW_DIR}/${file}" "${INSTALL_DIR}/${file}"
        ok "Replaced ${file}"
    fi
done

# Orphan-entrypoint cleanup. When the shipping format changes between
# compiled (.pyc) and source (.py), the new tarball will only contain
# one of main.py / main.pyc — the OTHER one stays on disk as a stale
# entrypoint that can confuse operators and future upgrades. Rename
# (don't delete) so the file is recoverable for one upgrade cycle.
# Reported by cheersin install 2026-05-13 transitioning compiled→source.
if [[ -f "${NEW_DIR}/main.py" && ! -f "${NEW_DIR}/main.pyc" && -f "${INSTALL_DIR}/main.pyc" ]]; then
    mv "${INSTALL_DIR}/main.pyc" "${INSTALL_DIR}/main.pyc.orphan-${TIMESTAMP}"
    ok "Quarantined orphan main.pyc (compiled→source transition)"
fi
if [[ -f "${NEW_DIR}/main.pyc" && ! -f "${NEW_DIR}/main.py" && -f "${INSTALL_DIR}/main.py" ]]; then
    mv "${INSTALL_DIR}/main.py" "${INSTALL_DIR}/main.py.orphan-${TIMESTAMP}"
    ok "Quarantined orphan main.py (source→compiled transition)"
fi

# Replace static assets (dashboard HTML, logo)
if [[ -d "${NEW_DIR}/src/api/static" ]]; then
    ok "Dashboard UI updated"
fi

# Merge config: add new sections from new config without overwriting existing values.
#
# SKIP this entirely when config.enc is present. In the encrypted-base
# deployment model, config/config.yaml is a THIN OVERLAY that is deep-merged
# on top of the decrypted config.enc — it intentionally holds only the
# operator's customised keys. Appending the new release's full template
# config.yaml to that overlay makes the template defaults shadow the real
# base config on every key (new config keys are covered by code defaults,
# not by this merge). Reported by cheersin upgrade 2026-05-20, where a
# 2-section overlay ballooned to 21 sections and would have masked the
# real LLM/agent/pipeline config.
if [[ -f "${INSTALL_DIR}/config/config.enc" ]]; then
    info "Encrypted base config (config.enc) present — config.yaml is a thin overlay; skipping section merge"
elif [[ -f "${NEW_DIR}/config/config.yaml" ]]; then
    info "Checking for new config sections..."
    # Check for new top-level sections in new config that don't exist in customer config
    NEW_SECTIONS=$(grep -E '^[a-z]' "${NEW_DIR}/config/config.yaml" | sed 's/:.*//' | sort)
    EXISTING_SECTIONS=$(grep -E '^[a-z]' "${INSTALL_DIR}/config/config.yaml" | sed 's/:.*//' | sort)

    for section in $NEW_SECTIONS; do
        if ! echo "$EXISTING_SECTIONS" | grep -qw "$section"; then
            warn "New config section '${section}' found — adding with defaults"
            echo "" >> "${INSTALL_DIR}/config/config.yaml"
            # Extract the section from new config
            sed -n "/^${section}:/,/^[a-z]/{ /^[a-z]/!p; /^${section}:/p; }" \
                "${NEW_DIR}/config/config.yaml" >> "${INSTALL_DIR}/config/config.yaml"
        fi
    done
    ok "Config preserved (new sections added if any)"
fi

# Update guidance files only if customer hasn't modified them
for guidance_file in "${NEW_DIR}"/config/guidance/*.yaml; do
    if [[ ! -f "$guidance_file" ]]; then continue; fi
    base=$(basename "$guidance_file")
    existing="${INSTALL_DIR}/config/guidance/${base}"
    if [[ ! -f "$existing" ]]; then
        # New guidance file — add it
        cp "$guidance_file" "$existing"
        ok "Added new guidance file: ${base}"
    fi
done

# Add new playbooks (don't overwrite existing ones)
if [[ -d "${NEW_DIR}/config/guidance/playbooks" ]]; then
    for pb in "${NEW_DIR}"/config/guidance/playbooks/*.yaml; do
        base=$(basename "$pb")
        if [[ ! -f "${INSTALL_DIR}/config/guidance/playbooks/${base}" ]]; then
            cp "$pb" "${INSTALL_DIR}/config/guidance/playbooks/${base}"
            ok "Added new playbook: ${base}"
        fi
    done
fi

# Update version in config.yaml
if [[ "$NEW_VERSION" != "unknown" ]]; then
    sed -i "s/version: \".*\"/version: \"${NEW_VERSION}\"/" "${INSTALL_DIR}/config/config.yaml"
    ok "Version updated to ${NEW_VERSION}"
fi

# ── Step 5: Update dependencies ───────────────────────────────────────────

echo ""
echo -e "${GREEN}${BOLD}[STEP 5/6]${NC} ${BOLD}Updating dependencies${NC}"
echo -e "${GREEN}$(printf '%.0s─' {1..50})${NC}"

if [[ -d "${INSTALL_DIR}/venv" ]]; then
    info "Updating Python packages..."
    "${INSTALL_DIR}/venv/bin/pip" install -q -r "${INSTALL_DIR}/requirements.txt" 2>/dev/null
    ok "Dependencies updated"
else
    warn "No venv found — skip dependency update (Docker deployment?)"
fi

# ── Step 6: Restart ───────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}${BOLD}[STEP 6/6]${NC} ${BOLD}Starting upgraded platform${NC}"
echo -e "${GREEN}$(printf '%.0s─' {1..50})${NC}"

# Clean up temp
rm -rf "$TEMP_DIR"

# Apply any new Alembic migrations before starting the service. The boot
# gate in SOCDatabase._verify_schema refuses to start if schema is missing,
# so this must precede `systemctl start`.
if [[ -f "${INSTALL_DIR}/.env" ]]; then
    info "Applying database migrations (alembic upgrade head)..."
    if (set -a; source "${INSTALL_DIR}/.env"; set +a; \
        "${INSTALL_DIR}/venv/bin/python" "${INSTALL_DIR}/main.py" --migrate); then
        ok "Schema up to date"
    else
        fail "alembic upgrade failed — aborting restart. Check DATABASE_URL and Postgres reachability."
    fi
fi

if systemctl list-unit-files | grep -q "${SERVICE_NAME}"; then
    sudo systemctl start "$SERVICE_NAME"
    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        ok "Platform started successfully"
    else
        fail "Platform failed to start. Check: sudo journalctl -u ${SERVICE_NAME} -n 50"
    fi
else
    ok "Code upgraded. Start manually: source venv/bin/activate && python main.py config/config.yaml"
fi

# ── Summary ───────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}${BOLD}  ┌─────────────────────────────────────────────────┐${NC}"
echo -e "${GREEN}${BOLD}  │              Upgrade Complete                    │${NC}"
echo -e "${GREEN}${BOLD}  └─────────────────────────────────────────────────┘${NC}"
echo ""
echo -e "  ${CYAN}Previous version:${NC}  ${CURRENT_VERSION}"
echo -e "  ${CYAN}New version:${NC}       ${NEW_VERSION}"
echo -e "  ${CYAN}Backup:${NC}            ${BACKUP_FILE}"
echo ""
echo -e "  ${CYAN}Your data is intact:${NC}"
echo -e "    Database:      ${DATA_DIR}/ai-soc.db"
echo -e "    Assets:        ${DATA_DIR}/assets.yaml"
echo -e "    Identities:    ${DATA_DIR}/identities.yaml"
echo -e "    Config:        ${INSTALL_DIR}/config/config.yaml"
echo -e "    Credentials:   ${INSTALL_DIR}/.env"
echo -e "    License:       ${INSTALL_DIR}/license.key"
echo ""
echo -e "  ${CYAN}Check logs:${NC}        sudo journalctl -u ${SERVICE_NAME} -f"
echo -e "  ${CYAN}Dashboard:${NC}         http://localhost:8443"
echo ""
echo -e "  ${YELLOW}If anything goes wrong:${NC}"
echo -e "    1. Stop:    sudo systemctl stop ${SERVICE_NAME}"
echo -e "    2. Restore: cp ${DATA_DIR}/ai-soc.db.pre-upgrade-${TIMESTAMP} ${DATA_DIR}/ai-soc.db"
echo -e "    3. Start:   sudo systemctl start ${SERVICE_NAME}"
echo ""
