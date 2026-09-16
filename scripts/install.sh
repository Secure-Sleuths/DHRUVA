#!/usr/bin/env bash
# =============================================================================
# SecureSleuths DHRUVA — Installer
#
# Installs DHRUVA as a systemd service.
# Works with both binary (PyInstaller) and Docker distributions.
#
# Usage:  sudo bash install.sh
# =============================================================================
set -euo pipefail

INSTALL_DIR="/opt/ai-soc-platform"
DATA_DIR="/var/lib/ai-soc"
SERVICE_NAME="ai-soc-platform"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[-]${NC} $*"; exit 1; }

ensure_env_var() {
    local file="$1"
    local key="$2"
    local value="$3"
    if grep -q "^${key}=" "$file"; then
        sed -i "s#^${key}=.*#${key}=${value}#" "$file"
    else
        printf "\n%s=%s\n" "$key" "$value" >> "$file"
    fi
}

# ensure_env_secret FILE KEY LABEL — generate a Fernet master key ONLY if the
# file has no non-empty value for KEY. Note .env.template ships KEY= with an
# EMPTY value, so "the line exists" is not "it is configured".
#
# WO-H75: writing a tenant config now fails closed without this key (the
# platform used to invent a per-process one and store rows nobody could ever
# decrypt). So a first boot through this installer needs a real key persisted
# here, or it comes up with no tenant at all.
#
# Never overwrites: rotating this makes EVERY stored tenant config
# undecryptable. Rotate deliberately with tools/rotate_tenant_key.py
# (docs/KEY-ROTATION.md).
ensure_env_secret() {
    local file="$1"
    local key="$2"
    local label="$3"

    # Duplicate-line guard (WO-H75). This probe is FIRST-wins (grep|head -n1),
    # ensure_env_var's `sed` rewrites EVERY matching line, and python-dotenv —
    # what the platform actually reads — is LAST-wins. A .env holding the
    # template's blank `KEY=` line PLUS an appended real value (our own docs
    # teach `cat >> .env`) would read as "unconfigured" and the generated
    # replacement would be stamped over the real key. Unrecoverable for a
    # master key, and this branch also runs on upgrades of a LIVE install — so
    # refuse and let a human say which line is live.
    local dupes=0
    dupes=$(grep -c "^${key}=" "$file" 2>/dev/null || true)
    if [[ "${dupes:-0}" -gt 1 ]]; then
        warn "${file} has ${dupes} lines starting with '${key}=' (lines: $(grep -n "^${key}=" "$file" | cut -d: -f1 | tr '\n' ' '))"
        warn "The platform reads the LAST one; this script would rewrite ALL of them,"
        warn "destroying the others. For ${label} that is not recoverable."
        fail "Leave exactly ONE ${key}= line in ${file}, then re-run."
    fi

    local existing=""
    existing="$(grep "^${key}=" "$file" 2>/dev/null | head -n1 | cut -d= -f2- || true)"
    if [[ -n "$existing" ]]; then
        ok "existing ${label} preserved (not regenerated)"
        return 0
    fi

    local value=""
    if command -v python3 &>/dev/null; then
        value="$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())' 2>/dev/null || true)"
    fi
    if [[ -z "$value" ]] && command -v openssl &>/dev/null; then
        # A Fernet key IS url-safe base64 of 32 random bytes — the binary
        # distribution has no interpreter, so openssl is the fallback.
        value="$(openssl rand -base64 32 | tr '+/' '-_' || true)"
    fi
    if [[ -z "$value" ]]; then
        warn "Could not generate ${label} (needs python3 with cryptography, or openssl)"
        warn "Set ${key} in ${file} before first start, or tenant setup fails closed"
        return 0
    fi

    ensure_env_var "$file" "$key" "$value"
    ok "${label} generated — BACK UP ${file}, this key cannot be recovered"
}

# ── Pre-checks ───────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    fail "This installer must be run as root (sudo bash install.sh)"
fi

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     SecureSleuths DHRUVA — Installer                       ║${NC}"
echo -e "${CYAN}║     AI-Augmented Security Operations on Wazuh              ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: Install to /opt ──────────────────────────────────────────────────
info "Installing to ${INSTALL_DIR}..."

mkdir -p "$INSTALL_DIR" "$DATA_DIR"

# Copy binary and internal libs
if [[ -f "${SCRIPT_DIR}/ai-soc-platform" ]]; then
    # PyInstaller binary distribution
    cp -r "${SCRIPT_DIR}/"* "$INSTALL_DIR/"
    chmod +x "${INSTALL_DIR}/ai-soc-platform"
    EXEC_CMD="${INSTALL_DIR}/ai-soc-platform ${INSTALL_DIR}/config/config.yaml"
    ok "Binary installed"
else
    fail "Binary not found. Run this script from the distribution directory."
fi

# ── Step 2: Environment file ─────────────────────────────────────────────────
ENV_FILE="${INSTALL_DIR}/.env"
if [[ ! -f "$ENV_FILE" ]]; then
    cp "${INSTALL_DIR}/.env.template" "$ENV_FILE"
    ensure_env_var "$ENV_FILE" "DHRUVA_BUILD_PROFILE" "auto"
    ensure_env_secret "$ENV_FILE" "TENANT_ENCRYPTION_KEY" "tenant encryption key"
    warn "Created ${ENV_FILE} — you MUST edit this with your credentials"
    NEEDS_ENV_EDIT=true
else
    ensure_env_var "$ENV_FILE" "DHRUVA_BUILD_PROFILE" "auto"
    ensure_env_secret "$ENV_FILE" "TENANT_ENCRYPTION_KEY" "tenant encryption key"
    ok "Existing .env preserved"
    NEEDS_ENV_EDIT=false
fi

# ── Step 3: Set permissions ──────────────────────────────────────────────────
info "Setting permissions..."

# Create service user if not exists
if ! id -u soc &>/dev/null; then
    useradd -r -s /sbin/nologin -d "$INSTALL_DIR" soc
    ok "Created 'soc' service user"
fi

chown -R soc:soc "$INSTALL_DIR" "$DATA_DIR"
# Protect binary, allow config editing
chmod 750 "$INSTALL_DIR"
chmod 500 "${INSTALL_DIR}/ai-soc-platform"
find "${INSTALL_DIR}/_internal" -type f -exec chmod 400 {} \; 2>/dev/null || true
find "${INSTALL_DIR}/_internal" -type d -exec chmod 500 {} \; 2>/dev/null || true
# Config files remain editable
chmod 640 "${INSTALL_DIR}/config/config.yaml"
chmod 640 "$ENV_FILE"
find "${INSTALL_DIR}/config/guidance" -type f -exec chmod 640 {} \;

ok "Permissions set (binary: read-only, config: editable)"

# ── Step 4: Systemd service ─────────────────────────────────────────────────
info "Creating systemd service..."

cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<UNIT
[Unit]
Description=SecureSleuths DHRUVA
Documentation=https://github.com/securesleuths/dhruva
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=soc
Group=soc
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${EXEC_CMD}
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ai-soc

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${DATA_DIR}
ReadOnlyPaths=${INSTALL_DIR}
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
ok "Systemd service created and enabled"

# ── Step 5: Summary ─────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    Installation Complete                     ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Install directory:${NC}  ${INSTALL_DIR}"
echo -e "  ${CYAN}Data directory:${NC}    ${DATA_DIR}"
echo -e "  ${CYAN}Config file:${NC}       ${INSTALL_DIR}/config/config.yaml"
echo -e "  ${CYAN}Environment:${NC}       ${ENV_FILE}"
echo -e "  ${CYAN}Dashboard:${NC}         https://localhost:8443"
echo -e "  ${CYAN}Build profile:${NC}     auto (Community without license, full with license)"
echo ""

if [[ "$NEEDS_ENV_EDIT" == true ]]; then
    echo -e "  ${YELLOW}NEXT STEPS:${NC}"
    echo -e "  1. Edit credentials:  ${CYAN}sudo nano ${ENV_FILE}${NC}"
    echo -e "     (Include DATABASE_URL — v4.9.0 requires Postgres. Example:"
    echo -e "      ${CYAN}DATABASE_URL=postgresql://dhruva:PW@localhost:5432/dhruva${NC})"
    echo -e "  2. Edit config:       ${CYAN}sudo nano ${INSTALL_DIR}/config/config.yaml${NC}"
    echo -e "     (Set your Wazuh IP, OpenSearch host, etc.)"
    echo -e "  3. Apply schema:      ${CYAN}sudo -u soc env \$(grep -v '^#' ${ENV_FILE} | xargs) \\\\"
    echo -e "                          ${EXEC_CMD} --migrate${NC}"
    echo -e "     (one-time; re-runnable on upgrade — see docs/MIGRATION-FROM-SQLITE.md)"
    echo -e "  4. Start platform:    ${CYAN}sudo systemctl start ${SERVICE_NAME}${NC}"
    echo -e "  5. View logs:         ${CYAN}sudo journalctl -u ${SERVICE_NAME} -f${NC}"
else
    echo -e "  ${YELLOW}NEXT STEPS:${NC}"
    echo -e "  1. Apply schema:      ${CYAN}sudo -u soc env \$(grep -v '^#' ${ENV_FILE} | xargs) \\\\"
    echo -e "                          ${EXEC_CMD} --migrate${NC}"
    echo -e "  2. Start platform:    ${CYAN}sudo systemctl start ${SERVICE_NAME}${NC}"
    echo -e "  3. View logs:         ${CYAN}sudo journalctl -u ${SERVICE_NAME} -f${NC}"
fi

echo ""
echo -e "  ${CYAN}Customize playbooks:${NC}  sudo nano ${INSTALL_DIR}/config/guidance/playbooks/*.yaml"
echo -e "  ${CYAN}Manage service:${NC}       sudo systemctl {start|stop|restart|status} ${SERVICE_NAME}"
echo ""
