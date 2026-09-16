#!/usr/bin/env bash
# =============================================================================
# SecureSleuths DHRUVA — Automated Deployment Script
# Run: chmod +x deploy.sh && ./deploy.sh
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="$INSTALL_DIR/.env"
CONFIG_FILE="$INSTALL_DIR/config/config.yaml"
DATA_DIR="/var/lib/ai-soc"
SERVICE_NAME="ai-soc"
VENV_DIR="$INSTALL_DIR/venv"
PYTHON="${PYTHON:-python3}"
CURRENT_USER="$(whoami)"

# ─── CLI flags ───────────────────────────────────────────────────────────────
# By default deploy.sh NEVER regenerates a secret that already has a non-empty
# value in .env (see ensure_secret below and docs/KEY-ROTATION.md). These opt-in
# flags force rotation of ONE specific secret; each is gated behind a typed
# destructive-consequences confirmation before anything is overwritten.
ROTATE_JWT=0
ROTATE_SALT=0
ROTATE_TENANT_KEY=0
for arg in "$@"; do
    case "$arg" in
        --rotate-jwt)        ROTATE_JWT=1 ;;
        --rotate-salt)       ROTATE_SALT=1 ;;
        --rotate-tenant-key) ROTATE_TENANT_KEY=1 ;;
        -h|--help)
            echo "Usage: ./deploy.sh [--rotate-jwt] [--rotate-salt] [--rotate-tenant-key]"
            echo ""
            echo "  Existing crypto secrets in .env are PRESERVED by default (never"
            echo "  regenerated on re-run). The --rotate-* flags force regeneration of"
            echo "  that one secret — destructive, and each prompts for typed confirmation."
            echo "  See docs/KEY-ROTATION.md for each secret's blast radius."
            exit 0 ;;
        *) ;;
    esac
done

# ─── Helpers ─────────────────────────────────────────────────────────────────

banner() {
    echo ""
    echo -e "${CYAN}${BOLD}"
    echo "  ┌─────────────────────────────────────────────────┐"
    echo "  │       SecureSleuths DHRUVA                        │"
    echo "  │       Automated Deployment Script                │"
    echo "  └─────────────────────────────────────────────────┘"
    echo -e "${NC}"
}

step() {
    echo ""
    echo -e "${GREEN}${BOLD}[STEP $1]${NC} ${BOLD}$2${NC}"
    echo -e "${GREEN}$(printf '%.0s─' {1..60})${NC}"
}

info()    { echo -e "  ${CYAN}ℹ${NC}  $1"; }
success() { echo -e "  ${GREEN}✓${NC}  $1"; }
warn()    { echo -e "  ${YELLOW}⚠${NC}  $1"; }
# fail() writes to STDERR, not stdout. Diagnostics on stdout are silently eaten
# by any command substitution: `FLOOR=$(pg_required_major)` captured every
# fail line into the variable and threw it away, so a package missing
# src/database/pg_version.py aborted the installer with ZERO output — after
# .env had already been written with freshly generated secrets. stderr is the
# correct stream for an error anyway, and it makes every future
# `x=$(some_function)` safe by construction.
fail()    { echo -e "  ${RED}✗${NC}  $1" >&2; }

ask() {
    local prompt="$1"
    local var_name="$2"
    local default="$3"
    local is_secret="$4"

    if [ -n "$default" ]; then
        prompt="$prompt [${default}]"
    fi

    if [ "$is_secret" = "secret" ]; then
        echo -ne "  ${YELLOW}?${NC}  ${prompt}: "
        read -rs value
        echo ""
    else
        echo -ne "  ${YELLOW}?${NC}  ${prompt}: "
        read -r value
    fi

    if [ -z "$value" ] && [ -n "$default" ]; then
        value="$default"
    fi

    eval "$var_name='$value'"
}

ask_yesno() {
    local prompt="$1"
    local default="${2:-y}"
    echo -ne "  ${YELLOW}?${NC}  ${prompt} [${default}]: "
    read -r answer
    answer="${answer:-$default}"
    [[ "$answer" =~ ^[Yy] ]]
}

# WO-S2: .env holds JWT_SECRET (which alone permits minting an mssp_admin
# token), TENANT_ENCRYPTION_KEY, SOC_ADMIN_PASSWORD, DATABASE_URL and every
# Wazuh/OpenSearch/LLM/ticketing credential. This script builds .env from
# scratch (it deliberately does not copy .env.template), so the file is first
# created by the append below under the invoking shell's umask — 0022 on a
# default install, i.e. world-readable 0644. Create it 0600 up front instead.
ensure_env_file_secure() {
    if [[ ! -f "$ENV_FILE" ]]; then
        (umask 077 && : > "$ENV_FILE")
    fi
    chmod 600 "$ENV_FILE"
}

# WO-S8: generate a real inbound-webhook HMAC secret when a ticketing provider
# is configured. Without this the operator gets `ticketing.enabled: true` with
# *_WEBHOOK_SECRET unset, so config.yaml keeps the literal
# "${JIRA_WEBHOOK_SECRET}" — a constant published in this repo — as the live
# HMAC key on an UNAUTHENTICATED route. Never overwrites an existing value.
ensure_webhook_secret() {
    local key="$1"
    if grep -q "^${key}=." "$ENV_FILE" 2>/dev/null; then
        info "${key} already set — keeping the existing value"
        return
    fi
    local generated
    generated="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
    update_env "$key" "$generated"
    info "Generated ${key} (set the same value as the webhook secret in your provider)"
}

update_env() {
    local key="$1"
    local value="$2"
    ensure_env_file_secure
    if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
        sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
    else
        echo "${key}=${value}" >> "$ENV_FILE"
    fi
}

# confirm_rotation KEY LABEL — print a bold destructive warning describing the
# blast radius of rotating KEY and require the operator to type the exact secret
# name to proceed. Returns 0 only on an exact-match typed confirmation; empty or
# any other input returns non-zero (rotation is cancelled).
confirm_rotation() {
    local key="$1"
    local label="$2"
    echo ""
    echo -e "  ${RED}${BOLD}!! DESTRUCTIVE: rotating ${key} (${label}) !!${NC}"
    case "$key" in
        JWT_SECRET)
            warn "Rotating JWT_SECRET invalidates every issued token — ALL logged-in analysts are signed out immediately." ;;
        ANONYMIZATION_SALT)
            warn "Rotating ANONYMIZATION_SALT breaks anonymization-token consistency — the same client identifier tokenizes differently before vs. after, so historical anonymized references no longer correlate." ;;
        TENANT_ENCRYPTION_KEY)
            warn "Rotating TENANT_ENCRYPTION_KEY makes ALL existing tenant configs UNDECRYPTABLE (Wazuh creds, API keys, webhooks)."
            warn "Every tenant fails closed and stops being polled until re-encrypted."
            warn "For a safe, no-downtime rotation use tools/rotate_tenant_key.py — see docs/KEY-ROTATION.md. This flag is a last resort." ;;
    esac
    echo ""
    ask "Type the secret name (${key}) to confirm rotation, or press Enter to cancel" _rot_confirm ""
    if [ "$_rot_confirm" = "$key" ]; then
        return 0
    fi
    return 1
}

# ensure_secret KEY GENERATOR_CMD LABEL — generate a crypto secret only if it is
# ABSENT. If .env already has a non-empty value for KEY it is PRESERVED (never
# silently overwritten), so re-running deploy.sh does not rotate JWT/salt/tenant
# keys out from under a live install. Rotation happens only when the matching
# --rotate-* flag is set, and only after a typed confirmation.
# See docs/KEY-ROTATION.md for the rationale and blast radius of each secret.
ensure_secret() {
    local key="$1"
    local generator="$2"
    local label="$3"

    # Was explicit rotation requested for THIS secret via a --rotate-* flag?
    local rotate="no"
    if [ "$key" = "JWT_SECRET" ]            && [ "${ROTATE_JWT:-0}" = "1" ];        then rotate="yes"; fi
    if [ "$key" = "ANONYMIZATION_SALT" ]    && [ "${ROTATE_SALT:-0}" = "1" ];       then rotate="yes"; fi
    if [ "$key" = "TENANT_ENCRYPTION_KEY" ] && [ "${ROTATE_TENANT_KEY:-0}" = "1" ]; then rotate="yes"; fi

    # Duplicate-line guard (WO-H75). Three components disagree about what a
    # repeated `KEY=` line means: this probe is FIRST-wins (grep | head -n1),
    # update_env's `sed` rewrites EVERY matching line, and python-dotenv —
    # which is what the platform actually reads — is LAST-wins. So a .env
    # holding the template's blank `KEY=` line PLUS an appended real value
    # (our own docs teach `cat >> .env`) reads as "unconfigured" here, and the
    # generated replacement is then stamped over the real key too.
    #
    # For a master key that is unrecoverable. Refuse and let a human say which
    # line is live rather than guessing: even last-wins would silently rewrite
    # a line the operator did not expect us to touch.
    if [ -f "$ENV_FILE" ]; then
        local dupes=0
        dupes=$(grep -c "^${key}=" "$ENV_FILE" 2>/dev/null || true)
        if [ "${dupes:-0}" -gt 1 ]; then
            fail "${ENV_FILE} has ${dupes} lines starting with '${key}=' (lines: $(grep -n "^${key}=" "$ENV_FILE" | cut -d: -f1 | tr '\n' ' '))."
            fail "The platform reads the LAST one; this script would rewrite ALL of them,"
            fail "destroying the others. For ${label} that is not recoverable."
            fail "Leave exactly ONE ${key}= line in ${ENV_FILE}, then re-run."
            exit 1
        fi
    fi

    # Existing non-empty value? (pipeline exit status is cut's, so a no-match
    # grep does not trip set -e)
    local existing=""
    if [ -f "$ENV_FILE" ]; then
        existing=$(grep "^${key}=" "$ENV_FILE" 2>/dev/null | head -n1 | cut -d= -f2-)
    fi

    if [ -n "$existing" ] && [ "$rotate" != "yes" ]; then
        success "existing ${label} preserved (not regenerated)"
        return 0
    fi

    if [ -n "$existing" ] && [ "$rotate" = "yes" ]; then
        if confirm_rotation "$key" "$label"; then
            local value
            value=$(eval "$generator")
            update_env "$key" "$value"
            warn "${label} ROTATED — previous value overwritten"
        else
            info "${label} rotation cancelled — existing value preserved"
        fi
        return 0
    fi

    # No existing value — first install, generate fresh.
    local value
    value=$(eval "$generator")
    update_env "$key" "$value"
    success "${label} generated"
}

update_config() {
    local key="$1"
    local value="$2"
    local file="$CONFIG_FILE"
    # Simple YAML value replacement (works for scalar values on their own line)
    sed -i "s|${key}:.*|${key}: ${value}|" "$file"
}

# ─── WO-H129: the PostgreSQL version floor ───────────────────────────────────
# This script used to run `apt-get install postgresql postgresql-contrib` — the
# UNVERSIONED meta-package. On Ubuntu 22.04 that resolves to PostgreSQL 14, and
# on 14 migration 0018 cannot run its `agent_decisions.host` backfill (it needs
# `pg_input_is_valid`, PostgreSQL 16+). The result is a client whose decision
# history cannot be correlated by host, with nothing downstream saying so — the
# same failure again, shipped to the next customer.
#
# The floor is NOT hardcoded here. It is read from src/database/pg_version.py,
# the same constant the runtime enforces at boot, so the installer and the
# platform cannot disagree.

# ONE resolution chain, used by EVERY consumer of the floor in this script.
# src/ does not look the same in every build lane, so there are three ways to
# reach the module and they are tried in order:
#
#   1. src/database/pg_version.py       — source tarball, a git checkout, and
#      (since WO-H129 QA) the compiled client package, whose builder now
#      exempts this one file from Cython/.pyc for exactly this reason.
#   2. src/database/pg_version.pyc      — the DOCKER IMAGE (the Dockerfile
#      compiles and deletes every .py outside src/database/migrations) and any
#      client tarball built before that exemption. A .pyc can be executed
#      directly, the same probe the wizard does for deployment_wizard.{py,pyc}.
#      Docker never runs deploy.sh, but the shape is real and cheap to support.
#   3. importing the module             — the only thing that works if the file
#      was Cython-compiled to a .so, which cannot be run as a script at all.
#
# 2 and 3 need $PYTHON's bytecode magic / ABI to match the build box's.
#
# MEASURED, so nobody has to guess later: 3 already covers every ordinary .pyc
# layout, including a namespace package with no __init__.py at all. 2 is NOT
# redundant for one reason — importing src.database.pg_version executes
# src/__init__.py first, and that is an ordinary file one `from src.something
# import ...` away from needing a dependency the pre-venv interpreter does not
# have. On that day 3 breaks on a fresh box and 2 is the only path left.
# tests/test_pg_version_floor_h129.py pins exactly that shape
# (test_bytecode_behind_a_broken_package_init_is_still_readable) so this branch
# is not an untestable "just in case".
#
# Echoes the module's stdout. Returns non-zero ONLY when no form of the module
# could be run — which is a DIFFERENT FACT from "the module answered no", and
# keeping those two apart is the whole point (see --meets in pg_version.py).
# Every caller must use `|| true`: this is invoked from command substitutions,
# and under `set -e` a bare assignment would abort the installer with no
# message at all.
pg_version_cli() {
    local mod="$INSTALL_DIR/src/database/pg_version" out

    if [ -f "${mod}.py" ] && out=$("$PYTHON" "${mod}.py" "$@" 2>/dev/null) \
       && [ -n "$out" ]; then
        printf '%s\n' "$out"; return 0
    fi
    if [ -f "${mod}.pyc" ] && out=$("$PYTHON" "${mod}.pyc" "$@" 2>/dev/null) \
       && [ -n "$out" ]; then
        printf '%s\n' "$out"; return 0
    fi
    # Import form. Routed through the module's OWN _cli so all three paths
    # answer with identical semantics instead of a hand-rolled third copy.
    if out=$(cd "$INSTALL_DIR" && "$PYTHON" -c \
        'import sys
from src.database import pg_version as m
sys.exit(m._cli(["pg_version.py"] + sys.argv[1:]))' "$@" 2>/dev/null) \
       && [ -n "$out" ]; then
        printf '%s\n' "$out"; return 0
    fi
    return 1
}

# The floor, as an integer, on stdout — or a loud abort. Never a guess.
pg_required_major() {
    local floor mod="$INSTALL_DIR/src/database/pg_version"
    floor=$(pg_version_cli --floor || true)

    if [[ ! "$floor" =~ ^[0-9]+$ ]]; then
        # These go to STDERR (see fail() above). They used to go to stdout, and
        # both call sites are command substitutions, so on a compiled package
        # this aborted the installer with no output at all.
        fail "Could not read the required PostgreSQL major version from"
        fail "  ${mod}.py / ${mod}.pyc / importing src.database.pg_version"
        fail "using PYTHON=$PYTHON. That module ships with every build lane, so"
        fail "a missing copy means this package is incomplete — and a copy that"
        fail "is present but unreadable usually means the compiled bytecode was"
        fail "built for a different Python than $($PYTHON -V 2>&1)."
        fail "Re-download the release and re-run, or set PYTHON= to the"
        fail "interpreter the package was built for. Refusing to guess a"
        fail "version: guessing is exactly how the wrong major got installed."
        exit 1
    fi
    printf '%s\n' "$floor"
}

# Does VERSION meet the floor? Echoes "meets", "below", or "unknown".
#
# WO-H129 QA finding F2. The two sibling call sites below used to do
#
#     "$PYTHON" "$INSTALL_DIR/src/database/pg_version.py" --check "$v" \
#         >/dev/null 2>&1
#
# — single hardcoded path, and both possible failures funnelled into one exit
# code. On any lane that ships no .py (the Docker image, a client tarball built
# before the exemption) that reported a perfectly supported 16.14 as BELOW
# major 16, while $PG_FLOOR right next to it had already resolved 16 through
# pg_version_cli's fallback chain. The installer contradicting itself is worse
# than either answer on its own: on the same-server path it was a hard exit 1
# telling the operator their PostgreSQL 16.14 was below major 16.
#
# So: same three-form resolution as the floor, and THREE outcomes. "unknown"
# is a real answer and every caller handles it explicitly — refusing to guess
# in either direction is the rule this whole work order exists to enforce.
pg_version_verdict() {
    local answer
    answer=$(pg_version_cli --meets "$1" || true)
    case "$answer" in
        meets|below) printf '%s\n' "$answer" ;;
        *)           printf 'unknown\n' ;;
    esac
}

# Echo "<major> <port>" for the highest-version ONLINE cluster at or above $1.
# Silent (empty) when there is none — including when postgresql-common is not
# installed, which is the "nothing here yet" case.
pg_pick_cluster() {
    local floor="$1"
    command -v pg_lsclusters &>/dev/null || return 0
    pg_lsclusters -h 2>/dev/null | awk -v floor="$floor" '
        $4 == "online" { v = $1 + 0; if (v >= floor && v > best) { best = v; port = $3 } }
        END { if (best) print best, port }'
}

# `apt-get update` that EXPLAINS itself. Under `set -e` a bare
# `sudo apt-get update -qq` aborts the whole installer the moment one apt source
# is broken (an expired third-party key, an unreachable mirror, a stale
# sources.list.d entry) and prints only apt's own output, which does not say
# "your DHRUVA install just stopped". This names the step and what to do.
apt_update() {
    if ! sudo apt-get update -qq; then
        echo ""
        fail "\`apt-get update\` failed on this host, so no package can be"
        fail "installed. This is almost always ONE broken entry in"
        fail "/etc/apt/sources.list or /etc/apt/sources.list.d/ (an expired"
        fail "signing key, or a mirror that is down) — apt's own output above"
        fail "names it. Fix or remove that source and re-run ./deploy.sh."
        fail "Alternatively, re-run and choose option 1 (external Postgres),"
        fail "which needs no packages from this host at all."
        exit 1
    fi
}

# Install a PINNED major. Never the unversioned meta-package.
install_pinned_postgres() {
    local floor="$1"
    info "Installing postgresql-${floor} via apt (pinned major, not the"
    info "unversioned meta-package — see WO-H129)..."
    apt_update

    local candidate
    candidate=$(apt-cache policy "postgresql-${floor}" 2>/dev/null \
                | awk '/Candidate:/ {print $2}')
    if [ -z "$candidate" ] || [ "$candidate" = "(none)" ]; then
        echo ""
        warn "This host's apt sources do not offer postgresql-${floor}."
        warn "$(lsb_release -ds 2>/dev/null || echo 'This distribution') ships an"
        warn "older PostgreSQL by default, and DHRUVA requires ${floor} or newer:"
        warn "below ${floor}, migration 0018 cannot backfill agent_decisions.host,"
        warn "so decision history silently loses host correlation."
        echo ""
        echo -e "  ${CYAN}Option A${NC}  Add the official PostgreSQL project apt repository"
        echo "            (PGDG, apt.postgresql.org) and install postgresql-${floor}."
        echo "            This adds a THIRD-PARTY package source and its signing"
        echo "            key to this machine — a real trust decision, which is"
        echo "            why this script will not make it for you."
        echo ""
        echo -e "  ${CYAN}Option B${NC}  Abort. Install PostgreSQL ${floor}+ yourself (or point"
        echo "            DHRUVA at an external/managed one), then re-run."
        echo ""
        if ask_yesno "Add the official PostgreSQL (PGDG) apt repository now?" "n"; then
            add_pgdg_repo
            apt_update
            candidate=$(apt-cache policy "postgresql-${floor}" 2>/dev/null \
                        | awk '/Candidate:/ {print $2}')
            if [ -z "$candidate" ] || [ "$candidate" = "(none)" ]; then
                fail "postgresql-${floor} is still unavailable after adding PGDG."
                fail "PGDG may not publish packages for this release"
                fail "($(lsb_release -cs 2>/dev/null || echo 'unknown codename'))."
                fail "Install PostgreSQL ${floor}+ manually or use an external"
                fail "database (re-run and choose option 1)."
                exit 1
            fi
        else
            fail "Aborted — this host cannot install PostgreSQL ${floor} from its"
            fail "own sources. To do it manually:"
            fail "  sudo apt-get install -y curl ca-certificates gnupg"
            fail "  curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \\"
            fail "    | sudo gpg --batch --yes --dearmor -o /usr/share/keyrings/pgdg.gpg"
            fail "  echo \"deb [signed-by=/usr/share/keyrings/pgdg.gpg] \\"
            fail "    http://apt.postgresql.org/pub/repos/apt \$(lsb_release -cs)-pgdg main\" \\"
            fail "    | sudo tee /etc/apt/sources.list.d/pgdg.list"
            fail "  sudo apt-get update && sudo apt-get install -y postgresql-${floor}"
            fail "Then re-run ./deploy.sh."
            exit 1
        fi
    fi

    # contrib is versioned on PGDG and on modern Ubuntu; on some releases only
    # the transitional unversioned name exists. Install it only if a versioned
    # candidate is really there — an unversioned `postgresql-contrib` can pull
    # in a DIFFERENT major, which is the whole bug we are removing.
    # Checked with an explicit string compare, not `grep -v`: on an unknown
    # package `apt-cache policy` prints NOTHING, and `grep -qv` over empty input
    # was measured returning 0 on this platform — i.e. "install it", for a
    # package that does not exist. Same candidate test as above, same shape.
    local contrib="" contrib_candidate
    contrib_candidate=$(apt-cache policy "postgresql-contrib-${floor}" 2>/dev/null \
                        | awk '/Candidate:/ {print $2}')
    if [ -n "$contrib_candidate" ] && [ "$contrib_candidate" != "(none)" ]; then
        contrib="postgresql-contrib-${floor}"
    fi

    if ! sudo apt-get install -y -qq "postgresql-${floor}" ${contrib}; then
        fail "apt-get install postgresql-${floor} failed. Check network"
        fail "reachability and apt sources, then re-run this script."
        exit 1
    fi

    # Enable + start via systemd (best effort — non-systemd hosts fall through
    # to the pg_ctlcluster path below).
    sudo systemctl enable --now "postgresql@${floor}-main" 2>/dev/null \
        || sudo systemctl enable --now postgresql 2>/dev/null || true

    # Verify the cluster is actually accepting connections. systemctl can exit 0
    # while the cluster fails to start, and silent failure here leaves the
    # operator with a broken install and a misleading success message.
    local running=false attempt picked
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        picked=$(pg_pick_cluster "$floor")
        if [ -n "$picked" ] && \
           sudo -u postgres pg_isready -q -p "${picked##* }" 2>/dev/null; then
            running=true; break
        fi
        sleep 1
    done
    # SysV/OpenRC/container path. NOTE: this used to start
    # `$(ls /etc/postgresql/ | head -1)`, i.e. the LOWEST-numbered cluster on
    # the box — on a host that already had 14, that started 14 and ignored the
    # major we just installed. It starts the pinned major now.
    if ! $running && command -v pg_ctlcluster &>/dev/null; then
        warn "systemctl path did not start PostgreSQL ${floor} — falling back to pg_ctlcluster"
        sudo pg_ctlcluster "$floor" main start 2>/dev/null || true
        for attempt in 1 2 3 4 5; do
            picked=$(pg_pick_cluster "$floor")
            if [ -n "$picked" ] && \
               sudo -u postgres pg_isready -q -p "${picked##* }" 2>/dev/null; then
                running=true; break
            fi
            sleep 1
        done
    fi
    if ! $running; then
        fail "PostgreSQL ${floor} installed but failed to start. Diagnose with:"
        fail "  sudo systemctl status postgresql@${floor}-main"
        fail "  sudo journalctl -u postgresql@${floor}-main --no-pager -n 50"
        fail "  pg_lsclusters"
        fail "Then re-run this script."
        exit 1
    fi
    success "PostgreSQL ${floor} installed and running"
}

add_pgdg_repo() {
    local codename
    codename=$(lsb_release -cs 2>/dev/null || true)
    if [ -z "$codename" ]; then
        fail "Cannot determine the distribution codename (lsb_release missing)."
        fail "Install lsb-release, or add the PGDG repo manually, then re-run."
        exit 1
    fi
    info "Adding the official PostgreSQL apt repository (PGDG) for ${codename}..."
    sudo apt-get install -y -qq curl ca-certificates gnupg
    # --batch --yes, and rm -f the target on failure. Without them this is a
    # one-shot trap: if the fetch 404s, `gpg --dearmor -o F` still CREATES a
    # 0-byte F before exiting 2, and on the next run `gpg --dearmor -o F` sees
    # an existing F and asks "File exists. Overwrite?" on /dev/tty (or exits 2
    # outright when there is no tty) — so every retry fails, and the script
    # blames the network forever. --batch --yes overwrites without asking; the
    # rm -f keeps a broken keyring from being left behind at all.
    local keyring=/usr/share/keyrings/pgdg.gpg
    if ! curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
         | sudo gpg --batch --yes --dearmor -o "$keyring"; then
        sudo rm -f "$keyring"
        fail "Failed to fetch or import the PostgreSQL signing key. Check"
        fail "network access to www.postgresql.org (a proxy that returns an"
        fail "HTML error page fails here too — gpg rejects the empty input)"
        fail "and re-run. Nothing was left behind at $keyring."
        exit 1
    fi
    echo "deb [signed-by=/usr/share/keyrings/pgdg.gpg] http://apt.postgresql.org/pub/repos/apt ${codename}-pgdg main" \
        | sudo tee /etc/apt/sources.list.d/pgdg.list >/dev/null
    success "PGDG repository added (/etc/apt/sources.list.d/pgdg.list)"
}

install_local_postgres() {
    local floor
    floor=$(pg_required_major)
    info "Installing Postgres locally on this server (PostgreSQL ${floor}+ required)..."

    if ! command -v apt-get &>/dev/null; then
        fail "Same-server Postgres install currently supports Debian/Ubuntu only."
        fail "On RHEL/CentOS/Rocky/Alma, install postgresql-server (${floor} or"
        fail "newer) manually, then re-run this script and choose option 1"
        fail "(external Postgres)."
        exit 1
    fi

    # ── Which cluster are we going to use? ───────────────────────────────────
    # The old code reused ANY running Postgres it found. That is how a host with
    # the OS default 14 already installed ended up serving DHRUVA from 14. A
    # cluster is only reusable if it MEETS THE FLOOR.
    PG_PORT=""
    local picked reuse_ver
    picked=$(pg_pick_cluster "$floor")
    if [ -n "$picked" ]; then
        reuse_ver=${picked%% *}
        PG_PORT=${picked##* }
        info "Postgres ${reuse_ver} already installed and running on port ${PG_PORT} — reusing it."
    elif command -v pg_lsclusters &>/dev/null && \
         [ -n "$(pg_lsclusters -h 2>/dev/null)" ]; then
        warn "This host already runs PostgreSQL, but no cluster meets the"
        warn "required major ${floor}:"
        pg_lsclusters 2>/dev/null | sed 's/^/    /'
        warn "Existing clusters are left untouched; PostgreSQL ${floor} will be"
        warn "installed alongside them and DHRUVA will use that one."
    elif command -v psql &>/dev/null && sudo -u postgres pg_isready -q 2>/dev/null; then
        # A running Postgres with no Debian cluster tooling (custom build,
        # container image). Interrogate it directly rather than assuming.
        local running_ver
        running_ver=$(sudo -u postgres psql -tAc "SHOW server_version" 2>/dev/null | head -1)
        case "$(pg_version_verdict "$running_ver")" in
            meets)
                PG_PORT=$(sudo -u postgres psql -tAc "SHOW port" 2>/dev/null | head -1)
                info "Reusing the running PostgreSQL ${running_ver} instance on port ${PG_PORT}."
                ;;
            below)
                fail "The PostgreSQL running on this host is ${running_ver}, below the"
                fail "required major ${floor}, and this host has no Debian cluster"
                fail "tooling (pg_lsclusters) for installing a second major safely."
                fail "Upgrade it to ${floor}+ (see docs/POSTGRES-VERSION.md), or use an"
                fail "external database: re-run and choose option 1."
                exit 1
                ;;
            *)
                # "unknown" — the module could not be run in ANY form. Note we
                # only get here because pg_required_major already succeeded, so
                # this should be unreachable; if it ever fires, something moved
                # under us mid-run. Do NOT reuse an unverified server (that is
                # how a client ended up on PostgreSQL 14) and do NOT claim it is
                # below the floor either (that is finding F2). Say what could
                # not be determined, and stop.
                fail "Could not determine whether the PostgreSQL running on this"
                fail "host (${running_ver:-version unreadable}) meets the required"
                fail "major ${floor}: src/database/pg_version.py could not be run in"
                fail "any form (.py, .pyc, or imported) with PYTHON=$PYTHON."
                fail "Refusing to guess in either direction. Re-download the"
                fail "release, or re-run and choose option 1 (external Postgres)."
                exit 1
                ;;
        esac
    fi

    if [ -z "$PG_PORT" ]; then
        install_pinned_postgres "$floor"
        picked=$(pg_pick_cluster "$floor")
        if [ -z "$picked" ]; then
            fail "PostgreSQL ${floor} was installed but no online cluster at or"
            fail "above major ${floor} could be found. Check 'pg_lsclusters'."
            exit 1
        fi
        PG_PORT=${picked##* }
    fi

    ask "Postgres role name" PG_USER "dhruva"

    echo ""
    echo -e "  ${CYAN}ℹ${NC}  Press Enter at the next prompt to auto-generate a strong"
    echo "     password (URL-safe, stored in .env). Or type your own."
    ask "Postgres role password (Enter to auto-generate)" PG_PASS "" "secret"
    if [ -z "$PG_PASS" ]; then
        PG_PASS=$($PYTHON -c "import secrets; print(secrets.token_urlsafe(24))")
        info "Generated random password (stored in .env)"
    fi
    # Reject passwords with single quotes — would break the CREATE USER SQL.
    # Anything else is fine; we URL-encode it before building the DSN.
    if [[ "$PG_PASS" == *"'"* ]]; then
        fail "Password contains a single quote — please pick a different one."
        exit 1
    fi

    ask "Postgres database name" PG_DB "dhruva"

    info "Configuring role and database (idempotent)..."
    # WO-H12-followup: the app role MUST be NOSUPERUSER NOBYPASSRLS or Postgres
    # Row-Level Security (the WO-H12 tenant backstop) is silently bypassed. Set it
    # explicitly on both create and re-run rather than relying on the PG default.
    # WO-S18: the role statement carries the DB password, so it goes over
    # STDIN, never in argv. `psql -c "...PASSWORD '$PG_PASS'..."` put the
    # plaintext database password in the process table, readable via
    # /proc/<pid>/cmdline and `ps` by any local user for the duration of the
    # call — the same exposure class as WO-S16. (Note the statement still
    # reaches the Postgres server log if log_statement is on; that is inherent
    # to CREATE/ALTER USER and outside this script's control.)
    # WO-H129: every psql call below is pinned to ${PG_PORT} — the port of the
    # cluster we actually chose. Without it these run against the DEFAULT
    # cluster, which on a host that already had an older major is the OLD one:
    # the role and database would be created on 14 while we advertise 16.
    if sudo -u postgres psql -p "$PG_PORT" -tAc "SELECT 1 FROM pg_roles WHERE rolname='${PG_USER}'" 2>/dev/null | grep -q 1; then
        printf "ALTER USER %s WITH PASSWORD '%s' NOSUPERUSER NOBYPASSRLS;\n" \
            "${PG_USER}" "${PG_PASS}" | sudo -u postgres psql -p "$PG_PORT" -q -v ON_ERROR_STOP=1 >/dev/null
        info "Role ${PG_USER} already existed — password updated, NOSUPERUSER NOBYPASSRLS enforced"
    else
        printf "CREATE USER %s WITH PASSWORD '%s' NOSUPERUSER NOBYPASSRLS;\n" \
            "${PG_USER}" "${PG_PASS}" | sudo -u postgres psql -p "$PG_PORT" -q -v ON_ERROR_STOP=1 >/dev/null
        success "Role ${PG_USER} created (NOSUPERUSER NOBYPASSRLS — RLS can take effect)"
    fi

    if sudo -u postgres psql -p "$PG_PORT" -tAc "SELECT 1 FROM pg_database WHERE datname='${PG_DB}'" 2>/dev/null | grep -q 1; then
        info "Database ${PG_DB} already exists"
    else
        sudo -u postgres psql -p "$PG_PORT" -c "CREATE DATABASE ${PG_DB} OWNER ${PG_USER};" >/dev/null
        success "Database ${PG_DB} created (owner: ${PG_USER})"
    fi

    # URL-encode the password to make the DSN safe for libpq parsing
    # WO-S18: pass the password through the ENVIRONMENT, not argv — the same
    # process-table exposure as the psql calls above.
    PG_PASS_ENC=$(PG_PASS="$PG_PASS" $PYTHON -c "import os, urllib.parse; print(urllib.parse.quote(os.environ['PG_PASS'], safe=''))")
    DB_DSN="postgresql://${PG_USER}:${PG_PASS_ENC}@localhost:${PG_PORT}/${PG_DB}"
    update_env "DATABASE_URL" "$DB_DSN"
    success "DATABASE_URL configured for local Postgres (port ${PG_PORT})"
}

# ─── Pre-flight ──────────────────────────────────────────────────────────────

banner

# Record the build profile in .env before anything else. deploy.sh builds
# .env from scratch via update_env and never copies .env.template, so without
# this the var is absent and the runtime defaults to the full profile —
# wrongly mounting paid routes/modules in a Community install. "auto" resolves
# to community when no license.key is present, and full once a license is added.
update_env "DHRUVA_BUILD_PROFILE" "auto"

echo -e "${BOLD}Choose your setup method:${NC}"
echo ""
echo -e "${CYAN}1) Interactive Wizard${NC}  (recommended for new deployments)"
echo "   🚀 New guided wizard with multi-tenant LLM and webhook support"
echo "   ✅ Supports per-tenant provider configuration"
echo "   ✅ Real-time webhook alert ingestion"
echo "   ✅ Enhanced security and tenant management"
echo ""
echo -e "${CYAN}2) Classic Setup${NC}  (for existing deployments or simple setups)"
echo "   📋 Traditional step-by-step configuration"
echo "   ✅ Proven and stable configuration flow"
echo "   ✅ Compatible with existing deployments"
echo ""

ask "Enter 1 or 2" SETUP_METHOD "1"

if [ "$SETUP_METHOD" = "1" ]; then
    echo ""
    echo -e "${GREEN}✅ Launching Interactive Deployment Wizard${NC}"
    echo ""

    # Activate virtual environment for wizard
    if [ ! -d "$VENV_DIR" ]; then
        info "Creating virtual environment for wizard..."
        if ! $PYTHON -m venv "$VENV_DIR"; then
            fail "Failed to create venv. On Ubuntu/Debian, run: sudo apt install python3-venv"
            exit 1
        fi
    fi

    source "$VENV_DIR/bin/activate"

    # Install full runtime requirements up front so `python main.pyc` works
    # immediately after the wizard exits — and so the wizard's imports (which
    # may grow over time) never break on a missing dep.
    info "Installing platform dependencies (this can take a minute)..."
    pip install --quiet --upgrade pip
    if [ -f "$INSTALL_DIR/requirements.txt" ]; then
        pip install --quiet -r "$INSTALL_DIR/requirements.txt"
    else
        pip install --quiet pyyaml cryptography structlog
    fi

    # Run the deployment wizard. Invoked as a script path (not via -m or -c)
    # so it works regardless of whether src/setup ships as .py, .pyc, or .so —
    # and does not require the runtime's Python minor version.
    if [ -f "src/setup/deployment_wizard.py" ]; then
        exec $PYTHON src/setup/deployment_wizard.py --config "$CONFIG_FILE"
    elif [ -f "src/setup/deployment_wizard.pyc" ]; then
        exec $PYTHON src/setup/deployment_wizard.pyc --config "$CONFIG_FILE"
    else
        fail "Deployment wizard not found at src/setup/deployment_wizard.{py,pyc}."
        fail "This package may be a Community-tier build that ships without the wizard."
        fail "Use Classic Setup (re-run and pick option 2) instead."
        exit 1
    fi
fi

echo ""
echo -e "${GREEN}✅ Using Classic Setup Mode${NC}"
echo ""

echo -e "${BOLD}This script will:${NC}"
echo "  1. Check system prerequisites (Python, Node.js)"
echo "  2. Install Python dependencies"
echo "  3. Choose deployment mode (single-tenant or multi-tenant)"
echo "  4. Configure Postgres database (v4.9.0+ requirement)"
echo "  5. Configure Wazuh connection"
echo "  6. Configure AI backend (Claude, OpenAI, Ollama, or Groq)"
echo "  7. Set up dashboard credentials and HTTPS"
echo "  8. Create data directories"
echo "  9. Test connectivity"
echo " 10. Configure threat intelligence feeds"
echo " 11. Configure Slack/Email notifications"
echo " 12. Configure ticketing (Jira, ServiceNow, PagerDuty)"
echo " 13. Apply Postgres schema (alembic upgrade head)"
echo " 14. Optionally install as a systemd service"
echo ""

if ! ask_yesno "Continue with classic deployment?"; then
    echo "Aborted."
    exit 0
fi

DEPLOY_MODE="single"

# ─── Step 1: System Prerequisites ────────────────────────────────────────────

step 1 "Checking system prerequisites"

# Python
#
# WO-H116: the MINIMUM SUPPORTED interpreter is 3.10 — Ubuntu 22.04's system
# python3, which is what a source-tarball install actually runs. This check used
# to warn "3.11+ recommended, may still work" on exactly that interpreter, so
# the wizard a client runs told them their supported, production-grade Python
# was second-best. It also compared the majors and minors independently
# (`major >= 3 && minor >= 11`), which would reject a hypothetical Python 4.0.
PYTHON_MIN_MAJOR=3
PYTHON_MIN_MINOR=10
# qa-audit L3: there is a CEILING as well as a floor, and it is not caution.
# requirements.txt pins psycopg[binary]==3.2.4 and pydantic-core==2.27.2;
# neither publishes a cp314 wheel, so on 3.14 step 2's
# `pip install -r requirements.txt` FAILS outright rather than building from
# source. Warning here costs the operator nothing; finding out at step 2 costs
# them a half-finished install and an unreadable resolver error.
PYTHON_MAX_MAJOR=3
PYTHON_MAX_MINOR=13

# Pure predicate: 0 (true) if <version-string> is inside the supported window.
# Extracted so tests/test_python_floor_h116.py can execute the REAL comparison
# rather than assert on the text of this file.
python_version_supported() {
    local maj min
    maj=$(echo "$1" | cut -d. -f1)
    min=$(echo "$1" | cut -d. -f2)
    case "$maj$min" in *[!0-9]*|"") return 1 ;; esac
    # Below the floor?
    [ "$maj" -lt "$PYTHON_MIN_MAJOR" ] && return 1
    [ "$maj" -eq "$PYTHON_MIN_MAJOR" ] && [ "$min" -lt "$PYTHON_MIN_MINOR" ] \
        && return 1
    # Above the ceiling?
    [ "$maj" -gt "$PYTHON_MAX_MAJOR" ] && return 1
    [ "$maj" -eq "$PYTHON_MAX_MAJOR" ] && [ "$min" -gt "$PYTHON_MAX_MINOR" ] \
        && return 1
    return 0
}

PYTHON_WINDOW="${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR} to ${PYTHON_MAX_MAJOR}.${PYTHON_MAX_MINOR}"

if command -v python3 &>/dev/null; then
    PYTHON="${PYTHON:-python3}"
    py_version=$($PYTHON --version 2>&1 | awk '{print $2}')
    if python_version_supported "$py_version"; then
        success "Python $py_version found"
    else
        warn "Python $py_version found (DHRUVA supports Python ${PYTHON_WINDOW}; outside that window the pinned dependencies may not install)"
    fi
else
    fail "Python 3 not found. Install with: sudo apt install python3 python3-venv python3-pip"
    exit 1
fi

# pip / venv
if ! $PYTHON -m venv --help &>/dev/null; then
    warn "python3-venv not installed. Installing..."
    # apt_update, not a bare `apt-get update`: same L2 reasoning as the
    # Postgres step — under `set -e` one broken apt source aborts the installer
    # here with only apt's own output to explain it.
    apt_update && sudo apt-get install -y python3-venv
    success "python3-venv installed"
fi

# Node.js (needed for Claude CLI)
if command -v node &>/dev/null; then
    node_version=$(node --version)
    success "Node.js $node_version found"
else
    warn "Node.js not found. Needed only if using Claude CLI mode."
    if ask_yesno "Install Node.js via nvm? (skip if using API key)" "n"; then
        curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
        export NVM_DIR="$HOME/.nvm"
        [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
        nvm install --lts
        success "Node.js installed via nvm"
    fi
fi

# Git
if command -v git &>/dev/null; then
    success "Git found"
else
    fail "Git not found. Install with: sudo apt install git"
    exit 1
fi

# OpenSSL — used to auto-generate a self-signed dashboard certificate
if command -v openssl &>/dev/null; then
    success "OpenSSL found"
else
    warn "OpenSSL not found — needed only if you auto-generate a dashboard cert."
    warn "Install with: sudo apt install openssl"
fi

# ─── Step 2: Python Dependencies ─────────────────────────────────────────────

step 2 "Installing Python dependencies"

# Check for broken venv (exists but missing activate)
if [ -d "$VENV_DIR" ] && [ ! -f "$VENV_DIR/bin/activate" ]; then
    warn "Broken virtual environment detected — removing and recreating..."
    rm -rf "$VENV_DIR"
fi

if [ ! -d "$VENV_DIR" ]; then
    info "Creating virtual environment..."
    if ! $PYTHON -m venv "$VENV_DIR"; then
        fail "Failed to create venv. On Ubuntu/Debian, run: sudo apt install python3-venv"
        exit 1
    fi
    success "Virtual environment created"
else
    success "Virtual environment already exists"
fi

source "$VENV_DIR/bin/activate"
info "Installing packages from requirements.txt..."
pip install --quiet --upgrade pip
pip install --quiet -r "$INSTALL_DIR/requirements.txt"
success "Python dependencies installed"

# ─── Step 3: Deployment Mode ────────────────────────────────────────────────

step 3 "Choose your deployment mode"

echo ""
echo -e "  ${BOLD}How will you use this platform?${NC}"
echo ""
echo -e "  ${CYAN}1) Single Tenant${NC}  (most common)"
echo "     You are monitoring ONE organization's environment."
echo "     One Wazuh instance, one team of analysts, one set of alerts."
echo "     Example: Your company's own security team using the platform."
echo ""
echo -e "  ${CYAN}2) Multi-Tenant${NC}   (managed security / MSSP)"
echo "     You are monitoring MULTIPLE organizations from one platform."
echo "     Each client gets their own Wazuh connection, their own alerts,"
echo "     their own users — completely separated. You get a master account"
echo "     that can switch between clients from the dashboard."
echo "     Example: A security provider managing 10 different companies."
echo ""

ask "Enter 1 or 2" MODE_CHOICE "1"

if [ "$MODE_CHOICE" = "2" ]; then
    DEPLOY_MODE="multi"
    success "Multi-tenant mode selected"
    echo ""
    echo -e "  ${CYAN}What happens next:${NC}"
    echo "    - We'll set up your first client (you can add more from the dashboard later)"
    echo "    - You'll get a master admin account that can manage all clients"
    echo "    - Each client's credentials are encrypted and stored separately"
    echo ""
else
    DEPLOY_MODE="single"
    success "Single-tenant mode selected"
fi

# ─── Step 4: Postgres Database ───────────────────────────────────────────────

step 4 "Configuring Postgres database (v4.9.0+ requirement)"

echo ""
echo -e "  ${CYAN}ℹ${NC}  v4.9.0 retired SQLite. The platform needs a Postgres database."
echo ""
echo -e "  ${CYAN}1) Use an EXTERNAL Postgres${NC}  (recommended for production)"
echo "     Managed (RDS / Cloud SQL / Azure DB) or self-managed on a"
echo "     SEPARATE host. Provides blast-radius isolation — if this"
echo "     server is destroyed, your DHRUVA data survives."
echo "     See docs/DEPLOYMENT-SPLIT-HOST.md for the recommended topology."
echo ""
echo -e "  ${CYAN}2) Install Postgres on THIS SERVER${NC}  (single-box, convenient)"
echo "     The script installs a PINNED postgresql-<major> via apt, creates"
echo "     the role and database, and wires DATABASE_URL automatically."
echo ""

# WO-H129: resolve the floor ONCE, as its own statement so `set -e` aborts if
# pg_required_major fails (its `exit 1` only leaves the subshell). Its
# diagnostics survive this substitution because fail() writes to stderr — the
# first cut of this wrote them to stdout, where they were captured into
# PG_FLOOR and discarded, and a compiled client package aborted here in total
# silence. Reached AFTER .env exists, so silence is the worst possible failure:
# the operator is left with a half-configured box and no idea why.
PG_FLOOR=$(pg_required_major)

ask "Enter 1 or 2" PG_CHOICE "1"

case "$PG_CHOICE" in
    1)
        echo ""
        echo -e "  ${CYAN}ℹ${NC}  DHRUVA requires PostgreSQL ${PG_FLOOR} or newer."
        echo "     Below that, migration 0018 cannot backfill agent_decisions.host"
        echo "     (it needs pg_input_is_valid, PostgreSQL 16+) and host correlation"
        echo "     over your decision history is silently incomplete. The platform"
        echo "     enforces this at startup — see docs/POSTGRES-VERSION.md."
        echo ""
        ask "Postgres DSN (libpq URI)" DB_DSN \
            "postgresql://dhruva:CHANGE_ME@db-host.internal:5432/dhruva"
        if [[ ! "$DB_DSN" =~ ^postgres(ql)?:// ]]; then
            fail "DSN must start with postgresql:// (got: $DB_DSN)"
            exit 1
        fi
        update_env "DATABASE_URL" "$DB_DSN"
        success "DATABASE_URL written to .env"
        ;;
    2)
        echo ""
        echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║  ⚠  SAME-SERVER POSTGRES INSTALL — DATA-LOSS WARNING            ║${NC}"
        echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${YELLOW}With Postgres on the same host as the platform, a server${NC}"
        echo -e "  ${YELLOW}failure, disk corruption, or accidental reimage loses BOTH${NC}"
        echo -e "  ${YELLOW}the platform AND its database TOGETHER.${NC}"
        echo ""
        echo -e "  ${YELLOW}SecureSleuths is NOT responsible for data loss in a${NC}"
        echo -e "  ${YELLOW}same-server install. You take responsibility for:${NC}"
        echo ""
        echo -e "    ${YELLOW}• Regular pg_dump backups to off-host storage${NC}"
        echo -e "    ${YELLOW}• Disaster-recovery procedures${NC}"
        echo -e "    ${YELLOW}• Any data loss if this server is destroyed${NC}"
        echo ""
        echo -e "  ${YELLOW}For production, choose option 1 (external Postgres).${NC}"
        echo ""
        if ! ask_yesno "Accept these terms and install Postgres on THIS server?" "n"; then
            fail "Same-server install declined. Re-run and choose option 1."
            exit 1
        fi
        install_local_postgres
        ;;
    *)
        fail "Invalid choice: '$PG_CHOICE' (expected 1 or 2)."
        exit 1
        ;;
esac

# Reachability probe — only if the venv from Step 2 already has psycopg.
# Skipped silently otherwise; the apply-schema step is the real gate.
if [[ -x "$VENV_DIR/bin/python" ]] && \
   "$VENV_DIR/bin/python" -c "import psycopg" 2>/dev/null; then
    DB_DSN=$(grep '^DATABASE_URL=' "$ENV_FILE" | cut -d= -f2-)
    if ask_yesno "Test Postgres reachability now?" "y"; then
        if "$VENV_DIR/bin/python" -c \
            "import psycopg; psycopg.connect('$DB_DSN', connect_timeout=5).close()" \
            2>/dev/null; then
            success "Postgres reachable"
            # WO-H129: reachable is not the same as supported. Ask the server
            # what it is while we have a connection — this is the ONLY check an
            # external/managed database gets before the platform boots.
            REMOTE_PG_VER=$("$VENV_DIR/bin/python" -c \
                "import psycopg
with psycopg.connect('$DB_DSN', connect_timeout=5) as c:
    print(c.execute(\"SHOW server_version\").fetchone()[0])" 2>/dev/null | head -1)
            if [ -n "$REMOTE_PG_VER" ]; then
                case "$(pg_version_verdict "$REMOTE_PG_VER")" in
                    meets)
                        success "Postgres ${REMOTE_PG_VER} meets the required major ${PG_FLOOR}"
                        ;;
                    below)
                        warn "Postgres ${REMOTE_PG_VER} is BELOW the required major ${PG_FLOOR}."
                        warn "On this server migration 0018 cannot backfill"
                        warn "agent_decisions.host, so decision history loses host"
                        warn "correlation with nothing downstream saying so."
                        warn "DHRUVA will REFUSE TO START against an empty database on"
                        warn "this version. Upgrade the server, or point DATABASE_URL"
                        warn "at a PostgreSQL ${PG_FLOOR}+ instance."
                        warn "See docs/POSTGRES-VERSION.md."
                        ;;
                    *)
                        # "unknown". This is a PRE-FLIGHT, not the gate: the
                        # platform itself enforces the floor at boot. So warn
                        # and continue rather than exiting — but never print the
                        # BELOW text, which is what the old single-path form did
                        # to a perfectly supported managed database (F2).
                        warn "Could not verify whether Postgres ${REMOTE_PG_VER} meets"
                        warn "the required major ${PG_FLOOR}: src/database/pg_version.py"
                        warn "could not be run in any form with PYTHON=$PYTHON."
                        warn "NOT treating that as a failure — this is a pre-flight,"
                        warn "and the platform enforces the floor itself at startup."
                        warn "See docs/POSTGRES-VERSION.md."
                        ;;
                esac
            fi
        else
            warn "Postgres unreachable at the given DSN. The schema apply step"
            warn "(later in this script) will retry — fix DATABASE_URL or PG"
            warn "before that step if you want it to succeed."
        fi
    fi
fi

# ─── Step 5: Wazuh Connection ────────────────────────────────────────────────

step 5 "Configuring Wazuh connection"

if [ "$DEPLOY_MODE" = "multi" ]; then
    echo ""
    echo -e "  ${CYAN}ℹ${NC}  We need the Wazuh connection details for your ${BOLD}first client${NC}."
    echo "     This is the Wazuh Manager that monitors this client's environment."
    echo "     You can add more clients later from the dashboard."
    echo ""
else
    info "Enter the Wazuh manager details for this environment."
    echo ""
fi

ask "Wazuh Manager IP/Hostname" WAZUH_HOST ""
ask "Wazuh API Port" WAZUH_PORT "55000"
ask "Wazuh API Username" WAZUH_USER "wazuh-wui"
ask "Wazuh API Password" WAZUH_PASS "" "secret"

if [ -z "$WAZUH_PASS" ]; then
    fail "Wazuh password cannot be empty"
    exit 1
fi

ask "OpenSearch Username" OS_USER "admin"
ask "OpenSearch Password" OS_PASS "" "secret"

if [ -z "$OS_PASS" ]; then
    fail "OpenSearch password cannot be empty"
    exit 1
fi

if ask_yesno "Enable SSL verification for Wazuh/OpenSearch? (recommended for production)" "y"; then
    SSL_VERIFY="true"
    echo ""
    echo -e "  ${BOLD}CA Certificate Setup${NC}"
    echo "    If Wazuh uses self-signed certificates, provide the path to the"
    echo "    root CA certificate file (e.g. /var/ossec/etc/rootCA.pem)."
    echo "    Leave blank if using a trusted public CA."
    echo ""
    read -rp "  CA certificate path [leave blank for system default]: " CA_CERT_PATH
    CA_CERT_PATH=$(echo "$CA_CERT_PATH" | xargs)  # trim whitespace
    if [ -n "$CA_CERT_PATH" ] && [ ! -f "$CA_CERT_PATH" ]; then
        warn "File not found: $CA_CERT_PATH — SSL may fail. You can update ca_cert in config.yaml later."
    fi
else
    SSL_VERIFY="false"
    CA_CERT_PATH=""
    echo ""
    warn "TLS verification for Wazuh/OpenSearch will be DISABLED."
    warn "DHRUVA refuses to start with verify_ssl disabled — it reports an"
    warn "insecure-credential error and exits. Recommended instead: re-run,"
    warn "choose 'y', and supply your Wazuh root CA (e.g. the OpenSearch"
    warn "demo CA, or /etc/wazuh-indexer/certs/root-ca.pem)."
fi

# Write to .env
update_env "WAZUH_API_USER" "$WAZUH_USER"
update_env "WAZUH_API_PASSWORD" "$WAZUH_PASS"
update_env "OPENSEARCH_USER" "$OS_USER"
update_env "OPENSEARCH_PASSWORD" "$OS_PASS"

# Write connection URLs to .env (config.yaml reads these via ${VAR} substitution)
update_env "WAZUH_API_URL" "https://${WAZUH_HOST}"
update_env "OPENSEARCH_URL" "https://${WAZUH_HOST}:9200"

# Write Wazuh API port to config.yaml (not templated via env var)
sed -i "/host:.*WAZUH_API_URL/,+1 s|port: [0-9]*|port: ${WAZUH_PORT}|" "$CONFIG_FILE"
# Update verify_ssl (both occurrences under wazuh and opensearch)
if [ "$SSL_VERIFY" = "true" ]; then
    sed -i "s|verify_ssl: false|verify_ssl: true|g" "$CONFIG_FILE"
else
    sed -i "s|verify_ssl: true|verify_ssl: false|g" "$CONFIG_FILE"
fi
# Update ca_cert paths
if [ -n "$CA_CERT_PATH" ]; then
    sed -i "s|ca_cert: \"\"|ca_cert: \"${CA_CERT_PATH}\"|g" "$CONFIG_FILE"
fi

success "Wazuh connection configured (${WAZUH_HOST}:${WAZUH_PORT})"

# ─── Step 6: Claude AI Backend ───────────────────────────────────────────────

step 6 "Configuring AI backend (LLM provider)"

if [ "$DEPLOY_MODE" = "multi" ]; then
    echo ""
    echo -e "  ${CYAN}ℹ${NC}  This configures the AI backend for your ${BOLD}first client${NC}."
    echo "     Each client can have their own API key. You can set different"
    echo "     keys for other clients later from the dashboard."
    echo ""
fi

echo ""
echo -e "  ${BOLD}Choose your AI provider:${NC}"
echo ""
echo -e "  ${CYAN}1) Anthropic Claude${NC}  (recommended — best accuracy for security analysis)"
echo "     Requires an API key from console.anthropic.com"
echo "     OR a Claude Max subscription with Claude Code CLI installed"
echo ""
echo -e "  ${CYAN}2) OpenAI (GPT-4o)${NC}"
echo "     Requires an API key from platform.openai.com"
echo "     Also works with Azure OpenAI (set base_url in config.yaml after setup)"
echo ""
echo -e "  ${CYAN}3) Ollama (local / self-hosted)${NC}"
echo "     Free, runs on your own hardware. No API key needed."
echo "     Requires Ollama installed with a 70B+ model (e.g. llama3.1:70b)"
echo ""
echo -e "  ${CYAN}4) Groq (cloud Llama)${NC}"
echo "     Fast inference for Llama models. Free tier available."
echo "     Requires an API key from console.groq.com"
echo ""

ask "Enter 1, 2, 3, or 4" LLM_CHOICE "1"

case "$LLM_CHOICE" in
    1)
        LLM_PROVIDER="anthropic"
        echo ""
        echo -e "  ${BOLD}Anthropic Claude can run in two modes:${NC}"
        echo "    a) API Mode  — Requires an API key (faster, ~5s per call)"
        echo "    b) CLI Mode  — Uses Claude Code CLI with Max subscription (~50s per call)"
        echo ""

        ask "Choose mode (api/cli)" CLAUDE_MODE "cli"

        if [ "$CLAUDE_MODE" = "api" ]; then
            ask "Anthropic API Key" API_KEY "" "secret"
            if [ -z "$API_KEY" ]; then
                fail "API key cannot be empty in api mode"
                exit 1
            fi
            update_env "ANTHROPIC_API_KEY" "$API_KEY"
            success "Claude configured in API mode"
        else
            # CLI mode — check if claude is installed
            if command -v claude &>/dev/null; then
                claude_ver=$(claude --version 2>&1 || echo "unknown")
                success "Claude CLI found: $claude_ver"
            else
                warn "Claude CLI not found. Installing..."
                if command -v npm &>/dev/null; then
                    npm install -g @anthropic-ai/claude-code
                    success "Claude Code CLI installed"
                else
                    fail "npm not found. Install Node.js first, then: npm install -g @anthropic-ai/claude-code"
                    exit 1
                fi
            fi

            # Check if logged in
            info "Testing Claude CLI authentication..."
            if claude -p "respond with OK" --output-format text 2>/dev/null | grep -qi "ok"; then
                success "Claude CLI authenticated and working"
            else
                warn "Claude CLI may not be authenticated."
                echo ""
                echo -e "  ${YELLOW}Please run the following command to log in:${NC}"
                echo -e "  ${BOLD}  claude login${NC}"
                echo ""
                if ask_yesno "Run 'claude login' now?" "y"; then
                    claude login
                    success "Claude login completed"
                else
                    warn "Skipped — make sure to run 'claude login' before starting the platform"
                fi
            fi

            update_env "ANTHROPIC_API_KEY" ""
            success "Claude configured in CLI mode"
        fi
        ;;
    2)
        LLM_PROVIDER="openai"
        ask "OpenAI API Key" OPENAI_KEY "" "secret"
        if [ -z "$OPENAI_KEY" ]; then
            fail "API key cannot be empty"
            exit 1
        fi
        update_env "OPENAI_API_KEY" "$OPENAI_KEY"

        ask "Model name" OPENAI_MODEL "gpt-4o"
        sed -i "s|model: \"gpt-4o\"|model: \"${OPENAI_MODEL}\"|" "$CONFIG_FILE"

        echo ""
        info "Custom base URL — leave blank for api.openai.com."
        info "Examples: http://litellm.example.com:4000/v1  |  https://<resource>.openai.azure.com"
        ask "OpenAI base URL (optional)" OPENAI_BASE ""

        success "OpenAI configured (model: ${OPENAI_MODEL}${OPENAI_BASE:+, base_url: ${OPENAI_BASE}})"
        ;;
    3)
        LLM_PROVIDER="ollama"
        ask "Ollama base URL" OLLAMA_URL "http://localhost:11434"
        ask "Model name" OLLAMA_MODEL "llama3.1:70b"

        sed -i "s|base_url: \"http://localhost:11434\"|base_url: \"${OLLAMA_URL}\"|" "$CONFIG_FILE"
        sed -i "s|model: \"llama3.1:70b\"|model: \"${OLLAMA_MODEL}\"|" "$CONFIG_FILE"

        # Test connectivity
        info "Testing Ollama at ${OLLAMA_URL}..."
        ollama_resp=$(curl -s -o /dev/null -w "%{http_code}" "${OLLAMA_URL}/api/tags" 2>/dev/null || echo "000")
        if [ "$ollama_resp" = "200" ]; then
            success "Ollama is reachable"
        else
            warn "Ollama not reachable at ${OLLAMA_URL} (HTTP ${ollama_resp}) — make sure it's running before starting the platform"
        fi

        success "Ollama configured (model: ${OLLAMA_MODEL})"
        ;;
    4)
        LLM_PROVIDER="groq"
        ask "Groq API Key" GROQ_KEY "" "secret"
        if [ -z "$GROQ_KEY" ]; then
            fail "API key cannot be empty"
            exit 1
        fi
        update_env "GROQ_API_KEY" "$GROQ_KEY"

        ask "Model name" GROQ_MODEL "llama-3.1-70b-versatile"
        sed -i "s|model: \"llama-3.1-70b-versatile\"|model: \"${GROQ_MODEL}\"|" "$CONFIG_FILE"

        success "Groq configured (model: ${GROQ_MODEL})"
        ;;
    *)
        fail "Invalid choice. Run deploy.sh again."
        exit 1
        ;;
esac

# Set the provider in config.yaml
sed -i "s|provider: \"anthropic\"|provider: \"${LLM_PROVIDER}\"|" "$CONFIG_FILE"
info "LLM provider set to: ${LLM_PROVIDER}"

# Always write OPENAI_BASE_URL (possibly empty) so the ${OPENAI_BASE_URL}
# template in config.yaml resolves cleanly even when OpenAI is not the
# selected provider. Without this, _resolve_env_vars logs an unresolved-var
# warning at startup.
update_env "OPENAI_BASE_URL" "${OPENAI_BASE:-}"

# ─── Step 7: Dashboard Credentials ───────────────────────────────────────────

step 7 "Dashboard credentials and HTTPS"

if [ "$DEPLOY_MODE" = "multi" ]; then
    echo ""
    echo -e "  ${CYAN}ℹ${NC}  In multi-tenant mode, your admin account is a ${BOLD}master account${NC}."
    echo "     It can create and manage all client organizations, switch between"
    echo "     them, and see everything. Client-specific analysts are created"
    echo "     later from the Admin tab in the dashboard."
    echo ""
fi

ask "Dashboard admin username" ADMIN_USER "admin"
ask "Dashboard admin password" ADMIN_PASS "" "secret"

if [ -z "$ADMIN_PASS" ]; then
    fail "Admin password cannot be empty"
    exit 1
fi

if [ ${#ADMIN_PASS} -lt 8 ]; then
    warn "Password is short. Recommend 12+ characters for production."
fi

update_env "SOC_ADMIN_USER" "$ADMIN_USER"
update_env "SOC_ADMIN_PASSWORD" "$ADMIN_PASS"

# JWT signing secret — generate only if absent so re-running deploy.sh does not
# rotate the key and log out every session. Rotate deliberately with
# --rotate-jwt. See docs/KEY-ROTATION.md.
ensure_secret "JWT_SECRET" '$PYTHON -c "import secrets; print(secrets.token_hex(32))"' "JWT secret"

# Anonymization salt for persistent LLM prompt anonymization — generate only if
# absent so re-runs keep anonymization tokens consistent. Rotate deliberately
# with --rotate-salt. See docs/KEY-ROTATION.md.
ensure_secret "ANONYMIZATION_SALT" '$PYTHON -c "import secrets; print(secrets.token_hex(32))"' "anonymization salt"

# Tenant master encryption key — needed in EVERY mode, not just multi-tenant
# (WO-H75). A single-tenant install still writes an encrypted tenant row on
# first boot (main.py::_seed_default_tenant) and whenever the Admin tab edits
# the tenant config. Without a persisted key those writes now fail closed
# instead of being stored under a process-local key nothing can decrypt after
# a restart. Generate only if absent; rotate deliberately with
# --rotate-tenant-key (or, safely, tools/rotate_tenant_key.py).
ensure_secret "TENANT_ENCRYPTION_KEY" '$PYTHON -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"' "tenant encryption key"

if [ "$DEPLOY_MODE" = "multi" ]; then
    update_env "SOC_ADMIN_ROLE" "mssp_admin"
    success "Master admin account configured (role: mssp_admin)"
else
    update_env "SOC_ADMIN_ROLE" "admin"
    success "Dashboard credentials configured"
fi

# Multi-tenant: generate encryption key and collect first tenant info
if [ "$DEPLOY_MODE" = "multi" ]; then
    echo ""
    echo -e "  ${BOLD}Encryption Key${NC}"
    echo -e "  ${CYAN}ℹ${NC}  Each client's credentials (Wazuh passwords, API keys, webhooks) are"
    echo "     encrypted before being stored in the database. This encryption key"
    echo "     protects all of them. It is generated automatically."
    echo ""
    # Tenant master encryption key — generate only if absent. Regenerating this
    # makes ALL existing tenant configs undecryptable, so a re-run must PRESERVE
    # it. Rotate safely with tools/rotate_tenant_key.py (docs/KEY-ROTATION.md);
    # --rotate-tenant-key here is a destructive last resort.
    # (WO-H75: the generate/preserve call now runs for EVERY mode in step 7
    # above — this branch keeps the multi-tenant explanation and backup
    # warning, where the blast radius is every client at once.)
    warn "Back up your .env file securely — if this key is lost, client configs cannot be decrypted."
    echo ""

    echo -e "  ${BOLD}First Client Setup${NC}"
    echo -e "  ${CYAN}ℹ${NC}  Let's give your first client a name. This is the organization whose"
    echo "     Wazuh and Claude details you just entered above."
    echo "     You can add more clients later from the Admin tab in the dashboard."
    echo ""
    ask "Client organization name (e.g. Acme Corp)" FIRST_TENANT_NAME ""
    if [ -z "$FIRST_TENANT_NAME" ]; then
        FIRST_TENANT_NAME="Default Client"
    fi

    # Auto-generate slug from name
    FIRST_TENANT_SLUG=$(echo "$FIRST_TENANT_NAME" | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | tr -cd 'a-z0-9-' | head -c 50)
    if [ -z "$FIRST_TENANT_SLUG" ]; then
        FIRST_TENANT_SLUG="default-client"
    fi

    update_env "FIRST_TENANT_NAME" "$FIRST_TENANT_NAME"
    update_env "FIRST_TENANT_SLUG" "$FIRST_TENANT_SLUG"
    update_env "DEPLOYMENT_MODE" "multi_tenant"
    success "First client: ${FIRST_TENANT_NAME} (${FIRST_TENANT_SLUG})"
else
    update_env "DEPLOYMENT_MODE" "single_tenant"
fi

# Optional: CORS origin
echo ""
ask "Dashboard access URL/domain for CORS (or press Enter to skip)" CORS_ORIGIN ""
if [ -n "$CORS_ORIGIN" ]; then
    sed -i "s|\"https://soc.securesleuths.local\"|\"${CORS_ORIGIN}\"|" "$CONFIG_FILE"
    success "CORS origin set to ${CORS_ORIGIN}"
fi

# ─── Dashboard HTTPS / TLS ───────────────────────────────────────────────────
# DHRUVA refuses to start on a non-loopback bind without TLS, so the dashboard
# must have a certificate (or a loopback-only bind) wired in before first boot.
echo ""
echo -e "  ${BOLD}Dashboard HTTPS${NC}"
echo -e "  ${CYAN}ℹ${NC}  DHRUVA will not start on a public address without TLS."
echo ""
echo -e "  ${CYAN}1) Auto-generate a self-signed certificate${NC}  (recommended)"
echo "     Works immediately; browsers show a one-time warning you accept."
echo -e "  ${CYAN}2) Use my own certificate${NC}"
echo "     Provide paths to an existing PEM certificate and private key."
echo -e "  ${CYAN}3) Loopback only${NC}  (I run my own reverse proxy)"
echo "     Binds 127.0.0.1; terminate TLS at nginx/Caddy in front."
echo ""
ask "Enter 1, 2, or 3" TLS_CHOICE "1"

DASH_SCHEME="https"
DASH_HOST="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -z "$DASH_HOST" ] && DASH_HOST="$(hostname)"
CERT_DIR="$INSTALL_DIR/certs"

# Insert (or replace) the api.ssl block in config.yaml, idempotently.
apply_api_ssl() {
    "$PYTHON" - "$CONFIG_FILE" "$1" "$2" <<'PYEOF'
import re, sys
path, cert, key = sys.argv[1], sys.argv[2], sys.argv[3]
lines = open(path).read().splitlines()
out, i, n = [], 0, len(lines)
while i < n:
    if re.match(r'^api:\s*$', lines[i]):
        out.append(lines[i]); i += 1
        while i < n and (lines[i][:1] in (' ', '\t') or lines[i].strip() == ''):
            if re.match(r'^\s+ssl:\s*$', lines[i]):          # drop a stale ssl: block
                i += 1
                while i < n and re.match(r'^\s{3,}\S', lines[i]):
                    i += 1
                continue
            out.append(lines[i]); i += 1
        out += ['  ssl:', '    certfile: "%s"' % cert, '    keyfile: "%s"' % key]
        continue
    out.append(lines[i]); i += 1
open(path, 'w').write('\n'.join(out) + '\n')
PYEOF
}

case "$TLS_CHOICE" in
    2)
        ask "Path to TLS certificate (PEM)" TLS_CERT ""
        ask "Path to TLS private key (PEM)" TLS_KEY ""
        if [ -f "$TLS_CERT" ] && [ -f "$TLS_KEY" ]; then
            apply_api_ssl "$TLS_CERT" "$TLS_KEY"
            success "Dashboard HTTPS configured with your certificate"
        else
            warn "Certificate or key not found — falling back to a self-signed cert."
            TLS_CHOICE=1
        fi
        ;;
    3)
        sed -i '/^api:/,/^[^[:space:]]/ s/^\([[:space:]]*host:\).*/\1 127.0.0.1/' "$CONFIG_FILE"
        DASH_SCHEME="http"; DASH_HOST="127.0.0.1"
        success "Dashboard bound to 127.0.0.1 — terminate TLS at your reverse proxy"
        ;;
esac

if [ "$TLS_CHOICE" = "1" ]; then
    if command -v openssl &>/dev/null; then
        mkdir -p "$CERT_DIR"
        openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
            -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
            -subj "/CN=${DASH_HOST}" >/dev/null 2>&1
        chmod 600 "$CERT_DIR/key.pem"
        apply_api_ssl "$CERT_DIR/cert.pem" "$CERT_DIR/key.pem"
        success "Self-signed certificate generated and wired into config.yaml"
    else
        warn "OpenSSL not available — cannot auto-generate a certificate."
        warn "Binding to 127.0.0.1 instead; put a reverse proxy in front for TLS."
        sed -i '/^api:/,/^[^[:space:]]/ s/^\([[:space:]]*host:\).*/\1 127.0.0.1/' "$CONFIG_FILE"
        DASH_SCHEME="http"; DASH_HOST="127.0.0.1"
    fi
fi

# ─── Step 8: Data Directories ────────────────────────────────────────────────

step 8 "Creating data directories"

if [ ! -d "$DATA_DIR" ]; then
    sudo mkdir -p "$DATA_DIR"
    sudo chown "$CURRENT_USER:$CURRENT_USER" "$DATA_DIR"
    success "Created $DATA_DIR"
else
    success "$DATA_DIR already exists"
fi

# Create empty config files if missing
for f in assets.yaml identities.yaml local_iocs.yaml; do
    fpath="$DATA_DIR/$f"
    if [ ! -f "$fpath" ]; then
        echo "# Auto-generated by deploy.sh — customize for this client" > "$fpath"
        success "Created $fpath"
    fi
done

# Create detection rules dir
if [ ! -d "$DATA_DIR/detection-rules" ]; then
    mkdir -p "$DATA_DIR/detection-rules"
    success "Created detection-rules directory"
fi

# ─── Step 9: Connectivity Tests ──────────────────────────────────────────────

step 9 "Testing connectivity"

# Test Wazuh API
info "Testing Wazuh API at ${WAZUH_HOST}:${WAZUH_PORT}..."
ssl_flag=""
[ "$SSL_VERIFY" = "false" ] && ssl_flag="-k"

wazuh_resp=$(curl -s -o /dev/null -w "%{http_code}" $ssl_flag \
    -u "${WAZUH_USER}:${WAZUH_PASS}" \
    "https://${WAZUH_HOST}:${WAZUH_PORT}/" 2>/dev/null || echo "000")

if [ "$wazuh_resp" = "200" ] || [ "$wazuh_resp" = "401" ]; then
    # 401 means API is reachable but needs JWT auth (normal for Wazuh 4.x)
    if [ "$wazuh_resp" = "401" ]; then
        # Try JWT auth flow
        token=$(curl -s $ssl_flag -u "${WAZUH_USER}:${WAZUH_PASS}" \
            -X POST "https://${WAZUH_HOST}:${WAZUH_PORT}/security/user/authenticate" 2>/dev/null \
            | $PYTHON -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('token',''))" 2>/dev/null || echo "")
        if [ -n "$token" ] && [ "$token" != "" ]; then
            success "Wazuh API: connected and authenticated"
        else
            warn "Wazuh API: reachable but authentication failed — check credentials"
        fi
    else
        success "Wazuh API: connected (HTTP $wazuh_resp)"
    fi
else
    fail "Wazuh API: unreachable (HTTP $wazuh_resp) — check IP/port/firewall"
fi

# Test OpenSearch
info "Testing OpenSearch at ${WAZUH_HOST}:9200..."
os_resp=$(curl -s -o /dev/null -w "%{http_code}" $ssl_flag \
    -u "${OS_USER}:${OS_PASS}" \
    "https://${WAZUH_HOST}:9200/_cluster/health" 2>/dev/null || echo "000")

if [ "$os_resp" = "200" ]; then
    success "OpenSearch: connected (HTTP $os_resp)"
elif [ "$os_resp" = "401" ]; then
    fail "OpenSearch: reachable but authentication failed — check credentials"
else
    fail "OpenSearch: unreachable (HTTP $os_resp) — check IP/port/firewall"
fi

# ─── Step 10: Optional Threat Intel ───────────────────────────────────────────

step 10 "Threat Intelligence (optional)"

if ask_yesno "Configure AbuseIPDB API key?" "n"; then
    ask "AbuseIPDB API Key" ABUSE_KEY "" "secret"
    update_env "ABUSEIPDB_API_KEY" "$ABUSE_KEY"
    success "AbuseIPDB configured"
fi

if ask_yesno "Configure AlienVault OTX API key?" "n"; then
    ask "OTX API Key" OTX_KEY "" "secret"
    update_env "OTX_API_KEY" "$OTX_KEY"
    success "OTX configured"
fi

if ask_yesno "Configure VirusTotal API key?" "n"; then
    ask "VirusTotal API Key" VT_KEY "" "secret"
    update_env "VIRUSTOTAL_API_KEY" "$VT_KEY"
    success "VirusTotal configured"
fi

# ─── Step 11: Notifications (Slack / Email) ──────────────────────────────────

step 11 "Notification Integrations (optional)"

echo ""
echo -e "  ${BOLD}Notifications alert your team when:${NC}"
echo "    - Critical/high incidents are auto-created"
echo "    - Incidents are assigned to an analyst"
echo "    - Incidents are escalated or resolved"
echo ""
if [ "$DEPLOY_MODE" = "multi" ]; then
    echo -e "  ${CYAN}ℹ${NC}  These notifications apply to your ${BOLD}first client${NC}."
    echo "     You can set up different Slack channels and email recipients"
    echo "     for each client later from the dashboard."
    echo ""
fi

NOTIF_ENABLED="false"

# Slack
if ask_yesno "Configure Slack notifications?" "n"; then
    ask "Slack Webhook URL" SLACK_URL ""
    if [ -n "$SLACK_URL" ]; then
        update_env "SLACK_WEBHOOK_URL" "$SLACK_URL"
        NOTIF_ENABLED="true"
        success "Slack webhook configured"

        ask "Slack channel override (leave blank for webhook default)" SLACK_CHAN ""
        if [ -n "$SLACK_CHAN" ]; then
            sed -i "s|channel: \"\".*|channel: \"${SLACK_CHAN}\"|" "$CONFIG_FILE"
        fi
    else
        warn "No Slack URL provided — skipped"
    fi
fi

# Email / SMTP
if ask_yesno "Configure Email (SMTP) notifications?" "n"; then
    ask "SMTP Host" SMTP_HOST_VAL ""
    if [ -n "$SMTP_HOST_VAL" ]; then
        ask "SMTP Port" SMTP_PORT_VAL "587"
        ask "SMTP Username (or press Enter if no auth)" SMTP_USER_VAL ""
        if [ -n "$SMTP_USER_VAL" ]; then
            ask "SMTP Password" SMTP_PASS_VAL "" "secret"
        fi
        ask "From Address (e.g. soc@company.com)" SMTP_FROM_VAL ""
        ask "Recipient emails (comma-separated)" SMTP_RCPTS ""

        update_env "SMTP_HOST" "$SMTP_HOST_VAL"
        update_env "SMTP_USER" "${SMTP_USER_VAL:-}"
        update_env "SMTP_PASSWORD" "${SMTP_PASS_VAL:-}"
        update_env "SMTP_FROM" "$SMTP_FROM_VAL"

        # Update SMTP port in config
        sed -i "s|smtp_port: [0-9]*|smtp_port: ${SMTP_PORT_VAL}|" "$CONFIG_FILE"

        # Convert comma-separated recipients to YAML list
        if [ -n "$SMTP_RCPTS" ]; then
            RCPT_YAML=""
            IFS=',' read -ra ADDR <<< "$SMTP_RCPTS"
            for addr in "${ADDR[@]}"; do
                addr="$(echo "$addr" | xargs)"
                RCPT_YAML="${RCPT_YAML}\n      - \"${addr}\""
            done
            sed -i "s|recipients: \[\].*|recipients:${RCPT_YAML}|" "$CONFIG_FILE"
        fi

        NOTIF_ENABLED="true"
        success "Email/SMTP configured (${SMTP_HOST_VAL}:${SMTP_PORT_VAL})"
    else
        warn "No SMTP host provided — skipped"
    fi
fi

# Enable notifications if any channel was configured
if [ "$NOTIF_ENABLED" = "true" ]; then
    sed -i "s|  enabled: false.*# Set to true|  enabled: true   # Set to true|" "$CONFIG_FILE"
    success "Notifications enabled"
else
    info "No notification channels configured — can be added later in config.yaml"
fi

# ─── Step 12: Ticketing Integration (optional) ─────────────────────────────

step 12 "Ticketing Integration (optional)"

echo ""
echo -e "  ${BOLD}Connect to your ticketing system so incidents auto-create tickets:${NC}"
echo ""
echo -e "  ${CYAN}1) Jira${NC}          (Jira Cloud or Server)"
echo -e "  ${CYAN}2) ServiceNow${NC}    (ITSM incident table)"
echo -e "  ${CYAN}3) PagerDuty${NC}     (Incident alerting)"
echo -e "  ${CYAN}s) Skip${NC}          (configure later in config.yaml)"
echo ""

ask "Enter 1, 2, 3, or s" TICKET_CHOICE "s"

case "$TICKET_CHOICE" in
    1)
        TICKET_PROVIDER="jira"
        ask "Jira base URL (e.g. https://yourorg.atlassian.net)" JIRA_URL ""
        ask "Jira email" JIRA_EMAIL_VAL ""
        ask "Jira API token" JIRA_TOKEN "" "secret"
        ask "Jira project key" JIRA_PROJECT "SOC"

        update_env "JIRA_EMAIL" "$JIRA_EMAIL_VAL"
        update_env "JIRA_API_TOKEN" "$JIRA_TOKEN"
        ensure_webhook_secret "JIRA_WEBHOOK_SECRET"
        sed -i "s|provider: \"\".*# \"jira\"|provider: \"jira\"     # \"jira\"|" "$CONFIG_FILE"
        sed -i "s|base_url: \"\".*# e.g.|base_url: \"${JIRA_URL}\"   # e.g.|" "$CONFIG_FILE"
        sed -i "s|project_key: \"SOC\"|project_key: \"${JIRA_PROJECT}\"|" "$CONFIG_FILE"
        sed -i "s|enabled: false|enabled: true|" "$CONFIG_FILE"  # ticketing.enabled

        success "Jira configured (${JIRA_URL}, project: ${JIRA_PROJECT})"
        ;;
    2)
        TICKET_PROVIDER="servicenow"
        ask "ServiceNow instance URL (e.g. https://yourorg.service-now.com)" SNOW_URL ""
        ask "ServiceNow username" SNOW_USER ""
        ask "ServiceNow password" SNOW_PASS "" "secret"
        ask "Assignment group (optional)" SNOW_GROUP ""

        update_env "SERVICENOW_USER" "$SNOW_USER"
        update_env "SERVICENOW_PASSWORD" "$SNOW_PASS"
        ensure_webhook_secret "SERVICENOW_WEBHOOK_SECRET"
        sed -i "s|provider: \"\".*# \"jira\"|provider: \"servicenow\" # \"jira\"|" "$CONFIG_FILE"
        sed -i "s|instance_url: \"\".*# e.g.|instance_url: \"${SNOW_URL}\" # e.g.|" "$CONFIG_FILE"
        if [ -n "$SNOW_GROUP" ]; then
            sed -i "s|assignment_group: \"\"|assignment_group: \"${SNOW_GROUP}\"|" "$CONFIG_FILE"
        fi

        success "ServiceNow configured (${SNOW_URL})"
        ;;
    3)
        TICKET_PROVIDER="pagerduty"
        ask "PagerDuty routing key (Events API v2)" PD_ROUTING "" "secret"
        ask "PagerDuty API token (optional, for bi-directional sync)" PD_TOKEN "" "secret"
        ask "PagerDuty service ID" PD_SVC ""

        update_env "PAGERDUTY_ROUTING_KEY" "$PD_ROUTING"
        update_env "PAGERDUTY_API_TOKEN" "$PD_TOKEN"
        ensure_webhook_secret "PAGERDUTY_WEBHOOK_SECRET"
        sed -i "s|provider: \"\".*# \"jira\"|provider: \"pagerduty\" # \"jira\"|" "$CONFIG_FILE"
        if [ -n "$PD_SVC" ]; then
            sed -i "s|service_id: \"\"|service_id: \"${PD_SVC}\"|" "$CONFIG_FILE"
        fi

        success "PagerDuty configured"
        ;;
    *)
        info "Ticketing skipped — can be enabled later in config.yaml"
        ;;
esac

# ─── Step 13: Apply Postgres Schema ──────────────────────────────────────────

step 13 "Applying Postgres schema (alembic upgrade head)"

echo ""
echo -e "  ${CYAN}ℹ${NC}  v4.9.0's boot gate refuses to start the platform if the"
echo "     schema hasn't been applied. This step runs main.py --migrate,"
echo "     which is idempotent — safe to re-run on every upgrade."
echo ""

if ask_yesno "Apply the Postgres schema now?" "y"; then
    if [[ ! -x "$VENV_DIR/bin/python" ]]; then
        fail "Virtualenv not found at $VENV_DIR — Step 2 must have failed."
        fail "Fix Python deps and re-run this script before starting the service."
    elif ( set -a; source "$ENV_FILE"; set +a; \
           "$VENV_DIR/bin/python" "$INSTALL_DIR/main.py" --migrate ); then
        success "Schema applied"
    else
        fail "Schema migration failed. Common causes:"
        fail "  • DATABASE_URL points at an unreachable host"
        fail "  • Credentials wrong"
        fail "  • Database role lacks CREATE TABLE on the target DB"
        fail ""
        fail "Fix the cause, then re-run manually before starting the service:"
        fail "  cd $INSTALL_DIR && \\"
        fail "    \$( grep -v '^#' .env | xargs -I{} echo export {} ) && \\"
        fail "    $VENV_DIR/bin/python main.py --migrate"
    fi
else
    warn "Schema NOT applied. The systemd service will fail to start until"
    warn "you run:  $VENV_DIR/bin/python main.py --migrate"
fi

# ─── Step 14: Systemd Service ────────────────────────────────────────────────

step 14 "System service setup"

if ask_yesno "Install as a systemd service (auto-start on boot)?" "y"; then
    # Build PATH: include NVM node path if it exists (for claude CLI)
    SVC_PATH="${VENV_DIR}/bin:/usr/local/bin:/usr/bin:/bin"
    if command -v node &>/dev/null; then
        NODE_BIN="$(dirname "$(command -v node)")"
        SVC_PATH="${VENV_DIR}/bin:${NODE_BIN}:/usr/local/bin:/usr/bin:/bin"
    fi
    sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null << SVCEOF
[Unit]
Description=SecureSleuths AI SOC Platform
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${CURRENT_USER}
Group=${CURRENT_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${ENV_FILE}
Environment=PATH=${SVC_PATH}
ExecStart=${VENV_DIR}/bin/python main.py config/config.yaml
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=${DATA_DIR} ${INSTALL_DIR}
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
SVCEOF

    sudo systemctl daemon-reload
    sudo systemctl enable ${SERVICE_NAME}
    success "Systemd service installed and enabled"

    if ask_yesno "Start the service now?" "y"; then
        sudo systemctl start ${SERVICE_NAME}
        sleep 3
        if sudo systemctl is-active --quiet ${SERVICE_NAME}; then
            success "Service is running"
        else
            fail "Service failed to start. Check: sudo journalctl -u ${SERVICE_NAME} -n 50"
        fi
    fi
else
    info "Skipped. Start manually with:"
    echo -e "    ${BOLD}source venv/bin/activate && python main.py config/config.yaml${NC}"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}${BOLD}"
echo "  ┌─────────────────────────────────────────────────┐"
echo "  │          Deployment Complete                     │"
echo "  └─────────────────────────────────────────────────┘"
echo -e "${NC}"

DASH_PORT=$(grep -A4 "^api:" "$CONFIG_FILE" | grep -m1 "port:" | awk '{print $2}')
DASH_PORT="${DASH_PORT:-8443}"
echo -e "  ${BOLD}Dashboard:${NC}       ${DASH_SCHEME:-https}://${DASH_HOST:-$(hostname -I | awk '{print $1}')}:${DASH_PORT}"
echo -e "  ${BOLD}Login:${NC}           ${ADMIN_USER} / ********"
echo -e "  ${BOLD}Mode:${NC}            $([ "$DEPLOY_MODE" = "multi" ] && echo "Multi-Tenant" || echo "Single-Tenant")"
if [ "$DEPLOY_MODE" = "multi" ]; then
echo -e "  ${BOLD}Admin Role:${NC}      mssp_admin (master account)"
echo -e "  ${BOLD}First Client:${NC}    ${FIRST_TENANT_NAME}"
fi
echo -e "  ${BOLD}Wazuh:${NC}           ${WAZUH_HOST}:${WAZUH_PORT}"
echo -e "  ${BOLD}AI Provider:${NC}     ${LLM_PROVIDER}$([ "${LLM_PROVIDER}" = "anthropic" ] && echo " (${CLAUDE_MODE:-api})")"
if [ "$NOTIF_ENABLED" = "true" ]; then
    NOTIF_CHANNELS=""
    [ -n "${SLACK_URL:-}" ] && NOTIF_CHANNELS="Slack"
    [ -n "${SMTP_HOST_VAL:-}" ] && NOTIF_CHANNELS="${NOTIF_CHANNELS:+$NOTIF_CHANNELS + }Email"
    echo -e "  ${BOLD}Notifications:${NC}   ${NOTIF_CHANNELS}"
else
    echo -e "  ${BOLD}Notifications:${NC}   Not configured"
fi
echo -e "  ${BOLD}Data Dir:${NC}        ${DATA_DIR}"
echo -e "  ${BOLD}Config:${NC}          ${CONFIG_FILE}"
echo -e "  ${BOLD}Logs:${NC}            sudo journalctl -u ${SERVICE_NAME} -f"
echo ""
echo -e "  ${BOLD}Useful commands:${NC}"
echo "    sudo systemctl status ${SERVICE_NAME}     # Check status"
echo "    sudo systemctl restart ${SERVICE_NAME}    # Restart"
echo "    sudo systemctl stop ${SERVICE_NAME}       # Stop"
echo "    sudo journalctl -u ${SERVICE_NAME} -f     # Live logs"
echo ""
echo -e "  ${YELLOW}Post-deployment checklist:${NC}"
echo "    [ ] Open dashboard and verify login works"
echo "    [ ] Check Overview tab shows alert stats"
echo "    [ ] Go to Investigate tab, ask: 'What alerts fired in the last hour?'"
echo "    [ ] Go to Respond tab, verify agents are listed"
echo "    [ ] Click an agent to verify vulnerability/process data loads"
if [ "$DEPLOY_MODE" = "multi" ]; then
echo ""
echo -e "  ${YELLOW}Multi-tenant next steps:${NC}"
echo "    [ ] Log in with your master admin account"
echo "    [ ] Verify your first client's data appears in Overview"
echo "    [ ] To add more clients: go to Admin tab > Manage Tenants > Add Tenant"
echo "    [ ] To create client-specific analysts: go to Admin tab > Manage Users"
echo "    [ ] Use the tenant dropdown (top-right) to switch between clients"
fi
echo ""
echo -e "  ${CYAN}💡 New Features Available:${NC}"
echo "    🚀 Run './deploy.sh' with option 1 for the Interactive Wizard"
echo "    📡 Real-time webhook alert ingestion (faster than API polling)"
echo "    🤖 Multi-tenant LLM providers (different AI keys per client)"
echo "    📊 Per-tenant usage analytics and cost tracking"
echo "    🔐 Enhanced security with HMAC signature validation"
echo ""
echo -e "  ${YELLOW}To enable advanced features:${NC}"
echo "    [ ] Re-run: ./deploy.sh and choose option 1 (Interactive Wizard)"
echo "    [ ] Or configure manually: see docs/MULTI-TENANT.md"
echo ""
