#!/bin/sh
# =============================================================================
# SecureSleuths DHRUVA — Docker Entrypoint
# Auto-generates secrets if not provided via .env, then starts the platform.
# =============================================================================
set -e

# Generate JWT secret if not provided (ephemeral — set in .env for persistence)
if [ -z "$JWT_SECRET" ]; then
    export JWT_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")
    echo "[entrypoint] Generated ephemeral JWT_SECRET (set JWT_SECRET in .env for persistence across restarts)"
fi

# Generate anonymization salt if not provided
if [ -z "$ANONYMIZATION_SALT" ]; then
    export ANONYMIZATION_SALT=$(python -c "import secrets; print(secrets.token_hex(32))")
    echo "[entrypoint] Generated ephemeral ANONYMIZATION_SALT (set ANONYMIZATION_SALT in .env for persistence)"
fi

# Default build profile to auto so Community mode is selected automatically
# when no license file is present.
if [ -z "$DHRUVA_BUILD_PROFILE" ]; then
    export DHRUVA_BUILD_PROFILE=auto
    echo "[entrypoint] Defaulted DHRUVA_BUILD_PROFILE=auto"
fi

# Ensure the dashboard can serve HTTPS. DHRUVA refuses to start on a public
# bind without TLS. config.yaml is usually mounted read-only, so instead of
# editing it in place we generate a persistent self-signed cert in the data
# volume and run from an "effective" config derived next to it.
CONFIG_SRC="${1:-config/config.yaml}"
if [ -f "$CONFIG_SRC" ] && ! grep -qE '^[[:space:]]+ssl:[[:space:]]*$' "$CONFIG_SRC"; then
    CERT_DIR=/var/lib/ai-soc/certs
    mkdir -p "$CERT_DIR"
    if [ ! -f "$CERT_DIR/cert.pem" ] || [ ! -f "$CERT_DIR/key.pem" ]; then
        openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
            -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
            -subj "/CN=dhruva" >/dev/null 2>&1
        chmod 600 "$CERT_DIR/key.pem"
        echo "[entrypoint] Generated self-signed dashboard certificate in $CERT_DIR"
    fi
    EFFECTIVE_CONFIG=/var/lib/ai-soc/effective-config.yaml
    if python - "$CONFIG_SRC" "$EFFECTIVE_CONFIG" "$CERT_DIR/cert.pem" "$CERT_DIR/key.pem" <<'PYEOF'
import re, sys
src, dst, cert, key = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
lines = open(src).read().splitlines()
out, i, n = [], 0, len(lines)
while i < n:
    if re.match(r'^api:\s*$', lines[i]):
        out.append(lines[i]); i += 1
        while i < n and (lines[i][:1] in (' ', '\t') or lines[i].strip() == ''):
            if re.match(r'^\s+ssl:\s*$', lines[i]):
                i += 1
                while i < n and re.match(r'^\s{3,}\S', lines[i]):
                    i += 1
                continue
            out.append(lines[i]); i += 1
        out += ['  ssl:', '    certfile: "%s"' % cert, '    keyfile: "%s"' % key]
        continue
    out.append(lines[i]); i += 1
open(dst, 'w').write('\n'.join(out) + '\n')
PYEOF
    then
        echo "[entrypoint] Dashboard HTTPS enabled (effective config: $EFFECTIVE_CONFIG)"
        set -- "$EFFECTIVE_CONFIG"
    else
        echo "[entrypoint] WARNING: could not build effective config; continuing with $CONFIG_SRC"
    fi
fi

# Apply pending Postgres migrations. Idempotent — alembic skips already-
# applied revisions. Refuses to start if DATABASE_URL is unset (v4.9.0
# requires Postgres). Schema-init only; safe to re-run on every container
# boot. See docs/MIGRATION-FROM-SQLITE.md for first-time setup.
if [ -z "$DATABASE_URL" ]; then
    echo "[entrypoint] ERROR: DATABASE_URL is not set. v4.9.0 requires a"
    echo "[entrypoint]        Postgres connection — see docs/MIGRATION-FROM-SQLITE.md."
    exit 1
fi

# Wait for the DB to be reachable. Matters in split-host installs where
# the app container can boot before the network path to the DB host is
# usable, or where a managed Postgres is briefly cold-starting. Bounded
# retry (default ~60s) so a permanently misconfigured DSN still fails
# instead of hanging the container forever.
RETRY_MAX=${DB_RETRY_MAX:-30}
RETRY_SLEEP=${DB_RETRY_SLEEP:-2}
echo "[entrypoint] Waiting for Postgres (max ${RETRY_MAX} attempts, ${RETRY_SLEEP}s apart)..."
i=1
while [ "$i" -le "$RETRY_MAX" ]; do
    if python -c "import os, psycopg, sys
try:
    with psycopg.connect(os.environ['DATABASE_URL'], connect_timeout=3) as c:
        c.execute('SELECT 1')
except Exception as e:
    sys.exit(1)" >/dev/null 2>&1; then
        echo "[entrypoint] Postgres reachable after ${i} attempt(s)."
        break
    fi
    if [ "$i" -eq "$RETRY_MAX" ]; then
        echo "[entrypoint] ERROR: Postgres unreachable after ${RETRY_MAX} attempts."
        echo "[entrypoint]        Check DATABASE_URL and network reachability."
        exit 1
    fi
    sleep "$RETRY_SLEEP"
    i=$((i + 1))
done

echo "[entrypoint] Applying database migrations..."
if ! python main.pyc --migrate; then
    echo "[entrypoint] ERROR: alembic upgrade failed — aborting boot."
    exit 1
fi

exec python main.pyc "$@"
