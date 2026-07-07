# DHRUVA 5.0.0 — Community Edition

AI-augmented security operations layer for Wazuh SIEM. This package ships
plaintext Python source; deploy via either the bash installer or Docker.

Community edition — no license key required. Paid modules (Detection Agent, Hunt Agent, SOAR, ticketing, reporting, governance) are stripped from this build.

---

## Prerequisites

- A reachable Wazuh manager (API) and OpenSearch endpoint
- Linux host (Ubuntu 22.04+ / Debian 12+ / Kali — tested) or Docker 24+
- PostgreSQL 14+ (required since v4.9.0). The bash installer provisions a
  local Postgres instance automatically on apt-based hosts; Docker uses the
  bundled `db` service. To use an existing/managed Postgres instead, set
  `DATABASE_URL` in `.env`.
- Open outbound TCP to your Wazuh stack
- Port `8443/tcp` free on the host (dashboard)

---

## Option A — Bash installer (host install)

Use this when you want DHRUVA running directly under systemd on a Linux host.

```bash
tar xzf dhruva-5.0.0-source-community.tar.gz
cd dhruva-5.0.0-source-community

# 1. Configure credentials (Wazuh API, OpenSearch, JWT secret, etc.)
cp .env.template .env
$EDITOR .env

# 2. Point at your Wazuh stack
$EDITOR config/config.yaml

# 3. Run the deployer (creates venv, installs deps, provisions a local
#    Postgres database, applies schema migrations, writes the systemd unit,
#    starts the service)
chmod +x deploy.sh
./deploy.sh
```

After `deploy.sh` finishes:

- Dashboard: `https://<host>:8443`
- Service:   `sudo systemctl status ai-soc`
- Logs:      `sudo journalctl -u ai-soc -f`
- DB:        local PostgreSQL (provisioned by deploy.sh; DSN in `.env` `DATABASE_URL`)
- Data:      `/var/lib/ai-soc/` (assets, identities, IOCs — not the DB)

To upgrade later, drop a newer tarball next to the install and run
`bash scripts/upgrade.sh`.

---

## Option B — Docker / docker-compose

Use this when you prefer container isolation or are deploying on a host that
already manages Python via other means.

```bash
tar xzf dhruva-5.0.0-source-community.tar.gz
cd dhruva-5.0.0-source-community

# 1. Configure credentials
cp .env.template .env
$EDITOR .env

# 2. Point at your Wazuh stack
$EDITOR config/config.yaml

# 3. Build and start
docker compose up -d --build

# 4. Tail startup logs until the API is up
docker compose logs -f ai-soc
```

After the container is healthy:

- Dashboard: `https://<host>:8443`
- Status:    `docker compose ps`
- Logs:      `docker compose logs -f ai-soc`
- Data:      named volume `soc-data` (`/var/lib/ai-soc` inside the container)

If Wazuh / OpenSearch run on the **same Docker host**, uncomment the
`extra_hosts` block in `docker-compose.yml` so the container can reach
them via `host.docker.internal`.

Upgrades: drop the new tarball, run `docker compose pull` (or rebuild)
and `docker compose up -d`.

---

## First-run checklist

1. `.env` filled in — `WAZUH_API_URL`, `WAZUH_API_USER`, `WAZUH_API_PASSWORD`,
   `OPENSEARCH_URL`, `OPENSEARCH_USER`, `OPENSEARCH_PASSWORD`, `JWT_SECRET`,
   `ANONYMIZATION_SALT` all set (the entrypoint will generate ephemeral
   secrets if missing, but they will reset on every restart).
2. `config/config.yaml` — Wazuh/OpenSearch hosts match your environment.
3. Dashboard reachable on `:8443`, default admin login from `.env`.
4. Open the **Overview** tab — alert counts should populate within ~60s.
5. Open the **Triage** tab — first enrichment + verdict appears once Claude
   CLI auth is configured (`claude login` on the host, or mount the auth
   directory into the container).

---

## Troubleshooting

| Symptom | Check |
|--------|-------|
| Dashboard 502 / cert error | TLS self-signed — accept the warning, or set `SOC_TLS_DISABLE=true` in `.env` for plain HTTP |
| "Loading…" forever | `journalctl -u ai-soc -n 200` or `docker compose logs ai-soc`; look for OpenSearch auth failures |
| No alerts ingested | Confirm `wazuh-alerts-4.x-*` indices exist on OpenSearch and the configured user has read access |
| Claude verdicts empty | Run `claude login` once on the host (or in the container shell); Max subscription required for CLI mode |

Full operator documentation lives in `docs/SETUP-GUIDE.md`.
