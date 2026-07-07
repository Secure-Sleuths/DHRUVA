# DHRUVA — Community Edition

**AI-augmented security operations layer for [Wazuh](https://wazuh.com/) SIEM.**

DHRUVA adds a compounding-intelligence layer on top of Wazuh: it auto-triages
alerts with an LLM, enriches them with free threat-intel feeds, correlates
related activity into attack-chain campaigns, and surfaces it all through a
redesigned "glass-box" analyst dashboard — so an analyst rarely needs to leave
one pane of glass.

> This is the **Community Edition** — free, source-available under Apache-2.0.
> Paid modules (Detection Agent, Threat Hunt Agent, NL Query, SOAR, ticketing,
> reporting, and their routes) are not part of this build.

## The closed loop

```
Wazuh alerts (OpenSearch)
  → enrichment (asset · identity · threat-intel · historical · time context)
  → risk scoring  → LLM triage verdict
  → decisions recorded  → incidents auto-grouped into attack-chain campaigns
  → human review / override  → cleaner signal → repeat
```

## Highlights

- **AI triage** of Wazuh alerts with an explainable, "glass-box" verdict — every
  risk number opens to the math behind it.
- **Free threat-intel enrichment** (ThreatFox, URLhaus, Feodo, CISA KEV, EPSS,
  and more) wired into the verdict.
- **Attack-chain correlation** — related incidents are stitched into campaigns
  with MITRE ATT&CK kill-chain ordering.
- **Redesigned dashboard** — Next.js 15 / React 19 SPA served same-origin from
  FastAPI: worst-first triage queue, campaign command map, MITRE coverage,
  host integrity, and more.
- **Privacy boundary** — client identifiers are tokenized out of prompts before
  any LLM call and resolved back afterward.
- **Multi-provider LLM** — Anthropic, OpenAI, Groq, or local Ollama.

## Requirements

- A running Wazuh 4.x stack (manager + indexer/OpenSearch + dashboard)
- Python 3.11+, PostgreSQL 14+
- An LLM provider key (Anthropic / OpenAI / Groq) or a local Ollama, or a Claude
  Max subscription for CLI mode
- Node.js 20+ (only to build the dashboard from source)

## Quick start

```bash
# 1. Configure
cp .env.template .env        # set DATABASE_URL, LLM provider key, Wazuh/OpenSearch
# 2a. Bare-metal install (creates service user, venv, systemd unit)
bash deploy.sh
# 2b. …or Docker (bundled Postgres)
docker compose --profile bundled-db up -d
```

The dashboard is served by the API. See [`INSTALL.md`](INSTALL.md) for the full
walkthrough (migrations, TLS, multi-tenant, upgrades) and
[`docs/SETUP-GUIDE.md`](docs/SETUP-GUIDE.md).

## Build the dashboard from source

```bash
bash scripts/build-web.sh    # builds web/ (Next.js) → static export served by FastAPI
```
(The Docker build does this automatically.)

## Architecture

- `main.py` — orchestrator; constructs components and schedules periodic cycles.
- `src/agents/` — the LLM triage agent + provider abstraction + anonymization.
- `src/enrichment/` — Wazuh/OpenSearch clients, enrichers, threat-intel feeds.
- `src/incidents/` — attack-chain correlation + SLA.
- `src/api/` — FastAPI app, routes, RBAC; `web/` — the SPA source.
- `src/database/` — Postgres data layer + Alembic migrations.
- `config/guidance/` — behavioural YAMLs (risk criteria, escalation, playbooks)
  that agents read at runtime — edit these to change behaviour without code.

## Community vs. paid

The Community Edition ships the core closed loop (triage → enrich → correlate →
review) and the full dashboard. The paid editions add autonomous Detection-rule
engineering, threat hunting, natural-language investigation, SOAR/active-response
orchestration, ticketing, and reporting. Learn more at
[securesleuths.in](https://securesleuths.in).

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

Contributions welcome. By contributing you agree your contributions are licensed
under Apache-2.0.
