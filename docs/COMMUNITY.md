# DHRUVA Community

`DHRUVA Community` is the free, self-hosted edition of the platform.

It is intended for:

- evaluators
- small internal security teams
- researchers and labs
- Wazuh operators who want AI triage and incident workflow without a sales process

## Included Features

- AI alert triage with confidence scoring
- asset, identity, historical, and time-context enrichment
- composite risk scoring
- incident lifecycle with severity and analyst notes
- MITRE ATT&CK coverage heatmap and gap analysis
- 7 community threat-intel feeds
- LLM prompt anonymization
- knowledge base with full-text search
- JWT authentication
- `analyst` and `read_only` user roles
- 5 users, unlimited agents, unlimited alerts

## Build Profile

Community packaging should run with:

```bash
DHRUVA_BUILD_PROFILE=auto
```

`auto` means:

- if no `license.key` is present, DHRUVA runs as Community
- if a valid paid license is later added, the next restart mounts the full paid route surface

You can force a profile manually:

```bash
DHRUVA_BUILD_PROFILE=community
DHRUVA_BUILD_PROFILE=full
```

## Community Route Surface

Community keeps these areas enabled:

- dashboard overview
- triage
- incidents
- MITRE
- knowledge base
- threat intel tier-1
- auth, health, agent inventory

Community does not mount paid-only areas in a Community release profile:

- detection engineering
- hunt
- natural-language investigation
- ticketing
- SOAR / active response
- advanced metrics
- compliance
- webhook management

## Install Notes

- No license file is required.
- Keep `LICENSE_FILE=license.key` in `.env`; if the file is absent, Community mode is used automatically.
- The installer and deployment wizard now write `DHRUVA_BUILD_PROFILE=auto` by default.

For a Community-specific Docker run:

```bash
docker compose -f docker-compose.yml -f docker-compose.community.yml up -d --build
```

For a Community tarball build from the repo:

```bash
bash scripts/build-community-tarball.sh 4.8.8
```

## Upgrade Path

To upgrade from Community to a paid edition:

1. Place the issued `license.key` in the install directory.
2. Leave `DHRUVA_BUILD_PROFILE=auto` as-is.
3. Restart the service.

On restart, the paid feature surface becomes available according to the license tier.
