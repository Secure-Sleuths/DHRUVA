# Changelog

All notable changes to DHRUVA from v4.9.0 onward are documented here.
Pre-4.9 release history lives in [ROADMAP.md](ROADMAP.md).

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
DHRUVA follows [Semantic Versioning](https://semver.org/).

## [5.0.0] — 2026-07-06

DHRUVA 5.0.0 is a major product-generation release. It ships a fully
redesigned analyst dashboard (a Next.js single-page app served same-origin
from FastAPI), a new AI-safety track (PII/PHI redaction + deterministic output
grounding), deeper Wazuh detection telemetry feeding the triage verdict, and a
reliability/release-engineering overhaul (crash fixes, a paid-source-leak
close, and version/strip CI guards). See **Breaking changes & upgrade notes**
at the end of this entry before upgrading.

### Added

#### Redesigned analyst dashboard (headline)

- **New Next.js 15 / React 19 / Tailwind SPA, served same-origin from
  FastAPI.** The redesigned "glass-box" dashboard is now the default UI. It is
  built to a static export and served by `src/api/routes/frontend.py` via
  `register_spa(app)`; when the built export is present the SPA is served,
  otherwise the platform falls back to the legacy `dashboard.html`. Login page,
  auth gating, and logout were added to fill the redesign's missing auth flow.
- **RBAC per-tab ACLs preserved, mirrored client-side** over the existing
  `admin > senior_analyst > analyst > read_only` tiers; the anonymization
  boundary is unchanged (paid *backend* modules/routes still strip in Community;
  paid tabs gate/404 at runtime).
- **Write-wiring across the app (Waves 1–3):** incident case management,
  active-response, reports, metrics, detection, admin, tickets, SOAR,
  closed-loop, threat hunting, and knowledge views were wired end-to-end to the
  backend (loading/error states, RBAC-gated actions) — reaching full
  write-parity with the legacy dashboard.
- **New views and controls:** Campaign Command overview (KPI tiles + campaign
  map), worst-first glass-box triage queue, glass-box incident case view with
  risk-math/provenance and admin-only verdict override, grounded Copilot
  investigation, MITRE ATT&CK coverage with live-campaign overlay, restored
  segmented filter controls, and a plain-English **executive-briefing** Daily
  Review for non-technical readers.

#### AI-safety track (AIS1–AIS3)

- **AIS1 — regex PII/PHI redaction over free-text.** `AlertAnonymizer` now
  tokenizes semantic PII/PHI (email / phone / US + IN national-ID) out of
  free-text fields (rule description, location, `data` leaves, correlated
  events, incident summaries, query hits) before any external LLM call —
  reversibly, via the existing salted-SHA-256 token scheme. Detection-relevant
  fields (external IP, command line, file path, process name) are preserved by
  policy.
- **AIS2 — deterministic output faithfulness / grounding.** A new grounding
  module (`src/agents/grounding.py`) scores each triage verdict against the
  evidence actually provided, with a per-claim citation (`evidence_refs`)
  contract and detection of unsupported/fabricated references. The result is
  an independent signal from the model's self-reported confidence. Persisted in
  the new additive, nullable `agent_decisions.grounding` column (Alembic
  `0005`).
- **AIS3 — deterministic ATT&CK explanatory grounding.** A checked-in ATT&CK
  technique reference asset and a deterministic loader inject bounded,
  no-fabrication technique context into the triage prompt (`PROMPT_VERSION` →
  `2.2.0`) — no embeddings, no external call, no new dependency. Unknown IDs get
  an explicit "do not fabricate" marker.

#### Detection & telemetry

- **M4 — vulnerability/SCA host context into triage.** CVE/SCA posture on the
  affected host now contributes a bounded multiplier to the triage risk score
  (new `enrichment.vulnerability_context` config block), multi-tenant-safe.
- **M5 — attack-chain grouping (Alembic `0003`).** Correlation now groups
  related incidents into explainable, MITRE-tactic-ordered kill chains
  (`attack_chain_id` / `attack_chain_tactics` on incidents), surfaced as
  campaigns in the read API.
- **M6 — remaining Wazuh features surfaced (read-only, gated).** FIM/syscheck,
  rootcheck, registry, and agent-group data are now available as read-views.
- **M6b — host-integrity context into triage.** FIM/syscheck + rootcheck
  findings on the affected host now feed the triage risk score via a new
  `HostIntegrityContextEnricher`, with a conservative, explainable, bounded
  multiplier (rootcheck primary, FIM secondary + thresholded, combined cap
  1.5×) that sharpens rather than manufactures severity. Fail-safe (any error /
  missing agent / fail-closed tenant → no effect).

#### Active response (M3) — safety posture

- Per-tenant `auto_response.block_ip` policy (encrypted tenant config) with
  fail-closed reads (`tenant_registry.get_auto_response_policy`).
- Pure, exhaustively-tested auto-block gate (`src/soar/auto_block_gate.py`).
- Centralized `src/enrichment/ip_utils.py::is_blockable_external_ip` reused by
  the auto gate AND the manual block path (internal-IP + allowlist guard,
  IPv4+IPv6, CIDR-aware, fail-closed).
- `active_response_audit` table (Alembic `0002`) — durable who/what/why/when +
  triggering alert + TI evidence for every auto AND manual AR action; backs the
  durable auto-block rate cap.
- AR lifecycle endpoints: `POST /api/response/propose` (analyst+),
  `POST /api/response/approve/{id}` and `POST /api/response/reverse/{id}`
  (senior_analyst+), `GET /api/response/queue` and `/api/response/audit`
  (read_only+), `GET|PUT /api/response/auto-policy` (admin-only, own-tenant).

#### Human-in-the-loop

- **Reason required on verdict + incident-status changes (Alembic `0004`).**
  A human-supplied reason is now required (enforced at the API layer) when
  overriding a verdict or changing incident status; the most-recent reason is
  stored alongside the row (`agent_decisions.review_reason`,
  `incidents.status_reason`).

#### Release engineering

- **Release-time frontend build wired into every packaging lane and CI.**
  `scripts/build-web.sh` builds the SPA static export and stages it to the exact
  path the backend probes; the source, client (Cython/.so), and Docker build
  lanes now run it and hard-assert the SPA is present before packaging, and CI
  gained an independent `web` build job. Prevents the silent legacy-dashboard
  fallback that occurred when no build step ran.
- **Version single source of truth + CI drift guard.** The repo-root `VERSION`
  file is now canonical; `scripts/check_version_drift.py` fails CI if `VERSION`,
  `config/config.yaml`, and `src.__version__` disagree.

#### Backend-feature surfacing (Tier-1 UI gaps)

A frontend-vs-backend gap audit surfaced already-built backend capabilities the
redesigned SPA did not yet render; these were closed as self-contained Work
Orders (`docs/PLAN-tier1-surfacing.md`), each independently QA-audited.

- **AIS2 grounding flag surfaced (WO-U11).** The persisted evidence-grounding
  signal now renders as an amber "AI not confident" flag on the Triage glass-box
  card and a low-grounding count in Daily Review — read-only, flag-only.
- **Triage rule-stats + pending-review (WO-U13).** A lazy per-rule 7-day
  TP/FP/auto-close stats drill on each decision, plus a segmented pending-review
  (escalated, no human verdict) queue.
- **Threat Intel "Run collection now" trigger (WO-U12).** senior_analyst+ gated,
  confirm-dialogged manual TI-collection trigger.
- **Host Integrity inventory + SCA (WO-U14).** New syscollector Inventory
  (processes/ports/packages) and per-agent Configuration-assessment (SCA
  policies → checks) sub-views.
- **Compliance coverage matrix (WO-U16 + WO-B11).** A compliance-framework
  coverage view (PCI-DSS/HIPAA/NIST-800-53/GDPR → per-control detection
  coverage) as a MITRE-tab segment, dual-gated by role and `compliance_sca`.
  Backend fix WO-B11 disambiguated the shadowed compliance routes (per-agent SCA
  moved to `/api/agents/{id}/sca`), making `/api/compliance/matrix` reachable.
- **Vulnerability remediation (WO-U15).** A read-only critical-vulns table +
  advisory remediation plan, plus an **admin-only, confirm-gated** Remediate
  action (package update via Wazuh active response) with a verify follow-up.

### Changed

- **Threat-intel resilience:** NAT64 fallback for the CISA-KEV feed so KEV
  enrichment still resolves on IPv6-only egress.
- **Docs truth-up:** `plan.md` retired (it described a stale v2.5.0/SQLite
  system); `docs/STATUS.md`, `docs/ROADMAP.md`, and `docs/PROGRESS.md` are the
  authoritative state/queue/history sources.

### Fixed

- **Threat-hunt cycle no longer crashes every run.** Fixed a knowledge-base
  variable-shadowing bug plus a parameterized-`LIKE` `%`-escape bug in the hunt
  agent that made the scheduled hunt cycle fail on every execution.
- **Eliminated the parameterized-`LIKE` `%%`-escape bug class in `store.py`.**
  Two remaining call sites (`get_analyst_performance`, `get_analyst_stats`) were
  fixed — one had been returning empty analyst-performance stats silently, the
  other could 500 the analyst-stats endpoint.
- **Postgres `GROUP BY` aggregation** corrected in the reports/feedback queries.
- **Ambiguous `occurrence_count`** reference qualified in the feedback-pattern
  upsert.
- Assorted live-staging fixes (dashboard SQL, empty-inventory enrichers,
  same-day `processed_alerts` window, INSTALL.md SQLite→Postgres wording).

### Security

- **Closed a paid-source leak in Community Docker images** and added a CI
  strip-parity guard (`scripts/check_strip_parity.py`) that verifies paid
  modules are stripped consistently across all three build lanes.
- `POST /api/response/execute` lowered from admin-only to **senior_analyst+**
  (operator-approved); manual `block_ip` now also enforces the internal-IP +
  allowlist guardrail (defense-in-depth, both auto and manual paths).
- Tightened Content-Security-Policy to the self-contained SPA bundle and wrapped
  413 responses with security headers; auth hardening pass.
- Hardening carried in this generation: dashboard-proxy SSL defaults to
  `verify=True`, versioned tenant-key rotation, tenant decrypt failures fail
  closed (no global fallback), and internal exception detail is no longer leaked
  in 5xx responses.

### Breaking changes & upgrade notes

- **Source/tarball and Docker builds now REQUIRE a Node/npm build step** to
  compile the SPA static export (new build-time dependency: Node 20 + npm). The
  build lanes run `scripts/build-web.sh` and fail hard if the export is missing;
  the generated `web/out/` and `src/api/static/app/` are gitignored and never
  committed. Runtime has no new dependency.
- **Database migration to head `0005`.** Upgrades apply Alembic revisions
  `0002`–`0005` on top of the 4.9.0 baseline — all **additive / backward
  compatible** (new `active_response_audit` table, new nullable columns:
  attack-chain, review/status reason, and `agent_decisions.grounding`). No
  destructive changes.
- **`soar.auto_containment` is REMOVED.** The global auto-approval path that
  could set a SOAR execution to `auto_approved` (bypassing human approval for
  configured playbooks) no longer exists in code. It is superseded by a
  per-tenant, gated **`auto_response.block_ip`** policy that ships **OFF by
  default**.
  - **Upgrade note:** if your `config/config.yaml` still contains a
    `soar.auto_containment:` block, it is now inert — the SOAR engine logs a
    loud `soar_auto_containment_removed` warning at startup and treats it as
    disabled. Remove the block and configure auto-block per tenant via
    `PUT /api/response/auto-policy` if you want automated blocking.
  - The ONLY action that may ever auto-execute is `block_ip`, and only when
    BOTH gates clear on the SAME external IP: triage `verdict==true_positive`
    AND `confidence >= triage_confidence_floor` (default 0.90), AND a TI-feed
    hit on that exact IP with `confidence >= ti_feed_confidence_floor`
    (default 80). `kill_process`, `isolate_host`, `disable_user` can never
    auto-execute. Auto-block carries a native Wazuh TTL (default 24h),
    respects a per-tenant `rate_cap_per_hour` (default 3), and never blocks
    internal/reserved IPs or anything on the tenant `never_block_allowlist`.
- **Reference (already broken in 4.9.0, not new here):** DHRUVA is
  Postgres-only; there is no SQLite fallback.

## [4.9.0] — 2026-06-01

### Community quality-of-life (from cheersin 4.8.8 install retro, 2026-05-27)

- **In-memory alert buffer for Community installs.** `src/pipeline/`
  (and the durable `AlertBuffer`) is stripped from Community builds, so
  transient OpenSearch failures used to drop alerts on the floor
  (`alert_index_failed_no_buffer` followed by silent loss). Added
  `src/enrichment/inmem_buffer.py` — a 1000-alert bounded ring that
  mirrors the paid interface (`buffer_alert` / `flush_to_opensearch` /
  `get_buffer_count`). main.py auto-selects it when the paid module is
  absent. Not durable across restarts; Team/Enterprise still get the
  Postgres-backed buffer with dead-letter quarantine.
- **Frontend skips paid endpoint calls on Community.** Dashboard polling
  used to fire `/api/detection/proposals`, `/api/hunt/findings`,
  `/api/soar/stats`, `/api/tickets/stats` unconditionally every 10s →
  spammed 404s and added round-trip latency. `app.js` now reads
  `info.features` from `/api/license/tier-info` into a `_licenseFeatures`
  list and a `_hasFeature(name)` helper gates the polling fan-outs.
- **Wazuh rule-validation cleanup gated on DetectionAgent.** main.py
  called `_delete_rule_file("_ai_soc_validation_temp.xml")` at every
  startup. The temp file is only ever written by the Detection Agent's
  `wazuh-logtest` validation flow — stripped from Community. The delete
  attempt logged a misleading `wazuh_rulefile_delete_failed` 403 on every
  Community boot (the Wazuh API user typically lacks rule-management
  permission). Now skipped when DetectionAgent is None.

### BREAKING

- **Postgres is now required.** SQLite was retired in v4.9.0. Operators
  on v4.8.x must run the one-time data migration in
  `docs/MIGRATION-FROM-SQLITE.md` before upgrading.
- `config.yaml` schema: `database.path` → `database.dsn` (Postgres
  libpq URI). `DATABASE_URL` env var still overrides if set.
- `docker-compose.yml` now bundles a `postgres:16-alpine` service
  with health-gated `depends_on`. Production multi-host installs
  should point `DATABASE_URL` at managed Postgres and remove the
  inline service.

### Added

- **`python main.py --migrate`** — applies Alembic migrations against
  `DATABASE_URL`. Called automatically by `docker-entrypoint.sh`,
  `scripts/install.sh` next-steps, and `scripts/upgrade.sh` (which now
  refuses to start the service if migrations fail). PyInstaller binary
  ships alembic transitively via this entry point.
- **`tools/migrate_sqlite_to_postgres.py`** — idempotent one-shot data
  loader for v4.8.x → v4.9.0 upgrades. Disables FK triggers via
  `SET session_replication_role='replica'` for the load, batches inserts
  with `ON CONFLICT DO NOTHING`, resyncs SERIAL/IDENTITY sequences past
  the imported max, `--dry-run` mode. Refuses to run if Postgres has
  no `alembic_version`.
- **Alembic baseline** under `src/database/migrations/versions/` covering
  all 45 tables (replaces the 985-line inline `MIGRATIONS` list in
  `store.py`). `SOCDatabase._verify_schema()` boot gate refuses to start
  unless `alembic upgrade head` has run.
- **testcontainers-based test fixtures**: session-scoped
  `postgres:16-alpine` container, per-test `TRUNCATE … RESTART IDENTITY
  CASCADE`, `pg_terminate_backend()` of lingering 'idle in transaction'
  sessions to prevent fixture deadlocks.
- **`docs/MIGRATION-FROM-SQLITE.md`** — operator runbook (backup,
  schema apply, dry-run, load, verify, rollback, scope notes).
- **Bundled Postgres in `docker-compose.yml`** with `POSTGRES_USER`,
  `POSTGRES_PASSWORD`, `POSTGRES_DB` env vars (templated in `.env.template`).

### Changed

- `src/database/store.py` ported from `sqlite3` to `psycopg` v3 +
  `psycopg_pool.ConnectionPool` (min=2, max=20, `dict_row` factory).
  Per-thread cached connections from the pool; callers must never call
  `conn.close()`. Sweep across 20 files: 229 `?` → `%s`, 44
  `datetime('now')` → `CURRENT_TIMESTAMP::text`, FTS5 → tsvector
  + `to_tsquery('english', %s)`, julianday →
  `EXTRACT(EPOCH FROM …)/60`, `INSERT OR REPLACE/IGNORE` →
  `ON CONFLICT … DO UPDATE/NOTHING`, SQLite `MAX(a,b)` →
  `GREATEST(a,b)`, `GROUP_CONCAT` → `string_agg`.
- `tools/seed_demo_data.py` fully ported (32 INSERT sites + per-table
  `ON CONFLICT` clauses; mitre_coverage and rule_tuning_overrides use
  `DO UPDATE`, rest use `DO NOTHING`). `--db` flag renamed to `--dsn`.

### Removed

- **`SOCDatabase.checkpoint_wal()`** no-op stub (Postgres has no WAL
  checkpoint analog) and the matching `_checkpoint_sqlite_wal`
  APScheduler job in `main.py`.
- All `import sqlite3` and `sqlite3.*` references across the codebase
  (audit: `grep -rE "import sqlite3" src/ tools/ main.py` returns
  zero hits after the cutover).
- Embedded 985-line `MIGRATIONS` list and `_init_db()` / `_run_migrations()`
  methods from `store.py` (Alembic owns the schema now).

### Fixed (Phase 3 follow-up — production bugs caught by the testcontainer suite)

- 4 sites of `MAX(col, EXCLUDED.col)` → `GREATEST(col, EXCLUDED.col)`
  in store.py (PG MAX is aggregate-only, not scalar).
- `conn.executemany(...)` → `cur.executemany(...)` (psycopg v3
  Connection has no executemany method).
- `save_anon_mapping` ON CONFLICT clause `hit_count = hit_count + 1`
  → `anon_mappings.hit_count + 1` (PG AmbiguousColumn error).
- `load_revoked_tokens` stray `r[0]` indexing on a dict_row factory
  (KeyError) → `r["token_hash"]`.
- `feedback/loop.py` `GROUP_CONCAT(reasoning, '|||')` →
  `string_agg(reasoning, '|||')`.
- `migrations/env.py` DSN normalization: plain `postgresql://` URLs
  were resolving to psycopg2 (not installed). Now rewrites to
  `postgresql+psycopg://` so SQLAlchemy uses psycopg v3.

### Test suite

- **284/284 tests pass** against the testcontainer Postgres.
- 18 stale tests updated to match security-hardened or contract-changed
  code paths (signature validator sha1/Bearer/XFF, webhook handler
  3-state dedup contract, soar engine fixture, llm_usage 1/0 → True/False
  for BOOLEAN columns, multi_provider dict_row indexing).
