-- ============================================================================
-- WO-H12 — Postgres Row-Level Security (RLS) as the structural tenant backstop
-- ----------------------------------------------------------------------------
-- Defense-in-depth ON TOP OF the WO-H8 app-level query guard (_GuardedConnection
-- / _assert_tenant_scoped_query). H8 is a fail-LOUD regex heuristic at the app
-- layer; it treats any "*_id = X" as tenant-confining, so a forgotten-{tf} query
-- filtered only on a SHARED id (technique_id, rule_id, …) slips past it and can
-- return cross-tenant rows. RLS closes that class IN THE ENGINE: even a raw
-- ``SELECT * FROM incidents`` with no app filter returns only the session's
-- tenant rows. Both layers stay active.
--
-- Session wiring (src/database/store.py):
--   * Every checkout of a pooled connection re-issues
--       SELECT set_config('app.tenant_id', <value>, false)
--     so a pooled connection never leaks one tenant's GUC to the next request.
--     value = tenant_id          → sees only that tenant's rows
--     value = '__CROSS_TENANT__'  → audited bypass (matches H8's cross_tenant())
--     value = '' (no context)     → current_setting(...) = '' → matches nothing
--                                    → fail-closed (same posture as H8).
--   * current_setting('app.tenant_id', true) — the ``true`` (missing_ok) is
--     REQUIRED: before any set_config in a session the custom GUC is undefined;
--     missing_ok makes it return NULL (→ NULL comparison → no rows) instead of
--     raising "unrecognized configuration parameter".
--
-- ┌────────────────────────────────────────────────────────────────────────┐
-- │ CRITICAL — DHRUVA MUST CONNECT AS A NON-SUPERUSER, NON-BYPASSRLS ROLE.  │
-- │ PostgreSQL SUPERUSERS and roles with BYPASSRLS SKIP RLS ENTIRELY, even  │
-- │ with FORCE. If DHRUVA connects as such a role this migration applies    │
-- │ cleanly yet has NO runtime effect.                                      │
-- │  * deploy.sh path: `CREATE USER dhruva` → NOSUPERUSER/NOBYPASSRLS and    │
-- │    owns the DB → RLS ACTIVE (FORCE applies even to the owner). GOOD.     │
-- │  * docker-compose bundled-db: POSTGRES_USER=dhruva is created by the     │
-- │    postgres entrypoint as a SUPERUSER → RLS BYPASSED. Provision a        │
-- │    separate non-superuser app role (see docs/MULTI-TENANT.md §RLS).      │
-- │ Verify at runtime:                                                       │
-- │    SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user│
-- │    -- both must be `f`.                                                   │
-- └────────────────────────────────────────────────────────────────────────┘
--
-- FORCE ROW LEVEL SECURITY is set so the policy applies even when DHRUVA owns
-- the tables (the deploy.sh role owns the DB); without FORCE the owner bypasses.
--
-- Scope: exactly SOCDatabase.TENANT_SCOPED_TABLES (all have a TEXT client_id).
-- FK-scoped tables (incident_alerts, incident_timeline) have no client_id and
-- are protected transitively by their scoped parent + the app-layer join; a
-- subquery RLS policy for them is a possible follow-up, intentionally out of
-- scope here to keep this migration reversible and predicate-simple.
--
-- Idempotent: DROP POLICY IF EXISTS before CREATE; ENABLE/FORCE are no-ops when
-- already set; indexes use IF NOT EXISTS. Safe to re-run / rehearse on a copy.
-- ============================================================================

DO $$
DECLARE
    t text;
    tenant_tables text[] := ARRAY[
        'agent_decisions', 'incidents', 'detection_proposals',
        'feedback_patterns', 'behavioral_baselines', 'rule_tuning_overrides',
        'hunt_findings', 'operational_metrics', 'soar_executions',
        'mitre_coverage', 'audit_log', 'anon_mappings', 'decision_audit_trail',
        'sla_breaches', 'alert_enrichment_cache', 'processed_alerts',
        'tickets', 'ticket_sync_log', 'kb_documents', 'post_incident_reviews',
        'hunt_hypothesis_library', 'shift_handoffs', 'compliance_mappings',
        'llm_usage_metrics', 'buffered_alerts', 'assets', 'identities',
        'local_iocs'
    ];
BEGIN
    FOREACH t IN ARRAY tenant_tables LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I '
            'USING ('
            '    client_id = current_setting(''app.tenant_id'', true) '
            '    OR current_setting(''app.tenant_id'', true) = ''__CROSS_TENANT__'''
            ') '
            'WITH CHECK ('
            '    client_id = current_setting(''app.tenant_id'', true) '
            '    OR current_setting(''app.tenant_id'', true) = ''__CROSS_TENANT__'''
            ')',
            t);
    END LOOP;
END $$;

-- The RLS predicate adds a `client_id` filter to every read/write of these
-- tables. Most tenant-scoped tables already carry a client_id index from the
-- baseline; these six did not — add them so RLS introduces no seq-scan on the
-- hot path. (IF NOT EXISTS keeps this safe if a prior run already created them.)
CREATE INDEX IF NOT EXISTS idx_sla_breaches_client_id
    ON sla_breaches (client_id);
CREATE INDEX IF NOT EXISTS idx_alert_enrichment_cache_client_id
    ON alert_enrichment_cache (client_id);
CREATE INDEX IF NOT EXISTS idx_post_incident_reviews_client_id
    ON post_incident_reviews (client_id);
CREATE INDEX IF NOT EXISTS idx_hunt_hypothesis_library_client_id
    ON hunt_hypothesis_library (client_id);
CREATE INDEX IF NOT EXISTS idx_shift_handoffs_client_id
    ON shift_handoffs (client_id);
CREATE INDEX IF NOT EXISTS idx_buffered_alerts_client_id
    ON buffered_alerts (client_id);
