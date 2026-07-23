-- ============================================================================
-- WO-H29 (finding N2) — RLS backstop for the FK-scoped incident child tables
-- ----------------------------------------------------------------------------
-- Closes the last hole left open by WO-H12 / 0006_rls_tenant_backstop: the two
-- FK-scoped tables ``incident_alerts`` and ``incident_timeline`` carry no direct
-- ``client_id``, so 0006 deliberately skipped them (see its header §Scope) and
-- neither the WO-H8 app-level query guard NOR Postgres RLS confined them. There
-- is no live leak today — the DAO only ever reaches these rows through a join to
-- the already-RLS-scoped ``incidents`` parent — but a future forgotten-filter
-- query (e.g. a raw ``SELECT * FROM incident_timeline``) could return another
-- tenant's rows. This migration closes that class IN THE ENGINE.
--
-- APPROACH — SUBQUERY RLS POLICY (chosen over folding into the WO-H8 guard):
--   These tables have ``incident_id`` (FK → incidents.id), not ``client_id``,
--   so their tenant owner is defined transitively. The policy therefore scopes
--   by membership in the RLS-scoped parent:
--       USING (incident_id IN (SELECT id FROM incidents))
--   ``incidents`` itself carries the 0006 ``tenant_isolation`` policy, so the
--   inner ``SELECT id FROM incidents`` returns ONLY the session tenant's incident
--   ids (RLS is applied to tables referenced inside a policy predicate too).
--   Composition with the 0006 session GUC (``app.tenant_id``) is automatic:
--     value = tenant_id          → inner select = that tenant's ids  → child rows
--                                   for that tenant only.
--     value = '__CROSS_TENANT__' → incidents policy returns ALL ids  → all child
--                                   rows (audited bypass, same posture as parents).
--     value = '' / unset         → incidents returns NO ids → child rows = none
--                                   (fail-closed, same posture as 0006).
--   This needs NO new column and NO backfill, and it does not touch RLS on any
--   other table. It was preferred over the app-guard route because the WO-H8
--   guard already PASSES these tables (every DAO query carries an ``incident_id``
--   predicate, which the guard treats as tenant-confining) — so the real gap is
--   purely the missing engine-level backstop, which only RLS provides.
--
-- Same NON-SUPERUSER / NON-BYPASSRLS role requirement as 0006 applies — a
-- superuser or BYPASSRLS role skips this policy exactly as it skips the parent
-- policies (see 0006 header and docs/MULTI-TENANT.md §RLS). This adds no new
-- role requirement; it composes with the one 0006 established.
--
-- FORCE ROW LEVEL SECURITY is set so the policy applies even to the table owner
-- (the deploy.sh role owns the DB), mirroring 0006.
--
-- Idempotent: DROP POLICY IF EXISTS before CREATE; ENABLE/FORCE are no-ops when
-- already set. Safe to re-run / rehearse on a copy.
-- ============================================================================

DO $$
DECLARE
    t text;
    fk_tables text[] := ARRAY['incident_alerts', 'incident_timeline'];
BEGIN
    FOREACH t IN ARRAY fk_tables LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I '
            'USING (incident_id IN (SELECT id FROM incidents)) '
            'WITH CHECK (incident_id IN (SELECT id FROM incidents))',
            t);
    END LOOP;
END $$;
