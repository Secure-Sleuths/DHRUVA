-- ============================================================================
-- WO-H28 — ops hardening (transactional half)
-- ----------------------------------------------------------------------------
-- 1) llm_budget_reservations — the DB-side half of the atomic budget debit.
--    BudgetGuard.reserve() serializes on a per-tenant advisory lock and, while
--    holding it, counts (month-to-date llm_usage_metrics spend + active
--    reservations) against the cap before INSERTing its own reservation row.
--    The reservation is deleted (released) after the LLM call's real usage row
--    lands in llm_usage_metrics — so N parallel workers can no longer all read
--    the same pre-call spend and collectively overshoot the cap (the old
--    check-then-act race with the ~30s spend cache).
--
--    Same tenancy posture as llm_usage_metrics: tenant_id for the guard's
--    per-tenant queries, client_id + the 0006-style tenant_isolation RLS
--    policy (ENABLE + FORCE) as the engine-level backstop. Rows are
--    short-lived (seconds; stale ones are purged by reserve() after the
--    configured TTL and by the daily retention prune).
--
-- 2) The (metric_name, recorded_at) composite index on operational_metrics is
--    NOT here: CREATE INDEX CONCURRENTLY cannot run inside a transaction, so
--    it lives in 0009_ops_hardening.py inside an autocommit block (see
--    docs/DB-MAINTENANCE.md for the non-blocking-DDL standard).
--
-- Idempotent: IF NOT EXISTS / DROP POLICY IF EXISTS throughout.
-- ============================================================================

CREATE TABLE IF NOT EXISTS llm_budget_reservations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    estimated_cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    client_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_budget_reservations_tenant_created
    ON llm_budget_reservations (tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_budget_reservations_client_id
    ON llm_budget_reservations (client_id);

-- Mirror the 0006 tenant_isolation policy (same GUC, same sentinel).
ALTER TABLE llm_budget_reservations ENABLE ROW LEVEL SECURITY;
ALTER TABLE llm_budget_reservations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON llm_budget_reservations;
CREATE POLICY tenant_isolation ON llm_budget_reservations
    USING (
        client_id = current_setting('app.tenant_id', true)
        OR current_setting('app.tenant_id', true) = '__CROSS_TENANT__'
    )
    WITH CHECK (
        client_id = current_setting('app.tenant_id', true)
        OR current_setting('app.tenant_id', true) = '__CROSS_TENANT__'
    );
