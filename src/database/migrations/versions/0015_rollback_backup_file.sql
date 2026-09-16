-- ============================================================================
-- WO-H94 — record WHICH FILE a pre-deploy backup is a snapshot of.
-- ----------------------------------------------------------------------------
-- A rule deploy writes exactly one file: ai-soc-tuned.xml. The rollback chain
-- keyed on `detection_proposals.rule_file` instead — where the rule came FROM,
-- usually a stock Wazuh ruleset. So the "backup" was a copy of a file the
-- deploy never touched, and pressing rollback wrote that stale copy over the
-- stock ruleset while leaving the deployed rule live in ai-soc-tuned.xml.
--
-- `backup_xml` alone cannot say which file it came from, so after the fix
-- there is no way to tell a trustworthy snapshot from a poisoned one. This
-- column says it explicitly, and the rollback path refuses to restore a
-- snapshot into any file other than the one it names.
--
-- BACKFILL — A FACT, NOT A REINTERPRETATION. Before this change the backup was
-- read from `proposal['rule_file']`, at exactly one call site in
-- detection_agent.py, on both the single and bulk deploy paths. So for every
-- existing row `rule_file` IS the file `backup_xml` was read from. Copying it
-- into `backup_file` records what happened; it does not re-decide what the row
-- meant. The practical effect on a live install (measured 2026-08-22): of 28
-- deployed proposals, the 4 whose rule_file is already ai-soc-tuned.xml stay
-- rollback-able (their snapshot really is of the deployed file), and the other
-- 24 — snapshots of 0015/0020/0085/0095/0280/0315/0365 stock rulesets — are
-- refused by the rollback path instead of being written over the tuned
-- ruleset. That refusal is the point.
--
-- WHAT THIS MIGRATION DELIBERATELY DOES NOT DO: it does not touch
-- rule_deployment_history. Those 13 rows (all naming stock rulesets on the
-- install that was measured) are not rewritten, re-keyed or deleted.
-- `rule_file` there has always truthfully named the file `xml_before` was
-- read from — that half was never the bug — so keying the rollback lookup on
-- the file the deploy WROTE excludes them structurally, with no data edit
-- and nothing to undo if this judgement is ever revisited.
--
-- Idempotent: IF NOT EXISTS on the column; the backfill is guarded on
-- `backup_file IS NULL` so re-running is a no-op and rows written by the new
-- code are never overwritten.
--
-- ⚠ THIS FILE IS REFERENCE ONLY — it is NOT executed. The sibling
-- 0015_rollback_backup_file.py issues each statement separately and logs the
-- backfill rowcount (see 0010: a multi-statement blob half-applied on a live
-- install and reported success).
-- ============================================================================

ALTER TABLE detection_proposals
    ADD COLUMN IF NOT EXISTS backup_file TEXT;

-- Run the backfill cross-tenant. NOT optional: the migration role (`dhruva`)
-- has rolbypassrls = false and detection_proposals carries FORCE ROW LEVEL
-- SECURITY, so alembic runs with no tenant context and sees ZERO rows. Without
-- this line the UPDATE commits happily and changes nothing — the silent
-- success that WO-H87 already hit once on a live tenant.
SET LOCAL app.tenant_id = '__CROSS_TENANT__';

UPDATE detection_proposals
   SET backup_file = rule_file
 WHERE backup_file IS NULL
   AND backup_xml IS NOT NULL
   AND rule_file IS NOT NULL;

-- Back to fail-closed for the rest of the transaction: SET LOCAL survives to
-- the end of alembic's single migration transaction, and no later migration
-- should inherit a cross-tenant session it did not ask for.
SET LOCAL app.tenant_id = '';
