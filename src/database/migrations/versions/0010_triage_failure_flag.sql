-- ============================================================================
-- WO-H46-b — make a triage FAILURE distinguishable from a real verdict
-- ----------------------------------------------------------------------------
-- When the LLM is unreachable, triage_agent.py fails CLOSED: it writes
--     verdict = 'needs_investigation', escalated = true, confidence = 0.0
-- and a reasoning string beginning 'Triage agent error: '.
--
-- Failing closed is CORRECT and is NOT changed by this migration — the agent
-- must never guess "benign" with its brain offline.
--
-- The defect is that the failure was invisible in the `verdict` column: on a
-- dashboard, N dead LLM calls looked identical to N considered escalations.
-- Measured on wazuh-server 2026-07-20: ~37 rows (rules 5402 sudo-to-root and
-- 5501 PAM session) were logged as needs_investigation WITHOUT ever being
-- analyzed, and sat in the escalation queue looking like real decisions. The
-- only tells were confidence = 0.0 and a reasoning prefix — neither queryable
-- nor alertable.
--
-- This adds an explicit, queryable `llm_failed` flag.
--
-- WHY THIS MATTERS BEYOND THE DASHBOARD: agent_decisions feeds
-- get_fp_rate_for_rule() (historical_fp_rate, injected into the triage prompt)
-- and the feedback loop's FP mining. Un-analyzed rows counted as real triage
-- history inflate `total` and depress fp_rate, which then feeds back into
-- future verdicts and Detection Agent tuning proposals. store.py excludes
-- llm_failed rows from that computation as part of the same change.
--
-- BACKFILL: existing failure rows are identified by the reasoning prefix,
-- which is the only marker they carry. The prefix is a stable literal emitted
-- at a single site (triage_agent.py). Rows are matched with LIKE on that exact
-- anchored prefix, so a genuine verdict whose text merely mentions the phrase
-- mid-sentence is not caught.
--
-- Idempotent: IF NOT EXISTS throughout; the backfill is naturally idempotent
-- (re-running sets already-true rows to true).
--
-- ⚠ THIS FILE IS REFERENCE ONLY — it is NOT executed.
--
-- The sibling 0010_triage_failure_flag.py issues each statement separately and
-- BINDS the LIKE pattern. Do not go back to executing this file wholesale.
--
-- Why: a literal '%' inside a SQL string handed to psycopg is parsed as a
-- parameter placeholder ("only '%s', '%b', '%t' are allowed as placeholders,
-- got '%''"). Shipped as one multi-statement blob on a live install
-- (2026-07-20, wazuh-server) the DDL applied, the trailing UPDATE did not,
-- alembic reported SUCCESS, and the backfill flagged 0 of 1398 matching rows.
-- A migration that half-applies without raising is worse than one that fails.
-- The .py now binds the pattern and logs the affected rowcount.
-- ============================================================================

ALTER TABLE agent_decisions
    ADD COLUMN IF NOT EXISTS llm_failed BOOLEAN NOT NULL DEFAULT FALSE;

-- Partial index: failures are the rare case, so only index those rows. Keeps
-- "show me the LLM outages" and the failure-rate health signal index-served
-- without adding write cost for the overwhelmingly common false case.
CREATE INDEX IF NOT EXISTS idx_decisions_llm_failed
    ON agent_decisions (created_at)
    WHERE llm_failed;

-- Backfill historical failure rows written before the flag existed.
UPDATE agent_decisions
   SET llm_failed = TRUE
 WHERE llm_failed = FALSE
   AND reasoning LIKE 'Triage agent error: %';
