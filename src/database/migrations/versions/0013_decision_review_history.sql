-- ============================================================================
-- WO-H85 — append-only review history for alert (agent_decisions) verdicts
-- ----------------------------------------------------------------------------
-- `apply_human_override` (src/database/store.py) is a bare overwrite:
--
--     UPDATE agent_decisions
--     SET human_override = %s, human_verdict = %s, review_reason = %s, ...
--
-- so when a second analyst overrides a colleague's verdict, the FIRST reviewer's
-- name and their reason are gone — not archived, not versioned. Incidents keep
-- their history by accident (`incident_timeline` carries every status change and
-- its reason); alerts had no equivalent. This table is that equivalent.
--
-- It is APPEND-ONLY BY CONVENTION AND BY USE: the DAO only ever INSERTs into it
-- (`_record_decision_review`), never UPDATEs or DELETEs a row. Each entry
-- records WHO reviewed, WHEN, the verdict they recorded, their free-text reason,
-- and the verdict their review REPLACED (`previous_verdict`) — so a reviewer can
-- see they are disagreeing with someone BEFORE they override, and the
-- AI-verdict-corrected-by-a-human signal survives.
--
-- `reason` stays FREE TEXT deliberately. The value in a closure reason is the
-- specific finding ("48 checksum changes inside a three-second window, the
-- signature of package management") — no enum captures that.
--
-- ORDERING: `seq BIGSERIAL` rather than `created_at`. `created_at` is written as
-- `CURRENT_TIMESTAMP::text` (transaction start time) exactly like
-- `incident_timeline`, which is fine for display but can tie for two reviews
-- landing in the same instant. `seq` gives a strict, monotonic read order, which
-- is what "both entries readable, IN ORDER" needs.
--
-- TENANT SCOPING — FK-scoped, the `incident_timeline` pattern:
--   The table carries NO `client_id`. Its tenant owner is defined transitively
--   through `decision_id` → `agent_decisions.id`, which IS directly scoped
--   (`client_id` + the 0006 `tenant_isolation` RLS policy). That mirrors
--   `incident_alerts` / `incident_timeline` (see 0008) and keeps the DAO's
--   join reads unambiguous: `{tf}` = `AND client_id = %s` resolves to
--   `agent_decisions.client_id` with no column-name collision.
--   The RLS backstop is therefore the same SUBQUERY policy 0008 installs:
--       USING (decision_id IN (SELECT id FROM agent_decisions))
--   The inner select is itself RLS-scoped by 0006, so composition with the
--   `app.tenant_id` session GUC is automatic:
--     value = tenant_id          → only that tenant's decisions → its rows only
--     value = '__CROSS_TENANT__' → all decision ids            → all rows
--     value = '' / unset         → no decision ids             → no rows
--   Same NON-SUPERUSER / NON-BYPASSRLS role requirement as 0006/0008.
--
-- ADDITIVE-ONLY: a new table, no column added to and no data mutated on any
-- existing table. NO BACKFILL — historical rows have no recoverable history, and
-- fabricating one would invent reviewers who never reviewed anything.
--
-- Idempotent: IF NOT EXISTS everywhere, DROP POLICY IF EXISTS before CREATE.
-- ============================================================================

CREATE TABLE IF NOT EXISTS decision_reviews (
    id                TEXT PRIMARY KEY,
    seq               BIGSERIAL NOT NULL,
    decision_id       TEXT NOT NULL,
    reviewer          TEXT NOT NULL,
    human_verdict     TEXT,
    reason            TEXT,
    -- the verdict this review replaced (NULL = this was the first human
    -- verdict on the alert). Makes "you are disagreeing with X" readable
    -- without re-deriving it from the neighbouring rows.
    previous_verdict  TEXT,
    -- how the entry was created: 'human_review' (a person reviewed THIS alert)
    -- or 'incident_verdict_propagation' (an incident-level, opt-in bulk apply
    -- that only ever fills an EMPTY verdict). Kept so the Feedback Loop and any
    -- accuracy measurement can tell an individually-judged alert from one that
    -- inherited its label.
    source            TEXT NOT NULL DEFAULT 'human_review',
    created_at        TEXT NOT NULL,
    FOREIGN KEY (decision_id) REFERENCES agent_decisions(id)
);

CREATE INDEX IF NOT EXISTS idx_decision_reviews_decision
    ON decision_reviews(decision_id, seq);
CREATE INDEX IF NOT EXISTS idx_decision_reviews_created
    ON decision_reviews(created_at);

DO $$
BEGIN
    EXECUTE 'ALTER TABLE decision_reviews ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE decision_reviews FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON decision_reviews';
    EXECUTE
        'CREATE POLICY tenant_isolation ON decision_reviews '
        'USING (decision_id IN (SELECT id FROM agent_decisions)) '
        'WITH CHECK (decision_id IN (SELECT id FROM agent_decisions))';
END $$;
