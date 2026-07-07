-- WO-B2 + WO-B3 — Reason required on verdict + incident-status changes
-- Adds a nullable free-text "reason" column to each of the two tables that
-- record a human-driven state change, so the most-recent human-supplied
-- reason is queryable alongside the row it justifies. Full history continues
-- to live in the audit_log / incident_timeline.
--
-- ADDITIVE-ONLY / backward-compatible: both columns are nullable with no
-- default and no backfill. Existing (historical) rows keep NULL — they
-- predate the requirement, which is intended. INSERTs that omit the column
-- continue to succeed at the DB level; the mandatory-reason invariant is
-- enforced at the API layer (Pydantic), not by a NOT NULL constraint.

ALTER TABLE agent_decisions
    ADD COLUMN IF NOT EXISTS review_reason TEXT;

ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS status_reason TEXT;
