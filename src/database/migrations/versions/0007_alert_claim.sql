-- WO-H25 — alert-level claim (ownership of the individual triage decision)
-- Adds two nullable columns to agent_decisions so an analyst can claim an
-- alert/decision in the triage queue and colleagues can see it is being
-- worked ("claimed by X"), preventing two analysts double-working one item:
--
--   * agent_decisions.claimed_by  TEXT  (username of the claiming analyst)
--   * agent_decisions.claimed_at  TEXT  (ISO timestamp of the claim)
--
-- Extends WO-H24 (incident-level self-claim) down to the individual decision,
-- per the operator's ratified "L1 is an operator" decision.
--
-- ADDITIVE-ONLY / backward-compatible: both columns are nullable with no
-- default and no backfill. Existing (historical) rows keep NULL — they are
-- simply unclaimed. INSERTs that omit the columns continue to succeed. No
-- data mutation. Reversible by being additive (downgrade drops both).
--
-- RLS / tenant policy is deliberately NOT touched: agent_decisions already
-- carries client_id and every read/write goes through _tenant_filter(); the
-- new columns need no policy change.

ALTER TABLE agent_decisions
    ADD COLUMN IF NOT EXISTS claimed_by TEXT;

ALTER TABLE agent_decisions
    ADD COLUMN IF NOT EXISTS claimed_at TEXT;
