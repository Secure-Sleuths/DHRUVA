-- M5 — Attack-chain grouping (correlation by MITRE tactic progression)
-- Adds explainability columns to incidents. Backward-compatible: both
-- columns are nullable/defaulted so existing rows and INSERTs are unaffected.

ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS attack_chain_id TEXT;

ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS attack_chain_tactics TEXT DEFAULT '[]';

-- Lets the chain-candidate lookup filter on linked incidents cheaply.
CREATE INDEX IF NOT EXISTS idx_incidents_attack_chain
    ON incidents(attack_chain_id);
