-- AIS2 — AI output faithfulness / grounding on triage verdicts
-- Adds a nullable free-text column that stores the evidence-derived grounding
-- assessment (JSON blob: grounding band, score, unsupported/fabricated
-- evidence_refs, reasons) computed by src/agents/grounding.py alongside each
-- triage decision, so a confident-but-unsupported verdict is auditable and can
-- be surfaced to the analyst as "needs attention, not confident".
--
-- ADDITIVE-ONLY / backward-compatible: the column is nullable with no default
-- and no backfill. Existing (historical) rows keep NULL — they predate the
-- grounding check, which is intended. INSERTs that omit the column continue to
-- succeed. No data mutation. Reversible by being additive (downgrade drops it).

ALTER TABLE agent_decisions
    ADD COLUMN IF NOT EXISTS grounding TEXT;
