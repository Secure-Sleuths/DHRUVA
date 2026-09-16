-- ============================================================================
-- WO-H97 Phase 1 — store `response_urgency` and `kill_chain_stage`, use neither
-- ----------------------------------------------------------------------------
-- The triage prompt has asked the model for both fields since it was written
-- (src/agents/prompts/__init__.py: "response_urgency" and "kill_chain_stage").
-- The LLM backend returns whatever JSON the model produced (a plain
-- json.loads), so by the time triage_agent.py builds the decision record the
-- answers are already sitting in a Python dict. Nothing has ever read them and
-- no column has ever existed to hold them.
--
-- So they are free to collect and worthless to trust: nobody has ever seen what
-- the model says. A shadow replay of 24 stored decisions through the real
-- prompt and the tenant's configured model answered `24h` 21 times, returned
-- `immediate` for a stored FALSE POSITIVE, and once answered `none`, which is
-- not in the schema at all. That replay was not perfectly faithful, which is
-- exactly why the field gets a column and not a behaviour.
--
-- These columns are therefore NULLABLE and WIRED TO NOTHING. Severity is
-- computed by src/incidents/severity.py from the risk score and structured
-- alert facts; it does not read either column. Deriving severity from urgency
-- is Phase 2 and only happens if two weeks of real traffic earn it:
--
--     SELECT verdict, response_urgency, count(*)
--       FROM agent_decisions
--      WHERE response_urgency IS NOT NULL
--      GROUP BY 1, 2 ORDER BY 1, 2;
--
-- If each verdict maps to essentially one urgency, the field is a re-encoding
-- of the verdict and buys nothing.
--
-- NULL MEANS "WE ASKED BEFORE WE WERE LISTENING". It never means "low urgency"
-- or "recon". Every row written before this migration is NULL and there is
-- deliberately NO BACKFILL — the answers were not stored, so there is nothing
-- to recover, and inventing one would be fabricating a model output.
--
-- Only the four documented urgency literals are ever written (the whitelist
-- lives in triage_agent.py, mirroring the VALID_VERDICTS clamp); anything else
-- is stored as NULL. The alert body is attacker-controlled text that reaches
-- the prompt, so a free-text column here would be an injection sink.
--
-- ⚠ THIS FILE IS REFERENCE ONLY — it is NOT executed. The sibling
-- 0016_decision_urgency_shadow.py issues each statement separately (see 0010
-- for why a multi-statement blob is not used).
-- ============================================================================

ALTER TABLE agent_decisions
    ADD COLUMN IF NOT EXISTS response_urgency TEXT;

ALTER TABLE agent_decisions
    ADD COLUMN IF NOT EXISTS kill_chain_stage TEXT;

-- Partial index over the rows that have an answer. The shadow analysis groups
-- by (verdict, response_urgency) over the non-NULL rows, and for the first two
-- weeks those are a small minority of the table.
CREATE INDEX IF NOT EXISTS idx_decisions_response_urgency
    ON agent_decisions (response_urgency)
    WHERE response_urgency IS NOT NULL;
