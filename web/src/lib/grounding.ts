/**
 * Grounding (AIS2) — the triage output-safety self-check, surfaced read-only.
 *
 * `assess_triage_grounding` (src/agents/grounding.py) scores how well an AI
 * triage verdict's stated reasoning is supported by the evidence it was given,
 * and persists the result in the nullable `grounding` column of
 * `agent_decisions`. That column rides the SAME `SELECT * FROM agent_decisions`
 * row the triage queue (`/api/triage/decisions`) and incident detail serve, so
 * it reaches the client on `decision.grounding` as a JSON STRING — or null for
 * non-triage / legacy rows that were never assessed.
 *
 * FLAG-ONLY / DECORATIVE. This is surfaced purely as an analyst-attention hint.
 * It NEVER mutates a verdict, auto-closes, escalates, or changes any decision
 * state (the AIS2 flag-only invariant). Both surfaces (the Triage glass-box card
 * and Daily Review) parse through this one helper so the boundary is shared.
 */

export type GroundingLevel = "high" | "medium" | "low";

/** Parsed shape of `assess_triage_grounding` (grounding.py return, ~line 307). */
export interface GroundingAssessment {
  grounding: GroundingLevel;
  /** model-agreement score in [0, 1]; null when the backend omitted it */
  score: number | null;
  /** claims the self-check couldn't tie back to the evidence */
  unsupported: string[];
  /** short reasons the self-check recorded for the level */
  reasons: string[];
}

const LEVELS: ReadonlySet<string> = new Set<GroundingLevel>([
  "high",
  "medium",
  "low",
]);

/**
 * Parse the raw `grounding` value into a typed assessment, or `null` when it is
 * absent / null / malformed / carries an unknown level. Accepts either the JSON
 * string the backend serializes or an already-parsed object (forward-compat).
 *
 * Callers render NOTHING on `null` — and also render nothing for the `"high"`
 * level (a well-grounded decision needs no flag); only `"low"` / `"medium"`
 * produce a badge.
 */
export function parseGrounding(raw: unknown): GroundingAssessment | null {
  if (raw == null) return null;

  let obj: unknown = raw;
  if (typeof raw === "string") {
    const trimmed = raw.trim();
    if (!trimmed) return null;
    try {
      obj = JSON.parse(trimmed);
    } catch {
      // Malformed JSON → render nothing (never guess a level).
      return null;
    }
  }

  if (typeof obj !== "object" || obj === null) return null;
  const rec = obj as Record<string, unknown>;
  const level = rec.grounding;
  if (typeof level !== "string" || !LEVELS.has(level)) return null;

  const score = typeof rec.score === "number" ? rec.score : null;
  const unsupported = Array.isArray(rec.unsupported)
    ? rec.unsupported.filter((x): x is string => typeof x === "string")
    : [];
  const reasons = Array.isArray(rec.reasons)
    ? rec.reasons.filter((x): x is string => typeof x === "string")
    : [];

  return { grounding: level as GroundingLevel, score, unsupported, reasons };
}

/** True when a decision's own self-check flagged it low-grounding. */
export function isLowGrounding(raw: unknown): boolean {
  return parseGrounding(raw)?.grounding === "low";
}
