/**
 * Confidence ramp — NEUTRAL by design.
 *
 * Confidence is a model self-assessment (0..1), NOT a severity. It uses a
 * blue → teal ramp and must never borrow the severity colours: red belongs to
 * severity alone, so a "low confidence" score can never be misread as a
 * "critical" one. This is a hard rule (see docs/PLAN-ui-redesign.md).
 */

export type ConfidenceTier = "low" | "medium" | "high";

/** Bucket a 0..1 score. ≥0.8 high (teal), ≥0.5 medium (blue), else low. */
export function confidenceTier(value: number): ConfidenceTier {
  if (value >= 0.8) return "high";
  if (value >= 0.5) return "medium";
  return "low";
}

/** Fill colour for the confidence bar — neutral ramp only (token hexes). */
export function confidenceColor(value: number): string {
  switch (confidenceTier(value)) {
    case "high":
      return "#22d3aa"; // token: teal
    case "medium":
      return "#6ea8fe"; // token: acc
    case "low":
      return "#41618f"; // dim blue — still on the neutral (blue) ramp
  }
}

/** `0.86` → `"0.86"` (two decimals, tabular-friendly). */
export function formatConfidence(value: number): string {
  return value.toFixed(2);
}
