/**
 * Closed-Loop / Feedback presentation helpers (WO-U9c) — label the mined
 * pattern types and the pre/post effectiveness verdict in plain language.
 *
 * Pure presentation of `GET /api/feedback/{patterns,effectiveness}`. It derives
 * nothing and fabricates nothing: an `effective` verdict of `null` (not enough
 * post-deployment data) is surfaced honestly as "not enough data yet", never
 * guessed. READ-ONLY — the rule proposals the loop generates are reviewed on the
 * Detection tab (also read-only for now).
 */

import type { ProposalEffectiveness } from "./types";

/** Plain-language name + colour for a mined pattern type. */
export function patternTypePresentation(t: string | null | undefined): {
  label: string;
  className: string;
} {
  switch ((t ?? "").toLowerCase()) {
    case "recurring_fp":
    case "recurring_false_positive":
      return { label: "Recurring false positive", className: "text-sev-med" };
    case "noisy_rule":
      return { label: "Noisy rule", className: "text-sev-med" };
    case "false_negative":
      return { label: "Missed detection", className: "text-sev-high" };
    case "tuning_opportunity":
      return { label: "Tuning opportunity", className: "text-acc" };
    default:
      return { label: t ? String(t).replace(/_/g, " ") : "Pattern", className: "text-dim" };
  }
}

/**
 * The pre/post effectiveness verdict for a deployed tuning proposal. `effective`
 * is `null` until there is enough post-deployment signal (< 5 decisions) — that
 * case is shown as an honest "not enough data yet", not a pass/fail.
 */
export function effectivenessPresentation(row: ProposalEffectiveness): {
  label: string;
  className: string;
  detail: string;
} {
  if (row.effective === null) {
    return {
      label: "Not enough data yet",
      className: "text-dim2",
      detail: `Only ${row.post_total_decisions} decision${
        row.post_total_decisions === 1 ? "" : "s"
      } since deploy — the loop needs at least 5 to judge.`,
    };
  }
  if (row.effective) {
    return {
      label: "Working",
      className: "text-teal",
      detail: "False-positive rate dropped and true-positive rate held.",
    };
  }
  return {
    label: "Not working",
    className: "text-sev-high",
    detail: "False positives did not drop enough, or true positives regressed.",
  };
}
