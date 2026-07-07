/**
 * SOAR-tab presentation helpers (WO-U9b) — execution-status labelling and a
 * plain-language summary of a playbook's trigger conditions. Pure presentation
 * of what the endpoint returned; derives nothing and fabricates nothing. NONE of
 * these carry a write affordance (toggle/run/approve/reject/rollback is a later
 * gated WO); status is shown read-only.
 */

import { parseJsonArray } from "./incident";
import { fmtPct } from "./format";
import type { SoarExecutionStatus, SoarPlaybook } from "./types";

/** Verdict codes → plain label (mirrors triage.ts verdict copy). */
const VERDICT_LABEL: Record<string, string> = {
  true_positive: "true positive",
  false_positive: "false positive",
  needs_investigation: "needs investigation",
  auto_close: "auto-close",
};

/**
 * Execution status → plain label + colour. Read-only: these describe where the
 * execution IS, they are not actions. `pending_approval` is warm (a human must
 * approve — active response stays human-approved), completed is teal, partial is
 * amber, failed is red, cancelled is dim.
 */
export function soarStatusPresentation(s: SoarExecutionStatus): {
  label: string;
  className: string;
} {
  switch (s) {
    case "pending_approval":
      return { label: "Awaiting approval", className: "text-gated-ink" };
    case "completed":
      return { label: "Completed", className: "text-teal" };
    case "partial":
      return { label: "Partial", className: "text-sev-med" };
    case "failed":
      return { label: "Failed", className: "text-sev-crit" };
    case "cancelled":
      return { label: "Cancelled", className: "text-dim" };
    default:
      return { label: String(s), className: "text-dim" };
  }
}

/** Count the action steps encoded in a playbook's JSON `actions` column. */
export function actionCount(
  actions: string | unknown[] | null | undefined,
): number {
  if (Array.isArray(actions)) return actions.length;
  return parseJsonArray(actions as string | null | undefined).length;
}

/**
 * A short plain-language summary of a playbook's firing conditions, built from
 * the trigger columns. Returns the pieces that are actually present — never
 * fabricates a condition that isn't set.
 */
export function triggerSummary(pb: SoarPlaybook): string {
  const parts: string[] = [];
  const verdicts = parseJsonArray(pb.trigger_verdicts);
  if (verdicts.length) {
    parts.push(
      "verdict " + verdicts.map((v) => VERDICT_LABEL[v] ?? v).join(" / "),
    );
  }
  if (pb.trigger_min_confidence != null) {
    parts.push(`confidence ≥ ${fmtPct(pb.trigger_min_confidence, { fraction: true })}`);
  }
  if (pb.trigger_min_risk_score != null) {
    parts.push(`risk ≥ ${Math.round(pb.trigger_min_risk_score)}`);
  }
  const techniques = parseJsonArray(pb.trigger_mitre_techniques);
  if (techniques.length) {
    parts.push(`ATT&CK ${techniques.join(", ")}`);
  }
  if (pb.trigger_ti_required === 1 || pb.trigger_ti_required === true) {
    parts.push("threat-intel match required");
  }
  return parts.length ? parts.join(" · ") : "No trigger conditions recorded";
}
