/**
 * Hunt-tab presentation helpers (WO-U9c) — map a finding's priority to the
 * shared severity p-scale and label its review status in plain language.
 *
 * Pure presentation of what `GET /api/hunt/{findings,library}` returned — it
 * derives nothing and fabricates nothing. NONE of these carry a write
 * affordance (confirm/dismiss/replay is a later senior_analyst+ gated WO); a
 * finding's status is shown read-only.
 */

import { asBool } from "./format";
import { type Severity } from "./severity";
import type { HuntFinding } from "./types";

/** Map a hunt-finding `priority` string to the shared severity p-scale. */
export function huntPrioritySeverity(priority: string | null | undefined): Severity {
  switch ((priority ?? "").toLowerCase()) {
    case "critical":
      return "crit";
    case "high":
      return "high";
    case "medium":
      return "med";
    case "low":
      return "low";
    default:
      return "info";
  }
}

/**
 * Plain-language review state for a finding + a colour. Combines the `status`
 * column with the `confirmed` 0/1 flag so a "confirmed threat" reads distinctly
 * from a "dismissed" or still-"open" finding. Read-only — this describes where
 * the finding IS, it is not an action.
 */
export function huntFindingState(finding: HuntFinding): {
  label: string;
  className: string;
} {
  const status = (finding.status ?? "").toLowerCase();
  if (status === "confirmed" || asBool(finding.confirmed)) {
    return { label: "Confirmed threat", className: "text-sev-crit" };
  }
  if (status === "dismissed") {
    return { label: "Dismissed", className: "text-dim" };
  }
  if (status === "reviewed") {
    return { label: "Reviewed", className: "text-teal" };
  }
  // default / "open"
  return { label: "Awaiting review", className: "text-sev-med" };
}
