/**
 * Detection-tab presentation helpers (WO-U9) — change-type + status labelling
 * and a client-side line-diff of a proposal's original vs proposed rule XML.
 *
 * The backend stores `original_xml` + `proposed_xml` as-is (no pre-computed
 * diff), so the "reviewed like code" view diffs them here. This is pure
 * presentation of what the endpoint returned — it derives nothing and fabricates
 * nothing. NONE of these carry a write affordance (approve/deploy/reject/rollback
 * is a later gated WO); status is shown read-only.
 */

import type { DetectionChangeType, DetectionProposalStatus } from "./types";

/** Plain-language + colour for a proposal change type (glyph optional). */
export function changeTypePresentation(t: DetectionChangeType): {
  label: string;
  className: string;
} {
  switch (t) {
    case "tune":
      return { label: "Tune threshold", className: "text-acc" };
    case "modify":
      return { label: "Modify rule", className: "text-acc" };
    case "new_rule":
      return { label: "New rule", className: "text-teal" };
    case "disable":
      return { label: "Disable rule", className: "text-sev-med" };
    default:
      return { label: String(t), className: "text-dim" };
  }
}

/**
 * Status → plain label + colour + whether it's a terminal state. Read-only:
 * these describe where the proposal IS, they are not actions.
 */
export function statusPresentation(s: DetectionProposalStatus): {
  label: string;
  className: string;
} {
  switch (s) {
    case "proposed":
      return { label: "Awaiting review", className: "text-sev-med" };
    case "needs_manual_tuning":
      return { label: "Manual fix needed", className: "text-gated-ink" };
    case "approved":
      return { label: "Approved · not deployed", className: "text-acc" };
    case "deployed":
      return { label: "Deployed", className: "text-teal" };
    case "rejected":
      return { label: "Rejected", className: "text-dim" };
    case "rolled_back":
      return { label: "Rolled back", className: "text-dim" };
    default:
      return { label: String(s), className: "text-dim" };
  }
}

export type DiffKind = "ctx" | "add" | "del";
export interface DiffLine {
  kind: DiffKind;
  text: string;
}

/**
 * A minimal LCS line-diff — enough for the small rule-XML blocks the Detection
 * Agent proposes. Returns an ordered list of context / added / removed lines.
 * O(n·m) on line counts (fine for tens of lines). Handles null (a `new_rule` has
 * no original; a `disable` may have an empty proposed) by treating it as "".
 */
export function lineDiff(
  original: string | null | undefined,
  proposed: string | null | undefined,
): DiffLine[] {
  const a = (original ?? "").length ? (original as string).split("\n") : [];
  const b = (proposed ?? "").length ? (proposed as string).split("\n") : [];

  // LCS length table.
  const n = a.length;
  const m = b.length;
  const dp: number[][] = Array.from({ length: n + 1 }, () =>
    new Array(m + 1).fill(0),
  );
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] =
        a[i] === b[j]
          ? dp[i + 1][j + 1] + 1
          : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }

  // Walk the table to produce the diff.
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ kind: "ctx", text: a[i] });
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      out.push({ kind: "del", text: a[i] });
      i++;
    } else {
      out.push({ kind: "add", text: b[j] });
      j++;
    }
  }
  while (i < n) out.push({ kind: "del", text: a[i++] });
  while (j < m) out.push({ kind: "add", text: b[j++] });
  return out;
}
