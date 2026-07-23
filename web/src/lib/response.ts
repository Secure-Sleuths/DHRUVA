/**
 * Respond-tab presentation helpers (WO-U9b) — active-response action / mode /
 * status labelling for the READ-ONLY queue + audit view. Pure presentation of
 * what the endpoint returned. This module carries NO write affordance: the
 * Respond tab never proposes/approves/executes/reverses — approving a queued
 * containment is a human-gated senior_analyst+ write delivered in a dedicated
 * later WO, and active response stays human-approved (never auto).
 */

import type { ArMode, ArStatus } from "./types";

/** Active-response action code → plain label. Typed loosely for forward-compat. */
const ACTION_LABEL: Record<string, string> = {
  block_ip: "Block IP",
  unblock_ip: "Unblock IP",
  isolate_host: "Isolate host",
  unisolate_host: "Un-isolate host",
  kill_process: "Kill process",
  disable_user: "Disable user",
  enable_user: "Enable user",
  quarantine_file: "Quarantine file",
  restart_agent: "Restart agent",
  dns_sinkhole: "DNS sinkhole",
};

export function actionLabel(action: string): string {
  return ACTION_LABEL[action] ?? action;
}

/**
 * Mode → plain label + colour + whether it is the auto path. `auto` is a blessed
 * auto-block policy that fired without a human in the loop (still logged +
 * reversible); `manual` is an analyst-initiated action.
 */
export function modePresentation(m: ArMode): {
  label: string;
  className: string;
} {
  switch (m) {
    case "auto":
      return { label: "Auto", className: "text-gated-ink" };
    case "manual":
      return { label: "Manual", className: "text-dim" };
    default:
      return { label: String(m), className: "text-dim" };
  }
}

/**
 * Status → plain label + colour. Read-only: these describe where the action IS,
 * they are not controls. `pending_approval` = queued, never dispatched;
 * `executed` = live (a block is active until it expires or is reversed).
 */
export function arStatusPresentation(s: ArStatus): {
  label: string;
  className: string;
} {
  switch (s) {
    case "pending_approval":
      return { label: "Awaiting approval", className: "text-gated-ink" };
    case "executed":
      return { label: "Executed · active", className: "text-teal" };
    case "reversed":
      return { label: "Reversed", className: "text-dim" };
    case "expired":
      return { label: "Expired", className: "text-dim" };
    case "denied":
      return { label: "Denied", className: "text-sev-crit" };
    case "not_applied":
      return { label: "Not applied · no agent target", className: "text-gated-ink" };
    default:
      return { label: String(s), className: "text-dim" };
  }
}
