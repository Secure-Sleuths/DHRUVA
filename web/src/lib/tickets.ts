/**
 * Tickets-tab presentation helpers (WO-U9b) — ticket sync-status + priority
 * labelling for the READ-ONLY list. Pure presentation of what the endpoint
 * returned. NO write affordance: create/sync/retry are gated writes NOT wired
 * in this view.
 */

import type { Severity } from "./severity";
import type { TicketPlatformStatus } from "./types";

/**
 * DHRUVA-side sync status → plain label + colour. `synced`/`created` are healthy
 * (teal), `pending` is in-flight (amber), `error` failed (red), `closed` is dim.
 * This is DHRUVA's view of the sync — the provider's own status is shown
 * separately as `external_status`.
 */
export function ticketStatusPresentation(s: TicketPlatformStatus): {
  label: string;
  className: string;
} {
  switch (s) {
    case "created":
      return { label: "Created", className: "text-teal" };
    case "synced":
      return { label: "Synced", className: "text-teal" };
    case "pending":
      return { label: "Pending", className: "text-sev-med" };
    case "error":
      return { label: "Sync error", className: "text-sev-crit" };
    case "closed":
      return { label: "Closed", className: "text-dim" };
    default:
      return { label: String(s), className: "text-dim" };
  }
}

/**
 * Ticket priority string → a Severity key for a glyph+label+colour badge (never
 * colour alone). Returns null for an unknown/absent priority so the caller shows
 * a neutral dash rather than fabricating a severity.
 */
export function ticketPrioritySeverity(
  priority: string | null | undefined,
): Severity | null {
  switch ((priority ?? "").toLowerCase()) {
    case "critical":
    case "urgent":
    case "p0":
      return "crit";
    case "high":
    case "p1":
      return "high";
    case "medium":
    case "normal":
    case "p2":
      return "med";
    case "low":
    case "p3":
      return "low";
    default:
      return null;
  }
}
