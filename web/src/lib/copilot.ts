import type { ReactNode } from "react";

/**
 * Copilot rail data shapes. The rail is prop-driven — NO API calls live in the
 * component (WO-U1). The frontend-integrator wires real handlers later.
 *
 * Three modes model the mockup's degraded states:
 *  - "normal"   full copilot (paid tier, write-capable role)
 *  - "readonly" role is read_only → view analyst questions, can't run/approve
 *  - "locked"   tier lacks the NL-Query copilot → paid-feature upsell
 */
export type CopilotMode = "normal" | "readonly" | "locked";

/** A grounded source a copilot answer cites. Opened via a Citation chip. */
export interface CopilotCitation {
  id: string;
  /** source class, e.g. "alert" | "rule" | "threat-intel" | "knowledge" */
  kind: string;
  /** short title, e.g. "Alert 92003 · WIN-APP-03" */
  title: string;
  /** the grounded source text shown in the popover */
  detail: string;
  /** label for the "open the underlying surface" action */
  openLabel?: string;
}

/** A suggested investigation query chip shown under an AI message. */
export interface SuggestedQuery {
  id: string;
  /** the question text on the chip */
  label: string;
  /** icon hint — "action" chips (e.g. containment) look distinct */
  kind?: "query" | "action";
}

/** One turn in the copilot thread. `content` may embed <Citation> chips. */
export interface CopilotMessage {
  id: string;
  who: "user" | "ai";
  content: ReactNode;
  chips?: SuggestedQuery[];
}
