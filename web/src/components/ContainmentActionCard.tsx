"use client";

import { useRef, useState, type ReactNode } from "react";
import { ShieldAlert } from "lucide-react";
import { cn, focusRing } from "@/lib/ui";
import { Chip } from "./Chip";

/**
 * ContainmentActionCard — the copilot's containment card.
 *
 * ACTIVE RESPONSE IS HUMAN-APPROVED. This card states it is gated, NEVER
 * implies auto-execution, and REQUIRES a reason before it fires (the reason is
 * destined for the audit trail). The first click reveals the reason box and
 * focuses it; a second click with a non-empty reason invokes `onApprove(reason)`.
 * The button is disabled unless the role can act.
 *
 * Two `mode`s, same "human-approved, reason-required, never auto-executes" spine:
 *   - "approve"  (default) — the senior_analyst+ approval step; button
 *                "Approve & run" → confirms an already-proposed action.
 *   - "propose"  — the analyst+ PROPOSE step (WO-U6 Investigate); button
 *                "Propose containment" → QUEUES the action for human approval in
 *                the Respond queue. It explicitly does NOT execute, approve, or
 *                reverse anything.
 *
 * The component only signals intent via callbacks — it never executes anything.
 *
 * @example
 *   <ContainmentActionCard
 *     mode="propose"
 *     title="Isolate WIN-APP-03"
 *     description={<>Host containment via EDR … <Citation …/></>}
 *     canApprove={roleAtLeast(role, "analyst")}
 *     gateHint={canPropose ? "you can propose" : "needs analyst+"}
 *     onApprove={(reason) => propose(reason)}
 *     onDecline={decline}
 *   />
 */
export interface ContainmentActionCardProps {
  /** the proposed action, e.g. "Isolate WIN-APP-03" */
  title: string;
  /** rationale (may embed <Citation> chips) */
  description: ReactNode;
  /**
   * "approve" (default) = the approval step (Approve & run); "propose" = the
   * PROPOSE-ONLY step that queues the action for human approval (never executes).
   */
  mode?: "approve" | "propose";
  /** role gate — only true lets the analyst act (approve OR propose per mode) */
  canApprove: boolean;
  /** trailing hint, e.g. "you can approve" / "needs analyst+" */
  gateHint: string;
  /** invoked with the required reason on a confirmed approve/propose */
  onApprove: (reason: string) => void;
  onDecline: () => void;
  className?: string;
}

export function ContainmentActionCard({
  title,
  description,
  mode = "approve",
  canApprove,
  gateHint,
  onApprove,
  onDecline,
  className,
}: ContainmentActionCardProps) {
  const [showReason, setShowReason] = useState(false);
  const [reason, setReason] = useState("");
  const [error, setError] = useState(false);
  const reasonRef = useRef<HTMLTextAreaElement>(null);
  const isPropose = mode === "propose";

  const handleApprove = () => {
    if (!canApprove) return;
    if (!showReason) {
      setShowReason(true);
      requestAnimationFrame(() => reasonRef.current?.focus());
      return;
    }
    if (!reason.trim()) {
      setError(true);
      reasonRef.current?.focus();
      return;
    }
    onApprove(reason.trim());
  };

  return (
    <div
      className={cn(
        "mt-2 rounded-lg border border-gated-border bg-gated-bg p-3",
        className,
      )}
    >
      <div className="flex items-center gap-2">
        <ShieldAlert
          className="h-4 w-4 text-gated-ink"
          aria-hidden="true"
        />
        <b className="text-body">Proposed action — {title}</b>
        <Chip variant="gated" className="ml-auto">
          gated
        </Chip>
      </div>

      <div className="my-1.5 text-data leading-relaxed text-dim">{description}</div>

      {/* the invariant, stated plainly — never implies auto-execution */}
      <div className="mb-1.5 flex items-start gap-1 text-kbd text-dim2">
        <span aria-hidden="true">🔒</span>
        {isPropose ? (
          <span>
            Active response is <b>human-approved</b>. Proposing does <b>not</b>{" "}
            execute — it queues the action in the <b>Respond</b> queue for a human
            to approve. A reason is required for the audit trail.
          </span>
        ) : (
          <span>
            Active response is <b>human-approved</b>. The copilot will not
            execute — you approve, and a reason is required for the audit trail.
          </span>
        )}
      </div>

      {showReason && (
        <div className="mb-1.5">
          <label htmlFor="containment-reason" className="sr-only">
            Reason (required)
          </label>
          <textarea
            id="containment-reason"
            ref={reasonRef}
            rows={2}
            value={reason}
            onChange={(e) => {
              setReason(e.target.value);
              if (e.target.value.trim()) setError(false);
            }}
            aria-invalid={error}
            placeholder="Reason (required) — logged to audit + attached to the action…"
            className={cn(
              "w-full resize-none rounded-md border bg-field p-2 text-data text-ink placeholder:text-dim2",
              error ? "border-sev-crit" : "border-line",
              focusRing,
            )}
          />
          {error && (
            <p className="mt-1 text-kbd text-sev-crit" role="alert">
              {isPropose
                ? "A reason is required to propose a containment."
                : "A reason is required to run a response."}
            </p>
          )}
        </div>
      )}

      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={handleApprove}
          disabled={!canApprove}
          className={cn(
            "rounded-md border px-2.5 py-1 text-meta",
            focusRing,
            canApprove
              ? "cursor-pointer border-grounded-border bg-grounded-border/40 text-grounded-ink hover:brightness-125"
              : "cursor-not-allowed border-line bg-field text-dim opacity-50",
          )}
        >
          {isPropose
            ? showReason
              ? "Confirm proposal"
              : "Propose containment"
            : showReason
              ? "Confirm & run"
              : "Approve & run"}
        </button>
        <button
          type="button"
          onClick={onDecline}
          className={cn(
            "cursor-pointer rounded-md border border-line bg-field px-2.5 py-1 text-meta text-ink hover:bg-hover",
            focusRing,
          )}
        >
          Decline
        </button>
        <span className="ml-auto self-center text-kbd text-dim2">{gateHint}</span>
      </div>
    </div>
  );
}
