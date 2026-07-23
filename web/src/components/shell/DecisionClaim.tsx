"use client";

/**
 * DecisionClaim (WO-H25) — the alert-level claim affordance for the triage
 * queue's decision case view. WO-H24 gave analysts ownership of *incidents*;
 * this extends ownership down to the INDIVIDUAL triage decision so two
 * analysts working the queue never double-work the same item.
 *
 * DISCIPLINE (mirrors the server, never widens):
 *   - RBAC + ownership are mirrored from `src/api/routes/triage.py` via
 *     `rbac.ts::triageClaimGate` (analyst+; self-claim, unowned-only; release
 *     is owner-only — for EVERY role, admin included). A decision owned by a
 *     colleague renders as a plain "claimed by X" note — never a dead Claim
 *     button the server would 409. The server always re-checks.
 *   - The claim is ALWAYS to the caller: `POST .../claim` carries NO body and
 *     the server records its authenticated `sub`. Nothing client-supplied.
 *   - Explicit submitting / typed-error states; on success the caller's
 *     `onChanged` refetches so the queue reflects the new owner. No
 *     optimistic fabrication.
 *   - DEFENSIVE: `claimed_by` may be absent on older backends → "Unclaimed".
 */

import { useState } from "react";
import { claimDecision, unclaimDecision } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { triageClaimGate } from "@/lib/rbac";
import { cn, focusRing } from "@/lib/ui";

/** Same contract as GlassBoxCase's errMessage — local so this small control
 * doesn't pull the whole case module in (keeps it independently testable). */
function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : "Unknown error";
}

const BTN_PRIMARY =
  "rounded-md border-none bg-[#25406a] px-3 py-1.5 text-data text-white hover:brightness-110";
const BTN_NEUTRAL =
  "rounded-md border border-line bg-field px-2.5 py-1 text-meta text-ink hover:bg-hover";

/**
 * Ownership text for a queue row / case header — always renders something
 * honest: the owner when claimed, "Unclaimed" otherwise (including on older
 * backends that don't send the field at all).
 */
export function claimedLabel(claimedBy: string | null | undefined): string {
  return claimedBy ? `Claimed by ${claimedBy}` : "Unclaimed";
}

export function DecisionClaim({
  decisionId,
  claimedBy,
  onChanged,
}: {
  decisionId: string;
  /** the decision's current owner (`claimed_by`); null/absent = unclaimed. */
  claimedBy: string | null | undefined;
  /** refetch the queue/case after a successful claim/release. */
  onChanged: () => void;
}) {
  const { role, claims } = useAuth();
  const self = typeof claims?.sub === "string" ? claims.sub : null;
  const gate = triageClaimGate(role, claimedBy, self);

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async (fn: () => Promise<unknown>) => {
    setSubmitting(true);
    setError(null);
    try {
      await fn();
      onChanged();
    } catch (e) {
      setError(errMessage(e));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="text-kbd text-dim">
        {gate.ownedBySelf ? (
          <>
            Claimed by <b>you</b>
          </>
        ) : (
          claimedLabel(claimedBy)
        )}
      </span>

      {/* Claim — analyst+, unowned (or an idempotent re-claim shown as owned →
          the Release control replaces it). Owned-by-other renders the lock
          note instead of a dead button the server would 409. */}
      {gate.canClaim && !gate.ownedBySelf && (
        <button
          type="button"
          onClick={() => run(() => claimDecision(decisionId))}
          disabled={submitting}
          className={cn(
            BTN_PRIMARY,
            submitting ? "cursor-not-allowed opacity-50" : "",
            focusRing,
          )}
        >
          {submitting ? "Claiming…" : "Claim"}
        </button>
      )}

      {/* Release — owner-only (the server 409s anyone else). */}
      {gate.canUnclaim && (
        <button
          type="button"
          onClick={() => run(() => unclaimDecision(decisionId))}
          disabled={submitting}
          className={cn(
            BTN_NEUTRAL,
            submitting ? "cursor-not-allowed opacity-50" : "",
            focusRing,
          )}
        >
          {submitting ? "Releasing…" : "Release claim"}
        </button>
      )}

      {gate.ownedByOther && gate.lockNote && (
        <span className="text-kbd text-dim2">{gate.lockNote}</span>
      )}

      {error && (
        <span role="alert" className="text-kbd text-sev-crit">
          {error}
        </span>
      )}
    </div>
  );
}
