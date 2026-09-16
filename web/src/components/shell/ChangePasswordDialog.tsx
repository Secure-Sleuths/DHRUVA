"use client";

/**
 * ChangePasswordDialog (WO-H58) — self-service "Change password" for the
 * CURRENTLY signed-in user, available to EVERY authenticated role (it lives in
 * the account menu in the Topbar, NOT the admin-only tab). It wires to
 * `POST /api/my/password` (`changeMyPassword`) — the caller's own password only;
 * it never touches the admin reset path (`/api/admin/users`).
 *
 * Contract handling:
 *   - Three fields: current / new / confirm. Client-side we require confirm==new
 *     and pre-explain the policy (≥12 + upper/lower/digit/special) to disable a
 *     doomed submit — but the SERVER is the source of truth, so on a 400 we
 *     surface its `detail` message VERBATIM (wrong current password, policy
 *     failure, or new==current).
 *   - On 200 the server REVOKES the presenting token, so the session is dead.
 *     We show a brief "please sign in again" note and then run `onSignOut`
 *     (the Topbar's existing clearToken + /login path) — never leaving the user
 *     on a screen that will immediately 401.
 *   - Explicit loading (submit disabled + spinner), typed error, success states.
 *
 * Security: password values live only in local state for the lifetime of the
 * dialog and are cleared on close; they are NEVER logged or echoed back.
 */

import { useCallback, useEffect, useState } from "react";
import { Loader2 } from "lucide-react";
import { Dialog } from "@/components";
import { ApiError, changeMyPassword } from "@/lib/api";
import { cn, focusRing } from "@/lib/ui";

const FIELD_CLS =
  "mt-1 w-full rounded-lg border border-line bg-field px-2.5 py-2 text-data text-ink placeholder:text-dim2";
const BTN_PRIMARY =
  "rounded-md border-none bg-[#25406a] px-3 py-1.5 text-data text-white hover:brightness-110";
const BTN_NEUTRAL =
  "rounded-md border border-line bg-field px-2.5 py-1.5 text-data text-ink hover:bg-hover";

/**
 * Mirrors the server `password_policy_error` complexity rules. Used ONLY to
 * pre-disable submit + explain the requirement; the server re-checks and its
 * message wins. Never logs the value.
 */
function passwordIssue(pw: string): string | null {
  if (pw.length < 12) return "at least 12 characters";
  if (!/[A-Z]/.test(pw)) return "an uppercase letter";
  if (!/[a-z]/.test(pw)) return "a lowercase letter";
  if (!/[0-9]/.test(pw)) return "a digit";
  if (!/[!@#$%^&*()\-_=+[\]{}|;:',.<>?/`~]/.test(pw)) return "a special character";
  return null;
}

export interface ChangePasswordDialogProps {
  open: boolean;
  onClose: () => void;
  /**
   * Called after a successful change to end the (now-revoked) session — the
   * Topbar passes its existing clearToken + router.replace("/login") path so the
   * user is routed to sign in with the new password.
   */
  onSignOut: () => void;
}

export function ChangePasswordDialog({
  open,
  onClose,
  onSignOut,
}: ChangePasswordDialogProps) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  // Clear all secret state whenever the dialog closes so passwords never linger.
  useEffect(() => {
    if (!open) {
      setCurrent("");
      setNext("");
      setConfirm("");
      setSubmitting(false);
      setError(null);
      setDone(false);
    }
  }, [open]);

  const pwIssue = next ? passwordIssue(next) : "at least 12 characters";
  const confirmMismatch = confirm.length > 0 && confirm !== next;
  const canSubmit =
    !submitting &&
    !done &&
    current.length > 0 &&
    pwIssue === null &&
    confirm === next &&
    confirm.length > 0;

  const submit = useCallback(async () => {
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);
    try {
      await changeMyPassword(current, next);
      // Success: the server has revoked our token. Show the note, then hand off
      // to the sign-out path so the next screen is /login (never a 401 shell).
      setDone(true);
      window.setTimeout(() => onSignOut(), 1400);
    } catch (e) {
      // Surface the server's message verbatim (400 policy/current-password,
      // 429 rate-limit). ApiError.message already carries `detail`.
      if (e instanceof ApiError) {
        setError(
          e.status === 429
            ? "Too many attempts — please wait a minute and try again."
            : e.message,
        );
      } else {
        setError(e instanceof Error ? e.message : "Unable to change password.");
      }
      setSubmitting(false);
    }
  }, [canSubmit, current, next, onSignOut]);

  return (
    <Dialog open={open} onClose={onClose} title="Change password" maxWidth={440}>
      {done ? (
        <div role="status" className="text-data text-ink">
          <p className="text-grounded-ink">✓ Password changed.</p>
          <p className="mt-1 text-dim">
            Your session has ended — please sign in again with your new password.
          </p>
          <div className="mt-3 flex items-center gap-2 text-kbd text-dim">
            <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
            Redirecting to sign in…
          </div>
        </div>
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <div className="space-y-3">
            <div>
              <label className="text-kbd text-dim" htmlFor="cp-current">
                Current password<span className="ml-1 text-sev-crit">*</span>
              </label>
              <input
                id="cp-current"
                type="password"
                autoComplete="current-password"
                value={current}
                onChange={(e) => setCurrent(e.target.value)}
                disabled={submitting}
                className={cn(FIELD_CLS, focusRing)}
              />
            </div>

            <div>
              <label className="text-kbd text-dim" htmlFor="cp-new">
                New password<span className="ml-1 text-sev-crit">*</span>
              </label>
              <input
                id="cp-new"
                type="password"
                autoComplete="new-password"
                value={next}
                onChange={(e) => setNext(e.target.value)}
                disabled={submitting}
                aria-describedby="cp-policy"
                className={cn(FIELD_CLS, focusRing)}
              />
              <p id="cp-policy" className="mt-1 text-kbd text-dim2">
                {pwIssue
                  ? `Needs ${pwIssue} (min 12 chars with upper, lower, digit & special).`
                  : "Meets the password policy."}
              </p>
            </div>

            <div>
              <label className="text-kbd text-dim" htmlFor="cp-confirm">
                Confirm new password<span className="ml-1 text-sev-crit">*</span>
              </label>
              <input
                id="cp-confirm"
                type="password"
                autoComplete="new-password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                disabled={submitting}
                aria-invalid={confirmMismatch}
                className={cn(FIELD_CLS, focusRing)}
              />
              {confirmMismatch && (
                <p className="mt-1 text-kbd text-sev-crit">
                  Passwords don&apos;t match.
                </p>
              )}
            </div>
          </div>

          {error && (
            <p className="mt-3 text-kbd text-sev-crit" role="alert">
              {error}
            </p>
          )}

          <div className="mt-4 flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              disabled={submitting}
              className={cn(
                BTN_NEUTRAL,
                submitting && "cursor-not-allowed opacity-50",
                focusRing,
              )}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!canSubmit}
              className={cn(
                BTN_PRIMARY,
                "inline-flex items-center gap-1.5",
                !canSubmit && "cursor-not-allowed opacity-50",
                focusRing,
              )}
            >
              {submitting && (
                <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
              )}
              {submitting ? "Changing…" : "Change password"}
            </button>
          </div>
        </form>
      )}
    </Dialog>
  );
}
