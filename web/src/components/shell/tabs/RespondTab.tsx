"use client";

/**
 * RespondTab — the active-response queue → LIFECYCLE view (approve / reverse)
 * plus the durable audit trail.
 *
 * Reads:
 *   - `GET /api/response/queue` (`getResponseQueue`, active/pending blocks)
 *   - `GET /api/response/audit` (`getResponseAudit`, the full durable trail)
 * Both are `require_role(read_only+)` server-side, surfaced to senior_analyst+
 * by the shell ACL.
 *
 * Writes (HUMAN-GATED, this WO):
 *   - Approve & execute a pending proposal → `POST /api/response/approve/{id}`.
 *     On this server, approving a proposal ALSO dispatches it to Wazuh in the
 *     same call — there is no approved-but-not-executed state, so the single
 *     "Approve & execute" control IS the execute step, scoped (per the WO) to an
 *     already-proposed/queued action. Behind an explicit confirm dialog that
 *     shows exactly what will run (action, target IP, agent, mode, TTL, reason).
 *   - Reverse an active block → `POST /api/response/reverse/{id}`. Only offered
 *     for an executed `block_ip` (the server 409s otherwise). Behind its own
 *     explicit confirm dialog.
 *
 * SECURITY POSTURE (the standing rule — unchanged by this UI):
 *   - Active response stays HUMAN-APPROVED BY DEFAULT. This UI surfaces the
 *     EXISTING server-gated human actions; it NEVER auto-executes and changes NO
 *     server default. Auto-block remains a separate blessed policy (block_ip only,
 *     OFF by default, behind the fail-closed gate) and is not touched here.
 *   - Approve and reverse are both senior_analyst+ server-side; the client MIRRORS
 *     that exactly via `responseActionGate` (lib/rbac) and FAILS CLOSED — below
 *     senior_analyst the controls are shown locked, never widened. The server
 *     re-checks and remains the enforcement point.
 *   - The standalone `POST /api/response/execute` (un-queued, free-form direct
 *     path) is intentionally NOT surfaced — no free-typed agent/target form.
 *   - Every transition is durably audited server-side; the audit trail below is
 *     never hidden or edited from here.
 *
 * States: loading / empty / error+retry; per-action submitting + typed error
 * (402/403 → locked affordance, 409/404 → "changed, refreshing", never a crash);
 * PollingStatus (30s, aborts on unmount). Fixtures gate behind
 * NEXT_PUBLIC_DHRUVA_FIXTURES (approve/reverse short-circuit to a synthetic
 * success with NO real mutation).
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Chip,
  Dialog,
  Panel,
  PollingStatus,
  StatusState,
  FeatureLockedState,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
} from "@/components";
import { PageHeading } from "../PageHeading";
import {
  ApiError,
  approveResponseAction,
  getResponseAudit,
  getResponseQueue,
  reverseResponseAction,
} from "@/lib/api";
import {
  actionLabel,
  arStatusPresentation,
  modePresentation,
} from "@/lib/response";
import { responseActionGate, type ResponseActionGate } from "@/lib/rbac";
import { useAuth } from "@/lib/auth";
import { cn, focusRing } from "@/lib/ui";
import { DASH, fmtDateTime } from "@/lib/format";
import type { TabProps } from "../tabRegistry";
import type { ArAction } from "@/lib/types";

const POLL_MS = 30_000;

function isLockError(e: unknown): boolean {
  return e instanceof ApiError && (e.status === 402 || e.status === 403);
}
function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : "Unknown error";
}

interface State {
  queue: ArAction[] | null;
  audit: ArAction[] | null;
  error: string | null;
  locked: boolean;
  loading: boolean;
}

/** An in-flight confirm: which transition, on which row. */
type Pending = { kind: "approve" | "reverse"; row: ArAction };
/** A transient result banner. */
type Flash = { tone: "ok" | "warn"; msg: string };

export function RespondTab(_props: TabProps) {
  const { role } = useAuth();
  const gate = responseActionGate(role);

  const [state, setState] = useState<State>({
    queue: null,
    audit: null,
    error: null,
    locked: false,
    loading: true,
  });
  const [secondsAgo, setSecondsAgo] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  // ---- active-response write (approve / reverse) --------------------------
  const [confirm, setConfirm] = useState<Pending | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [flash, setFlash] = useState<Flash | null>(null);

  const load = useCallback(async (manual: boolean) => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    if (manual) setRefreshing(true);
    try {
      const [queue, audit] = await Promise.all([
        getResponseQueue({ limit: 100 }, ac.signal),
        getResponseAudit({ limit: 200 }, ac.signal),
      ]);
      if (ac.signal.aborted) return;
      setState({
        queue: queue.queue,
        audit: audit.audit,
        error: null,
        locked: false,
        loading: false,
      });
      setSecondsAgo(0);
    } catch (e) {
      if (ac.signal.aborted) return;
      if (isLockError(e)) {
        setState({
          queue: null,
          audit: null,
          error: null,
          locked: true,
          loading: false,
        });
        return;
      }
      const msg = errMessage(e);
      setState((prev) =>
        prev.audit
          ? { ...prev, loading: false }
          : {
              queue: null,
              audit: null,
              error: msg,
              locked: false,
              loading: false,
            },
      );
    } finally {
      if (!ac.signal.aborted) setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    load(false);
    const poll = setInterval(() => load(false), POLL_MS);
    return () => {
      clearInterval(poll);
      abortRef.current?.abort();
    };
  }, [load]);

  useEffect(() => {
    const t = setInterval(() => setSecondsAgo((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, []);

  const onUpgrade = useCallback(() => {
    if (typeof window !== "undefined") {
      window.open("https://securesleuths.in/pricing", "_blank", "noreferrer");
    }
  }, []);

  const closeConfirm = useCallback(() => {
    if (submitting) return; // don't let the dialog close mid-dispatch
    setConfirm(null);
    setActionError(null);
  }, [submitting]);

  /**
   * Run the confirmed transition. Invoked ONLY from the confirm dialog's
   * deliberate click — never automatically. Fail-closed on 402/403 (locked),
   * self-heal on 409/404 (the item changed), surface every other error typed.
   */
  const submitAction = useCallback(async () => {
    if (!confirm) return;
    const { kind, row } = confirm;
    setSubmitting(true);
    setActionError(null);
    try {
      if (kind === "approve") {
        const res = await approveResponseAction(row.id);
        if (res.status === "not_applied") {
          setActionError(
            `Wazuh accepted the ${actionLabel(row.action)} command but dispatched it to no agent (the target has no dispatchable active-response agent) — nothing was applied. The attempt is recorded in the audit trail as not-applied.`,
          );
          await load(true);
          return;
        }
        if (res.success === false || res.status === "failed") {
          setActionError(
            `The proposal was approved but the dispatch to Wazuh failed${
              res.error ? `: ${res.error}` : "."
            } Nothing is in force. The attempt is recorded in the audit trail.`,
          );
          await load(true);
          return;
        }
        setFlash(
          res.audit === "degraded"
            ? {
                tone: "warn",
                msg: `Approved and dispatched ${actionLabel(row.action)} on agent ${
                  row.agent_id ?? DASH
                } — but the audit-row write was degraded. Verify the trail is complete.`,
              }
            : {
                tone: "ok",
                msg: `Approved and dispatched ${actionLabel(row.action)} on agent ${
                  row.agent_id ?? DASH
                }. It is logged and reversible.`,
              },
        );
      } else {
        const res = await reverseResponseAction(row.id);
        if (res.success === false || res.status === "failed") {
          setActionError(
            `The reverse (unblock) failed${
              res.error ? `: ${res.error}` : "."
            } The block may still be in force — check the audit trail.`,
          );
          await load(true);
          return;
        }
        setFlash({
          tone: "ok",
          msg: `Reversed — ${row.target_ip ?? "the block"} is unblocked on agent ${
            row.agent_id ?? DASH
          }.`,
        });
      }
      setConfirm(null);
      await load(true);
    } catch (e) {
      if (isLockError(e)) {
        setActionError(
          "Your role or license tier does not permit this action — the server denied it (this control mirrors the server and stays locked). Nothing changed.",
        );
      } else if (
        e instanceof ApiError &&
        (e.status === 409 || e.status === 404)
      ) {
        setActionError(
          "This item changed since you loaded it — it may no longer be pending, or the block was already cleared. Refreshing the queue.",
        );
        setConfirm(null);
        await load(true);
      } else {
        setActionError(errMessage(e));
      }
    } finally {
      setSubmitting(false);
    }
  }, [confirm, load]);

  const { queue, audit, error, locked, loading } = state;
  const pending = (queue ?? []).filter((r) => r.status === "pending_approval");
  const active = (queue ?? []).filter((r) => r.status === "executed");

  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PageHeading
          title="Respond"
          sub="The active-response queue and the durable audit trail — what is awaiting a human decision, what is live, and everything that has run."
        />
        {!locked && (
          <PollingStatus
            className="mt-1"
            secondsAgo={secondsAgo}
            refreshing={refreshing}
            onRefresh={() => load(true)}
          />
        )}
      </div>

      {locked ? (
        <FeatureLockedState
          feature="Active response"
          tier="current"
          onUpgrade={onUpgrade}
        />
      ) : loading && !audit ? (
        <StatusState variant="loading" title="Loading active-response queue…" />
      ) : error && !audit ? (
        <StatusState
          variant="error"
          title="Couldn't load the active-response queue"
          description={error}
          action={<Chip onClick={() => load(true)}>Retry</Chip>}
        />
      ) : audit ? (
        <div className="flex flex-col gap-3">
          <PostureNote gate={gate} />

          {flash && (
            <FlashBanner flash={flash} onDismiss={() => setFlash(null)} />
          )}

          <QueuePanel
            title="Awaiting approval"
            hint="Proposed containment actions queued for a human decision. Approving one is a deliberate senior_analyst+ action — the server approves AND dispatches it to Wazuh in the same step, then logs it. It stays reversible (for a block)."
            rows={pending}
            emptyText="No actions are awaiting approval."
            controlHeader="Decision"
            renderControl={(r) => (
              <ApproveControl
                gate={gate}
                onApprove={() => {
                  setActionError(null);
                  setConfirm({ kind: "approve", row: r });
                }}
              />
            )}
          />

          <QueuePanel
            title="Active containment"
            hint="Executed actions still in force (a block is active until it expires or is reversed). Reversing is a deliberate senior_analyst+ action; only an active IP block can be reversed here."
            rows={active}
            emptyText="No active containment in force."
            controlHeader="Reverse"
            renderControl={(r) => (
              <ReverseControl
                row={r}
                gate={gate}
                onReverse={() => {
                  setActionError(null);
                  setConfirm({ kind: "reverse", row: r });
                }}
              />
            )}
          />

          <AuditPanel rows={audit} />
        </div>
      ) : null}

      <ConfirmActionDialog
        pending={confirm}
        submitting={submitting}
        error={actionError}
        onConfirm={submitAction}
        onClose={closeConfirm}
      />
    </>
  );
}

function PostureNote({ gate }: { gate: ResponseActionGate }) {
  return (
    <div className="rounded-lg border border-gated-border bg-panel2 px-3.5 py-2.5 text-kbd text-gated-ink">
      Approving a proposal dispatches it <b>immediately</b> (and logs it);
      reversing clears an active block. Both are senior_analyst+ and always
      behind an explicit confirm.
      {gate.lockNote && (
        <span className="mt-1 block text-dim2">{gate.lockNote}</span>
      )}
    </div>
  );
}

function FlashBanner({
  flash,
  onDismiss,
}: {
  flash: Flash;
  onDismiss: () => void;
}) {
  const tone =
    flash.tone === "ok"
      ? "border-grounded-border text-grounded-ink"
      : "border-gated-border text-gated-ink";
  return (
    <div
      role="status"
      aria-live="polite"
      className={cn(
        "flex items-start gap-3 rounded-lg border bg-panel2 px-3.5 py-2.5 text-data",
        tone,
      )}
    >
      <span className="flex-1">{flash.msg}</span>
      <button
        type="button"
        onClick={onDismiss}
        className={cn("shrink-0 text-kbd text-dim hover:text-ink", focusRing)}
      >
        Dismiss
      </button>
    </div>
  );
}

function ApproveControl({
  gate,
  onApprove,
}: {
  gate: ResponseActionGate;
  onApprove: () => void;
}) {
  if (!gate.canApprove) {
    return (
      <Chip
        variant="gated"
        aria-label="Approval requires a senior analyst or higher"
      >
        Locked · senior_analyst+
      </Chip>
    );
  }
  return (
    <button
      type="button"
      onClick={onApprove}
      className={cn(
        "cursor-pointer rounded-md border border-grounded-border bg-grounded-border/40 px-2.5 py-1 text-meta text-grounded-ink hover:brightness-125",
        focusRing,
      )}
    >
      Approve &amp; execute…
    </button>
  );
}

function ReverseControl({
  row,
  gate,
  onReverse,
}: {
  row: ArAction;
  gate: ResponseActionGate;
  onReverse: () => void;
}) {
  // The server only reverses an active block_ip; anything else has no reverse
  // path (it would 409). Mirror that: offer Reverse only for a block_ip.
  if (row.action !== "block_ip") {
    return (
      <span className="text-kbd text-dim2">No reverse for this action</span>
    );
  }
  if (!gate.canReverse) {
    return (
      <Chip
        variant="gated"
        aria-label="Reverse requires a senior analyst or higher"
      >
        Locked · senior_analyst+
      </Chip>
    );
  }
  return (
    <button
      type="button"
      onClick={onReverse}
      className={cn(
        "cursor-pointer rounded-md border border-gated-border bg-field px-2.5 py-1 text-meta text-gated-ink hover:brightness-125",
        focusRing,
      )}
    >
      Reverse (unblock)…
    </button>
  );
}

/**
 * The confirm-to-execute dialog. Shows EXACTLY what will run (action, target,
 * agent, mode, TTL/expiry, reason) so the human sees the consequence before
 * dispatching. The primary button is the only path that fires the write.
 */
function ConfirmActionDialog({
  pending,
  submitting,
  error,
  onConfirm,
  onClose,
}: {
  pending: Pending | null;
  submitting: boolean;
  error: string | null;
  onConfirm: () => void;
  onClose: () => void;
}) {
  if (!pending) return null;
  const { kind, row } = pending;
  const approve = kind === "approve";
  const mode = modePresentation(row.mode);

  return (
    <Dialog
      open
      onClose={onClose}
      maxWidth={540}
      title={approve ? "Approve & execute containment" : "Reverse containment"}
    >
      <p className="text-data text-dim">
        {approve ? (
          <>
            This <b>approves and immediately dispatches</b> the action below to
            Wazuh on the target agent. It is a deliberate, logged, reversible
            action. Nothing runs until you confirm.
          </>
        ) : (
          <>
            This <b>reverses (unblocks)</b> the active block below on the target
            agent, immediately. It is logged. Nothing changes until you confirm.
          </>
        )}
      </p>

      <dl className="mt-3 grid grid-cols-[7rem_1fr] gap-x-3 gap-y-1.5 rounded-lg border border-line bg-panel2 px-3.5 py-3 text-data">
        <dt className="text-dim2">Action</dt>
        <dd className="text-ink">
          {actionLabel(approve ? row.action : "unblock_ip")}
          {!approve && (
            <span className="text-kbd text-dim2">
              {" "}
              (reverse of {actionLabel(row.action)})
            </span>
          )}
        </dd>

        <dt className="text-dim2">Target IP</dt>
        <dd className="font-mono text-ink">{row.target_ip ?? DASH}</dd>

        <dt className="text-dim2">Agent</dt>
        <dd className="font-mono text-ink">{row.agent_id ?? DASH}</dd>

        <dt className="text-dim2">Mode</dt>
        <dd className={cn("font-semibold", mode.className)}>{mode.label}</dd>

        {approve && (
          <>
            <dt className="text-dim2">TTL</dt>
            <dd className="text-ink">
              {row.ttl_seconds ? `${row.ttl_seconds}s` : DASH}
              {row.expires_at && (
                <span className="text-kbd text-dim2">
                  {" "}
                  · expires {fmtDateTime(row.expires_at)}
                </span>
              )}
            </dd>
          </>
        )}

        <dt className="text-dim2">Reason</dt>
        <dd className="text-ink">{row.reason || DASH}</dd>

        <dt className="text-dim2">Proposed by</dt>
        <dd className="font-mono text-dim">{row.actor || DASH}</dd>
      </dl>

      {error && (
        <p className="mt-3 text-data text-sev-crit" role="alert">
          {error}
        </p>
      )}

      <div className="mt-4 flex items-center gap-2">
        <button
          type="button"
          onClick={onConfirm}
          disabled={submitting}
          className={cn(
            "rounded-md border px-3 py-1.5 text-data",
            focusRing,
            submitting
              ? "cursor-not-allowed border-line bg-field text-dim opacity-60"
              : approve
                ? "cursor-pointer border-grounded-border bg-grounded-border/40 text-grounded-ink hover:brightness-125"
                : "cursor-pointer border-gated-border bg-field text-gated-ink hover:brightness-125",
          )}
        >
          {submitting
            ? approve
              ? "Dispatching…"
              : "Reversing…"
            : approve
              ? "Approve & execute now"
              : "Reverse now"}
        </button>
        <button
          type="button"
          onClick={onClose}
          disabled={submitting}
          className={cn(
            "rounded-md border border-line bg-field px-3 py-1.5 text-data text-ink hover:bg-hover",
            focusRing,
            submitting && "cursor-not-allowed opacity-60",
          )}
        >
          Cancel
        </button>
      </div>
    </Dialog>
  );
}

function QueuePanel({
  title,
  hint,
  rows,
  emptyText,
  controlHeader,
  renderControl,
}: {
  title: string;
  hint: string;
  rows: ArAction[];
  emptyText: string;
  controlHeader?: string;
  renderControl?: (r: ArAction) => React.ReactNode;
}) {
  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-3">
        <div className="text-title text-ink">{title}</div>
        <span className="text-kbd text-dim2">{rows.length}</span>
      </div>
      <div className="px-4 text-kbd text-dim2">{hint}</div>
      {rows.length === 0 ? (
        <div className="px-4 pb-4 pt-2 text-data text-dim2">{emptyText}</div>
      ) : (
        <Table className="mt-2">
          <THead>
            <TR>
              <TH>Action</TH>
              <TH>Target</TH>
              <TH>Requested by</TH>
              <TH>Reason</TH>
              <TH>When</TH>
              {renderControl && <TH>{controlHeader ?? "Action"}</TH>}
            </TR>
          </THead>
          <TBody>
            {rows.map((r) => (
              <ActionRow
                key={r.id}
                r={r}
                showExpiry
                control={renderControl?.(r)}
              />
            ))}
          </TBody>
        </Table>
      )}
    </Panel>
  );
}

function AuditPanel({ rows }: { rows: ArAction[] }) {
  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-3">
        <div className="text-title text-ink">Audit trail</div>
        <span className="text-kbd text-dim2">{rows.length} shown</span>
      </div>
      <div className="px-4 text-kbd text-dim2">
        Every active-response action — auto and manual — is durably logged and
        auditable. This is the standing record; it is never edited from here.
      </div>
      {rows.length === 0 ? (
        <div className="px-4 pb-4 pt-2 text-data text-dim2">
          No active-response actions recorded for this tenant.
        </div>
      ) : (
        <Table className="mt-2">
          <THead>
            <TR>
              <TH>Action</TH>
              <TH>Mode</TH>
              <TH>Status</TH>
              <TH>Target</TH>
              <TH>Actor</TH>
              <TH>When</TH>
            </TR>
          </THead>
          <TBody>
            {rows.map((r) => {
              const st = arStatusPresentation(r.status);
              const mode = modePresentation(r.mode);
              return (
                <TR key={r.id}>
                  <TD>
                    <div className="text-ink">{actionLabel(r.action)}</div>
                    {r.reason && (
                      <div className="max-w-[420px] text-kbd text-dim2">
                        {r.reason}
                      </div>
                    )}
                  </TD>
                  <TD>
                    <span
                      className={`text-meta font-semibold ${mode.className}`}
                    >
                      {mode.label}
                    </span>
                  </TD>
                  <TD>
                    <span className={`text-meta font-semibold ${st.className}`}>
                      {st.label}
                    </span>
                    {r.reversed_at && (
                      <div className="text-kbd text-dim2">
                        by {r.reversed_by ?? DASH} · {fmtDateTime(r.reversed_at)}
                      </div>
                    )}
                  </TD>
                  <TD>
                    <TargetCell r={r} />
                  </TD>
                  <TD>
                    <span className="font-mono text-kbd text-dim">
                      {r.actor || DASH}
                    </span>
                  </TD>
                  <TD>{fmtDateTime(r.created_at)}</TD>
                </TR>
              );
            })}
          </TBody>
        </Table>
      )}
    </Panel>
  );
}

function ActionRow({
  r,
  showExpiry,
  control,
}: {
  r: ArAction;
  showExpiry?: boolean;
  control?: React.ReactNode;
}) {
  const mode = modePresentation(r.mode);
  return (
    <TR>
      <TD>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-ink">{actionLabel(r.action)}</span>
          <span className={`text-meta font-semibold ${mode.className}`}>
            {mode.label}
          </span>
        </div>
        {showExpiry && r.expires_at && (
          <div className="text-kbd text-dim2">
            expires {fmtDateTime(r.expires_at)}
          </div>
        )}
      </TD>
      <TD>
        <TargetCell r={r} />
      </TD>
      <TD>
        <span className="font-mono text-kbd text-dim">{r.actor || DASH}</span>
      </TD>
      <TD>
        <span className="max-w-[360px] text-kbd text-dim2">
          {r.reason || DASH}
        </span>
      </TD>
      <TD>{fmtDateTime(r.created_at)}</TD>
      {control !== undefined && <TD>{control}</TD>}
    </TR>
  );
}

function TargetCell({ r }: { r: ArAction }) {
  return (
    <div className="flex flex-col gap-0.5">
      {r.target_ip ? (
        <span className="font-mono text-kbd text-ink">{r.target_ip}</span>
      ) : (
        <span className="text-dim2">{DASH}</span>
      )}
      {r.agent_id && (
        <span className="font-mono text-kbd text-dim2">agent {r.agent_id}</span>
      )}
    </div>
  );
}
