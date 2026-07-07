"use client";

/**
 * SoarTab — SOAR playbooks + executions, with the endpoint-backed WRITES wired.
 *
 * ============================ ACTIVE-RESPONSE POSTURE ======================
 * SOAR playbooks CONTAIN containment actions (block_ip / isolate_host /
 * disable_user; src/soar/playbooks.py). Every write here is therefore
 * active-response-adjacent and obeys the standing rule — HUMAN-APPROVED BY
 * DEFAULT, NEVER auto, no server default changed by this UI. Each control is
 * confirm-gated, RBAC-mirrored, and its copy never implies auto-execution:
 *
 *   - TOGGLE a playbook (`POST /api/soar/playbooks/{id}/toggle`, admin+). Does
 *     NOT run anything now — it flips eligibility. ENABLING a playbook that
 *     contains containment is called out explicitly in the confirm dialog: when
 *     it later triggers, a containment step still routes to the human approval
 *     queue (it never auto-runs from being enabled; isolate/disable/kill stay
 *     ALWAYS-HUMAN, and only block_ip may auto-run via the SEPARATE per-tenant
 *     auto-block policy, which is OFF by default and untouched here).
 *   - APPROVE an execution (`POST /api/soar/executions/{id}/approve`,
 *     senior_analyst+) — the `pending_approval` queue IS the human gate; the
 *     server dispatches the execution's containment actions ON approval. The
 *     confirm dialog lists the exact actions that will run before you confirm.
 *   - REJECT an execution (senior_analyst+) — cancels a pending execution; NO
 *     containment runs.
 *   - ROLLBACK an execution (`POST /api/soar/executions/{id}/rollback`, admin+)
 *     — reverses a completed/partial execution's containment (inverse actions).
 *
 * There is NO manual "run playbook now" endpoint (executions are engine-generated
 * from real triage decisions), so nothing here starts containment from scratch.
 * Controls below a role's server gate are HIDDEN (mirroring the server) so the UI
 * never offers a write the server rejects.
 * ===========================================================================
 *
 * TIER GATE: a runtime 402/403 from the `soar` gate degrades the whole surface
 * to FeatureLockedState. States: loading / empty / error+retry / locked;
 * per-action submitting + typed error (402/403 → locked, 400 → "changed,
 * refreshing"); PollingStatus (30s, aborts on unmount). Fixtures gate behind
 * NEXT_PUBLIC_DHRUVA_FIXTURES (writes short-circuit to synthetic success, NO real
 * mutation).
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
  Tile,
} from "@/components";
import { PageHeading } from "../PageHeading";
import {
  ApiError,
  approveSoarExecution,
  getSoarExecutions,
  getSoarPlaybooks,
  getSoarStats,
  rejectSoarExecution,
  rollbackSoarExecution,
  toggleSoarPlaybook,
} from "@/lib/api";
import {
  soarExecutionGate,
  soarPlaybookGate,
  type SoarExecutionGate,
  type SoarPlaybookGate,
} from "@/lib/rbac";
import { useAuth } from "@/lib/auth";
import { actionCount, soarStatusPresentation, triggerSummary } from "@/lib/soar";
import { parseJsonArray } from "@/lib/incident";
import { cn, focusRing } from "@/lib/ui";
import { asBool, DASH, fmtDateTime, fmtInt, fmtPct } from "@/lib/format";
import type { TabProps } from "../tabRegistry";
import type { SoarExecution, SoarPlaybook, SoarStats } from "@/lib/types";

const POLL_MS = 30_000;

/**
 * Action codes that put a host/network/account under containment. Enabling a
 * playbook that plans any of these, or approving an execution that plans any of
 * these, is treated as active-response-adjacent (warned + confirmed). Everything
 * else (notify hooks, and the unblock/unisolate/enable rollback verbs) is
 * non-containment.
 */
const CONTAINMENT = new Set([
  "block_ip",
  "isolate_host",
  "disable_user",
  "quarantine_file",
  "kill_process",
  "restart_agent",
]);

function actionList(actions: string | unknown[] | null | undefined): string[] {
  if (Array.isArray(actions)) return actions.map(String);
  return parseJsonArray(actions as string | null | undefined);
}
function containmentIn(list: string[]): string[] {
  return list.filter((a) => CONTAINMENT.has(a));
}
function prettyAction(a: string): string {
  return a.replace(/_/g, " ");
}

function isLockError(e: unknown): boolean {
  return e instanceof ApiError && (e.status === 402 || e.status === 403);
}
function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : "Unknown error";
}

/**
 * Execution KANBAN grouping (restored parity sub-view — legacy app.js:4085-4127).
 * Groups the executions the tab already fetched into the same four swim-lanes the
 * legacy board used. READ-ONLY: this only re-buckets `state.executions`; it makes
 * NO new request and carries NO write affordance (approve/reject/rollback stay in
 * the List table, unchanged). Any status the map doesn't know falls into an
 * honest "Other" lane rather than being silently dropped.
 */
const SOAR_COLUMNS: { key: string; label: string; statuses: string[] }[] = [
  { key: "pending", label: "Pending", statuses: ["pending_approval", "approved"] },
  { key: "running", label: "Running", statuses: ["executing", "running"] },
  { key: "completed", label: "Completed", statuses: ["completed", "partial"] },
  {
    key: "failed",
    label: "Failed / reversed",
    statuses: ["failed", "rolled_back", "cancelled"],
  },
];

function groupExecutions(execs: SoarExecution[]): {
  cols: { key: string; label: string; items: SoarExecution[] }[];
  other: SoarExecution[];
} {
  const cols = SOAR_COLUMNS.map((c) => ({
    key: c.key,
    label: c.label,
    items: [] as SoarExecution[],
  }));
  const other: SoarExecution[] = [];
  for (const ex of execs) {
    const idx = SOAR_COLUMNS.findIndex((c) =>
      c.statuses.includes(String(ex.status)),
    );
    if (idx >= 0) cols[idx].items.push(ex);
    else other.push(ex);
  }
  return { cols, other };
}

interface State {
  playbooks: SoarPlaybook[] | null;
  executions: SoarExecution[] | null;
  stats: SoarStats | null;
  error: string | null;
  locked: boolean;
  loading: boolean;
}

type Flash = { tone: "ok" | "warn"; msg: string };
type Pending =
  | { kind: "toggle"; pb: SoarPlaybook }
  | { kind: "approve" | "reject" | "rollback"; ex: SoarExecution };

export function SoarTab(_props: TabProps) {
  const { role } = useAuth();
  const pbGate = soarPlaybookGate(role);
  const exGate = soarExecutionGate(role);

  const [state, setState] = useState<State>({
    playbooks: null,
    executions: null,
    stats: null,
    error: null,
    locked: false,
    loading: true,
  });
  const [secondsAgo, setSecondsAgo] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  // ---- write state --------------------------------------------------------
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
      const [playbooks, executions, stats] = await Promise.all([
        getSoarPlaybooks(ac.signal),
        getSoarExecutions({ limit: 50 }, ac.signal),
        getSoarStats(ac.signal),
      ]);
      if (ac.signal.aborted) return;
      setState({
        playbooks: playbooks.playbooks,
        executions: executions.executions,
        stats,
        error: null,
        locked: false,
        loading: false,
      });
      setSecondsAgo(0);
    } catch (e) {
      if (ac.signal.aborted) return;
      if (isLockError(e)) {
        setState({
          playbooks: null,
          executions: null,
          stats: null,
          error: null,
          locked: true,
          loading: false,
        });
        return;
      }
      const msg = errMessage(e);
      setState((prev) =>
        prev.playbooks
          ? { ...prev, loading: false }
          : {
              playbooks: null,
              executions: null,
              stats: null,
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
    if (submitting) return;
    setConfirm(null);
    setActionError(null);
  }, [submitting]);

  /** Run the confirmed write. ONLY invoked from the confirm dialog's click. */
  const submitAction = useCallback(async () => {
    if (!confirm) return;
    setSubmitting(true);
    setActionError(null);
    try {
      if (confirm.kind === "toggle") {
        const pb = confirm.pb;
        const wasEnabled = asBool(pb.enabled);
        await toggleSoarPlaybook(pb.id, wasEnabled);
        setFlash({
          tone: wasEnabled ? "ok" : "warn",
          msg: wasEnabled
            ? `Disabled "${pb.display_name || pb.name}" — it will no longer trigger.`
            : `Enabled "${pb.display_name || pb.name}". It can now trigger; any containment step still routes to the human approval queue.`,
        });
      } else if (confirm.kind === "approve") {
        const ex = confirm.ex;
        await approveSoarExecution(ex.id);
        setFlash({
          tone: "ok",
          msg: `Approved "${ex.playbook_name || ex.playbook_id}" — its actions are dispatching. It is logged and (for a block) reversible.`,
        });
      } else if (confirm.kind === "reject") {
        const ex = confirm.ex;
        await rejectSoarExecution(ex.id);
        setFlash({
          tone: "ok",
          msg: `Rejected "${ex.playbook_name || ex.playbook_id}" — the queued execution was cancelled. Nothing ran.`,
        });
      } else {
        const ex = confirm.ex;
        await rollbackSoarExecution(ex.id);
        setFlash({
          tone: "ok",
          msg: `Rolling back "${ex.playbook_name || ex.playbook_id}" — its containment is being reversed.`,
        });
      }
      setConfirm(null);
      await load(true);
    } catch (e) {
      if (isLockError(e)) {
        setActionError(
          "Your role or license tier does not permit this action — the server denied it (this control mirrors the server). Nothing changed.",
        );
      } else if (e instanceof ApiError && e.status === 400) {
        setActionError(
          "This changed since you loaded it — the execution may no longer be pending, or is not in a rollbackable state. Refreshing.",
        );
        setConfirm(null);
        await load(true);
      } else if (e instanceof ApiError && (e.status === 404 || e.status === 503)) {
        setActionError(
          e.status === 503
            ? "The SOAR engine is not available right now. Nothing changed."
            : "This item is gone. Refreshing the list.",
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

  const { playbooks, executions, stats, error, locked, loading } = state;

  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PageHeading
          title="SOAR"
          sub="Automation playbooks and their executions — read the trigger conditions like a rule, and act on what fired. Every action is human-approved and confirmed."
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
        <FeatureLockedState feature="SOAR" tier="current" onUpgrade={onUpgrade} />
      ) : loading && !playbooks ? (
        <StatusState variant="loading" title="Loading SOAR playbooks…" />
      ) : error && !playbooks ? (
        <StatusState
          variant="error"
          title="Couldn't load SOAR"
          description={error}
          action={<Chip onClick={() => load(true)}>Retry</Chip>}
        />
      ) : playbooks ? (
        <div className="flex flex-col gap-3">
          <PostureNote pbGate={pbGate} exGate={exGate} />
          {flash && <FlashBanner flash={flash} onDismiss={() => setFlash(null)} />}
          {stats && <StatsTiles stats={stats} />}
          <PlaybooksPanel
            playbooks={playbooks}
            gate={pbGate}
            onToggle={(pb) => {
              setActionError(null);
              setConfirm({ kind: "toggle", pb });
            }}
          />
          <ExecutionsPanel
            executions={executions ?? []}
            gate={exGate}
            onApprove={(ex) => {
              setActionError(null);
              setConfirm({ kind: "approve", ex });
            }}
            onReject={(ex) => {
              setActionError(null);
              setConfirm({ kind: "reject", ex });
            }}
            onRollback={(ex) => {
              setActionError(null);
              setConfirm({ kind: "rollback", ex });
            }}
          />
        </div>
      ) : null}

      <SoarConfirmDialog
        pending={confirm}
        submitting={submitting}
        error={actionError}
        onConfirm={submitAction}
        onClose={closeConfirm}
      />
    </>
  );
}

function PostureNote({
  pbGate,
  exGate,
}: {
  pbGate: SoarPlaybookGate;
  exGate: SoarExecutionGate;
}) {
  return (
    <div className="rounded-lg border border-gated-border bg-panel2 px-3.5 py-2.5 text-kbd text-gated-ink">
      SOAR playbooks contain containment actions, so every action here is{" "}
      <b>human-approved and never auto</b>. Enabling a playbook only makes it
      eligible — a containment step still routes to the human approval queue and
      never auto-runs from being enabled. Approving a queued execution{" "}
      <b>dispatches its actions</b>; it is behind an explicit confirm that lists
      them. This UI changes no server default and auto-executes nothing.
      {(pbGate.lockNote || exGate.approveLockNote) && (
        <span className="mt-1 block text-dim2">
          {exGate.approveLockNote ?? pbGate.lockNote}
        </span>
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

function StatsTiles({ stats }: { stats: SoarStats }) {
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
      <Tile label="Playbooks" value={fmtInt(stats.total_playbooks)} sub="configured" />
      <Tile label="Active" value={fmtInt(stats.active_playbooks)} sub="enabled" />
      <Tile
        label="Awaiting approval"
        value={fmtInt(stats.pending_approvals)}
        sub="executions queued"
        valueSeverity={stats.pending_approvals > 0 ? "med" : undefined}
      />
      <Tile label="Runs today" value={fmtInt(stats.executions_today)} sub="executions" />
      <Tile
        label="Success rate"
        value={fmtPct(stats.success_rate)}
        sub="last 30 days"
        math={
          <>
            completed / (completed + partial + failed) over the last 30 days
            (`get_soar_stats`). A real computed value, not an estimate.
          </>
        }
      />
    </div>
  );
}

function PlaybooksPanel({
  playbooks,
  gate,
  onToggle,
}: {
  playbooks: SoarPlaybook[];
  gate: SoarPlaybookGate;
  onToggle: (pb: SoarPlaybook) => void;
}) {
  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-3">
        <div className="text-title text-ink">Playbooks</div>
        <span className="text-kbd text-dim2">{playbooks.length} total</span>
      </div>
      {playbooks.length === 0 ? (
        <div className="px-4 pb-4 pt-2 text-data text-dim2">
          No SOAR playbooks configured for this tenant.
        </div>
      ) : (
        <Table className="mt-2">
          <THead>
            <TR>
              <TH>Playbook</TH>
              <TH>Fires when</TH>
              <TH className="text-right">Actions</TH>
              <TH>Approval</TH>
              <TH>State</TH>
              {gate.canToggle && <TH>Enable</TH>}
            </TR>
          </THead>
          <TBody>
            {playbooks.map((pb) => {
              const enabled = asBool(pb.enabled);
              const needsApproval = asBool(pb.require_approval);
              const contains = containmentIn(actionList(pb.actions));
              return (
                <TR key={pb.id}>
                  <TD>
                    <div className="text-ink">{pb.display_name || pb.name}</div>
                    {pb.description && (
                      <div className="max-w-[520px] text-kbd text-dim2">
                        {pb.description}
                      </div>
                    )}
                    {contains.length > 0 && (
                      <div className="mt-0.5 text-kbd text-gated-ink">
                        contains containment: {contains.map(prettyAction).join(", ")}
                      </div>
                    )}
                  </TD>
                  <TD>
                    <span className="text-data text-dim">{triggerSummary(pb)}</span>
                  </TD>
                  <TD mono className="text-right">
                    {fmtInt(actionCount(pb.actions))}
                  </TD>
                  <TD>
                    {needsApproval ? (
                      <Chip variant="gated">human-approved</Chip>
                    ) : (
                      <Chip>auto (blessed)</Chip>
                    )}
                  </TD>
                  <TD>
                    <span className={enabled ? "text-teal" : "text-dim2"}>
                      {enabled ? "enabled" : "disabled"}
                    </span>
                  </TD>
                  {gate.canToggle && (
                    <TD>
                      <button
                        type="button"
                        onClick={() => onToggle(pb)}
                        className={cn(
                          "cursor-pointer rounded-md border px-2.5 py-1 text-meta hover:brightness-125",
                          focusRing,
                          enabled
                            ? "border-line bg-field text-ink"
                            : "border-gated-border bg-field text-gated-ink",
                        )}
                      >
                        {enabled ? "Disable…" : "Enable…"}
                      </button>
                    </TD>
                  )}
                </TR>
              );
            })}
          </TBody>
        </Table>
      )}
    </Panel>
  );
}

function ExecutionsPanel({
  executions,
  gate,
  onApprove,
  onReject,
  onRollback,
}: {
  executions: SoarExecution[];
  gate: SoarExecutionGate;
  onApprove: (ex: SoarExecution) => void;
  onReject: (ex: SoarExecution) => void;
  onRollback: (ex: SoarExecution) => void;
}) {
  const showControls = gate.canApprove || gate.canRollback;
  const [view, setView] = useState<"list" | "board">("list");
  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-3">
        <div className="text-title text-ink">Recent executions</div>
        <div className="flex items-center gap-2">
          <div
            className="flex items-center gap-1.5"
            role="group"
            aria-label="Executions view"
          >
            <Chip
              variant={view === "list" ? "cite" : "default"}
              onClick={() => setView("list")}
              aria-label="List view (with actions)"
            >
              List
            </Chip>
            <Chip
              variant={view === "board" ? "cite" : "default"}
              onClick={() => setView("board")}
              aria-label="Board view grouped by status"
            >
              Board
            </Chip>
          </div>
          <span className="text-kbd text-dim2">{executions.length} shown</span>
        </div>
      </div>
      {executions.length === 0 ? (
        <div className="px-4 pb-4 pt-2 text-data text-dim2">
          No SOAR executions recorded yet. Executions appear here once a playbook
          trigger matches a triage decision.
        </div>
      ) : view === "board" ? (
        <ExecutionsBoard executions={executions} showControls={showControls} />
      ) : (
        <Table className="mt-2">
          <THead>
            <TR>
              <TH>Playbook</TH>
              <TH>Status</TH>
              <TH className="text-right">Progress</TH>
              <TH>Approved by</TH>
              <TH>Started</TH>
              {showControls && <TH>Decision</TH>}
            </TR>
          </THead>
          <TBody>
            {executions.map((ex) => {
              const st = soarStatusPresentation(ex.status);
              const total = ex.total_steps ?? 0;
              const done = ex.current_step ?? 0;
              const isPending = ex.status === "pending_approval";
              const isRollbackable =
                ex.status === "completed" || ex.status === "partial";
              return (
                <TR key={ex.id}>
                  <TD>
                    <div className="text-ink">
                      {ex.playbook_name || ex.playbook_id}
                    </div>
                    {ex.incident_id && (
                      <div className="font-mono text-kbd text-dim2">
                        incident {ex.incident_id}
                      </div>
                    )}
                  </TD>
                  <TD>
                    <div className={`text-meta font-semibold ${st.className}`}>
                      {st.label}
                    </div>
                    {ex.status === "partial" && ex.error_message && (
                      <div className="max-w-[360px] text-kbd text-sev-med">
                        {ex.error_message}
                      </div>
                    )}
                    {ex.status === "failed" && ex.error_message && (
                      <div className="max-w-[360px] text-kbd text-sev-crit">
                        {ex.error_message}
                      </div>
                    )}
                  </TD>
                  <TD mono className="text-right">
                    {total > 0 ? `${done}/${total}` : DASH}
                  </TD>
                  <TD>
                    {ex.approved_by ? (
                      <span className="text-dim">{ex.approved_by}</span>
                    ) : (
                      <span className="text-dim2">{DASH}</span>
                    )}
                  </TD>
                  <TD>{fmtDateTime(ex.started_at ?? ex.created_at)}</TD>
                  {showControls && (
                    <TD>
                      <div className="flex flex-wrap items-center gap-1.5">
                        {isPending && gate.canApprove && (
                          <>
                            <button
                              type="button"
                              onClick={() => onApprove(ex)}
                              className={cn(
                                "cursor-pointer rounded-md border border-grounded-border bg-grounded-border/40 px-2.5 py-1 text-meta text-grounded-ink hover:brightness-125",
                                focusRing,
                              )}
                            >
                              Approve…
                            </button>
                            <button
                              type="button"
                              onClick={() => onReject(ex)}
                              className={cn(
                                "cursor-pointer rounded-md border border-line bg-field px-2.5 py-1 text-meta text-ink hover:brightness-125",
                                focusRing,
                              )}
                            >
                              Reject…
                            </button>
                          </>
                        )}
                        {isRollbackable && gate.canRollback && (
                          <button
                            type="button"
                            onClick={() => onRollback(ex)}
                            className={cn(
                              "cursor-pointer rounded-md border border-gated-border bg-field px-2.5 py-1 text-meta text-gated-ink hover:brightness-125",
                              focusRing,
                            )}
                          >
                            Rollback…
                          </button>
                        )}
                        {isPending && !gate.canApprove && (
                          <Chip variant="gated">Locked · senior_analyst+</Chip>
                        )}
                        {!isPending && !isRollbackable && (
                          <span className="text-kbd text-dim2">{DASH}</span>
                        )}
                      </div>
                    </TD>
                  )}
                </TR>
              );
            })}
          </TBody>
        </Table>
      )}
    </Panel>
  );
}

/**
 * READ-ONLY execution kanban (restored parity sub-view). Renders the executions
 * the tab already fetched, grouped into the legacy four swim-lanes. It carries NO
 * write control — approve/reject/rollback remain in the List view (and its
 * gating) untouched; this board is a status overview, so it never re-implements
 * or widens a write. A "changed since load / actions live in List" note points
 * the analyst to where the (gated) actions are.
 */
function ExecutionsBoard({
  executions,
  showControls,
}: {
  executions: SoarExecution[];
  showControls: boolean;
}) {
  const { cols, other } = groupExecutions(executions);
  const lanes = other.length
    ? [...cols, { key: "other", label: "Other", items: other }]
    : cols;
  return (
    <div className="px-4 pb-4 pt-3">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {lanes.map((col) => (
          <div
            key={col.key}
            className="flex flex-col rounded-lg border border-line bg-panel2"
          >
            <div className="flex items-center justify-between border-b border-line px-3 py-2">
              <span className="text-meta font-semibold text-ink">
                {col.label}
              </span>
              <span className="text-kbd tabular text-dim2">
                {col.items.length}
              </span>
            </div>
            <div className="flex flex-col gap-2 p-2">
              {col.items.length === 0 ? (
                <div className="px-1 py-2 text-kbd text-dim2">None</div>
              ) : (
                col.items.map((ex) => {
                  const st = soarStatusPresentation(ex.status);
                  const total = ex.total_steps ?? 0;
                  const done = ex.current_step ?? 0;
                  return (
                    <div
                      key={ex.id}
                      className="rounded-md border border-line bg-panel px-2.5 py-2"
                    >
                      <div className="text-data text-ink">
                        {ex.playbook_name || ex.playbook_id}
                      </div>
                      {ex.incident_id && (
                        <div className="font-mono text-kbd text-dim2">
                          incident {ex.incident_id}
                        </div>
                      )}
                      <div
                        className={`mt-1 text-kbd font-semibold ${st.className}`}
                      >
                        {st.label}
                      </div>
                      <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-micro text-dim2">
                        {total > 0 && (
                          <span className="tabular">
                            {done}/{total} steps
                          </span>
                        )}
                        {ex.approved_by && <span>by {ex.approved_by}</span>}
                        <span>{fmtDateTime(ex.started_at ?? ex.created_at)}</span>
                      </div>
                      {(ex.status === "partial" || ex.status === "failed") &&
                        ex.error_message && (
                          <div
                            className={`mt-1 text-micro ${ex.status === "failed" ? "text-sev-crit" : "text-sev-med"}`}
                          >
                            {ex.error_message}
                          </div>
                        )}
                    </div>
                  );
                })
              )}
            </div>
          </div>
        ))}
      </div>
      <div className="mt-2 text-kbd text-dim2">
        Read-only status board.{" "}
        {showControls
          ? "Approve, reject and rollback (role-gated, confirm-first) live in the List view."
          : "Actions are role-gated server-side and shown in the List view."}
      </div>
    </div>
  );
}

/**
 * The confirm-to-act dialog for all four SOAR writes. Shows exactly what will
 * happen — for approve/enable it lists the containment actions involved — so the
 * human sees the consequence before confirming. The primary button is the only
 * path that fires the write.
 */
function SoarConfirmDialog({
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

  let title: string;
  let body: React.ReactNode;
  let primaryLabel: string;
  let busyLabel: string;
  let danger = false;

  if (pending.kind === "toggle") {
    const pb = pending.pb;
    const wasEnabled = asBool(pb.enabled);
    const contains = containmentIn(actionList(pb.actions));
    title = wasEnabled ? "Disable playbook" : "Enable playbook";
    primaryLabel = wasEnabled ? "Disable now" : "Enable now";
    busyLabel = wasEnabled ? "Disabling…" : "Enabling…";
    danger = !wasEnabled && contains.length > 0;
    body = (
      <>
        <p className="text-data text-dim">
          {wasEnabled ? (
            <>
              This <b>disables</b> &quot;{pb.display_name || pb.name}&quot; — it
              will no longer trigger. De-escalatory; nothing runs.
            </>
          ) : (
            <>
              This <b>enables</b> &quot;{pb.display_name || pb.name}&quot;. It does
              not run anything now — it makes the playbook eligible to trigger on a
              matching decision.
            </>
          )}
        </p>
        {!wasEnabled && contains.length > 0 && (
          <div className="mt-2 rounded-lg border border-gated-border bg-panel2 px-3 py-2 text-kbd text-gated-ink">
            This playbook plans containment ({contains.map(prettyAction).join(", ")}
            ). When it triggers, a containment step still routes to the{" "}
            <b>human approval queue</b> — it never auto-runs from being enabled.
            Isolate/disable/kill stay always-human; only block_ip can auto-run, and
            only via the separate auto-block policy (off by default), which this
            does not change.
          </div>
        )}
      </>
    );
  } else if (pending.kind === "approve") {
    const ex = pending.ex;
    const planned = actionList(ex.actions_planned);
    const contains = containmentIn(planned);
    title = "Approve & dispatch execution";
    primaryLabel = "Approve & dispatch now";
    busyLabel = "Dispatching…";
    danger = contains.length > 0;
    body = (
      <>
        <p className="text-data text-dim">
          This <b>approves and immediately dispatches</b> the queued execution
          below. Its actions run on approval. It is a deliberate, logged
          senior_analyst+ action; nothing runs until you confirm.
        </p>
        <dl className="mt-3 grid grid-cols-[7rem_1fr] gap-x-3 gap-y-1.5 rounded-lg border border-line bg-panel2 px-3.5 py-3 text-data">
          <dt className="text-dim2">Playbook</dt>
          <dd className="text-ink">{ex.playbook_name || ex.playbook_id}</dd>
          <dt className="text-dim2">Incident</dt>
          <dd className="font-mono text-ink">{ex.incident_id ?? DASH}</dd>
          <dt className="text-dim2">Will run</dt>
          <dd className="text-ink">
            {planned.length ? (
              <div className="flex flex-wrap gap-1.5">
                {planned.map((a, i) => (
                  <span
                    key={`${a}-${i}`}
                    className={cn(
                      "rounded border px-1.5 py-0.5 text-kbd",
                      CONTAINMENT.has(a)
                        ? "border-gated-border text-gated-ink"
                        : "border-line text-dim",
                    )}
                  >
                    {prettyAction(a)}
                  </span>
                ))}
              </div>
            ) : (
              <span className="text-dim2">{DASH}</span>
            )}
          </dd>
        </dl>
        {contains.length > 0 && (
          <div className="mt-2 rounded-lg border border-gated-border bg-panel2 px-3 py-2 text-kbd text-gated-ink">
            Approving dispatches containment ({contains.map(prettyAction).join(", ")}
            ) to the affected host/network/account. It is logged; a block is
            reversible from here.
          </div>
        )}
      </>
    );
  } else if (pending.kind === "reject") {
    const ex = pending.ex;
    title = "Reject execution";
    primaryLabel = "Reject now";
    busyLabel = "Rejecting…";
    body = (
      <p className="text-data text-dim">
        This <b>cancels</b> the queued execution &quot;
        {ex.playbook_name || ex.playbook_id}&quot;. No containment runs. It is
        logged; nothing changes until you confirm.
      </p>
    );
  } else {
    const ex = pending.ex;
    const planned = actionList(ex.actions_planned);
    const contains = containmentIn(planned);
    title = "Rollback execution";
    primaryLabel = "Roll back now";
    busyLabel = "Rolling back…";
    body = (
      <>
        <p className="text-data text-dim">
          This <b>reverses</b> the containment from the completed execution &quot;
          {ex.playbook_name || ex.playbook_id}&quot; by running its inverse actions
          (unblock / unisolate / re-enable). It is an admin action, logged;
          nothing changes until you confirm.
        </p>
        {contains.length > 0 && (
          <div className="mt-2 rounded-lg border border-line bg-panel2 px-3 py-2 text-kbd text-dim2">
            Reverses: {contains.map(prettyAction).join(", ")}.
          </div>
        )}
      </>
    );
  }

  return (
    <Dialog open onClose={onClose} maxWidth={560} title={title}>
      {body}

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
              : danger
                ? "cursor-pointer border-gated-border bg-gated-border/40 text-gated-ink hover:brightness-125"
                : "cursor-pointer border-grounded-border bg-grounded-border/40 text-grounded-ink hover:brightness-125",
          )}
        >
          {submitting ? busyLabel : primaryLabel}
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
