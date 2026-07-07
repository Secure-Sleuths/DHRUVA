"use client";

/**
 * DetectionTab (WO-U9 read + Detection-write wiring) — AI-proposed Wazuh rule
 * changes, reviewed like code, with the closed-loop WRITE step wired in:
 * "human approves → rule deployed".
 *
 * Reads: `GET /api/detection/proposals` (`getDetectionProposals`), `verify_jwt` +
 * `require_license_feature("detection")`, surfaced to senior_analyst+ by the ACL.
 *
 * Writes (each mirrors src/api/routes/detection.py EXACTLY; server re-checks):
 *   - Approve / Reject → `POST /api/detection/review` (senior_analyst+). A
 *     proposal-lifecycle transition (proposed→approved | proposed→rejected); it
 *     does NOT touch a live Wazuh rule. Reason is OPTIONAL server-side, so reject
 *     offers a note but never forces one.
 *   - Deploy → `POST /api/detection/deploy/{id}` (mssp_admin ONLY). Changes the
 *     SHARED live Wazuh ruleset (restarts the manager) → behind an explicit
 *     confirm dialog that shows exactly what deploys (rule id, description,
 *     target file).
 *   - Rollback → `POST /api/detection/rollback/{id}` (mssp_admin ONLY). Reverts a
 *     deployed rule to its original XML (restarts the manager) → behind its own
 *     explicit confirm dialog showing the same detail.
 *   - Test / dry-run → `POST /api/detection/validate` (admin+). READ-ONLY: runs
 *     the proposed XML through wazuh-logtest and reports valid/invalid. Changes
 *     nothing live, so no confirm.
 *
 * RBAC is mirrored via `detectionActionGate` (@/lib/rbac), fail-closed, NEVER
 * wider than the server (deploy/rollback stay mssp_admin-only). No auto-deploy —
 * every deploy/rollback is a deliberate human confirm.
 *
 * HONEST STUB: there is NO server endpoint to edit a proposal's XML before
 * deploy — a rule deploys EXACTLY as shown in the diff. The UI says so rather
 * than faking an edit affordance.
 *
 * TIER GATE: a runtime 402/403 from the `detection` gate degrades the whole
 * surface to FeatureLockedState. Typed action errors: 402/403 → locked, 409/404
 * → "changed, refreshing", 400 (deploy/rollback failure) → typed error + reload,
 * else typed. States: loading / empty / error+retry / locked; PollingStatus
 * (30s, aborts on unmount). Fixtures gate behind NEXT_PUBLIC_DHRUVA_FIXTURES
 * (writes short-circuit to a synthetic success with NO real mutation).
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
  getDetectionProposals,
  getDeploymentHistory,
  getRuleVersions,
  reviewDetectionProposal,
  deployDetectionProposal,
  rollbackDetectionProposal,
  validateDetectionRule,
} from "@/lib/api";
import {
  changeTypePresentation,
  lineDiff,
  statusPresentation,
  type DiffLine,
} from "@/lib/detection";
import { detectionActionGate, type DetectionActionGate } from "@/lib/rbac";
import { useAuth } from "@/lib/auth";
import { cn, focusRing } from "@/lib/ui";
import { DASH, fmtDateTime, fmtInt } from "@/lib/format";
import type { TabProps } from "../tabRegistry";
import type {
  DeploymentHistoryEntry,
  DetectionProposal,
  DetectionValidateResult,
  RuleVersion,
} from "@/lib/types";

const POLL_MS = 30_000;

function isLockError(e: unknown): boolean {
  return e instanceof ApiError && (e.status === 402 || e.status === 403);
}
function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : "Unknown error";
}

interface State {
  proposals: DetectionProposal[] | null;
  error: string | null;
  locked: boolean;
  lockMessage: string | null;
  loading: boolean;
}

/** An in-flight confirm: which transition, on which proposal. */
type PendingKind = "approve" | "reject" | "deploy" | "rollback";
type Pending = { kind: PendingKind; proposal: DetectionProposal };
/** A transient result banner. */
type Flash = { tone: "ok" | "warn"; msg: string };
/** The dry-run (logtest) test flow state for one proposal. */
type TestState = {
  proposal: DetectionProposal;
  loading: boolean;
  result: DetectionValidateResult | null;
  error: string | null;
} | null;

type DetectionSection = "proposals" | "history" | "versions";
const DETECTION_SECTIONS: { id: DetectionSection; label: string }[] = [
  { id: "proposals", label: "Proposals" },
  { id: "history", label: "Deployment History" },
  { id: "versions", label: "Rule Versions" },
];

/** Canonical proposal-status filter order (restores legacy `proposalFilter`). */
const DETECTION_STATUS_ORDER = [
  "proposed",
  // Detection Agent exhausted its auto-fix attempts and needs a human — the
  // highest-priority engineer queue (legacy "Manual Fix" chip). Placed up front.
  "needs_manual_tuning",
  "approved",
  "deployed",
  "rejected",
  "rolled_back",
] as const;

type FilterOption = { value: string; label: string; count?: number };

/**
 * Build the status-filter options from the loaded proposals: "All" plus each
 * status actually present (canonical order first, then any unknown status),
 * every chip carrying its live count. Only statuses that exist are offered — no
 * empty buckets, no fabricated states.
 */
function detectionStatusOptions(proposals: DetectionProposal[]): FilterOption[] {
  const counts = new Map<string, number>();
  for (const p of proposals) {
    const s = p.status ?? "";
    counts.set(s, (counts.get(s) ?? 0) + 1);
  }
  const opts: FilterOption[] = [
    { value: "all", label: "All", count: proposals.length },
  ];
  for (const s of DETECTION_STATUS_ORDER) {
    const c = counts.get(s);
    if (c) opts.push({ value: s, label: statusPresentation(s).label, count: c });
  }
  for (const [s, c] of counts) {
    if (s && !DETECTION_STATUS_ORDER.includes(s as (typeof DETECTION_STATUS_ORDER)[number])) {
      opts.push({ value: s, label: statusPresentation(s).label, count: c });
    }
  }
  return opts;
}

/**
 * A subtle segmented chip-row for optional list filtering — matches the WO-U1
 * Chip aesthetic (active = cite, rest = default) already used for the rule-file
 * selector. Read-side refinement only; the default ("all") preserves current
 * behaviour and never replaces the list's order.
 */
function FilterChipRow({
  label,
  options,
  value,
  onChange,
}: {
  label: string;
  options: FilterOption[];
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div
      className="flex flex-wrap items-center gap-1.5"
      role="group"
      aria-label={label}
    >
      <span className="text-kbd uppercase tracking-wider text-dim2">{label}</span>
      {options.map((o) => (
        <Chip
          key={o.value}
          variant={value === o.value ? "cite" : "default"}
          onClick={() => onChange(o.value)}
          aria-label={`${label} ${o.label}${value === o.value ? " (selected)" : ""}`}
        >
          {o.label}
          {typeof o.count === "number" ? ` · ${o.count}` : ""}
        </Chip>
      ))}
    </div>
  );
}

export function DetectionTab(_props: TabProps) {
  const { role } = useAuth();
  const gate = detectionActionGate(role);
  const [section, setSection] = useState<DetectionSection>("proposals");
  // OPTIONAL status filter on the Proposals list. CLIENT-SIDE: the proposals
  // endpoint returns every proposal (no server status param), so this narrows the
  // fully-loaded set — it is complete, not a page-local slice. "all" = default.
  const [statusFilter, setStatusFilter] = useState<string>("all");

  const [state, setState] = useState<State>({
    proposals: null,
    error: null,
    locked: false,
    lockMessage: null,
    loading: true,
  });
  const [secondsAgo, setSecondsAgo] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  // ---- detection write (approve / reject / deploy / rollback / test) -------
  const [confirm, setConfirm] = useState<Pending | null>(null);
  const [rejectNote, setRejectNote] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [flash, setFlash] = useState<Flash | null>(null);
  const [test, setTest] = useState<TestState>(null);

  const load = useCallback(async (manual: boolean) => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    if (manual) setRefreshing(true);
    try {
      const res = await getDetectionProposals(ac.signal);
      if (ac.signal.aborted) return;
      setState({
        proposals: res.proposals,
        error: null,
        locked: false,
        lockMessage: null,
        loading: false,
      });
      setSecondsAgo(0);
    } catch (e) {
      if (ac.signal.aborted) return;
      if (isLockError(e)) {
        setState({
          proposals: null,
          error: null,
          locked: true,
          lockMessage: errMessage(e),
          loading: false,
        });
        return;
      }
      const msg = errMessage(e);
      setState((prev) =>
        prev.proposals
          ? { ...prev, loading: false }
          : {
              proposals: null,
              error: msg,
              locked: false,
              lockMessage: null,
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

  const openConfirm = useCallback((kind: PendingKind, p: DetectionProposal) => {
    setActionError(null);
    setRejectNote("");
    setConfirm({ kind, proposal: p });
  }, []);

  const closeConfirm = useCallback(() => {
    if (submitting) return; // don't let the dialog close mid-dispatch
    setConfirm(null);
    setActionError(null);
  }, [submitting]);

  /**
   * Run the confirmed transition. Invoked ONLY from the confirm dialog's
   * deliberate click — never automatically. Fail-closed on 402/403 (locked),
   * self-heal on 409/404 (item changed), typed on 400 (deploy/rollback failure)
   * and every other error.
   */
  const submitAction = useCallback(async () => {
    if (!confirm) return;
    const { kind, proposal } = confirm;
    const rid = proposal.rule_id ?? "new";
    setSubmitting(true);
    setActionError(null);
    try {
      if (kind === "approve") {
        await reviewDetectionProposal(proposal.id, "approve");
        setFlash({
          tone: "ok",
          msg: `Approved rule ${rid}. It is now eligible to deploy — deploying is a separate, mssp_admin-only step.`,
        });
      } else if (kind === "reject") {
        await reviewDetectionProposal(
          proposal.id,
          "reject",
          rejectNote.trim() || undefined,
        );
        setFlash({ tone: "ok", msg: `Rejected rule ${rid}. It will not deploy.` });
      } else if (kind === "deploy") {
        await deployDetectionProposal(proposal.id);
        setFlash({
          tone: "ok",
          msg: `Deployed rule ${rid} to the shared Wazuh ruleset and restarted the manager. It is reversible via rollback.`,
        });
      } else {
        await rollbackDetectionProposal(proposal.id);
        setFlash({
          tone: "ok",
          msg: `Rolled rule ${rid} back to its original XML and restarted the manager.`,
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
          "This proposal changed since you loaded it — its status may have moved on. Refreshing the list.",
        );
        setConfirm(null);
        await load(true);
      } else if (e instanceof ApiError && e.status === 400) {
        // deploy/rollback failure surfaces as HTTP 400 with a detail message.
        setActionError(
          `The ${kind} did not complete: ${errMessage(e)}. Nothing partial should be in force — verify against Wazuh and the audit log. Refreshing the list.`,
        );
        await load(true);
      } else {
        setActionError(errMessage(e));
      }
    } finally {
      setSubmitting(false);
    }
  }, [confirm, rejectNote, load]);

  // ---- dry-run test (logtest) — read-only, no confirm ----------------------
  const runTest = useCallback(async (p: DetectionProposal) => {
    setTest({ proposal: p, loading: true, result: null, error: null });
    try {
      const result = await validateDetectionRule(p.proposed_xml ?? "");
      setTest({ proposal: p, loading: false, result, error: null });
    } catch (e) {
      setTest({
        proposal: p,
        loading: false,
        result: null,
        error: isLockError(e)
          ? "Testing rule XML requires an admin or higher — the server denied it (the control mirrors the server)."
          : errMessage(e),
      });
    }
  }, []);

  const { proposals, error, locked, lockMessage, loading } = state;

  // Optional status filter over the fully-loaded proposal set (client-side).
  const statusOptions = proposals ? detectionStatusOptions(proposals) : [];
  const filteredProposals =
    proposals && statusFilter !== "all"
      ? proposals.filter((p) => (p.status ?? "") === statusFilter)
      : proposals;

  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PageHeading
          title="Detection engineering"
          sub="AI-proposed Wazuh rule changes, reviewed like code — every proposal shows the diff, the reasoning, and the false-positive impact that triggered it. Approving, deploying, and rolling back close the loop."
        />
        {!locked && section === "proposals" && (
          <PollingStatus
            className="mt-1"
            secondsAgo={secondsAgo}
            refreshing={refreshing}
            onRefresh={() => load(true)}
          />
        )}
      </div>

      {locked ? (
        // The whole Detection surface (proposals + deployment history + rule
        // versions) shares the `detection` license gate — a runtime 402/403 on
        // proposals locks all three (fail-closed to locked).
        <FeatureLockedState
          feature="Detection engineering"
          tier="current"
          onUpgrade={onUpgrade}
        />
      ) : (
        <>
          {/* Proposals / Deployment History / Rule Versions — all READ except
              the proposal write-actions already wired in "Proposals". History +
              Versions are new READ-ONLY sub-views (same admin/senior_analyst +
              detection gate, mirrored). */}
          <div
            className="mb-3 flex flex-wrap gap-1.5"
            role="tablist"
            aria-label="Detection sections"
          >
            {DETECTION_SECTIONS.map((s) => (
              <button
                key={s.id}
                type="button"
                role="tab"
                aria-selected={section === s.id}
                onClick={() => setSection(s.id)}
                className={cn(
                  "rounded-md border px-2.5 py-1 text-meta",
                  section === s.id
                    ? "border-cite-border bg-cite-bg text-cite-ink"
                    : "border-line bg-field text-ink hover:bg-hover",
                  focusRing,
                )}
              >
                {s.label}
              </button>
            ))}
          </div>

          {section === "proposals" &&
            (loading && !proposals ? (
              <StatusState variant="loading" title="Loading rule proposals…" />
            ) : error && !proposals ? (
              <StatusState
                variant="error"
                title="Couldn't load detection proposals"
                description={error}
                action={<Chip onClick={() => load(true)}>Retry</Chip>}
              />
            ) : proposals && proposals.length === 0 ? (
              <StatusState
                variant="empty"
                title="No rule proposals"
                description="The Detection Agent hasn't proposed any rule changes for this tenant yet. Proposals appear here once the feedback loop mines a recurring false-positive or a coverage gap."
              />
            ) : proposals ? (
              <div className="flex flex-col gap-3">
                <PostureNote gate={gate} />
                {flash && (
                  <FlashBanner flash={flash} onDismiss={() => setFlash(null)} />
                )}
                {statusOptions.length > 2 && (
                  <FilterChipRow
                    label="Status"
                    options={statusOptions}
                    value={statusFilter}
                    onChange={setStatusFilter}
                  />
                )}
                {filteredProposals && filteredProposals.length === 0 ? (
                  <StatusState
                    variant="empty"
                    title="No proposals match this filter"
                    description="No rule proposals are in this status right now. Clear the filter to see all proposals."
                    action={
                      <Chip onClick={() => setStatusFilter("all")}>
                        Clear filter
                      </Chip>
                    }
                  />
                ) : (
                  (filteredProposals ?? []).map((p) => (
                    <ProposalCard
                      key={p.id}
                      proposal={p}
                      gate={gate}
                      onAct={openConfirm}
                      onTest={runTest}
                    />
                  ))
                )}
              </div>
            ) : null)}

          {section === "history" && <DeploymentHistorySection />}
          {section === "versions" && <RuleVersionsSection />}
        </>
      )}

      {lockMessage && locked && (
        <div className="mt-2 text-kbd text-dim2">{lockMessage}</div>
      )}

      <ConfirmActionDialog
        pending={confirm}
        rejectNote={rejectNote}
        onRejectNote={setRejectNote}
        submitting={submitting}
        error={actionError}
        onConfirm={submitAction}
        onClose={closeConfirm}
      />

      <TestResultDialog test={test} onClose={() => setTest(null)} />
    </>
  );
}

function PostureNote({ gate }: { gate: DetectionActionGate }) {
  return (
    <div className="rounded-lg border border-line bg-panel2 px-3.5 py-2.5 text-kbd text-dim2">
      Approving a proposal marks it eligible; <b>deploying it changes the live,
      shared Wazuh ruleset for every tenant</b> and is <b>mssp_admin-only</b>,
      always behind an explicit confirm — nothing auto-deploys. Rollback reverts a
      deployed rule to its original XML (also mssp_admin, confirmed). A rule
      deploys <b>exactly as shown in the diff</b> — there is no edit-before-deploy
      step on this server, so this surface never lets you alter the proposed XML
      before it ships.
      {(gate.reviewLockNote || gate.deployLockNote || gate.testLockNote) && (
        <span className="mt-1 block text-dim2">
          {gate.deployLockNote ?? gate.reviewLockNote ?? gate.testLockNote}
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

function ProposalCard({
  proposal: p,
  gate,
  onAct,
  onTest,
}: {
  proposal: DetectionProposal;
  gate: DetectionActionGate;
  onAct: (kind: PendingKind, p: DetectionProposal) => void;
  onTest: (p: DetectionProposal) => void;
}) {
  const ct = changeTypePresentation(p.change_type);
  const st = statusPresentation(p.status);
  const diff = lineDiff(p.original_xml, p.proposed_xml);

  return (
    <Panel className="p-4">
      {/* header */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className={`text-title ${ct.className}`}>{ct.label}</span>
          <Chip mono aria-label={`Wazuh rule ${p.rule_id ?? "new"}`}>
            rule {p.rule_id ?? "new"}
          </Chip>
          {p.rule_file && (
            <span className="font-mono text-kbd text-dim2">{p.rule_file}</span>
          )}
        </div>
        <span className={`text-meta font-semibold ${st.className}`}>
          {st.label}
        </span>
      </div>

      {/* meta line */}
      <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-kbd text-dim2">
        <span>proposed {fmtDateTime(p.proposed_at)}</span>
        {p.reviewed_by && (
          <span>
            reviewed by <b className="text-dim">{p.reviewed_by}</b>{" "}
            {fmtDateTime(p.reviewed_at)}
          </span>
        )}
        {p.deployed_at && <span>deployed {fmtDateTime(p.deployed_at)}</span>}
      </div>

      {/* FP impact */}
      <FpImpact
        count={p.fp_count_trigger}
        windowDays={p.fp_window_days}
        changeType={p.change_type}
      />

      {/* reasoning */}
      {p.reasoning && (
        <p className="mt-2.5 text-data leading-relaxed text-ink">
          {p.reasoning}
        </p>
      )}

      {/* rejection notes, if any */}
      {p.status === "rejected" && p.rejection_notes && (
        <div className="mt-2 rounded-md border border-line bg-field px-3 py-2 text-data text-dim">
          <span className="text-kbd uppercase tracking-wider text-dim2">
            Reviewer note ·{" "}
          </span>
          {p.rejection_notes}
        </div>
      )}

      {/* diff */}
      <RuleDiff diff={diff} changeType={p.change_type} />

      <div className="mt-2 text-kbd text-dim2">
        The diff is computed client-side from the stored original vs proposed
        rule XML. No logtest result or model-confidence score is stored on the
        proposal (logtest is a separate admin-only validation step) — use “Test
        (logtest)” to run one; nothing else is inferred.
      </div>

      {/* actions */}
      <ProposalActions proposal={p} gate={gate} onAct={onAct} onTest={onTest} />
    </Panel>
  );
}

/**
 * Per-proposal action controls, gated per-transition to mirror the server. Only
 * the transitions the server allows FROM this status are offered; a control the
 * user's role can't fire is shown LOCKED (a gated chip), never hidden-and-widened
 * — so a senior_analyst still sees that Deploy exists but is mssp_admin's call.
 */
function ProposalActions({
  proposal: p,
  gate,
  onAct,
  onTest,
}: {
  proposal: DetectionProposal;
  gate: DetectionActionGate;
  onAct: (kind: PendingKind, p: DetectionProposal) => void;
  onTest: (p: DetectionProposal) => void;
}) {
  const st = p.status;

  // Terminal states have no server transition.
  if (st === "rejected" || st === "rolled_back") {
    return (
      <div className="mt-3 border-t border-line pt-2.5 text-kbd text-dim2">
        {st === "rejected"
          ? "Rejected — a terminal state. Re-proposing is up to the Detection Agent's next cycle."
          : "Rolled back — a terminal state. The original rule XML is in force."}
      </div>
    );
  }

  const testControl =
    p.proposed_xml != null ? (
      gate.canTest ? (
        <ActionButton tone="neutral" onClick={() => onTest(p)}>
          Test (logtest)…
        </ActionButton>
      ) : (
        <LockedChip label="Test · admin+" title={gate.testLockNote} />
      )
    ) : null;

  return (
    <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-line pt-3">
      {st === "proposed" && (
        <>
          {gate.canReview ? (
            <>
              <ActionButton tone="ok" onClick={() => onAct("approve", p)}>
                Approve
              </ActionButton>
              <ActionButton tone="neutral" onClick={() => onAct("reject", p)}>
                Reject…
              </ActionButton>
            </>
          ) : (
            <LockedChip
              label="Approve / reject · senior_analyst+"
              title={gate.reviewLockNote}
            />
          )}
          {testControl}
        </>
      )}

      {st === "approved" && (
        <>
          {gate.canDeploy ? (
            <ActionButton tone="warn" onClick={() => onAct("deploy", p)}>
              Deploy to Wazuh…
            </ActionButton>
          ) : (
            <LockedChip
              label="Deploy · mssp_admin"
              title={gate.deployLockNote}
            />
          )}
          {testControl}
        </>
      )}

      {st === "deployed" && (
        <>
          {gate.canRollback ? (
            <ActionButton tone="warn" onClick={() => onAct("rollback", p)}>
              Roll back…
            </ActionButton>
          ) : (
            <LockedChip
              label="Rollback · mssp_admin"
              title={gate.deployLockNote}
            />
          )}
        </>
      )}
    </div>
  );
}

function ActionButton({
  tone,
  onClick,
  children,
}: {
  tone: "ok" | "warn" | "neutral";
  onClick: () => void;
  children: React.ReactNode;
}) {
  const cls =
    tone === "ok"
      ? "border-grounded-border bg-grounded-border/40 text-grounded-ink hover:brightness-125"
      : tone === "warn"
        ? "border-gated-border bg-field text-gated-ink hover:brightness-125"
        : "border-line bg-field text-ink hover:bg-hover";
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "cursor-pointer rounded-md border px-2.5 py-1 text-meta",
        cls,
        focusRing,
      )}
    >
      {children}
    </button>
  );
}

function LockedChip({ label, title }: { label: string; title?: string }) {
  return (
    <span title={title}>
      <Chip variant="gated" aria-label={title ?? label}>
        Locked · {label}
      </Chip>
    </span>
  );
}

/**
 * The confirm-to-act dialog. For deploy/rollback it shows EXACTLY what changes on
 * the LIVE shared Wazuh ruleset (rule id, change type, description, target file)
 * with a prominent warning, so the human sees the consequence before dispatching.
 * For approve/reject (lifecycle transitions, no live change) it is lighter;
 * reject offers an OPTIONAL note (the server does not require one). The primary
 * button is the only path that fires the write.
 */
function ConfirmActionDialog({
  pending,
  rejectNote,
  onRejectNote,
  submitting,
  error,
  onConfirm,
  onClose,
}: {
  pending: Pending | null;
  rejectNote: string;
  onRejectNote: (v: string) => void;
  submitting: boolean;
  error: string | null;
  onConfirm: () => void;
  onClose: () => void;
}) {
  if (!pending) return null;
  const { kind, proposal: p } = pending;
  const live = kind === "deploy" || kind === "rollback";
  const rid = p.rule_id ?? "new";
  const ct = changeTypePresentation(p.change_type);

  const title =
    kind === "approve"
      ? "Approve proposal"
      : kind === "reject"
        ? "Reject proposal"
        : kind === "deploy"
          ? "Deploy rule to Wazuh"
          : "Roll back deployed rule";

  const cta =
    kind === "approve"
      ? submitting
        ? "Approving…"
        : "Approve now"
      : kind === "reject"
        ? submitting
          ? "Rejecting…"
          : "Reject now"
        : kind === "deploy"
          ? submitting
            ? "Deploying…"
            : "Deploy now"
          : submitting
            ? "Rolling back…"
            : "Roll back now";

  return (
    <Dialog open onClose={onClose} maxWidth={560} title={title}>
      <p className="text-data text-dim">
        {kind === "approve" && (
          <>
            This marks the proposal <b>approved</b> — eligible to deploy. It does{" "}
            <b>not</b> change any live Wazuh rule; deploying is a separate,
            mssp_admin-only step. Nothing changes until you confirm.
          </>
        )}
        {kind === "reject" && (
          <>
            This marks the proposal <b>rejected</b> — it will not deploy. It does
            not change any live Wazuh rule. A note is optional and audited.
          </>
        )}
        {kind === "deploy" && (
          <>
            This <b>writes the proposed rule to the SHARED, live Wazuh ruleset</b>{" "}
            (affecting every tenant) and <b>restarts the Wazuh manager</b>. It is
            deliberate, logged, and reversible via rollback. Nothing deploys until
            you confirm.
          </>
        )}
        {kind === "rollback" && (
          <>
            This <b>reverts the deployed rule to its original XML</b> on the
            shared Wazuh backend and <b>restarts the Wazuh manager</b>. It is
            deliberate and logged. Nothing changes until you confirm.
          </>
        )}
      </p>

      {live && (
        <dl className="mt-3 grid grid-cols-[8rem_1fr] gap-x-3 gap-y-1.5 rounded-lg border border-gated-border bg-panel2 px-3.5 py-3 text-data">
          <dt className="text-dim2">Rule id</dt>
          <dd className="font-mono text-ink">{rid}</dd>

          <dt className="text-dim2">Change</dt>
          <dd className={cn("font-semibold", ct.className)}>{ct.label}</dd>

          <dt className="text-dim2">Description</dt>
          <dd className="text-ink">{p.reasoning || DASH}</dd>

          <dt className="text-dim2">Target file</dt>
          <dd className="font-mono text-ink">{p.rule_file || "local_rules.xml"}</dd>

          <dt className="text-dim2">Target</dt>
          <dd className="text-ink">Shared Wazuh manager (all tenants)</dd>
        </dl>
      )}

      {kind === "reject" && (
        <div className="mt-3">
          <label
            htmlFor="detection-reject-note"
            className="mb-1 block text-kbd text-dim2"
          >
            Note (optional — audited)
          </label>
          <textarea
            id="detection-reject-note"
            value={rejectNote}
            onChange={(e) => onRejectNote(e.target.value)}
            rows={3}
            disabled={submitting}
            placeholder="Why is this proposal being rejected? (optional)"
            className={cn(
              "w-full resize-y rounded-md border border-line bg-field px-3 py-2 text-data text-ink placeholder:text-dim2",
              focusRing,
            )}
          />
        </div>
      )}

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
              : kind === "approve"
                ? "cursor-pointer border-grounded-border bg-grounded-border/40 text-grounded-ink hover:brightness-125"
                : live
                  ? "cursor-pointer border-gated-border bg-field text-gated-ink hover:brightness-125"
                  : "cursor-pointer border-line bg-field text-ink hover:bg-hover",
          )}
        >
          {cta}
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

/**
 * The dry-run result dialog. `POST /api/detection/validate` runs the proposed XML
 * through wazuh-logtest and returns valid/invalid — a READ-ONLY check that
 * changes nothing live. Shown as its own non-mutating dialog.
 */
function TestResultDialog({
  test,
  onClose,
}: {
  test: TestState;
  onClose: () => void;
}) {
  if (!test) return null;
  const rid = test.proposal.rule_id ?? "new";
  return (
    <Dialog open onClose={onClose} maxWidth={560} title={`Test rule ${rid} (logtest)`}>
      <p className="text-data text-dim">
        A read-only dry-run of the proposed rule XML against Wazuh’s{" "}
        <span className="font-mono">wazuh-logtest</span>. This validates syntax
        only — it changes nothing live and deploys nothing.
      </p>

      {test.loading ? (
        <div className="mt-3 text-data text-dim2">Running logtest…</div>
      ) : test.error ? (
        <p className="mt-3 text-data text-sev-crit" role="alert">
          {test.error}
        </p>
      ) : test.result ? (
        <div className="mt-3 rounded-lg border border-line bg-panel2 px-3.5 py-3 text-data">
          {test.result.valid ? (
            <div className="text-grounded-ink">
              <b>Valid.</b> Wazuh accepts this rule XML.
            </div>
          ) : (
            <div className="text-sev-crit">
              <b>Invalid.</b>{" "}
              {test.result.error || "Wazuh rejected the rule (no detail returned)."}
            </div>
          )}
        </div>
      ) : null}

      <div className="mt-4">
        <button
          type="button"
          onClick={onClose}
          className={cn(
            "rounded-md border border-line bg-field px-3 py-1.5 text-data text-ink hover:bg-hover",
            focusRing,
          )}
        >
          Close
        </button>
      </div>
    </Dialog>
  );
}

function FpImpact({
  count,
  windowDays,
  changeType,
}: {
  count: number | null;
  windowDays: number | null;
  changeType: string;
}) {
  // A brand-new rule is not triggered by a false-positive count.
  if (changeType === "new_rule" && !count) {
    return (
      <div className="mt-2 text-kbd text-dim2">
        New-coverage proposal · not triggered by a false-positive count.
      </div>
    );
  }
  if (count == null) {
    return (
      <div className="mt-2 text-kbd text-dim2">
        False-positive impact {DASH} not recorded.
      </div>
    );
  }
  return (
    <div className="mt-2 flex items-center gap-2 text-kbd">
      <span className="text-dim2">False-positive impact:</span>
      <span className="text-ink">
        <b className="tabular">{fmtInt(count)}</b> false positive
        {count === 1 ? "" : "s"} over the last{" "}
        <b className="tabular">{windowDays ?? DASH}</b> day
        {windowDays === 1 ? "" : "s"}
      </span>
    </div>
  );
}

function RuleDiff({
  diff,
  changeType,
}: {
  diff: DiffLine[];
  changeType: string;
}) {
  if (diff.length === 0) {
    return (
      <div className="mt-2.5 text-kbd text-dim2">
        No rule XML recorded for this proposal.
      </div>
    );
  }
  return (
    <div className="mt-2.5">
      <div className="mb-1 flex items-center gap-3 text-kbd text-dim2">
        <span>Proposed rule diff</span>
        <span className="text-sev-crit">− removed</span>
        <span className="text-teal">+ added</span>
        {changeType === "new_rule" && <span>(all lines new)</span>}
      </div>
      <pre className="overflow-x-auto rounded-md border border-line bg-field p-2.5 font-mono text-[11.5px] leading-relaxed">
        {diff.map((l, i) => (
          <div
            key={i}
            className={
              l.kind === "add"
                ? "bg-grounded-border/25 text-teal"
                : l.kind === "del"
                  ? "bg-sev-crit/10 text-sev-crit"
                  : "text-dim"
            }
          >
            <span aria-hidden="true" className="select-none pr-2 text-dim2">
              {l.kind === "add" ? "+" : l.kind === "del" ? "−" : " "}
            </span>
            {l.text || " "}
          </div>
        ))}
      </pre>
    </div>
  );
}

// ============================================================================
// Detection → Deployment History (restores legacy `showDetectionHistory`,
// app.js:1172-1209). GET /api/detection/history —
// require_role("admin","senior_analyst") + require_license_feature("detection").
// READ-ONLY: it lists the append-only rule_deployment_history rows; it does NOT
// touch any live rule. A runtime 402/403 → FeatureLockedState (fail-closed).
// ============================================================================
function upgradeToPricing() {
  if (typeof window !== "undefined") {
    window.open("https://securesleuths.in/pricing", "_blank", "noreferrer");
  }
}

function DeploymentHistorySection() {
  const [entries, setEntries] = useState<DeploymentHistoryEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [locked, setLocked] = useState(false);
  const [loading, setLoading] = useState(true);
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setLoading(true);
    setError(null);
    try {
      const res = await getDeploymentHistory({ limit: 50 }, ac.signal);
      if (ac.signal.aborted) return;
      setEntries(res.history);
      setLoading(false);
    } catch (e) {
      if (ac.signal.aborted) return;
      if (isLockError(e)) {
        setLocked(true);
        setLoading(false);
        return;
      }
      setError(errMessage(e));
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    return () => abortRef.current?.abort();
  }, [load]);

  if (locked) {
    return (
      <FeatureLockedState
        feature="Detection engineering"
        tier="current"
        onUpgrade={upgradeToPricing}
      />
    );
  }
  if (loading && !entries) {
    return <StatusState variant="loading" title="Loading deployment history…" />;
  }
  if (error && !entries) {
    return (
      <StatusState
        variant="error"
        title="Couldn't load deployment history"
        description={error}
        action={<Chip onClick={load}>Retry</Chip>}
      />
    );
  }
  if (entries && entries.length === 0) {
    return (
      <StatusState
        variant="empty"
        title="No deployments yet"
        description="No rule has been deployed to the shared Wazuh backend for this tenant, so there's no version history to show."
      />
    );
  }

  return (
    <Panel className="overflow-hidden">
      <div className="px-4 pt-3 text-title text-ink">Deployment history</div>
      <div className="px-4 text-kbd text-dim2">
        Append-only record of every rule deployment (and rollback) to the shared
        Wazuh backend — most recent first. Read-only.
      </div>
      <Table className="mt-2">
        <THead>
          <TR>
            <TH>Rule file</TH>
            <TH className="text-right">Rule</TH>
            <TH className="text-right">Version</TH>
            <TH>Deployed by</TH>
            <TH>Deployed at</TH>
            <TH>Status</TH>
            <TH>Backup</TH>
          </TR>
        </THead>
        <TBody>
          {(entries ?? []).map((e, i) => (
            <TR key={e.id ?? i}>
              <TD mono>{e.rule_file ?? DASH}</TD>
              <TD mono className="text-right">{e.rule_id ?? DASH}</TD>
              <TD mono className="text-right">{e.version ?? DASH}</TD>
              <TD mono>{e.deployed_by ?? DASH}</TD>
              <TD>{fmtDateTime(e.deployed_at)}</TD>
              <TD>
                {e.rolled_back_at ? (
                  <span className="text-sev-med">
                    Rolled back {fmtDateTime(e.rolled_back_at)}
                  </span>
                ) : (
                  <span className="text-teal">Deployed</span>
                )}
              </TD>
              <TD>
                <span className="text-dim2">
                  {e.xml_before ? "Backup stored" : "No prior XML"}
                </span>
              </TD>
            </TR>
          ))}
        </TBody>
      </Table>
    </Panel>
  );
}

// ============================================================================
// Detection → Rule Versions (restores legacy `showRuleVersions`,
// app.js:1211-1240). GET /api/detection/history/{rule_file}/versions — same
// admin/senior_analyst + detection gate. READ-ONLY. The rule_file list is
// derived from the deployment history; the /versions projection strips XML to a
// `has_xml_before` flag (no rule XML is fetched or shown here).
// ============================================================================
function RuleVersionsSection() {
  const [files, setFiles] = useState<string[] | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [histError, setHistError] = useState<string | null>(null);
  const [locked, setLocked] = useState(false);
  const [histLoading, setHistLoading] = useState(true);

  const [versions, setVersions] = useState<RuleVersion[] | null>(null);
  const [verError, setVerError] = useState<string | null>(null);
  const [verLoading, setVerLoading] = useState(false);

  const histAbortRef = useRef<AbortController | null>(null);
  const verAbortRef = useRef<AbortController | null>(null);

  // Derive the distinct rule_files from deployment history (same gate).
  useEffect(() => {
    const ac = new AbortController();
    histAbortRef.current = ac;
    (async () => {
      setHistLoading(true);
      setHistError(null);
      try {
        const res = await getDeploymentHistory({ limit: 100 }, ac.signal);
        if (ac.signal.aborted) return;
        const distinct = Array.from(
          new Set(
            res.history
              .map((h) => h.rule_file)
              .filter((f): f is string => !!f),
          ),
        );
        setFiles(distinct);
        setSelected((prev) => prev ?? distinct[0] ?? null);
        setHistLoading(false);
      } catch (e) {
        if (ac.signal.aborted) return;
        if (isLockError(e)) {
          setLocked(true);
          setHistLoading(false);
          return;
        }
        setHistError(errMessage(e));
        setHistLoading(false);
      }
    })();
    return () => ac.abort();
  }, []);

  // Load versions whenever the selected rule_file changes.
  useEffect(() => {
    if (!selected) return;
    verAbortRef.current?.abort();
    const ac = new AbortController();
    verAbortRef.current = ac;
    (async () => {
      setVerLoading(true);
      setVerError(null);
      setVersions(null);
      try {
        const res = await getRuleVersions(selected, ac.signal);
        if (ac.signal.aborted) return;
        setVersions(res.versions);
        setVerLoading(false);
      } catch (e) {
        if (ac.signal.aborted) return;
        if (isLockError(e)) {
          setLocked(true);
          setVerLoading(false);
          return;
        }
        setVerError(errMessage(e));
        setVerLoading(false);
      }
    })();
    return () => ac.abort();
  }, [selected]);

  if (locked) {
    return (
      <FeatureLockedState
        feature="Detection engineering"
        tier="current"
        onUpgrade={upgradeToPricing}
      />
    );
  }
  if (histLoading && !files) {
    return <StatusState variant="loading" title="Loading deployed rule files…" />;
  }
  if (histError && !files) {
    return (
      <StatusState
        variant="error"
        title="Couldn't load rule files"
        description={histError}
      />
    );
  }
  if (files && files.length === 0) {
    return (
      <StatusState
        variant="empty"
        title="No deployed rule files"
        description="Nothing has been deployed yet, so there are no rule versions to browse."
      />
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-kbd uppercase tracking-wider text-dim2">
          Rule file
        </span>
        <div className="flex flex-wrap gap-1.5" role="group" aria-label="Rule file">
          {(files ?? []).map((f) => (
            <Chip
              key={f}
              mono
              variant={selected === f ? "cite" : "default"}
              onClick={() => setSelected(f)}
              aria-label={`Show versions of ${f}`}
            >
              {f}
            </Chip>
          ))}
        </div>
      </div>

      <Panel className="overflow-hidden">
        <div className="px-4 pt-3 text-title text-ink">
          Versions · <span className="font-mono">{selected ?? DASH}</span>
        </div>
        <div className="px-4 text-kbd text-dim2">
          Every deployed version of this rule file. Read-only — the rule XML
          itself is not exposed here (only whether a rollback backup was stored).
        </div>
        {verLoading && !versions ? (
          <div className="px-4 py-3">
            <StatusState variant="loading" title="Loading versions…" />
          </div>
        ) : verError && !versions ? (
          <div className="px-4 py-3">
            <StatusState
              variant="error"
              title="Couldn't load versions"
              description={verError}
            />
          </div>
        ) : versions && versions.length > 0 ? (
          <Table className="mt-2">
            <THead>
              <TR>
                <TH className="text-right">Version</TH>
                <TH className="text-right">Rule</TH>
                <TH>Deployed by</TH>
                <TH>Deployed at</TH>
                <TH>Status</TH>
                <TH>Backup</TH>
              </TR>
            </THead>
            <TBody>
              {versions.map((v) => (
                <TR key={v.version}>
                  <TD mono className="text-right">{v.version}</TD>
                  <TD mono className="text-right">{v.rule_id ?? DASH}</TD>
                  <TD mono>{v.deployed_by ?? DASH}</TD>
                  <TD>{fmtDateTime(v.deployed_at)}</TD>
                  <TD>
                    {v.rolled_back_at ? (
                      <span className="text-sev-med">
                        Rolled back {fmtDateTime(v.rolled_back_at)}
                      </span>
                    ) : (
                      <span className="text-teal">Deployed</span>
                    )}
                  </TD>
                  <TD>
                    <span className="text-dim2">
                      {v.has_xml_before ? "Backup stored" : "No prior XML"}
                    </span>
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        ) : (
          <div className="px-4 py-3 text-data text-dim2">
            No versions recorded for this rule file.
          </div>
        )}
      </Panel>
    </div>
  );
}
