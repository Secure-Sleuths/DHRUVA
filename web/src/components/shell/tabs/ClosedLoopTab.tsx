"use client";

/**
 * ClosedLoopTab — the compounding-intelligence loop: the FP / noisy-rule
 * patterns it mined + how deployed tunings performed, with the ONE
 * endpoint-backed WRITE wired.
 *
 * Reads:
 *   - `GET /api/feedback/patterns` (`getFeedbackPatterns`) +
 *     `GET /api/feedback/effectiveness` (`getProposalEffectiveness`, a BARE LIST)
 *     — both `require_role(admin, senior_analyst)` + `require_license_feature(
 *     "feedback_loop")`, surfaced to senior_analyst+ by the shell ACL.
 *
 * Write (this WO — mirrors `src/api/routes/feedback.py` + lib/rbac
 * `feedbackActionGate`, confirm-gated):
 *   - RUN CYCLE `POST /api/feedback/run-cycle` (admin+, rate-limited 2/min). Runs
 *     a feedback analysis cycle in the BACKGROUND: re-mines patterns and lets the
 *     Detection agent regenerate its tuning proposals. Returns immediately; the
 *     new patterns/proposals appear on the next poll.
 *
 * HONEST STUBS (no server endpoint exists): there is NO per-pattern accept /
 * dismiss and NO "mark a noisy rule for the Detection queue" endpoint — the loop
 * mines patterns AUTOMATICALLY and the Detection AGENT turns them into rule
 * proposals, which are accepted/rejected on the Detection tab. Running a cycle is
 * how you drive that pipeline; the tab says so rather than inventing a
 * client-only accept/dismiss mutation.
 *
 * TIER GATE: a runtime 402/403 from the `feedback_loop` gate degrades the whole
 * surface to FeatureLockedState. States: loading / empty / error+retry / locked;
 * submitting + typed error (402/403 → locked, 429 → rate-limited, 503 → engine
 * down); PollingStatus (30s, aborts on unmount). Fixtures gate behind
 * NEXT_PUBLIC_DHRUVA_FIXTURES (run-cycle short-circuits to synthetic accepted, NO
 * real mutation).
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
  getFeedbackPatterns,
  getProposalEffectiveness,
  runFeedbackCycle,
} from "@/lib/api";
import { feedbackActionGate, type FeedbackActionGate } from "@/lib/rbac";
import { useAuth } from "@/lib/auth";
import { effectivenessPresentation, patternTypePresentation } from "@/lib/feedback";
import { cn, focusRing } from "@/lib/ui";
import { DASH, fmtDateTime, fmtInt, fmtPct } from "@/lib/format";
import type { TabProps } from "../tabRegistry";
import type { FeedbackPattern, ProposalEffectiveness } from "@/lib/types";

const POLL_MS = 30_000;

function isLockError(e: unknown): boolean {
  return e instanceof ApiError && (e.status === 402 || e.status === 403);
}
function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : "Unknown error";
}

interface State {
  patterns: FeedbackPattern[] | null;
  effectiveness: ProposalEffectiveness[] | null;
  error: string | null;
  locked: boolean;
  loading: boolean;
}

type Flash = { tone: "ok" | "warn"; msg: string };

export function ClosedLoopTab(_props: TabProps) {
  const { role } = useAuth();
  const gate = feedbackActionGate(role);

  const [state, setState] = useState<State>({
    patterns: null,
    effectiveness: null,
    error: null,
    locked: false,
    loading: true,
  });
  const [secondsAgo, setSecondsAgo] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  // ---- write state --------------------------------------------------------
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [flash, setFlash] = useState<Flash | null>(null);

  const load = useCallback(async (manual: boolean) => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    if (manual) setRefreshing(true);
    try {
      const [patterns, effectiveness] = await Promise.all([
        getFeedbackPatterns({ minOccurrences: 1, limit: 200 }, ac.signal),
        getProposalEffectiveness(ac.signal),
      ]);
      if (ac.signal.aborted) return;
      setState({
        patterns: patterns.patterns,
        effectiveness,
        error: null,
        locked: false,
        loading: false,
      });
      setSecondsAgo(0);
    } catch (e) {
      if (ac.signal.aborted) return;
      if (isLockError(e)) {
        setState({ patterns: null, effectiveness: null, error: null, locked: true, loading: false });
        return;
      }
      const msg = errMessage(e);
      setState((prev) =>
        prev.patterns
          ? { ...prev, loading: false }
          : { patterns: null, effectiveness: null, error: msg, locked: false, loading: false },
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

  const submitRunCycle = useCallback(async () => {
    setSubmitting(true);
    setActionError(null);
    try {
      await runFeedbackCycle();
      setFlash({
        tone: "ok",
        msg: "Feedback cycle started in the background — new patterns and tuning proposals will appear on the next refresh.",
      });
      setConfirmOpen(false);
      // give the background task a moment, then refresh
      await load(true);
    } catch (e) {
      if (isLockError(e)) {
        setActionError(
          "Running a feedback cycle is an admin action — the server denied it for your role. Nothing changed.",
        );
      } else if (e instanceof ApiError && e.status === 429) {
        setActionError(
          "A cycle was run very recently (the server rate-limits this to twice a minute). Wait a moment and try again.",
        );
      } else if (e instanceof ApiError && e.status === 503) {
        setActionError(
          "The feedback engine is not available right now. Nothing changed.",
        );
      } else {
        setActionError(errMessage(e));
      }
    } finally {
      setSubmitting(false);
    }
  }, [load]);

  const { patterns, effectiveness, error, locked, loading } = state;

  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PageHeading
          title="Closed loop"
          sub="The false-positive patterns the loop mined, and how well each deployed tuning worked."
        />
        <div className="mt-1 flex items-center gap-2">
          {!locked && gate.canRunCycle && patterns && (
            <button
              type="button"
              onClick={() => {
                setActionError(null);
                setConfirmOpen(true);
              }}
              className={cn(
                "cursor-pointer rounded-md border border-grounded-border bg-grounded-border/40 px-2.5 py-1 text-meta text-grounded-ink hover:brightness-125",
                focusRing,
              )}
            >
              Run cycle now…
            </button>
          )}
          {!locked && (
            <PollingStatus
              secondsAgo={secondsAgo}
              refreshing={refreshing}
              onRefresh={() => load(true)}
            />
          )}
        </div>
      </div>

      {locked ? (
        <FeatureLockedState feature="Closed loop" tier="current" onUpgrade={onUpgrade} />
      ) : loading && !patterns ? (
        <StatusState variant="loading" title="Loading learned patterns…" />
      ) : error && !patterns ? (
        <StatusState
          variant="error"
          title="Couldn't load the feedback loop"
          description={error}
          action={<Chip onClick={() => load(true)}>Retry</Chip>}
        />
      ) : patterns ? (
        <div className="flex flex-col gap-3">
          <ActionNote gate={gate} />
          {flash && <FlashBanner flash={flash} onDismiss={() => setFlash(null)} />}
          <StatsTiles patterns={patterns} effectiveness={effectiveness ?? []} />
          <PatternsPanel patterns={patterns} />
          <EffectivenessPanel rows={effectiveness ?? []} />
        </div>
      ) : null}

      <RunCycleDialog
        open={confirmOpen}
        submitting={submitting}
        error={actionError}
        onConfirm={submitRunCycle}
        onClose={() => {
          if (submitting) return;
          setConfirmOpen(false);
          setActionError(null);
        }}
      />
    </>
  );
}

function ActionNote({ gate }: { gate: FeedbackActionGate }) {
  return (
    <div className="rounded-lg border border-line bg-panel2 px-3.5 py-2.5 text-kbd text-dim2">
      This is what the loop has learned. Running a cycle (admin only) re-mines
      these patterns and lets the Detection agent regenerate its tuning proposals
      — you then <b>accept or reject those proposals on the Detection tab</b>.
      There is deliberately no per-pattern accept/dismiss or &quot;mark for
      Detection&quot; button here: patterns are mined automatically, and a noisy
      rule reaches the Detection queue via a cycle, not a manual client action.
      {gate.lockNote && <span className="mt-1 block text-dim2">{gate.lockNote}</span>}
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

function StatsTiles({
  patterns,
  effectiveness,
}: {
  patterns: FeedbackPattern[];
  effectiveness: ProposalEffectiveness[];
}) {
  const totalOcc = patterns.reduce((s, p) => s + (p.occurrence_count || 0), 0);
  const working = effectiveness.filter((e) => e.effective === true).length;
  const pending = effectiveness.filter((e) => e.effective === null).length;
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
      <Tile label="Active patterns" value={fmtInt(patterns.length)} sub="mined & live" />
      <Tile
        label="Total occurrences"
        value={fmtInt(totalOcc)}
        sub="alerts across patterns"
        math={
          <>
            Sum of `occurrence_count` over the active patterns — the raw noise the
            loop is compressing. A real count, not an estimate.
          </>
        }
      />
      <Tile
        label="Tunings tracked"
        value={fmtInt(effectiveness.length)}
        sub="deployed proposals"
      />
      <Tile
        label="Working"
        value={fmtInt(working)}
        sub={pending > 0 ? `${fmtInt(pending)} still gathering data` : "confirmed effective"}
      />
    </div>
  );
}

function PatternsPanel({ patterns }: { patterns: FeedbackPattern[] }) {
  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-3">
        <div className="text-title text-ink">Learned patterns</div>
        <span className="text-kbd text-dim2">{patterns.length} active</span>
      </div>
      <div className="px-4 text-kbd text-dim2">
        Recurring false positives and noisy rules the loop has mined — these feed
        the Detection agent&apos;s tuning proposals.
      </div>
      {patterns.length === 0 ? (
        <div className="px-4 pb-4 pt-2 text-data text-dim2">
          No patterns mined yet. Patterns emerge once the loop sees a rule produce
          the same false-positive shape repeatedly.
        </div>
      ) : (
        <Table className="mt-2">
          <THead>
            <TR>
              <TH>Pattern</TH>
              <TH>Rule</TH>
              <TH className="text-right">Occurrences</TH>
              <TH>Loop action</TH>
              <TH>First → last seen</TH>
            </TR>
          </THead>
          <TBody>
            {patterns.map((p) => {
              const pt = patternTypePresentation(p.pattern_type);
              return (
                <TR key={p.id}>
                  <TD>
                    <div className={`text-meta font-semibold ${pt.className}`}>{pt.label}</div>
                    {p.description && (
                      <div className="max-w-[520px] text-kbd text-dim2">{p.description}</div>
                    )}
                  </TD>
                  <TD mono>{fmtInt(p.rule_id)}</TD>
                  <TD mono className="text-right">
                    {fmtInt(p.occurrence_count)}
                  </TD>
                  <TD>
                    {p.auto_action_taken ? (
                      <span className="text-acc">{p.auto_action_taken.replace(/_/g, " ")}</span>
                    ) : (
                      <span className="text-dim2">{DASH}</span>
                    )}
                  </TD>
                  <TD>
                    <span className="text-kbd text-dim">
                      {fmtDateTime(p.first_seen)} → {fmtDateTime(p.last_seen)}
                    </span>
                  </TD>
                </TR>
              );
            })}
          </TBody>
        </Table>
      )}
    </Panel>
  );
}

function EffectivenessPanel({ rows }: { rows: ProposalEffectiveness[] }) {
  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-3">
        <div className="text-title text-ink">Deployed-tuning scorecard</div>
        <span className="text-kbd text-dim2">{rows.length} tracked</span>
      </div>
      <div className="px-4 text-kbd text-dim2">
        For each deployed proposal: did the false-positive rate drop without the
        true-positive rate collapsing? Rates are over the 30 days after deploy.
      </div>
      {rows.length === 0 ? (
        <div className="px-4 pb-4 pt-2 text-data text-dim2">
          No deployed tunings to score yet. Rows appear here once a Detection
          proposal has been deployed and has accrued post-deployment decisions.
        </div>
      ) : (
        <Table className="mt-2">
          <THead>
            <TR>
              <TH>Rule</TH>
              <TH>Verdict</TH>
              <TH className="text-right">FP rate (after)</TH>
              <TH className="text-right">TP rate (after)</TH>
              <TH className="text-right">Decisions</TH>
              <TH>Deployed</TH>
            </TR>
          </THead>
          <TBody>
            {rows.map((r) => {
              const ep = effectivenessPresentation(r);
              return (
                <TR key={r.proposal_id}>
                  <TD mono>{fmtInt(r.rule_id)}</TD>
                  <TD>
                    <span className={`text-meta font-semibold ${ep.className}`}>{ep.label}</span>
                    <div className="max-w-[340px] text-kbd text-dim2">{ep.detail}</div>
                  </TD>
                  <TD mono className="text-right">
                    {fmtPct(r.post_fp_rate, { fraction: true })}
                  </TD>
                  <TD mono className="text-right">
                    {fmtPct(r.post_tp_rate, { fraction: true })}
                  </TD>
                  <TD mono className="text-right">
                    {fmtInt(r.post_total_decisions)}
                  </TD>
                  <TD>{fmtDateTime(r.deployed_at)}</TD>
                </TR>
              );
            })}
          </TBody>
        </Table>
      )}
    </Panel>
  );
}

function RunCycleDialog({
  open,
  submitting,
  error,
  onConfirm,
  onClose,
}: {
  open: boolean;
  submitting: boolean;
  error: string | null;
  onConfirm: () => void;
  onClose: () => void;
}) {
  if (!open) return null;
  return (
    <Dialog open onClose={onClose} maxWidth={520} title="Run a feedback cycle">
      <p className="text-data text-dim">
        This runs a feedback analysis cycle in the background: it re-mines
        false-positive / noisy-rule patterns and lets the Detection agent
        regenerate its tuning proposals. It <b>deploys nothing</b> on its own —
        any rule change still goes through review on the Detection tab. The server
        rate-limits this to twice a minute.
      </p>

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
              : "cursor-pointer border-grounded-border bg-grounded-border/40 text-grounded-ink hover:brightness-125",
          )}
        >
          {submitting ? "Starting…" : "Run cycle now"}
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
