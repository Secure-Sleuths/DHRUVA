"use client";

/**
 * HuntTab (WO-U9c read + Hunt-write wiring) — threat-hunt findings + the saved
 * hypothesis library, with the closed-loop WRITE steps wired in.
 *
 * Reads: `GET /api/hunt/findings` (`getHuntFindings` — `require_role(admin,
 * senior_analyst)` + `require_license_feature("hunt")`) and `GET /api/hunt/library`
 * (`getHuntLibrary` — same role, NOT license-gated). Findings are shown worst-first
 * (priority glyph+label+color) with the OpenSearch hit count each matched.
 *
 * Writes (each mirrors src/api/routes/hunt.py EXACTLY; server re-checks):
 *   - Run cycle  → `POST /api/hunt/run` (admin+, require_admin). Kicks a background
 *     hunt cycle. Confirm-gated (a deliberate, tenant-wide job) — never auto-fires.
 *   - Confirm / dismiss a finding → `POST /api/hunt/review` (senior_analyst+).
 *     CONFIRMING auto-creates an incident AND indexes the finding to the KB
 *     server-side, so it is treated as irreversible and gets an explicit confirm
 *     dialog that says so. Dismiss is a lighter state change; both offer an
 *     OPTIONAL note (the server requires no reason).
 *   - Replay a hypothesis → `POST /api/hunt/library/{id}/replay` (senior_analyst+,
 *     NOT license-gated). A READ-ish action: re-runs the stored query and returns a
 *     hit count + sample events. It mutates nothing, so no confirm — its result is
 *     shown in a read-only dialog.
 *
 * RBAC is mirrored via `huntActionGate` (@/lib/rbac), fail-closed, NEVER wider than
 * the server (run-cycle stays admin-only; review/replay senior_analyst+). read_only
 * never reaches this tab (TAB_ACCESS.hunt is senior_analyst+).
 *
 * TIER GATE: a runtime 402/403 from the `hunt` gate on the findings call degrades
 * the whole surface to FeatureLockedState. Typed action errors: 402/403 → locked,
 * 409/404 → "changed, refreshing", else typed. States: loading / empty / error+retry
 * / locked; PollingStatus (30s, aborts on unmount). Fixtures gate behind
 * NEXT_PUBLIC_DHRUVA_FIXTURES (writes short-circuit to a synthetic success with NO
 * real mutation).
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Chip,
  Dialog,
  Panel,
  PollingStatus,
  SeverityBadge,
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
  getHuntFindings,
  getHuntLibrary,
  reviewHuntFinding,
  replayHypothesis,
  triggerHuntCycle,
} from "@/lib/api";
import { huntActionGate, type HuntActionGate } from "@/lib/rbac";
import { useAuth } from "@/lib/auth";
import { huntFindingState, huntPrioritySeverity } from "@/lib/hunt";
import { asBool, DASH, fmtDateTime, fmtInt } from "@/lib/format";
import { SEVERITY_ORDER } from "@/lib/severity";
import { cn, focusRing } from "@/lib/ui";
import type { TabProps } from "../tabRegistry";
import type {
  HuntFinding,
  HuntHypothesis,
  HuntReplayResult,
} from "@/lib/types";

const POLL_MS = 30_000;

function isLockError(e: unknown): boolean {
  return e instanceof ApiError && (e.status === 402 || e.status === 403);
}
function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : "Unknown error";
}

/** Is a finding still awaiting review (i.e. actionable)? */
function isOpenFinding(f: HuntFinding): boolean {
  const s = (f.status ?? "").toLowerCase();
  return s !== "confirmed" && s !== "dismissed" && s !== "reviewed" && !asBool(f.confirmed);
}

interface State {
  findings: HuntFinding[] | null;
  hypotheses: HuntHypothesis[] | null;
  error: string | null;
  locked: boolean;
  loading: boolean;
}

/** An in-flight review confirm: which action, on which finding. */
type ReviewKind = "confirm" | "dismiss";
type Pending =
  | { kind: "review"; action: ReviewKind; finding: HuntFinding }
  | { kind: "run" };
/** A transient result banner. */
type Flash = { tone: "ok" | "warn"; msg: string };
/** The replay flow state for one hypothesis (read-only result dialog). */
type ReplayState = {
  hypothesis: HuntHypothesis;
  loading: boolean;
  result: HuntReplayResult | null;
  error: string | null;
} | null;

/**
 * Which filter bucket a finding falls in (legacy `huntFilter`: hit/miss/
 * confirmed/dismissed). The hunt agent writes `status` = "hit" (the hypothesis
 * matched real events → actionable) or "miss" (query ran clean → not actionable)
 * on creation (`hunt_agent.py`), then review sets confirmed/dismissed. Hit and
 * miss are the primary triage signal, so they stay INDEPENDENTLY selectable
 * (the redesign had merged them into one "awaiting review" bucket). Any other
 * status → "other" (visible only under "All", matching legacy).
 */
type FindingBucket = "hit" | "miss" | "confirmed" | "dismissed";
function findingBucket(f: HuntFinding): FindingBucket | "other" {
  const s = (f.status ?? "").toLowerCase();
  if (asBool(f.confirmed) || s === "confirmed") return "confirmed";
  if (s === "dismissed") return "dismissed";
  if (s === "hit") return "hit";
  if (s === "miss") return "miss";
  return "other";
}

type HuntTimeWindow = "24h" | "7d" | "all";
const TIME_WINDOW_MS: Record<Exclude<HuntTimeWindow, "all">, number> = {
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
};
/** Keep a finding if it falls inside the window. Undated rows are never hidden. */
function withinWindow(f: HuntFinding, w: HuntTimeWindow, now: number): boolean {
  if (w === "all") return true;
  const t = +new Date(f.created_at);
  if (!t) return true;
  return now - t <= TIME_WINDOW_MS[w];
}

function sortFindingsWorstFirst(rows: readonly HuntFinding[]): HuntFinding[] {
  const rank = (f: HuntFinding) => SEVERITY_ORDER.indexOf(huntPrioritySeverity(f.priority));
  const recency = (f: HuntFinding) => +new Date(f.created_at) || 0;
  return [...rows].sort((a, b) => {
    const bySev = rank(a) - rank(b);
    if (bySev !== 0) return bySev;
    return recency(b) - recency(a);
  });
}

export function HuntTab(_props: TabProps) {
  const { role } = useAuth();
  const gate = huntActionGate(role);

  const [state, setState] = useState<State>({
    findings: null,
    hypotheses: null,
    error: null,
    locked: false,
    loading: true,
  });
  const [secondsAgo, setSecondsAgo] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  // ---- hunt write (run cycle / confirm / dismiss) --------------------------
  const [confirm, setConfirm] = useState<Pending | null>(null);
  const [note, setNote] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [flash, setFlash] = useState<Flash | null>(null);
  // ---- replay (read-only) --------------------------------------------------
  const [replay, setReplay] = useState<ReplayState>(null);

  const load = useCallback(async (manual: boolean) => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    if (manual) setRefreshing(true);
    try {
      const [findings, library] = await Promise.all([
        getHuntFindings({ limit: 100 }, ac.signal),
        getHuntLibrary({ limit: 100 }, ac.signal),
      ]);
      if (ac.signal.aborted) return;
      setState({
        findings: findings.findings,
        hypotheses: library.hypotheses,
        error: null,
        locked: false,
        loading: false,
      });
      setSecondsAgo(0);
    } catch (e) {
      if (ac.signal.aborted) return;
      if (isLockError(e)) {
        setState({ findings: null, hypotheses: null, error: null, locked: true, loading: false });
        return;
      }
      const msg = errMessage(e);
      setState((prev) =>
        prev.findings
          ? { ...prev, loading: false }
          : { findings: null, hypotheses: null, error: msg, locked: false, loading: false },
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

  const openReview = useCallback((action: ReviewKind, finding: HuntFinding) => {
    setActionError(null);
    setNote("");
    setConfirm({ kind: "review", action, finding });
  }, []);

  const openRun = useCallback(() => {
    setActionError(null);
    setConfirm({ kind: "run" });
  }, []);

  const closeConfirm = useCallback(() => {
    if (submitting) return; // don't let the dialog close mid-dispatch
    setConfirm(null);
    setActionError(null);
  }, [submitting]);

  /**
   * Run the confirmed write. Invoked ONLY from the confirm dialog's deliberate
   * click — never automatically. Fail-closed on 402/403 (locked), self-heal on
   * 409/404 (finding changed), typed otherwise.
   */
  const submitAction = useCallback(async () => {
    if (!confirm) return;
    setSubmitting(true);
    setActionError(null);
    try {
      if (confirm.kind === "run") {
        await triggerHuntCycle();
        setFlash({
          tone: "ok",
          msg: "Hunt cycle started in the background. New findings will appear here as the agent re-runs each saved hypothesis — refresh in a moment.",
        });
      } else {
        const { action, finding } = confirm;
        if (action === "confirm") {
          await reviewHuntFinding({
            finding_id: finding.id,
            status: "confirmed",
            confirmed: true,
            notes: note.trim() || undefined,
          });
          setFlash({
            tone: "ok",
            msg: `Confirmed the finding as a real threat. The server auto-created an incident from it and indexed it to the knowledge base.`,
          });
        } else {
          await reviewHuntFinding({
            finding_id: finding.id,
            status: "dismissed",
            confirmed: false,
            notes: note.trim() || undefined,
          });
          setFlash({ tone: "ok", msg: `Dismissed the finding. No incident is created.` });
        }
      }
      setConfirm(null);
      await load(true);
    } catch (e) {
      if (isLockError(e)) {
        setActionError(
          "Your role or license tier does not permit this action — the server denied it (this control mirrors the server and stays locked). Nothing changed.",
        );
      } else if (e instanceof ApiError && (e.status === 409 || e.status === 404)) {
        setActionError(
          "This finding changed since you loaded it — it may have already been reviewed. Refreshing the list.",
        );
        setConfirm(null);
        await load(true);
      } else if (e instanceof ApiError && e.status === 503) {
        setActionError(
          `The hunt agent is not available right now (${errMessage(e)}). Nothing changed — try again once it is back.`,
        );
      } else {
        setActionError(errMessage(e));
      }
    } finally {
      setSubmitting(false);
    }
  }, [confirm, note, load]);

  // ---- replay a hypothesis — read-only, no confirm -------------------------
  const runReplay = useCallback(async (h: HuntHypothesis) => {
    setReplay({ hypothesis: h, loading: true, result: null, error: null });
    try {
      const result = await replayHypothesis(h.id);
      setReplay({ hypothesis: h, loading: false, result, error: null });
    } catch (e) {
      let msg: string;
      if (isLockError(e)) {
        msg =
          "Re-running a hypothesis requires a senior analyst or higher — the server denied it (the control mirrors the server).";
      } else if (e instanceof ApiError && e.status === 404) {
        msg = "This hypothesis no longer exists — it may have been removed. Refresh to update the library.";
      } else if (e instanceof ApiError && e.status === 400) {
        msg = `The saved query was rejected as invalid or unsafe: ${errMessage(e)}.`;
      } else if (e instanceof ApiError && e.status === 503) {
        msg = "The hunt agent is not available right now — try the replay again once it is back.";
      } else {
        msg = errMessage(e);
      }
      setReplay({ hypothesis: h, loading: false, result: null, error: msg });
    }
  }, []);

  const { findings, hypotheses, error, locked, loading } = state;

  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PageHeading
          title="Threat hunting"
          sub="Proactive hunt findings and the re-runnable hypotheses the hunt agent has learned — worst-first, read like a lead. Confirm a finding to open an incident, or re-run a hypothesis to check for fresh hits."
        />
        <div className="mt-1 flex items-center gap-2">
          {!locked && (
            <PollingStatus
              secondsAgo={secondsAgo}
              refreshing={refreshing}
              onRefresh={() => load(true)}
            />
          )}
          {!locked && findings && (
            gate.canRunCycle ? (
              <ActionButton tone="neutral" onClick={openRun}>
                Run hunt cycle…
              </ActionButton>
            ) : (
              <LockedChip label="Run cycle · admin" title={gate.runLockNote} />
            )
          )}
        </div>
      </div>

      {locked ? (
        <FeatureLockedState feature="Threat hunting" tier="current" onUpgrade={onUpgrade} />
      ) : loading && !findings ? (
        <StatusState variant="loading" title="Loading hunt findings…" />
      ) : error && !findings ? (
        <StatusState
          variant="error"
          title="Couldn't load hunt findings"
          description={error}
          action={<Chip onClick={() => load(true)}>Retry</Chip>}
        />
      ) : findings ? (
        <div className="flex flex-col gap-3">
          <PostureNote gate={gate} />
          {flash && <FlashBanner flash={flash} onDismiss={() => setFlash(null)} />}
          <StatsTiles findings={findings} hypotheses={hypotheses ?? []} />
          <FindingsPanel findings={findings} gate={gate} onReview={openReview} />
          <LibraryPanel
            hypotheses={hypotheses ?? []}
            gate={gate}
            onReplay={runReplay}
            replayingId={replay?.loading ? replay.hypothesis.id : null}
          />
        </div>
      ) : null}

      <ConfirmActionDialog
        pending={confirm}
        note={note}
        onNote={setNote}
        submitting={submitting}
        error={actionError}
        onConfirm={submitAction}
        onClose={closeConfirm}
      />

      <ReplayResultDialog replay={replay} onClose={() => setReplay(null)} />
    </>
  );
}

function PostureNote({ gate }: { gate: HuntActionGate }) {
  return (
    <div className="rounded-lg border border-line bg-panel2 px-3.5 py-2.5 text-kbd text-dim2">
      <b>Confirming</b> a finding marks it a real threat and{" "}
      <b>auto-creates an incident</b> from it (and indexes it to the knowledge
      base) — it is behind an explicit confirm. <b>Dismissing</b> closes it with an
      optional note; no incident is created. <b>Replaying</b> a hypothesis re-runs
      its saved query and shows the hit count — it changes nothing. Running a full{" "}
      <b>hunt cycle</b> is admin-only.
      {(gate.reviewLockNote || gate.runLockNote) && (
        <span className="mt-1 block text-dim2">
          {gate.reviewLockNote ?? gate.runLockNote}
        </span>
      )}
    </div>
  );
}

function FlashBanner({ flash, onDismiss }: { flash: Flash; onDismiss: () => void }) {
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
  findings,
  hypotheses,
}: {
  findings: HuntFinding[];
  hypotheses: HuntHypothesis[];
}) {
  const confirmed = findings.filter(
    (f) => asBool(f.confirmed) || (f.status ?? "").toLowerCase() === "confirmed",
  ).length;
  const open = findings.filter(isOpenFinding).length;
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
      <Tile label="Findings" value={fmtInt(findings.length)} sub="in view" />
      <Tile
        label="Confirmed threats"
        value={fmtInt(confirmed)}
        sub="analyst-verified"
        valueSeverity={confirmed > 0 ? "crit" : undefined}
      />
      <Tile
        label="Awaiting review"
        value={fmtInt(open)}
        sub="open findings"
        valueSeverity={open > 0 ? "med" : undefined}
      />
      <Tile
        label="Saved hypotheses"
        value={fmtInt(hypotheses.length)}
        sub="re-runnable queries"
      />
    </div>
  );
}

/**
 * A subtle segmented chip-row for optional list filtering — matches the WO-U1
 * Chip aesthetic (active = cite, rest = default). Read-side refinement only; the
 * "all" default preserves current behaviour and never replaces the worst-first
 * order.
 */
function FilterChipRow({
  label,
  options,
  value,
  onChange,
}: {
  label: string;
  options: { value: string; label: string; count?: number }[];
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

function FindingsPanel({
  findings,
  gate,
  onReview,
}: {
  findings: HuntFinding[];
  gate: HuntActionGate;
  onReview: (action: ReviewKind, f: HuntFinding) => void;
}) {
  // OPTIONAL status + time filters (restores legacy `huntFilter` + time-range).
  // CLIENT-SIDE: the findings endpoint has no time-window param and the "awaiting
  // review" bucket is compound (hit|miss|open), so both filters narrow the loaded
  // set here. "all"/"all" = default = unchanged behaviour.
  const [statusFilter, setStatusFilter] = useState<"all" | FindingBucket>("all");
  const [timeFilter, setTimeFilter] = useState<HuntTimeWindow>("all");

  const sorted = sortFindingsWorstFirst(findings);
  const now = Date.now();
  const rows = sorted.filter(
    (f) =>
      (statusFilter === "all" || findingBucket(f) === statusFilter) &&
      withinWindow(f, timeFilter, now),
  );

  const bucketCount = (b: FindingBucket) =>
    findings.filter((f) => findingBucket(f) === b).length;
  const statusOptions = [
    { value: "all", label: "All", count: findings.length },
    { value: "hit", label: "Hit", count: bucketCount("hit") },
    { value: "miss", label: "Miss", count: bucketCount("miss") },
    { value: "confirmed", label: "Confirmed", count: bucketCount("confirmed") },
    { value: "dismissed", label: "Dismissed", count: bucketCount("dismissed") },
  ];
  const timeOptions = [
    { value: "24h", label: "24h" },
    { value: "7d", label: "7d" },
    { value: "all", label: "All time" },
  ];
  const filtered = statusFilter !== "all" || timeFilter !== "all";

  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-3">
        <div className="text-title text-ink">Hunt findings</div>
        <span className="text-kbd text-dim2">
          {filtered ? `${rows.length} of ${findings.length} shown` : `${findings.length} shown`}
        </span>
      </div>
      {findings.length > 0 && (
        <div className="flex flex-col gap-2 px-4 pt-2.5">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
            <FilterChipRow
              label="Status"
              options={statusOptions}
              value={statusFilter}
              onChange={(v) => setStatusFilter(v as "all" | FindingBucket)}
            />
            <FilterChipRow
              label="Window"
              options={timeOptions}
              value={timeFilter}
              onChange={(v) => setTimeFilter(v as HuntTimeWindow)}
            />
          </div>
          <div className="text-kbd text-dim2">
            Filters refine the most recent findings loaded on this page (up to 100).
          </div>
        </div>
      )}
      {findings.length === 0 ? (
        <div className="px-4 pb-4 pt-2 text-data text-dim2">
          No hunt findings recorded yet. Findings appear here after a hunt cycle
          matches a hypothesis against the alert corpus.
        </div>
      ) : rows.length === 0 ? (
        <div className="flex flex-wrap items-center gap-2 px-4 pb-4 pt-3 text-data text-dim2">
          <span>No findings match this filter.</span>
          <Chip
            onClick={() => {
              setStatusFilter("all");
              setTimeFilter("all");
            }}
          >
            Clear filters
          </Chip>
        </div>
      ) : (
        <Table className="mt-2">
          <THead>
            <TR>
              <TH>Priority</TH>
              <TH>Hypothesis</TH>
              <TH>MITRE</TH>
              <TH className="text-right">Hits</TH>
              <TH>State</TH>
              <TH>Found</TH>
              <TH>Review</TH>
            </TR>
          </THead>
          <TBody>
            {rows.map((f) => {
              const st = huntFindingState(f);
              const open = isOpenFinding(f);
              return (
                <TR key={f.id}>
                  <TD>
                    <SeverityBadge severity={huntPrioritySeverity(f.priority)} />
                  </TD>
                  <TD>
                    <div className="max-w-[520px] text-ink">{f.hypothesis}</div>
                    {f.results_summary && (
                      <div className="max-w-[520px] text-kbd text-dim2">
                        {f.results_summary}
                      </div>
                    )}
                  </TD>
                  <TD>
                    {f.mitre_technique ? (
                      <span className="font-mono text-data text-dim">{f.mitre_technique}</span>
                    ) : (
                      <span className="text-dim2">{DASH}</span>
                    )}
                  </TD>
                  <TD mono className="text-right">
                    {fmtInt(f.result_count)}
                  </TD>
                  <TD>
                    <span className={`text-meta font-semibold ${st.className}`}>{st.label}</span>
                    {f.analyst_notes && (
                      <div className="max-w-[320px] text-kbd text-dim2">{f.analyst_notes}</div>
                    )}
                  </TD>
                  <TD>{fmtDateTime(f.created_at)}</TD>
                  <TD>
                    {!open ? (
                      <span className="text-kbd text-dim2">Reviewed</span>
                    ) : gate.canReview ? (
                      <div className="flex flex-wrap gap-1.5">
                        <ActionButton tone="ok" onClick={() => onReview("confirm", f)}>
                          Confirm…
                        </ActionButton>
                        <ActionButton tone="neutral" onClick={() => onReview("dismiss", f)}>
                          Dismiss…
                        </ActionButton>
                      </div>
                    ) : (
                      <LockedChip
                        label="Review · senior_analyst+"
                        title={gate.reviewLockNote}
                      />
                    )}
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

function LibraryPanel({
  hypotheses,
  gate,
  onReplay,
  replayingId,
}: {
  hypotheses: HuntHypothesis[];
  gate: HuntActionGate;
  onReplay: (h: HuntHypothesis) => void;
  replayingId: string | null;
}) {
  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-3">
        <div className="text-title text-ink">Hypothesis library</div>
        <span className="text-kbd text-dim2">{hypotheses.length} saved</span>
      </div>
      <div className="px-4 text-kbd text-dim2">
        The re-runnable hunt queries the agent has accumulated — how often each has
        surfaced a finding is the loop compounding. Replay re-runs the saved query
        now and reports the hit count; it changes nothing.
      </div>
      {hypotheses.length === 0 ? (
        <div className="px-4 pb-4 pt-2 text-data text-dim2">
          No saved hypotheses yet.
        </div>
      ) : (
        <Table className="mt-2">
          <THead>
            <TR>
              <TH>Hypothesis</TH>
              <TH>MITRE</TH>
              <TH className="text-right">Successes</TH>
              <TH>Last hit</TH>
              <TH>Tags</TH>
              <TH>Replay</TH>
            </TR>
          </THead>
          <TBody>
            {hypotheses.map((h) => (
              <TR key={h.id}>
                <TD>
                  <div className="max-w-[440px] text-ink">{h.hypothesis}</div>
                </TD>
                <TD>
                  {h.mitre_technique ? (
                    <span className="font-mono text-data text-dim">{h.mitre_technique}</span>
                  ) : (
                    <span className="text-dim2">{DASH}</span>
                  )}
                </TD>
                <TD mono className="text-right">
                  {fmtInt(h.success_count)}
                </TD>
                <TD>{fmtDateTime(h.last_success_at)}</TD>
                <TD>
                  {h.tags.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {h.tags.map((t) => (
                        <Chip key={t}>{t}</Chip>
                      ))}
                    </div>
                  ) : (
                    <span className="text-dim2">{DASH}</span>
                  )}
                </TD>
                <TD>
                  {gate.canReplay ? (
                    <ActionButton
                      tone="neutral"
                      disabled={replayingId === h.id}
                      onClick={() => onReplay(h)}
                    >
                      {replayingId === h.id ? "Running…" : "Replay"}
                    </ActionButton>
                  ) : (
                    <LockedChip label="Replay · senior_analyst+" title={gate.reviewLockNote} />
                  )}
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      )}
    </Panel>
  );
}

function ActionButton({
  tone,
  onClick,
  disabled,
  children,
}: {
  tone: "ok" | "warn" | "neutral";
  onClick: () => void;
  disabled?: boolean;
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
      disabled={disabled}
      className={cn(
        "rounded-md border px-2.5 py-1 text-meta",
        disabled ? "cursor-not-allowed opacity-60" : "cursor-pointer",
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
 * The confirm-to-act dialog. For "confirm" it prominently states the irreversible
 * side effect (auto-creates an incident + indexes to the KB) before dispatch; for
 * "dismiss" it is lighter (a state change, no incident). Both offer an OPTIONAL
 * note (the server requires none). For "run" it explains the background cycle. The
 * primary button is the only path that fires the write.
 */
function ConfirmActionDialog({
  pending,
  note,
  onNote,
  submitting,
  error,
  onConfirm,
  onClose,
}: {
  pending: Pending | null;
  note: string;
  onNote: (v: string) => void;
  submitting: boolean;
  error: string | null;
  onConfirm: () => void;
  onClose: () => void;
}) {
  if (!pending) return null;

  const isRun = pending.kind === "run";
  const isConfirm = pending.kind === "review" && pending.action === "confirm";
  const title = isRun
    ? "Run a hunt cycle"
    : isConfirm
      ? "Confirm finding as a threat"
      : "Dismiss finding";

  const cta = isRun
    ? submitting
      ? "Starting…"
      : "Run cycle now"
    : isConfirm
      ? submitting
        ? "Confirming…"
        : "Confirm & create incident"
      : submitting
        ? "Dismissing…"
        : "Dismiss now";

  return (
    <Dialog open onClose={onClose} maxWidth={560} title={title}>
      <p className="text-data text-dim">
        {isRun && (
          <>
            This kicks a <b>background hunt cycle</b> for this tenant — the agent
            re-runs every saved hypothesis against the alert corpus and records any
            new findings. It is deliberate and admin-only. Nothing runs until you
            confirm.
          </>
        )}
        {pending.kind === "review" && isConfirm && (
          <>
            This marks the finding a <b>real threat</b>. The server then{" "}
            <b>auto-creates an incident</b> from it and <b>indexes it to the
            knowledge base</b> — that incident creation is not automatically
            reversible from here. Nothing happens until you confirm.
          </>
        )}
        {pending.kind === "review" && !isConfirm && (
          <>
            This closes the finding as <b>not a threat</b>. No incident is created.
            A note is optional and audited.
          </>
        )}
      </p>

      {pending.kind === "review" && (
        <div className="mt-3">
          <label htmlFor="hunt-review-note" className="mb-1 block text-kbd text-dim2">
            Note (optional — audited)
          </label>
          <textarea
            id="hunt-review-note"
            value={note}
            onChange={(e) => onNote(e.target.value)}
            rows={3}
            disabled={submitting}
            placeholder={
              isConfirm
                ? "Why is this a real threat? (optional)"
                : "Why is this benign? (optional)"
            }
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
              : isConfirm
                ? "cursor-pointer border-grounded-border bg-grounded-border/40 text-grounded-ink hover:brightness-125"
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
 * The replay result dialog. `POST /api/hunt/library/{id}/replay` re-runs the saved
 * query and returns the current hit count plus a few sample event bodies — a
 * READ-only check that changes nothing. Sample events are real alert documents
 * (the analyst UI shows real values; the anonymization boundary is the LLM, not
 * this surface); they are shown compactly and scroll within their own container.
 */
function ReplayResultDialog({
  replay,
  onClose,
}: {
  replay: ReplayState;
  onClose: () => void;
}) {
  if (!replay) return null;
  return (
    <Dialog open onClose={onClose} maxWidth={620} title="Replay hypothesis">
      <p className="text-data text-dim">
        A read-only re-run of the saved query{" "}
        <span className="text-ink">“{replay.hypothesis.hypothesis}”</span> against
        the current alert corpus (tenant-scoped). It reports the hit count and a few
        sample events — it changes nothing and creates no finding.
      </p>

      {replay.loading ? (
        <div className="mt-3 text-data text-dim2">Running the saved query…</div>
      ) : replay.error ? (
        <p className="mt-3 text-data text-sev-crit" role="alert">
          {replay.error}
        </p>
      ) : replay.result ? (
        <div className="mt-3 flex flex-col gap-2">
          <div className="rounded-lg border border-line bg-panel2 px-3.5 py-3 text-data">
            <span className="text-kpi tabular text-ink">
              {fmtInt(replay.result.hit_count)}
            </span>{" "}
            <span className="text-dim2">
              current hit{replay.result.hit_count === 1 ? "" : "s"} in{" "}
              <span className="font-mono">{replay.result.query_index ?? "the alert index"}</span>
            </span>
          </div>
          {replay.result.sample_hits.length > 0 ? (
            <div>
              <div className="mb-1 text-kbd uppercase tracking-wider text-dim2">
                {replay.result.sample_hits.length} sample event
                {replay.result.sample_hits.length === 1 ? "" : "s"}
              </div>
              <pre className="max-h-72 overflow-auto rounded-md border border-line bg-field p-2.5 font-mono text-[11.5px] leading-relaxed text-dim">
                {JSON.stringify(replay.result.sample_hits, null, 2)}
              </pre>
            </div>
          ) : (
            <div className="text-kbd text-dim2">
              No sample events returned for this run.
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
