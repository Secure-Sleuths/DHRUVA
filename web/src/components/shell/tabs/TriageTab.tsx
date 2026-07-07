"use client";

/**
 * TriageTab (WO-U5) — the worst-first glass-box queue.
 *
 * Translates the approved mockup's `tTriage()`: a worst-first table where every
 * row pairs the AI verdict with its evidence + confidence and opens (master →
 * detail, in-tab) to THAT decision's glass-box case — verdict + confidence +
 * risk math + reasoning + provenance + the field-level anonymization boundary +
 * the reason-required review form — NOT the grouped Incidents list. It reuses the
 * shared `<GlassBoxAlertCard>` the Incidents case view uses (WO-U5 deep-link).
 * Composes the WO-U1 design system (SeverityBadge, ConfidenceBar, Table, Panel,
 * StatusState, PollingStatus, Chip) — no bespoke primitives, no hard-coded hexes.
 *
 * Data: binds to `GET /api/triage/decisions?sort=risk` (worst-first,
 * risk_score DESC) via `@/lib/api.ts::getTriageDecisions`, reading the WO-B1
 * flattened first-class fields. The product polls (no websocket) — a
 * PollingStatus shows the age of the last refresh + a manual refresh.
 *
 * RBAC: the tab is analyst+ (the shell hides it from read_only via TAB_ACCESS).
 * The queue itself is read-only; the ONLY write is the reason-required verdict
 * review inside the decision case, gated identically to the Incidents case view
 * (analyst+; overriding an existing human verdict is admin-only per WO-B10) via
 * the shared card. The "Ask copilot" launcher is provided by the shell on Triage.
 */

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import {
  Chip,
  ConfidenceBar,
  Panel,
  PollingStatus,
  SeverityBadge,
  StatusState,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
} from "@/components";
import { PageHeading } from "../PageHeading";
import {
  getDecisionAuditTrail,
  getPendingReview,
  getTriageDecisionsFiltered,
  ApiError,
} from "@/lib/api";
import { SEVERITY, riskSeverity, severityLabel } from "@/lib/severity";
import { verdictPresentation } from "@/lib/triage";
import { cn, focusRing } from "@/lib/ui";
import {
  GlassBoxAlertCard,
  errMessage,
  formatWhen,
} from "../GlassBoxCase";
import type { TabProps } from "../tabRegistry";
import type {
  GlassBox,
  IncidentAlert,
  TriageDecision,
  TriageVerdict,
} from "@/lib/types";

/** Auto-poll cadence (ms). The product polls; there is no push channel. */
const POLL_MS = 30_000;

/**
 * Restored segmented filters (parity gap ②) — OPTIONAL refinement over the
 * worst-first queue. Default = "all"/"all" = no filter = the current worst-first
 * behavior. Both are applied SERVER-SIDE (verdict + since on
 * `/api/triage/decisions`) so `sort=risk` still orders the filtered set.
 */
// `open` is a pseudo-verdict = the legacy "Pending" filter: the human-review
// backlog (escalated + no human verdict yet) from `GET /api/triage/pending-review`.
// It sits in the same chip row as the real verdicts but drives a DIFFERENT data
// source (see `load`); the other values map to a server-side `verdict` param on
// `/api/triage/decisions` with `sort=risk` preserved.
type VerdictFilter = "all" | "open" | "anomaly" | TriageVerdict;
type TimeFilter = "all" | "24h" | "7d";

/**
 * The Triage filter chips, in the legacy row order: All / Open / then the 4
 * canonical verdicts. "Open" restores the legacy "Pending" filter as an explicit
 * chip (WO-U13 first shipped it as a separate view toggle; consolidated here into
 * the single filter row to match the legacy shape).
 */
const VERDICT_FILTERS: { id: VerdictFilter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "open", label: "Open" },
  { id: "true_positive", label: "True positive" },
  { id: "needs_investigation", label: "Needs investigation" },
  { id: "false_positive", label: "False positive" },
  { id: "auto_close", label: "Auto-closed" },
  { id: "anomaly", label: "Anomaly" },
];

const TIME_FILTERS: { id: TimeFilter; label: string }[] = [
  { id: "24h", label: "24h" },
  { id: "7d", label: "7d" },
  { id: "all", label: "All time" },
];

/** ISO-8601 lower bound for a time filter, or undefined for "all" (no bound). */
function sinceForTimeFilter(t: TimeFilter): string | undefined {
  if (t === "all") return undefined;
  const ms = t === "24h" ? 24 * 3_600_000 : 7 * 24 * 3_600_000;
  return new Date(Date.now() - ms).toISOString();
}

/**
 * Normalize a pending-review row to the shape the row/case renderers expect.
 * `/pending-review` returns RAW decision dicts (not server-flattened like
 * `/decisions`), so `technique_ids`/`tactic_ids` may be absent — default them to
 * `[]` so the shared decision-card renderer never dereferences undefined. Host
 * and MITRE still surface in the glass-box body via `enrichment_summary`. Then
 * present the backlog worst-first (risk_score DESC) to match the queue's ordering
 * discipline — presentation only, no server reorder.
 */
function normalizePending(rows: TriageDecision[]): TriageDecision[] {
  return rows
    .map((d) => ({
      ...d,
      technique_ids: Array.isArray(d.technique_ids) ? d.technique_ids : [],
      tactic_ids: Array.isArray(d.tactic_ids) ? d.tactic_ids : [],
    }))
    .sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0));
}

interface QueueState {
  decisions: TriageDecision[] | null;
  total: number;
  error: string | null;
  loading: boolean;
}

export function TriageTab({ navParam }: TabProps) {
  const [state, setState] = useState<QueueState>({
    decisions: null,
    total: 0,
    error: null,
    loading: true,
  });
  const [secondsAgo, setSecondsAgo] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  // Filter chips (parity gap ② + the legacy "Open"/Pending chip). Default = no filter.
  const [verdictFilter, setVerdictFilter] = useState<VerdictFilter>("all");
  const [timeFilter, setTimeFilter] = useState<TimeFilter>("all");
  // Deep-link: opening a triage row selects that decision's glass-box case.
  const [selectedId, setSelectedId] = useState<string | null>(navParam ?? null);
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async (manual: boolean) => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    if (manual) setRefreshing(true);
    try {
      let decisions: TriageDecision[];
      let total: number;
      if (verdictFilter === "open") {
        // "Open" = the human-review backlog (escalated + no human verdict yet).
        // Its own endpoint takes no verdict/time params. Rows are normalized
        // (default array fields) + presented worst-first.
        const res = await getPendingReview(ac.signal);
        if (ac.signal.aborted) return;
        decisions = normalizePending(res.pending);
        total = res.count;
      } else {
        // Worst-first queue → sort=risk (risk_score DESC) ALWAYS. The optional
        // verdict / anomaly / time filters narrow the set server-side; the sort
        // is unchanged, so the filtered rows stay ordered highest-risk-first.
        const isAnomaly = verdictFilter === "anomaly";
        const res = await getTriageDecisionsFiltered(
          {
            sort: "risk",
            // "all" and "anomaly" are not real verdicts → no verdict param.
            verdict:
              verdictFilter === "all" || isAnomaly ? undefined : verdictFilter,
            anomaly: isAnomaly || undefined,
            // Widen the server window for anomaly so its server-side filter
            // isn't starved by the default 200-row page (anomalies boost risk,
            // so the worst-first window catches essentially all of them).
            limit: isAnomaly ? 1000 : undefined,
            since: sinceForTimeFilter(timeFilter),
          },
          ac.signal,
        );
        if (ac.signal.aborted) return;
        decisions = res.decisions;
        total = res.total;
      }
      setState({
        decisions,
        total,
        error: null,
        loading: false,
      });
      setSecondsAgo(0);
    } catch (e) {
      if (ac.signal.aborted) return;
      const msg =
        e instanceof ApiError
          ? e.message
          : e instanceof Error
            ? e.message
            : "Unknown error";
      // Keep any previously-loaded rows on a background poll failure; only fall
      // to the full error state when we have nothing to show yet.
      setState((prev) =>
        prev.decisions
          ? { ...prev, loading: false }
          : { decisions: null, total: 0, error: msg, loading: false },
      );
    } finally {
      if (!ac.signal.aborted) setRefreshing(false);
    }
  }, [verdictFilter, timeFilter]);

  // Initial fetch + auto-poll. Re-runs when a filter changes (load identity
  // changes) → the queue refetches server-side with the new filter.
  useEffect(() => {
    load(false);
    const poll = setInterval(() => load(false), POLL_MS);
    return () => {
      clearInterval(poll);
      abortRef.current?.abort();
    };
  }, [load]);

  // "refreshed Ns ago" ticker.
  useEffect(() => {
    const t = setInterval(() => setSecondsAgo((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, []);

  // Follow a later deep-link (navParam changing while mounted).
  useEffect(() => {
    if (navParam) setSelectedId(navParam);
  }, [navParam]);

  const { decisions, error, loading } = state;
  const filtersActive = verdictFilter !== "all" || timeFilter !== "all";
  const clearFilters = () => {
    setVerdictFilter("all");
    setTimeFilter("all");
  };

  // Master → detail: opening a row shows THAT decision's glass-box case (the
  // decision's own verdict/reasoning/anonymized_fields + its audit-trail
  // glass_box), NOT the grouped Incidents list.
  const selectedDecision = selectedId
    ? decisions?.find((d) => d.id === selectedId) ?? null
    : null;

  if (selectedId) {
    return (
      <DecisionCaseView
        decisionId={selectedId}
        decision={selectedDecision}
        onBack={() => setSelectedId(null)}
        onReload={() => load(true)}
      />
    );
  }

  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PageHeading
          title="Triage"
          sub="Worst-first · the AI verdict always pairs with its evidence + confidence. Use “Ask copilot” for a grounded second opinion."
        />
        <PollingStatus
          className="mt-1"
          secondsAgo={secondsAgo}
          refreshing={refreshing}
          onRefresh={() => load(true)}
        />
      </div>

      <TriageFilterBar
        verdict={verdictFilter}
        time={timeFilter}
        onVerdict={setVerdictFilter}
        onTime={setTimeFilter}
      />

      {loading && !decisions ? (
        <StatusState
          variant="loading"
          title={
            verdictFilter === "open"
              ? "Loading open alerts (awaiting review)…"
              : "Loading the triage queue…"
          }
        />
      ) : error && !decisions ? (
        <StatusState
          variant="error"
          title={
            verdictFilter === "open"
              ? "Couldn't load open alerts"
              : "Couldn't load the triage queue"
          }
          description={error}
          action={<Chip onClick={() => load(true)}>Retry</Chip>}
        />
      ) : decisions && decisions.length === 0 ? (
        verdictFilter === "open" ? (
          <StatusState
            variant="empty"
            title="No open alerts"
            description="No decision is currently escalated and waiting on a human verdict."
          />
        ) : filtersActive ? (
          <StatusState
            variant="empty"
            title="No alerts match these filters"
            description="No decision in the worst-first queue matches the selected verdict / time window. Clear the filters to see the full queue."
            action={<Chip onClick={clearFilters}>Clear filters</Chip>}
          />
        ) : (
          <StatusState
            variant="empty"
            title="No alerts in the queue"
            description="Nothing is waiting for triage right now."
          />
        )
      ) : (
        <Panel className="overflow-hidden">
          <Table>
            <THead>
              <TR>
                <TH className="w-8" aria-label="Severity" />
                <TH>Alert</TH>
                <TH>Host</TH>
                <TH>Rule</TH>
                <TH>AI verdict</TH>
                <TH>Confidence</TH>
                <TH>Risk</TH>
                <TH className="w-16" aria-label="Open" />
              </TR>
            </THead>
            <TBody>
              {decisions!.map((d) => (
                <TriageRow key={d.id} decision={d} onOpen={() => setSelectedId(d.id)} />
              ))}
            </TBody>
          </Table>
        </Panel>
      )}

      <div className="mt-2 text-kbd text-dim2">
        {verdictFilter === "open" ? (
          <>
            Open lists the human-review backlog — decisions the AI escalated that
            still have no human verdict yet. Selecting another chip returns to the
            worst-first queue.{" "}
          </>
        ) : verdictFilter === "anomaly" ? (
          <>
            Anomaly shows alerts flagged as a behavioral/baseline anomaly
            (filtered server-side); the time window still applies.{" "}
          </>
        ) : (
          <>
            Verdict and time filters refine the worst-first queue server-side —
            they narrow it, never reorder it.{" "}
          </>
        )}
        🔒 Changing a verdict requires a reason (audit trail). Confidence uses a
        neutral ramp — red is reserved for severity only, so color never carries
        meaning alone.
      </div>
    </>
  );
}

// ---- restored segmented filter bar (parity gap ②) ---------------------------
/**
 * OPTIONAL refinement over the worst-first queue: a subtle chip-row of two
 * segmented groups (AI verdict + time window). It NEVER changes the sort — the
 * queue stays `sort=risk` (worst-first) and these only narrow which rows the
 * server returns. Default = All / All time = the unfiltered worst-first queue.
 * Reuses the WO-U1 `Chip` primitive with the selected="cite" convention the
 * incident case sub-tabs already use — no bespoke control.
 */
function FilterChip<T extends string>({
  id,
  active,
  onSelect,
  children,
}: {
  id: T;
  active: T;
  onSelect: (v: T) => void;
  children: ReactNode;
}) {
  const selected = active === id;
  return (
    <Chip
      variant={selected ? "cite" : "default"}
      onClick={() => onSelect(id)}
      aria-label={`Filter: ${String(children)}${selected ? " (selected)" : ""}`}
    >
      {children}
    </Chip>
  );
}

function TriageFilterBar({
  verdict,
  time,
  onVerdict,
  onTime,
}: {
  verdict: VerdictFilter;
  time: TimeFilter;
  onVerdict: (v: VerdictFilter) => void;
  onTime: (v: TimeFilter) => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
      <div
        className="flex flex-wrap items-center gap-1.5"
        role="group"
        aria-label="Filter alerts"
      >
        <span className="text-micro uppercase tracking-wide text-dim2">
          Filter
        </span>
        {VERDICT_FILTERS.map((v) => (
          <FilterChip key={v.id} id={v.id} active={verdict} onSelect={onVerdict}>
            {v.label}
          </FilterChip>
        ))}
      </div>
      {/* Time window applies to the verdict filters only — the "Open" backlog
          endpoint takes no params, so it's hidden when Open is selected. */}
      {verdict !== "open" && (
        <div
          className="flex flex-wrap items-center gap-1.5"
          role="group"
          aria-label="Filter by time window"
        >
          <span className="text-micro uppercase tracking-wide text-dim2">
            Time
          </span>
          {TIME_FILTERS.map((t) => (
            <FilterChip key={t.id} id={t.id} active={time} onSelect={onTime}>
              {t.label}
            </FilterChip>
          ))}
        </div>
      )}
    </div>
  );
}

// ---- one queue row ----------------------------------------------------------

function TriageRow({
  decision: d,
  onOpen,
}: {
  decision: TriageDecision;
  onOpen: () => void;
}) {
  const sev = riskSeverity(d.risk_score);
  const verdict = verdictPresentation(String(d.verdict));
  const title = d.rule_description ?? `Alert ${d.id}`;

  // "open ›" → THAT decision's glass-box case (in-tab master→detail), NOT the
  // grouped Incidents list. The decision id keys the audit-trail glass_box.
  return (
    <TR onClick={onOpen} aria-label={`Open glass-box case for ${title} (${d.id})`}>
      <TD>
        <SeverityBadge severity={sev} glyphOnly aria-label={severityLabel(sev)} />
      </TD>
      <TD>
        <div>{title}</div>
        <div className="font-mono text-kbd text-dim2">{d.id}</div>
      </TD>
      <TD mono>{d.host ?? <span className="text-dim2">—</span>}</TD>
      <TD mono>
        {d.rule_id != null ? d.rule_id : <span className="text-dim2">—</span>}
      </TD>
      <TD>
        <span
          className={cn(
            "inline-flex items-center gap-1 text-[12px] font-semibold",
            verdict.className,
          )}
        >
          <span aria-hidden="true">{verdict.glyph}</span>
          <span>{verdict.label}</span>
        </span>
      </TD>
      <TD>
        <ConfidenceBar value={d.confidence} width={72} />
      </TD>
      <TD mono className={cn("font-bold", SEVERITY[sev].textClass)}>
        {d.risk_score}
      </TD>
      <TD className="text-kbd text-dim2">open ›</TD>
    </TR>
  );
}

// ===================== DECISION GLASS-BOX CASE ===============================
/**
 * The decision glass-box case opened from a triage row (WO-U5 deep-link). A
 * triage decision IS an `agent_decisions` row — the same entity the Incidents
 * case view calls a "member alert" — so this builds an `IncidentAlert` from the
 * decision (verdict/confidence/risk/reasoning/host/techniques/anonymized_fields)
 * plus its audit-trail `glass_box` (risk math + provenance), and renders the
 * SAME `<GlassBoxAlertCard>` the Incidents case uses. The reason-required review
 * form + RBAC gate (analyst+; existing-verdict override = admin per WO-B10) are
 * identical, living in the shared card. NOT the grouped Incidents list.
 */
function DecisionCaseView({
  decisionId,
  decision,
  onBack,
  onReload,
}: {
  decisionId: string;
  decision: TriageDecision | null;
  onBack: () => void;
  onReload: () => void;
}) {
  const [glassBox, setGlassBox] = useState<GlassBox | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const loadTrail = useCallback(async () => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setLoading(true);
    setError(null);
    try {
      const res = await getDecisionAuditTrail(decisionId, ac.signal);
      if (ac.signal.aborted) return;
      setGlassBox(res.glass_box ?? null);
    } catch (e) {
      if (ac.signal.aborted) return;
      // No audit trail for this decision → 404. That's not an error: render the
      // case from the decision's own fields with an honest empty glass_box (the
      // card shows "not recorded" for the math/provenance — never fabricated).
      if (e instanceof ApiError && e.status === 404) {
        setGlassBox(null);
      } else {
        setError(errMessage(e));
      }
    } finally {
      if (!ac.signal.aborted) setLoading(false);
    }
  }, [decisionId]);

  useEffect(() => {
    loadTrail();
    return () => abortRef.current?.abort();
  }, [loadTrail]);

  const backButton = (
    <button
      type="button"
      onClick={onBack}
      className={cn(
        "mb-3 inline-flex items-center gap-1 rounded-md border border-line bg-field px-2 py-1 text-kbd text-ink hover:bg-hover",
        focusRing,
      )}
    >
      ‹ Triage
    </button>
  );

  // The decision may not be in the current (polled) queue slice — surface that
  // honestly rather than fabricating a case.
  if (!decision) {
    return (
      <>
        {backButton}
        {loading ? (
          <StatusState variant="loading" title="Loading the decision…" />
        ) : (
          <StatusState
            variant="empty"
            title="Decision not in the current queue"
            description={`Decision ${decisionId} isn't in the current triage slice (it may have aged out or been re-sorted). Go back to the queue and reopen it.`}
          />
        )}
      </>
    );
  }

  const sev = riskSeverity(decision.risk_score);
  const alert: IncidentAlert = {
    id: decision.id,
    rule_id: decision.rule_id,
    rule_description: decision.rule_description,
    agent_type: "triage",
    verdict: decision.verdict,
    confidence: decision.confidence,
    risk_score: decision.risk_score,
    reasoning: decision.reasoning ?? null,
    enrichment_summary:
      decision.enrichment_summary ??
      JSON.stringify({
        agent_name: decision.host,
        src_ip: decision.src_ip,
        rule_mitre_techniques: decision.technique_ids,
        rule_mitre_tactics: decision.tactic_ids,
      }),
    human_verdict: decision.human_verdict ?? null,
    created_at: decision.created_at,
    glass_box: glassBox ?? undefined,
    anonymized_fields: decision.anonymized_fields,
    // AI recommended next-steps (legacy "Recommended Actions") — rendered by the
    // glass-box card's RecommendedActionsExpander.
    actions_taken: decision.actions_taken ?? null,
    // AIS2 grounding self-check — carried through so the glass-box card can show
    // the low/medium flag near confidence. Flag-only / decorative.
    grounding: decision.grounding,
  };

  return (
    <>
      {backButton}
      <Panel className="p-4">
        {/* case header */}
        <div className="mb-1.5 flex flex-wrap items-center gap-2.5">
          <Chip mono aria-label={`decision id ${decision.id}`}>
            {decision.id}
          </Chip>
          <SeverityBadge severity={sev} />
          {decision.host && (
            <span className="font-mono text-kbd text-dim">{decision.host}</span>
          )}
          <span className="text-kbd text-dim2">
            {formatWhen(decision.created_at)}
          </span>
          {decision.technique_ids.map((t) => (
            <Chip key={t} mono>
              {t}
            </Chip>
          ))}
        </div>
        <div className="text-title font-semibold">
          {decision.rule_description ?? `Alert ${decision.id}`}
        </div>
        <div className="mb-3 text-kbd text-dim2">
          One AI decision · glass-box — the risk math, the AI&apos;s reasoning,
          its provenance, and what it saw vs what you see.
        </div>

        {loading && !glassBox ? (
          <StatusState variant="loading" title="Loading the glass-box detail…" />
        ) : error ? (
          <StatusState
            variant="error"
            title="Couldn't load the decision audit trail"
            description={error}
            action={<Chip onClick={loadTrail}>Retry</Chip>}
          />
        ) : (
          <GlassBoxAlertCard alert={alert} primary onReviewed={onReload} />
        )}
      </Panel>
    </>
  );
}
