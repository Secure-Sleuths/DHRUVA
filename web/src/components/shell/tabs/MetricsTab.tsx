"use client";

/**
 * MetricsTab (WO-U9) — READ-ONLY SOC operational KPIs.
 *
 * Binds to `GET /api/metrics/soc-summary` (`getSocSummary` — today/7d/30d MTT),
 * `GET /api/metrics/automation-rates` (`getAutomationRates`), and
 * `GET /api/dashboard/stats` (`getDashboardStats`). All are `require_role(
 * admin, senior_analyst)` (surfaced by the shell ACL); the MTT/automation
 * endpoints are NOT license-gated, but the tab still degrades a runtime 402/403
 * to FeatureLockedState defensively.
 *
 * Every number expands to its basis via the Tile disclosure (sample size /
 * window) — nothing is a bare figure. MTTD/MTTA/MTTR/SLA/auto-close are REAL
 * computed values (not estimates). There is NO LLM-cost figure in these
 * endpoints, so the LLM-cost tile is an HONEST "not exposed here" placeholder
 * rather than a fabricated/estimated number.
 *
 * States: loading / empty / error+retry / locked; PollingStatus (30s, aborts).
 * Fixtures gate behind NEXT_PUBLIC_DHRUVA_FIXTURES.
 */

import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  Chip,
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
  getAnalystPerformance,
  getAnalystWorkload,
  getAutomationHealth,
  getAutomationRates,
  getCaseAging,
  getDashboardStats,
  getHuntTrends,
  getSocPerformance,
  getSocSummary,
} from "@/lib/api";
import { DASH, fmtDate, fmtInt, fmtMinutes, fmtNum, fmtPct } from "@/lib/format";
import type { TabProps } from "../tabRegistry";
import type {
  AnalystPerformanceResponse,
  AnalystWorkloadResponse,
  AutomationHealth,
  AutomationRates,
  CaseAgingResponse,
  DashboardStats,
  HuntTrendsResponse,
  MttMetrics,
  SocPerformanceResponse,
  SocSummaryResponse,
} from "@/lib/types";

const POLL_MS = 30_000;

function isLockError(e: unknown): boolean {
  return e instanceof ApiError && (e.status === 402 || e.status === 403);
}
function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : "Unknown error";
}

/**
 * Each extended metrics panel below owns its OWN fetch + abort so one endpoint
 * failing never blanks the others (the top-of-tab section keeps its combined
 * load). None of these endpoints is license-gated (only `/metrics/reports/*`
 * is), so a panel surfaces loading / empty / error+retry — no per-panel tier
 * lock. The panel only mounts inside the tab's success branch, so it never
 * fetches while the tab as a whole is locked or still loading.
 */
function usePanelData<T>(fetcher: (signal: AbortSignal) => Promise<T>) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setLoading(true);
    try {
      const d = await fetcher(ac.signal);
      if (ac.signal.aborted) return;
      setData(d);
      setError(null);
      setLoading(false);
    } catch (e) {
      if (ac.signal.aborted) return;
      setError(errMessage(e));
      setLoading(false);
    }
  }, [fetcher]);

  useEffect(() => {
    load();
    return () => abortRef.current?.abort();
  }, [load]);

  return { data, error, loading, reload: load };
}

/** Shared panel frame with title + per-panel loading / error / empty states. */
function DataPanel<T>({
  title,
  sub,
  state,
  isEmpty,
  children,
}: {
  title: string;
  sub?: string;
  state: { data: T | null; error: string | null; loading: boolean; reload: () => void };
  isEmpty: (d: T) => boolean;
  children: (d: T) => ReactNode;
}) {
  const { data, error, loading, reload } = state;
  return (
    <Panel className="overflow-hidden">
      <div className="px-4 pt-3 text-title text-ink">{title}</div>
      {sub && <div className="px-4 text-kbd text-dim2">{sub}</div>}
      <div className="p-4 pt-3">
        {loading && !data ? (
          <div className="text-kbd text-dim2">Loading…</div>
        ) : error && !data ? (
          <div className="flex items-center gap-3 text-kbd text-dim2">
            <span>Couldn&apos;t load: {error}</span>
            <Chip onClick={reload}>Retry</Chip>
          </div>
        ) : data && !isEmpty(data) ? (
          children(data)
        ) : (
          <div className="text-kbd text-dim2">No data in this window yet.</div>
        )}
      </div>
    </Panel>
  );
}

type MttWindow = "today" | "week" | "month";
const WINDOW_LABEL: Record<MttWindow, string> = {
  today: "Today",
  week: "7 days",
  month: "30 days",
};

interface State {
  soc: SocSummaryResponse | null;
  rates: AutomationRates | null;
  dash: DashboardStats | null;
  error: string | null;
  locked: boolean;
  loading: boolean;
}

export function MetricsTab(_props: TabProps) {
  const [win, setWin] = useState<MttWindow>("month");
  const [state, setState] = useState<State>({
    soc: null,
    rates: null,
    dash: null,
    error: null,
    locked: false,
    loading: true,
  });
  const [secondsAgo, setSecondsAgo] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async (manual: boolean) => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    if (manual) setRefreshing(true);
    try {
      const [soc, rates, dash] = await Promise.all([
        getSocSummary(ac.signal),
        getAutomationRates({}, ac.signal),
        getDashboardStats(ac.signal),
      ]);
      if (ac.signal.aborted) return;
      setState({ soc, rates, dash, error: null, locked: false, loading: false });
      setSecondsAgo(0);
    } catch (e) {
      if (ac.signal.aborted) return;
      if (isLockError(e)) {
        setState({ soc: null, rates: null, dash: null, error: null, locked: true, loading: false });
        return;
      }
      const msg = errMessage(e);
      setState((prev) =>
        prev.soc
          ? { ...prev, loading: false }
          : { soc: null, rates: null, dash: null, error: msg, locked: false, loading: false },
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

  const { soc, rates, dash, error, locked, loading } = state;
  const mtt: MttMetrics | null = soc ? soc[win] : null;

  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PageHeading
          title="SOC metrics"
          sub="Detection & response performance, automation rates, and the noisiest rules — every figure expands to its basis. Read-only."
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
        <FeatureLockedState feature="SOC metrics" tier="current" onUpgrade={onUpgrade} />
      ) : loading && !soc ? (
        <StatusState variant="loading" title="Loading SOC metrics…" />
      ) : error && !soc ? (
        <StatusState
          variant="error"
          title="Couldn't load SOC metrics"
          description={error}
          action={<Chip onClick={() => load(true)}>Retry</Chip>}
        />
      ) : soc ? (
        <div className="flex flex-col gap-3">
          {/* MTT window selector */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-kbd uppercase tracking-wider text-dim2">
              Response window
            </span>
            <div className="flex gap-1.5" role="group" aria-label="Metrics window">
              {(["today", "week", "month"] as MttWindow[]).map((w) => (
                <Chip
                  key={w}
                  variant={win === w ? "cite" : "default"}
                  onClick={() => setWin(w)}
                  aria-label={`Show ${WINDOW_LABEL[w]} metrics`}
                >
                  {WINDOW_LABEL[w]}
                </Chip>
              ))}
            </div>
          </div>

          <MttTiles mtt={mtt} win={win} />
          {rates && <AutomationTiles rates={rates} />}
          {dash && <DashboardCounts dash={dash} />}
          {mtt?.by_severity && Object.keys(mtt.by_severity).length > 0 && (
            <MttBySeverity mtt={mtt} win={win} />
          )}
          {dash && dash.noisy_rules.length > 0 && (
            <NoisyRules rows={dash.noisy_rules} />
          )}

          {/* Extended metrics — each panel owns its own fetch/abort (read-only) */}
          <AutomationHealthPanel />
          <AnalystPerformancePanel />
          <AnalystWorkloadPanel />
          <CaseAgingPanel />
          <HuntTrendsPanel />
          <SocPerformanceTrendPanel />
        </div>
      ) : null}
    </>
  );
}

function empty(v: number | null | undefined): boolean {
  return v == null;
}

function MttTiles({ mtt, win }: { mtt: MttMetrics | null; win: MttWindow }) {
  const sample = mtt?.sample_count ?? 0;
  const basis = (
    <>
      Over {WINDOW_LABEL[win]} · {fmtInt(sample)} closed incident
      {sample === 1 ? "" : "s"} in the sample. Computed from incident
      timestamps (`compute_mtt_metrics`), not an estimate.
    </>
  );
  const noData = !mtt || (empty(mtt.mttd_min) && empty(mtt.mtta_min) && empty(mtt.mttr_min));

  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
      <Tile label="MTTD" value={fmtMinutes(mtt?.mttd_min)} sub="time to detect" math={basis} />
      <Tile label="MTTA" value={fmtMinutes(mtt?.mtta_min)} sub="time to acknowledge" math={basis} />
      <Tile label="MTTR" value={fmtMinutes(mtt?.mttr_min)} sub="time to resolve" math={basis} />
      <Tile
        label="SLA · response"
        value={fmtPct(mtt?.sla_response_compliance)}
        sub="within target"
        math={basis}
      />
      <Tile
        label="SLA · resolution"
        value={fmtPct(mtt?.sla_resolution_compliance)}
        sub="within target"
        math={basis}
      />
      {/* HONEST placeholder — LLM cost is not returned by these endpoints. */}
      <Tile
        label="LLM cost"
        value={DASH}
        sub="not exposed by these endpoints"
        math={
          <>
            The metrics/dashboard read endpoints do not return an LLM-cost
            figure. Rather than estimate one, this is shown as unavailable —
            LLM spend lives in the operational-metrics timeseries and would be a
            separate, clearly-labelled estimate when wired.
          </>
        }
      />
      {noData && (
        <div className="col-span-full text-kbd text-dim2">
          No closed incidents in {WINDOW_LABEL[win].toLowerCase()} yet — MTT
          figures appear once incidents are resolved in this window.
        </div>
      )}
    </div>
  );
}

function AutomationTiles({ rates }: { rates: AutomationRates }) {
  const period = rates.period_days ?? 30;
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
      <Tile
        label="Auto-close rate"
        value={fmtPct(rates.auto_close_rate)}
        sub={`${fmtInt(rates.auto_closed)} of ${fmtInt(rates.total_decisions)} decisions`}
        math={<>Over {period} days: auto_closed / total_decisions.</>}
      />
      <Tile
        label="Enrichment automation"
        value={fmtPct(rates.enrichment_automation_pct)}
        sub="alerts auto-enriched"
      />
      <Tile
        label="True positives"
        value={fmtInt(rates.true_positives)}
        sub={`over ${period} days`}
      />
      <Tile
        label="False positives"
        value={fmtInt(rates.false_positives)}
        sub={`over ${period} days`}
      />
    </div>
  );
}

function DashboardCounts({ dash }: { dash: DashboardStats }) {
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
      <Tile
        label="Open incidents"
        value={fmtInt(dash.open_incidents)}
        sub={`${fmtInt(dash.critical_incidents)} critical`}
        valueSeverity={dash.critical_incidents > 0 ? "high" : undefined}
      />
      <Tile label="Pending reviews" value={fmtInt(dash.pending_reviews)} sub="awaiting an analyst" />
      <Tile label="Pending proposals" value={fmtInt(dash.pending_proposals)} sub="detection changes" />
      <Tile
        label="Today · avg confidence"
        value={fmtNum(dash.today.avg_confidence, 2)}
        sub={`${fmtInt(dash.today.total)} alerts · ${fmtInt(dash.today.auto_closed)} auto-closed`}
      />
    </div>
  );
}

function MttBySeverity({ mtt, win }: { mtt: MttMetrics; win: MttWindow }) {
  const entries = Object.entries(mtt.by_severity ?? {});
  return (
    <Panel className="overflow-hidden">
      <div className="px-4 pt-3 text-title text-ink">
        MTT by severity · {WINDOW_LABEL[win]}
      </div>
      <Table className="mt-2">
        <THead>
          <TR>
            <TH>Severity</TH>
            <TH className="text-right">Incidents</TH>
            <TH className="text-right">MTTD</TH>
            <TH className="text-right">MTTA</TH>
            <TH className="text-right">MTTR</TH>
          </TR>
        </THead>
        <TBody>
          {entries.map(([sev, m]) => (
            <TR key={sev}>
              <TD>{sev}</TD>
              <TD mono className="text-right">{fmtInt(m.count)}</TD>
              <TD mono className="text-right">{fmtMinutes(m.mttd_min)}</TD>
              <TD mono className="text-right">{fmtMinutes(m.mtta_min)}</TD>
              <TD mono className="text-right">{fmtMinutes(m.mttr_min)}</TD>
            </TR>
          ))}
        </TBody>
      </Table>
    </Panel>
  );
}

function NoisyRules({ rows }: { rows: DashboardStats["noisy_rules"] }) {
  return (
    <Panel className="overflow-hidden">
      <div className="px-4 pt-3 text-title text-ink">Noisiest rules</div>
      <div className="px-4 text-kbd text-dim2">
        The rules generating the most false positives — these feed the Detection
        loop&apos;s tuning proposals.
      </div>
      <Table className="mt-2">
        <THead>
          <TR>
            <TH>Rule</TH>
            <TH className="text-right">Alerts</TH>
            <TH className="text-right">FPs</TH>
            <TH className="text-right">FP rate</TH>
            <TH>Tuning</TH>
          </TR>
        </THead>
        <TBody>
          {rows.map((r) => (
            <TR key={String(r.rule_id)}>
              <TD>
                <span className="font-mono text-ink">{r.rule_id}</span>
                {r.rule_description && (
                  <div className="max-w-[420px] truncate text-kbd text-dim2" title={r.rule_description}>
                    {r.rule_description}
                  </div>
                )}
              </TD>
              <TD mono className="text-right">{fmtInt(r.total_alerts)}</TD>
              <TD mono className="text-right">{fmtInt(r.fp_count)}</TD>
              <TD mono className="text-right">{fmtPct(r.fp_rate, { fraction: true })}</TD>
              <TD>
                {r.tuning_action ? (
                  <span className="text-acc">{r.tuning_action}</span>
                ) : (
                  <span className="text-dim2">{DASH}</span>
                )}
              </TD>
            </TR>
          ))}
        </TBody>
      </Table>
    </Panel>
  );
}

// ---- Extended metrics panels (WO-U9 gap close) ------------------------------
// GET /api/metrics/automation-health · analyst-performance · analyst-workload ·
// case-aging · hunt-trends · soc-performance. All read-only, all
// require_role(admin, senior_analyst) (surfaced by the shell ACL), none
// license-gated.

function AutomationHealthPanel() {
  const state = usePanelData<AutomationHealth>(getAutomationHealth);
  return (
    <DataPanel
      title="Automation health"
      sub="Enrichment latency percentiles and SOAR action success — how the automated pipeline is performing."
      state={state}
      isEmpty={(d) =>
        !d.enrichment_latency?.sample_count && d.soar_actions?.total_actions === 0
      }
    >
      {(d) => {
        const lat = d.enrichment_latency ?? {};
        const soar = d.soar_actions ?? { total_actions: 0, success_count: 0, failure_count: 0 };
        return (
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-8">
            <Tile
              label="Enrichment p50"
              value={fmtMs(lat.p50_ms)}
              sub={`${fmtInt(lat.sample_count)} samples · ${d.period_days}d`}
            />
            <Tile label="p95" value={fmtMs(lat.p95_ms)} sub="latency" />
            <Tile label="p99" value={fmtMs(lat.p99_ms)} sub="latency" />
            <Tile label="Avg" value={fmtMs(lat.avg_ms)} sub="latency" />
            <Tile label="SOAR actions" value={fmtInt(soar.total_actions)} sub={`over ${d.period_days}d`} />
            <Tile label="Succeeded" value={fmtInt(soar.success_count)} sub="actions" />
            <Tile
              label="Failed"
              value={fmtInt(soar.failure_count)}
              sub="actions"
              valueSeverity={soar.failure_count > 0 ? "high" : undefined}
            />
            <Tile label="Success rate" value={fmtPct(soar.success_rate)} sub="of SOAR actions" />
          </div>
        );
      }}
    </DataPanel>
  );
}

function AnalystPerformancePanel() {
  const state = usePanelData<AnalystPerformanceResponse>(getAnalystPerformance);
  return (
    <DataPanel
      title="Analyst performance · 30 days"
      sub="Per-analyst activity from the incident timeline — incidents touched, resolved, and total actions."
      state={state}
      isEmpty={(d) => (d.analysts?.length ?? 0) === 0}
    >
      {(d) => (
        <Table>
          <THead>
            <TR>
              <TH>Analyst</TH>
              <TH className="text-right">Incidents touched</TH>
              <TH className="text-right">Resolved</TH>
              <TH className="text-right">Actions</TH>
            </TR>
          </THead>
          <TBody>
            {d.analysts.map((a) => (
              <TR key={a.actor}>
                <TD>{a.actor}</TD>
                <TD mono className="text-right">{fmtInt(a.incidents_touched)}</TD>
                <TD mono className="text-right">{fmtInt(a.resolved_count)}</TD>
                <TD mono className="text-right">{fmtInt(a.total_actions)}</TD>
              </TR>
            ))}
          </TBody>
        </Table>
      )}
    </DataPanel>
  );
}

function AnalystWorkloadPanel() {
  const state = usePanelData<AnalystWorkloadResponse>(getAnalystWorkload);
  return (
    <DataPanel
      title="Analyst workload"
      sub="Currently-open incidents per analyst, with overloaded analysts flagged (default threshold 15)."
      state={state}
      isEmpty={(d) => (d.analysts?.length ?? 0) === 0}
    >
      {(d) => (
        <Table>
          <THead>
            <TR>
              <TH>Analyst</TH>
              <TH className="text-right">Open</TH>
              <TH className="text-right">Critical</TH>
              <TH className="text-right">High</TH>
              <TH>Status</TH>
            </TR>
          </THead>
          <TBody>
            {d.analysts.map((a) => (
              <TR key={a.analyst}>
                <TD>{a.analyst}</TD>
                <TD mono className="text-right">{fmtInt(a.open_incidents)}</TD>
                <TD mono className="text-right">{fmtInt(a.critical)}</TD>
                <TD mono className="text-right">{fmtInt(a.high)}</TD>
                <TD>
                  {a.is_overloaded ? (
                    <span className="text-sev-high">Overloaded</span>
                  ) : (
                    <span className="text-dim2">OK</span>
                  )}
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      )}
    </DataPanel>
  );
}

function CaseAgingPanel() {
  const state = usePanelData<CaseAgingResponse>(getCaseAging);
  return (
    <DataPanel
      title="Case aging"
      sub="Open incidents oldest-first, with stale cases flagged (default threshold 48h)."
      state={state}
      isEmpty={(d) => (d.cases?.length ?? 0) === 0}
    >
      {(d) => (
        <Table>
          <THead>
            <TR>
              <TH>Incident</TH>
              <TH>Severity</TH>
              <TH>Status</TH>
              <TH>Assigned</TH>
              <TH className="text-right">Age (h)</TH>
              <TH className="text-right">Alerts</TH>
              <TH>State</TH>
            </TR>
          </THead>
          <TBody>
            {d.cases.map((c) => (
              <TR key={String(c.id)}>
                <TD>
                  <span className="font-mono text-ink">{c.id}</span>
                  {c.title && (
                    <div className="max-w-[360px] truncate text-kbd text-dim2" title={c.title}>
                      {c.title}
                    </div>
                  )}
                </TD>
                <TD>{c.severity}</TD>
                <TD>{c.status}</TD>
                <TD>{c.assigned_to || <span className="text-dim2">{DASH}</span>}</TD>
                <TD mono className="text-right">{fmtNum(c.hours_open, 1)}</TD>
                <TD mono className="text-right">{fmtInt(c.alert_count)}</TD>
                <TD>
                  {c.is_stale ? (
                    <span className="text-sev-high">Stale</span>
                  ) : (
                    <span className="text-dim2">Fresh</span>
                  )}
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      )}
    </DataPanel>
  );
}

function HuntTrendsPanel() {
  const state = usePanelData<HuntTrendsResponse>(getHuntTrends);
  return (
    <DataPanel
      title="Hunt trends"
      sub="Per-cycle hunt outcomes over the last 90 days — hypotheses run, hits, and confirmation rate."
      state={state}
      isEmpty={(d) => (d.cycles?.length ?? 0) === 0}
    >
      {(d) => (
        <Table>
          <THead>
            <TR>
              <TH>Cycle</TH>
              <TH className="text-right">Hypotheses</TH>
              <TH className="text-right">Hits</TH>
              <TH className="text-right">Confirmed</TH>
              <TH className="text-right">Hit rate</TH>
              <TH className="text-right">Confirmation rate</TH>
            </TR>
          </THead>
          <TBody>
            {d.cycles.map((c) => (
              <TR key={String(c.cycle_id)}>
                <TD>
                  <div className="text-ink">{fmtDate(c.cycle_date)}</div>
                  <div className="font-mono text-kbd text-dim2">{c.cycle_id}</div>
                </TD>
                <TD mono className="text-right">{fmtInt(c.total_hypotheses)}</TD>
                <TD mono className="text-right">{fmtInt(c.hits)}</TD>
                <TD mono className="text-right">{fmtInt(c.confirmed)}</TD>
                <TD mono className="text-right">{fmtPct(c.hit_rate)}</TD>
                <TD mono className="text-right">{fmtPct(c.confirmation_rate)}</TD>
              </TR>
            ))}
          </TBody>
        </Table>
      )}
    </DataPanel>
  );
}

function SocPerformanceTrendPanel() {
  const state = usePanelData<SocPerformanceResponse>(getSocPerformance);
  return (
    <DataPanel
      title="Daily MTT trend"
      sub="Per-day MTTD / MTTA / MTTR from incident timestamps (the snapshot above, broken out by day)."
      state={state}
      isEmpty={(d) => (d.trends?.length ?? 0) === 0}
    >
      {(d) => (
        <Table>
          <THead>
            <TR>
              <TH>Day</TH>
              <TH className="text-right">Incidents</TH>
              <TH className="text-right">MTTD</TH>
              <TH className="text-right">MTTA</TH>
              <TH className="text-right">MTTR</TH>
            </TR>
          </THead>
          <TBody>
            {d.trends.map((t) => (
              <TR key={t.day}>
                <TD>{fmtDate(t.day)}</TD>
                <TD mono className="text-right">{fmtInt(t.incident_count)}</TD>
                <TD mono className="text-right">{fmtMinutes(t.avg_mttd)}</TD>
                <TD mono className="text-right">{fmtMinutes(t.avg_mtta)}</TD>
                <TD mono className="text-right">{fmtMinutes(t.avg_mttr)}</TD>
              </TR>
            ))}
          </TBody>
        </Table>
      )}
    </DataPanel>
  );
}

/** Format a millisecond latency figure, `—` when absent. */
function fmtMs(v: number | null | undefined): string {
  return v == null ? DASH : `${fmtNum(v, 0)} ms`;
}
