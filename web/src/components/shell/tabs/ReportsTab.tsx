"use client";

/**
 * ReportsTab (WO-U9c) — READ-ONLY SOC reports.
 *
 * The ONLY reports route is `GET /api/metrics/reports/{daily|weekly|monthly}`
 * (`getSocReport`), gated `require_role("admin","senior_analyst")` +
 * `require_license_feature("reports")`. It GENERATES a fresh report as JSON on
 * demand — the generator runs only SELECTs (no writes, no persistence), so
 * "generate" here is effectively a READ, and this tab mutates nothing. There is
 * NO reports list/history endpoint, so no "recent reports" list is fabricated;
 * instead the analyst picks a window and the report is rendered inline, with an
 * optional client-side JSON download of exactly what the API returned.
 *
 * RBAC mirror: the tab is ACL-gated to admin/senior_analyst (shell), and a
 * runtime 402/403 from the `reports` license feature degrades to
 * FeatureLockedState — never widened.
 *
 * States: loading / empty / error+retry / locked. Fixtures gate behind
 * NEXT_PUBLIC_DHRUVA_FIXTURES.
 */

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { Download, FileText } from "lucide-react";
import {
  Chip,
  FeatureLockedState,
  Panel,
  PollingStatus,
  StatusState,
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
  getLlmBudgetAlerts,
  getLlmCostTrends,
  getLlmOptimization,
  getLlmUsageReport,
  getSocReport,
  getTIStrategicReport,
} from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { DASH, fmtDateTime, fmtInt, fmtMinutes, fmtNum, fmtPct } from "@/lib/format";
import { cn, focusRing } from "@/lib/ui";
import type { TabProps } from "../tabRegistry";
import type {
  LlmBreakdownEntry,
  LlmBudgetAlert,
  LlmBudgetAlertsResponse,
  LlmCostTrends,
  LlmOptimizationResponse,
  LlmOptimizationSuggestion,
  LlmUsageReport,
  MttMetrics,
  SocReport,
  SocReportType,
  TiStrategicReport,
} from "@/lib/types";

function isLockError(e: unknown): boolean {
  // 402/403 = license/role gate (paid route present but denied). 404 = the paid
  // route was physically stripped from this build (Community): the SOC report
  // (`/api/metrics/*`) and TI strategic report (`/api/threat-intel/
  // strategic-report`) both live in tier-stripped route modules, so a missing
  // route means the feature is absent — treat it as locked (graceful upgrade
  // state) rather than a raw "Not Found" error.
  return (
    e instanceof ApiError &&
    (e.status === 402 || e.status === 403 || e.status === 404)
  );
}
function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : "Unknown error";
}

const KIND_LABEL: Record<SocReportType, string> = {
  daily: "Daily · 24h",
  weekly: "Weekly · 7d",
  monthly: "Monthly · 30d",
};

interface State {
  report: SocReport | null;
  error: string | null;
  locked: boolean;
  loading: boolean;
}

// Resolve the leaf snapshot that carries alerts / incidents / noisy rules:
// daily has them at top level; weekly nests a daily_snapshot; monthly nests a
// weekly_snapshot → daily_snapshot.
function leaf(r: SocReport): SocReport {
  return r.daily_snapshot ?? r.weekly_snapshot?.daily_snapshot ?? r;
}
// The headline MTT for the report's own window.
function headlineMtt(r: SocReport): MttMetrics | undefined {
  return r.monthly_mtt ?? r.weekly_mtt ?? r.mtt_metrics;
}
// Detection/hunting/automation live at weekly top-level or in monthly's weekly_snapshot.
function weeklySection(r: SocReport): SocReport | undefined {
  if (r.detection_engineering || r.threat_hunting || r.automation_rates) return r;
  return r.weekly_snapshot;
}

type ReportsSubtab = "soc" | "llm" | "ti";
const REPORTS_SUBTABS: { id: ReportsSubtab; label: string }[] = [
  { id: "soc", label: "SOC Reports" },
  { id: "llm", label: "LLM Usage" },
  { id: "ti", label: "Threat Intel" },
];

/**
 * ReportsTab shell — restores the legacy 3-way `reportsSubTab` bar
 * (`app.js:4762-4771`): SOC Reports · LLM Usage · Threat Intel. Each sub-view is
 * self-fetching with its own loading / empty / typed-error / tier-lock states,
 * READ-ONLY, and mirrors its endpoint's RBAC/license gate (never widened). The
 * Reports tab itself is ACL-gated to admin/senior_analyst/mssp_admin (shell), so
 * every reachable role satisfies each sub-view's role gate; the per-view
 * differentiator is the LICENSE (LLM Usage has none; Threat-Intel strategic needs
 * `ti_feeds_tier2`), surfaced as FeatureLockedState on a runtime 402/403.
 */
export function ReportsTab(_props: TabProps) {
  const [subtab, setSubtab] = useState<ReportsSubtab>("soc");
  return (
    <>
      <PageHeading
        title="Reports"
        sub="SOC operational reports, LLM usage & cost, and the strategic threat-intel landscape — generated on demand as structured JSON. Read-only."
      />
      <div
        className="mb-1 flex flex-wrap gap-1.5"
        role="tablist"
        aria-label="Report sections"
      >
        {REPORTS_SUBTABS.map((s) => (
          <button
            key={s.id}
            type="button"
            role="tab"
            aria-selected={subtab === s.id}
            onClick={() => setSubtab(s.id)}
            className={cn(
              "rounded-md border px-2.5 py-1 text-meta",
              subtab === s.id
                ? "border-cite-border bg-cite-bg text-cite-ink"
                : "border-line bg-field text-ink hover:bg-hover",
              focusRing,
            )}
          >
            {s.label}
          </button>
        ))}
      </div>
      {subtab === "soc" && <SocReportsSection />}
      {subtab === "llm" && <LlmUsageSection />}
      {subtab === "ti" && <TiStrategicSection />}
    </>
  );
}

function SocReportsSection() {
  const [kind, setKind] = useState<SocReportType>("daily");
  const [state, setState] = useState<State>({
    report: null,
    error: null,
    locked: false,
    loading: true,
  });
  const [secondsAgo, setSecondsAgo] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async (rk: SocReportType, manual: boolean) => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    if (manual) setRefreshing(true);
    setState((prev) => ({ ...prev, loading: true, error: null }));
    try {
      const report = await getSocReport(rk, ac.signal);
      if (ac.signal.aborted) return;
      setState({ report, error: null, locked: false, loading: false });
      setSecondsAgo(0);
    } catch (e) {
      if (ac.signal.aborted) return;
      if (isLockError(e)) {
        setState({ report: null, error: null, locked: true, loading: false });
        return;
      }
      setState({ report: null, error: errMessage(e), locked: false, loading: false });
    } finally {
      if (!ac.signal.aborted) setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    load(kind, false);
    return () => abortRef.current?.abort();
  }, [kind, load]);

  useEffect(() => {
    const t = setInterval(() => setSecondsAgo((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, []);

  const onUpgrade = useCallback(() => {
    if (typeof window !== "undefined") {
      window.open("https://securesleuths.in/pricing", "_blank", "noreferrer");
    }
  }, []);

  const onDownload = useCallback(() => {
    const r = state.report;
    if (!r || typeof window === "undefined") return;
    const blob = new Blob([JSON.stringify(r, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `soc-report-${r.type}-${r.generated_at.slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }, [state.report]);

  const { report, error, locked, loading } = state;

  return (
    <>
      {!locked && (
        <div className="flex justify-end">
          <PollingStatus
            className="mt-1"
            secondsAgo={secondsAgo}
            refreshing={refreshing}
            onRefresh={() => load(kind, true)}
          />
        </div>
      )}

      {/* Window selector — always available so a locked/empty state is still switchable */}
      {!locked && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-kbd uppercase tracking-wider text-dim2">
            Report window
          </span>
          <div className="flex gap-1.5" role="group" aria-label="Report window">
            {(["daily", "weekly", "monthly"] as SocReportType[]).map((k) => (
              <Chip
                key={k}
                variant={kind === k ? "cite" : "default"}
                onClick={() => setKind(k)}
                aria-label={`Show ${KIND_LABEL[k]} report`}
              >
                {KIND_LABEL[k]}
              </Chip>
            ))}
          </div>
        </div>
      )}

      {locked ? (
        <FeatureLockedState feature="SOC reports" tier="current" onUpgrade={onUpgrade} />
      ) : loading ? (
        <StatusState variant="loading" title={`Generating ${KIND_LABEL[kind]} report…`} />
      ) : error ? (
        <StatusState
          variant="error"
          title="Couldn't generate the report"
          description={error}
          action={<Chip onClick={() => load(kind, true)}>Retry</Chip>}
        />
      ) : report ? (
        <ReportView report={report} onDownload={onDownload} />
      ) : null}
    </>
  );
}

function ReportView({
  report,
  onDownload,
}: {
  report: SocReport;
  onDownload: () => void;
}) {
  const base = leaf(report);
  const mtt = headlineMtt(report);
  const wk = weeklySection(report);
  const alerts = base.alerts;
  const inc = base.incidents;
  const noisy = base.top_noisy_rules ?? [];

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-line bg-panel2 px-3.5 py-2.5">
        <div className="text-kbd text-dim2">
          <span className="text-dim">{report.period}</span> · generated{" "}
          {fmtDateTime(report.generated_at)} · read-only (SELECT-only, nothing
          persisted server-side)
        </div>
        <Chip onClick={onDownload} aria-label="Download this report as JSON">
          <Download className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
          Download JSON
        </Chip>
      </div>

      {/* Alerts */}
      <Section title="Alerts">
        {alerts ? (
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
            <Tile label="Total" value={fmtInt(alerts.total)} sub="triaged" />
            <Tile label="True positives" value={fmtInt(alerts.true_positives)} sub="confirmed" />
            <Tile label="False positives" value={fmtInt(alerts.false_positives)} sub="ruled out" />
            <Tile label="Auto-closed" value={fmtInt(alerts.auto_closed)} sub="by the loop" />
            <Tile
              label="Escalated"
              value={fmtInt(alerts.escalated)}
              sub="to a human"
              valueSeverity={alerts.escalated > 0 ? "high" : undefined}
            />
            <Tile
              label="Avg confidence"
              value={fmtPct(alerts.avg_confidence, { fraction: true })}
              sub="model self-assessed"
            />
          </div>
        ) : (
          <EmptyNote>No alert figures in this window.</EmptyNote>
        )}
      </Section>

      {/* Incidents */}
      <Section title="Incidents">
        {inc ? (
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
            <Tile label="New" value={fmtInt(inc.new)} sub="opened" />
            <Tile
              label="Critical"
              value={fmtInt(inc.critical)}
              sub="severity"
              valueSeverity={inc.critical > 0 ? "high" : undefined}
            />
            <Tile label="High" value={fmtInt(inc.high)} sub="severity" />
            <Tile label="Resolved" value={fmtInt(inc.resolved)} sub="closed out" />
            <Tile label="Currently open" value={fmtInt(inc.currently_open)} sub="estate-wide" />
          </div>
        ) : (
          <EmptyNote>No incident figures in this window.</EmptyNote>
        )}
      </Section>

      {/* MTT */}
      <Section title="Response times">
        <MttTiles mtt={mtt} />
      </Section>

      {/* Weekly / monthly: detection & hunting + automation */}
      {wk && (wk.detection_engineering || wk.threat_hunting) && (
        <Section title="Detection engineering & hunting">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-7">
            <Tile label="Proposals" value={fmtInt(wk.detection_engineering?.proposals_created)} sub="created" />
            <Tile label="Approved" value={fmtInt(wk.detection_engineering?.proposals_approved)} sub="rule changes" />
            <Tile label="Deployed" value={fmtInt(wk.detection_engineering?.proposals_deployed)} sub="live" />
            <Tile label="Hunt findings" value={fmtInt(wk.threat_hunting?.findings_total)} sub="total" />
            <Tile label="Hits" value={fmtInt(wk.threat_hunting?.findings_hits)} sub="with results" />
            <Tile label="Confirmed" value={fmtInt(wk.threat_hunting?.findings_confirmed)} sub="true findings" />
            {wk.automation_rates && (
              <Tile
                label="Auto-close rate"
                value={fmtPct(wk.automation_rates.auto_close_rate)}
                sub={`${fmtInt(wk.automation_rates.auto_closed)} of ${fmtInt(wk.automation_rates.total_decisions)}`}
              />
            )}
          </div>
        </Section>
      )}

      {/* Monthly: analyst performance */}
      {report.analyst_performance && report.analyst_performance.length > 0 && (
        <Panel className="overflow-hidden">
          <div className="px-4 pt-3 text-title text-ink">Analyst performance · 30 days</div>
          <Table className="mt-2">
            <THead>
              <TR>
                <TH>Analyst</TH>
                <TH className="text-right">Incidents touched</TH>
                <TH className="text-right">Resolved</TH>
                <TH className="text-right">Actions</TH>
              </TR>
            </THead>
            <TBody>
              {report.analyst_performance.map((a) => (
                <TR key={a.actor}>
                  <TD>{a.actor}</TD>
                  <TD mono className="text-right">{fmtInt(a.incidents_touched)}</TD>
                  <TD mono className="text-right">{fmtInt(a.resolved_count)}</TD>
                  <TD mono className="text-right">{fmtInt(a.total_actions)}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </Panel>
      )}

      {/* Monthly: MITRE coverage + SLA */}
      {report.mitre_coverage && report.mitre_coverage.total_techniques > 0 && (
        <Section title="MITRE coverage">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
            <Tile label="Coverage" value={fmtPct(report.mitre_coverage.coverage_pct)} sub="active / total" />
            <Tile label="Active" value={fmtInt(report.mitre_coverage.active)} sub="techniques" />
            <Tile label="Stale" value={fmtInt(report.mitre_coverage.stale)} sub="techniques" />
            <Tile label="Noisy" value={fmtInt(report.mitre_coverage.noisy)} sub="techniques" />
            <Tile label="Total" value={fmtInt(report.mitre_coverage.total_techniques)} sub="tracked" />
          </div>
        </Section>
      )}
      {report.sla_compliance && report.sla_compliance.total_resolved > 0 && (
        <Section title="SLA compliance">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            <Tile
              label="Response SLA"
              value={fmtPct(report.sla_compliance.response_compliance_pct)}
              sub={`${fmtInt(report.sla_compliance.response_met)} of ${fmtInt(report.sla_compliance.total_resolved)} met`}
            />
            <Tile
              label="Resolution SLA"
              value={fmtPct(report.sla_compliance.resolution_compliance_pct)}
              sub={`${fmtInt(report.sla_compliance.resolution_met)} of ${fmtInt(report.sla_compliance.total_resolved)} met`}
            />
            <Tile label="Resolved" value={fmtInt(report.sla_compliance.total_resolved)} sub="in window" />
          </div>
        </Section>
      )}

      {/* Noisy rules */}
      <Panel className="overflow-hidden">
        <div className="px-4 pt-3 text-title text-ink">Top noisy rules</div>
        <div className="px-4 text-kbd text-dim2">
          The rules generating the most false positives in this window — these
          feed the Detection loop&apos;s tuning proposals.
        </div>
        {noisy.length > 0 ? (
          <Table className="mt-2">
            <THead>
              <TR>
                <TH>Rule</TH>
                <TH className="text-right">FP count</TH>
              </TR>
            </THead>
            <TBody>
              {noisy.map((r) => (
                <TR key={String(r.rule_id)}>
                  <TD>
                    <span className="font-mono text-ink">{r.rule_id}</span>
                    {r.description && (
                      <div
                        className="max-w-[520px] truncate text-kbd text-dim2"
                        title={r.description}
                      >
                        {r.description}
                      </div>
                    )}
                  </TD>
                  <TD mono className="text-right">{fmtInt(r.fp_count)}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        ) : (
          <div className="px-4 py-3">
            <EmptyNote>No false-positive-heavy rules in this window.</EmptyNote>
          </div>
        )}
      </Panel>
    </div>
  );
}

function MttTiles({ mtt }: { mtt: MttMetrics | undefined }) {
  const sample = mtt?.sample_count ?? 0;
  const noData =
    !mtt ||
    (mtt.mttd_min == null && mtt.mtta_min == null && mtt.mttr_min == null);
  if (noData) {
    return (
      <EmptyNote>
        No resolved incidents in this window yet — MTT figures appear once cases
        are closed.
      </EmptyNote>
    );
  }
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
      <Tile label="MTTD" value={fmtMinutes(mtt?.mttd_min)} sub="time to detect" />
      <Tile label="MTTA" value={fmtMinutes(mtt?.mtta_min)} sub="time to acknowledge" />
      <Tile label="MTTR" value={fmtMinutes(mtt?.mttr_min)} sub="time to resolve" />
      <Tile
        label="SLA · response"
        value={fmtPct(mtt?.sla_response_compliance)}
        sub={`${fmtInt(sample)} in sample`}
      />
      <Tile
        label="SLA · resolution"
        value={fmtPct(mtt?.sla_resolution_compliance)}
        sub="within target"
      />
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <div className="mb-1.5 text-kbd uppercase tracking-wider text-dim2">{title}</div>
      {children}
    </div>
  );
}

function EmptyNote({ children }: { children: ReactNode }) {
  return (
    <div className="flex items-start gap-2 rounded-lg border border-line bg-panel px-3.5 py-2.5 text-data text-dim2">
      <FileText className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
      <span>{children}</span>
    </div>
  );
}

// ============================================================================
// Reports → LLM Usage (restores legacy `renderReportsLLM`, app.js:4904-5052).
// GET /api/v1/llm-usage/tenant/{tenant_id}/{report,budget-alerts,cost-trends,
// optimization}. Auth: verify_jwt + own-tenant scoping; NO license gate. The
// section ONLY ever passes the caller's OWN client_id (from the JWT), so the
// request is always own-scoped (never widened). READ-ONLY.
// ============================================================================
const LLM_WINDOWS = [30, 90] as const;

function usd(v: number | null | undefined): string {
  if (v == null || Number.isNaN(v)) return DASH;
  return `$${fmtNum(v, 2)}`;
}

interface LlmState {
  report: LlmUsageReport | null;
  budget: LlmBudgetAlertsResponse | null;
  trends: LlmCostTrends | null;
  opt: LlmOptimizationResponse | null;
  error: string | null;
  loading: boolean;
}

function LlmUsageSection() {
  const { claims } = useAuth();
  const FIX = process.env.NEXT_PUBLIC_DHRUVA_FIXTURES;
  // Own tenant only — never another tenant's usage. In a fixtures/dev-preview
  // build (no JWT) fall back to a preview label so the states can be captured.
  const tenantId = claims?.client_id ?? (FIX ? "preview-tenant" : null);
  const [days, setDays] = useState<number>(30);
  const [state, setState] = useState<LlmState>({
    report: null,
    budget: null,
    trends: null,
    opt: null,
    error: null,
    loading: true,
  });
  const [secondsAgo, setSecondsAgo] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(
    async (manual: boolean) => {
      if (!tenantId) return;
      abortRef.current?.abort();
      const ac = new AbortController();
      abortRef.current = ac;
      if (manual) setRefreshing(true);
      setState((p) => ({ ...p, loading: true, error: null }));
      try {
        const [r, b, t, o] = await Promise.allSettled([
          getLlmUsageReport(tenantId, days, ac.signal),
          getLlmBudgetAlerts(tenantId, ac.signal),
          getLlmCostTrends(tenantId, days, ac.signal),
          getLlmOptimization(tenantId, Math.min(days, 90), ac.signal),
        ]);
        if (ac.signal.aborted) return;
        if (r.status === "rejected") {
          // The report is the primary read — surface its error typed. (There is
          // no license gate here; a 403 would only mean a tenant mismatch, which
          // this own-tenant-only call never produces.)
          setState({
            report: null,
            budget: null,
            trends: null,
            opt: null,
            error: errMessage(r.reason),
            loading: false,
          });
          return;
        }
        setState({
          report: r.value.report,
          budget: b.status === "fulfilled" ? b.value : null,
          trends: t.status === "fulfilled" ? t.value.trends : null,
          opt: o.status === "fulfilled" ? o.value : null,
          error: null,
          loading: false,
        });
        setSecondsAgo(0);
      } finally {
        if (!ac.signal.aborted) setRefreshing(false);
      }
    },
    [tenantId, days],
  );

  useEffect(() => {
    load(false);
    return () => abortRef.current?.abort();
  }, [load]);
  useEffect(() => {
    const t = setInterval(() => setSecondsAgo((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, []);

  if (!tenantId) {
    return (
      <StatusState
        variant="empty"
        title="Tenant not resolved from your session"
        description="This session didn't carry a tenant id (client_id), so per-tenant LLM usage can't be requested. Sign in with a tenant-scoped token to view cost & token usage."
      />
    );
  }

  const { report, budget, trends, opt, error, loading } = state;
  const summary = report?.summary;

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <WindowChips days={days} onPick={setDays} label="Usage window" />
        <PollingStatus
          className="mt-1"
          secondsAgo={secondsAgo}
          refreshing={refreshing}
          onRefresh={() => load(true)}
        />
      </div>

      {loading && !report ? (
        <StatusState variant="loading" title="Loading LLM usage…" />
      ) : error && !report ? (
        <StatusState
          variant="error"
          title="Couldn't load LLM usage"
          description={error}
          action={<Chip onClick={() => load(true)}>Retry</Chip>}
        />
      ) : report ? (
        <>
          {budget && budget.alerts.length > 0 && (
            <div className="flex flex-col gap-2">
              {budget.alerts.map((a, i) => (
                <BudgetBanner key={i} alert={a} />
              ))}
            </div>
          )}

          <Section title="Usage & cost">
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
              <Tile label="Requests" value={fmtInt(summary?.total_requests)} sub={`over ${report.period?.days ?? days}d`} />
              <Tile label="Total tokens" value={fmtInt(summary?.total_tokens)} sub="in + out" />
              <Tile label="Input tokens" value={fmtInt(summary?.total_tokens_input)} sub="prompt" />
              <Tile label="Output tokens" value={fmtInt(summary?.total_tokens_output)} sub="completion" />
              <Tile label="Cost" value={usd(summary?.total_cost_usd)} sub="USD, window" />
              <Tile
                label="Success rate"
                value={summary?.success_rate != null ? fmtPct(summary.success_rate, { fraction: true }) : DASH}
                sub={summary?.avg_latency_ms != null ? `${fmtNum(summary.avg_latency_ms)}ms avg` : "avg latency —"}
              />
            </div>
          </Section>

          <LlmBreakdownTable
            title="By provider"
            sub="Requests, tokens, cost, latency, and success rate per LLM provider."
            rows={report.breakdowns.providers ?? {}}
            withLatency
          />
          <LlmBreakdownTable
            title="By agent (request type)"
            sub="Which agents/request types consumed the tokens."
            rows={report.breakdowns.request_types ?? {}}
          />

          <Panel className="overflow-hidden">
            <div className="px-4 pt-3 text-title text-ink">Cost trend</div>
            <div className="px-4 text-kbd text-dim2">
              Daily spend over the window (table, not a chart — same figures).
            </div>
            {trends && trends.daily_trends.length > 0 ? (
              <Table className="mt-2">
                <THead>
                  <TR>
                    <TH>Date</TH>
                    <TH className="text-right">Cost</TH>
                    <TH className="text-right">Requests</TH>
                  </TR>
                </THead>
                <TBody>
                  {trends.daily_trends.map((d) => (
                    <TR key={d.date}>
                      <TD mono>{d.date}</TD>
                      <TD mono className="text-right">{usd(d.cost)}</TD>
                      <TD mono className="text-right">{fmtInt(d.requests)}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            ) : (
              <div className="px-4 py-3 text-data text-dim2">
                No daily cost points in this window.
              </div>
            )}
          </Panel>

          <Panel className="p-4">
            <div className="mb-1 text-title text-ink">Optimization suggestions</div>
            {opt && opt.suggestions.length > 0 ? (
              <div className="mt-1 flex flex-col gap-2">
                {opt.suggestions.map((s, i) => (
                  <OptimizationRow key={i} s={s} />
                ))}
              </div>
            ) : (
              <div className="text-data text-dim2">
                No optimization suggestions for this window — spend and routing
                look efficient, or there isn&apos;t enough usage to analyze.
              </div>
            )}
          </Panel>
        </>
      ) : null}
    </div>
  );
}

function BudgetBanner({ alert }: { alert: LlmBudgetAlert }) {
  const tone =
    alert.severity === "critical"
      ? "border-sev-crit/50 text-sev-crit"
      : alert.severity === "warning"
        ? "border-gated-border text-gated-ink"
        : "border-line text-dim";
  return (
    <div
      role="status"
      className={cn(
        "flex flex-wrap items-center gap-2 rounded-lg border bg-panel2 px-3.5 py-2.5 text-data",
        tone,
      )}
    >
      <Chip mono>{alert.severity}</Chip>
      <span className="flex-1">{alert.message}</span>
      {alert.budget_utilization != null && (
        <span className="text-kbd text-dim2">
          {fmtPct(alert.budget_utilization, { fraction: true })} of budget
        </span>
      )}
    </div>
  );
}

function LlmBreakdownTable({
  title,
  sub,
  rows,
  withLatency,
}: {
  title: string;
  sub: string;
  rows: Record<string, LlmBreakdownEntry>;
  withLatency?: boolean;
}) {
  const entries = Object.entries(rows);
  return (
    <Panel className="overflow-hidden">
      <div className="px-4 pt-3 text-title text-ink">{title}</div>
      <div className="px-4 text-kbd text-dim2">{sub}</div>
      {entries.length > 0 ? (
        <Table className="mt-2">
          <THead>
            <TR>
              <TH>Name</TH>
              <TH className="text-right">Requests</TH>
              <TH className="text-right">Tokens in</TH>
              <TH className="text-right">Tokens out</TH>
              <TH className="text-right">Cost</TH>
              {withLatency && <TH className="text-right">Avg latency</TH>}
              {withLatency && <TH className="text-right">Success</TH>}
            </TR>
          </THead>
          <TBody>
            {entries.map(([name, e]) => (
              <TR key={name}>
                <TD mono>{name}</TD>
                <TD mono className="text-right">{fmtInt(e.requests)}</TD>
                <TD mono className="text-right">{fmtInt(e.tokens_input)}</TD>
                <TD mono className="text-right">{fmtInt(e.tokens_output)}</TD>
                <TD mono className="text-right">{usd(e.cost_usd)}</TD>
                {withLatency && (
                  <TD mono className="text-right">
                    {e.avg_latency_ms != null ? `${fmtNum(e.avg_latency_ms)}ms` : DASH}
                  </TD>
                )}
                {withLatency && (
                  <TD mono className="text-right">
                    {e.success_rate != null ? fmtPct(e.success_rate, { fraction: true }) : DASH}
                  </TD>
                )}
              </TR>
            ))}
          </TBody>
        </Table>
      ) : (
        <div className="px-4 py-3 text-data text-dim2">No usage in this window.</div>
      )}
    </Panel>
  );
}

function OptimizationRow({ s }: { s: LlmOptimizationSuggestion }) {
  return (
    <div className="rounded-lg border border-line bg-panel2 px-3.5 py-2.5">
      <div className="mb-1 flex flex-wrap items-center gap-2">
        <Chip variant={s.priority === "high" ? "gated" : "default"}>
          {s.priority ?? "info"}
        </Chip>
        {s.type && <span className="font-mono text-kbd text-dim2">{s.type}</span>}
        {s.potential_savings != null && (
          <span className="text-kbd text-teal">
            ~{usd(s.potential_savings)} / window potential saving
          </span>
        )}
      </div>
      <div className="text-data leading-relaxed text-ink">{s.description ?? DASH}</div>
    </div>
  );
}

// ============================================================================
// Reports → Threat Intel strategic report (restores legacy `renderReportsTI`,
// app.js:5054-5122). GET /api/threat-intel/strategic-report?days= —
// require_role("admin","senior_analyst") + require_license_feature(
// "ti_feeds_tier2"). READ-ONLY. Distinct from the operational Threat Intel TAB.
// A runtime 402/403 → FeatureLockedState (fail-closed to locked).
// ============================================================================
interface TiState {
  report: TiStrategicReport | null;
  error: string | null;
  locked: boolean;
  loading: boolean;
}

function TiStrategicSection() {
  const [days, setDays] = useState<number>(30);
  const [state, setState] = useState<TiState>({
    report: null,
    error: null,
    locked: false,
    loading: true,
  });
  const [secondsAgo, setSecondsAgo] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(
    async (manual: boolean) => {
      abortRef.current?.abort();
      const ac = new AbortController();
      abortRef.current = ac;
      if (manual) setRefreshing(true);
      setState((p) => ({ ...p, loading: true, error: null }));
      try {
        const report = await getTIStrategicReport(days, ac.signal);
        if (ac.signal.aborted) return;
        setState({ report, error: null, locked: false, loading: false });
        setSecondsAgo(0);
      } catch (e) {
        if (ac.signal.aborted) return;
        if (isLockError(e)) {
          setState({ report: null, error: null, locked: true, loading: false });
          return;
        }
        setState({ report: null, error: errMessage(e), locked: false, loading: false });
      } finally {
        if (!ac.signal.aborted) setRefreshing(false);
      }
    },
    [days],
  );

  useEffect(() => {
    load(false);
    return () => abortRef.current?.abort();
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

  const { report, error, locked, loading } = state;

  if (locked) {
    return (
      <FeatureLockedState
        feature="Strategic threat-intel report"
        tier="current"
        onUpgrade={onUpgrade}
      />
    );
  }

  const verdicts = report ? Object.entries(report.alert_verdicts ?? {}) : [];

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <WindowChips days={days} onPick={setDays} label="Report window" />
        <PollingStatus
          className="mt-1"
          secondsAgo={secondsAgo}
          refreshing={refreshing}
          onRefresh={() => load(true)}
        />
      </div>

      {loading && !report ? (
        <StatusState variant="loading" title="Generating strategic report…" />
      ) : error && !report ? (
        <StatusState
          variant="error"
          title="Couldn't generate the strategic report"
          description={error}
          action={<Chip onClick={() => load(true)}>Retry</Chip>}
        />
      ) : report ? (
        <>
          <div className="rounded-lg border border-line bg-panel2 px-3.5 py-2.5 text-kbd text-dim2">
            {report.industry && (
              <>Industry: <span className="text-dim">{report.industry}</span> · </>
            )}
            Period: last {report.period_days ?? days} days · generated{" "}
            {fmtDateTime(report.generated_at)} · read-only landscape view.
          </div>

          <Section title="Alert verdicts">
            {verdicts.length > 0 ? (
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
                {verdicts.map(([k, v]) => (
                  <Tile key={k} label={k.replace(/_/g, " ")} value={fmtInt(v)} sub="alerts" />
                ))}
              </div>
            ) : (
              <EmptyNote>No verdict figures in this window.</EmptyNote>
            )}
          </Section>

          <Panel className="overflow-hidden">
            <div className="px-4 pt-3 text-title text-ink">IOC sources</div>
            {report.ioc_sources.length > 0 ? (
              <Table className="mt-2">
                <THead>
                  <TR>
                    <TH>Source</TH>
                    <TH className="text-right">Total</TH>
                    <TH className="text-right">Critical</TH>
                    <TH className="text-right">High</TH>
                  </TR>
                </THead>
                <TBody>
                  {report.ioc_sources.map((s, i) => (
                    <TR key={s.source ?? i}>
                      <TD>{s.source}</TD>
                      <TD mono className="text-right">{fmtInt(s.total)}</TD>
                      <TD mono className="text-right">{fmtInt(s.critical)}</TD>
                      <TD mono className="text-right">{fmtInt(s.high)}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            ) : (
              <div className="px-4 py-3 text-data text-dim2">No IOC source data.</div>
            )}
          </Panel>

          <Panel className="overflow-hidden">
            <div className="px-4 pt-3 text-title text-ink">Top MITRE techniques</div>
            {report.top_mitre_techniques.length > 0 ? (
              <Table className="mt-2">
                <THead>
                  <TR>
                    <TH>Technique</TH>
                    <TH className="text-right">Detections</TH>
                    <TH className="text-right">True positives</TH>
                  </TR>
                </THead>
                <TBody>
                  {report.top_mitre_techniques.map((t, i) => (
                    <TR key={t.id ?? i}>
                      <TD>
                        <span className="font-mono text-ink">{t.id}</span>
                        {t.name && <span className="text-dim2"> · {t.name}</span>}
                      </TD>
                      <TD mono className="text-right">{fmtInt(t.detections)}</TD>
                      <TD mono className="text-right">{fmtInt(t.true_positives)}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            ) : (
              <div className="px-4 py-3 text-data text-dim2">No technique data.</div>
            )}
          </Panel>

          <Panel className="overflow-hidden">
            <div className="px-4 pt-3 text-title text-ink">Trending threats · last 7 days</div>
            {report.trending_threats.length > 0 ? (
              <Table className="mt-2">
                <THead>
                  <TR>
                    <TH>Source</TH>
                    <TH>Type</TH>
                    <TH>Severity</TH>
                    <TH className="text-right">Count</TH>
                  </TR>
                </THead>
                <TBody>
                  {report.trending_threats.map((t, i) => (
                    <TR key={i}>
                      <TD mono>{t.source ?? DASH}</TD>
                      <TD mono>{t.ioc_type ?? DASH}</TD>
                      <TD>{t.severity ?? DASH}</TD>
                      <TD mono className="text-right">{fmtInt(t.count)}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            ) : (
              <div className="px-4 py-3 text-data text-dim2">No trending threats.</div>
            )}
          </Panel>
        </>
      ) : null}
    </div>
  );
}

/** Small day-window chip group shared by the LLM + strategic-TI sub-views. */
function WindowChips({
  days,
  onPick,
  label,
}: {
  days: number;
  onPick: (d: number) => void;
  label: string;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="text-kbd uppercase tracking-wider text-dim2">{label}</span>
      <div className="flex gap-1.5" role="group" aria-label={label}>
        {LLM_WINDOWS.map((d) => (
          <Chip
            key={d}
            variant={days === d ? "cite" : "default"}
            onClick={() => onPick(d)}
            aria-label={`Last ${d} days`}
          >
            {d}d
          </Chip>
        ))}
      </div>
    </div>
  );
}
