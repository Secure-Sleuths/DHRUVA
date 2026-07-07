/**
 * Metrics FIXTURE — screenshot / dev-preview only (WO-U9).
 *
 * Reached solely from `api.ts::{getSocSummary,getAutomationRates,
 * getDashboardStats}` when `NEXT_PUBLIC_DHRUVA_FIXTURES` is set, via dynamic
 * import so it is dead-code-eliminated from a normal production bundle. The real
 * path calls the live `GET /api/metrics/soc-summary`, `/automation-rates`, and
 * `/api/dashboard/stats`.
 *
 * Fabricates NO capability — mirrors `store.py::compute_mtt_metrics` (minutes +
 * % SLA), `calculator.py::get_automation_rates`, and `store.py::
 * get_dashboard_stats`. There is NO LLM-cost field in ANY of these — the tab
 * shows an honest "not exposed by these endpoints" note rather than invent one.
 */

import type {
  AnalystPerformanceResponse,
  AnalystWorkloadResponse,
  AutomationHealth,
  AutomationRates,
  CaseAgingResponse,
  DashboardStats,
  HuntTrendsResponse,
  SocPerformanceResponse,
  SocSummaryResponse,
} from "../types";

interface Opts {
  empty?: boolean;
}

const SOC_SUMMARY: SocSummaryResponse = {
  today: {
    mttd_min: 4.2,
    mtta_min: 11.8,
    mttr_min: 96.4,
    sla_response_compliance: 94.0,
    sla_resolution_compliance: 88.0,
    sample_count: 12,
  },
  week: {
    mttd_min: 5.1,
    mtta_min: 13.6,
    mttr_min: 118.2,
    sla_response_compliance: 91.5,
    sla_resolution_compliance: 85.3,
    sample_count: 87,
  },
  month: {
    mttd_min: 6.4,
    mtta_min: 15.2,
    mttr_min: 132.7,
    sla_response_compliance: 90.1,
    sla_resolution_compliance: 83.9,
    sample_count: 341,
    by_severity: {
      critical: { count: 18, mttd_min: 2.1, mtta_min: 6.4, mttr_min: 74.0 },
      high: { count: 96, mttd_min: 4.8, mtta_min: 12.1, mttr_min: 110.5 },
      medium: { count: 152, mttd_min: 7.9, mtta_min: 18.3, mttr_min: 158.9 },
      low: { count: 75, mttd_min: 11.2, mtta_min: 24.0, mttr_min: 201.4 },
    },
  },
};

const EMPTY_MTT = { today: {}, week: {}, month: {} };

const AUTOMATION_RATES: AutomationRates = {
  period_days: 30,
  total_decisions: 5842,
  auto_closed: 4123,
  auto_close_rate: 70.6,
  enrichment_automation_pct: 100.0,
  false_positives: 3510,
  true_positives: 612,
};

const DASHBOARD_STATS: DashboardStats = {
  today: {
    total: 214,
    fps: 151,
    tps: 22,
    auto_closed: 148,
    escalated: 9,
    avg_confidence: 0.83,
  },
  weekly_trend: [
    { day: "2026-06-26", total: 188, fps: 130, tps: 18, avg_confidence: 0.81 },
    { day: "2026-06-27", total: 201, fps: 142, tps: 20, avg_confidence: 0.82 },
    { day: "2026-06-28", total: 176, fps: 121, tps: 15, avg_confidence: 0.8 },
    { day: "2026-06-29", total: 233, fps: 168, tps: 24, avg_confidence: 0.84 },
    { day: "2026-06-30", total: 219, fps: 155, tps: 21, avg_confidence: 0.83 },
    { day: "2026-07-01", total: 245, fps: 172, tps: 26, avg_confidence: 0.85 },
    { day: "2026-07-02", total: 214, fps: 151, tps: 22, avg_confidence: 0.83 },
  ],
  noisy_rules: [
    {
      rule_id: 100120,
      rule_description: "OSSEC agent started",
      total_alerts: 1880,
      fp_count: 1880,
      fp_rate: 1.0,
      tuning_action: "disable proposed",
    },
    {
      rule_id: 100210,
      rule_description: "SSH authentication failure",
      total_alerts: 214,
      fp_count: 214,
      fp_rate: 1.0,
      tuning_action: "tune proposed",
    },
    {
      rule_id: 5501,
      rule_description: "PAM: Login session opened",
      total_alerts: 640,
      fp_count: 602,
      fp_rate: 0.94,
      tuning_action: null,
    },
  ],
  pending_reviews: 7,
  pending_proposals: 3,
  open_incidents: 11,
  critical_incidents: 2,
  anomaly_count: 4,
};

export function socSummaryFixture(opts: Opts): SocSummaryResponse {
  return opts.empty ? EMPTY_MTT : SOC_SUMMARY;
}

export function automationRatesFixture(opts: Opts): AutomationRates {
  return opts.empty ? {} : AUTOMATION_RATES;
}

export function dashboardStatsFixture(opts: Opts): DashboardStats {
  if (opts.empty) {
    return {
      today: { total: 0, fps: 0, tps: 0, auto_closed: 0, escalated: 0, avg_confidence: 0 },
      weekly_trend: [],
      noisy_rules: [],
      pending_reviews: 0,
      pending_proposals: 0,
      open_incidents: 0,
      critical_incidents: 0,
      anomaly_count: 0,
    };
  }
  return DASHBOARD_STATS;
}

// -- Extended metrics fixtures (analyst / case-aging / hunt / automation) ------
// Mirror the calculator/store shapes exactly — fabricate no capability.

const ANALYST_PERFORMANCE: AnalystPerformanceResponse = {
  analysts: [
    { actor: "j.okafor", incidents_touched: 41, resolved_count: 33, total_actions: 128 },
    { actor: "m.rossi", incidents_touched: 28, resolved_count: 19, total_actions: 87 },
    { actor: "s.tan", incidents_touched: 17, resolved_count: 12, total_actions: 54 },
  ],
};

const ANALYST_WORKLOAD: AnalystWorkloadResponse = {
  analysts: [
    { analyst: "j.okafor", open_incidents: 18, critical: 3, high: 6, is_overloaded: true },
    { analyst: "m.rossi", open_incidents: 11, critical: 1, high: 4, is_overloaded: false },
    { analyst: "s.tan", open_incidents: 6, critical: 0, high: 2, is_overloaded: false },
  ],
};

const CASE_AGING: CaseAgingResponse = {
  cases: [
    {
      id: "inc-4712",
      title: "Suspicious PowerShell on FIN-DB-03",
      severity: "critical",
      status: "investigating",
      assigned_to: "j.okafor",
      created_at: "2026-06-29T02:14:00Z",
      first_response_at: "2026-06-29T02:41:00Z",
      alert_count: 9,
      hours_open: 71.8,
      is_stale: true,
    },
    {
      id: "inc-4750",
      title: "Repeated failed SSH from external ASN",
      severity: "high",
      status: "open",
      assigned_to: null,
      created_at: "2026-06-30T18:03:00Z",
      first_response_at: null,
      alert_count: 4,
      hours_open: 31.4,
      is_stale: false,
    },
    {
      id: "inc-4788",
      title: "Anomalous S3 egress volume",
      severity: "medium",
      status: "open",
      assigned_to: "m.rossi",
      created_at: "2026-07-01T09:20:00Z",
      first_response_at: "2026-07-01T10:05:00Z",
      alert_count: 2,
      hours_open: 15.9,
      is_stale: false,
    },
  ],
};

const HUNT_TRENDS: HuntTrendsResponse = {
  cycles: [
    {
      cycle_id: "hc-2026-07-01",
      total_hypotheses: 12,
      hits: 4,
      confirmed: 2,
      hit_rate: 33.3,
      confirmation_rate: 50.0,
      cycle_date: "2026-07-01T01:00:00Z",
    },
    {
      cycle_id: "hc-2026-06-24",
      total_hypotheses: 10,
      hits: 3,
      confirmed: 1,
      hit_rate: 30.0,
      confirmation_rate: 33.3,
      cycle_date: "2026-06-24T01:00:00Z",
    },
    {
      cycle_id: "hc-2026-06-17",
      total_hypotheses: 11,
      hits: 5,
      confirmed: 3,
      hit_rate: 45.5,
      confirmation_rate: 60.0,
      cycle_date: "2026-06-17T01:00:00Z",
    },
  ],
};

const AUTOMATION_HEALTH: AutomationHealth = {
  period_days: 7,
  enrichment_latency: {
    sample_count: 5842,
    p50_ms: 84.0,
    p95_ms: 312.5,
    p99_ms: 731.2,
    avg_ms: 121.7,
  },
  soar_actions: {
    total_actions: 214,
    success_count: 203,
    failure_count: 11,
    success_rate: 94.9,
  },
};

const SOC_PERFORMANCE: SocPerformanceResponse = {
  metrics: SOC_SUMMARY.month,
  trends: [
    { day: "2026-06-28", avg_mttd: 6.9, avg_mtta: 16.1, avg_mttr: 140.2, incident_count: 9, critical: 1, high: 3, medium: 4, low: 1 },
    { day: "2026-06-29", avg_mttd: 5.8, avg_mtta: 14.7, avg_mttr: 128.6, incident_count: 12, critical: 2, high: 4, medium: 5, low: 1 },
    { day: "2026-06-30", avg_mttd: 6.2, avg_mtta: 15.9, avg_mttr: 133.4, incident_count: 10, critical: 0, high: 3, medium: 5, low: 2 },
    { day: "2026-07-01", avg_mttd: 5.4, avg_mtta: 13.2, avg_mttr: 119.8, incident_count: 14, critical: 2, high: 5, medium: 6, low: 1 },
    { day: "2026-07-02", avg_mttd: 4.9, avg_mtta: 12.6, avg_mttr: 111.3, incident_count: 8, critical: 1, high: 2, medium: 4, low: 1 },
  ],
};

export function analystPerformanceFixture(opts: Opts): AnalystPerformanceResponse {
  return opts.empty ? { analysts: [] } : ANALYST_PERFORMANCE;
}

export function analystWorkloadFixture(opts: Opts): AnalystWorkloadResponse {
  return opts.empty ? { analysts: [] } : ANALYST_WORKLOAD;
}

export function caseAgingFixture(opts: Opts): CaseAgingResponse {
  return opts.empty ? { cases: [] } : CASE_AGING;
}

export function huntTrendsFixture(opts: Opts): HuntTrendsResponse {
  return opts.empty ? { cycles: [] } : HUNT_TRENDS;
}

export function automationHealthFixture(opts: Opts): AutomationHealth {
  if (opts.empty) {
    return {
      period_days: 7,
      enrichment_latency: {},
      soar_actions: { total_actions: 0, success_count: 0, failure_count: 0 },
    };
  }
  return AUTOMATION_HEALTH;
}

export function socPerformanceFixture(opts: Opts): SocPerformanceResponse {
  return opts.empty ? { metrics: {}, trends: [] } : SOC_PERFORMANCE;
}
