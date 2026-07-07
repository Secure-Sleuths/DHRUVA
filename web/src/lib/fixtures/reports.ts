/**
 * Reports FIXTURE — screenshot / dev-preview only (WO-U9c).
 *
 * Reached solely from `api.ts::getSocReport` when `NEXT_PUBLIC_DHRUVA_FIXTURES`
 * is set, via dynamic import so it is dead-code-eliminated from a normal
 * production bundle. The real path calls the live
 * `GET /api/metrics/reports/{daily|weekly|monthly}`.
 *
 * Mirrors `src/reports/generator.py` shapes exactly — daily carries the leaf
 * fields; weekly nests a `daily_snapshot`; monthly nests a `weekly_snapshot`.
 * Fabricates NO capability the backend lacks. `locked: true`
 * (env `NEXT_PUBLIC_DHRUVA_FIXTURES=locked`) THROWS an ApiError(403) shaped like
 * the real `require_license_feature("reports")` gate.
 */

import { ApiError } from "../api";
import type { SocReport, SocReportType } from "../types";

interface Opts {
  empty?: boolean;
  locked?: boolean;
}

function lockedError(): never {
  throw new ApiError(
    403,
    "SOC reports are not available on this plan. Contact SecureSleuths to upgrade.",
  );
}

const DAILY: SocReport = {
  type: "daily",
  generated_at: "2026-07-02T06:00:00Z",
  period: "Last 24 hours",
  alerts: {
    total: 214,
    true_positives: 22,
    false_positives: 151,
    auto_closed: 148,
    escalated: 9,
    avg_confidence: 0.83,
  },
  incidents: { new: 6, critical: 2, high: 3, resolved: 4, currently_open: 11 },
  mtt_metrics: {
    mttd_min: 4.9,
    mtta_min: 12.6,
    mttr_min: 111.3,
    sla_response_compliance: 94.0,
    sla_resolution_compliance: 88.0,
    sample_count: 8,
  },
  top_noisy_rules: [
    { rule_id: 100120, description: "OSSEC agent started", fp_count: 88 },
    { rule_id: 100210, description: "SSH authentication failure", fp_count: 41 },
    { rule_id: 5501, description: "PAM: Login session opened", fp_count: 27 },
  ],
};

const WEEKLY: SocReport = {
  type: "weekly",
  generated_at: "2026-07-02T06:00:00Z",
  period: "Last 7 days",
  daily_snapshot: DAILY,
  weekly_mtt: {
    mttd_min: 5.1,
    mtta_min: 13.6,
    mttr_min: 118.2,
    sla_response_compliance: 91.5,
    sla_resolution_compliance: 85.3,
    sample_count: 87,
  },
  detection_engineering: {
    proposals_created: 14,
    proposals_deployed: 6,
    proposals_approved: 9,
  },
  threat_hunting: {
    findings_total: 33,
    findings_hits: 12,
    findings_confirmed: 6,
  },
  automation_rates: {
    period_days: 7,
    total_decisions: 1382,
    auto_closed: 968,
    auto_close_rate: 70.0,
    enrichment_automation_pct: 100.0,
    false_positives: 831,
    true_positives: 141,
  },
};

const MONTHLY: SocReport = {
  type: "monthly",
  generated_at: "2026-07-02T06:00:00Z",
  period: "Last 30 days",
  weekly_snapshot: WEEKLY,
  monthly_mtt: {
    mttd_min: 6.4,
    mtta_min: 15.2,
    mttr_min: 132.7,
    sla_response_compliance: 90.1,
    sla_resolution_compliance: 83.9,
    sample_count: 341,
  },
  analyst_performance: [
    { actor: "j.okafor", incidents_touched: 41, resolved_count: 33, total_actions: 128 },
    { actor: "m.rossi", incidents_touched: 28, resolved_count: 19, total_actions: 87 },
    { actor: "s.tan", incidents_touched: 17, resolved_count: 12, total_actions: 54 },
  ],
  mitre_coverage: {
    total_techniques: 210,
    active: 143,
    stale: 41,
    noisy: 26,
    coverage_pct: 68.1,
  },
  sla_compliance: {
    total_resolved: 298,
    response_met: 271,
    resolution_met: 249,
    response_compliance_pct: 90.9,
    resolution_compliance_pct: 83.6,
  },
};

const BY_TYPE: Record<SocReportType, SocReport> = {
  daily: DAILY,
  weekly: WEEKLY,
  monthly: MONTHLY,
};

/** An honest "no data yet" report — valid shape, all-zero leaf figures. */
function emptyReport(type: SocReportType): SocReport {
  const leaf: SocReport = {
    type: "daily",
    generated_at: "2026-07-02T06:00:00Z",
    period: "Last 24 hours",
    alerts: {
      total: 0,
      true_positives: 0,
      false_positives: 0,
      auto_closed: 0,
      escalated: 0,
      avg_confidence: 0,
    },
    incidents: { new: 0, critical: 0, high: 0, resolved: 0, currently_open: 0 },
    mtt_metrics: {},
    top_noisy_rules: [],
  };
  if (type === "daily") return leaf;
  if (type === "weekly") {
    return {
      type: "weekly",
      generated_at: leaf.generated_at,
      period: "Last 7 days",
      daily_snapshot: leaf,
      weekly_mtt: {},
      detection_engineering: {
        proposals_created: 0,
        proposals_deployed: 0,
        proposals_approved: 0,
      },
      threat_hunting: { findings_total: 0, findings_hits: 0, findings_confirmed: 0 },
      automation_rates: {},
    };
  }
  return {
    type: "monthly",
    generated_at: leaf.generated_at,
    period: "Last 30 days",
    weekly_snapshot: {
      type: "weekly",
      generated_at: leaf.generated_at,
      period: "Last 7 days",
      daily_snapshot: leaf,
    },
    monthly_mtt: {},
    analyst_performance: [],
    mitre_coverage: { total_techniques: 0, active: 0, stale: 0, noisy: 0, coverage_pct: 0 },
    sla_compliance: {
      total_resolved: 0,
      response_met: 0,
      resolution_met: 0,
      response_compliance_pct: 0,
      resolution_compliance_pct: 0,
    },
  };
}

export function socReportFixture(type: SocReportType, opts: Opts): SocReport {
  if (opts.locked) lockedError();
  return opts.empty ? emptyReport(type) : BY_TYPE[type];
}
