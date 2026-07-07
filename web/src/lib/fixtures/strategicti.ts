/**
 * Strategic Threat-Intel report FIXTURE — screenshot / dev-preview only
 * (parity-restore: Reports → Threat Intel strategic report).
 *
 * Reached solely from `api.ts::getTIStrategicReport` when
 * `NEXT_PUBLIC_DHRUVA_FIXTURES` is set, via dynamic import so it is
 * dead-code-eliminated from a normal production bundle. The real path calls the
 * live `GET /api/threat-intel/strategic-report` (require_role("admin",
 * "senior_analyst") + `ti_feeds_tier2` license).
 *
 * Mirrors `StrategicTIAnalyzer.generate_landscape_report()` EXACTLY — a FLAT
 * report (not wrapped in {report}); `alert_verdicts` has dynamic verdict keys.
 * Fabricates NO capability the backend lacks. `locked: true`
 * (env `NEXT_PUBLIC_DHRUVA_FIXTURES=locked`) THROWS an ApiError(403) shaped like
 * the real `require_license_feature("ti_feeds_tier2")` gate.
 */

import { ApiError } from "../api";
import type { TiStrategicReport } from "../types";

interface Opts {
  empty?: boolean;
  locked?: boolean;
  days?: number;
}

/** The exact 403 the `require_license_feature("ti_feeds_tier2")` gate raises. */
function lockedError(): never {
  throw new ApiError(
    403,
    "The strategic threat-intelligence report is not available on this plan. Contact SecureSleuths to upgrade.",
  );
}

export function tiStrategicReportFixture(opts: Opts): TiStrategicReport {
  if (opts.locked) lockedError();
  const days = opts.days ?? 30;
  if (opts.empty) {
    return {
      generated_at: "2026-07-03T06:00:00Z",
      period_days: days,
      industry: "financial_services",
      ioc_sources: [],
      alert_verdicts: {},
      top_mitre_techniques: [],
      trending_threats: [],
    };
  }
  return {
    generated_at: "2026-07-03T06:00:00Z",
    period_days: days,
    industry: "financial_services",
    ioc_sources: [
      { source: "CISA KEV", total: 1180, critical: 210, high: 460 },
      { source: "AlienVault OTX", total: 8640, critical: 120, high: 990 },
      { source: "Abuse.ch", total: 4020, critical: 60, high: 410 },
    ],
    alert_verdicts: {
      true_positive: 214,
      false_positive: 1806,
      auto_close: 1490,
      needs_investigation: 92,
    },
    top_mitre_techniques: [
      { id: "T1078", name: "Valid Accounts", detections: 142, true_positives: 31 },
      { id: "T1110", name: "Brute Force", detections: 98, true_positives: 12 },
      { id: "T1059", name: "Command and Scripting Interpreter", detections: 76, true_positives: 22 },
      { id: "T1486", name: "Data Encrypted for Impact", detections: 14, true_positives: 6 },
    ],
    trending_threats: [
      { source: "Abuse.ch", ioc_type: "domain", severity: "critical", count: 34, period_days: 7 },
      { source: "CISA KEV", ioc_type: "cve", severity: "high", count: 21, period_days: 7 },
      { source: "AlienVault OTX", ioc_type: "ip", severity: "high", count: 18, period_days: 7 },
    ],
  };
}
