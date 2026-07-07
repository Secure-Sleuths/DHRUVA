/**
 * MITRE coverage FIXTURE — screenshot / dev-preview only (WO-U8).
 *
 * Reached solely from `api.ts::{getMitreSummary,getMitreIncidentCoverage,
 * getMitreGaps}` when `NEXT_PUBLIC_DHRUVA_FIXTURES` is set, via dynamic import so
 * it is dead-code-eliminated from a normal production bundle. The real path calls
 * the live `/api/mitre/*` endpoints; this only lets the UI states be captured
 * without a backend.
 *
 * Fabricates NO capability — it mirrors the WO-B6 response shapes exactly:
 *   - per-tactic coverage uses the FULL ATT&CK tactic NAMES + TA-ids the backend
 *     emits (`src/mitre/matrix.py`), in canonical kill-chain order;
 *   - the numbers are self-consistent (coverage_pct = detected/total·100) and
 *     line up with the campaigns fixture so the overlay + priority-gap read true;
 *   - the incident-coverage chain is exactly what `build_incident_chain_coverage`
 *     would produce for INC-204's observed tactics, with ORG-WIDE org_coverage_pct.
 *
 * `locked: true` (env `NEXT_PUBLIC_DHRUVA_FIXTURES=locked`) THROWS an ApiError(403)
 * shaped like the real `mitre` license gate, so the tier-locked degradation can be
 * captured through the tab's real error path — no fabricated "locked" UI.
 */

import { ApiError } from "../api";
import type {
  MitreCoverageHeatmap,
  MitreGaps,
  MitreHeatmapTactic,
  MitreIncidentCoverage,
  MitreSummary,
  MitreTacticCoverage,
} from "../types";

interface Opts {
  empty?: boolean;
  locked?: boolean;
}

/** The exact 403 the `require_license_feature("mitre")` gate raises. */
function lockedError(): never {
  throw new ApiError(
    403,
    "MITRE ATT&CK is not available on this plan. Contact SecureSleuths to upgrade.",
  );
}

// Full backend tactic set (matrix.py MITRE_TACTICS) in canonical order, with
// TA-ids and coverage self-consistent as detected/total·100 (total 20 each).
const PER_TACTIC: MitreTacticCoverage[] = [
  ["Reconnaissance", "TA0043", 8],
  ["Resource Development", "TA0042", 5],
  ["Initial Access", "TA0001", 16],
  ["Execution", "TA0002", 14],
  ["Persistence", "TA0003", 15],
  ["Privilege Escalation", "TA0004", 9],
  ["Defense Evasion", "TA0005", 11],
  ["Credential Access", "TA0006", 18],
  ["Discovery", "TA0007", 7],
  ["Lateral Movement", "TA0008", 12],
  ["Collection", "TA0009", 6],
  ["Command and Control", "TA0011", 10],
  ["Exfiltration", "TA0010", 3],
  ["Impact", "TA0040", 2],
].map(([tactic, tactic_id, detected]) => ({
  tactic: tactic as string,
  tactic_id: tactic_id as string,
  total: 20,
  detected: detected as number,
  coverage_pct: Math.round(((detected as number) / 20) * 1000) / 10,
}));

const SUMMARY: MitreSummary = {
  per_tactic: PER_TACTIC,
  overall: {
    total_techniques: PER_TACTIC.length * 20,
    detected: PER_TACTIC.reduce((n, t) => n + t.detected, 0),
    coverage_pct:
      Math.round(
        (PER_TACTIC.reduce((n, t) => n + t.detected, 0) /
          (PER_TACTIC.length * 20)) *
          1000,
      ) / 10,
  },
};

const EMPTY_SUMMARY: MitreSummary = {
  per_tactic: [],
  overall: {},
};

export function mitreSummaryFixture(opts: Opts): MitreSummary {
  if (opts.locked) lockedError();
  return opts.empty ? EMPTY_SUMMARY : SUMMARY;
}

// Org-wide per-tactic coverage lookup (same numbers as the summary fixture) —
// the overlay `build_incident_chain_coverage` applies. ≥50 covered, <50 a gap.
const ORG_PCT: Record<string, number> = Object.fromEntries(
  PER_TACTIC.map((t) => [t.tactic, t.coverage_pct]),
);

/**
 * INC-204's observed tactics = [Credential Access, Persistence, Lateral
 * Movement]. Canonically ordered + spanned (Persistence…Lateral Movement) with
 * unseen intermediate tactics filled in — exactly `build_incident_chain_coverage`.
 */
const INC_204_COVERAGE: MitreIncidentCoverage = {
  incident_id: "INC-204",
  chain: [
    { tactic: "Persistence", tactic_id: "TA0003", present_in_incident: true, org_coverage_pct: ORG_PCT["Persistence"] },
    { tactic: "Privilege Escalation", tactic_id: "TA0004", present_in_incident: false, org_coverage_pct: ORG_PCT["Privilege Escalation"], is_gap: true },
    { tactic: "Defense Evasion", tactic_id: "TA0005", present_in_incident: false, org_coverage_pct: ORG_PCT["Defense Evasion"], is_gap: true },
    { tactic: "Credential Access", tactic_id: "TA0006", present_in_incident: true, org_coverage_pct: ORG_PCT["Credential Access"] },
    { tactic: "Discovery", tactic_id: "TA0007", present_in_incident: false, org_coverage_pct: ORG_PCT["Discovery"], is_gap: true },
    { tactic: "Lateral Movement", tactic_id: "TA0008", present_in_incident: true, org_coverage_pct: ORG_PCT["Lateral Movement"] },
  ],
  covered_count: 3,
  chain_length: 6,
  weakest_tactic: "Discovery", // lowest KNOWN org % in the span (35.0)
  furthest_tactic: "Lateral Movement",
  coverage_basis: "org_wide",
};

/** INC-176 (brute force campaign) — a single observed stage. */
const INC_176_COVERAGE: MitreIncidentCoverage = {
  incident_id: "INC-176",
  chain: [
    { tactic: "Initial Access", tactic_id: "TA0001", present_in_incident: true, org_coverage_pct: ORG_PCT["Initial Access"] },
  ],
  covered_count: 1,
  chain_length: 1,
  weakest_tactic: "Initial Access",
  furthest_tactic: "Initial Access",
  coverage_basis: "org_wide",
};

const EMPTY_COVERAGE = (id: string): MitreIncidentCoverage => ({
  incident_id: id,
  chain: [],
  covered_count: 0,
  chain_length: 0,
  weakest_tactic: null,
  furthest_tactic: null,
  coverage_basis: "org_wide",
});

export function mitreIncidentCoverageFixture(
  incidentId: string,
  opts: Opts,
): MitreIncidentCoverage {
  if (opts.locked) lockedError();
  if (opts.empty) return EMPTY_COVERAGE(incidentId);
  if (incidentId === "INC-176") return INC_176_COVERAGE;
  // Default (incl. INC-204) → the credential-harvest chain.
  return { ...INC_204_COVERAGE, incident_id: incidentId };
}

const GAPS: MitreGaps = {
  gaps: {
    Discovery: [
      { id: "T1087", name: "Account Discovery" },
      { id: "T1018", name: "Remote System Discovery" },
      { id: "T1046", name: "Network Service Discovery" },
    ],
    Exfiltration: [
      { id: "T1048", name: "Exfiltration Over Alternative Protocol" },
      { id: "T1041", name: "Exfiltration Over C2 Channel" },
    ],
    Impact: [
      { id: "T1486", name: "Data Encrypted for Impact" },
      { id: "T1490", name: "Inhibit System Recovery" },
    ],
    Collection: [{ id: "T1005", name: "Data from Local System" }],
  },
  total_gaps: 8,
  total_techniques: 280,
  coverage_pct: 48.6,
};

export function mitreGapsFixture(opts: Opts): MitreGaps {
  if (opts.locked) lockedError();
  if (opts.empty) return { gaps: {}, total_gaps: 0, total_techniques: 280, coverage_pct: 100 };
  return GAPS;
}

// ---- Technique heatmap (GET /api/mitre/coverage → get_heatmap_data) ---------
// Derived from the SAME PER_TACTIC numbers as the summary fixture so the tactic
// coverage % and the per-technique cells read consistently. Two representative
// techniques per tactic: one detected (with TP/FP/last-seen), one not_detected —
// so the heatmap + per-technique detail states are both exercised. Nothing here
// fabricates a capability; it mirrors the WO get_heatmap_data shape exactly.
const HEATMAP_TACTICS: MitreHeatmapTactic[] = PER_TACTIC.map((t, i) => {
  const detected = t.detected > 0;
  return {
    tactic: t.tactic,
    tactic_id: t.tactic_id,
    techniques: [
      {
        id: `T${1000 + i * 2}`,
        name: `${t.tactic} technique A`,
        detection_count: detected ? 5 + i : 0,
        tp_count: detected ? 3 + (i % 3) : 0,
        fp_count: detected ? i % 2 : 0,
        status: detected ? (i % 4 === 0 ? "noisy" : "active") : "not_detected",
        last_seen: detected ? "2026-07-01T03:12:00Z" : null,
      },
      {
        id: `T${1001 + i * 2}`,
        name: `${t.tactic} technique B`,
        detection_count: 0,
        tp_count: 0,
        fp_count: 0,
        status: "not_detected",
        last_seen: null,
      },
    ],
  };
});

export function mitreCoverageFixture(opts: Opts): MitreCoverageHeatmap {
  if (opts.locked) lockedError();
  return opts.empty ? { tactics: [] } : { tactics: HEATMAP_TACTICS };
}
