/**
 * HUNT FIXTURE — screenshot / dev-preview only (WO-U9c).
 *
 * Reached solely from `api.ts::getHunt{Findings,Library}` when
 * `NEXT_PUBLIC_DHRUVA_FIXTURES` is set, via dynamic import so it is
 * dead-code-eliminated from a normal production bundle. The real path calls the
 * live `GET /api/hunt/{findings,library}`; this only lets the UI states be
 * captured without a backend.
 *
 * Fabricates NO capability — it mirrors the `hunt_findings` row shape exactly
 * (`store.py`): `confirmed` as int 0/1, `result_count` as the OpenSearch hit
 * count, `priority`/`status` strings, plus the `hunt_hypothesis_library` row for
 * the saved-query panel.
 *
 * `locked: true` (env `NEXT_PUBLIC_DHRUVA_FIXTURES=locked`) THROWS an ApiError(403)
 * shaped like the real `require_license_feature("hunt")` gate — but ONLY for the
 * gated findings endpoint (the library is not `hunt`-gated).
 */

import { ApiError } from "../api";
import type {
  HuntFinding,
  HuntFindingsResponse,
  HuntHypothesis,
  HuntLibraryResponse,
} from "../types";

interface Opts {
  empty?: boolean;
  locked?: boolean;
}

function lockedError(): never {
  throw new ApiError(
    403,
    "Threat hunting is not available on this plan. Contact SecureSleuths to upgrade.",
  );
}

const FINDINGS: HuntFinding[] = [
  {
    id: "hf-9a12",
    hunt_cycle_id: "hc-2026-07-01",
    hypothesis:
      "Scheduled-task persistence created outside a change window on finance workstations",
    mitre_technique: "T1053.005",
    priority: "high",
    query_index: "wazuh-alerts-4.x-*",
    query_body: null,
    result_count: 7,
    results_summary:
      "7 schtasks.exe creations on 3 FIN-WKS hosts between 02:10–02:40 UTC, none matching a known deployment job.",
    status: "confirmed",
    confirmed: 1,
    analyst_notes: "Confirmed — matches the after-hours pattern from last month's IR.",
    created_at: "2026-07-01T03:05:00Z",
    reviewed_at: "2026-07-01T09:20:00Z",
  },
  {
    id: "hf-7c44",
    hunt_cycle_id: "hc-2026-07-01",
    hypothesis: "LSASS access by non-standard processes (possible credential dumping)",
    mitre_technique: "T1003.001",
    priority: "critical",
    query_index: "wazuh-alerts-4.x-*",
    query_body: null,
    result_count: 2,
    results_summary:
      "2 handle-open events to lsass.exe from an unsigned binary in %TEMP% on DC-02.",
    status: "open",
    confirmed: 0,
    analyst_notes: null,
    created_at: "2026-07-01T03:05:00Z",
    reviewed_at: null,
  },
  {
    id: "hf-5f08",
    hunt_cycle_id: "hc-2026-06-30",
    hypothesis: "Outbound DNS volume anomaly suggestive of tunnelling",
    mitre_technique: "T1071.004",
    priority: "medium",
    query_index: "wazuh-alerts-4.x-*",
    query_body: null,
    result_count: 0,
    results_summary: "No hosts exceeded the per-host TXT-record baseline in the window.",
    status: "dismissed",
    confirmed: 0,
    analyst_notes: "Benign — matched a new monitoring agent's heartbeat.",
    created_at: "2026-06-30T03:05:00Z",
    reviewed_at: "2026-06-30T14:02:00Z",
  },
];

const HYPOTHESES: HuntHypothesis[] = [
  {
    id: "hyp-01",
    hypothesis: "New service installed on a domain controller",
    mitre_technique: "T1543.003",
    query_index: "wazuh-alerts-4.x-*",
    success_count: 4,
    last_success_at: "2026-06-28T03:05:00Z",
    tags: ["persistence", "windows", "dc"],
    created_at: "2026-02-11T10:00:00Z",
  },
  {
    id: "hyp-02",
    hypothesis: "PowerShell download-cradle from an office document parent",
    mitre_technique: "T1059.001",
    query_index: "wazuh-alerts-4.x-*",
    success_count: 2,
    last_success_at: "2026-06-19T03:05:00Z",
    tags: ["execution", "phishing"],
    created_at: "2026-03-04T10:00:00Z",
  },
  {
    id: "hyp-03",
    hypothesis: "Kerberoasting — anomalous TGS requests for service accounts",
    mitre_technique: "T1558.003",
    query_index: "wazuh-alerts-4.x-*",
    success_count: 0,
    last_success_at: null,
    tags: ["credential-access", "ad"],
    created_at: "2026-05-22T10:00:00Z",
  },
];

export function huntFindingsFixture(opts: Opts): HuntFindingsResponse {
  if (opts.locked) lockedError();
  if (opts.empty) return { findings: [], total: 0 };
  return { findings: FINDINGS, total: FINDINGS.length };
}

export function huntLibraryFixture(opts: Opts): HuntLibraryResponse {
  // The library is NOT hunt-gated, so it never throws under "locked".
  if (opts.empty) return { hypotheses: [], total: 0 };
  return { hypotheses: HYPOTHESES, total: HYPOTHESES.length };
}
