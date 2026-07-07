/**
 * Threat Intel FIXTURE — screenshot / dev-preview only (WO-U9).
 *
 * Reached solely from `api.ts::{getTIStats,getTICves}` when
 * `NEXT_PUBLIC_DHRUVA_FIXTURES` is set, via dynamic import so it is
 * dead-code-eliminated from a normal production bundle. The real path calls the
 * live `GET /api/threat-intel/stats` + `GET /api/threat-intel/cve`.
 *
 * Fabricates NO capability — mirrors the `store.py::{get_ioc_stats,
 * get_feed_statuses,get_all_cves,get_kev_cves}` shapes exactly (int 0/1 flags for
 * enabled / in_cisa_kev / kev_ransomware).
 *
 * `locked: true` THROWS ApiError(403) shaped like the `ti_feeds_tier1` gate.
 */

import { ApiError } from "../api";
import type { TICve, TICvesResponse, TIStatsResponse } from "../types";

interface Opts {
  empty?: boolean;
  locked?: boolean;
  kevOnly?: boolean;
}

function lockedError(): never {
  throw new ApiError(
    403,
    "Threat-intel feeds are not available on this plan. Contact SecureSleuths to upgrade.",
  );
}

const STATS: TIStatsResponse = {
  stats: {
    total_iocs: 48213,
    by_source: [
      { source: "abuse.ch", count: 21044 },
      { source: "OTX AlienVault", count: 15320 },
      { source: "CISA KEV", count: 1112 },
      { source: "local", count: 10737 },
    ],
    by_type: [
      { ioc_type: "ip", count: 22890 },
      { ioc_type: "domain", count: 14002 },
      { ioc_type: "hash", count: 9321 },
      { ioc_type: "url", count: 2000 },
    ],
    by_severity: [
      { severity: "high", count: 8021 },
      { severity: "medium", count: 21990 },
      { severity: "low", count: 18202 },
    ],
  },
  feeds: [
    {
      id: 1,
      feed_name: "abuse.ch URLhaus",
      feed_type: "url",
      tier: 1,
      enabled: 1,
      requires_api_key: 0,
      last_fetch_at: "2026-07-02T05:30:00Z",
      last_success_at: "2026-07-02T05:30:00Z",
      last_ioc_count: 1204,
      total_ioc_count: 21044,
      error_count: 0,
      last_error: null,
      collection_interval_minutes: 60,
      status: "healthy",
      updated_at: "2026-07-02T05:30:00Z",
    },
    {
      id: 2,
      feed_name: "OTX AlienVault",
      feed_type: "mixed",
      tier: 1,
      enabled: 1,
      requires_api_key: 1,
      last_fetch_at: "2026-07-02T05:00:00Z",
      last_success_at: "2026-07-02T05:00:00Z",
      last_ioc_count: 890,
      total_ioc_count: 15320,
      error_count: 0,
      last_error: null,
      collection_interval_minutes: 120,
      status: "healthy",
      updated_at: "2026-07-02T05:00:00Z",
    },
    {
      id: 3,
      feed_name: "CISA Known Exploited Vulns",
      feed_type: "cve",
      tier: 1,
      enabled: 1,
      requires_api_key: 0,
      last_fetch_at: "2026-07-02T04:00:00Z",
      last_success_at: "2026-07-02T04:00:00Z",
      last_ioc_count: 6,
      total_ioc_count: 1112,
      error_count: 0,
      last_error: null,
      collection_interval_minutes: 720,
      status: "healthy",
      updated_at: "2026-07-02T04:00:00Z",
    },
    {
      id: 4,
      feed_name: "MISP (internal)",
      feed_type: "mixed",
      tier: 2,
      enabled: 1,
      requires_api_key: 1,
      last_fetch_at: "2026-07-02T03:10:00Z",
      last_success_at: "2026-07-01T15:10:00Z",
      last_ioc_count: 0,
      total_ioc_count: 4310,
      error_count: 3,
      last_error: "connection timed out after 30s (misp.internal:443)",
      collection_interval_minutes: 240,
      status: "degraded",
      updated_at: "2026-07-02T03:10:00Z",
    },
  ],
  kev_count: 1112,
};

const EMPTY_STATS: TIStatsResponse = {
  stats: { total_iocs: 0, by_source: [], by_type: [], by_severity: [] },
  feeds: [],
  kev_count: 0,
};

const CVES: TICve[] = [
  {
    cve_id: "CVE-2024-3400",
    description:
      "Command injection in the GlobalProtect feature of PAN-OS. Actively exploited in the wild.",
    severity: "Critical",
    cvss_score: 10.0,
    epss_score: 0.9421,
    epss_percentile: 0.999,
    in_cisa_kev: 1,
    kev_date_added: "2024-04-12",
    kev_due_date: "2024-04-19",
    kev_ransomware: 1,
    vendor: "Palo Alto Networks",
    product: "PAN-OS",
    updated_at: "2026-07-01T00:00:00Z",
  },
  {
    cve_id: "CVE-2023-4966",
    description:
      "Sensitive information disclosure in NetScaler ADC and Gateway ('Citrix Bleed').",
    severity: "Critical",
    cvss_score: 9.4,
    epss_score: 0.9388,
    epss_percentile: 0.998,
    in_cisa_kev: 1,
    kev_date_added: "2023-10-18",
    kev_due_date: "2023-11-08",
    kev_ransomware: 1,
    vendor: "Citrix",
    product: "NetScaler ADC",
    updated_at: "2026-06-30T00:00:00Z",
  },
  {
    cve_id: "CVE-2025-0282",
    description:
      "Stack-based buffer overflow in Ivanti Connect Secure allowing unauthenticated RCE.",
    severity: "Critical",
    cvss_score: 9.0,
    epss_score: 0.8123,
    epss_percentile: 0.987,
    in_cisa_kev: 1,
    kev_date_added: "2025-01-08",
    kev_due_date: "2025-01-15",
    kev_ransomware: 0,
    vendor: "Ivanti",
    product: "Connect Secure",
    updated_at: "2026-06-28T00:00:00Z",
  },
  {
    cve_id: "CVE-2024-21762",
    description:
      "Out-of-bounds write in FortiOS SSL VPN allowing remote code execution.",
    severity: "Critical",
    cvss_score: 9.6,
    epss_score: 0.7712,
    epss_percentile: 0.981,
    in_cisa_kev: 1,
    kev_date_added: "2024-02-09",
    kev_due_date: "2024-02-16",
    kev_ransomware: 0,
    vendor: "Fortinet",
    product: "FortiOS",
    updated_at: "2026-06-25T00:00:00Z",
  },
  {
    cve_id: "CVE-2024-1709",
    description:
      "Authentication bypass in ConnectWise ScreenConnect setup wizard.",
    severity: "High",
    cvss_score: 8.4,
    epss_score: 0.4523,
    epss_percentile: 0.94,
    in_cisa_kev: 0,
    kev_date_added: null,
    kev_due_date: null,
    kev_ransomware: 0,
    vendor: "ConnectWise",
    product: "ScreenConnect",
    updated_at: "2026-06-20T00:00:00Z",
  },
];

export function tiStatsFixture(opts: Opts): TIStatsResponse {
  if (opts.locked) lockedError();
  return opts.empty ? EMPTY_STATS : STATS;
}

export function tiCvesFixture(opts: Opts): TICvesResponse {
  if (opts.locked) lockedError();
  if (opts.empty) return { cves: [], total: 0 };
  const cves = opts.kevOnly ? CVES.filter((c) => Number(c.in_cisa_kev) === 1) : CVES;
  return { cves, total: cves.length };
}
