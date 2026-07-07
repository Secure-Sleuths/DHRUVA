/**
 * Overview (Campaign Command) FIXTURE — screenshot / dev-preview only.
 *
 * Reached solely from `api.ts::{getOverviewSummary,getCampaigns}` when
 * `NEXT_PUBLIC_DHRUVA_FIXTURES` is set, via dynamic import so it is
 * dead-code-eliminated from a normal production bundle. The real code path
 * calls `GET /api/overview/summary` and `GET /api/campaigns`; this only lets the
 * UI states be captured without a live backend.
 *
 * It fabricates NO capability — it mirrors the WO-B5 / WO-B7 response shapes
 * exactly (tactic NAMES only, no per-node technique/host/confidence; `of_total`
 * null; `projected_next_tactic` = the kill-chain-order heuristic). The KPI
 * numbers are self-consistent with the campaigns below (e.g. hosts_on_chain
 * counts distinct hosts across the ACTIVE campaigns only, so the CONTAINED
 * campaign's host is excluded — exactly what build_overview_summary does).
 *
 * Ported from the approved mockup's `CAMPAIGNS`, re-expressed in the real API
 * shape so the campaign→lane adapter (campaign.ts::adaptCampaign) is exercised.
 */

import type {
  ApiCampaign,
  CampaignsResponse,
  OverviewSummary,
} from "../types";

const CAMPAIGNS: ApiCampaign[] = [
  {
    attack_chain_id: "7f3a-204",
    name: "Credential harvest on WIN-APP-03",
    title: "Credential harvest on WIN-APP-03",
    severity: "critical",
    severity_rank: 3,
    p: "P0",
    severity_label: "Critical",
    status: "active",
    member_count: 3,
    member_incidents: [
      {
        id: "INC-204",
        title: "OS Credential Dumping (LSASS) on WIN-APP-03",
        severity: "critical",
        status: "investigating",
        first_seen: "2026-07-02T02:14:00Z",
        last_seen: "2026-07-02T02:41:00Z",
        alert_count: 3,
      },
    ],
    // Ordered ATT&CK TACTIC names (canonical kill-chain order) — no techniques.
    tactic_sequence: ["Credential Access", "Persistence", "Lateral Movement"],
    furthest_tactic: "Lateral Movement",
    projected_next_tactic: "Collection", // next unseen tactic after Lateral Movement
    projection_basis: "kill_chain_order_heuristic",
    assets: {
      hosts: ["WIN-APP-03", "svc-deploy", "10.4.2.19"],
      users: ["svc-deploy"],
      ips: ["10.4.2.19"],
    },
    alert_count: 3,
    first_seen: "2026-07-02T02:14:00Z",
    last_seen: "2026-07-02T02:41:00Z",
    dwell_seconds: 22320, // 6h 12m
    dwell: "6h 12m",
  },
  {
    attack_chain_id: "91be-198",
    name: "Phishing → macro exec on FIN-WKS-11",
    title: "Phishing → macro exec on FIN-WKS-11",
    severity: "high",
    severity_rank: 2,
    p: "P1",
    severity_label: "High",
    status: "contained",
    member_count: 2,
    member_incidents: [
      {
        id: "INC-198",
        title: "Phishing attachment on FIN-WKS-11",
        severity: "high",
        status: "resolved",
        first_seen: "2026-07-01T21:02:00Z",
        last_seen: "2026-07-01T21:03:00Z",
        alert_count: 2,
      },
    ],
    tactic_sequence: ["Initial Access", "Execution"],
    furthest_tactic: "Execution",
    projected_next_tactic: "Persistence",
    projection_basis: "kill_chain_order_heuristic",
    assets: {
      hosts: ["FIN-WKS-11", "mail-relay"],
      users: [],
      ips: [],
    },
    alert_count: 2,
    first_seen: "2026-07-01T21:02:00Z",
    last_seen: "2026-07-01T21:03:00Z",
    dwell_seconds: 68580, // 19h 03m
    dwell: "19h 3m",
  },
  {
    attack_chain_id: "5c20-176",
    name: "Brute force on VPN-GW-01",
    title: "Brute force on VPN-GW-01",
    severity: "medium",
    severity_rank: 1,
    p: "P2",
    severity_label: "Medium",
    status: "active",
    member_count: 1,
    member_incidents: [
      {
        id: "INC-176",
        title: "Multiple failed logins then success on VPN-GW-01",
        severity: "medium",
        status: "open",
        first_seen: "2026-07-02T05:44:00Z",
        last_seen: "2026-07-02T05:44:00Z",
        alert_count: 1,
      },
    ],
    tactic_sequence: ["Initial Access"],
    furthest_tactic: "Initial Access",
    projected_next_tactic: "Execution",
    projection_basis: "kill_chain_order_heuristic",
    assets: {
      hosts: ["VPN-GW-01"],
      users: [],
      ips: [],
    },
    alert_count: 1,
    first_seen: "2026-07-02T05:44:00Z",
    last_seen: "2026-07-02T05:44:00Z",
    dwell_seconds: 9600, // 2h 40m
    dwell: "2h 40m",
  },
];

// KPI strip, self-consistent with CAMPAIGNS (as build_overview_summary derives):
//  active = 7f3a-204 + 5c20-176 (2) · contained = 91be-198 (1)
//  worst active dwell = 7f3a-204 (6h 12m)
//  hosts on an ACTIVE chain = WIN-APP-03, svc-deploy, 10.4.2.19, VPN-GW-01 (4)
//    — FIN-WKS-11/mail-relay excluded (that campaign is contained)
//  furthest active tactic (canonical order) = Lateral Movement (7f3a-204)
const SUMMARY: OverviewSummary = {
  active_campaigns: { value: 3, advancing: 2, contained: 1 },
  estate_dwell_worst: {
    value_seconds: 22320,
    value: "6h 12m",
    campaign: {
      attack_chain_id: "7f3a-204",
      name: "Credential harvest on WIN-APP-03",
    },
  },
  hosts_on_chain: {
    value: 4,
    hosts: ["WIN-APP-03", "svc-deploy", "10.4.2.19", "VPN-GW-01"],
    of_total: null, // no cheap tenant-scoped monitored count (see contract)
  },
  furthest_tactic: {
    value: "Lateral Movement",
    campaign: {
      attack_chain_id: "7f3a-204",
      name: "Credential harvest on WIN-APP-03",
    },
    exfil_or_impact_reached: false,
  },
  open_incidents: { value: 4, critical: 1 },
};

const EMPTY_SUMMARY: OverviewSummary = {
  active_campaigns: { value: 0, advancing: 0, contained: 0 },
  estate_dwell_worst: { value_seconds: null, value: null, campaign: null },
  hosts_on_chain: { value: 0, hosts: [], of_total: null },
  furthest_tactic: { value: null, campaign: null, exfil_or_impact_reached: false },
  open_incidents: { value: 0, critical: 0 },
};

export function overviewSummaryFixture(opts: {
  empty?: boolean;
}): OverviewSummary {
  return opts.empty ? EMPTY_SUMMARY : SUMMARY;
}

export function campaignsFixture(opts: { empty?: boolean }): CampaignsResponse {
  if (opts.empty) return { campaigns: [], total: 0 };
  return { campaigns: CAMPAIGNS, total: CAMPAIGNS.length };
}
