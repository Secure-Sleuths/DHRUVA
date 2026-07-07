/**
 * Incidents (glass-box case) FIXTURE — screenshot / dev-preview only.
 *
 * Reached solely from `api.ts::{getIncidents,getIncident}` when
 * `NEXT_PUBLIC_DHRUVA_FIXTURES` is set, via dynamic import so it is
 * dead-code-eliminated from a normal production bundle. The real code path calls
 * `GET /api/incidents` and `GET /api/incidents/{id}`; this only lets the UI
 * states be captured without a live backend.
 *
 * It fabricates NO capability — it mirrors the real response shapes EXACTLY:
 *  - list rows are raw `incidents` rows (array columns as JSON-encoded TEXT),
 *  - detail member alerts are raw `agent_decisions` rows (un-flattened
 *    `enrichment_summary` JSON blob) with WO-B4 `glass_box` + WO-B9
 *    `anonymized_fields` attached, exactly as `routes/incidents.py` does.
 *
 * The INC-204 case is ported verbatim from the approved mockup's `incidentCard`
 * (risk 87 = 30 base × 2.1 asset × 1.8 TI × 1.4 anomaly → 158.8 → 87). It is
 * deliberately built so a screenshot shows BOTH review-gate states in one case:
 *  - the primary alert has NO `human_verdict` → the analyst+ "first verdict" flow,
 *  - a member alert already has a `human_verdict` → the WO-B10 admin-only override.
 */

import type {
  IncidentAlert,
  IncidentDetail,
  IncidentListRow,
  IncidentsResponse,
} from "../types";

const j = (arr: string[]) => JSON.stringify(arr); // mirror JSON-encoded TEXT cols

const INCIDENTS: IncidentListRow[] = [
  {
    id: "INC-204",
    title: "OS Credential Dumping (LSASS) on WIN-APP-03",
    severity: "critical",
    status: "investigating",
    first_seen: "2026-07-02T02:14:00Z",
    last_seen: "2026-07-02T02:41:00Z",
    alert_count: 3,
    attack_chain_id: "7f3a-204",
    mitre_tactics: j(["Credential Access", "Persistence", "Lateral Movement"]),
    affected_hosts: j(["WIN-APP-03"]),
    assigned_to: null,
    created_at: "2026-07-02T02:14:00Z",
    tier: "L2",
  },
  {
    id: "INC-198",
    title: "Phishing attachment then macro execution on FIN-WKS-11",
    severity: "high",
    status: "resolved",
    first_seen: "2026-07-01T21:02:00Z",
    last_seen: "2026-07-01T21:03:00Z",
    alert_count: 2,
    attack_chain_id: "91be-198",
    mitre_tactics: j(["Initial Access", "Execution"]),
    affected_hosts: j(["FIN-WKS-11"]),
    assigned_to: "j.rivera",
    created_at: "2026-07-01T21:02:00Z",
    tier: "L1",
    flagged_interesting: true,
    interesting_notes:
      "Clean macro-execution chain — good training example for the phishing playbook.",
  },
  {
    id: "INC-176",
    title: "Multiple failed logins then success on VPN-GW-01",
    severity: "medium",
    status: "open",
    first_seen: "2026-07-02T05:44:00Z",
    last_seen: "2026-07-02T05:44:00Z",
    alert_count: 1,
    attack_chain_id: "5c20-176",
    mitre_tactics: j(["Initial Access"]),
    affected_hosts: j(["VPN-GW-01"]),
    assigned_to: null,
    created_at: "2026-07-02T05:44:00Z",
    tier: "L1",
  },
  {
    id: "INC-152",
    title: "Benign administrative PowerShell on FIN-WKS-07",
    severity: "low",
    status: "open",
    first_seen: "2026-07-01T18:20:00Z",
    last_seen: "2026-07-01T18:20:00Z",
    alert_count: 1,
    // standalone incident — NOT correlated into a campaign (no chip)
    attack_chain_id: null,
    mitre_tactics: j(["Execution"]),
    affected_hosts: j(["FIN-WKS-07"]),
    assigned_to: null,
    created_at: "2026-07-01T18:20:00Z",
    tier: "L1",
  },
];

// enrichment_summary is the raw JSON-string blob (as the DB stores it); the case
// view parses host / src_ip / MITRE from it (incident.ts::alertEnrichment).
const enr = (o: Record<string, unknown>) => JSON.stringify(o);

const INC_204_ALERTS: IncidentAlert[] = [
  {
    id: "dec_9f2a04a1",
    alert_id: "wz-92003-01",
    rule_id: 92003,
    rule_description: "Mimikatz-like LSASS access",
    agent_type: "triage",
    verdict: "true_positive",
    confidence: 0.86,
    risk_score: 87,
    reasoning:
      "1) LSASS handle opened by a non-EDR process · 2) followed by a new local admin account within 4m · 3) SMB to a peer host · 4) off-hours (02:14), service identity · 5) matches the T1003→T1078 pattern in the KB. Confidence held at 0.86 — identity-graph signal missing.",
    enrichment_summary: enr({
      agent_name: "WIN-APP-03",
      src_ip: "10.4.2.19",
      rule_mitre_techniques: ["T1003"],
      rule_mitre_tactics: ["Credential Access"],
    }),
    playbook_used: "credential-access-response",
    escalated: 1,
    human_override: null,
    human_verdict: null, // first-verdict flow (analyst+ may submit)
    created_at: "2026-07-02T02:14:00Z",
    glass_box: {
      risk_breakdown: {
        base_severity: 30,
        asset_multiplier: 2.1,
        user_multiplier: 1.0,
        time_multiplier: 1.4,
        mitre_boost: 1.0,
        ti_boost: 1.8,
        fp_discount: 1.0,
        anomaly_boost: 1.0,
        vuln_context_multiplier: 1.0,
        vuln_context_reason: "",
        raw_score: 158.76,
        clamped_score: 87,
      },
      provenance: {
        playbook_version: "credential-access-response v3",
        guidance_hash: "a1f9c2e4d5b7",
        model: "claude-sonnet-4",
        latency_ms: 2300,
      },
    },
    anonymized_fields: [
      { field: "host", label: "Host" },
      { field: "internal_ip", label: "Internal IP" },
      { field: "user", label: "User" },
    ],
  },
  {
    id: "dec_9f2a04a2",
    alert_id: "wz-5710-02",
    rule_id: 5710,
    rule_description: "New local admin account created",
    agent_type: "triage",
    verdict: "needs_investigation",
    confidence: 0.71,
    risk_score: 64,
    reasoning:
      "1) New account added to the local Administrators group · 2) 4m after the LSASS access on the same host · 3) creator is a service identity · 4) no matching change ticket · 5) consistent with T1136 persistence following credential theft.",
    enrichment_summary: enr({
      agent_name: "WIN-APP-03",
      src_ip: "10.4.2.19",
      rule_mitre_techniques: ["T1136"],
      rule_mitre_tactics: ["Persistence"],
    }),
    playbook_used: "persistence-response",
    escalated: 0,
    human_override: "s.okafor",
    // EXISTING human verdict → WO-B10 override is admin-only. Demonstrates the
    // analyst/senior_analyst read-only "requires admin to override" state.
    human_verdict: "true_positive",
    created_at: "2026-07-02T02:18:00Z",
    glass_box: {
      risk_breakdown: {
        base_severity: 24,
        asset_multiplier: 2.1,
        user_multiplier: 1.0,
        time_multiplier: 1.4,
        mitre_boost: 1.0,
        ti_boost: 1.0,
        fp_discount: 1.0,
        anomaly_boost: 1.15,
        vuln_context_multiplier: 1.0,
        raw_score: 81.06,
        clamped_score: 64,
      },
      provenance: {
        playbook_version: "persistence-response v2",
        guidance_hash: "a1f9c2e4d5b7",
        model: "claude-sonnet-4",
        latency_ms: 1980,
      },
    },
    anonymized_fields: [
      { field: "host", label: "Host" },
      { field: "internal_ip", label: "Internal IP" },
      { field: "user", label: "User" },
    ],
  },
  {
    id: "dec_9f2a04a3",
    alert_id: "wz-92003-03",
    rule_id: 92100,
    rule_description: "SMB session to a peer host from an app server",
    agent_type: "triage",
    verdict: "needs_investigation",
    confidence: 0.68,
    risk_score: 58,
    reasoning:
      "1) Outbound SMB from an app server to a peer · 2) shortly after new-admin creation · 3) peer is adjacent to a domain controller · 4) unusual for this host's baseline · 5) consistent with T1021 lateral movement.",
    enrichment_summary: enr({
      agent_name: "WIN-APP-03",
      src_ip: "10.4.2.19",
      rule_mitre_techniques: ["T1021"],
      rule_mitre_tactics: ["Lateral Movement"],
    }),
    playbook_used: "lateral-movement-response",
    escalated: 0,
    human_override: null,
    human_verdict: null,
    created_at: "2026-07-02T02:22:00Z",
    // No glass_box recorded for this decision → exercises the honest
    // "risk breakdown not recorded" fallback in the case view.
    anonymized_fields: [
      { field: "host", label: "Host" },
      { field: "internal_ip", label: "Internal IP" },
    ],
  },
];

const TIMELINE_204: IncidentDetail["timeline"] = [
  {
    id: 1,
    event_type: "created",
    description: "Incident auto-created from correlated LSASS access alert.",
    actor: "correlation_engine",
    created_at: "2026-07-02T02:14:00Z",
  },
  {
    id: 2,
    event_type: "alert_added",
    description: "New local admin account creation correlated onto the chain.",
    actor: "correlation_engine",
    created_at: "2026-07-02T02:18:00Z",
  },
  {
    id: 3,
    event_type: "status_change",
    description: "Status → investigating.",
    actor: "s.okafor",
    created_at: "2026-07-02T02:30:00Z",
  },
];

const DETAILS: Record<string, IncidentDetail> = {
  "INC-204": {
    ...INCIDENTS[0],
    summary:
      "Credential access on an app server adjacent to a domain controller, followed by persistence and lateral movement — a kill-chain-ordered campaign.",
    mitre_techniques: j(["T1003", "T1136", "T1021"]),
    affected_users: j(["svc-deploy"]),
    affected_ips: j(["10.4.2.19"]),
    alerts: INC_204_ALERTS,
    timeline: TIMELINE_204,
  },
};

/** Build a minimal-but-real detail for a row with no hand-authored fixture. */
function synthDetail(row: IncidentListRow): IncidentDetail {
  const alert: IncidentAlert = {
    id: `dec_${row.id.toLowerCase()}`,
    rule_id: 0,
    rule_description: row.title,
    agent_type: "triage",
    verdict: "needs_investigation",
    confidence: 0.6,
    risk_score:
      row.severity === "high" ? 62 : row.severity === "medium" ? 41 : 20,
    reasoning:
      "Single-alert incident. Full 5-step reasoning is attached to the member decision at triage time.",
    enrichment_summary: JSON.stringify({
      agent_name: parseFirst(row.affected_hosts),
      rule_mitre_tactics: [],
      rule_mitre_techniques: [],
    }),
    human_verdict: null,
    created_at: row.first_seen ?? undefined,
    glass_box: {
      risk_breakdown: {},
      provenance: {
        playbook_version: null,
        guidance_hash: null,
        model: null,
        latency_ms: null,
      },
    },
    // No anonymized_fields → exercises the generic fallback line.
  };
  return {
    ...row,
    alerts: [alert],
    timeline: [
      {
        id: 1,
        event_type: "created",
        description: "Incident auto-created from a single alert.",
        actor: "correlation_engine",
        created_at: row.first_seen ?? undefined,
      },
    ],
  };
}

function parseFirst(v: string | string[] | null | undefined): string | null {
  if (Array.isArray(v)) return v[0] ?? null;
  if (typeof v === "string") {
    try {
      const p = JSON.parse(v);
      return Array.isArray(p) ? (p[0] ?? null) : null;
    } catch {
      return null;
    }
  }
  return null;
}

export function incidentsFixture(opts: { empty?: boolean }): IncidentsResponse {
  if (opts.empty) return { incidents: [], total: 0, offset: 0 };
  return { incidents: INCIDENTS, total: INCIDENTS.length, offset: 0 };
}

export function incidentDetailFixture(id: string): IncidentDetail {
  if (DETAILS[id]) return DETAILS[id];
  const row = INCIDENTS.find((r) => r.id === id) ?? INCIDENTS[0];
  return synthDetail(row);
}
