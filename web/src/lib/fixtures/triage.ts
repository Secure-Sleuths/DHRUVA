/**
 * Triage queue FIXTURE — screenshot / dev-preview only.
 *
 * Reached solely from `api.ts::getTriageDecisions` when
 * `NEXT_PUBLIC_DHRUVA_FIXTURES` is set, via a dynamic import so it is
 * dead-code-eliminated from a normal production bundle. The real code path
 * calls `GET /api/triage/decisions?sort=risk`; this only lets the UI states be
 * captured without a live backend. It fabricates NO capability — it mirrors the
 * WO-B1 response shape, including a null-host row (older, pre-flatten) so the
 * graceful-null rendering is exercised.
 *
 * Rows are ported from the approved mockup's `tTriage()` worst-first queue,
 * extended to cover all four canonical verdicts.
 */

import type {
  DecisionAuditTrail,
  TriageDecision,
  TriageDecisionsResponse,
  TriageSort,
} from "../types";

const NOW = Date.UTC(2026, 6, 2, 2, 45, 0); // 2026-07-02T02:45Z (stable for shots)
const ago = (mins: number) => new Date(NOW - mins * 60_000).toISOString();

const enr = (o: Record<string, unknown>) => JSON.stringify(o);

const DECISIONS: TriageDecision[] = [
  {
    id: "dec_9f2a04a1",
    verdict: "true_positive",
    confidence: 0.86,
    risk_score: 87,
    rule_id: 92003,
    rule_description: "Mimikatz-like LSASS access",
    host: "WIN-APP-03",
    src_ip: "10.4.2.11",
    technique_ids: ["T1003"],
    tactic_ids: ["credaccess"],
    created_at: ago(31),
    escalated: true,
    human_verdict: null,
    reasoning:
      "1) LSASS handle opened by a non-EDR process · 2) followed by a new local admin account within 4m · 3) SMB to a peer host · 4) off-hours (02:14), service identity · 5) matches the T1003→T1078 pattern in the KB. Confidence held at 0.86 — identity-graph signal missing.",
    enrichment_summary: enr({
      agent_name: "WIN-APP-03",
      src_ip: "10.4.2.11",
      rule_mitre_techniques: ["T1003"],
      rule_mitre_tactics: ["Credential Access"],
    }),
    anonymized_fields: [
      { field: "host", label: "Host" },
      { field: "internal_ip", label: "Internal IP" },
      { field: "user", label: "User" },
    ],
  },
  {
    id: "dec_9f2a04a2",
    verdict: "needs_investigation",
    confidence: 0.71,
    risk_score: 64,
    rule_id: 5710,
    rule_description: "New local admin account created",
    host: "WIN-APP-03",
    src_ip: "10.4.2.11",
    technique_ids: ["T1136"],
    tactic_ids: ["persist"],
    created_at: ago(27),
    escalated: false,
    human_verdict: "true_positive",
    reasoning:
      "1) New account added to the local Administrators group · 2) 4m after the LSASS access on the same host · 3) creator is a service identity · 4) no matching change ticket · 5) consistent with T1136 persistence following credential theft.",
    enrichment_summary: enr({
      agent_name: "WIN-APP-03",
      src_ip: "10.4.2.11",
      rule_mitre_techniques: ["T1136"],
      rule_mitre_tactics: ["Persistence"],
    }),
    anonymized_fields: [
      { field: "host", label: "Host" },
      { field: "internal_ip", label: "Internal IP" },
      { field: "user", label: "User" },
    ],
  },
  {
    id: "dec_5c20176a",
    verdict: "needs_investigation",
    confidence: 0.79,
    risk_score: 58,
    rule_id: 60204,
    rule_description: "Multiple failed logins then success",
    host: "VPN-GW-01",
    src_ip: "203.0.113.44",
    technique_ids: ["T1110"],
    tactic_ids: ["initial"],
    created_at: ago(61),
    escalated: false,
    human_verdict: null,
  },
  {
    id: "dec_31514ff4",
    verdict: "needs_investigation",
    confidence: 0.55,
    risk_score: 41,
    rule_id: 31514,
    rule_description: "Outbound connection to known-bad IP",
    host: "APP-EDGE-02",
    src_ip: "198.51.100.7",
    technique_ids: ["T1071"],
    tactic_ids: ["c2"],
    created_at: ago(88),
    escalated: false,
    human_verdict: null,
  },
  {
    id: "dec_51002abc",
    verdict: "false_positive",
    confidence: 0.42,
    risk_score: 22,
    rule_id: 51002,
    rule_description: "Scheduled task modification",
    // pre-flatten row: host/src_ip unknown — must render gracefully
    host: null,
    src_ip: null,
    technique_ids: ["T1053"],
    tactic_ids: ["persist"],
    created_at: ago(140),
    escalated: false,
    human_verdict: "false_positive",
  },
  {
    id: "dec_91533def",
    verdict: "auto_close",
    confidence: 0.31,
    risk_score: 12,
    rule_id: 91533,
    rule_description: "Benign administrative PowerShell",
    host: "FIN-WKS-07",
    src_ip: "10.6.1.20",
    technique_ids: ["T1059"],
    tactic_ids: ["exec"],
    created_at: ago(175),
    escalated: false,
    human_verdict: null,
  },
];

export function triageFixture(opts: {
  sort?: TriageSort;
  empty?: boolean;
}): TriageDecisionsResponse {
  if (opts.empty) return { decisions: [], total: 0 };
  const decisions =
    opts.sort === "risk"
      ? [...DECISIONS].sort((a, b) => b.risk_score - a.risk_score)
      : [...DECISIONS].sort(
          (a, b) => +new Date(b.created_at) - +new Date(a.created_at),
        );
  return { decisions, total: decisions.length };
}

// Parsed WO-B4 glass_box per decision, mirroring
// `GET /api/triage/decisions/{id}/audit-trail`. Decisions with no recorded trail
// resolve to the empty (honest) glass_box shape — exercising the "not recorded"
// fallback in the case view rather than fabricating math.
const AUDIT_TRAILS: Record<string, DecisionAuditTrail> = {
  dec_9f2a04a1: {
    decision_id: "dec_9f2a04a1",
    glass_box: {
      risk_breakdown: {
        base_severity: 30,
        asset_multiplier: 2.1,
        user_multiplier: 1.0,
        time_multiplier: 1.4,
        ti_boost: 1.8,
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
  },
  dec_9f2a04a2: {
    decision_id: "dec_9f2a04a2",
    glass_box: {
      risk_breakdown: {
        base_severity: 24,
        asset_multiplier: 2.1,
        time_multiplier: 1.4,
        anomaly_boost: 1.15,
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
  },
};

const EMPTY_GLASS_BOX: DecisionAuditTrail = {
  glass_box: {
    risk_breakdown: {},
    provenance: {
      playbook_version: null,
      guidance_hash: null,
      model: null,
      latency_ms: null,
    },
  },
};

export function decisionAuditTrailFixture(
  decisionId: string,
): DecisionAuditTrail {
  return (
    AUDIT_TRAILS[decisionId] ?? {
      ...EMPTY_GLASS_BOX,
      decision_id: decisionId,
    }
  );
}
