/**
 * Active-Response queue + audit FIXTURE — screenshot / dev-preview only (WO-U9b).
 *
 * Reached solely from `api.ts::getResponseQueue` / `getResponseAudit` when
 * `NEXT_PUBLIC_DHRUVA_FIXTURES` is set, via dynamic import so it is
 * dead-code-eliminated from a normal production bundle. The real path calls the
 * live `GET /api/response/queue|audit`; this only lets the UI states be captured
 * without a backend.
 *
 * Fabricates NO capability — it mirrors the `active_response_audit` row shape
 * exactly (`store.py::get_ar_audit`): mode auto|manual, status executed|
 * pending_approval|denied|reversed|expired, actor, target_ip, agent_id, reason,
 * ttl/expiry, reversed metadata. The queue variant returns only active/pending
 * rows (server `active_only=True`). There is NO `locked` variant — the
 * queue/audit endpoints are role-gated (read_only+), not license-gated.
 */

import type {
  ArAction,
  ResponseAuditResponse,
  ResponseQueueResponse,
} from "../types";

interface Opts {
  empty?: boolean;
}

const AUDIT: ArAction[] = [
  {
    id: "ar-9f21",
    mode: "manual",
    action: "block_ip",
    status: "pending_approval",
    actor: "j.rivera",
    target_ip: "203.0.113.44",
    agent_id: "001",
    alert_id: "alrt-5510",
    decision_id: "dec-90a1",
    incident_id: "inc-4821",
    ti_evidence: '{}',
    gate_snapshot: '{}',
    reason: "Proposed: repeated SSH brute-force from a known-bad IP (AbuseIPDB 96%)",
    ttl_seconds: 3600,
    expires_at: null,
    reversed_at: null,
    reversed_by: null,
    created_at: "2026-07-02T05:48:00Z",
  },
  {
    id: "ar-8c07",
    mode: "auto",
    action: "block_ip",
    status: "executed",
    actor: "system:auto-block-policy",
    target_ip: "198.51.100.9",
    agent_id: "004",
    alert_id: "alrt-5471",
    decision_id: "dec-81c0",
    incident_id: "inc-4771",
    ti_evidence: '{"abuseipdb":0.98,"otx":0.9}',
    gate_snapshot: '{"triage_conf":0.95,"ti_conf":0.98,"floor":0.9}',
    reason: "Auto-block policy: external IP, TI ≥ floor, triage confidence ≥ floor",
    ttl_seconds: 7200,
    expires_at: "2026-06-30T18:02:00Z",
    reversed_at: null,
    reversed_by: null,
    created_at: "2026-06-30T16:02:05Z",
  },
  {
    id: "ar-7b55",
    mode: "manual",
    action: "isolate_host",
    status: "executed",
    actor: "s.okafor",
    target_ip: null,
    agent_id: "011",
    alert_id: "alrt-5390",
    decision_id: "dec-88f2",
    incident_id: "inc-4790",
    ti_evidence: '{}',
    gate_snapshot: '{}',
    reason: "Confirmed ransomware detonation on FIN-WKS-11 — isolate pending IR",
    ttl_seconds: null,
    expires_at: null,
    reversed_at: null,
    reversed_by: null,
    created_at: "2026-07-01T22:14:10Z",
  },
  {
    id: "ar-6a12",
    mode: "manual",
    action: "block_ip",
    status: "reversed",
    actor: "a.mehra",
    target_ip: "192.0.2.77",
    agent_id: "004",
    alert_id: "alrt-5210",
    decision_id: "dec-77b1",
    incident_id: "inc-4702",
    ti_evidence: '{}',
    gate_snapshot: '{}',
    reason: "Blocked during investigation; reversed after confirmed false positive",
    ttl_seconds: 3600,
    expires_at: "2026-06-28T15:00:00Z",
    reversed_at: "2026-06-28T14:20:00Z",
    reversed_by: "a.mehra",
    created_at: "2026-06-28T14:00:00Z",
  },
  {
    id: "ar-5d88",
    mode: "auto",
    action: "block_ip",
    status: "denied",
    actor: "system:auto-block-policy",
    target_ip: "10.4.2.9",
    agent_id: "007",
    alert_id: "alrt-5120",
    decision_id: "dec-70a4",
    incident_id: null,
    ti_evidence: '{}',
    gate_snapshot: '{"reason":"internal_ip"}',
    reason: "Refused by guardrail: target is internal/reserved (never-block)",
    ttl_seconds: null,
    expires_at: null,
    reversed_at: null,
    reversed_by: null,
    created_at: "2026-06-27T09:30:00Z",
  },
];

/** The queue is the active_only subset: pending_approval + executed (not reversed). */
const QUEUE: ArAction[] = AUDIT.filter(
  (r) =>
    (r.status === "pending_approval" || r.status === "executed") &&
    !r.reversed_at,
);

export function responseQueueFixture(opts: Opts): ResponseQueueResponse {
  if (opts.empty) return { queue: [], total: 0 };
  return { queue: QUEUE, total: QUEUE.length };
}

export function responseAuditFixture(opts: Opts): ResponseAuditResponse {
  if (opts.empty) return { audit: [], total: 0 };
  return { audit: AUDIT, total: AUDIT.length };
}
