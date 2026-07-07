/**
 * NL-Query copilot FIXTURE — screenshot / dev-preview only.
 *
 * Reached solely from `api.ts::postQuery` when `NEXT_PUBLIC_DHRUVA_FIXTURES` is
 * set, via a dynamic import so it is dead-code-eliminated from a normal
 * production bundle. The real path calls `POST /api/query`; this only lets the
 * grounded / no-sources states be captured without a live backend.
 *
 * It mirrors the WO-B8 response shape (answer-level `sources` metadata — NO raw
 * hit bodies) and is ported from the approved mockup's INC-204 corpus. The
 * `empty` variant returns an answer with EMPTY sources so the honest
 * "no sources returned" (ungrounded) note is exercised — it never invents a
 * citation.
 */

import type { NLQueryResponse } from "../types";

/** A grounded answer over the mockup's INC-204 credential-access chain. */
function grounded(question: string): NLQueryResponse {
  const ask = question.trim();
  return {
    answer:
      (ask ? `On “${ask}” — ` : "") +
      "the activity on WIN-APP-03 reads as a credential-access chain: a non-EDR " +
      "process opened a read handle to lsass.exe at 02:14, a new local admin " +
      "account (svc-deploy-2) was created at 02:18, and svc-deploy then " +
      "authenticated over SMB to a DC-adjacent peer at 02:22. Confidence is held " +
      "at medium because the identity-graph signal is missing — I won't over-claim.",
    findings: [
      {
        rule_id: 92003,
        rule_description: "Mimikatz-like LSASS access",
        host: "WIN-APP-03",
        risk_score: 87,
        timestamp: "2026-07-02T02:14:07Z",
      },
      {
        rule_id: 5710,
        rule_description: "New local admin account created",
        host: "WIN-APP-03",
        risk_score: 64,
        timestamp: "2026-07-02T02:18:00Z",
      },
      {
        rule_id: 60204,
        rule_description: "SMB session to peer host",
        host: "WIN-APP-03",
        risk_score: 58,
        timestamp: "2026-07-02T02:22:00Z",
      },
    ],
    risk_assessment:
      "High — a Credential-Access → Persistence → Lateral-Movement chain one hop " +
      "from a domain controller, off-hours for this identity.",
    confidence: "medium",
    suggested_actions: [
      {
        action: "isolate_host",
        agent_id: "001",
        target: "WIN-APP-03",
        description:
          "Host containment via EDR (blocks all lateral SMB) to stop the pivot " +
          "before the next DC-adjacent hop.",
      },
      "Open a ticket for the on-call team to rotate svc-deploy credentials.",
    ],
    follow_up_queries: [
      "Show other logons by svc-deploy in the last 24h",
      "What processes had lsass.exe as parent?",
      "Who created the new admin account and when?",
    ],
    sources: [
      {
        id: "src_os_lsass",
        source: "opensearch",
        description:
          "Process-access events on WIN-APP-03 — handle opens against lsass.exe",
        count: 3,
        index: "wazuh-alerts-4.x-2026.07.02",
      },
      {
        id: "src_os_acct",
        source: "opensearch",
        description: "Windows account-management events (4720/4732)",
        count: 2,
        index: "wazuh-alerts-4.x-2026.07.02",
      },
      {
        id: "src_wz_smb",
        source: "wazuh_api",
        description: "Agent inventory + active SMB sessions for WIN-APP-03",
        count: 1,
      },
      {
        id: "src_kb_pattern",
        source: "knowledge_base",
        description:
          "Playbook memory — T1003→T1078 credential-access→lateral pattern",
        count: 1,
        dataset: "playbook_memory",
      },
    ],
    duration_ms: 1840,
    total_hits: 7,
    queries_executed: 3,
  };
}

/** An honest "found nothing" answer with EMPTY sources (ungrounded note). */
function ungrounded(): NLQueryResponse {
  return {
    answer:
      "I couldn't find any records matching that in the retrieved data. I won't " +
      "guess — try one of the suggested queries, or narrow the host/time window.",
    findings: [],
    risk_assessment: null,
    confidence: "low",
    suggested_actions: [],
    follow_up_queries: [
      "Show high-risk decisions in the last 24h",
      "Which hosts are on an active attack chain?",
    ],
    sources: [],
    duration_ms: 420,
    total_hits: 0,
    queries_executed: 1,
  };
}

export function investigateQueryFixture(
  question: string,
  opts: { empty?: boolean } = {},
): NLQueryResponse {
  return opts.empty ? ungrounded() : grounded(question);
}
