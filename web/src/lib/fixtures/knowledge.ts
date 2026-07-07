/**
 * KNOWLEDGE-BASE FIXTURE — screenshot / dev-preview only (WO-U9c).
 *
 * Reached solely from `api.ts::{getKbDocuments,searchKb,getKbStats}` when
 * `NEXT_PUBLIC_DHRUVA_FIXTURES` is set, via dynamic import so it is
 * dead-code-eliminated from a normal production bundle. The real path calls the
 * live `GET /api/kb/{documents,search,stats}`.
 *
 * Fabricates NO capability — it mirrors the `kb_documents` row shape exactly
 * (`store.py`): `tags` / `mitre_techniques` as JSON-encoded strings, search
 * results carrying a `ts_rank` `rank`, and stats as `{ total, by_type }`.
 *
 * `locked: true` (env `NEXT_PUBLIC_DHRUVA_FIXTURES=locked`) THROWS an ApiError(403)
 * shaped like the real `require_license_feature("knowledge_base")` gate.
 */

import { ApiError } from "../api";
import type {
  KbDocument,
  KbDocumentsResponse,
  KbSearchResponse,
  KbStats,
} from "../types";

interface Opts {
  empty?: boolean;
  locked?: boolean;
}

function lockedError(): never {
  throw new ApiError(
    403,
    "The knowledge base is not available on this plan. Contact SecureSleuths to upgrade.",
  );
}

const DOCS: KbDocument[] = [
  {
    id: "kb-001",
    doc_type: "playbook",
    title: "Ransomware containment playbook",
    content:
      "On a high-confidence ransomware verdict: isolate the host, quarantine the offending binary, preserve volatile memory, and notify the on-call lead before any remediation. Do not power off — capture memory first.",
    tags: '["ransomware","containment","ir"]',
    mitre_techniques: '["T1486","T1490"]',
    source_type: "manual",
    source_id: null,
    created_by: "s.okafor",
    created_at: "2026-03-01T10:00:00Z",
    updated_at: "2026-06-20T14:30:00Z",
  },
  {
    id: "kb-002",
    doc_type: "analyst_note",
    title: "Vulnerability scanner scan windows",
    content:
      "The Tenable scanner runs 02:00–04:00 UTC on Tuesdays/Thursdays. SSH and web auth-failure bursts in this window from 10.20.0.14 are expected and should be triaged benign unless paired with a successful auth.",
    tags: '["false-positive","scanner","context"]',
    mitre_techniques: "[]",
    source_type: "manual",
    source_id: null,
    created_by: "a.mehra",
    created_at: "2026-05-05T09:00:00Z",
    updated_at: "2026-05-05T09:00:00Z",
  },
  {
    id: "kb-003",
    doc_type: "hunt_finding",
    title: "Confirmed: after-hours scheduled-task persistence (FIN-WKS)",
    content:
      "Hunt cycle hc-2026-07-01 confirmed schtasks.exe persistence outside the change window on three finance workstations. See incident inc-4821. Root cause: contractor laptop with a stale RMM agent.",
    tags: '["persistence","T1053","finance"]',
    mitre_techniques: '["T1053.005"]',
    source_type: "hunt_finding",
    source_id: "hf-9a12",
    created_by: "system",
    created_at: "2026-07-01T09:25:00Z",
    updated_at: "2026-07-01T09:25:00Z",
  },
  {
    id: "kb-004",
    doc_type: "runbook",
    title: "Credential-dumping (LSASS) triage runbook",
    content:
      "Steps for LSASS-access alerts: confirm the accessing process signature and parent, check for a preceding suspicious logon, pull the process tree, and escalate to senior on any unsigned accessor.",
    tags: '["credential-access","lsass","runbook"]',
    mitre_techniques: '["T1003.001"]',
    source_type: "manual",
    source_id: null,
    created_by: "s.okafor",
    created_at: "2026-04-14T11:00:00Z",
    updated_at: "2026-06-01T08:15:00Z",
  },
];

const STATS: KbStats = {
  total: 4,
  by_type: {
    playbook: 1,
    analyst_note: 1,
    hunt_finding: 1,
    runbook: 1,
  },
};

export function kbDocumentsFixture(opts: Opts): KbDocumentsResponse {
  if (opts.locked) lockedError();
  if (opts.empty) return { documents: [], total: 0 };
  return { documents: DOCS, total: DOCS.length };
}

export function kbStatsFixture(opts: Opts): KbStats {
  if (opts.locked) lockedError();
  if (opts.empty) return { total: 0, by_type: {} };
  return STATS;
}

export function kbSearchFixture(query: string, opts: Opts): KbSearchResponse {
  if (opts.locked) lockedError();
  if (opts.empty) return { results: [], total: 0, query };
  // A naive relevance match over the fixture corpus so the search box behaves
  // plausibly for screenshots — it fabricates no rows beyond the seeded corpus.
  const q = query.toLowerCase();
  const hits = DOCS.filter(
    (d) =>
      d.title.toLowerCase().includes(q) ||
      (d.content ?? "").toLowerCase().includes(q),
  ).map((d, i) => ({ ...d, rank: 0.9 - i * 0.1 }));
  return { results: hits, total: hits.length, query };
}
