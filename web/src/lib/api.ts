/**
 * Typed fetch wrapper for the FastAPI backend.
 *
 * Modelled on the sibling ASM repo (web/src/lib/api.ts): reads
 * NEXT_PUBLIC_API_URL, attaches `Authorization: Bearer <token>`, and throws a
 * typed `ApiError`. All calls run from client components, so the build never
 * needs a live backend.
 */

import { clearToken, getToken } from "./token";
import type {
  AdminAnonMappingsResponse,
  AdminAuditLogResponse,
  AdminConfigResponse,
  AdminDataAccessPolicy,
  AdminGovernanceCharterResponse,
  AdminTenantsResponse,
  AdminUsersResponse,
  AgentsResponse,
  AgentPackagesResponse,
  AgentPortsResponse,
  AgentProcessesResponse,
  AgentVulnerabilitiesResponse,
  CriticalVulnerabilitiesResponse,
  RemediationExecuteResult,
  RemediationVerifyResult,
  VulnRemediationResponse,
  ScaChecksResponse,
  ScaPoliciesResponse,
  AnalystPerformanceResponse,
  AnalystWorkloadResponse,
  AutomationHealth,
  AutomationRates,
  CaseAgingResponse,
  CampaignsResponse,
  ComplianceMatrix,
  FrameworkCoverage,
  DashboardStats,
  DecisionAuditTrail,
  DetectionProposalsResponse,
  FeedbackPatternsResponse,
  HuntTrendsResponse,
  GroupsResponse,
  HuntFindingsResponse,
  HuntLibraryResponse,
  HuntReviewBody,
  HuntReviewResult,
  HuntRunResult,
  HuntReplayResult,
  KbCreateBody,
  KbCreateResult,
  KbDocumentsResponse,
  KbSearchResponse,
  KbStats,
  KbUpdateBody,
  KbWriteResult,
  ProposalEffectiveness,
  IncidentAssignBody,
  IncidentDetail,
  IncidentEscalateBody,
  IncidentEvidenceBody,
  IncidentFlagBody,
  IncidentMergeBody,
  IncidentNoteBody,
  IncidentReviewBody,
  IncidentStatusChangeBody,
  IncidentsResponse,
  IncidentWriteResult,
  LicenseTierInfo,
  MitreGaps,
  MitreIncidentCoverage,
  MitreSummary,
  NLQueryResponse,
  OverviewSummary,
  PendingReviewResponse,
  ProposeContainmentBody,
  ProposeContainmentResponse,
  RegistryResponse,
  RuleStats,
  ResponseAuditResponse,
  ResponseQueueResponse,
  RootcheckResponse,
  SoarExecutionsResponse,
  SoarPlaybooksResponse,
  SoarStats,
  SocPerformanceResponse,
  SocReport,
  SocReportType,
  SocSummaryResponse,
  SyscheckResponse,
  TICollectResult,
  TICvesResponse,
  TIStatsResponse,
  TicketsResponse,
  TicketStats,
  TriageDecision,
  TriageDecisionsResponse,
  TriageReviewBody,
  TriageSort,
  VulnSummary,
} from "./types";
// [frontend-integrator — parity gap ①] locally-scoped types for the restored
// IOC-lookup + MITRE-heatmap read fetchers appended at the bottom of this file.
import type {
  IocLookupResponse,
  IocMatch,
  MitreCoverageHeatmap,
} from "./types";
// WO-H21 — complete-context case view read contracts (raw event + playbook).
import type { DecisionPlaybookResponse, RawAlertResponse } from "./types";

/**
 * Screenshot/dev fixtures gate. When `NEXT_PUBLIC_DHRUVA_FIXTURES` is "true"
 * (populated) or "empty", data calls short-circuit to a typed fixture instead
 * of hitting the backend — so the UI states can be captured without a live API.
 * The flag is statically inlined by Next, so in a normal production build this
 * is a constant `undefined` and the fixture branch (with its dynamic import) is
 * dead-code-eliminated: the real endpoint path below is the ONLY shipped path.
 */
const FIXTURES = process.env.NEXT_PUBLIC_DHRUVA_FIXTURES;

// Base for API calls. Unset (the production/static-export deploy) → "" →
// requests are RELATIVE, i.e. same-origin as wherever the SPA is served (the
// FastAPI backend serves both the UI and /api/*). For local dev with a separate
// backend, set NEXT_PUBLIC_API_URL (e.g. http://127.0.0.1:8000) in .env.local.
export const API_URL = (process.env.NEXT_PUBLIC_API_URL ?? "").replace(
  /\/+$/,
  "",
);

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

interface RequestOpts {
  method?: string;
  body?: unknown;
  query?: Record<string, string | number | undefined | null>;
  /** skip the Authorization header */
  anonymous?: boolean;
  signal?: AbortSignal;
}

function buildUrl(path: string, query?: RequestOpts["query"]): string {
  // API_URL is "" in the same-origin (static-export) deploy → resolve the
  // relative path against the page origin so `new URL()` gets an absolute base.
  // When API_URL is set (dev, separate backend) it's already absolute.
  const base =
    API_URL || (typeof window !== "undefined" ? window.location.origin : "");
  const url = new URL(base + path);
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined && v !== null && v !== "") {
        url.searchParams.set(k, String(v));
      }
    }
  }
  return url.toString();
}

async function request<T>(path: string, opts: RequestOpts = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (!opts.anonymous) {
    const token = getToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
  }

  let res: Response;
  try {
    res = await fetch(buildUrl(path, opts.query), {
      method: opts.method ?? "GET",
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      cache: "no-store",
      signal: opts.signal,
    });
  } catch (e) {
    throw new ApiError(
      0,
      `Cannot reach API at ${API_URL || "(same origin)"}. Is the backend running? (${
        e instanceof Error ? e.message : String(e)
      })`,
    );
  }

  if (res.status === 401) {
    // token rejected/expired — drop it so the app falls back to a signed-out
    // (dev-preview) state rather than hammering a dead session.
    clearToken();
  }

  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const data = await res.json();
      if (data?.detail) {
        detail =
          typeof data.detail === "string"
            ? data.detail
            : JSON.stringify(data.detail);
      }
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail);
  }

  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

// ---- License / tier ---------------------------------------------------------
/**
 * `GET /api/license/tier-info` — drives tab tier-locks + copilot degradation.
 * The caller must fail toward locked/degraded if this throws (never unlock).
 */
export function getTierInfo(signal?: AbortSignal): Promise<LicenseTierInfo> {
  return request<LicenseTierInfo>("/api/license/tier-info", { signal });
}

// ---- Auth -------------------------------------------------------------------
/** Shape returned by `POST /api/auth/login`. */
export interface LoginResponse {
  access_token: string;
  token_type: string;
}

/**
 * `POST /api/auth/login` — exchange username/password for a JWT. Anonymous (no
 * Bearer). The caller stores the returned `access_token` (see token.ts) and
 * routes to the dashboard. A 401 surfaces as an `ApiError` with status 401.
 */
export async function login(
  username: string,
  password: string,
): Promise<LoginResponse> {
  return request<LoginResponse>("/api/auth/login", {
    method: "POST",
    body: { username, password },
    anonymous: true,
  });
}

// ---- Triage decisions -------------------------------------------------------
/**
 * `GET /api/triage/decisions?sort=…` → `{ decisions, total }` (WO-B1).
 *
 * The worst-first queue passes `sort: "risk"` (risk_score DESC); the server
 * defaults to `recent` (newest-first) when omitted. Rows carry the flattened
 * first-class fields (host, src_ip, technique_ids, tactic_ids, verdict,
 * confidence, risk_score, …) — see `TriageDecision`.
 */
export async function getTriageDecisions(
  params: { sort?: TriageSort } = {},
  signal?: AbortSignal,
): Promise<TriageDecisionsResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { triageFixture } = await import("./fixtures/triage");
    return triageFixture({ sort: params.sort, empty: FIXTURES === "empty" });
  }
  return request<TriageDecisionsResponse>("/api/triage/decisions", {
    query: { sort: params.sort },
    signal,
  });
}

/**
 * `GET /api/triage/decisions/{id}/audit-trail` → the audit-trail row + a parsed
 * WO-B4 `glass_box`. Backs the triage decision glass-box case view (WO-U5
 * deep-link). Auth: `verify_jwt` (all roles that can see the queue). The endpoint
 * returns 404 when no audit trail exists for the decision — the caller catches
 * that and renders the case from the decision's own fields with an empty
 * glass_box (never fabricated). READ-only.
 *
 * In fixture mode this short-circuits to a typed fixture keyed by decision id so
 * the case can be captured without a live backend.
 */
export async function getDecisionAuditTrail(
  decisionId: string,
  signal?: AbortSignal,
): Promise<DecisionAuditTrail> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { decisionAuditTrailFixture } = await import("./fixtures/triage");
    return decisionAuditTrailFixture(decisionId);
  }
  return request<DecisionAuditTrail>(
    `/api/triage/decisions/${encodeURIComponent(decisionId)}/audit-trail`,
    { signal },
  );
}

/**
 * `GET /api/triage/rule-stats/{rule_id}?days=7` (WO-U13) → per-rule verdict
 * stats over the last `days` window (server default 7, allowed 1..90),
 * tenant-scoped server-side. Backs the "Rule N stats (7d)" drill in the decision
 * glass-box card, fetched LAZILY on first expand (never up-front per card).
 * READ-ONLY (`verify_jwt`). `days` is omitted from the query when undefined so
 * the server default (7) applies.
 *
 * Fixture mode short-circuits to synthetic per-rule stats (zeros under "empty")
 * so the drill's loaded/empty states can be captured without a live backend —
 * it performs NO real query.
 */
export async function getRuleStats(
  ruleId: number,
  days?: number,
  signal?: AbortSignal,
): Promise<RuleStats> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return FIXTURES === "empty"
      ? {
          rule_id: ruleId,
          total: 0,
          fp_count: 0,
          tp_count: 0,
          auto_closed: 0,
          fp_rate: 0,
          avg_confidence: 0,
        }
      : {
          rule_id: ruleId,
          total: 42,
          fp_count: 27,
          tp_count: 9,
          auto_closed: 6,
          fp_rate: 27 / 42,
          avg_confidence: 0.71,
        };
  }
  return request<RuleStats>(`/api/triage/rule-stats/${ruleId}`, {
    query: { days },
    signal,
  });
}

/**
 * `GET /api/triage/decisions/{id}/raw-alert` (WO-H21) → the raw underlying
 * Wazuh event behind a decision, from the enriched-alert index (the derived
 * `enrichment` blob is dropped server-side — the case already renders it).
 * Backs the "Raw Wazuh event" drill on the decision card, fetched LAZILY on
 * first expand. READ-ONLY (`verify_jwt`), tenant-scoped server-side; a
 * degraded deployment (no OpenSearch / event rotated out) answers
 * `found: false` + `reason` — an empty state, never an error.
 *
 * Fixture mode short-circuits to a small synthetic event ("empty" → an honest
 * not-found) so the drill's states can be captured without a live backend.
 */
export async function getDecisionRawAlert(
  decisionId: string,
  signal?: AbortSignal,
): Promise<RawAlertResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    if (FIXTURES === "empty") {
      return {
        found: false,
        alert: null,
        reason:
          "The underlying event was not found in the enriched-alert index (it may have been rotated out of retention).",
      };
    }
    return {
      found: true,
      alert: {
        alert_id: "1713520200.987654",
        timestamp: "2026-04-19T10:30:00+00:00",
        rule_id: 5710,
        rule_level: 10,
        rule_description: "sshd: authentication success.",
        rule_groups: ["syslog", "sshd", "authentication_success"],
        agent_id: "001",
        agent_name: "prod-db-01",
        src_ip: "185.220.101.34",
        data: { srcip: "185.220.101.34", dstuser: "root" },
        full_log:
          "Apr 19 10:30:00 prod-db-01 sshd[1234]: Accepted publickey for root from 185.220.101.34 port 54321 ssh2",
        decoder: { name: "sshd" },
        location: "/var/log/auth.log",
      },
      reason: null,
    };
  }
  return request<RawAlertResponse>(
    `/api/triage/decisions/${encodeURIComponent(decisionId)}/raw-alert`,
    { signal },
  );
}

/**
 * `GET /api/triage/decisions/{id}/playbook` (WO-H21) → the matched playbook's
 * CONTENT (investigation steps + verdict/escalation criteria + recommended
 * actions), resolved server-side from the decision's stored `playbook_used`
 * against the currently loaded guidance. Backs the "Matched playbook" drill on
 * the decision card, fetched LAZILY on first expand. READ-ONLY (`verify_jwt`).
 * `matched: false` + `reason` covers every honest no-playbook state (none
 * recorded / generic no-match / guidance unavailable) — an empty state, never
 * an error.
 *
 * Fixture mode short-circuits to a small synthetic playbook ("empty" → an
 * honest no-match) so the drill's states can be captured without a backend.
 */
export async function getDecisionPlaybook(
  decisionId: string,
  signal?: AbortSignal,
): Promise<DecisionPlaybookResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    if (FIXTURES === "empty") {
      return {
        matched: false,
        playbook: null,
        reason:
          "No specific playbook matched this alert — the AI applied the general investigation methodology.",
      };
    }
    return {
      matched: true,
      playbook: {
        key: "suspicious_login",
        name: "Suspicious Login Investigation",
        trigger_rule_groups: ["authentication_failures", "sshd"],
        trigger_rule_ids: [5710, 5712],
        investigation_steps: [
          {
            step: 1,
            name: "Identify the user and source",
            assess:
              "- How many unique source IPs are involved?\n- Is the user a known service account or human?",
            query_template: "",
          },
          {
            step: 2,
            name: "Check for successful auth following failures",
            assess:
              "- Did authentication failures precede a successful login?",
            query_template: "",
          },
        ],
        verdict_criteria: {
          true_positive: [
            "Successful auth following brute force from external IP",
          ],
          false_positive: ["Known CI/CD or monitoring system auth patterns"],
          needs_investigation: [
            "New user account (< 7 days) with login anomalies",
          ],
        },
        escalation_criteria: [
          "New user account (< 7 days) with login anomalies",
        ],
        recommended_actions: {
          if_true_positive: ["Force password reset for affected user"],
          if_false_positive: ["Tag alert with FP reason for feedback loop"],
        },
      },
      reason: null,
    };
  }
  return request<DecisionPlaybookResponse>(
    `/api/triage/decisions/${encodeURIComponent(decisionId)}/playbook`,
    { signal },
  );
}

/**
 * `GET /api/triage/pending-review` (WO-U13) → `{ pending, count }`, the
 * human-review backlog (decisions ESCALATED with NO human verdict yet). Each
 * item is a full decision dict — the SAME entity the Triage queue renders — so
 * the Triage tab lists them with the SAME decision cards, as an ALTERNATE view to
 * the worst-first all-decisions queue (never replacing the `sort=risk` default).
 * READ-ONLY (`verify_jwt`). These rows are NOT server-flattened, so the caller
 * defaults `technique_ids`/`tactic_ids` and reads host/MITRE from
 * `enrichment_summary`.
 *
 * Fixture mode derives the backlog from the shared triage fixture (escalated &&
 * no human verdict) so the pending view's states can be captured offline.
 */
export async function getPendingReview(
  signal?: AbortSignal,
): Promise<PendingReviewResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { triageFixture } = await import("./fixtures/triage");
    const res = await triageFixture({
      sort: "risk",
      empty: FIXTURES === "empty",
    });
    const pending = res.decisions.filter(
      (d) => d.escalated && !d.human_verdict,
    );
    return { pending, count: pending.length };
  }
  return request<PendingReviewResponse>("/api/triage/pending-review", {
    signal,
  });
}

// ---- Incidents (glass-box case) — WO-U4 -------------------------------------
/**
 * `GET /api/incidents` (optionally `?status=open`) → `{ incidents, total }`.
 * The rows are presented worst-first by the caller (severity, then recency) —
 * the server orders by `last_seen DESC`, so the UI re-sorts (see
 * `incident.ts::sortIncidentsWorstFirst`). Read-only; all roles may list.
 */
export async function getIncidents(
  params: { status?: string } = {},
  signal?: AbortSignal,
): Promise<IncidentsResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { incidentsFixture } = await import("./fixtures/incidents");
    return incidentsFixture({ empty: FIXTURES === "empty" });
  }
  return request<IncidentsResponse>("/api/incidents", {
    query: { status: params.status },
    signal,
  });
}

/**
 * `GET /api/incidents/{id}` → the incident + `alerts` (member decisions, each
 * carrying WO-B4 `glass_box` + WO-B9 `anonymized_fields`) + `timeline`. Backs
 * the glass-box case view.
 */
export async function getIncident(
  id: string,
  signal?: AbortSignal,
): Promise<IncidentDetail> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { incidentDetailFixture } = await import("./fixtures/incidents");
    return incidentDetailFixture(id);
  }
  return request<IncidentDetail>(`/api/incidents/${encodeURIComponent(id)}`, {
    signal,
  });
}

/**
 * `POST /api/triage/review` (WO-B2) — record a human verdict on a member
 * decision. `reason` is REQUIRED server-side (empty → 422); the case view
 * disables submit until a reason is present so it never fires a request the
 * server rejects. The server ALSO gates the write by role (analyst+; overriding
 * an EXISTING human verdict is admin-only per WO-B10) — the UI mirrors that but
 * the server remains the source of truth.
 *
 * In fixture mode this short-circuits to a synthetic success so the write flow
 * can be exercised without a live backend — it performs NO real mutation.
 */
export async function submitTriageReview(
  body: TriageReviewBody,
  signal?: AbortSignal,
): Promise<{ status: string; decision_id: string }> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "ok", decision_id: body.decision_id };
  }
  return request<{ status: string; decision_id: string }>("/api/triage/review", {
    method: "POST",
    body,
    signal,
  });
}

// ---- Alert-level claim (WO-H25) ----------------------------------------------
/** `POST /api/triage/decisions/{id}/claim|unclaim` envelope. */
export interface DecisionClaimResult {
  status: string;
  decision_id: string;
  /** the (server-authenticated) owner after the call — null after unclaim */
  claimed_by: string | null;
}

/**
 * `POST /api/triage/decisions/{id}/claim` (WO-H25) — claim a triage decision
 * for YOURSELF. There is NO body: the server takes the claimant from the JWT
 * `sub` (never a client-supplied field). Role: analyst+ (L1 is operator).
 * Self-claim, unowned-only — a decision owned by another user is a 409 with
 * no write (mirror this with `rbac.ts::triageClaimGate` so the control is
 * never a dead button); re-claiming your own is an idempotent 200.
 * FIXTURE-GATED like `submitTriageReview`: fixture mode short-circuits to a
 * synthetic success with an "you" placeholder owner and performs NO mutation.
 */
export async function claimDecision(
  decisionId: string,
  signal?: AbortSignal,
): Promise<DecisionClaimResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "ok", decision_id: decisionId, claimed_by: "you" };
  }
  return request<DecisionClaimResult>(
    `/api/triage/decisions/${encodeURIComponent(decisionId)}/claim`,
    { method: "POST", signal },
  );
}

/**
 * `POST /api/triage/decisions/{id}/unclaim` (WO-H25) — release YOUR OWN claim.
 * Idempotent when already unclaimed; releasing a colleague's claim is a 409
 * server-side (only the owner releases). Fixture-gated like `claimDecision`.
 */
export async function unclaimDecision(
  decisionId: string,
  signal?: AbortSignal,
): Promise<DecisionClaimResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "ok", decision_id: decisionId, claimed_by: null };
  }
  return request<DecisionClaimResult>(
    `/api/triage/decisions/${encodeURIComponent(decisionId)}/unclaim`,
    { method: "POST", signal },
  );
}

// ---- Incident case-management writes (WO-U4 case writes) --------------------
/**
 * The eight case-management writes on `/api/incidents/*`. Each mirrors a server
 * Pydantic model + RBAC gate (see `rbac.ts::incidentActionGate`) and is
 * FIXTURE-GATED like `submitTriageReview`/`proposeContainment`: in fixture mode
 * it short-circuits to a synthetic success and performs NO real mutation, so the
 * write flows can be exercised for screenshots without a live backend. The
 * shipped production path calls the real endpoint ONLY (the fixture branch is
 * dead-code-eliminated when `NEXT_PUBLIC_DHRUVA_FIXTURES` is unset). The server
 * remains the enforcement point for RBAC, ownership, reason-required, valid
 * transitions and the merge license gate — the client never bypasses it.
 */

/**
 * `POST /api/incidents/{id}/status` (WO-B3). `reason` is REQUIRED server-side
 * (empty → 422); callers must gate submit on a non-empty reason. Analyst-only
 * writes are additionally ownership-checked server-side (403 if not assigned).
 */
export async function changeIncidentStatus(
  id: string,
  body: IncidentStatusChangeBody,
  signal?: AbortSignal,
): Promise<IncidentWriteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "ok", incident_id: id, new_status: body.status };
  }
  return request<IncidentWriteResult>(
    `/api/incidents/${encodeURIComponent(id)}/status`,
    { method: "POST", body, signal },
  );
}

/** `POST /api/incidents/{id}/assign` (senior_analyst+). */
export async function assignIncident(
  id: string,
  body: IncidentAssignBody,
  signal?: AbortSignal,
): Promise<IncidentWriteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "ok", incident_id: id };
  }
  return request<IncidentWriteResult>(
    `/api/incidents/${encodeURIComponent(id)}/assign`,
    { method: "POST", body, signal },
  );
}

/** `POST /api/incidents/{id}/note` (analyst+, assignee). */
export async function addIncidentNote(
  id: string,
  body: IncidentNoteBody,
  signal?: AbortSignal,
): Promise<IncidentWriteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "ok", incident_id: id, note_id: `note_fixture_${Date.now()}` };
  }
  return request<IncidentWriteResult>(
    `/api/incidents/${encodeURIComponent(id)}/note`,
    { method: "POST", body, signal },
  );
}

/** `POST /api/incidents/{id}/escalate` — raw JSON body (senior_analyst+). */
export async function escalateIncident(
  id: string,
  body: IncidentEscalateBody,
  signal?: AbortSignal,
): Promise<IncidentWriteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "ok", incident_id: id, tier: body.tier };
  }
  return request<IncidentWriteResult>(
    `/api/incidents/${encodeURIComponent(id)}/escalate`,
    { method: "POST", body, signal },
  );
}

/** `POST /api/incidents/{id}/flag-interesting` (analyst+, no ownership check). */
export async function flagIncidentInteresting(
  id: string,
  body: IncidentFlagBody,
  signal?: AbortSignal,
): Promise<IncidentWriteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "ok", incident_id: id };
  }
  return request<IncidentWriteResult>(
    `/api/incidents/${encodeURIComponent(id)}/flag-interesting`,
    { method: "POST", body, signal },
  );
}

/** `POST /api/incidents/{id}/evidence` (analyst+, assignee). */
export async function addIncidentEvidence(
  id: string,
  body: IncidentEvidenceBody,
  signal?: AbortSignal,
): Promise<IncidentWriteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "ok", incident_id: id };
  }
  return request<IncidentWriteResult>(
    `/api/incidents/${encodeURIComponent(id)}/evidence`,
    { method: "POST", body, signal },
  );
}

/** `POST /api/incidents/{id}/review` — post-incident review (senior_analyst+). */
export async function saveIncidentReview(
  id: string,
  body: IncidentReviewBody,
  signal?: AbortSignal,
): Promise<IncidentWriteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "ok", review_id: `pir_fixture_${Date.now()}` };
  }
  return request<IncidentWriteResult>(
    `/api/incidents/${encodeURIComponent(id)}/review`,
    { method: "POST", body, signal },
  );
}

/**
 * `POST /api/incidents/merge` — IRREVERSIBLE (senior_analyst+ AND the
 * `incidents_merge` license feature). Callers must confirm before firing.
 */
export async function mergeIncidents(
  body: IncidentMergeBody,
  signal?: AbortSignal,
): Promise<IncidentWriteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "ok", target_id: body.target_id };
  }
  return request<IncidentWriteResult>("/api/incidents/merge", {
    method: "POST",
    body,
    signal,
  });
}

// ---- Overview (Campaign Command) — WO-B7 / WO-B5 ----------------------------
/**
 * `GET /api/overview/summary` → the KPI strip (WO-B7). Each tile is
 * `{ value, ...supporting detail }` so the UI can expand-to-math. Un-gated by
 * tier (the Overview tab is available across tiers).
 */
export async function getOverviewSummary(
  signal?: AbortSignal,
): Promise<OverviewSummary> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { overviewSummaryFixture } = await import("./fixtures/overview");
    return overviewSummaryFixture({ empty: FIXTURES === "empty" });
  }
  return request<OverviewSummary>("/api/overview/summary", { signal });
}

/**
 * `GET /api/campaigns` → `{ campaigns, total }` (WO-B5), worst-severity /
 * longest-dwell first (the server already sorts). Each campaign is the M5
 * attack-chain rollup — see `ApiCampaign`. The Overview maps these onto the
 * `Campaign` viz type via `campaign.ts::adaptCampaign`.
 */
export async function getCampaigns(
  signal?: AbortSignal,
  scope: "active" | "contained" = "active",
): Promise<CampaignsResponse> {
  // "locked" is a MITRE-only fixture (the `mitre` endpoints 403); campaigns are
  // not gated by that feature, so under "locked" they still return populated —
  // this keeps the MitreTab's parallel load deterministic (only /mitre/* throws).
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { campaignsFixture } = await import("./fixtures/overview");
    return campaignsFixture({ empty: FIXTURES === "empty" });
  }
  // WO-H47: request ACTIVE campaigns only.
  //
  // This call previously passed no filter, so it returned every campaign ever
  // recorded, capped at the API's default limit=100. Measured on a live
  // install: 930 campaigns, of which only 3 were active — and because the
  // rollup sorts by (severity, dwell) WITHOUT considering status, the active
  // ones ranked 10th, 244th and 440th. The top 100 was 99 contained + 1 open,
  // so the Campaign map rendered a wall of closed campaigns while silently
  // dropping TWO of the three that actually needed attention.
  //
  // The panel is titled "Active campaigns" and has a "No active campaigns"
  // empty state, so active-only is the intent this call was always missing.
  //
  // `scope` keeps the contained history REACHABLE rather than merely hidden —
  // the Overview's toggle flips this. Defaulting to "active" means every
  // existing caller (MitreTab's live-campaign overlay) gets the corrected
  // behaviour without change.
  const query =
    scope === "contained" ? "?status=contained" : "?active_only=true";
  return request<CampaignsResponse>(`/api/campaigns${query}`, { signal });
}

// ---- NL-Query copilot (WO-B8) — Investigate (WO-U6) -------------------------
/**
 * `POST /api/query` body `{ question }` → the grounded NL-Query answer (WO-B8).
 * The copilot cites the `sources` that informed the answer (answer-level
 * grounding). Auth: `verify_jwt` + `require_nl_query_quota()` — the copilot is a
 * PAID module. The caller must degrade gracefully on the paid/quota gate:
 *   - client-side, the tab checks `copilotAvailable(tier)` and renders the locked
 *     rail without ever calling this;
 *   - at RUNTIME, a 402/403 from `require_nl_query_quota()` throws an `ApiError`
 *     the caller surfaces as an honest gate note (never a fabricated answer).
 *
 * In fixture mode this short-circuits to a typed fixture so the grounded/empty
 * states can be captured without a live backend.
 */
export async function postQuery(
  question: string,
  signal?: AbortSignal,
): Promise<NLQueryResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { investigateQueryFixture } = await import("./fixtures/investigate");
    return investigateQueryFixture(question, { empty: FIXTURES === "empty" });
  }
  return request<NLQueryResponse>("/api/query", {
    method: "POST",
    body: { question },
    signal,
  });
}

/**
 * `POST /api/response/propose` (active response — HUMAN-APPROVED). Body carries
 * the action + target + a REQUIRED reason; the server returns the created
 * proposal as `status: "pending_approval"`. This QUEUES the action for a human to
 * approve in the Respond queue — it does NOT execute, approve, or reverse
 * anything. Role: analyst+ (the server re-checks; the UI mirrors it).
 *
 * In fixture mode this short-circuits to a synthetic `pending_approval` result and
 * performs NO real mutation — so the propose flow can be exercised for
 * screenshots without touching a live active-response subsystem. The shipped path
 * calls the real endpoint only.
 */
export async function proposeContainment(
  body: ProposeContainmentBody,
  signal?: AbortSignal,
): Promise<ProposeContainmentResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return {
      id: `prop_fixture_${Date.now()}`,
      status: "pending_approval",
      action: body.action,
    };
  }
  return request<ProposeContainmentResponse>("/api/response/propose", {
    method: "POST",
    body,
    signal,
  });
}

// ---- MITRE ATT&CK coverage (WO-B6) — MITRE tab (WO-U8) ----------------------
/**
 * Every call below is `verify_jwt` + the `mitre` LICENSE gate. The caller must
 * degrade toward LOCKED on a runtime 402/403 (feature not available) or 503
 * (license not loaded) — the MitreTab renders `FeatureLockedState`, never a
 * broken grid or fabricated coverage. In the shipped license model `mitre` is a
 * core feature in every tier, so this only fires for a restricted/custom license.
 *
 * The fixtures gate here also honours a "locked" sentinel
 * (`NEXT_PUBLIC_DHRUVA_FIXTURES=locked`) so the tier-locked state can be captured
 * without a live backend — the fixture THROWS an ApiError(403) exactly as the
 * real gate would, exercising the tab's real degradation path.
 */

/**
 * `GET /api/mitre/summary` → `{ per_tactic, overall }` — the per-tactic coverage
 * grid (WO-B6 contract). `per_tactic` is already canonical kill-chain order.
 */
export async function getMitreSummary(
  signal?: AbortSignal,
): Promise<MitreSummary> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { mitreSummaryFixture } = await import("./fixtures/mitre");
    return mitreSummaryFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<MitreSummary>("/api/mitre/summary", { signal });
}

/**
 * `GET /api/mitre/incident/{id}` → per-incident kill-chain coverage (WO-B6). The
 * per-stage `org_coverage_pct` is ORG-WIDE (never incident-specific) —
 * `coverage_basis` confirms it and the UI labels it as such. Used to render a
 * campaign's chain as covered-vs-gap stages.
 */
export async function getMitreIncidentCoverage(
  incidentId: string,
  signal?: AbortSignal,
): Promise<MitreIncidentCoverage> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { mitreIncidentCoverageFixture } = await import("./fixtures/mitre");
    return mitreIncidentCoverageFixture(incidentId, {
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<MitreIncidentCoverage>(
    `/api/mitre/incident/${encodeURIComponent(incidentId)}`,
    { signal },
  );
}

/**
 * `GET /api/mitre/gaps` → uncovered techniques grouped by tactic (WO-U8 optional
 * drill-down). Backs the per-tactic "which techniques are uncovered" dialog.
 */
export async function getMitreGaps(signal?: AbortSignal): Promise<MitreGaps> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { mitreGapsFixture } = await import("./fixtures/mitre");
    return mitreGapsFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<MitreGaps>("/api/mitre/gaps", { signal });
}

// ---- Compliance coverage matrix (WO-U16) — MITRE tab sub-view (READ-ONLY) ---
/**
 * Both calls are `require_role("admin","senior_analyst")` +
 * `require_license_feature("compliance_sca")`. The compliance sub-view of the
 * MITRE tab gates client-side by BOTH role (senior_analyst+) and tier (a runtime
 * 402/403 degrades that segment to FeatureLockedState) — the server remains the
 * enforcement point. READ-ONLY: both are GETs; nothing here mutates.
 *
 * The fixture branches short-circuit for screenshot mode: "empty" yields the
 * honest no-frameworks-configured state; "true" yields a small synthetic matrix;
 * "locked" THROWS ApiError(403) exactly as the `compliance_sca` gate would, so
 * the segment's tier-locked path can be captured without a live backend.
 */

/**
 * `GET /api/compliance/matrix` → `{ frameworks: { <name>: Control[] } }` — the
 * STRUCTURE (frameworks → controls), no coverage numbers. `frameworks == {}`
 * (mapping YAML absent) is a valid response the caller renders as empty. Loaded
 * LAZILY on first entry to the compliance sub-view (never on tab mount).
 */
export async function getComplianceMatrix(
  signal?: AbortSignal,
): Promise<ComplianceMatrix> {
  if (FIXTURES === "locked") {
    throw new ApiError(403, "compliance_sca feature not available (fixture)");
  }
  if (FIXTURES === "true" || FIXTURES === "empty") {
    if (FIXTURES === "empty") return { frameworks: {} };
    return {
      frameworks: {
        "PCI-DSS": [
          {
            control_id: "10.2",
            control_name: "Audit trails for access to system components",
            description: "Automated audit trails for all system components.",
            rule_groups: ["authentication", "audit"],
            mitre_techniques: ["T1078"],
          },
          {
            control_id: "11.4",
            control_name: "Intrusion detection / prevention",
            description: "Detect and/or prevent intrusions into the network.",
            rule_groups: ["ids", "attack"],
            mitre_techniques: ["T1046"],
          },
        ],
        "HIPAA": [
          {
            control_id: "164.312(b)",
            control_name: "Audit controls",
            description: "Record and examine activity in systems with ePHI.",
            rule_groups: ["audit"],
            mitre_techniques: [],
          },
        ],
      },
    };
  }
  return request<ComplianceMatrix>("/api/compliance/matrix", { signal });
}

/**
 * `GET /api/compliance/{framework}/coverage` → per-framework detection coverage
 * (`total_controls`, `covered_controls`, `coverage_pct`, per-control rows). A bad
 * framework name returns 404 — the caller surfaces it as an honest "unknown
 * framework" error, never a fabricated table. Loaded on framework selection.
 */
export async function getFrameworkCoverage(
  framework: string,
  signal?: AbortSignal,
): Promise<FrameworkCoverage> {
  if (FIXTURES === "locked") {
    throw new ApiError(403, "compliance_sca feature not available (fixture)");
  }
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const controls =
      FIXTURES === "empty"
        ? []
        : [
            {
              control_id: "10.2",
              control_name: "Audit trails for access to system components",
              description: "Automated audit trails for all system components.",
              rule_groups: ["authentication", "audit"],
              mitre_techniques: ["T1078"],
              detection_count: 14,
              covered: true,
            },
            {
              control_id: "11.4",
              control_name: "Intrusion detection / prevention",
              description: "Detect and/or prevent intrusions into the network.",
              rule_groups: ["ids", "attack"],
              mitre_techniques: ["T1046"],
              detection_count: 0,
              covered: false,
            },
          ];
    const covered = controls.filter((c) => c.covered).length;
    const total = controls.length;
    return {
      framework,
      total_controls: total,
      covered_controls: covered,
      coverage_pct: total > 0 ? Math.round((covered / total) * 1000) / 10 : 0,
      controls,
    };
  }
  return request<FrameworkCoverage>(
    `/api/compliance/${encodeURIComponent(framework)}/coverage`,
    { signal },
  );
}

// ---- Detection proposals (WO-U9) — Detection tab (READ-ONLY) ----------------
/**
 * `GET /api/detection/proposals` → `{ proposals, count }`. Auth: `verify_jwt` +
 * `require_license_feature("detection")` (senior_analyst+ per the shell ACL).
 * READ-ONLY view — approve/deploy/reject/rollback are a later gated WO and are
 * NOT called here. A runtime 402/403 from the `detection` gate → the tab renders
 * `FeatureLockedState`.
 *
 * The `locked` fixture sentinel THROWS ApiError(403) exactly like the gate so
 * that degradation can be captured without a live backend.
 */
export async function getDetectionProposals(
  signal?: AbortSignal,
): Promise<DetectionProposalsResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { detectionProposalsFixture } = await import("./fixtures/detection");
    return detectionProposalsFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<DetectionProposalsResponse>("/api/detection/proposals", {
    signal,
  });
}

// ---- Threat Intel (WO-U9) — Threat Intel tab (READ-ONLY) --------------------
/**
 * `GET /api/threat-intel/stats` → `{ stats, feeds, kev_count }`. Auth:
 * `verify_jwt` + `require_license_feature("ti_feeds_tier1")`. 402/403 → locked.
 */
export async function getTIStats(
  signal?: AbortSignal,
): Promise<TIStatsResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { tiStatsFixture } = await import("./fixtures/threatintel");
    return tiStatsFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<TIStatsResponse>("/api/threat-intel/stats", { signal });
}

/**
 * `GET /api/threat-intel/cve?kev_only=&limit=` → `{ cves, total }`. Same
 * `ti_feeds_tier1` gate. `kev_only` filters to the CISA-KEV catalog.
 */
export async function getTICves(
  params: { kev_only?: boolean; limit?: number } = {},
  signal?: AbortSignal,
): Promise<TICvesResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { tiCvesFixture } = await import("./fixtures/threatintel");
    return tiCvesFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
      kevOnly: params.kev_only,
    });
  }
  return request<TICvesResponse>("/api/threat-intel/cve", {
    query: {
      kev_only: params.kev_only ? "true" : undefined,
      limit: params.limit,
    },
    signal,
  });
}

/**
 * `POST /api/threat-intel/collect` (WO-U12) — manually trigger a TI collection
 * cycle. Auth: `require_role("admin","senior_analyst")` ⇒ senior_analyst+ (see
 * `rbac.ts::tiCollectGate`) + `require_license_feature("ti_feeds_tier1")`,
 * rate-limited 2/min server-side. No body. Kicks a background collect_all thread
 * and returns immediately with `{status:"collection_started"}` (or
 * `{status:"error", message}` if the collector is not initialized); a 402/403
 * (role/tier) or 429 (rate limit) is surfaced typed by the calling tab. Call
 * ONLY from an explicit confirm. FIXTURE-gated like the other TI reads/triggers:
 * in fixture mode it short-circuits to a synthetic success and performs NO real
 * collection — the server remains the enforcement point.
 */
export async function triggerTICollection(
  signal?: AbortSignal,
): Promise<TICollectResult> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    return { status: "collection_started", message: "TI collection started (fixture)" };
  }
  return request<TICollectResult>("/api/threat-intel/collect", {
    method: "POST",
    signal,
  });
}

// ---- Host Integrity (WO-U9) — fim tab (READ-ONLY) ---------------------------
/**
 * `GET /api/agents` → `{ agents, total }`. Auth: `verify_jwt` (NOT license-gated;
 * scoped to the caller's tenant agents server-side). The agent picker drives the
 * per-agent host-integrity reads below.
 */
export async function getAgents(
  params: { status?: string } = {},
  signal?: AbortSignal,
): Promise<AgentsResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    // Agents are not host_integrity-gated, so under "locked" they still return
    // populated — only the syscheck/rootcheck/registry + vuln reads throw 403.
    const { agentsFixture } = await import("./fixtures/hostintegrity");
    return agentsFixture({ empty: FIXTURES === "empty" });
  }
  return request<AgentsResponse>("/api/agents", {
    query: { status: params.status },
    signal,
  });
}

/**
 * `GET /api/agents/{id}/syscheck` — FIM. Auth: analyst+ +
 * `require_license_feature("host_integrity")`. 402/403 → locked (host-integrity
 * section only). READ-ONLY.
 */
export async function getAgentSyscheck(
  agentId: string,
  signal?: AbortSignal,
): Promise<SyscheckResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { syscheckFixture } = await import("./fixtures/hostintegrity");
    return syscheckFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<SyscheckResponse>(
    `/api/agents/${encodeURIComponent(agentId)}/syscheck`,
    { signal },
  );
}

/** `GET /api/agents/{id}/rootcheck` — policy monitoring. Same gate as syscheck. */
export async function getAgentRootcheck(
  agentId: string,
  signal?: AbortSignal,
): Promise<RootcheckResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { rootcheckFixture } = await import("./fixtures/hostintegrity");
    return rootcheckFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<RootcheckResponse>(
    `/api/agents/${encodeURIComponent(agentId)}/rootcheck`,
    { signal },
  );
}

/** `GET /api/agents/{id}/registry` — Windows registry FIM. Same gate as syscheck. */
export async function getAgentRegistry(
  agentId: string,
  signal?: AbortSignal,
): Promise<RegistryResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { registryFixture } = await import("./fixtures/hostintegrity");
    return registryFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<RegistryResponse>(
    `/api/agents/${encodeURIComponent(agentId)}/registry`,
    { signal },
  );
}

/**
 * `GET /api/vulnerabilities/summary` → host-vulnerability overview. Auth:
 * `verify_jwt` + `require_license_feature("compliance_sca")`. This is a DIFFERENT
 * license gate from host_integrity, so the tab degrades the vuln section
 * independently of the FIM/rootcheck/registry section.
 */
export async function getVulnSummary(
  signal?: AbortSignal,
): Promise<VulnSummary> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { vulnSummaryFixture } = await import("./fixtures/hostintegrity");
    return vulnSummaryFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<VulnSummary>("/api/vulnerabilities/summary", { signal });
}

/**
 * `GET /api/vulnerabilities?agent_id=…` → this agent's vulnerabilities. Auth:
 * `verify_jwt` + `require_license_feature("compliance_sca")` — the SAME gate as
 * the estate summary (a `compliance_sca` 402/403 degrades the per-agent vuln view
 * to `FeatureLockedState`, independently of the host_integrity FIM view). The
 * items are RAW Wazuh vuln documents (`AgentVulnerability`), rendered defensively.
 * READ-ONLY — remediation is an admin-gated write NOT wired here.
 */
export async function getAgentVulnerabilities(
  agentId: string,
  params: { severity?: string; limit?: number } = {},
  signal?: AbortSignal,
): Promise<AgentVulnerabilitiesResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { agentVulnerabilitiesFixture } = await import(
      "./fixtures/hostintegrity"
    );
    return agentVulnerabilitiesFixture(agentId, {
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<AgentVulnerabilitiesResponse>("/api/vulnerabilities", {
    query: {
      agent_id: agentId,
      severity: params.severity,
      limit: params.limit ?? 200,
    },
    signal,
  });
}

/**
 * `GET /api/vulnerabilities/critical?limit=` (WO-U15 READ half) → fleet-wide
 * Critical-severity vulns as RAW Wazuh vuln docs, scoped to the tenant's allowed
 * agents server-side. Auth: `verify_jwt` +
 * `require_license_feature("compliance_sca")` — the SAME gate as the estate/per-
 * agent vuln reads, so a runtime 402/403 degrades this section exactly like the
 * others (never a fabricated table). `limit` is 1..200 (server default 50); it is
 * omitted from the query when undefined so the server default applies. READ-ONLY.
 */
export async function getCriticalVulns(
  limit?: number,
  signal?: AbortSignal,
): Promise<CriticalVulnerabilitiesResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { criticalVulnsFixture } = await import("./fixtures/hostintegrity");
    return criticalVulnsFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<CriticalVulnerabilitiesResponse>(
    "/api/vulnerabilities/critical",
    { query: { limit }, signal },
  );
}

/**
 * `GET /api/vulnerabilities/remediation?agent_id=…&limit=` (WO-U15 READ half) →
 * per-agent recommended remediation for that agent's vulns (server does
 * `_verify_agent_access`). Auth: `verify_jwt` +
 * `require_license_feature("compliance_sca")` (402/403 → locked). The items carry
 * an ADVISORY package-update `command` string — DISPLAY ONLY; the UI never
 * executes it (the state-changing `/remediate` execute path is a separate,
 * admin-gated WO that is deliberately NOT wired here). `limit` is 1..200 (server
 * default 50), omitted when undefined so the server default applies. READ-ONLY.
 */
export async function getVulnRemediation(
  agentId: string,
  limit?: number,
  signal?: AbortSignal,
): Promise<VulnRemediationResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { vulnRemediationFixture } = await import("./fixtures/hostintegrity");
    return vulnRemediationFixture(agentId, {
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<VulnRemediationResponse>("/api/vulnerabilities/remediation", {
    query: { agent_id: agentId, limit },
    signal,
  });
}

/**
 * `POST /api/vulnerabilities/remediate` (WO-U15 EXECUTE half) — run a package
 * update on an agent via Wazuh active response. STATE-CHANGING and
 * ACTIVE-RESPONSE-ADJACENT. Server gating (MIRRORED here, NEVER relaxed):
 * `require_admin` (ADMIN ONLY — stricter than the Respond/SOAR senior_analyst+
 * gates) + `require_license_feature("vuln_remediation")` + rate-limit 3/min +
 * `_verify_agent_access` + platform-restricted (Linux apt/yum/zypper only; other
 * platforms → 400). Body is `{ agent_id, package_name }`. `status:"pending"`
 * means the AR command was ACCEPTED (confirm with `verifyRemediation`);
 * `status:"failed"` means the dispatch failed (nothing in force). Call ONLY from
 * an explicit admin confirm dialog. A 400 (platform / agent-id), 402/403
 * (tier/role) or 429 (rate limit) is surfaced typed to the calling tab. FIXTURE-
 * gated: in fixture mode it short-circuits to a synthetic `pending` result and
 * performs NO real remediation — the server remains the enforcement point.
 */
export async function executeRemediation(
  agentId: string,
  packageName: string,
  signal?: AbortSignal,
): Promise<RemediationExecuteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    return {
      status: "pending",
      agent_id: agentId,
      package: packageName,
      pkg_manager: "apt",
      version_before: "1.0.0-1",
      result: { success: true },
      message: "Use /api/vulnerabilities/verify to confirm update (fixture)",
    };
  }
  return request<RemediationExecuteResult>("/api/vulnerabilities/remediate", {
    method: "POST",
    body: { agent_id: agentId, package_name: packageName },
    signal,
  });
}

/**
 * `GET /api/vulnerabilities/verify?agent_id=…&package_name=…&version_before=…`
 * (WO-U15 EXECUTE half) — the "did the update land" follow-up check. Auth:
 * `verify_jwt` + `require_license_feature("compliance_sca")`. Read-only. Pass the
 * `version_before` returned by `executeRemediation` so the server can report an
 * exact before→after transition (it is omitted from the query when undefined).
 * FIXTURE-gated to a synthetic `updated` result so the verify UX can be captured
 * without a live backend.
 */
export async function verifyRemediation(
  agentId: string,
  packageName: string,
  versionBefore?: string,
  signal?: AbortSignal,
): Promise<RemediationVerifyResult> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    return {
      status: "updated",
      message: `Package updated: ${versionBefore ?? "1.0.0-1"} -> 1.0.0-2 (fixture)`,
      version_before: versionBefore ?? "1.0.0-1",
      version_after: "1.0.0-2",
    };
  }
  return request<RemediationVerifyResult>("/api/vulnerabilities/verify", {
    query: {
      agent_id: agentId,
      package_name: packageName,
      version_before: versionBefore,
    },
    signal,
  });
}

// ---- Host Integrity (WO-U14) — syscollector inventory + SCA (READ-ONLY) -----
// These five endpoints are `verify_jwt` only (NOT license-gated) and enforce
// tenant isolation server-side via `_verify_agent_access`. The items are RAW
// Wazuh syscollector / SCA dicts, rendered defensively by the tab. Because they
// carry no license gate they do not throw 402/403; the tab still tolerates a lock
// error (never occurs in practice) for symmetry with the FIM/vuln reads. Loaded
// LAZILY on first entry to the inventory / SCA views — never in the eager host
// load — so picking a host does not fan out extra requests.

/** `GET /api/agents/{id}/processes` → running processes (syscollector). */
export async function getAgentProcesses(
  agentId: string,
  signal?: AbortSignal,
): Promise<AgentProcessesResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { agentProcessesFixture } = await import("./fixtures/hostintegrity");
    return agentProcessesFixture(agentId, { empty: FIXTURES === "empty" });
  }
  return request<AgentProcessesResponse>(
    `/api/agents/${encodeURIComponent(agentId)}/processes`,
    { signal },
  );
}

/** `GET /api/agents/{id}/ports` → open ports / network connections (syscollector). */
export async function getAgentPorts(
  agentId: string,
  signal?: AbortSignal,
): Promise<AgentPortsResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { agentPortsFixture } = await import("./fixtures/hostintegrity");
    return agentPortsFixture(agentId, { empty: FIXTURES === "empty" });
  }
  return request<AgentPortsResponse>(
    `/api/agents/${encodeURIComponent(agentId)}/ports`,
    { signal },
  );
}

/** `GET /api/agents/{id}/packages` → installed packages (syscollector). */
export async function getAgentPackages(
  agentId: string,
  signal?: AbortSignal,
): Promise<AgentPackagesResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { agentPackagesFixture } = await import("./fixtures/hostintegrity");
    return agentPackagesFixture(agentId, { empty: FIXTURES === "empty" });
  }
  return request<AgentPackagesResponse>(
    `/api/agents/${encodeURIComponent(agentId)}/packages`,
    { signal },
  );
}

/** `GET /api/agents/{agent_id}/sca` → SCA policy list with pass/fail summary. */
export async function getAgentCompliance(
  agentId: string,
  signal?: AbortSignal,
): Promise<ScaPoliciesResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { agentComplianceFixture } = await import("./fixtures/hostintegrity");
    return agentComplianceFixture(agentId, { empty: FIXTURES === "empty" });
  }
  return request<ScaPoliciesResponse>(
    `/api/agents/${encodeURIComponent(agentId)}/sca`,
    { signal },
  );
}

/**
 * `GET /api/agents/{agent_id}/sca/{policy_id}?result_filter=&limit=` → the
 * individual SCA checks for one policy (drill-down from the policy list).
 */
export async function getAgentCompliancePolicy(
  agentId: string,
  policyId: string,
  opts: { resultFilter?: string; limit?: number } = {},
  signal?: AbortSignal,
): Promise<ScaChecksResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { agentCompliancePolicyFixture } = await import(
      "./fixtures/hostintegrity"
    );
    return agentCompliancePolicyFixture(agentId, policyId, {
      empty: FIXTURES === "empty",
    });
  }
  return request<ScaChecksResponse>(
    `/api/agents/${encodeURIComponent(agentId)}/sca/${encodeURIComponent(policyId)}`,
    {
      query: { result_filter: opts.resultFilter, limit: opts.limit },
      signal,
    },
  );
}

// ---- Metrics (WO-U9) — Metrics tab (READ-ONLY) ------------------------------
/**
 * `GET /api/metrics/soc-summary` → `{ today, week, month }` MTT snapshots. Auth:
 * `require_role("admin","senior_analyst")` (NOT license-gated). READ-ONLY.
 */
export async function getSocSummary(
  signal?: AbortSignal,
): Promise<SocSummaryResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { socSummaryFixture } = await import("./fixtures/metrics");
    return socSummaryFixture({ empty: FIXTURES === "empty" });
  }
  return request<SocSummaryResponse>("/api/metrics/soc-summary", { signal });
}

/** `GET /api/metrics/automation-rates` → auto-close / TP / FP rates. */
export async function getAutomationRates(
  params: { days?: number } = {},
  signal?: AbortSignal,
): Promise<AutomationRates> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { automationRatesFixture } = await import("./fixtures/metrics");
    return automationRatesFixture({ empty: FIXTURES === "empty" });
  }
  return request<AutomationRates>("/api/metrics/automation-rates", {
    query: { days: params.days },
    signal,
  });
}

/** `GET /api/dashboard/stats` → comprehensive counts (open/critical, pending, trend, noisy rules). */
export async function getDashboardStats(
  signal?: AbortSignal,
): Promise<DashboardStats> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { dashboardStatsFixture } = await import("./fixtures/metrics");
    return dashboardStatsFixture({ empty: FIXTURES === "empty" });
  }
  return request<DashboardStats>("/api/dashboard/stats", { signal });
}

/**
 * `GET /api/metrics/analyst-performance` → `{ analysts }` per-analyst activity.
 * `require_role("admin","senior_analyst")`, NOT license-gated. READ-ONLY.
 */
export async function getAnalystPerformance(
  signal?: AbortSignal,
): Promise<AnalystPerformanceResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { analystPerformanceFixture } = await import("./fixtures/metrics");
    return analystPerformanceFixture({ empty: FIXTURES === "empty" });
  }
  return request<AnalystPerformanceResponse>(
    "/api/metrics/analyst-performance",
    { signal },
  );
}

/** `GET /api/metrics/analyst-workload` → `{ analysts }` open-load + overload flags. */
export async function getAnalystWorkload(
  signal?: AbortSignal,
): Promise<AnalystWorkloadResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { analystWorkloadFixture } = await import("./fixtures/metrics");
    return analystWorkloadFixture({ empty: FIXTURES === "empty" });
  }
  return request<AnalystWorkloadResponse>("/api/metrics/analyst-workload", {
    signal,
  });
}

/** `GET /api/metrics/case-aging` → `{ cases }` open incidents by age, stale-flagged. */
export async function getCaseAging(
  signal?: AbortSignal,
): Promise<CaseAgingResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { caseAgingFixture } = await import("./fixtures/metrics");
    return caseAgingFixture({ empty: FIXTURES === "empty" });
  }
  return request<CaseAgingResponse>("/api/metrics/case-aging", { signal });
}

/** `GET /api/metrics/hunt-trends` → `{ cycles }` hunt hit/confirmation trends. */
export async function getHuntTrends(
  signal?: AbortSignal,
): Promise<HuntTrendsResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { huntTrendsFixture } = await import("./fixtures/metrics");
    return huntTrendsFixture({ empty: FIXTURES === "empty" });
  }
  return request<HuntTrendsResponse>("/api/metrics/hunt-trends", { signal });
}

/** `GET /api/metrics/automation-health` → enrichment latency + SOAR action stats. */
export async function getAutomationHealth(
  signal?: AbortSignal,
): Promise<AutomationHealth> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { automationHealthFixture } = await import("./fixtures/metrics");
    return automationHealthFixture({ empty: FIXTURES === "empty" });
  }
  return request<AutomationHealth>("/api/metrics/automation-health", { signal });
}

/** `GET /api/metrics/soc-performance` → MTT snapshot + daily MTT trend series. */
export async function getSocPerformance(
  signal?: AbortSignal,
): Promise<SocPerformanceResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { socPerformanceFixture } = await import("./fixtures/metrics");
    return socPerformanceFixture({ empty: FIXTURES === "empty" });
  }
  return request<SocPerformanceResponse>("/api/metrics/soc-performance", {
    signal,
  });
}

// ---- Reports (WO-U9c) — Reports tab (generate-on-demand, READ-ONLY) ---------
/**
 * `GET /api/metrics/reports/{daily|weekly|monthly}` → a freshly-generated SOC
 * report as JSON. `require_role("admin","senior_analyst")` +
 * `require_license_feature("reports")`. The generator runs only SELECTs (no
 * writes/persistence), so this is a READ, not a mutation. A 402/403 means the
 * `reports` license feature is unavailable → the tab shows FeatureLockedState.
 *
 * The `locked` fixture sentinel (`NEXT_PUBLIC_DHRUVA_FIXTURES=locked`) THROWS an
 * ApiError(403) shaped like the gate so the locked state can be captured.
 */
export async function getSocReport(
  reportType: SocReportType,
  signal?: AbortSignal,
): Promise<SocReport> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { socReportFixture } = await import("./fixtures/reports");
    return socReportFixture(reportType, {
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<SocReport>(`/api/metrics/reports/${reportType}`, { signal });
}

// ---- Admin (WO-U9) — Admin tab (READ-ONLY, never tier-locked) ---------------
/**
 * `GET /api/admin/users` → `{ users, total }`. Auth: `require_role("admin")`.
 * READ-ONLY — user create/edit is NOT wired here.
 */
export async function getAdminUsers(
  params: { include_inactive?: boolean } = {},
  signal?: AbortSignal,
): Promise<AdminUsersResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { adminUsersFixture } = await import("./fixtures/admin");
    return adminUsersFixture({ empty: FIXTURES === "empty" });
  }
  return request<AdminUsersResponse>("/api/admin/users", {
    query: { include_inactive: params.include_inactive ? "true" : undefined },
    signal,
  });
}

/**
 * `GET /api/admin/tenants` → `{ tenants }`. Auth: `require_role("mssp_admin")` —
 * the tab gates this call on the mssp_admin role client-side (mirroring the
 * server) so a plain admin never fires a request the server would 403. READ-ONLY.
 */
export async function getAdminTenants(
  signal?: AbortSignal,
): Promise<AdminTenantsResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { adminTenantsFixture } = await import("./fixtures/admin");
    return adminTenantsFixture({ empty: FIXTURES === "empty" });
  }
  return request<AdminTenantsResponse>("/api/admin/tenants", { signal });
}

/**
 * `GET /api/admin/audit-log?actor=&action=&limit=` → `{ entries, total }`. Auth:
 * `require_role("admin")`. READ-ONLY append-only trail.
 */
export async function getAdminAuditLog(
  params: { actor?: string; action?: string; limit?: number } = {},
  signal?: AbortSignal,
): Promise<AdminAuditLogResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { adminAuditLogFixture } = await import("./fixtures/admin");
    return adminAuditLogFixture({ empty: FIXTURES === "empty" });
  }
  return request<AdminAuditLogResponse>("/api/admin/audit-log", {
    query: { actor: params.actor, action: params.action, limit: params.limit ?? 200 },
    signal,
  });
}

/**
 * `GET /api/admin/config` → `{ config }` (curated safe subset). Auth:
 * `require_role("admin")`. READ-ONLY — there is no config-write endpoint.
 */
export async function getAdminConfig(
  signal?: AbortSignal,
): Promise<AdminConfigResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { adminConfigFixture } = await import("./fixtures/admin");
    return adminConfigFixture({ empty: FIXTURES === "empty" });
  }
  return request<AdminConfigResponse>("/api/admin/config", { signal });
}

/**
 * `GET /api/admin/governance/charter` → `{ charter, message? }`. Auth: `verify_jwt`.
 * READ-ONLY institutional knowledge (the SOC charter YAML).
 */
export async function getAdminGovernanceCharter(
  signal?: AbortSignal,
): Promise<AdminGovernanceCharterResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { adminGovernanceCharterFixture } = await import("./fixtures/admin");
    return adminGovernanceCharterFixture({ empty: FIXTURES === "empty" });
  }
  return request<AdminGovernanceCharterResponse>(
    "/api/admin/governance/charter",
    { signal },
  );
}

/**
 * `GET /api/admin/governance/data-access` → the raw data-access-policy dict
 * (NO wrapper key). Auth: `admin` OR `senior_analyst`. READ-ONLY.
 */
export async function getAdminDataAccessPolicy(
  signal?: AbortSignal,
): Promise<AdminDataAccessPolicy> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { adminDataAccessFixture } = await import("./fixtures/admin");
    return adminDataAccessFixture({ empty: FIXTURES === "empty" });
  }
  return request<AdminDataAccessPolicy>(
    "/api/admin/governance/data-access",
    { signal },
  );
}

/**
 * `GET /api/admin/anon-mappings?field_type=&limit=` → `{ mappings, total }`. Auth:
 * `require_role("admin")`. READ-ONLY admin token↔value map.
 */
export async function getAdminAnonMappings(
  params: { field_type?: string; limit?: number } = {},
  signal?: AbortSignal,
): Promise<AdminAnonMappingsResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { adminAnonMappingsFixture } = await import("./fixtures/admin");
    return adminAnonMappingsFixture({ empty: FIXTURES === "empty" });
  }
  return request<AdminAnonMappingsResponse>("/api/admin/anon-mappings", {
    query: { field_type: params.field_type, limit: params.limit ?? 200 },
    signal,
  });
}

// ---- SOAR (WO-U9b) — SOAR tab (READ-ONLY) -----------------------------------
/**
 * `GET /api/soar/playbooks` → `{ playbooks }`. Auth: `verify_jwt` +
 * `require_license_feature("soar")` (senior_analyst+ per the shell ACL).
 * READ-ONLY — enable/disable (toggle) and run/approve/reject/rollback are NOT
 * wired here (they are admin/senior gated writes for a later WO). A runtime
 * 402/403 from the `soar` gate → the tab renders `FeatureLockedState`. The
 * `locked` fixture sentinel THROWS ApiError(403) like the gate.
 */
export async function getSoarPlaybooks(
  signal?: AbortSignal,
): Promise<SoarPlaybooksResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { soarPlaybooksFixture } = await import("./fixtures/soar");
    return soarPlaybooksFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<SoarPlaybooksResponse>("/api/soar/playbooks", { signal });
}

/**
 * `GET /api/soar/executions?limit=` → `{ executions }`. Same `soar` gate.
 * READ-ONLY (approve/reject/rollback not wired).
 */
export async function getSoarExecutions(
  params: { limit?: number } = {},
  signal?: AbortSignal,
): Promise<SoarExecutionsResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { soarExecutionsFixture } = await import("./fixtures/soar");
    return soarExecutionsFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<SoarExecutionsResponse>("/api/soar/executions", {
    query: { limit: params.limit },
    signal,
  });
}

/** `GET /api/soar/stats` → SOAR dashboard counts. Same `soar` gate. */
export async function getSoarStats(signal?: AbortSignal): Promise<SoarStats> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { soarStatsFixture } = await import("./fixtures/soar");
    return soarStatsFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<SoarStats>("/api/soar/stats", { signal });
}

// ---- Active Response queue + audit (WO-U9b) — Respond tab (READ-ONLY) --------
/**
 * `GET /api/response/queue?limit=` → `{ queue, total }` — active/pending blocks.
 * Auth: `require_role(read_only+)` (surfaced to senior_analyst+ by the shell ACL);
 * NOT license-gated, but the tab still degrades a runtime 402/403 to
 * `FeatureLockedState` defensively. READ-ONLY: this NEVER wires propose/approve/
 * execute/reverse — approving a queued containment is a human-gated senior_analyst+
 * write delivered in a dedicated later WO. Active response stays human-approved.
 */
export async function getResponseQueue(
  params: { limit?: number } = {},
  signal?: AbortSignal,
): Promise<ResponseQueueResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    // The queue/audit endpoints are NOT license-gated, so under "locked" they
    // still return populated (only the SOAR/Tickets/Groups gates 403).
    const { responseQueueFixture } = await import("./fixtures/response");
    return responseQueueFixture({ empty: FIXTURES === "empty" });
  }
  return request<ResponseQueueResponse>("/api/response/queue", {
    query: { limit: params.limit },
    signal,
  });
}

/**
 * `GET /api/response/audit?limit=&status=&mode=` → `{ audit, total }` — the
 * durable active-response audit trail. Same role gate as the queue. READ-ONLY.
 */
export async function getResponseAudit(
  params: { limit?: number; status?: string; mode?: string } = {},
  signal?: AbortSignal,
): Promise<ResponseAuditResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { responseAuditFixture } = await import("./fixtures/response");
    return responseAuditFixture({ empty: FIXTURES === "empty" });
  }
  return request<ResponseAuditResponse>("/api/response/audit", {
    query: { limit: params.limit, status: params.status, mode: params.mode },
    signal,
  });
}

// ---- Tickets (WO-U9b) — Tickets tab (READ-ONLY) -----------------------------
/**
 * `GET /api/tickets?status=&provider=&limit=` → `{ tickets, total }`. Auth:
 * `verify_jwt` + `require_license_feature("ticketing")` (all roles per the shell
 * ACL). READ-ONLY — create/sync/retry are gated writes NOT wired here. A runtime
 * 402/403 from the `ticketing` gate → `FeatureLockedState`; the `locked` fixture
 * sentinel THROWS ApiError(403) like the gate.
 */
export async function getTickets(
  params: { status?: string; provider?: string; limit?: number } = {},
  signal?: AbortSignal,
): Promise<TicketsResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { ticketsFixture } = await import("./fixtures/tickets");
    return ticketsFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<TicketsResponse>("/api/tickets", {
    query: {
      status: params.status,
      provider: params.provider,
      limit: params.limit,
    },
    signal,
  });
}

/** `GET /api/tickets/stats` → ticket dashboard counts. Same `ticketing` gate. */
export async function getTicketStats(
  signal?: AbortSignal,
): Promise<TicketStats> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { ticketStatsFixture } = await import("./fixtures/tickets");
    return ticketStatsFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<TicketStats>("/api/tickets/stats", { signal });
}

// ---- Agent Groups (WO-U9b) — Agent Groups tab (READ-ONLY, mssp_admin) --------
/**
 * `GET /api/groups?limit=` → `{ groups, total }`. Auth: `require_role("mssp_admin")`
 * + `require_license_feature("host_integrity")` — the Wazuh group list is
 * Manager-GLOBAL, so it is a structural mssp_admin-only boundary. The tab gates
 * this call on the mssp_admin role client-side (mirroring the server) so a lower
 * role never fires a request the server would 403. READ-ONLY — no group edit. A
 * runtime 402/403 from the `host_integrity` gate → `FeatureLockedState`; the
 * `locked` fixture sentinel THROWS ApiError(403) like the gate.
 */
export async function getAgentGroups(
  params: { limit?: number } = {},
  signal?: AbortSignal,
): Promise<GroupsResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { groupsFixture } = await import("./fixtures/groups");
    return groupsFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<GroupsResponse>("/api/groups", {
    query: { limit: params.limit },
    signal,
  });
}

// ---- Hunt (WO-U9c) — Hunt tab (READ-ONLY) -----------------------------------
/**
 * `GET /api/hunt/findings?limit=` → `{ findings, total }`. Auth: `require_role(
 * admin, senior_analyst)` + `require_license_feature("hunt")` (surfaced to
 * senior_analyst+ by the shell ACL). READ-ONLY — confirm/dismiss (`POST
 * /api/hunt/review`) is a gated write NOT wired here. A runtime 402/403 from the
 * `hunt` gate → the tab renders `FeatureLockedState`; the `locked` fixture
 * sentinel THROWS ApiError(403) like the gate.
 */
export async function getHuntFindings(
  params: { status?: string; limit?: number } = {},
  signal?: AbortSignal,
): Promise<HuntFindingsResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { huntFindingsFixture } = await import("./fixtures/hunt");
    return huntFindingsFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<HuntFindingsResponse>("/api/hunt/findings", {
    query: { status: params.status, limit: params.limit },
    signal,
  });
}

/**
 * `GET /api/hunt/library?limit=` → `{ hypotheses, total }`. Auth: `require_role(
 * admin, senior_analyst)` (NOT license-gated). READ-ONLY — replay (POST) is NOT
 * wired here. The `locked` fixture sentinel still populates this (the library is
 * not `hunt`-gated), so only findings drive the tab's lock.
 */
export async function getHuntLibrary(
  params: { limit?: number } = {},
  signal?: AbortSignal,
): Promise<HuntLibraryResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { huntLibraryFixture } = await import("./fixtures/hunt");
    return huntLibraryFixture({ empty: FIXTURES === "empty" });
  }
  return request<HuntLibraryResponse>("/api/hunt/library", {
    query: { limit: params.limit },
    signal,
  });
}

// ---- Hunt WRITES (Hunt tab) — run cycle / review finding / replay -----------
/**
 * The three hunt writes. Each mirrors a server route + RBAC gate (see
 * `rbac.ts::huntActionGate`) and is FIXTURE-GATED like `submitTriageReview`: in
 * fixture mode it short-circuits to a synthetic success and performs NO real
 * mutation, so the flows can be exercised for screenshots without a live
 * backend. The shipped production path calls the real endpoint ONLY (the fixture
 * branch is dead-code-eliminated when `NEXT_PUBLIC_DHRUVA_FIXTURES` is unset).
 * The server remains the enforcement point for RBAC, the license gate, and the
 * confirm→auto-incident side effect — the client never bypasses it.
 */

/**
 * `POST /api/hunt/run` — trigger a background hunt cycle. Auth: `require_admin` +
 * `require_license_feature("hunt")` (rate-limited 3/min). Returns `202`-style
 * `{status:"accepted", message}`; 503 if the hunt agent is not initialized.
 */
export async function triggerHuntCycle(
  signal?: AbortSignal,
): Promise<HuntRunResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "accepted", message: "Hunt cycle started in background" };
  }
  return request<HuntRunResult>("/api/hunt/run", { method: "POST", signal });
}

/**
 * `POST /api/hunt/review` — confirm or dismiss a finding. Auth: `require_role(
 * admin, senior_analyst)` + `require_license_feature("hunt")`. `confirmed: true`
 * (only with `status: "confirmed"`) triggers the server-side side effects:
 * auto-index to the KB AND auto-create an incident. `notes` is optional (no
 * server reason gate). The tab confirm-gates the confirm action because of that
 * irreversible incident creation.
 */
export async function reviewHuntFinding(
  body: HuntReviewBody,
  signal?: AbortSignal,
): Promise<HuntReviewResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "ok", finding_id: body.finding_id, action: body.status };
  }
  return request<HuntReviewResult>("/api/hunt/review", {
    method: "POST",
    body,
    signal,
  });
}

/**
 * `POST /api/hunt/library/{id}/replay` — re-execute a saved hypothesis query.
 * Auth: `require_role(admin, senior_analyst)` — NOTE: NOT license-gated. A
 * read-ish action: the server re-runs the stored, key-validated OpenSearch query
 * tenant-scoped and returns `{hypothesis, query_index, hit_count, sample_hits}`.
 * 404 if the hypothesis is gone, 400 on an invalid/blocked query, 503 if the
 * hunt agent is unavailable, 500 on execution failure. Mutates nothing, so no
 * confirm dialog — but it IS senior_analyst+ gated.
 *
 * In fixture mode this returns a minimal synthetic result (hit_count 0, no sample
 * bodies) — it fabricates NO alert data.
 */
export async function replayHypothesis(
  hypothesisId: string,
  signal?: AbortSignal,
): Promise<HuntReplayResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return {
      hypothesis: "(fixture) saved hypothesis",
      query_index: "wazuh-alerts-4.x-*",
      hit_count: 0,
      sample_hits: [],
    };
  }
  return request<HuntReplayResult>(
    `/api/hunt/library/${encodeURIComponent(hypothesisId)}/replay`,
    { method: "POST", signal },
  );
}

// ---- Closed Loop / Feedback (WO-U9c) — feedback tab (READ-ONLY) -------------
/**
 * `GET /api/feedback/patterns?min_occurrences=&limit=` → `{ patterns, total }`.
 * Auth: `require_role(admin, senior_analyst)` + `require_license_feature(
 * "feedback_loop")`. READ-ONLY (the loop's rule proposals are reviewed on the
 * Detection tab, also read-only). A runtime 402/403 → `FeatureLockedState`; the
 * `locked` fixture sentinel THROWS ApiError(403) like the gate.
 */
export async function getFeedbackPatterns(
  params: { minOccurrences?: number; limit?: number } = {},
  signal?: AbortSignal,
): Promise<FeedbackPatternsResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { feedbackPatternsFixture } = await import("./fixtures/feedback");
    return feedbackPatternsFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<FeedbackPatternsResponse>("/api/feedback/patterns", {
    query: { min_occurrences: params.minOccurrences, limit: params.limit },
    signal,
  });
}

/**
 * `GET /api/feedback/effectiveness` → a BARE LIST of `ProposalEffectiveness`
 * (not an envelope). Same `feedback_loop` gate + role. READ-ONLY. 402/403 →
 * `FeatureLockedState`.
 */
export async function getProposalEffectiveness(
  signal?: AbortSignal,
): Promise<ProposalEffectiveness[]> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { proposalEffectivenessFixture } = await import("./fixtures/feedback");
    return proposalEffectivenessFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<ProposalEffectiveness[]>("/api/feedback/effectiveness", {
    signal,
  });
}

// ---- Knowledge Base (WO-U9c) — knowledge tab (READ-ONLY) --------------------
/**
 * `GET /api/kb/documents?type=&limit=` → `{ documents, total }`. Auth:
 * `verify_jwt` + `require_license_feature("knowledge_base")` (all roles per the
 * shell ACL). READ-ONLY — create/edit/delete are gated writes NOT wired here. A
 * runtime 402/403 → `FeatureLockedState`; the `locked` fixture THROWS ApiError(403).
 */
export async function getKbDocuments(
  params: { type?: string; limit?: number } = {},
  signal?: AbortSignal,
): Promise<KbDocumentsResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { kbDocumentsFixture } = await import("./fixtures/knowledge");
    return kbDocumentsFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<KbDocumentsResponse>("/api/kb/documents", {
    query: { type: params.type, limit: params.limit },
    signal,
  });
}

/**
 * `GET /api/kb/search?q=&type=&limit=` → `{ results, total, query }`. This is a
 * GET-backed full-text search (a READ, not a write). Same `knowledge_base` gate.
 * The caller only fires it for a non-empty query (server requires `q` ≥ 2 chars).
 */
export async function searchKb(
  params: { q: string; type?: string; limit?: number },
  signal?: AbortSignal,
): Promise<KbSearchResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { kbSearchFixture } = await import("./fixtures/knowledge");
    return kbSearchFixture(params.q, {
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<KbSearchResponse>("/api/kb/search", {
    query: { q: params.q, type: params.type, limit: params.limit },
    signal,
  });
}

/** `GET /api/kb/stats` → `{ total, by_type }`. Same `knowledge_base` gate. */
export async function getKbStats(signal?: AbortSignal): Promise<KbStats> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { kbStatsFixture } = await import("./fixtures/knowledge");
    return kbStatsFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<KbStats>("/api/kb/stats", { signal });
}

// ---- Knowledge-base WRITES (Knowledge tab) — create / edit / delete ---------
/**
 * The three KB writes. Each mirrors a server route + RBAC gate (see
 * `rbac.ts::knowledgeActionGate` — create=analyst+, edit/delete=senior_analyst+)
 * and is FIXTURE-GATED like the other writes: in fixture mode it short-circuits
 * to a synthetic success and performs NO real mutation. The shipped production
 * path calls the real endpoint ONLY. The server remains the enforcement point for
 * RBAC, the `knowledge_base` license gate, doc_type validation, and title/content
 * requirements. `created_by` is set server-side from the JWT — never sent here.
 */

/**
 * `POST /api/kb/documents` — create a document. Auth: analyst+ (read_only
 * excluded) + `knowledge_base` license. Server requires `title`+`content` (400
 * otherwise) and a valid `doc_type` (400 otherwise); 503 if the KB is disabled.
 */
export async function createKbDocument(
  body: KbCreateBody,
  signal?: AbortSignal,
): Promise<KbCreateResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return {
      status: "ok",
      document: {
        id: "kb-fixture-new",
        doc_type: body.doc_type,
        title: body.title,
        content: body.content,
        tags: body.tags ?? [],
        mitre_techniques: body.mitre_techniques ?? [],
        created_by: "you",
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    };
  }
  return request<KbCreateResult>("/api/kb/documents", {
    method: "POST",
    body,
    signal,
  });
}

/**
 * `PUT /api/kb/documents/{id}` — edit a document's mutable fields. Auth:
 * senior_analyst+ (a plain analyst may create but NOT edit) + `knowledge_base`
 * license. 404 if the document is gone; 400 if no editable field is supplied.
 * `doc_type` is not editable server-side (ignored) — the form never sends it.
 */
export async function updateKbDocument(
  docId: string,
  body: KbUpdateBody,
  signal?: AbortSignal,
): Promise<KbWriteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "ok", document_id: docId };
  }
  return request<KbWriteResult>(
    `/api/kb/documents/${encodeURIComponent(docId)}`,
    { method: "PUT", body, signal },
  );
}

/**
 * `DELETE /api/kb/documents/{id}` — hard-delete a document. Auth: senior_analyst+
 * + `knowledge_base` license. 404 if it is already gone. Destructive and
 * irreversible → the tab gates it behind an explicit confirm dialog.
 */
export async function deleteKbDocument(
  docId: string,
  signal?: AbortSignal,
): Promise<KbWriteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "ok", document_id: docId };
  }
  return request<KbWriteResult>(
    `/api/kb/documents/${encodeURIComponent(docId)}`,
    { method: "DELETE", signal },
  );
}

// =============================================================================
// Active-response LIFECYCLE writes (Respond tab) — approve / reverse
// -----------------------------------------------------------------------------
// The HUMAN-GATED transitions the Respond tab wires. Server: response.py, both
// `require_role("senior_analyst","admin","mssp_admin")` (mirrored client-side
// via lib/rbac `responseActionGate`; the server re-checks and is the source of
// truth). Every call here is invoked ONLY from an explicit human confirm — the
// UI never auto-executes. This changes NO server default. Fixture-gated exactly
// like `proposeContainment`: in fixture mode they short-circuit to a synthetic
// success and perform NO real mutation (so the confirm→result flow is
// screenshottable), and the shipped bundle calls the real endpoint only.
//
// NOTE on scope: `/approve/{id}` APPROVES **and dispatches** in one call
// (approve == execute-on-approval; there is no approved-but-not-executed state).
// The standalone `POST /api/response/execute` is the un-queued, free-form direct
// path (legacy AR cards, free-typed agent/target) and is intentionally NOT wired
// here — the task scopes Execute to "already-approved actions", which on this
// server IS the approve call. Import types locally to avoid touching the shared
// top-of-file import block while sibling agents edit it.
// =============================================================================
import type {
  ApproveResponseActionResult,
  ReverseResponseActionResult,
} from "./types";

/**
 * `POST /api/response/approve/{action_id}` — approve a `pending_approval`
 * proposal, which the server ALSO dispatches to Wazuh in the same call. Role:
 * senior_analyst+ (server re-checks). No request body; no `reason` is required by
 * the server on approve (the proposal already carries its reason). Call ONLY from
 * an explicit human confirm. A 402/403 (tier/role) or 409 (no longer pending) is
 * surfaced by the caller as a locked/typed error, never a crash.
 */
export async function approveResponseAction(
  actionId: string,
  signal?: AbortSignal,
): Promise<ApproveResponseActionResult> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    // Fixture: synthetic success, NO real mutation (mirrors proposeContainment).
    return {
      id: `exec_fixture_${Date.now()}`,
      proposal_id: actionId,
      action: "block_ip",
      status: "executed",
      audit: "ok",
      success: true,
    };
  }
  return request<ApproveResponseActionResult>(
    `/api/response/approve/${encodeURIComponent(actionId)}`,
    { method: "POST", signal },
  );
}

/**
 * `POST /api/response/reverse/{action_id}` — reverse (unblock) an active
 * `block_ip`. Role: senior_analyst+ (server re-checks). No request body. The
 * server 409s unless the row is an executed `block_ip`; the UI only offers
 * Reverse for those rows. Call ONLY from an explicit human confirm.
 */
export async function reverseResponseAction(
  actionId: string,
  signal?: AbortSignal,
): Promise<ReverseResponseActionResult> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    return {
      id: actionId,
      action: "unblock_ip",
      status: "reversed",
      success: true,
    };
  }
  return request<ReverseResponseActionResult>(
    `/api/response/reverse/${encodeURIComponent(actionId)}`,
    { method: "POST", signal },
  );
}

// =============================================================================
// Detection engineering WRITES (DetectionTab) — approve / reject / deploy /
// rollback / test(dry-run) of AI-proposed Wazuh rule changes. This is the
// "human approves → rule deployed" step of the closed loop.
//
// Appended as a self-contained Detection section (types imported locally) to
// avoid touching the shared top-of-file import block while sibling agents edit
// it. Each client mirrors src/api/routes/detection.py EXACTLY (path, method,
// body). RBAC/tier are re-checked server-side; the client mirrors them via
// `detectionActionGate` and never widens. Fixture mode short-circuits to a
// synthetic success with NO real mutation (screenshot/dev-preview only).
//
// Server RBAC (never widen client-side):
//   - review (approve/reject) → require_role("admin","senior_analyst") [+mssp]
//   - deploy / rollback       → require_deploy_authority() (WO-H30): mssp_admin
//                               ONLY in multi-tenant, admin+ in single-tenant
//   - validate (test/dry-run) → require_admin (admin | mssp_admin)
// All are behind require_license_feature("detection") (402/403 → locked).
// NOTE: there is NO server endpoint to edit a proposal's XML before deploy —
// a rule deploys EXACTLY as stored; the UI stubs "edit before deploy" honestly.
// =============================================================================
import type {
  DetectionReviewResult,
  DetectionDeployResult,
  DetectionRollbackResult,
  DetectionValidateResult,
} from "./types";

/**
 * `POST /api/detection/review` — approve or reject a proposal. This is a
 * proposal-lifecycle transition (proposed→approved | proposed→rejected); it does
 * NOT change any live Wazuh rule (deploy does). `notes` is OPTIONAL server-side
 * (`ProposalReviewRequest.notes: Optional[str]`) — reason is NOT required here,
 * so the UI offers it (on reject) but never forces it. Role: senior_analyst+
 * (server re-checks). Call ONLY from a deliberate human action.
 */
export async function reviewDetectionProposal(
  proposalId: string,
  action: "approve" | "reject",
  notes?: string,
  signal?: AbortSignal,
): Promise<DetectionReviewResult> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    return { status: "ok", proposal_id: proposalId, action };
  }
  return request<DetectionReviewResult>("/api/detection/review", {
    method: "POST",
    body: { proposal_id: proposalId, action, notes: notes || null },
    signal,
  });
}

/**
 * `POST /api/detection/deploy/{id}` — deploy an APPROVED proposal to the SHARED
 * Wazuh backend and restart the manager. mssp_admin ONLY (a Wazuh rule change
 * affects EVERY tenant — the client mirrors this and never widens to admin).
 * No request body. Server returns `{status:"deployed", proposal_id}`; a failed
 * deploy is HTTP 400 (surfaced as a typed error, never a silent success). Call
 * ONLY from an explicit human confirm.
 */
export async function deployDetectionProposal(
  proposalId: string,
  signal?: AbortSignal,
): Promise<DetectionDeployResult> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    return { status: "deployed", proposal_id: proposalId };
  }
  return request<DetectionDeployResult>(
    `/api/detection/deploy/${encodeURIComponent(proposalId)}`,
    { method: "POST", signal },
  );
}

/**
 * `POST /api/detection/rollback/{id}` — roll a DEPLOYED rule back to its original
 * XML and restart the manager. mssp_admin ONLY. No request body. Server returns
 * `{status:"rolled_back", ...}`; a failed rollback (no backup / not deployed) is
 * HTTP 400. Call ONLY from an explicit human confirm.
 */
export async function rollbackDetectionProposal(
  proposalId: string,
  signal?: AbortSignal,
): Promise<DetectionRollbackResult> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    return { status: "rolled_back", proposal_id: proposalId };
  }
  return request<DetectionRollbackResult>(
    `/api/detection/rollback/${encodeURIComponent(proposalId)}`,
    { method: "POST", signal },
  );
}

/**
 * `POST /api/detection/validate` — a READ-ONLY dry-run of rule XML against
 * wazuh-logtest. Changes NOTHING live. admin+ ONLY (`require_admin`). Body
 * `{rule_xml}`; returns `{valid, error}`. Used to test a proposal's proposed XML
 * before anyone deploys it.
 */
export async function validateDetectionRule(
  ruleXml: string,
  signal?: AbortSignal,
): Promise<DetectionValidateResult> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    return { valid: true, error: null };
  }
  return request<DetectionValidateResult>("/api/detection/validate", {
    method: "POST",
    body: { rule_xml: ruleXml },
    signal,
  });
}

// =============================================================================
// Admin WRITE actions (AdminTab) — clients for the admin mutating endpoints.
// Appended (Admin section) to keep the edit append-only while sibling agents
// touch this file. Every path/method/RBAC mirrors src/api/routes/admin.py +
// routes/health.py (guidance reload). The server is the RBAC enforcement point;
// these clients never bypass it. NO password/secret is ever returned or logged.
// =============================================================================
import type {
  AdminAssetsResponse,
  AdminIdentitiesResponse,
  AdminLocalIocsResponse,
  AssignTenantAgentsResult,
  DecisionCacheResponse,
  UpdateDecisionCacheBody,
  CreateAssetBody,
  CreateIdentityBody,
  CreateLocalIocBody,
  CreateTenantBody,
  CreateTenantResult,
  CreateUserBody,
  CreateUserResult,
  GuidanceReloadResult,
  HandoffBody,
  HandoffResult,
  ReloadEnrichersResult,
  RemoveTenantAgentResult,
  SettingsWriteResult,
  TenantAgentsResponse,
  TenantWriteResult,
  UpdateAssetBody,
  UpdateIdentityBody,
  UpdateTenantBody,
  UpdateUserBody,
  UpdateUserResult,
} from "./types";

// ---- Users (require_role("admin")) ------------------------------------------
/**
 * `POST /api/admin/users` — create a user. The admin-typed `password` is sent
 * once; the server hashes it and returns ONLY `{status,user_id,username}`. The
 * caller must never log or re-display the password. Role is server-validated
 * against the actor's assignable set (`assignableRoles`) — a 403 comes back if
 * the actor tries to assign above their tier.
 */
export async function createAdminUser(
  body: CreateUserBody,
  signal?: AbortSignal,
): Promise<CreateUserResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "created", user_id: `u_fixture_${Date.now()}`, username: body.username };
  }
  return request<CreateUserResult>("/api/admin/users", {
    method: "POST",
    body,
    signal,
  });
}

/**
 * `POST /api/admin/users/{id}` — edit a user (role / display / email / active /
 * password-reset). Only provided fields change. A password reset (`password`)
 * is sent once and never echoed back. `is_active:false` is the only "delete".
 */
export async function updateAdminUser(
  userId: string,
  body: UpdateUserBody,
  signal?: AbortSignal,
): Promise<UpdateUserResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "updated", user_id: userId };
  }
  return request<UpdateUserResult>(
    `/api/admin/users/${encodeURIComponent(userId)}`,
    { method: "POST", body, signal },
  );
}

// ---- Tenants (require_role("mssp_admin")) -----------------------------------
/** `POST /api/admin/tenants` — create a tenant (mssp_admin + multi_tenant). */
export async function createAdminTenant(
  body: CreateTenantBody,
  signal?: AbortSignal,
): Promise<CreateTenantResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "ok", tenant_id: `t_fixture_${Date.now()}`, name: body.name, slug: body.slug };
  }
  return request<CreateTenantResult>("/api/admin/tenants", {
    method: "POST",
    body,
    signal,
  });
}

/** `PUT /api/admin/tenants/{id}` — rename / activate / deactivate (mssp_admin). */
export async function updateAdminTenant(
  tenantId: string,
  body: UpdateTenantBody,
  signal?: AbortSignal,
): Promise<TenantWriteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "ok", tenant_id: tenantId };
  }
  return request<TenantWriteResult>(
    `/api/admin/tenants/${encodeURIComponent(tenantId)}`,
    { method: "PUT", body, signal },
  );
}

/** `GET /api/admin/tenants/{id}/agents` — mapped Wazuh agent IDs (mssp_admin). */
export async function getTenantAgents(
  tenantId: string,
  signal?: AbortSignal,
): Promise<TenantAgentsResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { tenantAgentsFixture } = await import("./fixtures/admin");
    return tenantAgentsFixture(tenantId, { empty: FIXTURES === "empty" });
  }
  return request<TenantAgentsResponse>(
    `/api/admin/tenants/${encodeURIComponent(tenantId)}/agents`,
    { signal },
  );
}

/** `POST /api/admin/tenants/{id}/agents` — assign numeric agent IDs (mssp_admin).
 * The server rejects non-numeric IDs (400) and reports already-mapped IDs as
 * `conflicts`. */
export async function assignTenantAgents(
  tenantId: string,
  agentIds: string[],
  signal?: AbortSignal,
): Promise<AssignTenantAgentsResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "ok", tenant_id: tenantId, assigned: agentIds };
  }
  return request<AssignTenantAgentsResult>(
    `/api/admin/tenants/${encodeURIComponent(tenantId)}/agents`,
    { method: "POST", body: { agent_ids: agentIds }, signal },
  );
}

/** `DELETE /api/admin/tenants/{id}/agents/{agent_id}` — unmap an agent (mssp_admin). */
export async function removeTenantAgent(
  tenantId: string,
  agentId: string,
  signal?: AbortSignal,
): Promise<RemoveTenantAgentResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "ok", tenant_id: tenantId, removed: agentId };
  }
  return request<RemoveTenantAgentResult>(
    `/api/admin/tenants/${encodeURIComponent(tenantId)}/agents/${encodeURIComponent(agentId)}`,
    { method: "DELETE", signal },
  );
}

// ---- Settings: assets (require_role("admin")) -------------------------------
export async function getAdminAssets(
  signal?: AbortSignal,
): Promise<AdminAssetsResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { adminAssetsFixture } = await import("./fixtures/admin");
    return adminAssetsFixture({ empty: FIXTURES === "empty" });
  }
  return request<AdminAssetsResponse>("/api/admin/settings/assets", { signal });
}
export async function createAdminAsset(
  body: CreateAssetBody,
  signal?: AbortSignal,
): Promise<SettingsWriteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "created", asset_id: `a_fixture_${Date.now()}` };
  }
  return request<SettingsWriteResult>("/api/admin/settings/assets", {
    method: "POST",
    body,
    signal,
  });
}

/**
 * WO-H51: seed asset context from the enrolled Wazuh agents. The server reads
 * the agent inventory and upserts a stub per host WITHOUT clobbering any tier/
 * owner an analyst already set (insert-if-absent for classification). Returns
 * how many were newly added vs already present.
 */
export interface DiscoverAssetsResult {
  status: string;
  discovered: number;
  new: number;
  existing: number;
}
export async function discoverAdminAssets(
  signal?: AbortSignal,
): Promise<DiscoverAssetsResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "ok", discovered: 3, new: 3, existing: 0 };
  }
  return request<DiscoverAssetsResult>(
    "/api/admin/settings/assets/discover",
    { method: "POST", signal },
  );
}
export async function updateAdminAsset(
  assetId: string,
  body: UpdateAssetBody,
  signal?: AbortSignal,
): Promise<SettingsWriteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "updated" };
  }
  return request<SettingsWriteResult>(
    `/api/admin/settings/assets/${encodeURIComponent(assetId)}`,
    { method: "PUT", body, signal },
  );
}
export async function deleteAdminAsset(
  assetId: string,
  signal?: AbortSignal,
): Promise<SettingsWriteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "deleted" };
  }
  return request<SettingsWriteResult>(
    `/api/admin/settings/assets/${encodeURIComponent(assetId)}`,
    { method: "DELETE", signal },
  );
}

// ---- Decision cache (WO-H57) — senior_analyst+ ------------------------------
// View / disable / edit / delete the persistent verdict cache that lets a
// recurring alert reuse its stored verdict for $0 instead of re-calling the LLM.
export async function getDecisionCache(
  opts?: { includeDisabled?: boolean; limit?: number },
  signal?: AbortSignal,
): Promise<DecisionCacheResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { decisionCacheFixture } = await import("./fixtures/admin");
    return decisionCacheFixture({ empty: FIXTURES === "empty" });
  }
  return request<DecisionCacheResponse>("/api/admin/decision-cache", {
    query: {
      include_disabled: String(opts?.includeDisabled ?? true),
      limit: opts?.limit ?? 500,
    },
    signal,
  });
}
export async function updateDecisionCacheEntry(
  cacheId: string,
  body: UpdateDecisionCacheBody,
  signal?: AbortSignal,
): Promise<SettingsWriteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") return { status: "updated" };
  return request<SettingsWriteResult>(
    `/api/admin/decision-cache/${encodeURIComponent(cacheId)}`,
    { method: "PATCH", body, signal },
  );
}
export async function deleteDecisionCacheEntry(
  cacheId: string,
  signal?: AbortSignal,
): Promise<SettingsWriteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") return { status: "deleted" };
  return request<SettingsWriteResult>(
    `/api/admin/decision-cache/${encodeURIComponent(cacheId)}`,
    { method: "DELETE", signal },
  );
}
export async function purgeDecisionCache(
  scope: "expired" | "all",
  signal?: AbortSignal,
): Promise<{ status: string; scope: string; removed: number }> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "purged", scope, removed: 0 };
  }
  return request<{ status: string; scope: string; removed: number }>(
    "/api/admin/decision-cache/purge",
    { method: "POST", query: { scope }, signal },
  );
}

// ---- Settings: identities (require_role("admin")) ---------------------------
export async function getAdminIdentities(
  signal?: AbortSignal,
): Promise<AdminIdentitiesResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { adminIdentitiesFixture } = await import("./fixtures/admin");
    return adminIdentitiesFixture({ empty: FIXTURES === "empty" });
  }
  return request<AdminIdentitiesResponse>("/api/admin/settings/identities", {
    signal,
  });
}
export async function createAdminIdentity(
  body: CreateIdentityBody,
  signal?: AbortSignal,
): Promise<SettingsWriteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "created", identity_id: `i_fixture_${Date.now()}` };
  }
  return request<SettingsWriteResult>("/api/admin/settings/identities", {
    method: "POST",
    body,
    signal,
  });
}
export async function updateAdminIdentity(
  identityId: string,
  body: UpdateIdentityBody,
  signal?: AbortSignal,
): Promise<SettingsWriteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "updated" };
  }
  return request<SettingsWriteResult>(
    `/api/admin/settings/identities/${encodeURIComponent(identityId)}`,
    { method: "PUT", body, signal },
  );
}
export async function deleteAdminIdentity(
  identityId: string,
  signal?: AbortSignal,
): Promise<SettingsWriteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "deleted" };
  }
  return request<SettingsWriteResult>(
    `/api/admin/settings/identities/${encodeURIComponent(identityId)}`,
    { method: "DELETE", signal },
  );
}

// ---- Settings: local IOCs (require_role("admin")) — create + delete only -----
export async function getAdminLocalIocs(
  signal?: AbortSignal,
): Promise<AdminLocalIocsResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { adminLocalIocsFixture } = await import("./fixtures/admin");
    return adminLocalIocsFixture({ empty: FIXTURES === "empty" });
  }
  return request<AdminLocalIocsResponse>("/api/admin/settings/local-iocs", {
    signal,
  });
}
export async function createAdminLocalIoc(
  body: CreateLocalIocBody,
  signal?: AbortSignal,
): Promise<SettingsWriteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "created", ioc_id: `ioc_fixture_${Date.now()}` };
  }
  return request<SettingsWriteResult>("/api/admin/settings/local-iocs", {
    method: "POST",
    body,
    signal,
  });
}
export async function deleteAdminLocalIoc(
  iocId: string,
  signal?: AbortSignal,
): Promise<SettingsWriteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "deleted" };
  }
  return request<SettingsWriteResult>(
    `/api/admin/settings/local-iocs/${encodeURIComponent(iocId)}`,
    { method: "DELETE", signal },
  );
}

// ---- Reload triggers + shift handoff ----------------------------------------
/** `POST /api/admin/settings/reload-enrichers` (admin) — confirm → POST → toast. */
export async function reloadEnrichers(
  signal?: AbortSignal,
): Promise<ReloadEnrichersResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "ok", assets: 0, identities: 0, local_iocs: 0 };
  }
  return request<ReloadEnrichersResult>("/api/admin/settings/reload-enrichers", {
    method: "POST",
    signal,
  });
}
/** `POST /api/guidance/reload` (require_admin, rate-limited 2/min). */
export async function reloadGuidance(
  signal?: AbortSignal,
): Promise<GuidanceReloadResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "ok", message: "Guidance reloaded" };
  }
  return request<GuidanceReloadResult>("/api/guidance/reload", {
    method: "POST",
    signal,
  });
}
/** `POST /api/admin/shifts/handoff` (admin/senior_analyst + "sla" license). */
export async function saveShiftHandoff(
  body: HandoffBody,
  signal?: AbortSignal,
): Promise<HandoffResult> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "ok", handoff_id: `handoff_fixture_${Date.now()}` };
  }
  return request<HandoffResult>("/api/admin/shifts/handoff", {
    method: "POST",
    body,
    signal,
  });
}

// =============================================================================
// Tickets WRITES (TicketsTab) — create / force-sync / retry
// -----------------------------------------------------------------------------
// The three mutating endpoints on `/api/tickets` (src/api/routes/tickets.py).
// Each mirrors a server RBAC gate (see lib/rbac `ticketActionGate`) and is
// FIXTURE-GATED like `submitTriageReview`/`proposeContainment`: in fixture mode
// it short-circuits to a synthetic success and performs NO real mutation, so the
// create/retry/sync flows are screenshottable without a live backend. The
// shipped bundle calls the real endpoint ONLY. The server remains the
// enforcement point for RBAC, the ticketing license gate, provider validity, and
// the "only error tickets can be retried" rule — the client never bypasses it.
// Types imported locally to avoid touching the shared top-of-file import block.
// =============================================================================
import type { CreateTicketBody, TicketWriteResult } from "./types";

/**
 * `POST /api/tickets` — create a ticket from an incident. Role: analyst+
 * (read_only excluded server-side). Body: `{incident_id (required), provider?,
 * summary?}` — `provider` must be one of jira|servicenow|pagerduty when set. No
 * `reason`. 503 if ticketing is disabled; 400 on a provider/creation error. Call
 * from a form submit; the tab gates submit on a non-empty incident_id.
 */
export async function createTicket(
  body: CreateTicketBody,
  signal?: AbortSignal,
): Promise<TicketWriteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    return {
      status: "ok",
      ticket_id: `tkt_fixture_${Date.now()}`,
      external_id: null,
      incident_id: body.incident_id,
    };
  }
  return request<TicketWriteResult>("/api/tickets", {
    method: "POST",
    body,
    signal,
  });
}

/**
 * `POST /api/tickets/{id}/sync` — force a re-sync of a ticket's status from the
 * external tracker. Role: senior_analyst+. No body. 503 if disabled, 400 on a
 * provider error. A mutation server-side (writes last_synced_at) so it is
 * confirm-gated in the tab.
 */
export async function syncTicket(
  ticketId: string,
  signal?: AbortSignal,
): Promise<TicketWriteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    return { status: "ok", ticket_id: ticketId };
  }
  return request<TicketWriteResult>(
    `/api/tickets/${encodeURIComponent(ticketId)}/sync`,
    { method: "POST", signal },
  );
}

/**
 * `POST /api/tickets/{id}/retry` — retry a FAILED (platform_status=="error")
 * ticket push. Role: senior_analyst+. No body. The server 400s if the ticket is
 * not in error state and 404s if it is gone; the tab offers Retry only on error
 * rows and surfaces a 400/404 as a typed "changed, refreshing" message.
 */
export async function retryTicket(
  ticketId: string,
  signal?: AbortSignal,
): Promise<TicketWriteResult> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    return { status: "ok", ticket_id: ticketId, external_id: "SOC-RETRY" };
  }
  return request<TicketWriteResult>(
    `/api/tickets/${encodeURIComponent(ticketId)}/retry`,
    { method: "POST", signal },
  );
}

// =============================================================================
// SOAR WRITES (SoarTab) — toggle playbook / approve · reject · rollback exec
// -----------------------------------------------------------------------------
// ACTIVE-RESPONSE-ADJACENT. SOAR playbooks contain containment actions
// (block_ip/isolate_host/disable_user). These mirror the server RBAC in
// `src/api/routes/soar.py` (see lib/rbac `soarPlaybookGate`/`soarExecutionGate`)
// and are FIXTURE-GATED like the response writes: in fixture mode they
// short-circuit to a synthetic success and perform NO real mutation. Every call
// here is invoked ONLY from an explicit human confirm — the UI never
// auto-executes and changes NO server default. The server re-checks every call
// (RBAC + license + execution state) and remains the enforcement point.
//
// SCOPE NOTE: `approve` APPROVES **and dispatches** the queued execution's
// containment actions in one call (engine.approve → _execute). There is no
// separate "run" endpoint (executions are engine-generated from real triage
// decisions), so nothing here starts containment from scratch. Types imported
// locally to avoid touching the shared top-of-file import block.
// =============================================================================
import type { SoarToggleResult, SoarExecutionActionResult } from "./types";

/**
 * `POST /api/soar/playbooks/{id}/toggle` — flip a playbook enabled↔disabled.
 * Role: admin+ (require_role("admin")). No body (the server flips the current
 * state and returns the NEW `enabled`). Enabling does NOT run anything now; it
 * makes the playbook eligible to trigger (a containment step still routes to the
 * human approval queue). Call ONLY from an explicit confirm.
 */
export async function toggleSoarPlaybook(
  playbookId: string,
  currentlyEnabled: boolean,
  signal?: AbortSignal,
): Promise<SoarToggleResult> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    return { status: "ok", playbook_id: playbookId, enabled: !currentlyEnabled };
  }
  return request<SoarToggleResult>(
    `/api/soar/playbooks/${encodeURIComponent(playbookId)}/toggle`,
    { method: "POST", signal },
  );
}

/**
 * `POST /api/soar/executions/{id}/approve` — approve a `pending_approval`
 * execution, WHICH THE ENGINE THEN DISPATCHES (its containment actions run).
 * Role: senior_analyst+. No body. The server 400s if the execution is not
 * pending_approval; the tab surfaces that as a typed "changed, refreshing"
 * message. Call ONLY from an explicit confirm that lists the actions.
 */
export async function approveSoarExecution(
  executionId: string,
  signal?: AbortSignal,
): Promise<SoarExecutionActionResult> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    return { status: "ok", execution_id: executionId, approved_by: "you" };
  }
  return request<SoarExecutionActionResult>(
    `/api/soar/executions/${encodeURIComponent(executionId)}/approve`,
    { method: "POST", signal },
  );
}

/**
 * `POST /api/soar/executions/{id}/reject` — reject/cancel a `pending_approval`
 * execution. NO containment runs. Role: senior_analyst+. No body. 400 if not
 * pending_approval. Call ONLY from an explicit confirm.
 */
export async function rejectSoarExecution(
  executionId: string,
  signal?: AbortSignal,
): Promise<SoarExecutionActionResult> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    return { status: "ok", execution_id: executionId, rejected_by: "you" };
  }
  return request<SoarExecutionActionResult>(
    `/api/soar/executions/${encodeURIComponent(executionId)}/reject`,
    { method: "POST", signal },
  );
}

/**
 * `POST /api/soar/executions/{id}/rollback` — reverse a completed/partial
 * execution by running its INVERSE actions (unblock/unisolate/enable). Role:
 * admin+ (require_role("admin")). No body. 400 if the execution is not in a
 * rollbackable state or defines no rollback actions. Call ONLY from an explicit
 * confirm.
 */
export async function rollbackSoarExecution(
  executionId: string,
  signal?: AbortSignal,
): Promise<SoarExecutionActionResult> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    return { status: "ok", execution_id: executionId, rolled_back_by: "you" };
  }
  return request<SoarExecutionActionResult>(
    `/api/soar/executions/${encodeURIComponent(executionId)}/rollback`,
    { method: "POST", signal },
  );
}

// =============================================================================
// Closed-loop / feedback WRITE (ClosedLoopTab) — trigger a feedback cycle
// -----------------------------------------------------------------------------
// The only mutating endpoint on `/api/feedback` (src/api/routes/feedback.py):
// re-mine patterns + regenerate tuning proposals. Role: admin+ (require_admin),
// rate-limited 2/min server-side. Runs in the BACKGROUND (returns
// `{status:"accepted"}` immediately; the new patterns/proposals appear on the
// next poll). FIXTURE-GATED like the others. There is NO per-pattern
// accept/dismiss or mark-for-detection endpoint — those are stubbed honestly in
// the tab. Type imported locally.
// =============================================================================
import type { FeedbackRunCycleResult } from "./types";

/**
 * `POST /api/feedback/run-cycle` — manually trigger a feedback analysis cycle.
 * Role: admin+ (require_admin). No body. Returns `{status:"accepted"}` and runs
 * in the background; a 429 (rate limit 2/min) or 503 (engine unavailable) is
 * surfaced typed. Call ONLY from an explicit confirm.
 */
export async function runFeedbackCycle(
  signal?: AbortSignal,
): Promise<FeedbackRunCycleResult> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    return { status: "accepted", message: "Feedback cycle started (fixture)" };
  }
  return request<FeedbackRunCycleResult>("/api/feedback/run-cycle", {
    method: "POST",
    signal,
  });
}

// =============================================================================
// Parity-restore READ-VIEWS (missing legacy sub-tabs the redesign dropped).
// Each mirrors the server route's role + license gate EXACTLY. A runtime 402/403
// degrades the view to FeatureLockedState (fail-closed to locked) where a license
// gate exists; role gating is mirrored by the calling tab (never widened here).
// FIXTURE-gated like every other read; types imported locally (append-only).
// =============================================================================
import type {
  DeploymentHistoryResponse,
  LogSourcesResponse,
  LlmBudgetAlertsResponse,
  LlmCostTrendsResponse,
  LlmOptimizationResponse,
  LlmUsageReportResponse,
  PipelineHealth,
  RuleVersionsResponse,
  TiStrategicReport,
} from "./types";

// ---- Admin → Pipeline Health (mssp_admin + pipeline_health license) ---------
/**
 * `GET /api/health/pipeline` → heartbeats + EPS/anomaly + parser fail-rate
 * (+ route-merged automation_health). Auth: `require_role("mssp_admin")` +
 * `require_license_feature("pipeline_health")`. The calling section is rendered
 * ONLY for mssp_admin (mirrors the server — a plain admin never fires it); a
 * runtime 402/403 degrades to FeatureLockedState. The `locked` fixture sentinel
 * THROWS ApiError(403) like the gate.
 */
export async function getPipelineHealth(
  signal?: AbortSignal,
): Promise<PipelineHealth> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { pipelineHealthFixture } = await import("./fixtures/pipeline");
    return pipelineHealthFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<PipelineHealth>("/api/health/pipeline", { signal });
}

/**
 * `GET /api/health/log-sources` → `{ sources }` — log-source inventory with a
 * live silent/reporting heartbeat stamp. Same `mssp_admin` + `pipeline_health`
 * gate as pipeline health.
 */
export async function getLogSources(
  signal?: AbortSignal,
): Promise<LogSourcesResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { logSourcesFixture } = await import("./fixtures/pipeline");
    return logSourcesFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<LogSourcesResponse>("/api/health/log-sources", { signal });
}

// ---- Reports → LLM Usage (verify_jwt + own-tenant; NO license gate) ----------
/**
 * `GET /api/v1/llm-usage/tenant/{tenant_id}/report?days=` — comprehensive usage
 * report. Auth: `verify_jwt`; the server 403s unless `tenant_id` is the caller's
 * OWN tenant (mssp_admin may cross-tenant). The tab ONLY ever passes the caller's
 * own `client_id` from the JWT, so the request is always own-scoped (never
 * widened). NO license gate.
 */
export async function getLlmUsageReport(
  tenantId: string,
  days = 30,
  signal?: AbortSignal,
): Promise<LlmUsageReportResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { llmUsageReportFixture } = await import("./fixtures/llmusage");
    return llmUsageReportFixture({ empty: FIXTURES === "empty", tenantId, days });
  }
  return request<LlmUsageReportResponse>(
    `/api/v1/llm-usage/tenant/${encodeURIComponent(tenantId)}/report`,
    { query: { days }, signal },
  );
}

/** `GET /api/v1/llm-usage/tenant/{tenant_id}/budget-alerts` — same auth/scope. */
export async function getLlmBudgetAlerts(
  tenantId: string,
  signal?: AbortSignal,
): Promise<LlmBudgetAlertsResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { llmBudgetAlertsFixture } = await import("./fixtures/llmusage");
    return llmBudgetAlertsFixture({ empty: FIXTURES === "empty", tenantId });
  }
  return request<LlmBudgetAlertsResponse>(
    `/api/v1/llm-usage/tenant/${encodeURIComponent(tenantId)}/budget-alerts`,
    { signal },
  );
}

/** `GET /api/v1/llm-usage/tenant/{tenant_id}/cost-trends?days=` — same auth/scope. */
export async function getLlmCostTrends(
  tenantId: string,
  days = 30,
  signal?: AbortSignal,
): Promise<LlmCostTrendsResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { llmCostTrendsFixture } = await import("./fixtures/llmusage");
    return llmCostTrendsFixture({ empty: FIXTURES === "empty", tenantId, days });
  }
  return request<LlmCostTrendsResponse>(
    `/api/v1/llm-usage/tenant/${encodeURIComponent(tenantId)}/cost-trends`,
    { query: { days }, signal },
  );
}

/** `GET /api/v1/llm-usage/tenant/{tenant_id}/optimization?days=` — same auth/scope. */
export async function getLlmOptimization(
  tenantId: string,
  days = 30,
  signal?: AbortSignal,
): Promise<LlmOptimizationResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { llmOptimizationFixture } = await import("./fixtures/llmusage");
    return llmOptimizationFixture({ empty: FIXTURES === "empty", tenantId, days });
  }
  return request<LlmOptimizationResponse>(
    `/api/v1/llm-usage/tenant/${encodeURIComponent(tenantId)}/optimization`,
    { query: { days }, signal },
  );
}

// ---- Reports → Threat-Intel strategic report --------------------------------
/**
 * `GET /api/threat-intel/strategic-report?days=` → a FLAT strategic landscape
 * report. Auth: `require_role("admin","senior_analyst")` +
 * `require_license_feature("ti_feeds_tier2")`. A runtime 402/403 degrades to
 * FeatureLockedState. The `locked` fixture sentinel THROWS ApiError(403).
 */
export async function getTIStrategicReport(
  days = 30,
  signal?: AbortSignal,
): Promise<TiStrategicReport> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { tiStrategicReportFixture } = await import("./fixtures/strategicti");
    return tiStrategicReportFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
      days,
    });
  }
  return request<TiStrategicReport>("/api/threat-intel/strategic-report", {
    query: { days },
    signal,
  });
}

// ---- Detection → Deployment History + Rule Versions -------------------------
/**
 * `GET /api/detection/history?limit=` → `{ history, count }` (full rows incl.
 * XML). Auth: `require_role("admin","senior_analyst")` +
 * `require_license_feature("detection")`. A runtime 402/403 degrades to
 * FeatureLockedState. READ-ONLY.
 */
export async function getDeploymentHistory(
  params: { limit?: number; rule_file?: string; rule_id?: number } = {},
  signal?: AbortSignal,
): Promise<DeploymentHistoryResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { deploymentHistoryFixture } = await import("./fixtures/detectionhistory");
    return deploymentHistoryFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<DeploymentHistoryResponse>("/api/detection/history", {
    query: {
      limit: params.limit ?? 50,
      rule_file: params.rule_file,
      rule_id: params.rule_id,
    },
    signal,
  });
}

/**
 * `GET /api/detection/history/{rule_file}/versions` → `{ rule_file, versions }`
 * (XML stripped to `has_xml_before`). Same `detection` gate. READ-ONLY.
 */
export async function getRuleVersions(
  ruleFile: string,
  signal?: AbortSignal,
): Promise<RuleVersionsResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { ruleVersionsFixture } = await import("./fixtures/detectionhistory");
    return ruleVersionsFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
      ruleFile,
    });
  }
  return request<RuleVersionsResponse>(
    `/api/detection/history/${encodeURIComponent(ruleFile)}/versions`,
    { signal },
  );
}

// ===== [frontend-integrator — parity gap ① restored read-only subviews] ======
// Append-only block. Two READ fetchers mirroring their routes' gates exactly:
//   - lookupIoc        → GET /api/threat-intel/ioc/{ioc_value}
//                        verify_jwt + require_license_feature("ti_feeds_tier1")
//   - getMitreCoverage → GET /api/mitre/coverage
//                        verify_jwt + require_license_feature("mitre")
// (SOAR's execution BOARD reuses the already-wired getSoarExecutions — no new
// fetcher; it only regroups the response client-side.)

/**
 * `GET /api/threat-intel/ioc/{ioc_value}` → `{ ioc_value, matches, total }`
 * (`threat_intel.py::lookup_ioc`). Auth: `verify_jwt` +
 * `require_license_feature("ti_feeds_tier1")` — the SAME gate as the rest of the
 * Threat Intel tab, so a 402/403 degrades with the surface. USER-INITIATED read
 * (an analyst types an indicator) — it looks up THREAT indicators in the local
 * IOC store, NOT client PII / anon tokens (that boundary is untouched). READ-ONLY.
 *
 * The value is a `{ioc_value:path}` path segment server-side (slashes/dots in
 * IPs/domains/hashes pass through) — we still `encodeURIComponent` it so a value
 * with a slash can't traverse the path; the server's `:path` converter re-joins it.
 *
 * In fixture mode this short-circuits to a small synthetic result (behind
 * NEXT_PUBLIC_DHRUVA_FIXTURES) so the lookup states can be captured without a
 * backend; "locked" THROWS ApiError(403) exactly like the gate. NO real data.
 */
export async function lookupIoc(
  iocValue: string,
  signal?: AbortSignal,
): Promise<IocLookupResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    if (FIXTURES === "locked") {
      throw new ApiError(
        403,
        "Threat intelligence feeds are not available on this plan. Contact SecureSleuths to upgrade.",
      );
    }
    const v = iocValue.trim();
    if (FIXTURES === "empty" || v === "") {
      return { ioc_value: v, matches: [], total: 0 };
    }
    // A single self-consistent synthetic match so the populated state renders.
    const matches: IocMatch[] = [
      {
        ioc_value: v,
        ioc_type: /^\d{1,3}(\.\d{1,3}){3}$/.test(v)
          ? "ip"
          : /^[a-f0-9]{32,64}$/i.test(v)
            ? "hash"
            : "domain",
        source: "abuse.ch",
        severity: "high",
        confidence: 90,
        first_seen: "2026-06-28T11:20:00Z",
        last_seen: "2026-07-01T04:10:00Z",
        description: "Observed in commodity-loader C2 infrastructure.",
        tags: '["c2","loader"]',
        is_active: 1,
      },
    ];
    return { ioc_value: v, matches, total: matches.length };
  }
  return request<IocLookupResponse>(
    `/api/threat-intel/ioc/${encodeURIComponent(iocValue)}`,
    { signal },
  );
}

/**
 * `GET /api/mitre/coverage` → `{ tactics: [{ tactic, tactic_id, techniques: [{
 * id, name, detection_count, tp_count, fp_count, status, last_seen }] }] }`
 * (`mitre.py::get_coverage` → `get_heatmap_data`). Auth: `verify_jwt` + the same
 * `mitre` LICENSE gate as `/mitre/summary`, so it degrades WITH the MITRE tab (a
 * 402/403 → FeatureLockedState via the tab's existing lock path). The technique
 * cells carry the per-technique TP/FP/detection/last-seen the drill needs.
 * READ-ONLY. The "locked" fixture sentinel THROWS ApiError(403) like the gate.
 */
export async function getMitreCoverage(
  signal?: AbortSignal,
): Promise<MitreCoverageHeatmap> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { mitreCoverageFixture } = await import("./fixtures/mitre");
    return mitreCoverageFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<MitreCoverageHeatmap>("/api/mitre/coverage", { signal });
}
// ===== [/frontend-integrator — parity gap ①] ================================

// =============================================================================
// [frontend-integrator — parity gap ①: Incidents case INNER SUB-VIEWS] ========
// SLA + per-incident Tickets clients for IncidentsTab's restored case sub-tabs.
// All READ-ONLY. Timeline + Evidence need NO client (they ride the existing GET
// /api/incidents/{id} detail: `.timeline`, and the raw `.evidence_chain` JSON
// string). SLA + Tickets each mirror the server gate EXACTLY and fail-closed to
// LOCKED on a 402/403 (the sub-view renders FeatureLockedState). Types are
// defined+exported HERE (not types.ts) to keep the shared types.ts untouched
// while sibling agents edit it. FIXTURE-gated; type imported locally.
//
// Server contract (src/api/routes/incidents.py + tickets.py):
//   - SLA     → GET /api/incidents/{id}/sla     verify_jwt + require_license_feature("sla")
//   - Tickets → GET /api/tickets/incident/{id}  verify_jwt + require_license_feature("ticketing")
// Both are visible to EVERY role that can open the case (verify_jwt = read_only+);
// only the LICENSE gate can lock them — the client never widens the role.
// `TicketsResponse` is already imported at the top of this file (reused here).
// =============================================================================

/**
 * One SLA breach row (`store.py::get_sla_breaches` = `SELECT * FROM sla_breaches`).
 * NOTE: the real column is `sla_type` (the legacy UI read a non-existent
 * `breach_type`/`type`/`note` — corrected here). Every field optional/loose.
 */
export interface IncidentSlaBreach {
  id?: string | number;
  incident_id?: string;
  sla_type?: string | null;
  severity?: string | null;
  tier?: string | null;
  due_at?: string | null;
  breached_at?: string | null;
  client_id?: string | null;
  [k: string]: unknown;
}

/**
 * `GET /api/incidents/{id}/sla` response (`incidents.py::get_incident_sla`).
 * `*_remaining_sec` are int seconds floored at 0 (or null when no due date);
 * `*_met` are tri-state (true = met, false = missed, null = not yet evaluated).
 */
export interface IncidentSla {
  tier?: string | null;
  sla_response_due?: string | null;
  sla_resolution_due?: string | null;
  first_response_at?: string | null;
  response_remaining_sec?: number | null;
  resolution_remaining_sec?: number | null;
  sla_response_met?: boolean | null;
  sla_resolution_met?: boolean | null;
  breaches?: IncidentSlaBreach[];
  escalation_count?: number | null;
}

/**
 * One evidence-chain entry — read DEFENSIVELY off the detail's raw
 * `evidence_chain` JSON string (`incidents.py::add_evidence` writes this shape).
 * There is NO GET-list endpoint; the chain is a field on GET /api/incidents/{id}.
 */
export interface IncidentEvidenceEntry {
  type?: string | null;
  description?: string | null;
  ref_id?: string | null;
  added_by?: string | null;
  added_at?: string | null;
  [k: string]: unknown;
}

/**
 * `GET /api/incidents/{id}/sla` — SLA timers / status / breaches for one incident.
 * Auth: verify_jwt + require_license_feature("sla"). A runtime 402/403 (the `sla`
 * feature isn't licensed) throws an ApiError the SLA sub-view surfaces as
 * FeatureLockedState (fail-closed to locked). READ-ONLY.
 *
 * Fixture mode: the `locked` sentinel THROWS ApiError(403) exactly like the gate
 * so the degraded state is capturable; `empty` returns a bare SLA; `true` returns
 * a synthetic populated SLA. It fabricates NO real tenant data.
 */
export async function getIncidentSla(
  incidentId: string,
  signal?: AbortSignal,
): Promise<IncidentSla> {
  if (FIXTURES === "locked") {
    throw new ApiError(
      403,
      "SLA tracking is not available on this plan. Contact SecureSleuths to upgrade.",
    );
  }
  if (FIXTURES === "empty") {
    return { tier: "L1", breaches: [], escalation_count: 0 };
  }
  if (FIXTURES === "true") {
    const now = Date.now();
    return {
      tier: "L2",
      sla_response_due: new Date(now + 45 * 60_000).toISOString(),
      sla_resolution_due: new Date(now + 6 * 3_600_000).toISOString(),
      first_response_at: new Date(now - 12 * 60_000).toISOString(),
      response_remaining_sec: 45 * 60,
      resolution_remaining_sec: 6 * 3600,
      sla_response_met: true,
      sla_resolution_met: null,
      breaches: [],
      escalation_count: 0,
    };
  }
  return request<IncidentSla>(
    `/api/incidents/${encodeURIComponent(incidentId)}/sla`,
    { signal },
  );
}

/**
 * `GET /api/tickets/incident/{id}` — tickets linked to ONE incident. Auth:
 * verify_jwt + require_license_feature("ticketing"). This is a READ (ticket
 * CREATION lives on the Tickets tab, not duplicated here). A runtime 402/403
 * throws an ApiError the Tickets sub-view surfaces as FeatureLockedState. In
 * fixture mode this reuses the tickets fixture (which THROWS on the `locked`
 * sentinel) for parity.
 */
export async function getTicketsForIncident(
  incidentId: string,
  signal?: AbortSignal,
): Promise<TicketsResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    const { ticketsFixture } = await import("./fixtures/tickets");
    return ticketsFixture({
      empty: FIXTURES === "empty",
      locked: FIXTURES === "locked",
    });
  }
  return request<TicketsResponse>(
    `/api/tickets/incident/${encodeURIComponent(incidentId)}`,
    { signal },
  );
}
// ===== [/frontend-integrator — parity gap ① incidents sub-views] ============

// =============================================================================
// [frontend-integrator — parity gap ②: restored SEGMENTED FILTER controls] ====
// The redesign dropped the legacy segmented filter bars in favour of a fixed
// worst-first sort. These two READ-ONLY clients restore them as OPTIONAL
// refinement that narrows the worst-first list — the sort is NEVER replaced.
//   - Triage → GET /api/triage/decisions already accepts `verdict` + `since`
//     (src/api/routes/triage.py). We pass them SERVER-SIDE alongside the
//     existing `sort=risk`, so worst-first still orders the filtered set.
//   - Incidents STATUS filter reuses the existing `getIncidents({status})`
//     (server-side); Mine/Interesting narrow the loaded rows client-side from
//     fields already on each row (`assigned_to`, `flagged_interesting`); the SLA
//     filter reads the dedicated at-risk endpoint below and intersects by id.
// Types are defined+exported HERE (not types.ts) to keep the shared types.ts
// untouched while sibling agents edit it. FIXTURE-gated like every other client.
// =============================================================================

/**
 * `GET /api/triage/decisions?sort=&verdict=&since=` → `{ decisions, total }`.
 * A superset of `getTriageDecisions` that also forwards the OPTIONAL segmented
 * filters the queue restores. `sort` stays `risk` (worst-first) so the server
 * orders the filtered set highest-risk-first; `verdict` narrows to one AI
 * verdict; `since` (ISO-8601) narrows to a time window (SQL-level `created_at >=`
 * — applied before the row cap, so it genuinely widens what the window can
 * surface). Omitted/empty params are dropped by `buildUrl` → no filter.
 * READ-ONLY (`verify_jwt`); mirrors `getTriageDecisions`' fixture short-circuit.
 */
export async function getTriageDecisionsFiltered(
  params: {
    sort?: TriageSort;
    verdict?: string;
    since?: string;
    /** Server-side baseline-anomaly filter (`?anomaly=true`). */
    anomaly?: boolean;
    /** Widen the server window (default 200, max 1000) — used for the anomaly
     * filter so it isn't starved by the default page size. */
    limit?: number;
    /** WO-H33: rows to skip (SQL-side) — pages past the first window. */
    offset?: number;
  } = {},
  signal?: AbortSignal,
): Promise<TriageDecisionsResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { triageFixture } = await import("./fixtures/triage");
    return triageFixture({ sort: params.sort, empty: FIXTURES === "empty" });
  }
  return request<TriageDecisionsResponse>("/api/triage/decisions", {
    query: {
      sort: params.sort,
      verdict: params.verdict,
      since: params.since,
      anomaly: params.anomaly ? "true" : undefined,
      limit: params.limit,
      offset: params.offset,
    },
    signal,
  });
}

/**
 * `GET /api/triage/decisions/{id}` (WO-H33) → a single flattened decision row,
 * tenant-scoped server-side (foreign/unknown id → 404). Lets the deep-linked
 * case view resolve a decision that sits beyond the currently-loaded queue
 * window instead of dead-ending on "not in the current slice". READ-ONLY
 * (`verify_jwt`). Fixture mode resolves from the same fixture list as the
 * queue and 404s when the id isn't there (mirrors the server).
 */
export async function getTriageDecision(
  decisionId: string,
  signal?: AbortSignal,
): Promise<TriageDecision> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    const { triageFixture } = await import("./fixtures/triage");
    const row = triageFixture({ empty: FIXTURES === "empty" }).decisions.find(
      (d) => d.id === decisionId,
    );
    if (!row) throw new ApiError(404, "Decision not found");
    return row;
  }
  return request<TriageDecision>(
    `/api/triage/decisions/${encodeURIComponent(decisionId)}`,
    { signal },
  );
}

/** One incident approaching/breaching SLA (`GET /api/incidents/sla-at-risk`). */
export interface SlaAtRiskItem {
  incident_id: string;
  title?: string | null;
  severity?: string | null;
  tier?: string | null;
  /** "response" | "resolution" */
  sla_type?: string | null;
  remaining_sec?: number | null;
}

/** `GET /api/incidents/sla-at-risk` envelope. */
export interface SlaAtRiskResponse {
  at_risk: SlaAtRiskItem[];
  count: number;
}

/**
 * `GET /api/incidents/sla-at-risk` → incidents with < 15 min (or breached) SLA
 * remaining (`src/api/routes/incidents.py`). Auth: `verify_jwt` +
 * `require_license_feature("sla")` — so it 402/403s when the SLA feature is not
 * licensed; the Incidents tab treats that as "SLA filter unavailable" (the chip
 * is disabled, never silently empty). The tab intersects these `incident_id`s
 * with the already-loaded, already-authorized list — it NEVER widens what the
 * list returned. READ-ONLY. In fixture mode returns an empty set (no fabricated
 * breaches); the SLA filter then honestly matches nothing.
 */
export async function getSlaAtRisk(
  signal?: AbortSignal,
): Promise<SlaAtRiskResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty" || FIXTURES === "locked") {
    return { at_risk: [], count: 0 };
  }
  return request<SlaAtRiskResponse>("/api/incidents/sla-at-risk", { signal });
}
// ===== [/frontend-integrator — parity gap ②] ================================

// ===== [ui/DailyReview — plain-English incident summaries] ==================
// Imports are hoisted, so this type-only import at EOF keeps the file additions
// strictly append-only while staying valid.
import type {
  BatchPlainSummaryResponse,
  PlainSummaryResponse,
} from "./types";

/**
 * `POST /api/incidents/{id}/plain-summary` — generate, or return the CACHED,
 * plain-English de-anonymized summary of ONE incident for a non-technical
 * reader. Backs the Daily Review "what needs you now" list + click→plain panel.
 *
 * Role: analyst+ (`require_role("admin","senior_analyst","analyst")`). A
 * read_only user 403s → the caller shows an honest "plain summary needs analyst
 * access" note and the technical title, NEVER a fabricated summary (fail-closed,
 * mirroring the server). Rate-limited 10/min server-side.
 *
 * TOKEN COST: the FIRST call runs an LLM; the backend then caches the result in
 * the incident timeline, so every later call returns `cached:true` with no new
 * spend. Callers MUST additionally cache per-incident-id CLIENT-side and fetch
 * once (never on a poll) — see DailyReviewTab's `ensureSummaries`.
 *
 * Fixture mode returns a synthetic, clearly-structured plain summary so the panel
 * and list states can be captured without a live LLM — it performs NO real
 * generation and spends no tokens.
 */
export async function getPlainSummary(
  incidentId: string,
  signal?: AbortSignal,
): Promise<PlainSummaryResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return {
      summary:
        "WHAT HAPPENED\n" +
        "One of your laptops repeatedly tried to reach a website known to be used by attackers. Our AI spotted the pattern and stepped in automatically.\n\n" +
        "WHAT IS AT RISK\n" +
        "The affected machine and anything the signed-in user can access. No data appears to have left the company yet.\n\n" +
        "HOW SERIOUS IS THIS\n" +
        "Medium — it was caught early and contained, but it should be checked.\n\n" +
        "WHAT YOU SHOULD DO\n" +
        "Ask the user what they were doing around that time, and let the security team confirm the machine is clean before it goes back to normal use.",
      cached: true,
    };
  }
  return request<PlainSummaryResponse>(
    `/api/incidents/${encodeURIComponent(incidentId)}/plain-summary`,
    { method: "POST", signal },
  );
}

/**
 * `POST /api/incidents/batch-plain-summary` — best-effort PRE-WARM of the server
 * cache for up to 10 incident ids. Role: senior_analyst+
 * (`require_role("admin","senior_analyst")`); the background thread pre-generates
 * + caches each summary (skipping already-cached ones, one batch at a time) and
 * the endpoint returns IMMEDIATELY with a status — it does NOT return text.
 *
 * The Daily Review fires this ONCE per load (not per poll) as a warm so the
 * per-incident `getPlainSummary` reads mostly hit the cache. It is fire-and-
 * forget: a 402/403 (role/tier) or any error is swallowed by the caller — the
 * per-incident path still works for analyst+, so the warm is purely an optimisation.
 *
 * Fixture mode returns a synthetic `generating` acknowledgement and performs NO
 * real generation.
 */
export async function batchPlainSummary(
  incidentIds: string[],
  signal?: AbortSignal,
): Promise<BatchPlainSummaryResponse> {
  if (FIXTURES === "true" || FIXTURES === "empty") {
    return { status: "generating", count: incidentIds.length };
  }
  return request<BatchPlainSummaryResponse>(
    "/api/incidents/batch-plain-summary",
    { method: "POST", body: { incident_ids: incidentIds }, signal },
  );
}
