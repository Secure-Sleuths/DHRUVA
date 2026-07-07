/**
 * Shared types for the DHRUVA AI-SOC web app.
 *
 * These model the FastAPI JSON API contract the dashboard talks to. The server
 * is the source of truth for RBAC and licensing; the client only mirrors it
 * (see rbac.ts) and never widens it.
 */

/** RBAC roles, least → most privileged. `mssp_admin` is a superuser. */
export type Role =
  | "read_only"
  | "analyst"
  | "senior_analyst"
  | "admin"
  | "mssp_admin";

/**
 * The subset of JWT payload claims the client reads for DISPLAY ONLY. The token
 * is verified server-side; the client base64-decodes the middle segment without
 * verifying the signature (see token.ts::decodeJwtClaims). Never treat these as
 * an authorization decision — the server enforces.
 */
export interface JwtClaims {
  /** the operator subject (username / id) */
  sub?: string;
  /** RBAC role — mirrored (never widened) by the client */
  role?: Role | string;
  /** tenant id the token is scoped to */
  client_id?: string;
  /** human tenant name for the tenant chip */
  tenant_name?: string;
  /** standard expiry (seconds since epoch) if present */
  exp?: number;
  [claim: string]: unknown;
}

/**
 * `GET /api/license/tier-info` response. Shape confirmed against
 * `src/api/feature_gates.py::get_license_tier_info`.
 */
export interface LicenseTierInfo {
  /** machine tier id, e.g. "community" | "team" | "enterprise" | "unknown" */
  tier: string;
  /** pretty tier name, e.g. "Team" (absent on the error/unknown shape) */
  tier_display?: string;
  /** free tier → show the upgrade affordance */
  is_free?: boolean;
  /** LICENSE tab names unlocked by the tier (NOT ui tab ids — see TAB_NAME_MAP) */
  tabs: string[];
  /** feature keys, e.g. "nl_query", "full" */
  features: string[];
  limits?: Record<
    string,
    { max: number; label: string } | undefined
  >;
  active_response_actions?: string[];
  days_remaining?: number | null;
  upgrade_url?: string;
}

// ---- Triage decisions (WO-B1 contract) --------------------------------------
/**
 * The 4 canonical triage verdicts the backend emits. The UI relabels these for
 * display (see lib/triage.ts::verdictPresentation) — never invent new verdicts.
 */
export type TriageVerdict =
  | "true_positive"
  | "false_positive"
  | "needs_investigation"
  | "auto_close";

/**
 * One row from `GET /api/triage/decisions` — the FLATTENED, first-class shape
 * WO-B1 landed. `host` / `src_ip` may be null for rows created before the
 * flattening migration; render them gracefully (— placeholder). The verdict is
 * typed loosely (`TriageVerdict | string`) so an unknown value from a newer
 * backend degrades to a humanised label rather than crashing.
 */
export interface TriageDecision {
  id: string;
  verdict: TriageVerdict | string;
  /** model self-assessed confidence in [0, 1] — neutral ramp, NOT severity */
  confidence: number;
  /** 0..100; drives the row severity glyph + risk colour (see riskSeverity) */
  risk_score: number;
  rule_id: string | number | null;
  rule_description: string | null;
  host: string | null;
  src_ip: string | null;
  technique_ids: string[];
  tactic_ids: string[];
  created_at: string;
  escalated?: boolean;
  human_verdict?: TriageVerdict | string | null;
  /**
   * The following ride the SAME `SELECT * FROM agent_decisions` row the queue
   * serves (`triage.py::get_triage_decisions`), so they are present on the wire
   * even though the queue table doesn't render them — the decision glass-box
   * case view (WO-U5 deep-link) reads them. Optional/defensive: an older row may
   * omit any of them.
   */
  reasoning?: string | null;
  /** raw enrichment blob (JSON string or parsed) — parsed for host/MITRE/stage */
  enrichment_summary?: string | Record<string, unknown> | null;
  /** AI recommended next-steps for this alert — the `actions_taken` column
   * (JSON string array), riding the same SELECT * row. */
  actions_taken?: string | string[] | null;
  /** WO-B9 field-level anonymization categories, added at read time by the route */
  anonymized_fields?: AnonymizedField[];
  /**
   * AIS2 grounding self-check — the nullable `grounding` column, riding the SAME
   * `SELECT * FROM agent_decisions` row (`triage.py::_flatten_enrichment`
   * preserves it). A JSON STRING of shape
   * `{grounding:"high"|"medium"|"low", score, unsupported:[], reasons:[]}`, or
   * null for non-triage / legacy rows. Parse with `grounding.ts::parseGrounding`.
   * FLAG-ONLY / decorative — surfaced as an analyst-attention hint, never
   * mutating a verdict.
   */
  grounding?: string | null;
}

/** `GET /api/triage/decisions` envelope. */
export interface TriageDecisionsResponse {
  decisions: TriageDecision[];
  total: number;
}

/**
 * `GET /api/triage/rule-stats/{rule_id}?days=7` (`triage.py::get_rule_stats` →
 * `store.get_fp_rate_for_rule`) — per-rule verdict stats over the last `days`
 * (default 7, allowed 1..90), tenant-scoped server-side. `fp_rate` and
 * `avg_confidence` are floats in [0, 1]. READ-ONLY (`verify_jwt`). A rule with
 * no decisions in the window returns `total: 0` with zeroed counts.
 */
export interface RuleStats {
  rule_id: number;
  total: number;
  fp_count: number;
  tp_count: number;
  auto_closed: number;
  /** false-positive rate in [0, 1] (0 when total is 0) */
  fp_rate: number;
  /** mean model self-assessed confidence in [0, 1] (0 when total is 0) */
  avg_confidence: number;
}

/**
 * `GET /api/triage/pending-review` (`triage.py::get_pending_reviews`) — the
 * human-review backlog: decisions that were ESCALATED and have NO human verdict
 * yet. Each item is a full decision dict (same entity as the Triage queue). NB:
 * unlike `/decisions`, these rows are NOT server-flattened, so `host` / `src_ip`
 * / `technique_ids` / `tactic_ids` / `anonymized_fields` may be absent — the
 * client defaults them and reads host/MITRE from `enrichment_summary`. READ-ONLY
 * (`verify_jwt`).
 */
export interface PendingReviewResponse {
  pending: TriageDecision[];
  count: number;
}

/**
 * `GET /api/triage/decisions/{id}/audit-trail` (`triage.py`) — the raw
 * `decision_audit_trail` row PLUS a parsed WO-B4 `glass_box` (risk_breakdown +
 * provenance) the server attaches. The decision glass-box case view reads only
 * `glass_box`; the raw trail fields are left alongside for forward-compat. The
 * endpoint 404s when no trail exists for the decision — the caller then renders
 * the case from the decision's own fields with an empty (honest) glass_box.
 */
export interface DecisionAuditTrail {
  decision_id?: string;
  glass_box: GlassBox;
  [k: string]: unknown;
}

/** Sort mode for the triage queue. `recent` is the server default; the
 *  worst-first queue passes `risk` (risk_score DESC). */
export type TriageSort = "risk" | "recent";

// ---- Campaigns (WO-B5 contract) ---------------------------------------------
/**
 * A *campaign* is the set of incidents the M5 correlation engine linked by a
 * shared `attack_chain_id`, rolled up into one cross-host kill-chain. Shape
 * confirmed against `src/database/store.py::build_campaigns_from_incident_rows`
 * and served by `GET /api/campaigns` (`src/api/routes/campaigns.py`).
 *
 * IMPORTANT — what this contract does NOT carry (do not fabricate it):
 *  - `tactic_sequence` is an ordered list of ATT&CK TACTIC names only. There is
 *    NO per-node technique id / host / confidence / "why" here — that lives on
 *    the member incident/decision and is a future drill-down (WO-U4/U8).
 *  - `severity` is the incident string ("critical"|"high"|"medium"|"low"); map
 *    it onto the UI `Severity` scale via `campaign.ts::apiSeverity`.
 */
export type CampaignStatus = "active" | "contained";

export interface CampaignMemberIncident {
  id: string;
  title: string | null;
  severity: string | null;
  status: string | null;
  first_seen: string | null;
  last_seen: string | null;
  alert_count: number;
}

export interface CampaignAssets {
  hosts: string[];
  users: string[];
  ips: string[];
}

export interface ApiCampaign {
  attack_chain_id: string;
  name: string;
  title: string;
  /** incident severity string — "critical" | "high" | "medium" | "low" */
  severity: string;
  severity_rank: number;
  /** p-scale code, "P0".."P3" (presentation only; may be null) */
  p: string | null;
  severity_label: string | null;
  status: CampaignStatus | string;
  member_count: number;
  member_incidents: CampaignMemberIncident[];
  /** ordered ATT&CK TACTIC names (canonical kill-chain order) — NOT techniques */
  tactic_sequence: string[];
  furthest_tactic: string | null;
  /** next unseen tactic — heuristic hunt hint, never observed/actioned */
  projected_next_tactic: string | null;
  /** always "kill_chain_order_heuristic" (PM decision #4) */
  projection_basis: string;
  assets: CampaignAssets;
  alert_count: number;
  first_seen: string | null;
  last_seen: string | null;
  dwell_seconds: number | null;
  dwell: string | null;
}

/** `GET /api/campaigns` envelope. */
export interface CampaignsResponse {
  campaigns: ApiCampaign[];
  total: number;
}

// ---- Incidents / glass-box case view (WO-U4 contract) -----------------------
/**
 * The WO-B4 `glass_box.risk_breakdown` object — the per-enricher multiplier math
 * behind a decision's `risk_score`. Shape confirmed against
 * `src/enrichment/service.py::_compute_risk_score` → `breakdown`. Every field is
 * OPTIONAL because an older decision (or one with no recorded audit trail) yields
 * the stable default `{}` (see `store.py::parse_glass_box`); the case view falls
 * back to an honest "not recorded" line when the object is empty. The index
 * signature keeps a newer backend key from crashing the render.
 */
export interface RiskBreakdown {
  base_severity?: number;
  asset_multiplier?: number;
  user_multiplier?: number;
  time_multiplier?: number;
  mitre_boost?: number;
  ti_boost?: number;
  fp_discount?: number;
  anomaly_boost?: number;
  vuln_context_multiplier?: number;
  vuln_context_reason?: string;
  raw_score?: number;
  clamped_score?: number;
  [key: string]: number | string | undefined;
}

/** WO-B4 provenance for THIS exact verdict. Any field may be null on old rows. */
export interface GlassBoxProvenance {
  playbook_version: string | null;
  /** parsed guidance-version object (or a scalar/hash) — display as-is, never trusted */
  guidance_hash: unknown;
  model: string | null;
  latency_ms: number | null;
}

/** WO-B4 `glass_box` attached to each member alert on the incident detail. */
export interface GlassBox {
  risk_breakdown: RiskBreakdown;
  provenance: GlassBoxProvenance;
}

/**
 * WO-B9 "what the AI saw vs what you see" — the identity field CATEGORIES that
 * were anonymized before the LLM call. FIELD-LEVEL ONLY: `field` is one of the
 * three categories the anonymizer tokenizes, `label` its human name. This shape
 * NEVER carries a token string (e.g. `HOST_7f3a`) or a raw client value — that
 * is a hard invariant of the contract (`store.py::anonymized_fields_for`). When
 * the array is ABSENT (older backend / B9 not landed) the case view falls back
 * to a generic honest line.
 */
export interface AnonymizedField {
  /** category id: "host" | "internal_ip" | "user" (typed loosely for forward-compat) */
  field: string;
  /** human label: "Host" | "Internal IP" | "User" */
  label: string;
}

/**
 * One member alert (agent decision) on an incident detail. This is the raw
 * `agent_decisions` row (NOT the flattened triage-queue shape) with `glass_box`
 * + `anonymized_fields` attached server-side. `enrichment_summary` is the JSON
 * blob the queue flattens — the case view parses host / src_ip / techniques from
 * it defensively (see `incident.ts`), since the incident-detail endpoint does
 * not pre-flatten member alerts.
 */
export interface IncidentAlert {
  id: string;
  alert_id?: string;
  rule_id: string | number | null;
  rule_description: string | null;
  agent_type?: string;
  verdict: TriageVerdict | string;
  /** model self-assessed confidence in [0, 1] — neutral ramp, NOT severity */
  confidence: number;
  /** 0..100 */
  risk_score: number;
  reasoning: string | null;
  /** JSON string (or already-parsed object) of enrichment context */
  enrichment_summary?: string | Record<string, unknown> | null;
  /** AI recommended next-steps — `actions_taken` (JSON string array). */
  actions_taken?: string | string[] | null;
  playbook_used?: string | null;
  escalated?: boolean | number;
  human_override?: string | null;
  /** the human's recorded verdict, if one exists (gates the B10 override rule) */
  human_verdict?: TriageVerdict | string | null;
  created_at?: string;
  /** WO-B4 — attached to every member alert on the detail */
  glass_box?: GlassBox;
  /** WO-B9 — field-level anonymization categories; ABSENT on older backends */
  anonymized_fields?: AnonymizedField[];
  /**
   * AIS2 grounding self-check (nullable `grounding` column). Rides the same
   * `SELECT *` row incident detail serves; a JSON STRING (or null). Parse with
   * `grounding.ts::parseGrounding`. FLAG-ONLY / decorative — never mutates a
   * verdict.
   */
  grounding?: string | null;
}

/** One incident-timeline entry (append-only audit of the case). */
export interface IncidentTimelineEntry {
  id?: string | number;
  event_type: string;
  description: string;
  actor?: string | null;
  created_at?: string;
}

/**
 * One row from `GET /api/incidents`. The server returns the raw `incidents`
 * table row, so `mitre_tactics` / `affected_hosts` arrive as JSON-encoded TEXT
 * (e.g. `"[]"`) — parse defensively (see `incident.ts::parseJsonArray`), which
 * also tolerates an already-parsed array from a future serializer.
 */
export interface IncidentListRow {
  id: string;
  title: string;
  /** incident severity string — "critical" | "high" | "medium" | "low" */
  severity: string;
  status: string;
  first_seen: string | null;
  last_seen?: string | null;
  alert_count: number;
  attack_chain_id?: string | null;
  /** JSON-encoded string OR array of ATT&CK tactic names/ids */
  mitre_tactics?: string | string[] | null;
  /** JSON-encoded string OR array of hostnames */
  affected_hosts?: string | string[] | null;
  assigned_to?: string | null;
  created_at?: string | null;
  tier?: string | null;
  /** case-of-the-week flag (raw `flagged_interesting` col; 1/0 or bool). */
  flagged_interesting?: boolean | number | null;
  /** notes attached when flagged interesting. */
  interesting_notes?: string | null;
}

/** `GET /api/incidents` envelope. */
export interface IncidentsResponse {
  incidents: IncidentListRow[];
  total: number;
  offset?: number;
}

/** `GET /api/incidents/{id}` — the incident row + member alerts + timeline. */
export interface IncidentDetail extends IncidentListRow {
  summary?: string | null;
  mitre_techniques?: string | string[] | null;
  affected_users?: string | string[] | null;
  affected_ips?: string | string[] | null;
  alerts: IncidentAlert[];
  timeline: IncidentTimelineEntry[];
}

/**
 * `POST /api/triage/review` body (WO-B2). `reason` is REQUIRED server-side — an
 * empty reason yields a 422; the case view disables submit and explains why to
 * mirror that. `human_verdict` must be one of the 4 canonical verdicts.
 */
export interface TriageReviewBody {
  decision_id: string;
  human_verdict: TriageVerdict;
  reason: string;
}

// ---- Incident case-management write bodies (WO-U4 case writes) --------------
/**
 * Each body below mirrors a Pydantic model / raw-JSON contract in
 * `src/api/routes/incidents.py`. The client shapes match the server EXACTLY —
 * see `rbac.ts::incidentActionGate` for the mirrored RBAC per action and
 * `api.ts` for the fixture-gated clients. No client-side widening: the server
 * `require_role` (and `_check_incident_access` ownership check on
 * status/note/evidence) remains the source of truth.
 */

/** The 4 canonical incident states the server accepts (`ALLOWED_INCIDENT_STATUSES`). */
export type IncidentStatus = "open" | "investigating" | "resolved" | "closed";

/**
 * `POST /api/incidents/{id}/status` (WO-B3) — `IncidentStatusRequest`. `reason`
 * is MANDATORY server-side (empty/whitespace → 422); the panel disables submit
 * until a reason is present so it never fires a request the server rejects.
 * RBAC: analyst+, and an `analyst` may only act on an incident assigned to them.
 * The server also forbids reopening a `closed` incident (400).
 */
export interface IncidentStatusChangeBody {
  status: IncidentStatus;
  reason: string;
}

/** `POST /api/incidents/{id}/assign` — `IncidentAssignRequest`. RBAC: senior_analyst+. */
export interface IncidentAssignBody {
  assigned_to: string;
}

/** `POST /api/incidents/{id}/note` — `IncidentNoteRequest`. RBAC: analyst+ (assignee). */
export interface IncidentNoteBody {
  note: string;
}

/**
 * `POST /api/incidents/{id}/escalate` — a RAW JSON body (no Pydantic model on
 * the route). `handoff_notes` is optional server-side. RBAC: senior_analyst+.
 * The server rejects escalating to the same or a lower tier (400).
 */
export interface IncidentEscalateBody {
  tier: "L2" | "L3";
  handoff_notes: string;
}

/** `POST /api/incidents/{id}/flag-interesting` — `FlagInterestingRequest`. RBAC: analyst+. */
export interface IncidentFlagBody {
  flagged: boolean;
  notes: string;
}

/**
 * `POST /api/incidents/merge` — `IncidentMergeRequest`. IRREVERSIBLE (source
 * incidents are closed + their alerts re-linked). RBAC: senior_analyst+, AND
 * the `incidents_merge` LICENSE feature (server `require_license_feature`).
 */
export interface IncidentMergeBody {
  target_id: string;
  source_ids: string[];
}

/** The evidence `type` enum the server accepts (`EvidenceRequest`). */
export type EvidenceType =
  | "note"
  | "artifact"
  | "screenshot"
  | "log"
  | "ioc"
  | "file"
  | "other";

/** `POST /api/incidents/{id}/evidence` — `EvidenceRequest`. RBAC: analyst+ (assignee). */
export interface IncidentEvidenceBody {
  type: EvidenceType;
  description: string;
  ref_id?: string;
}

/** The post-incident-review status enum (`IncidentReviewRequest`). */
export type PirStatus = "draft" | "in_review" | "completed";

/**
 * `POST /api/incidents/{id}/review` — `IncidentReviewRequest` (post-incident
 * review). RBAC: senior_analyst+. All text fields are optional server-side.
 */
export interface IncidentReviewBody {
  review_date?: string | null;
  participants: string[];
  timeline_accuracy: string;
  detection_gap: string;
  response_effectiveness: string;
  lessons_learned: string;
  action_items: Record<string, unknown>[];
  detection_backlog_items: Record<string, unknown>[];
  status: PirStatus;
}

/** The `{status: "ok", ...}` envelope the incident write endpoints return. */
export interface IncidentWriteResult {
  status: string;
  incident_id?: string;
  [k: string]: unknown;
}

// ---- Overview KPI summary (WO-B7 contract) ----------------------------------
/**
 * `GET /api/overview/summary` — the KPI strip, each tile `{ value, ...detail }`
 * so the UI can expand-to-math. Shape confirmed against
 * `src/api/routes/overview.py::build_overview_summary`.
 */
export interface OverviewCampaignRef {
  attack_chain_id: string | null;
  name: string | null;
}

export interface OverviewSummary {
  active_campaigns: { value: number; advancing: number; contained: number };
  estate_dwell_worst: {
    value_seconds: number | null;
    value: string | null;
    campaign: OverviewCampaignRef | null;
  };
  /** `of_total` is null by contract (no cheap tenant-scoped monitored count) */
  hosts_on_chain: { value: number; hosts: string[]; of_total: number | null };
  furthest_tactic: {
    value: string | null;
    campaign: OverviewCampaignRef | null;
    exfil_or_impact_reached: boolean;
  };
  open_incidents: { value: number; critical: number };
}

// ---- NL-Query copilot (WO-B8 contract) — Investigate tab (WO-U6) ------------
/**
 * The model's self-assessed answer confidence. This is a COARSE 3-level string,
 * distinct from the numeric per-decision `confidence` (0..1) used elsewhere — it
 * rides a NEUTRAL ramp and is NEVER coloured on the severity scale.
 */
export type NLQueryConfidence = "high" | "medium" | "low";

/** The three grounded data planes a source can come from (WO-B8). */
export type NLQuerySourceKind = "opensearch" | "wazuh_api" | "knowledge_base";

/**
 * ONE answer-level grounded source (WO-B8, LANDED). This is METADATA ONLY — it
 * carries a description + a hit count + the index/dataset it came from, NEVER a
 * raw hit body. The copilot renders each `source` as a Citation chip; this is
 * the MVP grounding granularity (answer-level). Per-claim inline citations are a
 * marked fast-follow — do NOT fabricate them from this shape.
 */
export interface NLQuerySource {
  id: string;
  /** which data plane — typed loosely for forward-compat with a newer backend */
  source: NLQuerySourceKind | string;
  /** human description of what was queried, e.g. "process-access events on HOST" */
  description: string;
  /** number of matching records this source contributed */
  count: number;
  /** OpenSearch index the source hit (when `source` is "opensearch") */
  index?: string | null;
  /** knowledge-base dataset name (when `source` is "knowledge_base") */
  dataset?: string | null;
  /** a per-source retrieval error (e.g. the plane was unreachable) — shown honestly */
  error?: string | null;
}

/**
 * A finding row the copilot pulled in. The backend most commonly returns each
 * finding as a plain STRING (`"Key finding 1 …"`), but the shape is intentionally
 * open (it varies by query plane), so a finding may also be a structured record.
 * The UI renders DEFENSIVELY: a bare string IS the finding title; a record has a
 * handful of well-known optional keys with a compact fallback. It never assumes a
 * field is present and never fabricates one.
 */
export type NLQueryFinding = string | Record<string, unknown>;

/**
 * A suggested action the copilot returned. It may be a bare label (string) OR a
 * STRUCTURED containment proposal carrying the fields the propose endpoint needs
 * (`action` + `agent_id`, plus optional target/incident/alert). Only a structured
 * action with both `action` and `agent_id` is surfaced as a proposable
 * ContainmentActionCard — a bare string renders as an informational note, never a
 * fabricated proposal (see `investigate.ts::normalizeSuggestedActions`).
 */
export type NLQuerySuggestedAction =
  | string
  | {
      action?: string;
      agent_id?: string;
      target?: string;
      host?: string;
      description?: string;
      label?: string;
      reason?: string;
      timeout?: number;
      alert_id?: string;
      incident_id?: string;
      [key: string]: unknown;
    };

/**
 * `POST /api/query` response (WO-B8). The NL-Query agent answers in natural
 * language, cites the `sources` that informed it (answer-level grounding), and
 * suggests follow-ups. Auth: `verify_jwt` + `require_nl_query_quota()` — the PAID
 * gate. A runtime 402/403 from the quota gate is handled gracefully by the caller.
 */
export interface NLQueryResponse {
  answer: string;
  findings: NLQueryFinding[];
  risk_assessment?: string | null;
  confidence: NLQueryConfidence | string;
  suggested_actions: NLQuerySuggestedAction[];
  follow_up_queries: string[];
  sources: NLQuerySource[];
  duration_ms?: number;
  total_hits?: number;
  queries_executed?: number;
}

// ---- Propose containment (active response — HUMAN-APPROVED) -----------------
/**
 * `POST /api/response/propose` body. This QUEUES a containment proposal for human
 * approval — it does NOT execute. Role: analyst+ (mirrored client-side). `reason`
 * is REQUIRED. The Investigate tab NEVER calls approve/execute/reverse — proposing
 * is the only mutation it performs, and even that short-circuits in fixture mode.
 */
export interface ProposeContainmentBody {
  action: string;
  agent_id: string;
  target?: string;
  timeout?: number;
  alert_id?: string;
  incident_id?: string;
  reason: string;
}

/**
 * `POST /api/response/propose` response — the created proposal, always
 * `status: "pending_approval"`. The action is now queued in the Respond queue for
 * a human to approve; nothing has run.
 */
export interface ProposeContainmentResponse {
  id: string;
  /** always "pending_approval" — the proposal is queued, not executed */
  status: string;
  action: string;
}

// ---- MITRE ATT&CK coverage (WO-B6 / WO-U8) ----------------------------------
/**
 * All MITRE endpoints below are `verify_jwt` + the `mitre` LICENSE gate
 * (`src/api/routes/mitre.py`, `require_license_feature("mitre")`). NOTE: in the
 * shipped license model (`src/licensing.py`) `mitre` is a CORE feature included
 * in EVERY tier (community/team/enterprise), so a standard tenant never hits the
 * gate — a 403/503 only occurs for a restricted/custom license or when the
 * license isn't loaded. The tab degrades to FeatureLockedState in that case
 * (never a broken grid / fabricated coverage).
 */

/**
 * One per-tactic coverage row from `GET /api/mitre/summary`. `tactic` is the
 * FULL ATT&CK tactic NAME (e.g. "Credential Access"), matching campaign
 * `tactic_sequence` / `projected_next_tactic` / `furthest_tactic` — the overlay
 * joins on this name. `coverage_pct` is DETECTION coverage (detected/total
 * techniques for the tactic), on its own neutral coverage-band scale — NOT the
 * severity scale. Shape confirmed against `mitre/coverage.py::get_coverage_summary`.
 */
export interface MitreTacticCoverage {
  tactic: string;
  tactic_id: string;
  total: number;
  detected: number;
  coverage_pct: number;
}

/** Overall coverage stats — `{}` on the no-analyzer path, so every field is optional. */
export interface MitreOverall {
  total_techniques?: number;
  detected?: number;
  coverage_pct?: number;
}

/**
 * `GET /api/mitre/summary` — the per-tactic coverage grid. `per_tactic` is
 * already in canonical kill-chain order (the backend iterates `MITRE_TACTICS`),
 * so the grid renders it verbatim rather than hard-coding a tactic list. Empty
 * `per_tactic` (no analyzer / no coverage yet) → the tab shows an empty state.
 */
export interface MitreSummary {
  per_tactic: MitreTacticCoverage[];
  overall: MitreOverall;
}

/**
 * One stage of a per-incident kill chain (`GET /api/mitre/incident/{id}`, WO-B6).
 * `org_coverage_pct` is ORG-WIDE detection %, NEVER this incident's — it is
 * labelled as such in the UI and matches the response `coverage_basis`. `is_gap`
 * is present+true when the stage is either an unseen intermediate tactic OR its
 * org coverage is below the backend gap threshold. `null` org_coverage_pct means
 * the org overlay is unknown for that tactic (then it can only be an unseen gap).
 */
export interface MitreChainStage {
  tactic: string;
  tactic_id: string;
  present_in_incident: boolean;
  /** ORG-WIDE detection % (never incident-specific); null when unknown */
  org_coverage_pct: number | null;
  is_gap?: boolean;
}

/**
 * `GET /api/mitre/incident/{id}` — per-incident kill-chain coverage (WO-B6). The
 * `chain` spans the incident's earliest→furthest observed tactic (canonical
 * order) with unseen intermediate tactics filled in as blind spots.
 * `coverage_basis` is always "org_wide" — the org overlay, not the incident's.
 */
export interface MitreIncidentCoverage {
  incident_id: string;
  chain: MitreChainStage[];
  /** span stages that are NOT gaps */
  covered_count: number;
  chain_length: number;
  /** span stage with the lowest KNOWN org coverage %; null if none known */
  weakest_tactic: string | null;
  /** furthest (latest canonical) tactic the incident actually reached */
  furthest_tactic: string | null;
  /** always "org_wide" — the coverage overlay is org-wide, not incident-specific */
  coverage_basis: "org_wide" | string;
}

// ---- Detection proposals (WO-U9) — Detection tab ----------------------------
/**
 * The AI-proposed Wazuh rule change types the Detection Agent emits
 * (`src/database/store.py::DetectionProposal.change_type`). Typed loosely so a
 * newer backend value degrades to a humanised label rather than crashing.
 */
export type DetectionChangeType =
  | "tune"
  | "disable"
  | "new_rule"
  | "modify"
  | string;

/** Proposal lifecycle status. `deployed`/`rolled_back` are terminal states. */
export type DetectionProposalStatus =
  | "proposed"
  | "needs_manual_tuning"
  | "approved"
  | "deployed"
  | "rejected"
  | "rolled_back"
  | string;

/**
 * One row from `GET /api/detection/proposals` — the raw `detection_proposals`
 * row (`store.py::get_all_proposals`, `SELECT *`). The proposal is keyed on
 * `id` (NOT `proposal_id`); the rule XML is carried as `original_xml` +
 * `proposed_xml` (there is NO pre-computed diff — the UI diffs them line-by-line
 * client-side). There is NO stored logtest result and NO `confidence`/`created_at`
 * on the proposal — the timestamp is `proposed_at`, and the false-positive
 * context is only `fp_count_trigger` (# FPs that triggered the proposal) over
 * `fp_window_days`. Read-only: approve/deploy/reject/rollback are a later gated WO.
 */
export interface DetectionProposal {
  id: string;
  rule_id: number | string | null;
  rule_file: string | null;
  change_type: DetectionChangeType;
  original_xml: string | null;
  proposed_xml: string | null;
  reasoning: string | null;
  /** # of false positives that triggered this proposal (FP-impact) */
  fp_count_trigger: number | null;
  /** the window over which the FPs were counted */
  fp_window_days: number | null;
  status: DetectionProposalStatus;
  proposed_at: string | null;
  reviewed_by: string | null;
  reviewed_at: string | null;
  deployed_at?: string | null;
  rejection_notes?: string | null;
  /** peer-review metadata (may be null) */
  assigned_reviewer?: string | null;
  review_requested_at?: string | null;
  peer_review_notes?: string | null;
}

/** `GET /api/detection/proposals` envelope. */
export interface DetectionProposalsResponse {
  proposals: DetectionProposal[];
  count: number;
}

// ---- Threat Intel (WO-U9) — Threat Intel tab --------------------------------
/**
 * IoC statistics from `GET /api/threat-intel/stats` (`store.py::get_ioc_stats`).
 * The three breakdowns are lists of `{ <dimension>, count }` (the dimension key
 * differs per breakdown — source / ioc_type / severity).
 */
export interface IocStats {
  total_iocs: number;
  by_source: { source: string; count: number }[];
  by_type: { ioc_type: string; count: number }[];
  by_severity: { severity: string; count: number }[];
}

/** One feed status row (`store.py::get_feed_statuses`, `threat_intel_feeds`). */
export interface TIFeed {
  id: string | number;
  feed_name: string;
  feed_url?: string | null;
  feed_type?: string | null;
  tier?: number | null;
  /** stored as int 0/1 in Postgres — coerce for display */
  enabled?: number | boolean | null;
  requires_api_key?: number | boolean | null;
  last_fetch_at?: string | null;
  last_success_at?: string | null;
  last_ioc_count?: number | null;
  total_ioc_count?: number | null;
  error_count?: number | null;
  last_error?: string | null;
  collection_interval_minutes?: number | null;
  status?: string | null;
  updated_at?: string | null;
}

/** `GET /api/threat-intel/stats` envelope. */
export interface TIStatsResponse {
  stats: IocStats;
  feeds: TIFeed[];
  kev_count: number;
}

/**
 * One CVE row (`GET /api/threat-intel/cve`, `store.py::get_all_cves`/`get_kev_cves`,
 * `threat_intel_cve`). `in_cisa_kev` / `kev_ransomware` are int 0/1 flags, not
 * booleans — coerce for display.
 */
export interface TICve {
  cve_id: string;
  description?: string | null;
  severity?: string | null;
  cvss_score?: number | null;
  epss_score?: number | null;
  epss_percentile?: number | null;
  in_cisa_kev?: number | boolean | null;
  kev_date_added?: string | null;
  kev_due_date?: string | null;
  kev_ransomware?: number | boolean | null;
  vendor?: string | null;
  product?: string | null;
  updated_at?: string | null;
}

/** `GET /api/threat-intel/cve` envelope. */
export interface TICvesResponse {
  cves: TICve[];
  total: number;
}

// ---- Host Integrity (WO-U9) — fim tab ---------------------------------------
/** Nested OS block on a Wazuh agent (`get_all_agents`, Wazuh 4.x native). */
export interface WazuhAgentOs {
  name?: string | null;
  platform?: string | null;
  version?: string | null;
}

/** One Wazuh agent (`GET /api/agents`). Fields are Wazuh 4.x native (passthrough). */
export interface WazuhAgent {
  id: string;
  name?: string | null;
  ip?: string | null;
  status?: string | null;
  os?: WazuhAgentOs | null;
  version?: string | null;
  lastKeepAlive?: string | null;
  group?: string[] | string | null;
}

/** `GET /api/agents` envelope. */
export interface AgentsResponse {
  agents: WazuhAgent[];
  total: number;
}

/**
 * One FIM/syscheck entry (`GET /api/agents/{id}/syscheck`). Wazuh-version-native
 * passthrough — the JS-rendered subset below is the guaranteed-present set; the
 * index signature tolerates extra native keys. Registry entries share this shape.
 */
export interface SyscheckEntry {
  file?: string | null;
  type?: string | null;
  mtime?: string | null;
  size?: number | string | null;
  perm?: string | null;
  uname?: string | null;
  gname?: string | null;
  md5?: string | null;
  sha1?: string | null;
  sha256?: string | null;
  date?: string | null;
  [k: string]: unknown;
}

/** `GET /api/agents/{id}/syscheck` envelope. */
export interface SyscheckResponse {
  syscheck: SyscheckEntry[];
  total: number;
}

/** One rootcheck (policy-monitoring) entry (`GET /api/agents/{id}/rootcheck`). */
export interface RootcheckEntry {
  title?: string | null;
  log?: string | null;
  status?: string | null;
  cis?: string | null;
  pci_dss?: string | null;
  date_first?: string | null;
  date_last?: string | null;
  event?: string | null;
  [k: string]: unknown;
}

/** `GET /api/agents/{id}/rootcheck` envelope. */
export interface RootcheckResponse {
  rootcheck: RootcheckEntry[];
  total: number;
}

/** `GET /api/agents/{id}/registry` envelope (Windows registry FIM). */
export interface RegistryResponse {
  registry: SyscheckEntry[];
  total: number;
}

/**
 * `GET /api/vulnerabilities/summary` — host-vulnerability overview scoped to the
 * caller's tenant agents. `by_severity` is a severity→count map; `top_cves` is
 * the most-frequent CVE ids. Shape confirmed against `response.py`.
 */
export interface VulnSummary {
  total_vulnerabilities: number;
  by_severity: Record<string, number>;
  affected_agents: number;
  top_cves: { cve: string; count: number }[];
}

/**
 * One per-agent vulnerability item from `GET /api/vulnerabilities?agent_id=…`
 * (`response.py`). The backend passes the RAW Wazuh OpenSearch `_source` document
 * through VERBATIM — it is NOT reshaped into flat `{cve, cvss, severity}` fields.
 * So this models the nested ECS-style Wazuh 4.x vuln doc, read DEFENSIVELY: the
 * CVE lives at `vulnerability.id`, CVSS at `vulnerability.score.base`, severity at
 * `vulnerability.severity`, and the affected package under `package`. Every field
 * is optional and the index signature tolerates extra native keys — nothing is
 * fabricated when a field is absent (see `hostintegrity.ts::vulnFields`).
 */
export interface AgentVulnerability {
  agent?: { id?: string | null; name?: string | null } | null;
  vulnerability?: {
    id?: string | null;
    severity?: string | null;
    score?: { base?: number | null; version?: string | null } | null;
    reference?: string | null;
    published?: string | null;
    [k: string]: unknown;
  } | null;
  package?: {
    name?: string | null;
    version?: string | null;
    architecture?: string | null;
    [k: string]: unknown;
  } | null;
  host?: { os?: { platform?: string | null; name?: string | null } | null } | null;
  [k: string]: unknown;
}

/** `GET /api/vulnerabilities?agent_id=…` envelope (raw Wazuh docs passthrough). */
export interface AgentVulnerabilitiesResponse {
  vulnerabilities: AgentVulnerability[];
  total: number;
}

// ---- Host Integrity (WO-U15 READ half) — critical vulns + remediation --------
/**
 * `GET /api/vulnerabilities/critical?limit=` envelope (`response.py::
 * get_critical_vulnerabilities`). Fleet-wide Critical-severity vulns, scoped to
 * the tenant's allowed agents server-side. The items are the SAME RAW Wazuh vuln
 * `_source` docs as `/api/vulnerabilities` (`AgentVulnerability`), rendered
 * DEFENSIVELY — the fleet view additionally reads `agent.id`/`agent.name` and the
 * optional `vulnerability.title`. READ-ONLY; same `compliance_sca` gate.
 */
export interface CriticalVulnerabilitiesResponse {
  vulnerabilities: AgentVulnerability[];
  total: number;
}

/**
 * One recommended-remediation record from `GET /api/vulnerabilities/remediation?
 * agent_id=…` (`response.py::_generate_remediation`). ADVISORY / INFORMATIONAL
 * ONLY — the `command` is a suggested package-update string that DHRUVA does NOT
 * execute from the UI (the state-changing `/remediate` execute path is a separate,
 * admin-gated WO that is deliberately NOT wired here). Every field is best-effort
 * and read defensively; the index signature tolerates extra server keys (e.g. the
 * server's `can_auto_execute` hint, which the read UI intentionally never surfaces
 * as a control). READ-ONLY.
 */
export interface VulnRemediation {
  cve_id?: string | null;
  package_name?: string | null;
  current_version?: string | null;
  fix_version?: string | null;
  fix_hint?: string | null;
  cvss_score?: number | null;
  severity?: string | null;
  /** suggested package-update command — DISPLAY ONLY, never executed by the UI */
  command?: string | null;
  method?: string | null;
  platform?: string | null;
  reference?: string | null;
  [k: string]: unknown;
}

/** `GET /api/vulnerabilities/remediation?agent_id=…` envelope. */
export interface VulnRemediationResponse {
  remediations: VulnRemediation[];
  total: number;
}

// ---- Host Integrity (WO-U15 EXECUTE half) — remediate + verify ---------------
/**
 * `POST /api/vulnerabilities/remediate` result (WO-U15 EXECUTE half,
 * `response.py::execute_remediation`). STATE-CHANGING / ACTIVE-RESPONSE-ADJACENT:
 * the server (ADMIN ONLY via `require_admin`, `vuln_remediation` tier, 3/min rate
 * limit, `_verify_agent_access`, and platform-restricted to Linux apt/yum/zypper)
 * dispatches an async package-update command via Wazuh active response.
 * `status:"pending"` means the AR command was ACCEPTED — NOT that the update has
 * landed; confirm with `/verify`. `status:"failed"` means the dispatch itself
 * failed (nothing in force). `version_before` is the package version captured
 * pre-update, fed back into the verify call. Read defensively.
 */
export interface RemediationExecuteResult {
  status: "pending" | "failed";
  agent_id: string;
  package: string;
  pkg_manager: string;
  version_before: string | null;
  result: { success?: boolean; error?: string; [k: string]: unknown };
  message: string;
}

/**
 * `GET /api/vulnerabilities/verify` result (WO-U15 EXECUTE half,
 * `response.py::verify_remediation`). The "did the update land" follow-up check.
 * `status` is one of: `not_found` (package absent), `updated` (version changed —
 * carries version_before/after), `unchanged` (same version, vuln still present),
 * `possibly_updated` (version same but vuln no longer indexed — rescan pending).
 * Every field beyond `status`/`message` is best-effort and read defensively; the
 * union keeps `string` so an unexpected server status never breaks the render.
 */
export interface RemediationVerifyResult {
  status: "not_found" | "updated" | "unchanged" | "possibly_updated" | string;
  message: string;
  version_before?: string | null;
  version_after?: string | null;
  version_current?: string | null;
  still_vulnerable?: boolean;
}

// ---- Host Integrity (WO-U14) — syscollector inventory + SCA ------------------
// All five shapes below are RAW Wazuh 4.x syscollector / SCA `affected_items`
// dicts, returned VERBATIM by the API (`enrichment/wazuh_client.py`). Field names
// come straight from Wazuh and vary by version/OS, so every field is optional, the
// index signature tolerates extra native keys, and the tab renders each field
// defensively (absent → dash, never a crash).

/** One syscollector process (`GET /api/agents/{id}/processes`). */
export interface AgentProcess {
  name?: string | null;
  pid?: number | string | null;
  ppid?: number | string | null;
  state?: string | null;
  cmd?: string | null;
  command?: string | null;
  euser?: string | null;
  [k: string]: unknown;
}
/** `GET /api/agents/{id}/processes` envelope. */
export interface AgentProcessesResponse {
  processes: AgentProcess[];
  total: number;
}

/** One syscollector open port / network connection (`GET /api/agents/{id}/ports`). */
export interface AgentPort {
  protocol?: string | null;
  local?: { ip?: string | null; port?: number | string | null } | null;
  local_ip?: string | null;
  local_port?: number | string | null;
  state?: string | null;
  process?: string | null;
  pid?: number | string | null;
  [k: string]: unknown;
}
/** `GET /api/agents/{id}/ports` envelope. */
export interface AgentPortsResponse {
  ports: AgentPort[];
  total: number;
}

/** One installed package (`GET /api/agents/{id}/packages`). */
export interface AgentPackage {
  name?: string | null;
  version?: string | null;
  architecture?: string | null;
  arch?: string | null;
  format?: string | null;
  vendor?: string | null;
  [k: string]: unknown;
}
/** `GET /api/agents/{id}/packages` envelope. */
export interface AgentPackagesResponse {
  packages: AgentPackage[];
  total: number;
}

/**
 * One SCA policy summary (`GET /api/agents/{agent_id}/sca`). Each carries a
 * pass/fail/score roll-up; drill into `policy_id` for its individual checks.
 */
export interface ScaPolicy {
  policy_id?: string | null;
  name?: string | null;
  pass?: number | null;
  fail?: number | null;
  invalid?: number | null;
  score?: number | null;
  total_checks?: number | null;
  end_scan?: string | null;
  [k: string]: unknown;
}
/** `GET /api/agents/{agent_id}/sca` envelope (SCA policy list). */
export interface ScaPoliciesResponse {
  policies: ScaPolicy[];
  total: number;
}

/**
 * One SCA check result (`GET /api/agents/{agent_id}/sca/{policy_id}`). `result`
 * is "passed" / "failed" / "not applicable". A failed check feeds the M4 triage
 * risk score server-side; this view is read-only surfacing only.
 */
export interface ScaCheck {
  id?: number | string | null;
  title?: string | null;
  result?: string | null;
  rationale?: string | null;
  remediation?: string | null;
  compliance?: unknown;
  [k: string]: unknown;
}
/** `GET /api/agents/{agent_id}/sca/{policy_id}` envelope (SCA checks). */
export interface ScaChecksResponse {
  checks: ScaCheck[];
  total: number;
}

// ---- Metrics (WO-U9) — Metrics tab ------------------------------------------
/**
 * MTT metrics snapshot (`store.py::compute_mtt_metrics`), returned per window by
 * `GET /api/metrics/soc-summary`. Times are in MINUTES; SLA figures are % compliance.
 * NOTE: these endpoints do NOT return an LLM-cost figure — the Metrics tab renders
 * an honest "not exposed" placeholder for it rather than fabricating one.
 */
export interface MttMetrics {
  mttd_min?: number | null;
  mtta_min?: number | null;
  mttr_min?: number | null;
  sla_response_compliance?: number | null;
  sla_resolution_compliance?: number | null;
  sample_count?: number;
  by_severity?: Record<
    string,
    { count: number; mttd_min?: number | null; mtta_min?: number | null; mttr_min?: number | null }
  >;
}

/** `GET /api/metrics/soc-summary` — today / 7d / 30d MTT snapshots. */
export interface SocSummaryResponse {
  today: MttMetrics;
  week: MttMetrics;
  month: MttMetrics;
}

/** `GET /api/metrics/automation-rates` (`calculator.py::get_automation_rates`). */
export interface AutomationRates {
  period_days?: number;
  total_decisions?: number;
  auto_closed?: number;
  auto_close_rate?: number;
  enrichment_automation_pct?: number;
  false_positives?: number;
  true_positives?: number;
}

/** `GET /api/dashboard/stats::today`. */
export interface DashboardStatsToday {
  total: number;
  fps: number;
  tps: number;
  auto_closed: number;
  escalated: number;
  avg_confidence: number;
}

/** One `weekly_trend` point on the dashboard stats. */
export interface DashboardTrendPoint {
  day: string;
  total: number;
  fps: number;
  tps: number;
  avg_confidence: number;
}

/** One noisy-rule row on the dashboard stats (feeds the Detection loop). */
export interface DashboardNoisyRule {
  rule_id: number | string;
  rule_description?: string | null;
  total_alerts: number;
  fp_count: number;
  fp_rate: number;
  tuning_action?: string | null;
}

/** `GET /api/dashboard/stats` — comprehensive dashboard counts. */
export interface DashboardStats {
  today: DashboardStatsToday;
  weekly_trend: DashboardTrendPoint[];
  noisy_rules: DashboardNoisyRule[];
  pending_reviews: number;
  pending_proposals: number;
  open_incidents: number;
  critical_incidents: number;
  anomaly_count?: number;
}

// ---- Metrics (WO-U9 extension) — the remaining metrics endpoints ------------
// All of these are `require_role("admin","senior_analyst")` and NONE is
// license-gated (only `/metrics/reports/{type}` carries a license feature).

/** One row of `GET /api/metrics/analyst-performance::analysts` (`store.py::get_analyst_performance`). */
export interface AnalystPerformanceRow {
  actor: string;
  incidents_touched: number;
  resolved_count: number;
  total_actions: number;
}
export interface AnalystPerformanceResponse {
  analysts: AnalystPerformanceRow[];
}

/** One row of `GET /api/metrics/analyst-workload::analysts` (`calculator.py::check_analyst_workload`). */
export interface AnalystWorkloadRow {
  analyst: string;
  open_incidents: number;
  critical: number;
  high: number;
  is_overloaded: boolean;
}
export interface AnalystWorkloadResponse {
  analysts: AnalystWorkloadRow[];
}

/** One open case in `GET /api/metrics/case-aging::cases` (`calculator.py::get_case_aging`). */
export interface CaseAgingRow {
  id: number | string;
  title: string;
  severity: string;
  status: string;
  assigned_to?: string | null;
  created_at: string;
  first_response_at?: string | null;
  alert_count?: number | null;
  hours_open: number;
  is_stale: boolean;
}
export interface CaseAgingResponse {
  cases: CaseAgingRow[];
}

/** One hunt cycle in `GET /api/metrics/hunt-trends::cycles` (`calculator.py::get_hunt_cycle_trends`). */
export interface HuntTrendCycle {
  cycle_id: number | string;
  total_hypotheses: number;
  hits: number;
  confirmed: number;
  hit_rate: number;
  confirmation_rate: number;
  cycle_date?: string | null;
}
export interface HuntTrendsResponse {
  cycles: HuntTrendCycle[];
}

/** `GET /api/metrics/automation-health` (`calculator.py::get_automation_health`). */
export interface AutomationHealth {
  period_days: number;
  enrichment_latency: {
    sample_count?: number;
    p50_ms?: number | null;
    p95_ms?: number | null;
    p99_ms?: number | null;
    avg_ms?: number | null;
  };
  soar_actions: {
    total_actions: number;
    success_count: number;
    failure_count: number;
    success_rate?: number | null;
  };
}

/** One day of `GET /api/metrics/soc-performance::trends` (`store.py::get_mtt_daily_trend`). */
export interface SocPerformanceTrendPoint {
  day: string;
  avg_mttd?: number | null;
  avg_mtta?: number | null;
  avg_mttr?: number | null;
  incident_count: number;
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
}
/** `GET /api/metrics/soc-performance` — MTT snapshot + daily trend. */
export interface SocPerformanceResponse {
  metrics: MttMetrics;
  trends: SocPerformanceTrendPoint[];
}

// ---- Reports (WO-U9c) — Reports tab -----------------------------------------
// The ONLY reports route is `GET /api/metrics/reports/{daily|weekly|monthly}`
// (`require_role("admin","senior_analyst")` + `require_license_feature(
// "reports")`). It GENERATES a fresh report as JSON on demand from read-only
// SELECTs (no persistence, no side effects); there is NO list/history endpoint.
// Shapes mirror `src/reports/generator.py`.

export type SocReportType = "daily" | "weekly" | "monthly";

export interface SocReportAlerts {
  total: number;
  true_positives: number;
  false_positives: number;
  auto_closed: number;
  escalated: number;
  avg_confidence: number;
}
export interface SocReportIncidents {
  new: number;
  critical: number;
  high: number;
  resolved: number;
  currently_open: number;
}
export interface SocReportNoisyRule {
  rule_id: number | string;
  description?: string | null;
  fp_count: number;
}
export interface SocReportDetectionEngineering {
  proposals_created: number;
  proposals_deployed: number;
  proposals_approved: number;
}
export interface SocReportThreatHunting {
  findings_total: number;
  findings_hits: number;
  findings_confirmed: number;
}
export interface SocReportMitreCoverage {
  total_techniques: number;
  active: number;
  stale: number;
  noisy: number;
  coverage_pct: number;
}
export interface SocReportSlaCompliance {
  total_resolved: number;
  response_met: number;
  resolution_met: number;
  response_compliance_pct: number;
  resolution_compliance_pct: number;
}
/**
 * A generated SOC report. `daily` carries the leaf fields (alerts/incidents/
 * top_noisy_rules/mtt_metrics); `weekly` nests a `daily_snapshot` and adds
 * detection/hunting/automation; `monthly` nests a `weekly_snapshot` and adds
 * analyst/MITRE/SLA. Every extra field is optional so one type covers all three.
 */
export interface SocReport {
  type: SocReportType;
  generated_at: string;
  period: string;
  // daily leaf
  alerts?: SocReportAlerts;
  incidents?: SocReportIncidents;
  mtt_metrics?: MttMetrics;
  top_noisy_rules?: SocReportNoisyRule[];
  // weekly
  daily_snapshot?: SocReport;
  weekly_mtt?: MttMetrics;
  detection_engineering?: SocReportDetectionEngineering;
  threat_hunting?: SocReportThreatHunting;
  automation_rates?: AutomationRates;
  // monthly
  weekly_snapshot?: SocReport;
  monthly_mtt?: MttMetrics;
  analyst_performance?: AnalystPerformanceRow[];
  mitre_coverage?: SocReportMitreCoverage;
  sla_compliance?: SocReportSlaCompliance;
}

// ---- Admin (WO-U9) — Admin tab ----------------------------------------------
/**
 * One user row (`GET /api/admin/users`, `store.py::get_all_users`). The endpoint
 * explicitly SELECTs a safe column set — `password_hash` / `salt` are NEVER
 * returned. `is_active` is an int 0/1 in Postgres. Read-only: no create/edit here.
 */
export interface AdminUser {
  id: string;
  username: string;
  display_name?: string | null;
  email?: string | null;
  role: Role | string;
  is_active: number | boolean;
  created_at?: string | null;
  updated_at?: string | null;
}

/** `GET /api/admin/users` envelope. */
export interface AdminUsersResponse {
  users: AdminUser[];
  total: number;
}

/**
 * One tenant row (`GET /api/admin/tenants`, mssp_admin only). The route strips
 * the encrypted config and returns only metadata + config KEY names (never
 * values) + boolean "is X configured" flags. Read-only.
 */
export interface AdminTenant {
  id: string;
  name: string;
  slug: string;
  active: boolean;
  created_at?: string | null;
  updated_at?: string | null;
  config_keys: string[];
  has_wazuh: boolean;
  has_claude: boolean;
  has_notifications: boolean;
}

/** `GET /api/admin/tenants` envelope. */
export interface AdminTenantsResponse {
  tenants: AdminTenant[];
}

/**
 * One audit-log entry (`GET /api/admin/audit-log`, `require_role("admin")`). The
 * append-only trail of who did what. `details` is a JSON blob (or already-parsed
 * object); render it as compact JSON, never trusted. READ-ONLY.
 */
export interface AdminAuditEntry {
  id?: string | number;
  actor?: string | null;
  action?: string | null;
  target_type?: string | null;
  target_id?: string | null;
  ip_address?: string | null;
  details?: string | Record<string, unknown> | null;
  created_at?: string | null;
  [k: string]: unknown;
}

/** `GET /api/admin/audit-log` envelope. */
export interface AdminAuditLogResponse {
  entries: AdminAuditEntry[];
  total: number;
}

/**
 * `GET /api/admin/config` (`require_role("admin")`) — a CURATED SAFE SUBSET of
 * runtime config (thresholds, poll interval, grouping window, notification flag);
 * never secrets. The value types vary, so it is a permissive record rendered as
 * key/value pairs. READ-ONLY — there is no config-write endpoint.
 */
export interface AdminConfigResponse {
  config: Record<string, unknown>;
}

/**
 * `GET /api/admin/governance/charter` (`verify_jwt`) — the parsed SOC-charter
 * YAML (or null when none is configured). Displayed as read-only institutional
 * knowledge; the structure is open, so it is a permissive record.
 */
export interface AdminGovernanceCharterResponse {
  charter: Record<string, unknown> | null;
  message?: string | null;
}

/**
 * `GET /api/admin/governance/data-access` (`admin` OR `senior_analyst`) — the raw
 * data-access-policy YAML root dict returned DIRECTLY (no wrapper key). Read-only.
 */
export type AdminDataAccessPolicy = Record<string, unknown>;

/**
 * One anonymization mapping (`GET /api/admin/anon-mappings`, `require_role("admin")`).
 * The admin-only token↔real-value map DHRUVA uses to resolve anonymized LLM
 * output back to real identifiers. This is deliberately admin-gated: the
 * anonymization boundary protects the LLM call, not an authenticated admin who
 * already has tenant data access. READ-ONLY.
 */
export interface AdminAnonMapping {
  token: string;
  original_value?: string | null;
  field_type?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
  hit_count?: number | null;
  client_id?: string | null;
  [k: string]: unknown;
}

/** `GET /api/admin/anon-mappings` envelope. */
export interface AdminAnonMappingsResponse {
  mappings: AdminAnonMapping[];
  total: number;
}

/** One uncovered technique in a tactic's gap list (`GET /api/mitre/gaps`). */
export interface MitreGapTechnique {
  id: string;
  name: string;
}

/**
 * `GET /api/mitre/gaps` (optional drill-down) — techniques with ZERO detections,
 * grouped by tactic NAME. Backs the per-tactic "which techniques are uncovered"
 * dialog. `coverage_pct` here is technique-level (1 − gaps/total).
 */
export interface MitreGaps {
  gaps: Record<string, MitreGapTechnique[]>;
  total_gaps: number;
  total_techniques?: number;
  coverage_pct: number;
}

// ---- SOAR (WO-U9b) — SOAR tab (READ-ONLY) -----------------------------------
/**
 * One SOAR playbook row (`GET /api/soar/playbooks`, `store.py::get_soar_playbooks`,
 * `SELECT *` from `soar_playbooks`). The trigger columns + `actions` /
 * `rollback_actions` arrive as JSON-encoded TEXT (parse with `parseJsonArray`);
 * `enabled` / `require_approval` / `trigger_ti_required` are int 0/1 flags.
 * READ-ONLY: enable/disable (toggle) is admin-only and NOT wired here.
 */
export interface SoarPlaybook {
  id: string;
  name: string;
  display_name?: string | null;
  description?: string | null;
  /** int 0/1 in Postgres — coerce for display */
  enabled?: number | boolean | null;
  /** JSON-encoded array of trigger verdicts */
  trigger_verdicts?: string | string[] | null;
  trigger_min_confidence?: number | null;
  trigger_min_risk_score?: number | null;
  trigger_mitre_techniques?: string | string[] | null;
  trigger_rule_groups?: string | string[] | null;
  trigger_ti_required?: number | boolean | null;
  /** JSON-encoded array of action steps (count via parseJsonArray) */
  actions?: string | unknown[] | null;
  rollback_actions?: string | unknown[] | null;
  require_approval?: number | boolean | null;
  cooldown_minutes?: number | null;
  max_executions_per_hour?: number | null;
  priority?: number | null;
  created_at?: string | null;
  updated_at?: string | null;
}

/** `GET /api/soar/playbooks` envelope. */
export interface SoarPlaybooksResponse {
  playbooks: SoarPlaybook[];
}

/** SOAR execution lifecycle status (`soar_executions.status`). */
export type SoarExecutionStatus =
  | "pending_approval"
  | "completed"
  | "partial"
  | "failed"
  | "cancelled"
  | string;

/**
 * One SOAR execution row (`GET /api/soar/executions`, `store.py::get_soar_executions`,
 * `SELECT *` from `soar_executions`). `playbook_name` is denormalized onto the
 * row. Progress is `current_step` / `total_steps`; there is NO `result`/`error`
 * column — the failure detail is `error_message`. READ-ONLY: approve/reject/
 * rollback are a later gated WO and NOT wired here.
 */
export interface SoarExecution {
  id: string;
  playbook_id: string;
  playbook_name?: string | null;
  incident_id?: string | null;
  decision_id?: string | null;
  status: SoarExecutionStatus;
  trigger_data?: string | Record<string, unknown> | null;
  actions_planned?: string | unknown[] | null;
  actions_completed?: string | unknown[] | null;
  current_step?: number | null;
  total_steps?: number | null;
  approved_by?: string | null;
  approved_at?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
  error_message?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
}

/** `GET /api/soar/executions` envelope. */
export interface SoarExecutionsResponse {
  executions: SoarExecution[];
}

/** `GET /api/soar/stats` (`store.py::get_soar_stats`). `success_rate` is a 0..100 %. */
export interface SoarStats {
  total_playbooks: number;
  active_playbooks: number;
  pending_approvals: number;
  executions_today: number;
  /** 0..100 percentage of completed vs (completed+partial+failed) over 30d */
  success_rate: number;
}

// ---- Active Response queue + audit (WO-U9b) — Respond tab (READ-ONLY) --------
/** Active-response dispatch mode. `auto` = a blessed auto-block policy fired. */
export type ArMode = "auto" | "manual" | string;

/**
 * Active-response action status (`active_response_audit.status`). `pending_approval`
 * is a proposed/queued action that has NOT been dispatched; `executed` is a live
 * action (a block is active until reversed/expired).
 */
export type ArStatus =
  | "executed"
  | "pending_approval"
  | "denied"
  | "reversed"
  | "expired"
  | string;

/**
 * One active-response audit row (`store.py::get_ar_audit`, `SELECT *` from
 * `active_response_audit`) — served by BOTH `GET /api/response/queue`
 * (active-only: pending/executed, not reversed) and `GET /api/response/audit`
 * (the full trail). `ti_evidence` / `gate_snapshot` are JSON blobs (the auto-path
 * evidence + the gate floors at decision time). READ-ONLY: this view never
 * proposes/approves/executes/reverses — those are human-gated senior_analyst+
 * writes delivered in a dedicated later WO.
 */
export interface ArAction {
  id: string;
  mode: ArMode;
  action: string;
  status: ArStatus;
  actor: string;
  target_ip?: string | null;
  agent_id?: string | null;
  alert_id?: string | null;
  decision_id?: string | null;
  incident_id?: string | null;
  ti_evidence?: string | Record<string, unknown> | null;
  gate_snapshot?: string | Record<string, unknown> | null;
  reason?: string | null;
  ttl_seconds?: number | null;
  expires_at?: string | null;
  reversed_at?: string | null;
  reversed_by?: string | null;
  created_at?: string | null;
}

/** `GET /api/response/queue` envelope (active/pending only). */
export interface ResponseQueueResponse {
  queue: ArAction[];
  total: number;
}

/** `GET /api/response/audit` envelope (full trail). */
export interface ResponseAuditResponse {
  audit: ArAction[];
  total: number;
}

// ---- Tickets (WO-U9b) — Tickets tab (READ-ONLY) -----------------------------
/** Ticket sync status on the DHRUVA side (`tickets.platform_status`). */
export type TicketPlatformStatus =
  | "pending"
  | "created"
  | "synced"
  | "error"
  | "closed"
  | string;

/**
 * One ticket row (`GET /api/tickets`, `store.py::get_tickets`, `SELECT *` from
 * `tickets`). `platform_status` is DHRUVA's view of the sync; `external_status`
 * is the provider's own status string. READ-ONLY: create/sync/retry are gated
 * writes (analyst+/senior_analyst+) NOT wired here.
 */
export interface Ticket {
  id: string;
  incident_id: string;
  provider: string;
  external_id?: string | null;
  external_url?: string | null;
  external_status?: string | null;
  platform_status: TicketPlatformStatus;
  summary: string;
  description?: string | null;
  priority?: string | null;
  assigned_to_external?: string | null;
  sync_direction?: string | null;
  last_synced_at?: string | null;
  sync_error?: string | null;
  retry_count?: number | null;
  created_by?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
}

/** `GET /api/tickets` envelope. */
export interface TicketsResponse {
  tickets: Ticket[];
  total: number;
}

/** `GET /api/tickets/stats` (`store.py::get_ticket_stats`). */
export interface TicketStats {
  total: number;
  synced: number;
  pending: number;
  errors: number;
  closed: number;
  by_provider: Record<string, number>;
}

// ---- Agent Groups (WO-U9b) — Agent Groups tab (READ-ONLY, mssp_admin) --------
/**
 * One Wazuh agent group (`GET /api/groups`, `wazuh_client.get_agent_groups` —
 * a raw Wazuh 4.x `GET /groups` `affected_items` passthrough). `name` + `count`
 * are the reliably-present keys; `mergedSum` / `configSum` are the standard 4.x
 * checksums. mssp_admin-only + `host_integrity` license (Manager-global list).
 */
export interface AgentGroup {
  name: string;
  count?: number | null;
  mergedSum?: string | null;
  configSum?: string | null;
  [k: string]: unknown;
}

/** `GET /api/groups` envelope. */
export interface GroupsResponse {
  groups: AgentGroup[];
  total: number;
}

// ---- Hunt (WO-U9c) — Hunt tab (READ-ONLY) -----------------------------------
/**
 * One threat-hunt finding (`GET /api/hunt/findings`, `store.py::get_hunt_findings`
 * = raw `hunt_findings` row). `confirmed` is an int 0/1 (Postgres), NOT a bool.
 * `result_count` is the OpenSearch hit count the hypothesis matched. READ-ONLY —
 * confirm/dismiss (`POST /api/hunt/review`) is a senior_analyst+ gated write NOT
 * wired here.
 */
export interface HuntFinding {
  id: string;
  hunt_cycle_id: string;
  hypothesis: string;
  mitre_technique: string | null;
  /** "critical" | "high" | "medium" | "low" (default "medium") */
  priority: string;
  query_index: string | null;
  query_body: string | null;
  result_count: number;
  results_summary: string | null;
  /** "open" | "confirmed" | "dismissed" | … */
  status: string;
  /** int 0/1 — whether an analyst confirmed the finding is a real threat */
  confirmed: number;
  analyst_notes: string | null;
  created_at: string;
  reviewed_at: string | null;
}

/** `GET /api/hunt/findings` envelope. */
export interface HuntFindingsResponse {
  findings: HuntFinding[];
  total: number;
}

/**
 * One saved hunt hypothesis (`GET /api/hunt/library`) — a re-runnable query the
 * hunt agent has accumulated. `success_count` is how many times it surfaced a
 * finding; `tags` is a real array (already parsed server-side). Replay (POST) is
 * NOT wired here (read-only view).
 */
export interface HuntHypothesis {
  id: string;
  hypothesis: string;
  mitre_technique: string | null;
  query_index: string | null;
  success_count: number;
  last_success_at: string | null;
  tags: string[];
  created_at: string;
}

/** `GET /api/hunt/library` envelope. */
export interface HuntLibraryResponse {
  hypotheses: HuntHypothesis[];
  total: number;
}

// ---- Closed Loop / Feedback (WO-U9c) — feedback tab (READ-ONLY) -------------
/**
 * One mined feedback pattern (`GET /api/feedback/patterns`,
 * `store.py::get_active_patterns` = raw `feedback_patterns` row). These are the
 * recurring FP / noisy-rule signals the closed loop has learned; they feed the
 * Detection agent's tuning proposals (reviewed on the Detection tab). READ-ONLY.
 */
export interface FeedbackPattern {
  id: string;
  /** e.g. "recurring_fp" | "noisy_rule" | … */
  pattern_type: string;
  rule_id: number;
  description: string | null;
  occurrence_count: number;
  first_seen: string;
  last_seen: string;
  /** the action the loop auto-took (or null if none yet) */
  auto_action_taken: string | null;
  status: string;
  client_id?: string | null;
}

/** `GET /api/feedback/patterns` envelope. */
export interface FeedbackPatternsResponse {
  patterns: FeedbackPattern[];
  total: number;
}

/**
 * One deployed-proposal effectiveness row (`GET /api/feedback/effectiveness`,
 * `FeedbackEngine.track_proposal_effectiveness` — returns a BARE LIST, not an
 * envelope). Compares pre/post-deployment FP & TP rates for a tuned rule.
 * `effective` is `null` when there is not yet enough post-deployment data
 * (< 5 decisions) — surfaced honestly as "not enough data yet", never guessed.
 * Rates are 0..1 fractions.
 */
export interface ProposalEffectiveness {
  rule_id: number;
  proposal_id: string;
  deployed_at: string;
  pre_fp_count: number | null;
  pre_tp_rate: number;
  post_total_decisions: number;
  post_fp_count: number;
  post_tp_count: number;
  post_fp_rate: number;
  post_tp_rate: number;
  effective: boolean | null;
}

// ---- Knowledge Base (WO-U9c) — knowledge tab (READ-ONLY) --------------------
/**
 * One KB document (`GET /api/kb/documents`, `store.py::get_kb_documents` = raw
 * `kb_documents` row). `tags` and `mitre_techniques` arrive as JSON-encoded TEXT
 * (e.g. `"[]"`) — parse defensively (see `knowledge.ts::parseKbList`). The
 * `search_tsv` tsvector column may be present over the wire; it is ignored.
 * READ-ONLY — create/edit/delete are gated writes NOT wired here.
 */
export interface KbDocument {
  id: string;
  doc_type: string;
  title: string;
  content: string;
  /** JSON-encoded string OR array of tag strings */
  tags?: string | string[] | null;
  /** JSON-encoded string OR array of ATT&CK technique ids */
  mitre_techniques?: string | string[] | null;
  source_id?: string | null;
  source_type?: string | null;
  created_by?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  client_id?: string | null;
  [k: string]: unknown;
}

/** `GET /api/kb/documents` envelope. */
export interface KbDocumentsResponse {
  documents: KbDocument[];
  total: number;
}

/** A KB search hit = a `KbDocument` plus a `ts_rank` relevance score. */
export interface KbSearchResult extends KbDocument {
  rank?: number;
}

/** `GET /api/kb/search?q=` envelope. */
export interface KbSearchResponse {
  results: KbSearchResult[];
  total: number;
  query: string;
}

/** `GET /api/kb/stats` (`store.py::get_kb_stats`). */
export interface KbStats {
  total: number;
  by_type: Record<string, number>;
}

// =============================================================================
// Active-response LIFECYCLE writes (Respond tab) — approve / reverse
// -----------------------------------------------------------------------------
// Response bodies for the HUMAN-GATED active-response transitions the Respond
// tab wires (`POST /api/response/approve/{id}`, `/reverse/{id}`). Server
// contract: src/api/routes/response.py. Both are senior_analyst+
// (`require_role("senior_analyst","admin","mssp_admin")`). The UI NEVER
// auto-invokes these — each is behind an explicit human confirm. There is NO
// separate "execute an already-approved action" endpoint: `/approve/{id}`
// APPROVES **and dispatches** in one server call (approve == execute-on-
// approval). The standalone `POST /api/response/execute` is the un-queued,
// free-form direct path (legacy AR cards) and is deliberately NOT surfaced here.
// =============================================================================

/**
 * `POST /api/response/approve/{action_id}` response. Approving a `pending_approval`
 * proposal ALSO dispatches it to Wazuh immediately (there is no approved-but-not-
 * executed state). `status` is "executed" on success, "failed" if the dispatch
 * failed; `audit` is "ok" or "degraded" (the action ran but its audit-row write
 * failed — the trail may be incomplete). `success`/`error` come from the Wazuh
 * dispatch result.
 */
export interface ApproveResponseActionResult {
  id: string | null;
  proposal_id: string;
  action: string;
  /** "executed" (dispatched) | "failed" (dispatch failed) */
  status: string;
  /** "ok" | "degraded" (action ran, audit-row write failed) */
  audit?: string;
  success?: boolean;
  error?: string;
}

/**
 * `POST /api/response/reverse/{action_id}` response. Reverses (unblocks) an active
 * `block_ip`. The server 409s unless the row is an executed `block_ip`, so the UI
 * only offers Reverse for those rows. `status` is "reversed" on success, "failed"
 * otherwise.
 */
export interface ReverseResponseActionResult {
  id: string;
  action: string;
  /** "reversed" | "failed" */
  status: string;
  success?: boolean;
  error?: string;
}

// =============================================================================
// Detection engineering WRITES (DetectionTab) — response shapes.
// Appended (Detection section) to avoid touching the shared import block while
// sibling agents edit this file. Mirrors src/api/routes/detection.py exactly.
// =============================================================================

/**
 * `POST /api/detection/review` response — approve/reject a proposal (a proposal
 * lifecycle transition; NOT a live Wazuh change). Server:
 * `{status:"ok", proposal_id, action}`. `action` is "approve" | "reject".
 */
export interface DetectionReviewResult {
  status: string;
  proposal_id: string;
  action: string;
}

/**
 * `POST /api/detection/deploy/{id}` response — deploys an APPROVED proposal to
 * the SHARED Wazuh backend (restarts the manager). mssp_admin only.
 * Server on success: `{status:"deployed", proposal_id}`. Failure → HTTP 400.
 */
export interface DetectionDeployResult {
  status: string;
  proposal_id: string;
}

/**
 * `POST /api/detection/rollback/{id}` response — rolls a DEPLOYED rule back to
 * its original XML (restarts the manager). mssp_admin only. Server:
 * `{status:"rolled_back", ...result}` — the extra keys vary by backend version,
 * so they're carried loosely. Failure → HTTP 400.
 */
export interface DetectionRollbackResult {
  status: string;
  proposal_id?: string;
  [key: string]: unknown;
}

/**
 * `POST /api/detection/validate` response — a read-only dry-run of rule XML
 * against wazuh-logtest (changes NOTHING live). admin+ only.
 * Server: `{valid, error}` (`error` is null when valid).
 */
export interface DetectionValidateResult {
  valid: boolean;
  error: string | null;
}

// =============================================================================
// Admin WRITE actions (AdminTab) — request bodies + response shapes.
// Appended (Admin section) to avoid touching the shared import block while
// sibling agents edit this file. Mirrors src/api/models.py + routes/admin.py +
// the guidance-reload in routes/health.py EXACTLY. No password/secret is ever
// returned by the server; these types never carry one back.
// =============================================================================

// ---- Users (POST /api/admin/users, POST /api/admin/users/{id}) --------------
/**
 * `CreateUserRequest` — the admin TYPES the initial password (server rules: ≥12
 * chars, upper+lower+digit+special). The server hashes it and returns ONLY
 * `{status,user_id,username}` — never the password. `role` is validated against
 * the actor's assignable set (`assignableRoles`).
 */
export interface CreateUserBody {
  username: string;
  password: string;
  display_name?: string;
  email?: string;
  role: string;
}
export interface CreateUserResult {
  status: string;
  user_id: string;
  username: string;
}

/**
 * `UpdateUserRequest` — every field optional; only provided fields change.
 * `password` (when present) is a reset — server-validated + hashed, never echoed
 * back. `is_active:false` is the ONLY "delete" (there is no hard-delete endpoint).
 */
export interface UpdateUserBody {
  display_name?: string;
  email?: string;
  role?: string;
  password?: string;
  is_active?: boolean;
}
export interface UpdateUserResult {
  status: string;
  user_id: string;
}

// ---- Tenants (mssp_admin only) ----------------------------------------------
/** `CreateTenantRequest` — name + slug + optional config. The UI sends only
 * name/slug (no secret config) to avoid credential handling; secrets are
 * configured out-of-band. */
export interface CreateTenantBody {
  name: string;
  slug: string;
  config?: Record<string, unknown>;
}
export interface CreateTenantResult {
  status: string;
  tenant_id: string;
  name: string;
  slug: string;
}
/** `PUT /api/admin/tenants/{id}` raw-JSON body — the UI only sends name/active
 * (rename + activate/deactivate). It never sends `config` (secret-bearing). */
export interface UpdateTenantBody {
  name?: string;
  active?: boolean;
}
export interface TenantWriteResult {
  status: string;
  tenant_id: string;
}

/** One tenant→Wazuh-agent mapping row (`GET /api/admin/tenants/{id}/agents`). */
export interface TenantAgentRow {
  agent_id: string;
  added_at?: string | null;
}
export interface TenantAgentsResponse {
  tenant_id: string;
  agents: TenantAgentRow[];
  total: number;
}
export interface AssignTenantAgentsResult {
  status: string;
  tenant_id: string;
  assigned: string[];
  conflicts?: string[];
  message?: string;
}
export interface RemoveTenantAgentResult {
  status: string;
  tenant_id: string;
  removed: string;
}

// ---- Settings: assets / identities / local-IOCs (admin+) --------------------
/** `GET /api/admin/settings/assets` row (SELECT * — permissive). */
export interface AdminAsset {
  id: string;
  hostname: string;
  tier?: string;
  owner?: string;
  environment?: string;
  criticality_multiplier?: number;
  tags?: string[];
  services?: string[];
  created_at?: string | null;
  updated_at?: string | null;
  [k: string]: unknown;
}
export interface AdminAssetsResponse {
  assets: AdminAsset[];
}
export interface CreateAssetBody {
  hostname: string;
  tier?: string;
  owner?: string;
  environment?: string;
  criticality_multiplier?: number;
  tags?: string[];
  services?: string[];
}
export interface UpdateAssetBody {
  tier?: string;
  owner?: string;
  environment?: string;
  criticality_multiplier?: number;
  tags?: string[];
  services?: string[];
}

/** `GET /api/admin/settings/identities` row. */
export interface AdminIdentity {
  id: string;
  username: string;
  risk_level?: string;
  risk_multiplier?: number;
  is_admin?: boolean;
  is_service_account?: boolean;
  roles?: string[];
  known_ips?: string[];
  department?: string;
  onboarded_date?: string | null;
  [k: string]: unknown;
}
export interface AdminIdentitiesResponse {
  identities: AdminIdentity[];
}
export interface CreateIdentityBody {
  username: string;
  risk_level?: string;
  risk_multiplier?: number;
  is_admin?: boolean;
  is_service_account?: boolean;
  roles?: string[];
  department?: string;
  known_ips?: string[];
}
export interface UpdateIdentityBody {
  risk_level?: string;
  risk_multiplier?: number;
  is_admin?: boolean;
  is_service_account?: boolean;
  roles?: string[];
  department?: string;
  known_ips?: string[];
}

/** `GET /api/admin/settings/local-iocs` row. Create + delete only (no update). */
export interface AdminLocalIoc {
  id: string;
  ioc_type: string;
  value: string;
  severity?: string;
  description?: string;
  updated_at?: string | null;
  [k: string]: unknown;
}
export interface AdminLocalIocsResponse {
  iocs: AdminLocalIoc[];
}
export interface CreateLocalIocBody {
  ioc_type: string;
  value: string;
  severity?: string;
  description?: string;
}

/** Generic `{status:"created"|"updated"|"deleted", ...}` from the settings CRUD. */
export interface SettingsWriteResult {
  status: string;
  asset_id?: string;
  identity_id?: string;
  ioc_id?: string;
}

// ---- Reload triggers + shift handoff ----------------------------------------
/** `POST /api/admin/settings/reload-enrichers` → `{status:"ok", ...counts}`. */
export interface ReloadEnrichersResult {
  status: string;
  [k: string]: unknown;
}
/** `POST /api/guidance/reload` → `{status, message}`. */
export interface GuidanceReloadResult {
  status: string;
  message?: string;
}
/** `HandoffRequest` — shift_from/shift_to are both required, 1-100 chars. */
export interface HandoffBody {
  shift_from: string;
  shift_to: string;
}
export interface HandoffResult {
  status: string;
  handoff_id: string | number;
}

// =============================================================================
// Tickets / SOAR / Closed-loop WRITE bodies + results (Tickets/SOAR/ClosedLoop)
// -----------------------------------------------------------------------------
// Request/response shapes for the write clients appended to api.ts. Mirrors the
// server Pydantic models + route return shapes (src/api/routes/tickets.py,
// soar.py, feedback.py). Kept in one clearly-delimited EOF block per the shared
// -file append convention.
// =============================================================================

/**
 * `POST /api/tickets` body (`CreateTicketRequest`). `incident_id` is REQUIRED;
 * `provider` (when set) must be one of jira|servicenow|pagerduty (server 422s
 * otherwise); `summary` overrides the auto-generated summary.
 */
export interface CreateTicketBody {
  incident_id: string;
  provider?: string;
  summary?: string;
}

/**
 * Return shape shared by create/sync/retry (`{status:"ok", ...result}`). The
 * spread result is provider-dependent; the reliably-present keys are typed and
 * the rest left open. `ticket_id`/`external_id` appear on create/retry.
 */
export interface TicketWriteResult {
  status: string;
  ticket_id?: string;
  external_id?: string | null;
  external_url?: string | null;
  external_status?: string | null;
  incident_id?: string;
  error?: string;
  [k: string]: unknown;
}

/** `POST /api/soar/playbooks/{id}/toggle` → the NEW enabled state. */
export interface SoarToggleResult {
  status: string;
  playbook_id: string;
  enabled: boolean;
}

/**
 * Shared return shape for approve/reject/rollback of a SOAR execution
 * (`{status:"ok", execution_id, approved_by|rejected_by|rolled_back_by}`).
 */
export interface SoarExecutionActionResult {
  status: string;
  execution_id: string;
  approved_by?: string;
  rejected_by?: string;
  rolled_back_by?: string;
}

/** `POST /api/feedback/run-cycle` → `{status:"accepted", message}` (background). */
export interface FeedbackRunCycleResult {
  status: string;
  message?: string;
}

/**
 * `POST /api/threat-intel/collect` → triggers a TI collection cycle in a
 * background thread. Server returns `{status:"collection_started"}` on success,
 * or `{status:"error", message}` if the collector is not initialized. Auth:
 * `require_role("admin","senior_analyst")` + `require_license_feature(
 * "ti_feeds_tier1")`, rate-limited 2/min (a 429 is surfaced typed by the tab).
 */
export interface TICollectResult {
  status: string;
  message?: string;
}

// =============================================================================
// Hunt WRITES (Hunt tab) — run cycle / review finding / replay hypothesis
// -----------------------------------------------------------------------------
// Request/response shapes for the three hunt writes wired on the Hunt tab. Server
// contract: src/api/routes/hunt.py (+ models.py::HuntReviewRequest). RBAC is
// mirrored in rbac.ts::huntActionGate; the server remains the enforcement point.
// =============================================================================
/** The two review actions the server accepts (`ALLOWED_HUNT_STATUSES`). */
export type HuntReviewStatus = "confirmed" | "dismissed";

/**
 * `POST /api/hunt/review` body (`HuntReviewRequest`). `confirmed` is the boolean
 * the server keys the auto-incident/KB-index side effect on; `status` is the
 * plain-language transition. `notes` is OPTIONAL (no server-side reason gate).
 * Callers set `confirmed: true` only for `status: "confirmed"`.
 */
export interface HuntReviewBody {
  finding_id: string;
  status: HuntReviewStatus;
  confirmed: boolean;
  notes?: string;
}

/** `POST /api/hunt/review` → `{status, finding_id, action}`. */
export interface HuntReviewResult {
  status: string;
  finding_id: string;
  action: string;
}

/** `POST /api/hunt/run` → `{status:"accepted", message}` (background cycle). */
export interface HuntRunResult {
  status: string;
  message?: string;
}

/**
 * `POST /api/hunt/library/{id}/replay` → the re-executed query's result. This is
 * a READ-ish action (mutates nothing): the server re-runs the stored, key-
 * validated OpenSearch query tenant-scoped and returns the hit count plus up to
 * 10 sample event `_source` bodies. `sample_hits` are REAL alert documents (the
 * analyst UI shows real host/IP/user — the anonymization boundary is the LLM,
 * not this surface), typed loosely as they are raw OpenSearch docs.
 */
export interface HuntReplayResult {
  hypothesis: string;
  query_index: string | null;
  hit_count: number;
  sample_hits: Record<string, unknown>[];
}

// =============================================================================
// Knowledge-base WRITES (Knowledge tab) — create / edit / delete a document
// -----------------------------------------------------------------------------
// Request/response shapes for the three KB writes wired on the Knowledge tab.
// Server contract: src/api/routes/knowledge_base.py (+ knowledge_base/service.py::
// ALLOWED_DOC_TYPES). RBAC (create=analyst+, edit/delete=senior_analyst+) is
// mirrored in rbac.ts::knowledgeActionGate; the server remains the enforcement
// point. `created_by` is set server-side from the JWT `sub` — never sent by the
// client. No reason required on any of these.
// =============================================================================
/**
 * The human-authored KB doc types the create form offers. The server's
 * `ALLOWED_DOC_TYPES` also includes system-generated types (hunt_finding,
 * feedback_pattern, incident_learning, guidance) that the platform self-indexes —
 * the UI offers only the two an analyst authors by hand, matching legacy.
 */
export type KbAuthorableDocType = "analyst_note" | "investigation_pattern";

/**
 * `POST /api/kb/documents` body. `title` + `content` are REQUIRED server-side
 * (400 otherwise); the form disables submit until both are present so it never
 * fires a request the server rejects. `tags` / `mitre_techniques` are real
 * arrays (the client parses the comma-separated inputs before sending).
 */
export interface KbCreateBody {
  title: string;
  content: string;
  doc_type: KbAuthorableDocType;
  tags?: string[];
  mitre_techniques?: string[];
}

/** `POST /api/kb/documents` → `{status, document}`. */
export interface KbCreateResult {
  status: string;
  document: KbDocument;
}

/**
 * `PUT /api/kb/documents/{id}` body — only the mutable fields. `doc_type` is NOT
 * editable server-side (the endpoint ignores it), so the edit form shows it
 * read-only. At least one field must be present (400 otherwise).
 */
export interface KbUpdateBody {
  title?: string;
  content?: string;
  tags?: string[];
  mitre_techniques?: string[];
}

/** `POST(PUT)/DELETE /api/kb/documents/{id}` → `{status, document_id}`. */
export interface KbWriteResult {
  status: string;
  document_id: string;
}

// ============================================================================
// Parity-restore read-views (mirrors legacy sub-tabs the redesign dropped).
// All READ-ONLY. Each type mirrors the real backend response EXACTLY; RBAC/tier
// gates are enforced server-side and mirrored (never widened) client-side.
// ============================================================================

// ---- Admin → Pipeline Health (mssp_admin + pipeline_health license) ---------
// GET /api/health/pipeline. The monitor returns only {heartbeat, eps, parser};
// the route MERGES automation_health and may return {status:"unavailable",
// message} when the monitor is not initialised. Each sub-status is POLYMORPHIC
// (a normal shape, a status-variant, or {error}), so every field is optional.
export interface PipelineHeartbeat {
  checked_at?: string;
  window_minutes?: number;
  known_active_agents?: number;
  reporting_agents?: number;
  silent_agents?: number;
  silent_agent_names?: string[];
  error?: string;
}
export interface PipelineEps {
  checked_at?: string;
  status?: string; // "insufficient_data"
  bucket_count?: number;
  mean_events_per_minute?: number;
  std_dev?: number;
  recent_5min_avg?: number;
  z_score?: number;
  is_anomaly?: boolean;
  threshold?: number;
  error?: string;
}
export interface PipelineParser {
  checked_at?: string;
  status?: string; // "no_events"
  total_events_1h?: number;
  unparsed_events_1h?: number;
  failure_rate?: number; // 0-1
  threshold?: number;
  is_above_threshold?: boolean;
  error?: string;
}
export interface PipelineAutomationLatency {
  sample_count?: number;
  p50_ms?: number;
  p95_ms?: number | null;
  p99_ms?: number | null;
  avg_ms?: number;
}
export interface PipelineAutomationSoar {
  total_actions?: number;
  success_count?: number;
  failure_count?: number;
  success_rate?: number; // 0-100 (NOTE: different scale from LLM success_rate)
}
export interface PipelineAutomationHealth {
  period_days?: number;
  enrichment_latency?: PipelineAutomationLatency;
  soar_actions?: PipelineAutomationSoar;
}
export interface PipelineHealth {
  status?: string; // "unavailable"
  message?: string;
  heartbeat?: PipelineHeartbeat;
  eps?: PipelineEps;
  parser?: PipelineParser;
  automation_health?: PipelineAutomationHealth;
}
// GET /api/health/log-sources → { sources } (or { sources: [], message|error }).
export interface LogSource {
  name: string;
  type?: string;
  description?: string;
  collection_method?: string;
  volume_eps_estimate?: number;
  retention_days?: number;
  reliability?: string;
  parser?: string;
  notes?: string;
  status?: string; // "silent" | "reporting" (stamped at runtime)
}
export interface LogSourcesResponse {
  sources: LogSource[];
  message?: string;
  error?: string;
}

// ---- Reports → LLM Usage (verify_jwt + own-tenant; NO license gate) ---------
// The route reshapes the analyzer dataclass: *_breakdown → breakdowns.{...} and
// adds summary.total_tokens. success_rate is a 0-1 fraction here.
export interface LlmBreakdownEntry {
  requests?: number;
  tokens_input?: number;
  tokens_output?: number;
  cost_usd?: number;
  avg_latency_ms?: number;
  success_rate?: number; // 0-1
}
export interface LlmUsageReport {
  tenant_id: string;
  period: { start?: string; end?: string; days?: number };
  summary: {
    total_requests?: number;
    total_tokens_input?: number;
    total_tokens_output?: number;
    total_tokens?: number;
    total_cost_usd?: number;
    avg_latency_ms?: number;
    success_rate?: number; // 0-1
  };
  breakdowns: {
    providers?: Record<string, LlmBreakdownEntry>;
    models?: Record<string, LlmBreakdownEntry>;
    request_types?: Record<string, LlmBreakdownEntry>;
  };
}
export interface LlmUsageReportResponse {
  success: boolean;
  report: LlmUsageReport;
}
export interface LlmBudgetAlert {
  type?: string;
  severity: string; // "critical" | "warning" | "info"
  message: string;
  budget_utilization?: number; // ratio
  current_spend?: number;
  monthly_budget?: number;
}
export interface LlmBudgetAlertsResponse {
  success: boolean;
  tenant_id: string;
  alerts: LlmBudgetAlert[];
  alert_count: number;
  has_critical: boolean;
}
export interface LlmCostTrendPoint {
  date: string; // YYYY-MM-DD
  cost?: number;
  requests?: number;
  tokens?: number;
}
export interface LlmCostTrends {
  tenant_id?: string;
  period_days?: number;
  daily_trends: LlmCostTrendPoint[];
  total_cost?: number;
  avg_daily_cost?: number;
}
export interface LlmCostTrendsResponse {
  success: boolean;
  trends: LlmCostTrends;
}
export interface LlmOptimizationSuggestion {
  type?: string;
  priority?: string; // "high" | "medium"
  description?: string;
  // provider_cost_optimization
  current_expensive_provider?: string;
  suggested_provider?: string;
  potential_savings?: number;
  // model_optimization
  expensive_model?: string;
  cheaper_alternative?: string;
  // reliability_cost_issue
  provider?: string;
  success_rate?: number; // 0-1
  cost?: number;
}
export interface LlmOptimizationResponse {
  success: boolean;
  tenant_id: string;
  suggestions: LlmOptimizationSuggestion[];
  analysis_period_days: number;
  suggestion_count: number;
  high_priority_count: number;
}

// ---- Reports → Threat-Intel strategic report --------------------------------
// GET /api/threat-intel/strategic-report?days= — require_role("admin",
// "senior_analyst") + require_license_feature("ti_feeds_tier2"). FLAT (not
// wrapped in {report}). alert_verdicts has dynamic verdict keys.
export interface TiStrategicIocSource {
  source: string;
  total?: number;
  critical?: number;
  high?: number;
}
export interface TiStrategicTechnique {
  id: string;
  name?: string;
  detections?: number;
  true_positives?: number;
}
export interface TiStrategicTrend {
  source?: string;
  ioc_type?: string;
  severity?: string;
  count?: number;
  period_days?: number;
}
export interface TiStrategicReport {
  generated_at?: string;
  period_days?: number;
  industry?: string;
  ioc_sources: TiStrategicIocSource[];
  alert_verdicts: Record<string, number>;
  top_mitre_techniques: TiStrategicTechnique[];
  trending_threats: TiStrategicTrend[];
}

// ---- Detection → Deployment History + Rule Versions -------------------------
// GET /api/detection/history + /history/{rule_file}/versions —
// require_role("admin","senior_analyst") + require_license_feature("detection").
// The /history endpoint returns full rows (incl. XML); /versions strips XML to
// has_xml_before.
export interface DeploymentHistoryEntry {
  id?: string;
  proposal_id?: string;
  rule_id?: number;
  rule_file?: string;
  version?: number;
  xml_before?: string | null;
  xml_after?: string | null;
  deployed_by?: string | null;
  deployed_at?: string;
  rolled_back_at?: string | null;
  client_id?: string | null;
}
export interface DeploymentHistoryResponse {
  history: DeploymentHistoryEntry[];
  count: number;
}
export interface RuleVersion {
  version: number;
  proposal_id?: string;
  rule_id?: number;
  deployed_by?: string | null;
  deployed_at?: string;
  rolled_back_at?: string | null;
  has_xml_before?: boolean;
}
export interface RuleVersionsResponse {
  rule_file: string;
  versions: RuleVersion[];
}

// ===== [frontend-integrator — parity gap ① restored read-only subviews] ======
// Append-only block. Backs: Threat Intel IOC lookup, MITRE technique heatmap +
// per-technique detail. (SOAR execution board reuses the existing SoarExecution
// type — no new type needed.) Shapes verified against the live routes:
//   - GET /api/threat-intel/ioc/{ioc_value}  (threat_intel.py::lookup_ioc)
//   - GET /api/mitre/coverage                (mitre.py::get_coverage → get_heatmap_data)

/**
 * One local-IOC match from `GET /api/threat-intel/ioc/{ioc_value}` — a full
 * `threat_intel_iocs` row (`store.py::lookup_ioc`, `SELECT * … is_active=1 ORDER
 * BY confidence DESC`). Every field optional/defensive: the row is rendered as-is
 * and never reshaped. `tags` arrives as a JSON-encoded TEXT string (parse
 * defensively). This looks up THREAT indicators — it is NOT the anonymization
 * token reverse-lookup (that boundary is preserved elsewhere and unwired).
 */
export interface IocMatch {
  ioc_value?: string | null;
  ioc_type?: string | null;
  source?: string | null;
  severity?: string | null;
  confidence?: number | null;
  first_seen?: string | null;
  last_seen?: string | null;
  description?: string | null;
  /** JSON-encoded array TEXT (e.g. '["c2","apt29"]') — parse with parseJsonArray */
  tags?: string | string[] | null;
  is_active?: number | boolean | null;
}

/** `GET /api/threat-intel/ioc/{ioc_value}` envelope (built inline server-side). */
export interface IocLookupResponse {
  ioc_value: string;
  matches: IocMatch[];
  total: number;
}

/** Per-technique detection status (`coverage_status` in `mitre_coverage`). */
export type MitreTechniqueStatus =
  | "active"
  | "noisy"
  | "stale"
  | "not_detected"
  | string;

/**
 * One technique cell in the ATT&CK heatmap (`GET /api/mitre/coverage` →
 * `get_heatmap_data`). Carries the per-technique TP/FP/detection/last-seen the
 * legacy `showMitreTechnique` drill showed, so the detail panel renders straight
 * from the cell (no second endpoint).
 */
export interface MitreHeatmapTechnique {
  id: string;
  name: string;
  detection_count?: number | null;
  tp_count?: number | null;
  fp_count?: number | null;
  status?: MitreTechniqueStatus | null;
  last_seen?: string | null;
}

/** One tactic column in the ATT&CK heatmap. */
export interface MitreHeatmapTactic {
  tactic: string;
  tactic_id: string;
  techniques: MitreHeatmapTechnique[];
}

/** `GET /api/mitre/coverage` envelope — the full technique-level heatmap. */
export interface MitreCoverageHeatmap {
  tactics: MitreHeatmapTactic[];
}
// ===== [/frontend-integrator — parity gap ①] ================================

// ===== [ui/DailyReview — plain-English incident summaries] ==================
/**
 * `POST /api/incidents/{id}/plain-summary` response. The backend translates an
 * incident into plain, de-anonymized English (via the triage LLM) for a
 * NON-technical reader and CACHES the text in the incident timeline
 * (event_type="plain_summary"). Repeat calls therefore return the SAME text with
 * `cached: true` and NO new LLM spend. Text is free-form plain paragraphs under
 * the headings WHAT HAPPENED / WHAT IS AT RISK / HOW SERIOUS IS THIS /
 * WHAT YOU SHOULD DO (the model is prompted to emit them, but may vary — parse
 * defensively).
 */
export interface PlainSummaryResponse {
  summary: string;
  cached: boolean;
}

/**
 * `POST /api/incidents/batch-plain-summary` response. Fire-and-forget: the
 * backend pre-generates + caches summaries for up to 10 incident ids in a
 * background thread (skipping already-cached ones, one batch at a time) and
 * returns immediately — it never returns the summary text itself.
 */
export interface BatchPlainSummaryResponse {
  status: "generating" | "already_running" | string;
  count: number;
}

// ===== [WO-U16 — Compliance coverage matrix] ================================
/**
 * Both compliance endpoints are `require_role("admin","senior_analyst")` +
 * `require_license_feature("compliance_sca")`. A runtime 402/403 (tier lacks the
 * feature) degrades the compliance surface to FeatureLockedState; below
 * senior_analyst the surface shows a role-locked state — the ATT&CK surface in
 * the same tab is unaffected. READ-ONLY: both are GETs.
 */

/**
 * One control row from `GET /api/compliance/matrix` — the STRUCTURE only
 * (framework → controls), with NO coverage numbers. Shape confirmed against
 * `src/api/routes/compliance.py::get_compliance_matrix` (the raw
 * `compliance_mapping.yaml` control dicts). `description` may be absent in the
 * YAML (server defaults it to ""); `rule_groups` / `mitre_techniques` default to
 * [] — parse defensively.
 */
export interface ComplianceControl {
  control_id: string;
  control_name: string;
  description?: string;
  rule_groups?: string[];
  mitre_techniques?: string[];
}

/**
 * `GET /api/compliance/matrix` → `{ frameworks: { <name>: Control[] } }`. The
 * mapping YAML is absent on some installs → `frameworks` is `{}`; the UI renders
 * an honest "no frameworks configured" empty state rather than fabricating any.
 */
export interface ComplianceMatrix {
  frameworks: Record<string, ComplianceControl[]>;
}

/**
 * One control row from `GET /api/compliance/{framework}/coverage` — the matrix
 * control PLUS its computed detection coverage. `covered` is `detection_count > 0`
 * over a 30-day window, tenant-scoped server-side. "Uncovered" is a GAP, not a
 * severity — the UI renders it neutral/amber, never red (WO-U1).
 */
export interface FrameworkControlCoverage extends ComplianceControl {
  detection_count: number;
  covered: boolean;
}

/**
 * `GET /api/compliance/{framework}/coverage` — per-framework detection coverage.
 * A bad framework name returns 404 (the caller surfaces an honest "unknown
 * framework" error). Shape confirmed against
 * `src/api/routes/compliance.py::get_framework_coverage`.
 */
export interface FrameworkCoverage {
  framework: string;
  total_controls: number;
  covered_controls: number;
  coverage_pct: number;
  controls: FrameworkControlCoverage[];
}
