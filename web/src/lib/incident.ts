/**
 * Incident (glass-box case) presentation + parse helpers — WO-U4.
 *
 * The incident endpoints return raw DB rows: JSON-encoded TEXT for the array
 * columns (`mitre_tactics`, `affected_hosts`, …) and an un-flattened
 * `enrichment_summary` blob on each member alert. These helpers parse that
 * shape DEFENSIVELY (tolerating already-parsed values from a future serializer)
 * and never fabricate data — a missing field renders as a graceful placeholder,
 * not an invented value. They also translate the WO-B4 `risk_breakdown` into the
 * mockup's multiplier-chain math and centralise the anonymization-boundary copy.
 */

import { apiSeverity } from "./campaign";
import { SEVERITY_ORDER, type Severity } from "./severity";
import type {
  AnonymizedField,
  IncidentAlert,
  IncidentListRow,
  RiskBreakdown,
} from "./types";

export { apiSeverity };

// ---- JSON-text array parsing ------------------------------------------------
/**
 * Parse a column that may be a JSON-encoded string (`'["a","b"]'`), an actual
 * array, or null/empty → always a `string[]`. Never throws.
 */
export function parseJsonArray(
  value: string | string[] | null | undefined,
): string[] {
  if (Array.isArray(value)) return value.map((v) => String(v));
  if (typeof value !== "string") return [];
  const trimmed = value.trim();
  if (!trimmed || trimmed === "[]") return [];
  try {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed)) return parsed.map((v) => String(v));
    // A bare scalar (non-JSON string) → treat as a single value.
    return [String(parsed)];
  } catch {
    // Not JSON — treat the raw string as a single value.
    return [trimmed];
  }
}

// ---- member-alert enrichment (un-flattened on the incident detail) ----------
interface ParsedEnrichment {
  host: string | null;
  src_ip: string | null;
  technique_ids: string[];
  tactic_ids: string[];
}

/**
 * Parse an alert's `enrichment_summary` (a JSON string, an already-parsed
 * object, or null/malformed) into an object — or `null` when there is nothing
 * parseable. Shared by `alertEnrichment` and `caseContext`. Never throws.
 */
export function parseEnrichmentBlob(
  raw: IncidentAlert["enrichment_summary"],
): Record<string, unknown> | null {
  if (raw && typeof raw === "object") return raw as Record<string, unknown>;
  if (typeof raw === "string" && raw.trim()) {
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      return null;
    }
  }
  return null;
}

const asStr = (v: unknown): string | null =>
  typeof v === "string" && v ? v : null;
const asList = (v: unknown): string[] =>
  Array.isArray(v) ? v.map(String) : v ? [String(v)] : [];
const asNum = (v: unknown): number | null =>
  typeof v === "number" && Number.isFinite(v) ? v : null;
/** A strict list of non-empty strings from a possibly-bad value (WO-H23). */
const asStrList = (v: unknown): string[] =>
  Array.isArray(v)
    ? v.filter((x) => typeof x === "string" && x.trim()).map((x) => String(x))
    : [];

/**
 * WO-H23: parse the persisted `threat_intel_match` list into `TiMatchRecord`s.
 * Defensive — a non-list / bad entry / an entry with no `indicator` is dropped,
 * and each optional field defaults to null. Never throws.
 */
function parseTiMatches(v: unknown): TiMatchRecord[] {
  if (!Array.isArray(v)) return [];
  const out: TiMatchRecord[] = [];
  for (const raw of v) {
    if (!raw || typeof raw !== "object") continue;
    const m = raw as Record<string, unknown>;
    const indicator = asStr(m.indicator);
    if (!indicator) continue;
    out.push({
      indicator,
      type: asStr(m.type),
      source: asStr(m.source),
      severity: asStr(m.severity),
      category: asStr(m.category),
      lastSeen: asStr(m.last_seen),
      description: asStr(m.description),
    });
  }
  return out;
}

/**
 * WO-H23: parse the persisted `host_top_cve_details` list into `VulnCveDetail`s.
 * Defensive — a non-list / bad entry / an entry with no `cve` is dropped; CVSS/
 * EPSS default to null (honest absent) and `kev` to false. Never throws.
 */
function parseCveDetails(v: unknown): VulnCveDetail[] {
  if (!Array.isArray(v)) return [];
  const out: VulnCveDetail[] = [];
  for (const raw of v) {
    if (!raw || typeof raw !== "object") continue;
    const d = raw as Record<string, unknown>;
    const cve = asStr(d.cve);
    if (!cve) continue;
    out.push({
      cve,
      severity: asStr(d.severity),
      cvss: asNum(d.cvss),
      cvssVersion: asStr(d.cvss_version),
      epss: asNum(d.epss),
      epssPercentile: asNum(d.epss_percentile),
      // Tri-state: true / false / (absent or non-boolean → null = unknown).
      kev: d.kev === true ? true : d.kev === false ? false : null,
    });
  }
  return out;
}

/**
 * Mirror the server's `_flatten_enrichment` (triage.py): the incident-detail
 * endpoint attaches `glass_box` + `anonymized_fields` to each member alert but
 * does NOT flatten `enrichment_summary`, so the case view parses host / src_ip /
 * MITRE from it here. Defensive: any bad/missing blob yields null / [].
 */
export function alertEnrichment(alert: IncidentAlert): ParsedEnrichment {
  const enr = parseEnrichmentBlob(alert.enrichment_summary);
  if (!enr) return { host: null, src_ip: null, technique_ids: [], tactic_ids: [] };

  return {
    host: asStr(enr.agent_name),
    src_ip: asStr(enr.src_ip),
    technique_ids: asList(enr.rule_mitre_techniques),
    tactic_ids: asList(enr.rule_mitre_tactics),
  };
}

// ---- WO-H21: complete-context records behind each risk factor ----------------
/**
 * The underlying enrichment RECORDS the case view surfaces inline (WO-H21) —
 * parsed defensively from the SAME stored `enrichment_summary` the risk
 * multipliers were computed from. DISPLAY-ONLY: this parses what triage already
 * persisted; nothing is recomputed and nothing here feeds the LLM. Each
 * dimension is `null` when the blob carries none of its keys (older decision /
 * missing / malformed blob) — the caller renders an honest empty state.
 */
export interface AssetContextRecord {
  hostname: string | null;
  agentIp: string | null;
  tier: string | null;
  owner: string | null;
  environment: string | null;
  tags: string[];
  services: string[];
}

export interface IdentityContextRecord {
  riskLevel: string | null;
  roles: string[];
  hasAdmin: boolean;
  isServiceAccount: boolean;
  department: string | null;
  /**
   * Positive proof that a record was FOUND in the identity store and merged.
   *
   * `IdentityEnricher.enrich` pre-seeds `user_roles: []`, `user_has_admin:
   * false` and `user_department: "unknown"` (enrichers/__init__.py:314) and
   * only ever writes `user_normal_hours` / `user_normal_ips` /
   * `user_onboarded_date` inside its `if identity is not None:` branch. None of
   * those three are in the pre-seed, so their PRESENCE is the only evidence
   * that the principal was actually resolved. Without it, `roles: []` means
   * "we have no roles on file", NOT "this account has no roles".
   */
  storeMatched: boolean;
}

export interface TimeContextRecord {
  context: string | null;
  isBusinessHours: boolean | null;
  isWeekend: boolean | null;
  isMaintenanceWindow: boolean | null;
}

export interface MitreContextRecord {
  techniqueIds: string[];
  tacticIds: string[];
}

/**
 * WO-H23: the EXACT matched indicator behind `is_known_malicious`, trimmed at
 * triage time to a display-safe subset (see `_ti_match_summary` server-side).
 * Every field but `indicator` is optional — absent means "not carried by this
 * feed", rendered as an honest empty, never fabricated.
 */
export interface TiMatchRecord {
  indicator: string;
  type: string | null;
  source: string | null;
  severity: string | null;
  category: string | null;
  lastSeen: string | null;
  description: string | null;
}

export interface TiContextRecord {
  /** `null` when the key was absent — never silently rendered as a real 0 */
  hits: number | null;
  sources: string[];
  highestSeverity: string | null;
  isKnownMalicious: boolean;
  /** the IOC present in the alert (its source IP) — drives the lazy IOC lookup */
  srcIp: string | null;
  /** WO-H23: the exact matched indicator record(s) persisted at triage time */
  matches: TiMatchRecord[];
}

export interface HistoricalContextRecord {
  fpRate: number | null;
  sameRule7d: number | null;
  sameSource7d: number | null;
  sameUser7d: number | null;
  previouslySeenPattern: boolean;
  /**
   * How many decisions the FP-rate query counted, and over how many days.
   *
   * ONLY `windowDays` proves anything. `historical_window_days` is written
   * exclusively inside the HistoricalEnricher's `if self.db and rule_id:`
   * branch (enrichers/__init__.py ~line 664) and has no pre-seeded default, so
   * its presence is positive proof the lookup ran. `occurrenceCount` is NOT
   * proof — `historical_occurrence_count` IS pre-seeded, to 0, at line 640,
   * exactly like `historical_fp_rate` at 0.0; both survive a missing database
   * handle untouched. So `occurrenceCount` may only be read AFTER `windowDays`
   * has established that the query happened, and a "0%" rate must never be
   * rendered over zero samples.
   */
  occurrenceCount: number | null;
  windowDays: number | null;
}

export interface AnomalyContextDetail {
  dimension: string;
  value: string;
  current24h: number | null;
  baselineMean: number | null;
  baselineStd: number | null;
  zScore: number | null;
  sampleDays: number | null;
}

export interface AnomalyContextRecord {
  isAnomaly: boolean;
  deviation: number | null;
  details: AnomalyContextDetail[];
}

/**
 * WO-H23: per-CVE CVSS / EPSS / KEV for a host's top critical CVEs. CVSS comes
 * from the Wazuh vuln doc; EPSS/KEV from the local CVE TI table. Any of the
 * three may be `null`/`false` when not available — shown as an honest absent
 * state, never a guessed or zero-that-looks-real value.
 */
export interface VulnCveDetail {
  cve: string;
  severity: string | null;
  cvss: number | null;
  cvssVersion: string | null;
  epss: number | null;
  epssPercentile: number | null;
  /**
   * Tri-state, honest about "unknown": `true` = in CISA KEV, `false` = the KEV
   * catalog is populated and this CVE is genuinely not in it, `null` = KEV
   * status unavailable (no CVE record / catalog not yet populated). `null` must
   * render as "unavailable", never a definitive "not in KEV".
   */
  kev: boolean | null;
}

export interface VulnContextRecord {
  /**
   * `null` when the key was absent. `asNum(...) ?? 0` used to manufacture a
   * confident "0 critical · 0 high CVEs" out of keys that were never written —
   * a count nobody measured, printed next to counts that were.
   */
  critical: number | null;
  high: number | null;
  scaFailed: number | null;
  topCves: string[];
  reason: string | null;
  /** WO-H23: per-CVE CVSS/EPSS/KEV detail for the top critical CVEs */
  topCveDetails: VulnCveDetail[];
}

export interface HostIntegrityContextRecord {
  /** `null` when the key was absent (see `VulnContextRecord.critical`) */
  rootcheckFindings: number | null;
  fimRecentChanges: number | null;
  reason: string | null;
  /** WO-H23: the specific rootcheck finding signature text(s) */
  rootcheckSignatures: string[];
  /** WO-H23: the specific recently-changed FIM file path(s) */
  fimChangedPaths: string[];
}

export interface CaseContext {
  /**
   * Enrichers that RAISED during this alert's enrichment, from the stored
   * `degraded_enrichers` marker (src/enrichment/service.py:538/584/608).
   *
   * This is the only positive evidence the UI has that a check ERRORED rather
   * than returned nothing, and it exists for exactly THREE enrichers —
   * `asset`, `threat_intel` and `time`. Every other dimension pre-seeds its
   * keys to 0/false and swallows its own failures internally, so for those the
   * UI cannot tell "clean" from "never ran" and must stay neutral.
   */
  degraded: string[];
  asset: AssetContextRecord | null;
  identity: IdentityContextRecord | null;
  time: TimeContextRecord | null;
  mitre: MitreContextRecord | null;
  ti: TiContextRecord | null;
  historical: HistoricalContextRecord | null;
  anomaly: AnomalyContextRecord | null;
  vuln: VulnContextRecord | null;
  hostIntegrity: HostIntegrityContextRecord | null;
}

const EMPTY_CASE_CONTEXT: CaseContext = {
  degraded: [],
  asset: null,
  identity: null,
  time: null,
  mitre: null,
  ti: null,
  historical: null,
  anomaly: null,
  vuln: null,
  hostIntegrity: null,
};

/**
 * Extract the per-dimension context records from an alert's stored
 * `enrichment_summary`. A dimension is present when the blob carries at least
 * one of its keys — its individual fields still default gracefully (`null` /
 * `[]` / `0`), so a partial blob renders honest "unknown" values rather than
 * fabricating any. A missing/malformed blob yields ALL-null (the caller's
 * empty state). Pure; never throws.
 */
export function caseContext(alert: IncidentAlert): CaseContext {
  const enr = parseEnrichmentBlob(alert.enrichment_summary);
  if (!enr) return EMPTY_CASE_CONTEXT;

  const asBool = (v: unknown): boolean => v === true;
  const has = (...keys: string[]) => keys.some((k) => k in enr);

  const asset: AssetContextRecord | null = has(
    "asset_tier",
    "asset_owner",
    "asset_environment",
    "asset_tags",
    "asset_services",
  )
    ? {
        hostname: asStr(enr.agent_name),
        agentIp: asStr(enr.agent_ip),
        tier: asStr(enr.asset_tier),
        owner: asStr(enr.asset_owner),
        environment: asStr(enr.asset_environment),
        tags: asList(enr.asset_tags),
        services: asList(enr.asset_services),
      }
    : null;

  const identity: IdentityContextRecord | null = has(
    "user_risk_level",
    "user_roles",
    "user_has_admin",
    "user_is_service_account",
    "user_department",
  )
    ? {
        riskLevel: asStr(enr.user_risk_level),
        roles: asList(enr.user_roles),
        hasAdmin: asBool(enr.user_has_admin),
        isServiceAccount: asBool(enr.user_is_service_account),
        department: asStr(enr.user_department),
        storeMatched: has(
          "user_normal_hours",
          "user_normal_ips",
          "user_onboarded_date",
        ),
      }
    : null;

  const time: TimeContextRecord | null = has(
    "time_context",
    "is_business_hours",
    "is_weekend",
    "is_maintenance_window",
  )
    ? {
        context: asStr(enr.time_context),
        isBusinessHours:
          typeof enr.is_business_hours === "boolean"
            ? enr.is_business_hours
            : null,
        isWeekend:
          typeof enr.is_weekend === "boolean" ? enr.is_weekend : null,
        isMaintenanceWindow:
          typeof enr.is_maintenance_window === "boolean"
            ? enr.is_maintenance_window
            : null,
      }
    : null;

  const techniqueIds = asList(enr.rule_mitre_techniques);
  const tacticIds = asList(enr.rule_mitre_tactics);
  const mitre: MitreContextRecord | null =
    techniqueIds.length > 0 || tacticIds.length > 0
      ? { techniqueIds, tacticIds }
      : null;

  const ti: TiContextRecord | null = has(
    "threat_intel_hits",
    "threat_intel_sources",
    "highest_ti_severity",
    "is_known_malicious",
    "threat_intel_match",
  )
    ? {
        hits: asNum(enr.threat_intel_hits),
        sources: [...new Set(asList(enr.threat_intel_sources))],
        highestSeverity: asStr(enr.highest_ti_severity),
        isKnownMalicious: asBool(enr.is_known_malicious),
        srcIp: asStr(enr.src_ip),
        matches: parseTiMatches(enr.threat_intel_match),
      }
    : null;

  const historical: HistoricalContextRecord | null = has(
    "historical_fp_rate",
    "same_rule_last_7d",
    "same_source_last_7d",
    "same_user_last_7d",
  )
    ? {
        fpRate: asNum(enr.historical_fp_rate),
        sameRule7d: asNum(enr.same_rule_last_7d),
        sameSource7d: asNum(enr.same_source_last_7d),
        sameUser7d: asNum(enr.same_user_last_7d),
        previouslySeenPattern: asBool(enr.previously_seen_pattern),
        occurrenceCount: asNum(enr.historical_occurrence_count),
        windowDays: asNum(enr.historical_window_days),
      }
    : null;

  let anomaly: AnomalyContextRecord | null = null;
  if (has("baseline_anomaly", "baseline_deviation", "baseline_anomaly_details")) {
    const rawDetails = Array.isArray(enr.baseline_anomaly_details)
      ? enr.baseline_anomaly_details
      : [];
    const details: AnomalyContextDetail[] = rawDetails
      .filter((d): d is Record<string, unknown> => !!d && typeof d === "object")
      .map((d) => ({
        dimension: asStr(d.dimension) ?? "—",
        value: asStr(d.value) ?? "—",
        current24h: asNum(d.current_24h),
        baselineMean: asNum(d.baseline_mean),
        baselineStd: asNum(d.baseline_std),
        zScore: asNum(d.z_score),
        sampleDays: asNum(d.sample_days),
      }));
    anomaly = {
      isAnomaly: asBool(enr.baseline_anomaly),
      deviation: asNum(enr.baseline_deviation),
      details,
    };
  }

  const vuln: VulnContextRecord | null = has(
    "host_vulnerabilities_critical",
    "host_vulnerabilities_high",
    "host_sca_failed_checks",
    "host_top_critical_cves",
    "host_top_cve_details",
  )
    ? {
        critical: asNum(enr.host_vulnerabilities_critical),
        high: asNum(enr.host_vulnerabilities_high),
        scaFailed: asNum(enr.host_sca_failed_checks),
        topCves: asList(enr.host_top_critical_cves),
        reason: asStr(enr.vuln_context_reason),
        topCveDetails: parseCveDetails(enr.host_top_cve_details),
      }
    : null;

  const hostIntegrity: HostIntegrityContextRecord | null = has(
    "host_rootcheck_findings",
    "host_fim_recent_changes",
    "host_rootcheck_signatures",
    "host_fim_changed_paths",
  )
    ? {
        rootcheckFindings: asNum(enr.host_rootcheck_findings),
        fimRecentChanges: asNum(enr.host_fim_recent_changes),
        reason: asStr(enr.host_integrity_reason),
        rootcheckSignatures: asStrList(enr.host_rootcheck_signatures),
        fimChangedPaths: asStrList(enr.host_fim_changed_paths),
      }
    : null;

  return {
    degraded: asStrList(enr.degraded_enrichers),
    asset,
    identity,
    time,
    mitre,
    ti,
    historical,
    anomaly,
    vuln,
    hostIntegrity,
  };
}

// ---- worst-first ordering ---------------------------------------------------
/**
 * Present incidents worst-first: by severity (crit → info), then most-recent
 * first within a severity band. Pure; returns a new array.
 */
export function sortIncidentsWorstFirst<T extends IncidentListRow>(
  incidents: readonly T[],
): T[] {
  const rank = (sev: string) => SEVERITY_ORDER.indexOf(apiSeverity(sev));
  const recency = (r: IncidentListRow) =>
    +new Date(r.last_seen ?? r.first_seen ?? r.created_at ?? 0) || 0;
  return [...incidents].sort((a, b) => {
    const bytSev = rank(a.severity) - rank(b.severity);
    if (bytSev !== 0) return bytSev;
    return recency(b) - recency(a);
  });
}

// ---- risk-breakdown math (WO-B4) --------------------------------------------
/** One factor in the multiplier chain. `kind` drives the severity tint. */
export interface RiskFactor {
  key: string;
  label: string;
  value: number;
  /** "base" = the additive base; "mult" = a multiplier (× value) */
  kind: "base" | "mult";
  /** emphasis tint for a multiplier that moved the score up/down */
  tone: Severity | "neutral";
}

/** The multipliers, in the order `_compute_risk_score` applies them. */
const MULT_FACTORS: ReadonlyArray<readonly [keyof RiskBreakdown, string]> = [
  ["asset_multiplier", "asset"],
  ["user_multiplier", "identity"],
  ["time_multiplier", "time"],
  ["mitre_boost", "MITRE"],
  ["ti_boost", "TI"],
  ["fp_discount", "FP history"],
  ["anomaly_boost", "anomaly"],
  ["vuln_context_multiplier", "vuln context"],
  ["host_integrity_multiplier", "host integrity"],
];

function multTone(v: number): Severity | "neutral" {
  if (v >= 1.8) return "crit";
  if (v >= 1.4) return "high";
  if (v > 1.0) return "med";
  if (v < 1.0) return "low"; // a discount (< 1.0) pulled the score DOWN
  return "neutral";
}

/**
 * Turn a `risk_breakdown` into the ordered factor chain the case view renders as
 * `base × asset × TI × … = raw → clamped`. Only multipliers that actually MOVED
 * the score (≠ 1.0) are surfaced (matching the mockup's readable chain); a `1.0`
 * multiplier is a no-op and is elided. Returns `null` when no breakdown was
 * recorded (empty `{}`), so the caller shows an honest "not recorded" line
 * rather than a fabricated equation.
 */
export function riskMath(breakdown: RiskBreakdown | undefined | null): {
  base: RiskFactor;
  factors: RiskFactor[];
  raw: number | null;
  clamped: number | null;
} | null {
  if (!breakdown || typeof breakdown !== "object") return null;
  const base =
    typeof breakdown.base_severity === "number" ? breakdown.base_severity : null;
  const hasAnyMult = MULT_FACTORS.some(
    ([k]) => typeof breakdown[k] === "number",
  );
  if (base === null && !hasAnyMult) return null;

  const factors: RiskFactor[] = [];
  for (const [k, label] of MULT_FACTORS) {
    const v = breakdown[k];
    if (typeof v === "number" && v !== 1.0) {
      factors.push({ key: String(k), label, value: v, kind: "mult", tone: multTone(v) });
    }
  }
  return {
    base: {
      key: "base_severity",
      label: "base",
      value: base ?? 0,
      kind: "base",
      tone: "neutral",
    },
    factors,
    raw: typeof breakdown.raw_score === "number" ? breakdown.raw_score : null,
    clamped:
      typeof breakdown.clamped_score === "number"
        ? breakdown.clamped_score
        : null,
  };
}

// ---- what the number actually MEANS (WO-H97) --------------------------------
/**
 * The stored score is NOT a danger score, and calling it one is what broke an
 * analyst's trust in the product: thirty 404s from a public web crawler
 * displayed the figure **99.41**, because 443 of 443 human labels on that rule
 * say it fired correctly. The maths is right (WO-H71, untouched); the label was
 * wrong.
 *
 * Under the bounded model the score is **rule precision** — how often a human
 * has confirmed this rule fired correctly — so the case view says that instead.
 * Under the LEGACY multiplicative model the same number is a composite risk
 * figure and must keep its old wording, which is why `model` is read first and
 * why an unrecognised/absent breakdown returns `null` rather than a guess.
 *
 * `confident: false` is its own state, never folded into a percentage: the rule
 * has no track record and the score is the platform's cold-start prior. Saying
 * "this rule is right 75% of the time" about a rule nobody has ever labelled
 * would be inventing a measurement.
 */
export interface RuleAccuracy {
  /** true when the rule has enough human labels to have a track record */
  confident: boolean;
  /**
   * 0..100, rounded — only meaningful when `confident`.
   *
   * Taken from `smoothed_p` (the platform's shrunk estimate), NOT from the raw
   * label ratio, because that is the figure the score is built from: rule 31516
   * is 443 of 443 = 100% raw, and the platform says 99% because a finite sample
   * never earns a certainty. Showing 100% next to a stored score of 99.41 would
   * put two different numbers for one quantity on the same screen.
   */
  pct: number | null;
  /** how many human labels the rule carries */
  labels: number | null;
  /** how many of those said "the rule fired correctly" */
  tp: number | null;
  /** backend's plain-language reason when `confident` is false */
  reason: string;
}

export function ruleAccuracy(
  breakdown: RiskBreakdown | undefined | null,
): RuleAccuracy | null {
  if (!breakdown || typeof breakdown !== "object") return null;
  if (breakdown.model !== "bounded") return null;
  const confident = breakdown.confident === true;
  const labels =
    typeof breakdown.rule_human_labels === "number"
      ? breakdown.rule_human_labels
      : null;
  const tp =
    typeof breakdown.rule_human_tp === "number" ? breakdown.rule_human_tp : null;
  const smoothed =
    typeof breakdown.smoothed_p === "number" ? breakdown.smoothed_p : null;
  const rate =
    smoothed !== null
      ? smoothed
      : typeof breakdown.rule_tp_rate_human === "number"
        ? breakdown.rule_tp_rate_human
        : null;
  return {
    confident,
    pct: confident && rate !== null ? Math.round(rate * 100) : null,
    labels,
    tp,
    reason:
      typeof breakdown.confidence_reason === "string"
        ? breakdown.confidence_reason
        : "",
  };
}

/**
 * THE ONE PLACE THE SCORE'S WORDING LIVES (WO-H97 QA D7).
 *
 * The first cut of this change relabelled the number in the case view only, so
 * an incident could show a MEDIUM severity badge — the backend's authoritative
 * answer, after the guidance floors and ceilings — beside a critical-red `99`
 * captioned "Risk". That is the display that started this work order, sitting
 * next to its own correction.
 *
 * Every surface that prints the stored score now asks this function what the
 * number is called, so there is one wording to change and no way for one screen
 * to drift.
 *
 * `tinted` is false for the bounded model on purpose: a rule-precision figure
 * painted on the severity ramp IS the misreading, in colour. Severity has its
 * own badge and the backend computes it.
 */
export interface ScorePresentation {
  /** the figure alone, e.g. `"99%"` or `"75"` — never prefixed */
  figure: string;
  /** short column/heading label, e.g. `"Rule accuracy"` */
  label: string;
  /** one plain-language line saying what the number measures */
  caption: string;
  /** true ONLY for the legacy composite risk figure, which keeps its old tint */
  tinted: boolean;
}

export function scorePresentation(
  riskScore: number,
  breakdown: RiskBreakdown | undefined | null,
): ScorePresentation {
  const score = Math.round(riskScore ?? 0);
  const accuracy = ruleAccuracy(breakdown);

  if (accuracy && accuracy.confident && accuracy.pct !== null) {
    const evidence =
      accuracy.labels !== null && accuracy.tp !== null
        ? ` (${accuracy.tp} of ${accuracy.labels} human labels)`
        : "";
    return {
      figure: `${accuracy.pct}%`,
      label: "Rule accuracy",
      caption: `how often this rule is right${evidence}`,
      tinted: false,
    };
  }

  if (accuracy && !accuracy.confident) {
    return {
      figure: `${score}`,
      label: "Starting score",
      caption: "no track record for this rule yet — starting score",
      tinted: false,
    };
  }

  /* No `model` recorded. This is the LEGACY multiplicative score and the old
     wording is correct for it, not a gap: measured on the live tenant
     2026-08-24, all 22,991 such rows were written on or before
     2026-08-12T22:41 and all 12,280 `model: "bounded"` rows on or after
     2026-08-12T22:53 — a clean split at the WO-H71 rollout. So the fallback is
     "this decision really was scored the old way", and it keeps the old tint
     because that number really is a composite risk figure. */
  return {
    figure: `${score}`,
    label: "Risk",
    caption: "platform score",
    tinted: true,
  };
}

/**
 * The recorded `risk_breakdown` for a decision row, from whichever field the
 * caller's endpoint supplies: the incident detail attaches `glass_box`, while
 * every `/api/triage/decisions` row carries the enrichment blob (which has
 * always contained `risk_breakdown` — `_flatten_enrichment` passes it through
 * untouched). Returns null when neither is present.
 */
export function decisionRiskBreakdown(row: {
  glass_box?: { risk_breakdown?: RiskBreakdown } | null;
  enrichment_summary?: string | Record<string, unknown> | null;
}): RiskBreakdown | null {
  const fromGlassBox = row.glass_box?.risk_breakdown;
  if (fromGlassBox && typeof fromGlassBox === "object") return fromGlassBox;
  const blob = parseEnrichmentBlob(row.enrichment_summary);
  const fromBlob = blob?.risk_breakdown;
  if (fromBlob && typeof fromBlob === "object" && !Array.isArray(fromBlob)) {
    return fromBlob as RiskBreakdown;
  }
  return null;
}

// ---- anonymization boundary copy (WO-B9) ------------------------------------
/**
 * Build the "what the AI saw vs what you see" copy — FIELD-LEVEL, framing
 * anonymization as the LLM boundary. NEVER references token strings or raw
 * values (the contract forbids them here). When `anonymized_fields` is present
 * we list the specific categories; when ABSENT (B9 not landed) we fall back to a
 * generic honest line. The trailing pass-through note is constant.
 */
export function anonymizationCopy(fields: AnonymizedField[] | undefined): {
  /** the "these were anonymized before AI" sentence */
  primary: string;
  /** whether we listed specific fields (true) or gave the generic fallback */
  specific: boolean;
  /** constant pass-through clause */
  passThrough: string;
} {
  const passThrough =
    "External IPs, MITRE technique/tactic IDs and enrichment pass through un-anonymized.";
  if (fields && fields.length > 0) {
    const labels = fields.map((f) => f.label);
    const list =
      labels.length === 1
        ? labels[0]
        : labels.length === 2
          ? `${labels[0]} and ${labels[1]}`
          : `${labels.slice(0, -1).join(", ")} and ${labels[labels.length - 1]}`;
    const wereWas = labels.length === 1 ? "was" : "were";
    return {
      primary: `${list} ${wereWas} anonymized before AI analysis — you see the real values.`,
      specific: true,
      passThrough,
    };
  }
  return {
    primary:
      "Client identifiers (host, internal IP, user) are anonymized before AI analysis — you see the real values.",
    specific: false,
    passThrough,
  };
}
