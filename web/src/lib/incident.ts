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
 * Mirror the server's `_flatten_enrichment` (triage.py): the incident-detail
 * endpoint attaches `glass_box` + `anonymized_fields` to each member alert but
 * does NOT flatten `enrichment_summary`, so the case view parses host / src_ip /
 * MITRE from it here. Defensive: any bad/missing blob yields null / [].
 */
export function alertEnrichment(alert: IncidentAlert): ParsedEnrichment {
  const raw = alert.enrichment_summary;
  let enr: Record<string, unknown> | null = null;
  if (raw && typeof raw === "object") {
    enr = raw as Record<string, unknown>;
  } else if (typeof raw === "string" && raw.trim()) {
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object") {
        enr = parsed as Record<string, unknown>;
      }
    } catch {
      enr = null;
    }
  }
  if (!enr) return { host: null, src_ip: null, technique_ids: [], tactic_ids: [] };

  const asStr = (v: unknown): string | null =>
    typeof v === "string" && v ? v : null;
  const asList = (v: unknown): string[] =>
    Array.isArray(v) ? v.map(String) : v ? [String(v)] : [];

  return {
    host: asStr(enr.agent_name),
    src_ip: asStr(enr.src_ip),
    technique_ids: asList(enr.rule_mitre_techniques),
    tactic_ids: asList(enr.rule_mitre_tactics),
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
