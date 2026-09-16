/**
 * Severity p-scale — the single source of truth for how DHRUVA renders risk.
 *
 * HARD RULE (accessibility invariant): severity is ALWAYS expressed as
 * glyph + label + color together, NEVER color alone. Colour-blind and
 * low-contrast users read the glyph and the word; colour is redundant
 * reinforcement. Never derive severity from `color` at a call site — use the
 * `glyph`/`p`/`label` fields alongside it.
 *
 * Confidence has its own NEUTRAL ramp (see `confidence.ts`) and must never
 * reuse these colours: red is reserved for severity so it can never be
 * misread as "low confidence".
 */

export type Severity = "crit" | "high" | "med" | "low" | "info";

export interface SeverityMeta {
  /** stable key used in data + `text-sev-*` / bg utilities */
  readonly key: Severity;
  /** shape that carries the meaning without any colour */
  readonly glyph: string;
  /** priority code on the p-scale (empty for `info`, which is off-scale) */
  readonly p: string;
  /** plain-language name (copy rule: human words, not jargon) */
  readonly label: string;
  /** hex — only ever painted next to `glyph` + `label` */
  readonly color: string;
  /** tailwind text-colour utility for the severity */
  readonly textClass: string;
}

export const SEVERITY: Record<Severity, SeverityMeta> = {
  crit: {
    key: "crit",
    glyph: "◆",
    p: "P0",
    label: "Critical",
    color: "#ff8a8a",
    textClass: "text-sev-crit",
  },
  high: {
    key: "high",
    glyph: "▲",
    p: "P1",
    label: "High",
    color: "#ffb37a",
    textClass: "text-sev-high",
  },
  med: {
    key: "med",
    glyph: "■",
    p: "P2",
    label: "Medium",
    color: "#ffe08a",
    textClass: "text-sev-med",
  },
  low: {
    key: "low",
    glyph: "●",
    p: "P3",
    label: "Low",
    color: "#8ad0ff",
    textClass: "text-sev-low",
  },
  info: {
    key: "info",
    glyph: "○",
    p: "",
    label: "Info",
    color: "#9fb6ff",
    textClass: "text-sev-info",
  },
};

/** worst → least, for sorting queues and legends */
export const SEVERITY_ORDER: readonly Severity[] = [
  "crit",
  "high",
  "med",
  "low",
  "info",
];

/**
 * Full plain-language label, e.g. `"P0 · Critical"` (or just `"Info"` for the
 * off-scale level). Use for the primary badge on a case/incident.
 */
export function severityLabel(sev: Severity): string {
  const m = SEVERITY[sev];
  return m.p ? `${m.p} · ${m.label}` : m.label;
}

/**
 * Map a 0..100 `risk_score` to a severity level — the SINGLE source of truth
 * for the row severity glyph + risk-number colour in the Triage / Incidents
 * queues. Thresholds are chosen to reproduce the approved mockup's mapping
 * (87 → crit, 64/58 → high, 41 → med):
 *
 *   crit ≥ 80 · high ≥ 55 · med ≥ 30 · low < 30
 *
 * THESE NUMBERS MUST STAY EQUAL TO `src/incidents/severity.py::RISK_THRESHOLDS`
 * (WO-H97). `tests/test_severity_ladder.py` parses THIS declaration and fails if
 * the two drift.
 *
 * NOTE `high: 55` is the DISCRETIONARY half. Only `crit: 80` is load-bearing
 * (it is what stops an unlearned rule's 75.00 opening a critical incident, and
 * it costs zero notifications). Measured on the live tenant, moving the backend
 * `high` from 50 to 55 is what removes 622 incidents from the notification set
 * — 75% of the cost of WO-H97 — for agreement with this number alone. If that
 * is reverted it must be reverted in BOTH files; the ladder test enforces it.
 *
 * There used to be two ladders. The backend opened critical at
 * `verdict == "true_positive" OR risk_score >= 75`, this file at `>= 80` with no
 * verdict — so the same 75.00 alert read **High** in the triage queue and became
 * a **Critical** incident. These numbers won, and the backend moved to them: the
 * analyst already reads this scale, and 80 puts a deliberate gap between the
 * cold-start prior (an unlearned rule scores exactly 75.00) and "critical", so
 * critical has to be earned by a rule's measured track record rather than handed
 * out for the absence of one.
 *
 * NOTE the backend can move an INCIDENT's severity off this band deliberately —
 * the guidance floors and ceilings in `config/guidance/escalation_logic.yaml`
 * (e.g. a host that went dark is floored, a web request the server refused with
 * a 4xx is capped). An incident's stored `severity` is authoritative for the
 * incident; this function is for colouring a per-alert risk NUMBER.
 *
 * This drives SEVERITY only. Confidence has its own neutral ramp (confidence.ts)
 * and must never be coloured from this scale. `info` is off-scale and is never
 * produced from a risk score.
 */
export const RISK_THRESHOLDS = { crit: 80, high: 55, med: 30 } as const;

export function riskSeverity(score: number): Severity {
  if (score >= RISK_THRESHOLDS.crit) return "crit";
  if (score >= RISK_THRESHOLDS.high) return "high";
  if (score >= RISK_THRESHOLDS.med) return "med";
  return "low";
}
