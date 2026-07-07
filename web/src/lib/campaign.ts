import { SEVERITY, type Severity } from "./severity";
import type { ApiCampaign } from "./types";

/**
 * Campaign data shapes — the correlation engine (M5) groups incidents into
 * campaigns by `attack_chain_id`. These types drive the KillChainLane viz and
 * the campaign Overview. Kept UI-agnostic; the frontend-integrator (WO-U3+)
 * maps the API payload onto these.
 */

/** ATT&CK tactics in kill-chain order (id → display name). */
export const TACTICS: ReadonlyArray<readonly [string, string]> = [
  ["recon", "Recon"],
  ["initial", "Initial Access"],
  ["exec", "Execution"],
  ["persist", "Persistence"],
  ["privesc", "Priv Esc"],
  ["credaccess", "Cred Access"],
  ["discovery", "Discovery"],
  ["lateral", "Lateral Movement"],
  ["collect", "Collection"],
  ["c2", "C2"],
  ["exfil", "Exfiltration"],
  ["impact", "Impact"],
];

export function tacticName(id: string): string {
  return TACTICS.find(([tid]) => tid === id)?.[1] ?? id;
}

/** Likelihood band for a PROJECTED (not-yet-observed) step. */
export type Projection = "likely" | "possible" | "watch";

export const PROJECTION_LABEL: Record<Projection, string> = {
  likely: "likely next",
  possible: "possible",
  watch: "watch",
};

/**
 * An OBSERVED step in a campaign's kill chain.
 *
 * REQUIRED fields (`t`, `tname`, `x`, `severity`) are the structural minimum the
 * lane always has. The rich per-node detail (`tid`, `host`, `when`, `alert`,
 * `conf`, `why`) is OPTIONAL: the approved mockup carried it per node, but the
 * real `GET /api/campaigns` contract does NOT — it gives ordered tactic names
 * only (see adaptCampaign). Those fields are OMITTED, never fabricated, when
 * they are not in the source; the lane renders gracefully without them, and the
 * per-node alert/verdict is a future drill-down (WO-U4/U8).
 */
export interface ObservedNode {
  /** tactic id/slug (matches TACTICS where mapped; the tactic name otherwise) */
  t: string;
  /** ATT&CK technique id, e.g. "T1003" — optional (not in /api/campaigns) */
  tid?: string;
  /** node label: technique name (mockup) OR tactic name (real campaign data) */
  tname: string;
  /** de-anonymized host — optional (not per-node in /api/campaigns) */
  host?: string;
  /** horizontal position along the lane, 0..100 (%) */
  x: number;
  /** when it fired (display string) — optional (not in /api/campaigns) */
  when?: string;
  /** originating alert id — optional (not in /api/campaigns) */
  alert?: string;
  severity: Severity;
  /** model confidence, 0..1 (string) — optional (not in /api/campaigns) */
  conf?: string;
  /** plain-language "why the AI flagged this" — optional (drill-down) */
  why?: string;
}

/**
 * A PROJECTED step: where the correlation engine thinks the campaign could go
 * next. Heuristic only — never observed, never auto-actioned. `tid`/`host` are
 * optional for the same reason as ObservedNode (real data has neither).
 */
export interface ProjectedNode {
  t: string;
  tid?: string;
  tname: string;
  host?: string;
  x: number;
  prob: Projection;
}

// ---- API → viz adapter ------------------------------------------------------

/** Map the backend incident severity string → the UI `Severity` scale. */
export function apiSeverity(sev: string | null | undefined): Severity {
  switch ((sev ?? "").toLowerCase()) {
    case "critical":
      return "crit";
    case "high":
      return "high";
    case "medium":
      return "med";
    case "low":
      return "low";
    default:
      return "info";
  }
}

// Lane geometry: observed tactics spread across the left/centre; the single
// heuristic projection sits near the right edge ("where it could go").
const OBSERVED_START = 8;
const OBSERVED_END = 72;
const PROJECTION_X = 90;

/**
 * Adapt one `GET /api/campaigns` campaign onto the `Campaign` viz shape the
 * KillChainLane consumes.
 *
 * Faithful-to-contract mapping (NO fabrication):
 *  - Observed nodes = `tactic_sequence` (already canonical kill-chain order),
 *    positioned evenly. Each node is labelled with its TACTIC name (`tname`) —
 *    the API has no per-node technique/host/confidence/"why", so those are left
 *    undefined and the lane omits them. Node glyph severity = the campaign's
 *    severity (the API has no per-node severity).
 *  - Projected node = `projected_next_tactic` (kill_chain_order_heuristic),
 *    rendered as the dashed violet projection with the "possible" band. Omitted
 *    entirely when the API returns none.
 *  - `hosts`/`alerts`/`dwell`/`p`/`plabel` come straight from the campaign.
 */
export function adaptCampaign(c: ApiCampaign): Campaign {
  const severity = apiSeverity(c.severity);
  const tactics = c.tactic_sequence ?? [];
  const n = tactics.length;

  const steps: ObservedNode[] = tactics.map((tactic, i) => ({
    // No frontend tactic-id map is needed — the lane labels by name. Use the
    // tactic name as the stable `t` too (honest; not a fabricated technique).
    t: tactic,
    tname: tactic,
    severity,
    x:
      n <= 1
        ? OBSERVED_START
        : OBSERVED_START + ((OBSERVED_END - OBSERVED_START) * i) / (n - 1),
    // tid / host / when / alert / conf / why: NOT in the /api/campaigns
    // contract — intentionally omitted (drill-down opens the member incident).
  }));

  const proj: ProjectedNode[] = c.projected_next_tactic
    ? [
        {
          t: c.projected_next_tactic,
          tname: c.projected_next_tactic,
          x: PROJECTION_X,
          // projection_basis is kill_chain_order_heuristic → the softest band.
          prob: "possible",
        },
      ]
    : [];

  const statusCap =
    c.status === "active"
      ? "Active"
      : c.status === "contained"
        ? "Contained"
        : String(c.status ?? "");
  const status = c.furthest_tactic
    ? `${statusCap} · ${c.furthest_tactic}`
    : statusCap;

  return {
    id: c.attack_chain_id,
    name: c.title || c.name || `Campaign ${c.attack_chain_id}`,
    severity,
    p: c.p ?? SEVERITY[severity].p,
    plabel: c.severity_label ?? SEVERITY[severity].label,
    chain: c.attack_chain_id,
    status,
    // progress is not read by the lane (nodes carry their own x); keep it
    // consistent with the observed spread rather than inventing a percentage.
    progress: steps.length ? Math.round(steps[steps.length - 1].x) : 0,
    dwell: c.dwell ?? "—",
    hosts: c.assets?.hosts ?? [],
    alerts: c.alert_count ?? 0,
    steps,
    proj,
  };
}

export interface Campaign {
  id: string;
  name: string;
  severity: Severity;
  /** p-scale code, e.g. "P0" */
  p: string;
  /** plain-language severity label, e.g. "Critical" */
  plabel: string;
  /** the correlation key, e.g. "attack_chain_id 7f3a-204" */
  chain: string;
  /** human status line, e.g. "Active · Lateral Movement" */
  status: string;
  /** 0..100 progress along the chain */
  progress: number;
  /** dwell time (display string) */
  dwell: string;
  hosts: string[];
  alerts: number;
  steps: ObservedNode[];
  proj: ProjectedNode[];
}
