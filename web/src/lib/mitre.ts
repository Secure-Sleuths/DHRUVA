/**
 * MITRE coverage derivation (WO-U8) — pure, UI-agnostic helpers.
 *
 * All of these derive HONESTLY from the real endpoints (`/api/mitre/summary`
 * + `/api/campaigns`): the coverage band from `coverage_pct`, the live-campaign
 * overlay from active campaigns' `tactic_sequence` / `projected_next_tactic`,
 * and the priority-gap sentence from summary coverage + campaigns' furthest /
 * projected tactics. NOTHING here fabricates a coverage number or a priority.
 *
 * INVARIANT: coverage bands ride their OWN neutral scale (teal → blue → muted),
 * kept OFF the severity p-scale — a weak-coverage tactic must never read as a
 * "critical severity" tactic. The band is always paired with the % text + a word
 * label, so colour is never load-bearing alone (see severity.ts for the rule).
 */

import type {
  ApiCampaign,
  MitreSummary,
  MitreTacticCoverage,
} from "./types";

// ---- Coverage band (neutral scale, never the severity scale) ----------------

export type CoverageBand = "strong" | "moderate" | "weak" | "none";

/** Thresholds reproduce the approved mockup's 70 / 40 coverage cutoffs. */
export const COVERAGE_THRESHOLDS = { strong: 70, moderate: 40 } as const;

/** Bucket a 0..100 detection coverage % onto the neutral band. `null` → "none". */
export function coverageBand(pct: number | null | undefined): CoverageBand {
  if (pct == null) return "none";
  if (pct >= COVERAGE_THRESHOLDS.strong) return "strong";
  if (pct >= COVERAGE_THRESHOLDS.moderate) return "moderate";
  return "weak";
}

/** Plain-language band word (paired with the % so colour is never alone). */
export function coverageBandLabel(band: CoverageBand): string {
  switch (band) {
    case "strong":
      return "strong";
    case "moderate":
      return "moderate";
    case "weak":
      return "weak";
    case "none":
      return "no data";
  }
}

/**
 * Tailwind TEXT-colour utility for a coverage band — neutral ramp only (token
 * classes, no hex). `weak` uses `sev-med` amber ONLY as a neutral attention hue
 * here — it is NOT a severity claim (there is no glyph, and it is paired with the
 * % + the word "weak"); it draws the eye to the gap without borrowing red.
 */
export function coverageTextClass(band: CoverageBand): string {
  switch (band) {
    case "strong":
      return "text-teal";
    case "moderate":
      return "text-acc";
    case "weak":
      return "text-sev-med";
    case "none":
      return "text-dim2";
  }
}

/** Tailwind BG-colour utility for the coverage bar fill (same neutral ramp). */
export function coverageBarClass(band: CoverageBand): string {
  switch (band) {
    case "strong":
      return "bg-teal";
    case "moderate":
      return "bg-acc";
    case "weak":
      return "bg-sev-med";
    case "none":
      return "bg-dim2";
  }
}

// ---- Live-campaign overlay (from ACTIVE campaigns only) ---------------------

export interface CampaignOverlay {
  /** tactic NAME → number of ACTIVE campaigns whose chain has reached it (◉) */
  seen: Map<string, number>;
  /** tactic NAMEs that are an active campaign's projected-next tactic (▦) */
  projected: Set<string>;
}

/** A campaign counts toward the overlay only when its status is "active". */
export function isActiveCampaign(c: ApiCampaign): boolean {
  return c.status === "active";
}

/**
 * Overlay markers for the coverage grid, derived from the campaigns feed:
 *   - "seen" = the tactic appears in ANY active campaign's `tactic_sequence`
 *     (◉ exercised now), counted per campaign for the "N campaigns" caption.
 *   - "projected" = the tactic is an active campaign's `projected_next_tactic`
 *     (▦ heuristic next step — never observed, never auto-actioned).
 * Contained campaigns are excluded (they aren't "live").
 */
export function campaignOverlay(campaigns: ApiCampaign[]): CampaignOverlay {
  const seen = new Map<string, number>();
  const projected = new Set<string>();
  for (const c of campaigns) {
    if (!isActiveCampaign(c)) continue;
    for (const tactic of c.tactic_sequence ?? []) {
      seen.set(tactic, (seen.get(tactic) ?? 0) + 1);
    }
    if (c.projected_next_tactic) projected.add(c.projected_next_tactic);
  }
  return { seen, projected };
}

// ---- Priority-gap sentence (honest, from summary + campaigns) ---------------

export interface PriorityGap {
  /** furthest tactic reached across ACTIVE campaigns (canonical order) */
  furthestTactic: string | null;
  /** the 1–2 weakest-coverage tactics (lowest coverage_pct first) */
  weakest: MitreTacticCoverage[];
  /** an active campaign projecting toward a tactic (the closest thing to intent) */
  projection: { campaign: string; tactic: string } | null;
}

/**
 * Canonical kill-chain index for a tactic NAME, taken from the API's own
 * per-tactic ORDER (the backend emits `per_tactic` in `MITRE_TACTICS` order), so
 * we never hard-code or duplicate the tactic list. Unknown → -1.
 */
function canonicalIndex(summary: MitreSummary): (tactic: string) => number {
  const idx = new Map<string, number>();
  summary.per_tactic.forEach((row, i) => idx.set(row.tactic, i));
  return (t: string) => idx.get(t) ?? -1;
}

/**
 * Derive the priority-gap call-out: the furthest tactic the LIVE campaigns have
 * reached, the WEAKEST-coverage tactics from the summary, and (if any) an active
 * campaign's projected next tactic. Everything is sourced — no fabricated
 * priorities. Returns null weakest/furthest when there's nothing to say.
 */
export function priorityGap(
  summary: MitreSummary,
  campaigns: ApiCampaign[],
  topN = 2,
): PriorityGap {
  const indexOf = canonicalIndex(summary);

  // Furthest ACTIVE tactic = the highest canonical index among active campaigns'
  // furthest_tactic (fall back to the last of their tactic_sequence).
  let furthestTactic: string | null = null;
  let furthestIdx = -1;
  for (const c of campaigns) {
    if (!isActiveCampaign(c)) continue;
    const candidate =
      c.furthest_tactic ??
      (c.tactic_sequence?.length
        ? c.tactic_sequence[c.tactic_sequence.length - 1]
        : null);
    if (!candidate) continue;
    const i = indexOf(candidate);
    if (i > furthestIdx) {
      furthestIdx = i;
      furthestTactic = candidate;
    }
  }

  // Weakest coverage = lowest coverage_pct first; canonical order breaks ties.
  const weakest = [...summary.per_tactic]
    .sort(
      (a, b) =>
        a.coverage_pct - b.coverage_pct ||
        indexOf(a.tactic) - indexOf(b.tactic),
    )
    .slice(0, topN);

  // An active campaign heading somewhere (its projected next tactic).
  let projection: PriorityGap["projection"] = null;
  for (const c of campaigns) {
    if (isActiveCampaign(c) && c.projected_next_tactic) {
      projection = {
        campaign: c.title || c.name || c.attack_chain_id,
        tactic: c.projected_next_tactic,
      };
      break;
    }
  }

  return { furthestTactic, weakest, projection };
}

/**
 * The primary member-incident id to use for a campaign's chain-coverage drill
 * (WO-B6). We use the FIRST member incident — honest: the API gives ordered
 * members and we never fabricate an id. `null` when a campaign carries no
 * members (then the drill is disabled with a note, never faked).
 */
export function primaryIncidentId(c: ApiCampaign): string | null {
  return c.member_incidents?.[0]?.id ?? null;
}
