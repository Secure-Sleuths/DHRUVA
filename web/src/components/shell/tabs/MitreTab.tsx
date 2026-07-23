"use client";

/**
 * MitreTab (WO-U8) — MITRE ATT&CK coverage, overlaid with the tactics the LIVE
 * campaigns are actually exercising, plus per-campaign kill-chain coverage.
 *
 * Translates the approved mockup's `tMitre()`:
 *   - a per-tactic COVERAGE GRID (each tile: detection coverage_pct + a bar),
 *     overlaid with ◉ "seen in an active campaign now" (violet) and ▦ "projected
 *     next" (blue), derived from `/api/campaigns`;
 *   - a PRIORITY-GAP call-out: the weakest-coverage tactics the live campaigns
 *     are heading toward;
 *   - the WO-B6 payoff — per-campaign CHAIN COVERAGE via
 *     `GET /api/mitre/incident/{member_incident_id}`, rendered covered-vs-gap with
 *     the org-wide overlay clearly labelled org-wide.
 *
 * Data (all `verify_jwt` + the `mitre` LICENSE gate):
 *   - `GET /api/mitre/summary`  → the coverage grid (per_tactic, canonical order)
 *   - `GET /api/campaigns`      → the live-campaign overlay (WO-U3's getCampaigns)
 *   - `GET /api/mitre/incident/{id}` (WO-B6) → per-campaign chain coverage
 *   - `GET /api/mitre/gaps`     → the optional per-tactic technique drill-down
 *
 * READ-ONLY tab: no write action, no active-response affordance. Projections are
 * labelled heuristic + never auto-actioned. Coverage rides its OWN neutral band
 * scale (see lib/mitre.ts) — severity glyphs/red are reserved for severity.
 *
 * TIER-GATE: `mitre` is a paid feature server-side. If the API returns 402/403
 * the whole surface degrades to `FeatureLockedState` — never a broken/blank grid
 * or fabricated coverage. (In the shipped license model `mitre` is core to every
 * tier, so this only fires for a restricted/custom license.)
 *
 * States: loading / empty / error+retry / locked; PollingStatus (30s, aborts on
 * unmount) mirrors the other tabs. Fixtures gate behind NEXT_PUBLIC_DHRUVA_FIXTURES.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Lock } from "lucide-react";
import {
  Chip,
  Dialog,
  Panel,
  PollingStatus,
  StatusState,
  FeatureLockedState,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
  Tile,
} from "@/components";
import { PageHeading } from "../PageHeading";
import { DASH, fmtDateTime, fmtInt } from "@/lib/format";
import {
  ApiError,
  getCampaigns,
  getComplianceMatrix,
  getFrameworkCoverage,
  getMitreCoverage,
  getMitreGaps,
  getMitreIncidentCoverage,
  getMitreSummary,
} from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { roleAtLeast } from "@/lib/rbac";
import { cn, focusRing } from "@/lib/ui";
import {
  campaignOverlay,
  coverageBand,
  coverageBandLabel,
  coverageBarClass,
  coverageTextClass,
  isActiveCampaign,
  primaryIncidentId,
  priorityGap,
  type CoverageBand,
} from "@/lib/mitre";
import type { TabProps } from "../tabRegistry";
import type {
  ApiCampaign,
  ComplianceControl,
  ComplianceMatrix,
  FrameworkControlCoverage,
  FrameworkCoverage,
  MitreCoverageHeatmap,
  MitreGaps,
  MitreHeatmapTactic,
  MitreHeatmapTechnique,
  MitreIncidentCoverage,
  MitreSummary,
  MitreTacticCoverage,
} from "@/lib/types";

/** Auto-poll cadence (ms). The product polls; there is no push channel. */
const POLL_MS = 30_000;

/** A runtime 402/403 from the `mitre` license gate → degrade to locked. */
function isLockError(e: unknown): boolean {
  return e instanceof ApiError && (e.status === 402 || e.status === 403);
}

function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : "Unknown error";
}

interface MitreState {
  summary: MitreSummary | null;
  campaigns: ApiCampaign[] | null;
  heatmap: MitreCoverageHeatmap | null;
  error: string | null;
  locked: boolean;
  lockMessage: string | null;
  loading: boolean;
}

/**
 * The MITRE tab hosts TWO coverage surfaces behind a segmented control:
 *   - "ATT&CK Coverage" (default) — the existing MITRE surface, fully preserved.
 *   - "Compliance Frameworks" — the WO-U16 compliance coverage matrix.
 * Both share the "coverage" mental model. The compliance segment gates
 * INDEPENDENTLY by role (senior_analyst+) AND tier (`compliance_sca`), so a lower
 * role/other tier locks ONLY that segment — ATT&CK stays usable. The compliance
 * matrix loads LAZILY (only when its segment is first selected), never on mount.
 */
type MitreSegment = "attack" | "compliance";

export function MitreTab(props: TabProps) {
  const [segment, setSegment] = useState<MitreSegment>("attack");

  return (
    <>
      <SegmentedControl segment={segment} onSelect={setSegment} />
      {/* Mounting is the lazy boundary: ATT&CK is default; the compliance matrix
          fetch fires only once ComplianceView mounts (segment first selected). */}
      {segment === "attack" ? (
        <AttackCoverageView {...props} />
      ) : (
        <ComplianceView />
      )}
    </>
  );
}

/** The two-option segmented control at the top of the MITRE tab. */
function SegmentedControl({
  segment,
  onSelect,
}: {
  segment: MitreSegment;
  onSelect: (s: MitreSegment) => void;
}) {
  return (
    <div
      className="mb-3 inline-flex items-center gap-1.5"
      role="group"
      aria-label="Coverage view"
    >
      <Chip
        variant={segment === "attack" ? "cite" : "default"}
        onClick={() => onSelect("attack")}
        aria-label="ATT&CK Coverage (detection coverage overlaid with live campaigns)"
      >
        ATT&amp;CK Coverage
      </Chip>
      <Chip
        variant={segment === "compliance" ? "cite" : "default"}
        onClick={() => onSelect("compliance")}
        aria-label="Compliance Frameworks (per-framework control coverage)"
      >
        Compliance Frameworks
      </Chip>
    </div>
  );
}

function AttackCoverageView(_props: TabProps) {
  const [state, setState] = useState<MitreState>({
    summary: null,
    campaigns: null,
    heatmap: null,
    error: null,
    locked: false,
    lockMessage: null,
    loading: true,
  });
  const [secondsAgo, setSecondsAgo] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async (manual: boolean) => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    if (manual) setRefreshing(true);
    try {
      // One refresh fans out to the reads — the tactic coverage grid, the
      // technique heatmap, and the live campaign overlay are all views of the
      // same tenant state (summary + coverage share the `mitre` gate).
      const [summary, campaignsRes, heatmap] = await Promise.all([
        getMitreSummary(ac.signal),
        getCampaigns(ac.signal),
        getMitreCoverage(ac.signal),
      ]);
      if (ac.signal.aborted) return;
      setState({
        summary,
        campaigns: campaignsRes.campaigns,
        heatmap,
        error: null,
        locked: false,
        lockMessage: null,
        loading: false,
      });
      setSecondsAgo(0);
    } catch (e) {
      if (ac.signal.aborted) return;
      // Tier gate → lock the whole surface (never a broken grid / fake coverage).
      if (isLockError(e)) {
        setState({
          summary: null,
          campaigns: null,
          heatmap: null,
          error: null,
          locked: true,
          lockMessage: errMessage(e),
          loading: false,
        });
        return;
      }
      const msg = errMessage(e);
      // Keep any previously-loaded data on a background poll failure; only fall
      // to the full error state when we have nothing to show yet.
      setState((prev) =>
        prev.summary || prev.campaigns
          ? { ...prev, loading: false }
          : {
              summary: null,
              campaigns: null,
              heatmap: null,
              error: msg,
              locked: false,
              lockMessage: null,
              loading: false,
            },
      );
    } finally {
      if (!ac.signal.aborted) setRefreshing(false);
    }
  }, []);

  // Initial fetch + auto-poll.
  useEffect(() => {
    load(false);
    const poll = setInterval(() => load(false), POLL_MS);
    return () => {
      clearInterval(poll);
      abortRef.current?.abort();
    };
  }, [load]);

  // "refreshed Ns ago" ticker.
  useEffect(() => {
    const t = setInterval(() => setSecondsAgo((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, []);

  const onUpgrade = useCallback(() => {
    if (typeof window !== "undefined") {
      window.open("https://securesleuths.in/pricing", "_blank", "noreferrer");
    }
  }, []);

  const { summary, campaigns, heatmap, error, locked, lockMessage, loading } =
    state;

  const overlay = useMemo(
    () => campaignOverlay(campaigns ?? []),
    [campaigns],
  );
  const gap = useMemo(
    () => (summary ? priorityGap(summary, campaigns ?? []) : null),
    [summary, campaigns],
  );

  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PageHeading
          title="MITRE ATT&CK coverage"
          sub="Detection coverage overlaid with the tactics your live campaigns are actually exercising — derived from real decisions."
        />
        {!locked && (
          <PollingStatus
            className="mt-1"
            secondsAgo={secondsAgo}
            refreshing={refreshing}
            onRefresh={() => load(true)}
          />
        )}
      </div>

      {locked ? (
        <FeatureLockedState
          feature="MITRE ATT&CK coverage"
          tier="current"
          onUpgrade={onUpgrade}
        />
      ) : loading && !summary ? (
        <StatusState variant="loading" title="Loading coverage…" />
      ) : error && !summary ? (
        <StatusState
          variant="error"
          title="Couldn't load MITRE coverage"
          description={error}
          action={<Chip onClick={() => load(true)}>Retry</Chip>}
        />
      ) : summary ? (
        <div className="flex flex-col gap-3">
          <CoverageGrid summary={summary} overlay={overlay} />
          {heatmap && <TechniqueHeatmap heatmap={heatmap} />}
          {gap && <PriorityGapPanel gap={gap} />}
          <CampaignChainCoverage campaigns={campaigns ?? []} />
        </div>
      ) : null}

      {lockMessage && locked && (
        <div className="mt-2 text-kbd text-dim2">{lockMessage}</div>
      )}
    </>
  );
}

// ---- Coverage grid ----------------------------------------------------------

function CoverageGrid({
  summary,
  overlay,
}: {
  summary: MitreSummary;
  overlay: ReturnType<typeof campaignOverlay>;
}) {
  const [gapTactic, setGapTactic] = useState<MitreTacticCoverage | null>(null);

  if (summary.per_tactic.length === 0) {
    return (
      <Panel className="p-4">
        <StatusState
          variant="empty"
          title="No coverage computed yet"
          description="The coverage analyzer hasn't mapped any detections onto ATT&CK tactics for this tenant. Coverage appears once triage decisions carry technique context."
        />
      </Panel>
    );
  }

  const overall = summary.overall;

  return (
    <Panel className="p-4">
      <div className="mb-2.5 flex flex-wrap items-center justify-between gap-2">
        <CoverageLegend />
        {overall.coverage_pct != null && (
          <span className="text-kbd text-dim2">
            Overall{" "}
            <b className={coverageTextClass(coverageBand(overall.coverage_pct))}>
              {overall.coverage_pct}%
            </b>{" "}
            technique coverage
            {overall.detected != null && overall.total_techniques != null ? (
              <> · {overall.detected}/{overall.total_techniques} techniques</>
            ) : null}
          </span>
        )}
      </div>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6">
        {summary.per_tactic.map((t) => (
          <TacticTile
            key={t.tactic}
            tactic={t}
            seenCount={overlay.seen.get(t.tactic) ?? 0}
            projected={overlay.projected.has(t.tactic)}
            onOpen={() => setGapTactic(t)}
          />
        ))}
      </div>

      <div className="mt-2 text-kbd text-dim2">
        Coverage % is DETECTION coverage (detected/total techniques per tactic),
        on its own neutral band scale — it is not a severity. Click a tactic to
        see which techniques are uncovered.
      </div>

      <GapDrillDialog
        tactic={gapTactic}
        onClose={() => setGapTactic(null)}
      />
    </Panel>
  );
}

function CoverageLegend() {
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-kbd text-dim2">
      <span>Each tile: detection coverage %</span>
      <span className="text-violet">◉ seen in an active campaign now</span>
      <span className="text-acc">▦ projected next</span>
      <span className="flex items-center gap-1.5">
        band:
        <span className="text-teal">strong</span>
        <span className="text-acc">moderate</span>
        <span className="text-sev-med">weak</span>
      </span>
    </div>
  );
}

function TacticTile({
  tactic,
  seenCount,
  projected,
  onOpen,
}: {
  tactic: MitreTacticCoverage;
  seenCount: number;
  projected: boolean;
  onOpen: () => void;
}) {
  const band: CoverageBand = coverageBand(tactic.coverage_pct);
  const seen = seenCount > 0;

  // Overlay border: violet when seen in a live campaign, blue when projected.
  const overlayBorder = seen
    ? "border-violet/70"
    : projected
      ? "border-acc/60"
      : "border-line";

  const marker = seen ? (
    <span className="text-violet">
      ◉ {seenCount} campaign{seenCount > 1 ? "s" : ""}
    </span>
  ) : projected ? (
    <span className="text-acc">▦ projected</span>
  ) : (
    <span aria-hidden="true">&nbsp;</span>
  );

  return (
    <button
      type="button"
      onClick={onOpen}
      aria-label={`${tactic.tactic}: ${tactic.coverage_pct}% detection coverage (${coverageBandLabel(band)})${seen ? `, seen in ${seenCount} active campaign${seenCount > 1 ? "s" : ""}` : projected ? ", projected next by a live campaign" : ""}. Open uncovered techniques.`}
      className={`flex flex-col rounded-lg border bg-panel2 p-2.5 text-left transition hover:brightness-110 focus:outline-none focus-visible:ring-2 focus-visible:ring-acc ${overlayBorder} ${
        seen ? "bg-gradient-to-b from-violet/10 to-transparent" : ""
      }`}
    >
      <div className="min-h-[28px] text-kbd text-dim">{tactic.tactic}</div>
      <div className={`text-metric tabular ${coverageTextClass(band)}`}>
        {tactic.coverage_pct}%
      </div>
      {/* bar — neutral coverage ramp, never the severity scale */}
      <div className="mt-1 h-1.5 w-full overflow-hidden rounded-pill bg-bar">
        <div
          className={`h-full rounded-pill ${coverageBarClass(band)}`}
          style={{ width: `${Math.max(0, Math.min(100, tactic.coverage_pct))}%` }}
        />
      </div>
      <div className="mt-1 flex items-center justify-between text-micro">
        <span className={coverageTextClass(band)}>{coverageBandLabel(band)}</span>
        {marker}
      </div>
    </button>
  );
}

// ---- Technique heatmap + per-technique detail (restored parity sub-view) -----
// Legacy app.js:3920-3947 (technique heatmap grid) + 3966-4001 (showMitreTechnique
// per-technique TP/FP/detections/last-seen drill). Sourced from GET
// /api/mitre/coverage (get_heatmap_data): each technique cell already carries
// detection_count / tp_count / fp_count / status / last_seen, so the per-technique
// detail renders straight from the cell — no second request, no fabricated number.
// Status colours ride a NEUTRAL detection ramp (teal/amber/dim), NOT the severity
// scale, and every cell pairs a glyph + word so colour is never load-bearing alone.

type TechniqueTone = {
  label: string;
  glyph: string;
  cell: string;
  text: string;
};

function techniqueTone(t: MitreHeatmapTechnique): TechniqueTone {
  switch (t.status) {
    case "active":
      return {
        label: "detected",
        glyph: "●",
        cell: "border-teal/50 bg-teal/10 hover:bg-teal/20",
        text: "text-teal",
      };
    case "noisy":
      return {
        label: "noisy",
        glyph: "◐",
        cell: "border-sev-med/50 bg-sev-med/10 hover:bg-sev-med/20",
        text: "text-sev-med",
      };
    case "stale":
      return {
        label: "stale",
        glyph: "○",
        cell: "border-line bg-panel2 hover:brightness-110",
        text: "text-dim",
      };
    default:
      return {
        label: "not detected",
        glyph: "·",
        cell: "border-line bg-transparent hover:bg-panel2",
        text: "text-dim2",
      };
  }
}

function TechniqueHeatmap({ heatmap }: { heatmap: MitreCoverageHeatmap }) {
  const [detail, setDetail] = useState<{
    technique: MitreHeatmapTechnique;
    tactic: string;
  } | null>(null);

  const tactics = heatmap.tactics ?? [];
  const totals = useMemo(() => {
    let total = 0;
    let detected = 0;
    for (const tac of heatmap.tactics ?? []) {
      for (const tech of tac.techniques ?? []) {
        total += 1;
        if ((tech.detection_count ?? 0) > 0) detected += 1;
      }
    }
    return { total, detected };
  }, [heatmap]);

  if (tactics.length === 0) {
    return (
      <Panel className="p-4">
        <div className="mb-1 text-title text-ink">Technique heatmap</div>
        <StatusState
          variant="empty"
          title="No technique coverage computed yet"
          description="The coverage analyzer hasn't mapped detections onto individual ATT&CK techniques for this tenant. The heatmap fills in as triage decisions carry technique context."
        />
      </Panel>
    );
  }

  return (
    <Panel className="p-4">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div className="text-title text-ink">Technique heatmap</div>
        <span className="text-kbd text-dim2">
          <b className="text-ink tabular">
            {fmtInt(totals.detected)}/{fmtInt(totals.total)}
          </b>{" "}
          techniques with ≥1 detection
        </span>
      </div>
      <TechniqueLegend />
      <div className="mt-2 overflow-x-auto">
        <div className="flex gap-2 pb-1">
          {tactics.map((tac) => (
            <TechniqueColumn key={tac.tactic} tactic={tac} onOpen={setDetail} />
          ))}
        </div>
      </div>
      <div className="mt-2 text-kbd text-dim2">
        Each cell is one ATT&CK technique, coloured by DETECTION status (a neutral
        ramp, not a severity). Click a technique for its detection counts. Click to
        drill; read-only — building a detection is Detection-tab work.
      </div>
      <TechniqueDetailDialog
        detail={detail}
        onClose={() => setDetail(null)}
      />
    </Panel>
  );
}

function TechniqueLegend() {
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-kbd text-dim2">
      <span className="text-teal">● detected</span>
      <span className="text-sev-med">◐ noisy (high FP)</span>
      <span className="text-dim">○ stale</span>
      <span className="text-dim2">· not detected</span>
    </div>
  );
}

function TechniqueColumn({
  tactic,
  onOpen,
}: {
  tactic: MitreHeatmapTactic;
  onOpen: (d: { technique: MitreHeatmapTechnique; tactic: string }) => void;
}) {
  const techs = tactic.techniques ?? [];
  return (
    <div className="flex w-[132px] shrink-0 flex-col">
      <div className="mb-1 min-h-[30px] text-micro text-dim">
        <div className="text-dim">{tactic.tactic}</div>
        <div className="font-mono text-dim2">{tactic.tactic_id}</div>
      </div>
      <div className="flex flex-col gap-1">
        {techs.length === 0 ? (
          <div className="text-micro text-dim2">—</div>
        ) : (
          techs.map((tech) => {
            const tone = techniqueTone(tech);
            return (
              <button
                key={tech.id}
                type="button"
                onClick={() => onOpen({ technique: tech, tactic: tactic.tactic })}
                aria-label={`${tech.id} ${tech.name}: ${tone.label}, ${tech.detection_count ?? 0} detections. Open detail.`}
                className={`flex items-center gap-1 rounded border px-1.5 py-1 text-left transition focus:outline-none focus-visible:ring-2 focus-visible:ring-acc ${tone.cell}`}
              >
                <span className={`text-micro ${tone.text}`} aria-hidden="true">
                  {tone.glyph}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-mono text-micro text-ink">
                    {tech.id}
                  </span>
                </span>
                {(tech.detection_count ?? 0) > 0 && (
                  <span className="text-micro tabular text-dim">
                    {fmtInt(tech.detection_count)}
                  </span>
                )}
              </button>
            );
          })
        )}
      </div>
    </div>
  );
}

function TechniqueDetailDialog({
  detail,
  onClose,
}: {
  detail: { technique: MitreHeatmapTechnique; tactic: string } | null;
  onClose: () => void;
}) {
  const t = detail?.technique;
  const tone = t ? techniqueTone(t) : null;
  return (
    <Dialog
      open={detail !== null}
      onClose={onClose}
      title={t ? `${t.id} — ${t.name}` : undefined}
      maxWidth={460}
    >
      {t && tone && (
        <div>
          <div className="mb-3 flex flex-wrap items-center gap-2 text-kbd">
            <Chip mono>{t.id}</Chip>
            <span className="text-dim2">tactic {detail!.tactic}</span>
            <span className={`font-semibold ${tone.text}`}>
              <span aria-hidden="true">{tone.glyph}</span> {tone.label}
            </span>
          </div>
          <dl className="grid grid-cols-2 gap-2">
            <DetailStat label="Detections" value={fmtInt(t.detection_count)} />
            <DetailStat label="True positives" value={fmtInt(t.tp_count)} tone="text-teal" />
            <DetailStat label="False positives" value={fmtInt(t.fp_count)} tone={(t.fp_count ?? 0) > 0 ? "text-sev-med" : undefined} />
            <DetailStat
              label="Last seen"
              value={t.last_seen ? fmtDateTime(t.last_seen) : DASH}
            />
          </dl>
          <div className="mt-3 text-kbd text-dim2">
            Aggregate detection stats for this technique across this tenant
            (GET /api/mitre/coverage). Read-only — closing a gap or tuning a noisy
            technique is Detection-tab work.
          </div>
        </div>
      )}
    </Dialog>
  );
}

function DetailStat({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: string;
}) {
  return (
    <div className="rounded-lg border border-line bg-panel2 px-3 py-2">
      <div className="text-micro uppercase tracking-wider text-dim2">{label}</div>
      <div className={`text-data tabular ${tone ?? "text-ink"}`}>{value}</div>
    </div>
  );
}

// ---- Priority-gap panel -----------------------------------------------------

function PriorityGapPanel({
  gap,
}: {
  gap: NonNullable<ReturnType<typeof priorityGap>>;
}) {
  const { furthestTactic, weakest, projection } = gap;

  // Nothing honest to say if we have neither a live furthest tactic nor weak
  // coverage — don't invent a priority.
  if (!furthestTactic && weakest.length === 0) return null;

  const weakList = weakest.map((w) => `${w.tactic} (${w.coverage_pct}%)`);
  const weakSentence =
    weakList.length === 1
      ? weakList[0]
      : weakList.length === 2
        ? `${weakList[0]} and ${weakList[1]}`
        : weakList.slice(0, -1).join(", ") + `, and ${weakList[weakList.length - 1]}`;

  return (
    <div className="rounded-lg border border-sev-crit/40 bg-panel2 p-3.5">
      <div className="flex items-center gap-1.5 text-meta font-semibold text-sev-crit">
        <span aria-hidden="true">◆</span> PRIORITY GAP
      </div>
      <p className="mt-1 text-data text-ink">
        {furthestTactic ? (
          <>
            Live campaigns have reached <b>{furthestTactic}</b>
            {weakest.length > 0 ? (
              <>
                {" "}
                but <b>{weakSentence}</b>{" "}
                {weakest.length === 1 ? "is" : "are"} your weakest coverage
              </>
            ) : null}
            .
          </>
        ) : (
          <>
            Your weakest detection coverage is <b>{weakSentence}</b>.
          </>
        )}
        {projection ? (
          <>
            {" "}
            <span className="text-dim">{projection.campaign}</span> projects
            toward <b>{projection.tactic}</b> (heuristic · never auto-actioned) —
            closing that gap is the highest-leverage detection work right now.
          </>
        ) : (
          <> Closing that gap is high-leverage detection work.</>
        )}
      </p>
      <div className="mt-1.5 text-kbd text-dim2">
        Derived honestly from per-tactic coverage (weakest %) + the live
        campaigns&apos; furthest / projected tactics — no fabricated priorities.
      </div>
    </div>
  );
}

// ---- Per-campaign chain coverage (the WO-B6 payoff) -------------------------

function CampaignChainCoverage({ campaigns }: { campaigns: ApiCampaign[] }) {
  const active = useMemo(
    () => campaigns.filter(isActiveCampaign),
    [campaigns],
  );

  // Default-select the first active campaign that HAS a member incident to
  // drill into (never fabricate an id).
  const firstDrillable = useMemo(
    () => active.find((c) => primaryIncidentId(c) !== null) ?? null,
    [active],
  );
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const effectiveId = selectedId ?? firstDrillable?.attack_chain_id ?? null;
  const selected = active.find((c) => c.attack_chain_id === effectiveId) ?? null;

  const incidentId = selected ? primaryIncidentId(selected) : null;

  const [chain, setChain] = useState<{
    coverage: MitreIncidentCoverage | null;
    error: string | null;
    loading: boolean;
  }>({ coverage: null, error: null, loading: false });

  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    if (!incidentId) {
      setChain({ coverage: null, error: null, loading: false });
      return;
    }
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setChain((c) => ({ ...c, loading: true, error: null }));
    getMitreIncidentCoverage(incidentId, ac.signal)
      .then((coverage) => {
        if (ac.signal.aborted) return;
        setChain({ coverage, error: null, loading: false });
      })
      .catch((e) => {
        if (ac.signal.aborted) return;
        setChain({ coverage: null, error: errMessage(e), loading: false });
      });
    return () => ac.abort();
  }, [incidentId]);

  if (active.length === 0) {
    return (
      <Panel className="p-4">
        <div className="mb-1 text-title text-ink">Per-campaign chain coverage</div>
        <StatusState
          variant="empty"
          title="No active campaigns"
          description="Once the correlation engine links incidents into a live attack chain, its per-incident kill-chain coverage appears here."
        />
      </Panel>
    );
  }

  return (
    <Panel className="p-4">
      <div className="mb-0.5 text-title text-ink">
        Per-campaign chain coverage
      </div>
      <div className="mb-2.5 text-kbd text-dim2">
        A live campaign&apos;s kill chain, stage by stage — which stages your
        detections cover and which are blind spots. The per-stage coverage % is
        ORG-WIDE detection, not this incident&apos;s.
      </div>

      {/* campaign selector */}
      <div
        className="mb-3 flex flex-wrap gap-1.5"
        role="group"
        aria-label="Choose a campaign to inspect its chain coverage"
      >
        {active.map((c) => {
          const drillable = primaryIncidentId(c) !== null;
          const isSel = c.attack_chain_id === effectiveId;
          return (
            <Chip
              key={c.attack_chain_id}
              variant={isSel ? "cite" : "default"}
              disabled={!drillable}
              onClick={drillable ? () => setSelectedId(c.attack_chain_id) : undefined}
              aria-label={
                drillable
                  ? `Show chain coverage for ${c.title || c.name}`
                  : `${c.title || c.name} has no member incident to inspect`
              }
            >
              {c.title || c.name || c.attack_chain_id}
              {!drillable && <span className="text-dim2"> · no incident</span>}
            </Chip>
          );
        })}
      </div>

      {!selected || !incidentId ? (
        <div className="text-kbd text-dim2">
          This campaign carries no member incident to inspect — the chain
          coverage drill needs a real incident id, so it&apos;s omitted rather
          than faked.
        </div>
      ) : chain.loading ? (
        <StatusState variant="loading" title="Loading chain coverage…" />
      ) : chain.error ? (
        <StatusState
          variant="error"
          title="Couldn't load this chain's coverage"
          description={chain.error}
        />
      ) : chain.coverage ? (
        <ChainView
          coverage={chain.coverage}
          campaignName={selected.title || selected.name || selected.attack_chain_id}
          incidentId={incidentId}
        />
      ) : null}
    </Panel>
  );
}

function ChainView({
  coverage,
  campaignName,
  incidentId,
}: {
  coverage: MitreIncidentCoverage;
  campaignName: string;
  incidentId: string;
}) {
  if (coverage.chain.length === 0) {
    return (
      <StatusState
        variant="empty"
        title="No observed tactics on this chain"
        description="This incident hasn't surfaced any mapped ATT&CK tactic yet, so there's no kill-chain span to score."
      />
    );
  }

  return (
    <div>
      {/* summary line — "this chain · N/M · weakest = X" */}
      <div className="mb-2.5 flex flex-wrap items-center gap-2 text-data">
        <Chip mono aria-label={`member incident ${incidentId}`}>{incidentId}</Chip>
        <span className="text-dim">
          <b className="text-ink">{campaignName}</b> · this chain{" "}
          <b className="text-ink tabular">
            {coverage.covered_count}/{coverage.chain_length}
          </b>{" "}
          stages covered
          {coverage.weakest_tactic ? (
            <>
              {" "}
              · weakest = <b className="text-sev-med">{coverage.weakest_tactic}</b>
            </>
          ) : null}
        </span>
      </div>

      {/* stages */}
      <ol className="flex flex-col gap-1.5">
        {coverage.chain.map((stage, i) => {
          const isGap = stage.is_gap === true;
          const orgBand = coverageBand(stage.org_coverage_pct);
          return (
            <li
              key={`${stage.tactic}-${i}`}
              className="flex items-center gap-2.5 rounded-lg border border-line bg-panel px-3 py-2"
            >
              <span
                className={
                  isGap ? "text-sev-med" : "text-teal"
                }
                aria-hidden="true"
              >
                {isGap ? "▦" : "◉"}
              </span>
              <div className="min-w-0 flex-1">
                <div className="text-data text-ink">
                  {stage.tactic}{" "}
                  <span className="font-mono text-kbd text-dim2">
                    {stage.tactic_id}
                  </span>
                </div>
                <div className="text-kbd text-dim2">
                  {stage.present_in_incident
                    ? "observed in this incident"
                    : "not observed — intermediate blind spot"}
                  {isGap ? (
                    <span className="text-sev-med"> · gap</span>
                  ) : (
                    <span className="text-teal"> · covered</span>
                  )}
                </div>
              </div>
              {/* ORG-WIDE coverage — explicitly labelled, never incident-specific */}
              <div className="shrink-0 text-right">
                {stage.org_coverage_pct != null ? (
                  <span className={`text-data tabular ${coverageTextClass(orgBand)}`}>
                    {stage.org_coverage_pct}%
                  </span>
                ) : (
                  <span className="text-kbd text-dim2">n/a</span>
                )}
                <div className="text-micro text-dim2">org-wide</div>
              </div>
            </li>
          );
        })}
      </ol>

      <div className="mt-2 text-kbd text-dim2">
        Coverage basis: <b>{coverage.coverage_basis}</b>. The per-stage % is your
        ORG-WIDE detection coverage for that tactic (reused overlay), not this
        incident&apos;s — a stage is a gap when it&apos;s an unseen intermediate
        tactic or its org coverage is weak.
      </div>
    </div>
  );
}

// ---- Per-tactic uncovered-technique drill-down (optional /api/mitre/gaps) ----

function GapDrillDialog({
  tactic,
  onClose,
}: {
  tactic: MitreTacticCoverage | null;
  onClose: () => void;
}) {
  const [gaps, setGaps] = useState<MitreGaps | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  // Refetch guard as a REF (not `gaps`): the gaps corpus is a one-shot cache.
  // Using `gaps` as the guard would also make it an effect dep, and then the
  // setGaps re-run's cleanup would flip `cancelled` in the microtask between
  // .then and .finally — stranding `loading` at true. A ref guard keeps the
  // effect keyed on `tactic` ALONE, so nothing cancels its own in-flight read.
  const fetchedRef = useRef(false);

  // Lazy-fetch the gaps corpus once, the first time any tactic tile is opened.
  useEffect(() => {
    if (!tactic || fetchedRef.current) return;
    fetchedRef.current = true;
    let cancelled = false;
    setLoading(true);
    setError(null);
    getMitreGaps()
      .then((g) => {
        if (!cancelled) setGaps(g);
      })
      .catch((e) => {
        if (!cancelled) setError(errMessage(e));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [tactic]);

  const techniques = tactic && gaps ? gaps.gaps[tactic.tactic] ?? [] : [];

  return (
    <Dialog
      open={tactic !== null}
      onClose={onClose}
      title={tactic ? `${tactic.tactic} — uncovered techniques` : undefined}
      maxWidth={480}
    >
      {tactic && (
        <div>
          <div className="mb-2 flex items-center gap-2 text-kbd text-dim2">
            <Chip mono>{tactic.tactic_id}</Chip>
            <span className={coverageTextClass(coverageBand(tactic.coverage_pct))}>
              {tactic.coverage_pct}% coverage
            </span>
            <span>
              · {tactic.detected}/{tactic.total} techniques detected
            </span>
          </div>

          {loading ? (
            <StatusState variant="loading" title="Loading uncovered techniques…" />
          ) : error ? (
            <StatusState
              variant="error"
              title="Couldn't load the gap list"
              description={error}
            />
          ) : techniques.length === 0 ? (
            <p className="text-data text-dim">
              No uncovered techniques recorded for this tactic — either every
              tracked technique here has a detection, or the gap analyzer has no
              entry for it. Nothing is inferred.
            </p>
          ) : (
            <ul className="flex flex-col gap-1.5">
              {techniques.map((t) => (
                <li
                  key={t.id}
                  className="flex items-center gap-2.5 rounded-lg border border-line bg-panel2 px-3 py-2"
                >
                  <Chip mono aria-label={`technique ${t.id}`}>{t.id}</Chip>
                  <span className="text-data text-ink">{t.name}</span>
                </li>
              ))}
            </ul>
          )}

          <div className="mt-3 text-kbd text-dim2">
            Uncovered = techniques with zero detections in this tenant
            (GET /api/mitre/gaps). Read-only — closing a gap is detection
            engineering work, done in the Detection tab.
          </div>
        </div>
      )}
    </Dialog>
  );
}

// =============================================================================
// Compliance Frameworks (WO-U16) — the MITRE tab's second segment
// -----------------------------------------------------------------------------
// READ-ONLY. Two GETs, both `require_role("admin","senior_analyst")` +
// `require_license_feature("compliance_sca")`:
//   - GET /api/compliance/matrix              → frameworks → controls (STRUCTURE)
//   - GET /api/compliance/{framework}/coverage → per-framework detection coverage
// This segment gates INDEPENDENTLY of the tab: below senior_analyst it shows a
// role-locked state; a runtime 402/403 (tier lacks `compliance_sca`) degrades it
// to FeatureLockedState — neither affects the ATT&CK segment. The matrix loads
// only when this view MOUNTS (segment first selected), so the tab mount never
// fires the compliance calls. "Uncovered" is a GAP → neutral/amber (never
// red-as-severity, WO-U1), reusing the tab's coverage tokens.
// =============================================================================

interface ComplianceMatrixState {
  matrix: ComplianceMatrix | null;
  error: string | null;
  locked: boolean;
  loading: boolean;
}

interface FrameworkCoverageState {
  coverage: FrameworkCoverage | null;
  error: string | null;
  loading: boolean;
}

function ComplianceView() {
  const { role } = useAuth();
  const roleAllowed = roleAtLeast(role, "senior_analyst");

  const [state, setState] = useState<ComplianceMatrixState>({
    matrix: null,
    error: null,
    locked: false,
    loading: true,
  });
  const [selected, setSelected] = useState<string | null>(null);
  const [cov, setCov] = useState<FrameworkCoverageState>({
    coverage: null,
    error: null,
    loading: false,
  });
  const [secondsAgo, setSecondsAgo] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const covAbortRef = useRef<AbortController | null>(null);

  // ---- matrix load (lazy: fires on mount, i.e. when the segment is selected) --
  const loadMatrix = useCallback(
    async (manual: boolean) => {
      if (!roleAllowed) return; // role-locked → never call an endpoint the server 403s
      abortRef.current?.abort();
      const ac = new AbortController();
      abortRef.current = ac;
      if (manual) setRefreshing(true);
      try {
        const matrix = await getComplianceMatrix(ac.signal);
        if (ac.signal.aborted) return;
        setState({ matrix, error: null, locked: false, loading: false });
        setSecondsAgo(0);
      } catch (e) {
        if (ac.signal.aborted) return;
        // Tier gate (`compliance_sca`) → lock THIS segment only (never a broken
        // matrix / fabricated coverage). ATT&CK is a separate segment, untouched.
        if (isLockError(e)) {
          setState({ matrix: null, error: null, locked: true, loading: false });
          return;
        }
        const msg = errMessage(e);
        setState((prev) =>
          prev.matrix
            ? { ...prev, loading: false }
            : { matrix: null, error: msg, locked: false, loading: false },
        );
      } finally {
        if (!ac.signal.aborted) setRefreshing(false);
      }
    },
    [roleAllowed],
  );

  // Initial fetch + auto-poll (mirrors the ATT&CK segment's 30s cadence).
  useEffect(() => {
    if (!roleAllowed) return;
    loadMatrix(false);
    const poll = setInterval(() => loadMatrix(false), POLL_MS);
    return () => {
      clearInterval(poll);
      abortRef.current?.abort();
    };
  }, [roleAllowed, loadMatrix]);

  useEffect(() => {
    const t = setInterval(() => setSecondsAgo((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, []);

  // ---- per-framework coverage drill (on selection; re-fetches on manual refresh) --
  const loadCoverage = useCallback((framework: string) => {
    covAbortRef.current?.abort();
    const ac = new AbortController();
    covAbortRef.current = ac;
    setCov((c) => ({ ...c, loading: true, error: null }));
    getFrameworkCoverage(framework, ac.signal)
      .then((coverage) => {
        if (ac.signal.aborted) return;
        setCov({ coverage, error: null, loading: false });
      })
      .catch((e) => {
        if (ac.signal.aborted) return;
        // A bad/removed framework name → 404: honest error, never a faked table.
        const msg =
          e instanceof ApiError && e.status === 404
            ? `Framework "${framework}" is no longer in the compliance mapping.`
            : errMessage(e);
        setCov({ coverage: null, error: msg, loading: false });
      });
  }, []);

  useEffect(() => {
    if (!selected) {
      covAbortRef.current?.abort();
      setCov({ coverage: null, error: null, loading: false });
      return;
    }
    loadCoverage(selected);
    return () => covAbortRef.current?.abort();
  }, [selected, loadCoverage]);

  const onUpgrade = useCallback(() => {
    if (typeof window !== "undefined") {
      window.open("https://securesleuths.in/pricing", "_blank", "noreferrer");
    }
  }, []);

  const { matrix, error, locked, loading } = state;
  const frameworks = matrix ? Object.keys(matrix.frameworks) : [];

  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PageHeading
          title="Compliance frameworks"
          sub="Per-framework control coverage — which compliance controls your detections actually cover, computed from real decisions over the last 30 days."
        />
        {roleAllowed && !locked && (
          <PollingStatus
            className="mt-1"
            secondsAgo={secondsAgo}
            refreshing={refreshing}
            onRefresh={() => {
              loadMatrix(true);
              if (selected) loadCoverage(selected);
            }}
          />
        )}
      </div>

      {!roleAllowed ? (
        <StatusState
          variant="degraded"
          icon={<Lock className="h-7 w-7" aria-hidden="true" />}
          title="Compliance coverage requires a senior analyst"
          description="This view is restricted to senior_analyst and above — the server rejects the compliance endpoints for your role (403). The ATT&CK Coverage view remains available from the toggle above."
        />
      ) : locked ? (
        <FeatureLockedState
          feature="Compliance coverage"
          tier="current"
          onUpgrade={onUpgrade}
        />
      ) : loading && !matrix ? (
        <StatusState variant="loading" title="Loading compliance frameworks…" />
      ) : error && !matrix ? (
        <StatusState
          variant="error"
          title="Couldn't load compliance frameworks"
          description={error}
          action={<Chip onClick={() => loadMatrix(true)}>Retry</Chip>}
        />
      ) : matrix && frameworks.length === 0 ? (
        <StatusState
          variant="empty"
          title="No compliance frameworks configured"
          description="This install has no compliance mapping (config/governance/compliance_mapping.yaml is absent or empty), so there are no frameworks to score. Nothing is inferred."
        />
      ) : matrix ? (
        selected ? (
          <FrameworkCoverageDetail
            framework={selected}
            controlCount={matrix.frameworks[selected]?.length ?? 0}
            cov={cov}
            onBack={() => setSelected(null)}
            onRetry={() => loadCoverage(selected)}
          />
        ) : (
          <FrameworkList
            matrix={matrix}
            frameworks={frameworks}
            onSelect={setSelected}
          />
        )
      ) : null}
    </>
  );
}

/** The framework picker — one card per framework, showing its control count. */
function FrameworkList({
  matrix,
  frameworks,
  onSelect,
}: {
  matrix: ComplianceMatrix;
  frameworks: string[];
  onSelect: (framework: string) => void;
}) {
  return (
    <Panel className="p-4">
      <div className="mb-2.5 text-kbd text-dim2">
        Pick a framework to compute its per-control detection coverage. Coverage %
        rides the same neutral band scale as ATT&amp;CK coverage — it is not a
        severity. Read-only.
      </div>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {frameworks.map((name) => {
          const controls: ComplianceControl[] = matrix.frameworks[name] ?? [];
          return (
            <button
              key={name}
              type="button"
              onClick={() => onSelect(name)}
              aria-label={`${name}: ${controls.length} controls. Compute detection coverage.`}
              className={cn(
                "flex flex-col rounded-lg border border-line bg-panel2 p-3 text-left transition hover:brightness-110",
                focusRing,
              )}
            >
              <div className="text-data font-medium text-ink">{name}</div>
              <div className="mt-1 text-kbd text-dim2 tabular">
                {fmtInt(controls.length)} control
                {controls.length === 1 ? "" : "s"} mapped
              </div>
              <div className="mt-2 text-micro text-acc">View coverage →</div>
            </button>
          );
        })}
      </div>
    </Panel>
  );
}

/** The per-control coverage table for one selected framework. */
function FrameworkCoverageDetail({
  framework,
  controlCount,
  cov,
  onBack,
  onRetry,
}: {
  framework: string;
  controlCount: number;
  cov: FrameworkCoverageState;
  onBack: () => void;
  onRetry: () => void;
}) {
  const { coverage, error, loading } = cov;
  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-3">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onBack}
            aria-label="Back to the framework list"
            className={cn(
              "rounded-md border border-line bg-field px-2 py-0.5 text-kbd text-ink hover:bg-hover",
              focusRing,
            )}
          >
            ← Frameworks
          </button>
          <div className="text-title text-ink">{framework}</div>
        </div>
        {coverage && <ComplianceHeadline coverage={coverage} />}
      </div>

      {loading && !coverage ? (
        <div className="px-4 pb-4 pt-3">
          <StatusState variant="loading" title="Computing control coverage…" />
        </div>
      ) : error && !coverage ? (
        <div className="px-4 pb-4 pt-3">
          <StatusState
            variant="error"
            title="Couldn't compute coverage for this framework"
            description={error}
            action={<Chip onClick={onRetry}>Retry</Chip>}
          />
        </div>
      ) : coverage && coverage.controls.length === 0 ? (
        <div className="px-4 pb-4 pt-2 text-data text-dim2">
          {framework} maps {fmtInt(controlCount)} control
          {controlCount === 1 ? "" : "s"}, but the coverage computation returned no
          rows for this tenant. Nothing is inferred.
        </div>
      ) : coverage ? (
        <>
          <Table className="mt-2">
            <THead>
              <TR>
                <TH>Control</TH>
                <TH>Covered</TH>
                <TH className="text-right">Detections (30d)</TH>
                <TH>Mapped techniques</TH>
              </TR>
            </THead>
            <TBody>
              {coverage.controls.map((c) => (
                <ControlRow key={c.control_id} control={c} />
              ))}
            </TBody>
          </Table>
          <div className="px-4 py-3 text-kbd text-dim2">
            &quot;Covered&quot; = ≥1 matching detection in the last 30 days for the
            control&apos;s rule groups / mapped ATT&amp;CK techniques
            (GET /api/compliance/{framework}/coverage). An uncovered control is a
            detection GAP (neutral/amber), not a severity. Read-only — closing a
            gap is Detection-tab work.
          </div>
        </>
      ) : null}
    </Panel>
  );
}

/** Headline coverage % + covered/total, on the neutral coverage band scale. */
function ComplianceHeadline({ coverage }: { coverage: FrameworkCoverage }) {
  const band = coverageBand(coverage.coverage_pct);
  return (
    <span className="text-kbd text-dim2">
      <b className={coverageTextClass(band)}>{coverage.coverage_pct}%</b> covered ·{" "}
      <b className="text-ink tabular">
        {fmtInt(coverage.covered_controls)}/{fmtInt(coverage.total_controls)}
      </b>{" "}
      controls
      <span className="ml-2 inline-block h-1.5 w-16 overflow-hidden rounded-pill bg-bar align-middle">
        <span
          className={cn("block h-full rounded-pill", coverageBarClass(band))}
          style={{
            width: `${Math.max(0, Math.min(100, coverage.coverage_pct))}%`,
          }}
        />
      </span>
    </span>
  );
}

/** One control row: id/name, a covered ✓/gap indicator, detections, techniques. */
function ControlRow({ control }: { control: FrameworkControlCoverage }) {
  const covered = control.covered;
  const techniques = control.mitre_techniques ?? [];
  return (
    <TR>
      <TD>
        <div className="flex items-center gap-2">
          <Chip mono aria-label={`control ${control.control_id}`}>
            {control.control_id}
          </Chip>
          <span className="text-ink">{control.control_name}</span>
        </div>
        {control.description && (
          <div className="mt-0.5 max-w-[560px] text-kbd text-dim2">
            {control.description}
          </div>
        )}
      </TD>
      <TD>
        {covered ? (
          <span className="text-meta font-semibold text-teal">
            <span aria-hidden="true">✓</span> covered
          </span>
        ) : (
          // Uncovered is a GAP, not a severity — neutral/amber, never red (WO-U1).
          <span className="text-meta font-semibold text-sev-med">
            <span aria-hidden="true">▦</span> gap
          </span>
        )}
      </TD>
      <TD mono className="text-right">
        {covered ? (
          fmtInt(control.detection_count)
        ) : (
          <span className="text-dim2">{fmtInt(control.detection_count)}</span>
        )}
      </TD>
      <TD>
        {techniques.length === 0 ? (
          <span className="text-kbd text-dim2">{DASH}</span>
        ) : (
          <div className="flex flex-wrap gap-1">
            {techniques.map((t) => (
              <Chip key={t} mono aria-label={`technique ${t}`}>
                {t}
              </Chip>
            ))}
          </div>
        )}
      </TD>
    </TR>
  );
}
