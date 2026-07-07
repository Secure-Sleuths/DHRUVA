"use client";

/**
 * OverviewTab (WO-U3) — the "Campaign Command" lens.
 *
 * Translates the approved mockup's `tOverview()`: a KPI tile strip on top
 * (every tile expands to its math), then the "Campaign map" — each active
 * attack-chain campaign rendered as a KillChainLane, worst-first.
 *
 * Composes the WO-U1 design system (Tile, KillChainLane/KillChainLegend, Panel,
 * SeverityBadge, Chip, StatusState, PollingStatus, Dialog) — no bespoke
 * primitives, no hard-coded hexes.
 *
 * Data (both un-gated by tier — Overview is available across tiers):
 *   - `GET /api/overview/summary` (WO-B7) → the KPI strip. Each tile is
 *     `{ value, ...supporting detail }`; the detail is the expand-to-math body.
 *   - `GET /api/campaigns` (WO-B5) → the campaign rollups, already worst-first.
 *     Each is adapted onto the KillChainLane `Campaign` viz via
 *     `campaign.ts::adaptCampaign`.
 *
 * The product polls (no websocket); a PollingStatus shows the age of the last
 * refresh + a manual refresh, and in-flight requests abort on unmount — mirrors
 * TriageTab.
 *
 * RBAC: overview is read_only+ (all roles, see TAB_ACCESS). This surface is
 * READ-only — no write action, no active-response affordance — so there is
 * nothing to gate here; projections are clearly labelled heuristic + never
 * auto-actioned.
 *
 * Honesty note: the campaign contract carries ordered TACTIC names only — no
 * per-node technique/host/confidence/"why". Those node details are omitted (not
 * fabricated); the per-node alert/verdict drill-down opens the member incident,
 * a future Work Order (WO-U4/U8) — see the TODOs on node/title clicks.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Chip,
  Dialog,
  KillChainLane,
  KillChainLegend,
  Panel,
  PollingStatus,
  SeverityBadge,
  StatusState,
  Tile,
} from "@/components";
import { PageHeading } from "../PageHeading";
import { getCampaigns, getOverviewSummary, ApiError } from "@/lib/api";
import { adaptCampaign } from "@/lib/campaign";
import { severityLabel, type Severity } from "@/lib/severity";
import type { TabProps } from "../tabRegistry";
import type { ApiCampaign, OverviewSummary } from "@/lib/types";
import type { Campaign } from "@/lib/campaign";
import type { KillChainNodeRef } from "@/components";

/** Auto-poll cadence (ms). The product polls; there is no push channel. */
const POLL_MS = 30_000;

interface OverviewState {
  summary: OverviewSummary | null;
  campaigns: ApiCampaign[] | null;
  error: string | null;
  loading: boolean;
}

export function OverviewTab({ onNavigate }: TabProps) {
  const [state, setState] = useState<OverviewState>({
    summary: null,
    campaigns: null,
    error: null,
    loading: true,
  });
  const [secondsAgo, setSecondsAgo] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const [nodeDetail, setNodeDetail] = useState<KillChainNodeRef | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async (manual: boolean) => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    if (manual) setRefreshing(true);
    try {
      // One refresh fans out to both reads; the KPI strip and the map are two
      // views of the same tenant state.
      const [summary, campaignsRes] = await Promise.all([
        getOverviewSummary(ac.signal),
        getCampaigns(ac.signal),
      ]);
      if (ac.signal.aborted) return;
      setState({
        summary,
        campaigns: campaignsRes.campaigns,
        error: null,
        loading: false,
      });
      setSecondsAgo(0);
    } catch (e) {
      if (ac.signal.aborted) return;
      const msg =
        e instanceof ApiError
          ? e.message
          : e instanceof Error
            ? e.message
            : "Unknown error";
      // Keep any previously-loaded data on a background poll failure; only fall
      // to the full error state when we have nothing to show yet.
      setState((prev) =>
        prev.summary || prev.campaigns
          ? { ...prev, loading: false }
          : {
              summary: null,
              campaigns: null,
              error: msg,
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

  const { summary, campaigns, error, loading } = state;

  // "open ›" → the Incidents case view. WO-U4 builds the glass-box case; until
  // it accepts a target, this navigates to the Incidents tab.
  // TODO(WO-U4): forward the campaign / member-incident id so Incidents opens it.
  const openCampaign = useCallback(
    (_campaign: Campaign) => onNavigate?.("incidents"),
    [onNavigate],
  );

  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PageHeading
          title="State of the estate"
          sub="Every active attack campaign as a kill-chain lane — tactics advancing across your assets over time. Every tile expands to its math."
        />
        <PollingStatus
          className="mt-1"
          secondsAgo={secondsAgo}
          refreshing={refreshing}
          onRefresh={() => load(true)}
        />
      </div>

      {loading && !summary && !campaigns ? (
        <StatusState variant="loading" title="Loading the estate…" />
      ) : error && !summary && !campaigns ? (
        <StatusState
          variant="error"
          title="Couldn't load the overview"
          description={error}
          action={<Chip onClick={() => load(true)}>Retry</Chip>}
        />
      ) : (
        <>
          {summary && <KpiStrip summary={summary} />}
          <CampaignMap campaigns={campaigns ?? []} onOpen={openCampaign} onNode={setNodeDetail} />
        </>
      )}

      {/* node detail — read-only, honest about the drill-down gap */}
      <NodeDetailDialog
        detail={nodeDetail}
        onClose={() => setNodeDetail(null)}
        onOpenIncident={() => {
          setNodeDetail(null);
          onNavigate?.("incidents");
        }}
      />
    </>
  );
}

// ---- KPI strip --------------------------------------------------------------

function KpiStrip({ summary }: { summary: OverviewSummary }) {
  const {
    active_campaigns: ac,
    estate_dwell_worst: dwell,
    hosts_on_chain: hosts,
    furthest_tactic: furthest,
    open_incidents: open,
  } = summary;

  const dwellCampaign = dwell.campaign?.name ?? dwell.campaign?.attack_chain_id;
  const furthestCampaign =
    furthest.campaign?.name ?? furthest.campaign?.attack_chain_id;

  return (
    <div className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
      {/* KPI 1 — Active campaigns */}
      <Tile
        label="Active campaigns"
        value={ac.value}
        valueSeverity={ac.value > 0 ? "crit" : undefined}
        sub={`${ac.advancing} advancing · ${ac.contained} contained`}
        math={
          <>
            Groups alerts by <span className="font-mono">attack_chain_id</span>{" "}
            (M5 correlation). {ac.value} tracked campaign
            {ac.value === 1 ? "" : "s"} — {ac.advancing} advancing (any member
            open/investigating) · {ac.contained} contained.
          </>
        }
      />

      {/* KPI 2 — Estate dwell (worst) */}
      <Tile
        label="Estate dwell (worst)"
        value={dwell.value ?? "—"}
        valueSeverity={dwell.value ? "high" : undefined}
        sub={dwellCampaign ? `${dwellCampaign} · worst open` : "no active dwell"}
        math={
          dwell.value ? (
            <>
              Worst-of open campaigns = now − first correlated alert on the
              chain. Driven by{" "}
              <b>{dwell.campaign?.name ?? "a campaign"}</b>
              {dwell.campaign?.attack_chain_id ? (
                <>
                  {" "}
                  (<span className="font-mono">{dwell.campaign.attack_chain_id}</span>)
                </>
              ) : null}
              . Contained chains are excluded.
            </>
          ) : (
            <>No active campaign has a measurable dwell right now.</>
          )
        }
      />

      {/* KPI 3 — Hosts on a chain (of_total is null → no fabricated denominator) */}
      <Tile
        label="Hosts on a chain"
        value={hosts.value}
        valueSeverity={hosts.value > 0 ? "med" : undefined}
        sub="distinct assets on an active chain"
        math={
          <>
            Distinct assets appearing in any active campaign step
            {hosts.hosts.length > 0 ? (
              <>
                : <span className="font-mono">{hosts.hosts.join(", ")}</span>
              </>
            ) : (
              " (none currently)"
            )}
            .
            <span className="mt-1 block text-dim2">
              Of a total monitored estate: not available here — agent inventory
              isn&apos;t counted by this endpoint, so no denominator is shown.
            </span>
          </>
        }
      />

      {/* KPI 4 — Furthest tactic reached */}
      <Tile
        label="Furthest tactic reached"
        value={furthest.value ?? "—"}
        valueSeverity={
          furthest.exfil_or_impact_reached
            ? "crit"
            : furthest.value
              ? "high"
              : undefined
        }
        sub={
          furthest.exfil_or_impact_reached
            ? "Exfil/Impact reached"
            : "no Exfil/Impact yet"
        }
        math={
          furthest.value ? (
            <>
              Max ATT&amp;CK stage across live chains, by canonical kill-chain
              order = <b>{furthest.value}</b>
              {furthestCampaign ? <> ({furthestCampaign})</> : null}.{" "}
              {furthest.exfil_or_impact_reached
                ? "Exfiltration / Impact has been reached."
                : "Exfiltration / Impact not yet observed — projected only."}
            </>
          ) : (
            <>No active campaign has advanced along the kill chain yet.</>
          )
        }
      />

      {/* KPI 5 — Open incidents */}
      <Tile
        label="Open incidents"
        value={open.value}
        valueSeverity={
          open.critical > 0 ? "crit" : open.value > 0 ? "high" : undefined
        }
        sub={`${open.critical} critical`}
        math={
          <>
            Incidents currently <span className="font-mono">open</span> or{" "}
            <span className="font-mono">investigating</span> for this tenant, of
            which {open.critical} {open.critical === 1 ? "is" : "are"} critical.
          </>
        }
      />
    </div>
  );
}

// ---- Campaign map -----------------------------------------------------------

function CampaignMap({
  campaigns,
  onOpen,
  onNode,
}: {
  campaigns: ApiCampaign[];
  onOpen: (c: Campaign) => void;
  onNode: (ref: KillChainNodeRef) => void;
}) {
  return (
    <Panel className="px-3.5 pb-2 pt-3.5">
      {/* header: title + severity/projection legend */}
      <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
        <b className="text-title">Campaign map</b>
        <KillChainLegend />
      </div>

      {/* axis labels (from the mockup) */}
      <div className="flex justify-between px-1 pb-0.5 text-micro uppercase tracking-[0.08em] text-dim2">
        <span>← Earlier</span>
        <span>Kill-chain progression →</span>
        <span>Where it could go</span>
      </div>

      {campaigns.length === 0 ? (
        <StatusState
          variant="empty"
          title="No active campaigns"
          description="The correlation engine hasn't linked any incidents into an attack chain right now."
        />
      ) : (
        campaigns.map((c) => {
          const adapted = adaptCampaign(c);
          return (
            <div key={c.attack_chain_id} className="border-t border-line py-2.5">
              <div className="mb-0.5 flex flex-wrap items-center gap-2.5">
                <SeverityBadge
                  severity={adapted.severity}
                  label={`${adapted.p} · ${adapted.plabel}`}
                />
                <button
                  type="button"
                  onClick={() => onOpen(adapted)}
                  className="font-semibold text-ink hover:underline"
                  aria-label={`Open incidents for campaign ${adapted.name} (${c.attack_chain_id})`}
                >
                  {adapted.name}
                </button>
                <Chip mono aria-label={`attack chain id ${c.attack_chain_id}`}>
                  {c.attack_chain_id}
                </Chip>
                <span className="flex-1" />
                <span className="text-kbd text-dim2">
                  {adapted.status} · dwell {adapted.dwell} · {c.alert_count}{" "}
                  alert{c.alert_count === 1 ? "" : "s"}
                </span>
              </div>
              <KillChainLane campaign={adapted} onNodeClick={onNode} />
            </div>
          );
        })
      )}

      <div className="mt-2 text-kbd text-dim2">
        Click a campaign title to open its case (Incidents). Dashed violet nodes
        are the correlation engine&apos;s projection — hunt candidates, never
        auto-actioned. Per-node alert + AI verdict is a drill-down to the member
        incident (coming in WO-U4).
      </div>
    </Panel>
  );
}

// ---- node detail dialog (read-only; honest about the drill-down gap) --------

function NodeDetailDialog({
  detail,
  onClose,
  onOpenIncident,
}: {
  detail: KillChainNodeRef | null;
  onClose: () => void;
  onOpenIncident: () => void;
}) {
  const node = detail?.node;
  const title = node ? node.tname : undefined;
  return (
    <Dialog open={detail !== null} onClose={onClose} title={title} maxWidth={480}>
      {detail &&
        node &&
        (detail.projected ? (
          <div>
            <Chip variant="violet" className="mb-2">
              Projected · heuristic
            </Chip>
            <p className="text-data text-dim">
              The correlation engine extrapolates this tactic as the next unseen
              step in canonical kill-chain order. It has <b>not fired</b> — a
              heuristic hint to prioritise hunting, never auto-actioned. No
              response is taken on projections.
            </p>
          </div>
        ) : (
          <div>
            <SeverityBadge
              severity={"severity" in node ? (node.severity as Severity) : "info"}
              label={severityLabel(
                "severity" in node ? (node.severity as Severity) : "info",
              )}
            />
            <p className="mt-2 text-data text-dim">
              Observed tactic in this campaign&apos;s kill chain (glyph severity
              is the campaign&apos;s). The alert + AI verdict behind this tactic
              lives on the member incident.
            </p>
            <p className="mt-2 text-kbd text-dim2">
              Per-node technique, host, confidence and the AI&apos;s
              &ldquo;why&rdquo; aren&apos;t in the campaign feed — they open on
              the glass-box case (WO-U4).
            </p>
            <div className="mt-3">
              <Chip variant="cite" onClick={onOpenIncident}>
                Open incident ›
              </Chip>
            </div>
          </div>
        ))}
    </Dialog>
  );
}
