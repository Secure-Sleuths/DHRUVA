import { SEVERITY, type Severity } from "@/lib/severity";
import {
  PROJECTION_LABEL,
  type Campaign,
  type ObservedNode,
  type ProjectedNode,
} from "@/lib/campaign";
import { cn, focusRing } from "@/lib/ui";
import { Pill } from "./Chip";

/**
 * KillChainLane — the campaign hero viz (mockup's `laneSVG`), typed.
 *
 * A horizontal kill-chain lane: OBSERVED nodes (severity dot + glyph, T-code
 * pill, host pill) connected along a time axis, followed by DASHED PROJECTED
 * nodes (violet, "possible / likely / watch"). Projections are visually
 * distinct AND labelled — they are the correlation engine's heuristic guess at
 * where the campaign could go next, and are NEVER auto-actioned.
 *
 * Every node is a keyboard-operable button with a descriptive aria-label;
 * clicking calls back with the node so the parent can open a detail Dialog.
 *
 * @example
 *   <KillChainLane campaign={c} onNodeClick={(n) => openDetail(n)} />
 */
export interface KillChainNodeRef {
  campaignId: string;
  index: number;
  projected: boolean;
  node: ObservedNode | ProjectedNode;
}

export interface KillChainLaneProps {
  campaign: Campaign;
  /** invoked when a node (observed or projected) is activated */
  onNodeClick?: (ref: KillChainNodeRef) => void;
  /** render projected nodes (default true) */
  showProjections?: boolean;
  /** lane height in px (default 92) */
  height?: number;
  className?: string;
}

export function KillChainLane({
  campaign,
  onNodeClick,
  showProjections = true,
  height = 92,
  className,
}: KillChainLaneProps) {
  const midY = height / 2;
  const sevColor = SEVERITY[campaign.severity].color;
  const seq: Array<ObservedNode | ProjectedNode> = showProjections
    ? [...campaign.steps, ...campaign.proj]
    : campaign.steps;

  return (
    <div>
      <div
        className={cn(
          "relative rounded-xl border border-line bg-panel2 px-3.5",
          className,
        )}
        style={{ height, paddingTop: 22, paddingBottom: 30, marginTop: 6 }}
        role="group"
        aria-label={`Kill-chain lane for ${campaign.id}: ${campaign.steps.length} observed step(s), ${campaign.proj.length} projected`}
      >
        {/* time ticks (observed only; omitted when the source has no timestamp) */}
        {campaign.steps.map((s, i) =>
          s.when ? (
            <span
              key={`tick-${i}`}
              className="absolute -translate-x-1/2 text-micro text-dim2"
              style={{ left: `${s.x}%`, top: -16 }}
            >
              {s.when}
            </span>
          ) : null,
        )}

        {/* baseline */}
        <div
          className="absolute left-0 right-0 h-px bg-bar"
          style={{ top: midY }}
        />

        {/* connectors */}
        {seq.slice(0, -1).map((a, i) => {
          const b = seq[i + 1];
          const isProj = i >= campaign.steps.length - 1;
          return (
            <div
              key={`conn-${i}`}
              className="absolute h-0.5 -translate-y-1/2"
              style={{
                left: `${a.x}%`,
                width: `${b.x - a.x}%`,
                top: midY,
                background: isProj
                  ? "repeating-linear-gradient(90deg, #a78bfa 0 5px, transparent 5px 10px)"
                  : sevColor,
                opacity: isProj ? 0.75 : 1,
              }}
            />
          );
        })}

        {/* observed nodes */}
        {campaign.steps.map((s, i) => {
          const meta = SEVERITY[s.severity];
          return (
            <button
              key={`obs-${i}`}
              type="button"
              onClick={() =>
                onNodeClick?.({
                  campaignId: campaign.id,
                  index: i,
                  projected: false,
                  node: s,
                })
              }
              aria-label={`${s.tid ? `${s.tid} ` : ""}${s.tname}${
                s.host ? ` on ${s.host}` : ""
              }, ${meta.label} severity${s.when ? `, observed ${s.when}` : ""}`}
              className={cn(
                "absolute flex -translate-x-1/2 -translate-y-1/2 cursor-pointer flex-col items-center gap-1",
                focusRing,
              )}
              style={{ left: `${s.x}%`, top: midY }}
            >
              <span
                className={cn(
                  "flex h-[18px] w-[18px] items-center justify-center rounded-full border-2 border-black/35 text-[9px] font-extrabold text-[#04121f]",
                  campaign.severity === "crit"
                    ? "shadow-glow-crit"
                    : "shadow-glow-high",
                )}
                style={{ background: meta.color }}
                aria-hidden="true"
              >
                {meta.glyph}
              </span>
              {/* label: technique code where present (mockup), else the tactic
                  name (real campaign data has tactics, not techniques) */}
              {s.tid ? (
                <Pill mono color={meta.color} borderColor={`${meta.color}44`}>
                  {s.tid}
                </Pill>
              ) : (
                <Pill color={meta.color} borderColor={`${meta.color}44`}>
                  {s.tname}
                </Pill>
              )}
              {s.host && <Pill className="text-dim">{s.host}</Pill>}
            </button>
          );
        })}

        {/* projected nodes — dashed violet, heuristic, never actioned */}
        {showProjections &&
          campaign.proj.map((s, i) => (
            <button
              key={`proj-${i}`}
              type="button"
              onClick={() =>
                onNodeClick?.({
                  campaignId: campaign.id,
                  index: i,
                  projected: true,
                  node: s,
                })
              }
              aria-label={`Projected ${s.tid ? `${s.tid} ` : ""}${s.tname}${
                s.host ? ` on ${s.host}` : ""
              }, ${PROJECTION_LABEL[s.prob]} — heuristic, never auto-actioned`}
              className={cn(
                "absolute flex -translate-x-1/2 -translate-y-1/2 cursor-pointer flex-col items-center gap-1",
                focusRing,
              )}
              style={{ left: `${s.x}%`, top: midY }}
            >
              <span
                className="flex h-[18px] w-[18px] items-center justify-center rounded-full border-2 border-dashed border-violet bg-transparent text-[10px] text-violet"
                aria-hidden="true"
              >
                ?
              </span>
              <Pill
                mono={Boolean(s.tid)}
                dashed
                color="#a78bfa"
                borderColor="#a78bfa55"
              >
                {s.tid ?? s.tname}
              </Pill>
              <Pill className="text-dim2">{PROJECTION_LABEL[s.prob]}</Pill>
            </button>
          ))}
      </div>

      {/* projection disclaimer — required label */}
      {showProjections && campaign.proj.length > 0 && (
        <div className="mt-1.5 flex items-center gap-1.5 text-kbd text-dim2">
          <span
            className="text-violet"
            aria-hidden="true"
            style={{ letterSpacing: "-1px" }}
          >
            ▦
          </span>
          <span>
            Dashed violet = projection ·{" "}
            <span className="text-violet">
              possible (heuristic) · never auto-actioned
            </span>
          </span>
        </div>
      )}
    </div>
  );
}

/** Convenience legend for the campaign map header (severity + projection). */
export function KillChainLegend({ className }: { className?: string }) {
  const levels: Severity[] = ["crit", "high", "med"];
  return (
    <div className={cn("flex items-center gap-3 text-kbd", className)}>
      {levels.map((s) => {
        const m = SEVERITY[s];
        return (
          <span key={s} className={cn("inline-flex items-center gap-1", m.textClass)}>
            <span aria-hidden="true">{m.glyph}</span> {m.p}
          </span>
        );
      })}
      <span className="text-violet">▦ dashed = projection</span>
    </div>
  );
}
