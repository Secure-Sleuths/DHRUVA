import { cn } from "@/lib/ui";
import {
  confidenceColor,
  confidenceTier,
  formatConfidence,
} from "@/lib/confidence";

/**
 * ConfidenceBar — a model-confidence meter on the NEUTRAL blue→teal ramp.
 *
 * Kept deliberately off the severity scale so it can never read as "critical".
 * Shows a tabular-nums value by default. Exposed to AT as a `progressbar` with
 * the 0..1 value described in words.
 *
 * @example <ConfidenceBar value={0.86} />            // 0.86, teal fill
 * @example <ConfidenceBar value={0.55} width={56} showValue={false} />
 */
export interface ConfidenceBarProps {
  /** confidence in [0, 1] */
  value: number;
  /** show the numeric value beside the bar (default true) */
  showValue?: boolean;
  /** fixed track width in px; omit to fill the container */
  width?: number;
  className?: string;
}

export function ConfidenceBar({
  value,
  showValue = true,
  width,
  className,
}: ConfidenceBarProps) {
  const clamped = Math.max(0, Math.min(1, value));
  const pct = Math.round(clamped * 100);
  const tier = confidenceTier(clamped);
  const label = `confidence ${formatConfidence(clamped)} (${tier})`;

  return (
    <div className={cn("flex items-center gap-2", className)}>
      {showValue && (
        <span className="tabular font-mono text-data text-ink">
          {formatConfidence(clamped)}
        </span>
      )}
      <div
        className="h-[6px] flex-1 overflow-hidden rounded-pill bg-bar"
        style={width ? { width, flex: "none" } : undefined}
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={1}
        aria-valuenow={clamped}
        aria-label={label}
      >
        <span
          className="block h-full rounded-pill"
          style={{ width: `${pct}%`, background: confidenceColor(clamped) }}
        />
      </div>
    </div>
  );
}
