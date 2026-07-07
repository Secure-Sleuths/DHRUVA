import type { ReactNode } from "react";
import {
  AlertTriangle,
  Inbox,
  Loader2,
  Lock,
  RefreshCw,
  WifiOff,
} from "lucide-react";
import { cn, focusRing } from "@/lib/ui";

/**
 * StatusState — the empty / loading / error / degraded placeholders every data
 * surface falls back to. One primitive, four `variant`s, so the states look
 * consistent across screens.
 *
 *  - empty     nothing to show yet (no alerts in queue, etc.)
 *  - loading   first fetch in flight (spinner respects reduced-motion)
 *  - error     fetch failed — offer a retry
 *  - degraded  partial/stale data or a gated feature (amber)
 *
 * @example <StatusState variant="loading" title="Loading triage queue…" />
 * @example <StatusState variant="error" title="Couldn't load incidents"
 *            action={<button onClick={retry}>Retry</button>} />
 */
export type StatusVariant = "empty" | "loading" | "error" | "degraded";

export interface StatusStateProps {
  variant: StatusVariant;
  title: ReactNode;
  description?: ReactNode;
  /** e.g. a retry / upgrade button */
  action?: ReactNode;
  /** override the default icon for the variant */
  icon?: ReactNode;
  className?: string;
}

const ICONS: Record<StatusVariant, ReactNode> = {
  empty: <Inbox className="h-7 w-7" aria-hidden="true" />,
  loading: <Loader2 className="h-7 w-7 animate-spin" aria-hidden="true" />,
  error: <AlertTriangle className="h-7 w-7" aria-hidden="true" />,
  degraded: <WifiOff className="h-7 w-7" aria-hidden="true" />,
};

const TONE: Record<StatusVariant, string> = {
  empty: "text-dim2",
  loading: "text-dim",
  error: "text-sev-crit",
  degraded: "text-sev-med",
};

export function StatusState({
  variant,
  title,
  description,
  action,
  icon,
  className,
}: StatusStateProps) {
  return (
    <div
      className={cn(
        "flex flex-col items-center gap-2.5 rounded-xl border border-line bg-panel px-6 py-11 text-center",
        className,
      )}
      role={variant === "error" ? "alert" : "status"}
      aria-live={variant === "loading" ? "polite" : undefined}
    >
      <span className={TONE[variant]}>{icon ?? ICONS[variant]}</span>
      <div className="max-w-[560px] text-body font-medium text-ink">{title}</div>
      {description && (
        <div className="max-w-[560px] text-data text-dim">{description}</div>
      )}
      {action && <div className="mt-1">{action}</div>}
    </div>
  );
}

/**
 * PollingStatus — the "refreshed Ns ago · refresh" affordance for a product
 * that POLLS (no push channel). Shows a live dot, the age of the last refresh,
 * and a manual Refresh button. Screens pass the age they track + an `onRefresh`
 * handler; while refreshing the button shows a spinner and is disabled.
 *
 * @example <PollingStatus secondsAgo={22} onRefresh={refresh} refreshing={busy} />
 */
export interface PollingStatusProps {
  /** seconds since the last successful poll */
  secondsAgo: number;
  onRefresh?: () => void;
  /** a refresh is currently in flight */
  refreshing?: boolean;
  /** show the "polling" prefix + dot (default true) */
  polling?: boolean;
  /** the feature is degraded — show amber "stale" instead of a live dot */
  stale?: boolean;
  className?: string;
}

export function PollingStatus({
  secondsAgo,
  onRefresh,
  refreshing = false,
  polling = true,
  stale = false,
  className,
}: PollingStatusProps) {
  return (
    <div className={cn("flex items-center gap-2 text-kbd text-dim2", className)}>
      {polling && (
        <span
          className={cn("text-[10px]", stale ? "text-sev-med" : "text-teal")}
          aria-hidden="true"
        >
          ●
        </span>
      )}
      <span aria-live="polite">
        {stale ? "stale · " : polling ? "polling · " : ""}
        refreshed {secondsAgo}s ago
      </span>
      {onRefresh && (
        <button
          type="button"
          onClick={onRefresh}
          disabled={refreshing}
          aria-label="Refresh now"
          className={cn(
            "inline-flex items-center gap-1 rounded-md border border-line bg-field px-2 py-0.5 text-kbd text-ink hover:bg-hover",
            refreshing && "cursor-not-allowed opacity-60",
            focusRing,
          )}
        >
          <RefreshCw
            className={cn("h-3 w-3", refreshing && "animate-spin")}
            aria-hidden="true"
          />
          Refresh
        </button>
      )}
    </div>
  );
}

/**
 * FeatureLockedState — the tier-gate "paid feature" placeholder (amber). Used
 * when a whole surface is license-locked; pairs with `Dialog` for the upsell.
 */
export function FeatureLockedState({
  feature,
  tier,
  onUpgrade,
  className,
}: {
  feature: string;
  tier: string;
  onUpgrade?: () => void;
  className?: string;
}) {
  return (
    <StatusState
      variant="degraded"
      icon={<Lock className="h-7 w-7" aria-hidden="true" />}
      title={`${feature} is a paid feature`}
      description={`Not included in the ${tier} tier. Upgrade to unlock it.`}
      action={
        onUpgrade && (
          <button
            type="button"
            onClick={onUpgrade}
            className={cn(
              "rounded-md border-none bg-[#25406a] px-4 py-2 text-data text-white hover:brightness-110",
              focusRing,
            )}
          >
            Upgrade to unlock
          </button>
        )
      }
      className={className}
    />
  );
}
