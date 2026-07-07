import type { ReactNode } from "react";
import { cn, focusRing } from "@/lib/ui";

/**
 * Chip — the mockup's `.chip`: a small bordered token for metadata, filters,
 * and inline actions. Renders as a `<span>` by default, or an accessible
 * `<button>` when `onClick` is supplied.
 *
 * Variants map to token surfaces:
 *  - default  neutral field chip
 *  - grounded teal "positive / grounded" (e.g. "✓ logtest: PASS", "Grounded")
 *  - violet   campaign / correlation ("part of campaign …")
 *  - cite     citation-style blue
 *  - gated    warm "human-approved / gated" active-response marker
 *
 * @example <Chip icon={<Building2 />}>Tenant Acme</Chip>
 * @example <Chip variant="grounded">Grounded</Chip>
 * @example <Chip onClick={open} variant="cite">Open Triage ›</Chip>
 */
export type ChipVariant = "default" | "grounded" | "violet" | "cite" | "gated";

export interface ChipProps {
  children: ReactNode;
  variant?: ChipVariant;
  /** leading icon (e.g. a lucide-react icon element) */
  icon?: ReactNode;
  /** use monospace + tabular-nums (ids, hashes, T-codes) */
  mono?: boolean;
  /** makes the chip an accessible button */
  onClick?: () => void;
  disabled?: boolean;
  /** required accessible name when the visible content is not descriptive */
  "aria-label"?: string;
  className?: string;
}

const VARIANT: Record<ChipVariant, string> = {
  default: "border-line bg-field text-ink",
  grounded: "border-grounded-border bg-field text-grounded-ink",
  violet: "border-violet/40 bg-field text-violet",
  cite: "border-cite-border bg-cite-bg text-cite-ink",
  gated: "border-gated-border bg-field text-gated-ink",
};

export function Chip({
  children,
  variant = "default",
  icon,
  mono = false,
  onClick,
  disabled = false,
  "aria-label": ariaLabel,
  className,
}: ChipProps) {
  const base = cn(
    "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-meta",
    VARIANT[variant],
    mono && "font-mono tabular",
    className,
  );

  if (onClick) {
    return (
      <button
        type="button"
        onClick={onClick}
        disabled={disabled}
        aria-label={ariaLabel}
        className={cn(
          base,
          focusRing,
          disabled ? "cursor-not-allowed opacity-50" : "cursor-pointer hover:brightness-125",
        )}
      >
        {icon && <span className="inline-flex shrink-0">{icon}</span>}
        {children}
      </button>
    );
  }

  return (
    <span className={base} aria-label={ariaLabel}>
      {icon && <span className="inline-flex shrink-0">{icon}</span>}
      {children}
    </span>
  );
}

/**
 * Pill — the tiny `.pill` used inside the kill-chain lane (host names, T-codes,
 * projection labels). Smaller than Chip and never interactive.
 *
 * @example <Pill mono>T1003</Pill>  <Pill>WIN-APP-03</Pill>
 */
export interface PillProps {
  children: ReactNode;
  mono?: boolean;
  /** inline colour override for severity/violet-tinted pills */
  color?: string;
  borderColor?: string;
  dashed?: boolean;
  className?: string;
}

export function Pill({
  children,
  mono = false,
  color,
  borderColor,
  dashed = false,
  className,
}: PillProps) {
  return (
    <span
      className={cn(
        "whitespace-nowrap rounded-sm border bg-field px-1.5 py-px text-micro tracking-wide",
        !borderColor && "border-line",
        dashed && "border-dashed",
        mono && "font-mono tabular",
        className,
      )}
      style={{ color, borderColor }}
    >
      {children}
    </span>
  );
}
