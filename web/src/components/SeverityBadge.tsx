import { cn } from "@/lib/ui";
import { SEVERITY, severityLabel, type Severity } from "@/lib/severity";

/**
 * SeverityBadge — the `sevTag` from the mockup, as a typed primitive.
 *
 * Renders GLYPH + LABEL + colour together. This is the only sanctioned way to
 * show severity: never paint `sev.*` colour without this pairing (a11y
 * invariant — colour must never be the sole carrier of meaning).
 *
 * @example
 *   <SeverityBadge severity="crit" />                 // ◆ P0 · Critical
 *   <SeverityBadge severity="high" label="P1" />      // ▲ P1  (legend chip)
 *   <SeverityBadge severity="med" glyphOnly aria-label="Medium" /> // ■ (table cell)
 */
export interface SeverityBadgeProps {
  severity: Severity;
  /** Override the text (defaults to the full `"P0 · Critical"` label). */
  label?: string;
  /** Show only the glyph (e.g. a dense table cell). Still colour + shape. */
  glyphOnly?: boolean;
  /** Accessible name — REQUIRED when `glyphOnly` (screen readers need words). */
  "aria-label"?: string;
  className?: string;
}

export function SeverityBadge({
  severity,
  label,
  glyphOnly = false,
  "aria-label": ariaLabel,
  className,
}: SeverityBadgeProps) {
  const meta = SEVERITY[severity];
  const text = label ?? severityLabel(severity);

  if (glyphOnly) {
    return (
      <span
        className={cn(meta.textClass, "text-[12px] font-semibold", className)}
        // glyph alone is not readable text → expose the word to AT
        aria-label={ariaLabel ?? meta.label}
        role="img"
        title={ariaLabel ?? meta.label}
      >
        {meta.glyph}
      </span>
    );
  }

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 text-[12px] font-semibold",
        meta.textClass,
        className,
      )}
    >
      <span aria-hidden="true">{meta.glyph}</span>
      <span>{text}</span>
    </span>
  );
}
