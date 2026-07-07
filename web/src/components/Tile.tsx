"use client";

import { useId, useState, type ReactNode } from "react";
import { cn, focusRing } from "@/lib/ui";
import { SEVERITY, type Severity } from "@/lib/severity";

/**
 * Tile — a KPI tile with the "expand-to-math" affordance from the mockup:
 * nothing is a bare number, so every KPI can open to show how it was computed.
 *
 * The header is a real <button aria-expanded> toggling a disclosure region —
 * keyboard-operable and announced to AT. If `math` is omitted the tile is a
 * static KPI (no toggle).
 *
 * The big value can be tinted by severity, but severity as colour-only is not
 * allowed elsewhere — here the number IS the datum and `valueSeverity` is an
 * emphasis hint on a labelled metric, not a severity claim on its own.
 *
 * @example
 *   <Tile label="Active campaigns" value="3" valueSeverity="crit"
 *         sub="2 advancing · 1 contained"
 *         math={<>base:1/campaign · groups alerts by attack_chain_id …</>} />
 */
export interface TileProps {
  label: string;
  value: ReactNode;
  /** small caption under the value */
  sub?: ReactNode;
  /** tint the value with a severity colour (still a labelled metric) */
  valueSeverity?: Severity;
  /** trailing icon in the header (e.g. a lucide-react element) */
  icon?: ReactNode;
  /** disclosure content: the math / provenance behind the number */
  math?: ReactNode;
  className?: string;
}

export function Tile({
  label,
  value,
  sub,
  valueSeverity,
  icon,
  math,
  className,
}: TileProps) {
  const [open, setOpen] = useState(false);
  const bodyId = useId();
  const valueClass = valueSeverity ? SEVERITY[valueSeverity].textClass : "text-ink";

  const header = (
    <div className="flex items-start justify-between text-dim2">
      <span className="text-meta">{label}</span>
      {icon && <span className="inline-flex shrink-0">{icon}</span>}
    </div>
  );

  const valueBlock = (
    <>
      <div className={cn("mt-1 text-kpi tabular", valueClass)}>{value}</div>
      {sub && (
        <div className="text-kbd text-dim2">
          {sub}
          {math && <span className="text-teal"> · how?</span>}
        </div>
      )}
    </>
  );

  return (
    <div className={cn("rounded-lg border border-line bg-panel2 p-3", className)}>
      {math ? (
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          aria-controls={bodyId}
          className={cn("block w-full cursor-pointer text-left", focusRing)}
        >
          {header}
          {valueBlock}
        </button>
      ) : (
        <div>
          {header}
          {valueBlock}
        </div>
      )}

      {math && (
        <div
          id={bodyId}
          hidden={!open}
          className="mt-2 border-t border-line pt-1.5 text-kbd leading-relaxed text-dim"
        >
          {math}
        </div>
      )}
    </div>
  );
}
