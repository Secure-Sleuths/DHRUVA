import type { ReactNode } from "react";
import { cn } from "@/lib/ui";

/**
 * Panel — the mockup's `.panel`: the bordered dark surface that wraps most
 * content blocks (tables, cards, canvases). `inset` uses the deeper `panel2`
 * surface (for nested panels / tiles-on-panels).
 *
 * @example <Panel className="p-4"><Table>…</Table></Panel>
 */
export interface PanelProps {
  children: ReactNode;
  /** use the deeper `panel2` surface for nested emphasis */
  inset?: boolean;
  className?: string;
}

export function Panel({ children, inset = false, className }: PanelProps) {
  return (
    <div
      className={cn(
        "rounded-xl border border-line",
        inset ? "bg-panel2" : "bg-panel",
        className,
      )}
    >
      {children}
    </div>
  );
}
