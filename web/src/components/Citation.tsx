"use client";

import { useEffect, useId, useRef, useState } from "react";
import { Link2 } from "lucide-react";
import { cn, focusRing } from "@/lib/ui";
import type { CopilotCitation } from "@/lib/copilot";

/**
 * Citation — an inline "grounded source" chip (the mockup's `.cite`). Every AI
 * claim links to the evidence behind it; clicking opens a popover with the
 * source detail and an optional "open the underlying surface" action. This is
 * how the copilot stays a glass box, never a black box.
 *
 * Accessible: the chip is a `<button aria-expanded aria-haspopup>`; the popover
 * is labelled, closes on Esc / outside-click, and its action is focusable.
 *
 * @example
 *   <Citation citation={cite} onOpenSource={(c) => goTo(c)} />
 */
export interface CitationProps {
  citation: CopilotCitation;
  /** open the underlying alert/rule/enrichment surface */
  onOpenSource?: (citation: CopilotCitation) => void;
  /** short label on the chip (defaults to the part before " · " in title) */
  label?: string;
}

export function Citation({ citation, onOpenSource, label }: CitationProps) {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLSpanElement>(null);
  const popId = useId();
  const chipLabel = label ?? citation.title.split(" · ")[0];

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (!wrapRef.current?.contains(e.target as Node)) setOpen(false);
    };
    const onEsc = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onEsc);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onEsc);
    };
  }, [open]);

  return (
    <span ref={wrapRef} className="relative inline-block align-baseline">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-haspopup="dialog"
        aria-label={`Source: ${citation.title}`}
        className={cn(
          "mx-px inline-flex items-center gap-0.5 rounded-sm border border-cite-border bg-cite-bg px-1.5 font-mono text-[10px] text-cite-ink hover:brightness-125",
          focusRing,
        )}
      >
        <Link2 className="h-2.5 w-2.5" aria-hidden="true" />
        {chipLabel}
      </button>

      {open && (
        <span
          role="dialog"
          aria-label={`Grounded source: ${citation.title}`}
          id={popId}
          className="absolute bottom-full left-0 z-[70] mb-2 block w-[320px] rounded-xl border border-line bg-panel p-3 text-left shadow-overlay animate-fade-in"
        >
          <span className="block text-kbd uppercase tracking-wider text-dim2">
            {citation.kind} — grounded source
          </span>
          <span className="mb-1 mt-1 block text-body font-semibold text-ink">
            {citation.title}
          </span>
          <span className="block text-data leading-relaxed text-dim">
            {citation.detail}
          </span>
          {onOpenSource && (
            <button
              type="button"
              onClick={() => {
                setOpen(false);
                onOpenSource(citation);
              }}
              className={cn(
                "mt-2.5 inline-flex items-center rounded-md border border-cite-border bg-transparent px-2 py-0.5 text-meta text-cite-ink hover:bg-cite-bg",
                focusRing,
              )}
            >
              {citation.openLabel ?? "Open source"} ›
            </button>
          )}
        </span>
      )}
    </span>
  );
}
