"use client";

import {
  useCallback,
  useEffect,
  useId,
  useRef,
  type ReactNode,
} from "react";
import { X } from "lucide-react";
import { cn, focusRing } from "@/lib/ui";

/**
 * Dialog — the accessible modal behind the mockup's `.ov` overlays
 * (tier-lock, node-detail, etc.). Bakes accessibility into the primitive so no
 * screen re-implements it:
 *   - role="dialog" + aria-modal, labelled by its title (or `aria-label`)
 *   - focus moves in on open and is RESTORED to the trigger on close
 *   - Tab / Shift+Tab are trapped within the dialog
 *   - Esc closes; clicking the backdrop closes
 *   - a focus-visible close button
 *
 * Controlled: the parent owns `open` and `onClose`.
 *
 * @example
 *   <Dialog open={open} onClose={close} title="Feature locked">
 *     <p>Upgrade to unlock …</p>
 *   </Dialog>
 */
export interface DialogProps {
  open: boolean;
  onClose: () => void;
  /** visible heading; also becomes the accessible name */
  title?: ReactNode;
  /** accessible name when there is no visible `title` */
  "aria-label"?: string;
  children: ReactNode;
  /** max width of the panel (px) */
  maxWidth?: number;
  /** hide the default close button (e.g. a custom header handles it) */
  hideClose?: boolean;
  className?: string;
}

const FOCUSABLE =
  'a[href],button:not([disabled]),textarea:not([disabled]),input:not([disabled]),select:not([disabled]),[tabindex]:not([tabindex="-1"])';

export function Dialog({
  open,
  onClose,
  title,
  "aria-label": ariaLabel,
  children,
  maxWidth = 460,
  hideClose = false,
  className,
}: DialogProps) {
  const panelRef = useRef<HTMLDivElement>(null);
  const restoreRef = useRef<HTMLElement | null>(null);
  const titleId = useId();

  // Remember the trigger so focus can return to it on close.
  useEffect(() => {
    if (open) {
      restoreRef.current = document.activeElement as HTMLElement | null;
    } else {
      restoreRef.current?.focus?.();
    }
  }, [open]);

  // Move focus into the dialog when it opens.
  useEffect(() => {
    if (!open) return;
    const el = panelRef.current;
    if (!el) return;
    const first = el.querySelector<HTMLElement>(FOCUSABLE);
    (first ?? el).focus();
  }, [open]);

  const onKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key !== "Tab") return;
      const el = panelRef.current;
      if (!el) return;
      const nodes = Array.from(el.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
        (n) => n.offsetParent !== null || n === document.activeElement,
      );
      if (nodes.length === 0) {
        e.preventDefault();
        return;
      }
      const first = nodes[0];
      const last = nodes[nodes.length - 1];
      const activeEl = document.activeElement as HTMLElement;
      if (e.shiftKey && activeEl === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && activeEl === last) {
        e.preventDefault();
        first.focus();
      }
    },
    [onClose],
  );

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center bg-[rgba(4,7,12,0.72)] p-4 animate-fade-in"
      onMouseDown={(e) => {
        // backdrop click (not a click that started inside the panel) closes
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={title ? titleId : undefined}
        aria-label={!title ? ariaLabel : undefined}
        tabIndex={-1}
        onKeyDown={onKeyDown}
        className={cn(
          "relative w-full rounded-xl border border-line bg-panel p-6 shadow-overlay animate-overlay-in",
          className,
        )}
        style={{ maxWidth }}
      >
        {(title || !hideClose) && (
          <div className="mb-2 flex items-start gap-3">
            {title && (
              <h2 id={titleId} className="text-title">
                {title}
              </h2>
            )}
            {!hideClose && (
              <button
                type="button"
                onClick={onClose}
                aria-label="Close dialog"
                className={cn(
                  "ml-auto inline-flex h-6 w-6 items-center justify-center rounded-md text-dim hover:bg-hover hover:text-ink",
                  focusRing,
                )}
              >
                <X className="h-4 w-4" aria-hidden="true" />
              </button>
            )}
          </div>
        )}
        {children}
      </div>
    </div>
  );
}
