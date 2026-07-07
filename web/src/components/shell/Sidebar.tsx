"use client";

import { Lock, ShieldCheck } from "lucide-react";
import { cn, focusRing } from "@/lib/ui";
import {
  GROUPS,
  isTabLocked,
  isTabVisible,
} from "@/lib/rbac";
import type { LicenseTierInfo, Role } from "@/lib/types";
import { PollingStatus } from "@/components";

/**
 * Sidebar — the left nav (mockup's `#sidebar` + `buildSidebar()`).
 *
 * Renders the four IA groups; a tab is HIDDEN when the role is not in its ACL
 * (RBAC mirror) and LOCKED (shown with a lock + upgrade overlay on click) when
 * the license tier doesn't include it. Empty groups collapse.
 */
export interface SidebarProps {
  role: Role;
  tier: LicenseTierInfo | null;
  active: string;
  /** seconds since last poll, for the footer polling status */
  secondsAgo: number;
  onSelect: (tabId: string) => void;
  /** a locked tab was clicked → open the tier-lock dialog */
  onLockedSelect: (tabId: string) => void;
  onRefresh?: () => void;
}

export function Sidebar({
  role,
  tier,
  active,
  secondsAgo,
  onSelect,
  onLockedSelect,
  onRefresh,
}: SidebarProps) {
  return (
    <aside
      className="flex w-[216px] flex-none flex-col border-r border-line bg-[#0c1220] px-2 py-3"
      aria-label="Primary navigation"
    >
      {/* brand */}
      <div className="flex items-center gap-2 px-2 pb-2.5 pt-1">
        <div className="flex h-[26px] w-[26px] items-center justify-center rounded-md bg-gradient-to-br from-teal to-acc">
          <ShieldCheck className="h-4 w-4 text-[#04121f]" aria-hidden="true" />
        </div>
        <div>
          <div className="text-[13px] font-bold tracking-wide">DHRUVA</div>
          <div className="text-[9px] tracking-[0.13em] text-dim2">
            AI-SOC · v5.0.0
          </div>
        </div>
      </div>

      {/* nav */}
      <nav className="flex-1 overflow-auto" aria-label="Sections">
        {GROUPS.map(([group, tabs]) => {
          const visible = tabs.filter((t) => isTabVisible(t.id, role));
          if (visible.length === 0) return null;
          return (
            <div key={group}>
              <div className="mx-2.5 mb-1.5 mt-3.5 text-[10px] uppercase tracking-[0.12em] text-dim2">
                {group}
              </div>
              {visible.map((t) => {
                const locked = isTabLocked(t.id, tier);
                const isActive = t.id === active;
                const Icon = t.icon;
                return (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() =>
                      locked ? onLockedSelect(t.id) : onSelect(t.id)
                    }
                    aria-current={isActive ? "page" : undefined}
                    aria-label={`${t.label}${locked ? " (locked)" : ""}`}
                    className={cn(
                      "flex w-full items-center gap-2.5 rounded-md px-2.5 py-1.5 text-left text-[13px] text-dim",
                      focusRing,
                      "hover:bg-[#16202f] hover:text-ink",
                      isActive && "bg-[#13233a] text-white shadow-nav-on",
                      locked && "opacity-55",
                    )}
                  >
                    <Icon className="h-[15px] w-[15px] shrink-0" aria-hidden="true" />
                    <span className="truncate">{t.label}</span>
                    {locked && (
                      <Lock
                        className="ml-auto h-3 w-3 shrink-0 opacity-60"
                        aria-hidden="true"
                      />
                    )}
                  </button>
                );
              })}
            </div>
          );
        })}
      </nav>

      {/* correlation-engine + polling footer note */}
      <div className="mt-4 rounded-lg border border-dashed border-line p-2.5">
        <div className="text-kbd uppercase tracking-[0.1em] text-dim2">
          Correlation engine
        </div>
        <div className="mt-1 text-[11px] text-dim">
          M5 links incidents into{" "}
          <b className="text-violet">campaigns</b> by{" "}
          <span className="font-mono">attack_chain_id</span>.
        </div>
        <PollingStatus
          className="mt-2"
          secondsAgo={secondsAgo}
          onRefresh={onRefresh}
        />
      </div>
    </aside>
  );
}
