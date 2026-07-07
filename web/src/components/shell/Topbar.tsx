"use client";

import { Building2, EyeOff, LogOut, Sparkles } from "lucide-react";
import { useRouter } from "next/navigation";
import { clearToken } from "@/lib/token";
import { cn, focusRing } from "@/lib/ui";
import { Chip } from "@/components";
import type { LicenseTierInfo, Role } from "@/lib/types";
import { showUpgradeAffordance } from "@/lib/rbac";
import { DevSwitcher } from "./DevSwitcher";

/**
 * Topbar — the mockup's `<header>`.
 *
 * Carries: the tenant chip, the anonymization = LLM-boundary chip (copy is
 * load-bearing — see below), the contextual "Ask copilot" launcher (Incidents /
 * Triage only), the Community→upgrade affordance, the dev role/tier switcher,
 * and the role badge sourced from the JWT.
 */
export interface TopbarProps {
  tenantName: string;
  role: Role;
  roleIsPreview: boolean;
  /** subject/username from the JWT (avatar initial) */
  subject?: string;
  tier: LicenseTierInfo | null;
  tierIsPreview: boolean;
  devTierId: string | null;
  authenticated: boolean;
  /** dev-preview build → render the dev role/tier switcher (never in production) */
  devPreview: boolean;
  /** show the "Ask copilot" launcher (Incidents / Triage) */
  showAskCopilot: boolean;
  copilotOpen: boolean;
  onToggleCopilot: () => void;
  onSetDevRole: (role: Role | null) => void;
  onSetDevTier: (tier: string | null) => void;
}

export function Topbar({
  tenantName,
  role,
  roleIsPreview,
  subject,
  tier,
  tierIsPreview,
  devTierId,
  authenticated,
  devPreview,
  showAskCopilot,
  copilotOpen,
  onToggleCopilot,
  onSetDevRole,
  onSetDevTier,
}: TopbarProps) {
  const upgrade = showUpgradeAffordance(tier);
  const upgradeUrl = tier?.upgrade_url ?? "https://securesleuths.in/pricing";
  const router = useRouter();
  const onLogout = () => {
    clearToken();
    router.replace("/login");
  };
  const initial = (subject?.[0] ?? tenantName[0] ?? "U").toUpperCase();

  return (
    <header className="flex flex-wrap items-center gap-2.5 border-b border-line bg-[#0b101a] px-4 py-2.5">
      <Chip icon={<Building2 className="h-3.5 w-3.5" />}>
        Tenant <b className="text-white">{tenantName}</b>
      </Chip>

      {/*
        LOAD-BEARING COPY (anonymization invariant): the boundary is that data is
        anonymized BEFORE it reaches the LLM and the analyst sees the REAL names.
        Never phrase this as "you are viewing anonymized data".
      */}
      <Chip variant="grounded" icon={<EyeOff className="h-3.5 w-3.5" />}>
        Anonymized before AI analysis
        <span className="ml-1 text-kbd text-[#63a894]">· you see real names</span>
      </Chip>

      {showAskCopilot && (
        <button
          type="button"
          onClick={onToggleCopilot}
          aria-pressed={copilotOpen}
          className={cn(
            "inline-flex items-center gap-1.5 rounded-lg border border-[#1c3a34] bg-[#0f2620] px-2.5 py-1 text-[12px] text-[#7fe8cf] hover:bg-[#123028]",
            focusRing,
          )}
        >
          <Sparkles className="h-3.5 w-3.5" aria-hidden="true" /> Ask copilot
        </button>
      )}

      <div className="flex-1" />

      {upgrade && (
        <a
          href={upgradeUrl}
          target="_blank"
          rel="noreferrer"
          className={cn(
            "inline-flex items-center gap-1.5 rounded-md border border-[#4a4326] bg-[#161206] px-2.5 py-1 text-[12px] text-sev-med hover:brightness-125",
            focusRing,
          )}
        >
          Community — upgrade
        </a>
      )}

      {/* dev-only: never rendered in a production build (see DEV_PREVIEW) */}
      {devPreview && (
        <DevSwitcher
          role={role}
          tierId={devTierId}
          authenticated={authenticated}
          roleIsPreview={roleIsPreview}
          tierIsPreview={tierIsPreview}
          onSetRole={onSetDevRole}
          onSetTier={onSetDevTier}
        />
      )}

      {/* role / tier context + role badge (from the JWT) */}
      <div className="flex items-center gap-2 border-l border-line pl-2.5">
        <div className="flex h-[26px] w-[26px] items-center justify-center rounded-full bg-[#25406a] text-[12px] text-white">
          {initial}
        </div>
        <div className="leading-tight">
          <div className="text-[12px]">{subject ?? "Analyst"}</div>
          <div className="text-kbd font-semibold text-acc">
            {role}
            {roleIsPreview && (
              <span className="ml-1 font-normal text-dim2">· preview</span>
            )}
          </div>
        </div>
        {authenticated && (
          <button
            type="button"
            onClick={onLogout}
            aria-label="Sign out"
            title="Sign out"
            className={cn(
              "ml-1 flex h-[26px] w-[26px] items-center justify-center rounded-md text-dim hover:bg-hover hover:text-ink",
              focusRing,
            )}
          >
            <LogOut className="h-[15px] w-[15px]" />
          </button>
        )}
      </div>
    </header>
  );
}
