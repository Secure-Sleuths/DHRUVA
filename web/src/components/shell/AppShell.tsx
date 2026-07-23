"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import {
  Dialog,
  FeatureLockedState,
  CopilotRail,
} from "@/components";
import { useAuth } from "@/lib/auth";
import {
  GROUPS,
  TAB_LABEL,
  isTabLocked,
  isTabVisible,
} from "@/lib/rbac";
import { useCopilotConversation } from "@/lib/useCopilotConversation";
import type { Role } from "@/lib/types";
import type { CopilotMessage } from "@/lib/copilot";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";
import { resolveTab } from "./tabRegistry";

/**
 * Tabs where the SHELL surfaces the contextual copilot launcher (WO-U7 wires the
 * real NL-Query onto these next). The Investigate tab (WO-U6) owns its OWN wired
 * hero rail internally, so it is deliberately NOT here — the shell must not
 * double-render a rail over it.
 */
const COPILOT_TABS = new Set(["incidents", "triage"]);

/** Pick a safe active tab for the given role/tier (visible + preferably unlocked). */
function pickActiveTab(role: Role, tierLocked: (id: string) => boolean, current: string): string {
  const visible = (id: string) => isTabVisible(id, role);
  if (visible(current) && !tierLocked(current)) return current;
  if (visible("overview") && !tierLocked("overview")) return "overview";
  for (const [, tabs] of GROUPS) {
    for (const t of tabs) if (visible(t.id) && !tierLocked(t.id)) return t.id;
  }
  // nothing unlocked+visible — fall back to the first visible tab (may be locked)
  for (const [, tabs] of GROUPS) {
    for (const t of tabs) if (visible(t.id)) return t.id;
  }
  return "overview";
}

/**
 * Serialize the navigation state into the dashboard query string. `tab` is
 * always present; the deep-linked entity id (`incident`) only when navigation
 * carries one. Kept in a stable key order so two equal states stringify
 * identically (the URL-reconciliation effect compares these strings).
 */
function buildTabQuery(tab: string, entity?: string): string {
  const p = new URLSearchParams();
  p.set("tab", tab);
  if (entity) p.set("incident", entity);
  return p.toString();
}

export function AppShell() {
  const {
    role,
    roleIsPreview,
    tier,
    tierIsPreview,
    devTier,
    loading,
    authenticated,
    devPreview,
    claims,
    tenantName,
    setDevRole,
    setDevTier,
  } = useAuth();

  const [copilotOpen, setCopilotOpen] = useState(false);
  const [lockedTab, setLockedTab] = useState<string | null>(null);
  const [seconds, setSeconds] = useState(22);
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  // ---- URL is the source of truth for navigation (WO-H22) -----------------
  // The active tab and the deep-linked entity live in the query string
  // (`/dashboard?tab=<id>&incident=<id>`) so every view is bookmarkable,
  // shareable, and survives refresh + browser back/forward. We DERIVE the active
  // tab from the URL each render instead of holding it in React state, giving a
  // single source of truth and no bidirectional-sync loop: back/forward mutate
  // the URL, `useSearchParams` re-renders, and the derived tab follows. The raw
  // values below are gated (never rendered directly) a few lines down.
  const urlTab = searchParams.get("tab") ?? "overview";
  const urlEntity = searchParams.get("incident") ?? undefined;

  // Auth guard: once bootstrap settles, an unauthenticated real session (no
  // JWT) is sent to the login page. In dev-preview builds the switcher stands
  // in for a login, so we don't redirect. Mirrors the server: no token → no
  // access.
  useEffect(() => {
    if (!loading && !authenticated && !devPreview) router.replace("/login");
  }, [loading, authenticated, devPreview, router]);

  const tierLocked = useCallback((id: string) => isTabLocked(id, tier), [tier]);

  // Gate the URL-requested tab EXACTLY as a sidebar click would — through the
  // same RBAC role + license-tier gating (`pickActiveTab`). A deep-link to a tab
  // the current role/tier can't reach falls back to a safe tab; the URL can
  // NEVER force a gated tab to render. This is the RBAC-bypass guard.
  const active = pickActiveTab(role, tierLocked, urlTab);
  // The deep-linked entity applies ONLY if the requested tab actually resolved
  // (was not gated away). Cleared whenever navigation carries no id, or when the
  // tab it belonged to was denied.
  const navParam = active === urlTab ? urlEntity : undefined;

  // Keep the URL honest with what is actually shown: if gating overrode the
  // requested tab (or dropped an entity whose tab was denied), rewrite the URL
  // to the resolved state. Guarded on `loading` so we never clobber a legitimate
  // deep-link before the real role/tier settle (the JWT-derived role starts at
  // the least-privilege default during bootstrap).
  useEffect(() => {
    if (loading) return;
    const desired = buildTabQuery(active, navParam);
    const current = buildTabQuery(urlTab, urlEntity);
    if (desired !== current) router.replace(`${pathname}?${desired}`);
  }, [loading, active, navParam, urlTab, urlEntity, pathname, router]);

  // Close the shell's contextual rail when leaving the tabs that host its
  // launcher. (Investigate owns its own rail, so it isn't in COPILOT_TABS.)
  useEffect(() => {
    if (!COPILOT_TABS.has(active)) setCopilotOpen(false);
  }, [active]);

  // Cosmetic polling clock (no push channel — see PollingStatus).
  useEffect(() => {
    const t = setInterval(() => setSeconds((s) => s + 4), 4000);
    return () => clearInterval(t);
  }, []);

  const onSelect = useCallback(
    (id: string, param?: string) => {
      const url = `${pathname}?${buildTabQuery(id, param)}`;
      // replace-vs-push: a lateral tab switch is NOT worth a history entry (it
      // would bloat back/forward on every sidebar click), so it REPLACES.
      // Drilling into a specific entity (a deep-link, e.g. opening an incident
      // case) IS a distinct navigation worth a Back step, so it PUSHES — Back
      // then returns from the case to the list it was opened from.
      if (param) router.push(url);
      else router.replace(url);
    },
    [pathname, router],
  );
  const onLockedSelect = useCallback((id: string) => setLockedTab(id), []);
  const refresh = useCallback(() => setSeconds(0), []);

  // ---- shell launcher copilot (Incidents/Triage) — REAL grounded rail ----
  // Context is a DISPLAY label for the CURRENT surface. The backend `/api/query`
  // takes a free-form `{question}` (no context param), so the label doubles as a
  // lightweight prefix hint for a specific entity — never a fabricated backend
  // capability. The only entity the shell can honestly name is a deep-linked
  // incident id (`navParam` on the Incidents tab); the in-tab list owns its own
  // selection, so a directly-clicked incident keeps the generic "Incidents"
  // label rather than claiming the wrong one.
  const incidentContext =
    active === "incidents" && navParam ? `INC-${navParam}` : undefined;
  const contextLabel = incidentContext
    ? incidentContext
    : active === "triage"
      ? "Triage queue"
      : "Incidents";

  const copilot = useCopilotConversation({
    role,
    tier,
    seedMessages: SEED_MESSAGES,
    // Prefix only when we can honestly name a specific incident.
    contextHint: incidentContext,
  });

  const TabBody = useMemo(() => resolveTab(active), [active]);

  // Unauthenticated real session → the guard effect above is redirecting to
  // /login; render a minimal placeholder instead of the (data-less) shell.
  if (!loading && !authenticated && !devPreview) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-bg text-dim">
        Redirecting to sign in…
      </div>
    );
  }

  return (
    <div className="flex min-h-screen">
      <Sidebar
        role={role}
        tier={tier}
        active={active}
        secondsAgo={seconds}
        onSelect={onSelect}
        onLockedSelect={onLockedSelect}
        onRefresh={refresh}
      />

      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar
          tenantName={tenantName}
          role={role}
          roleIsPreview={roleIsPreview}
          subject={typeof claims?.sub === "string" ? claims.sub : undefined}
          tier={tier}
          tierIsPreview={tierIsPreview}
          devTierId={devTier}
          authenticated={authenticated}
          devPreview={devPreview}
          showAskCopilot={COPILOT_TABS.has(active)}
          copilotOpen={copilotOpen}
          onToggleCopilot={() => setCopilotOpen((v) => !v)}
          onSetDevRole={setDevRole}
          onSetDevTier={setDevTier}
        />

        <div className="flex min-h-0 flex-1">
          <main className="min-w-0 flex-1 overflow-auto px-5 py-4">
            <TabBody tabId={active} onNavigate={onSelect} navParam={navParam} />
          </main>

          {copilotOpen && (
            <div
              className="flex-none overflow-hidden transition-[width] duration-rail ease-rail"
              style={{ width: 392 }}
            >
              <CopilotRail
                mode={copilot.mode}
                role={role}
                tier={tier?.tier ?? "community"}
                contextLabel={contextLabel}
                messages={copilot.messages}
                previewQueries={PREVIEW_QUERIES}
                onSend={copilot.onSend}
                onRunQuery={copilot.onRunQuery}
                onUpgrade={() => setLockedTab("investigate")}
                onClose={() => setCopilotOpen(false)}
                className="h-full"
              />
            </div>
          )}
        </div>

      </div>

      {/* tier-lock overlay — license gate, independent of role; Admin never locked */}
      <Dialog
        open={lockedTab !== null}
        onClose={() => setLockedTab(null)}
        title={
          lockedTab
            ? `${TAB_LABEL[lockedTab] ?? lockedTab} — not in your ${
                tier?.tier_display ?? tier?.tier ?? "current"
              } tier`
            : undefined
        }
        maxWidth={460}
      >
        <FeatureLockedState
          feature={lockedTab ? TAB_LABEL[lockedTab] ?? lockedTab : "This feature"}
          tier={tier?.tier_display ?? tier?.tier ?? "current"}
          onUpgrade={() => {
            const url = tier?.upgrade_url ?? "https://securesleuths.in/pricing";
            if (typeof window !== "undefined") window.open(url, "_blank", "noreferrer");
          }}
        />
        <p className="mt-3 text-kbd text-dim2">
          Community physically strips paid modules; Team/Enterprise progressively
          unlock. This is a license gate, independent of your role — Admin is
          never locked.
        </p>
      </Dialog>
    </div>
  );
}

// ---- seed copilot content (honest UI copy — no fabricated SOC results) ------
const PREVIEW_QUERIES = [
  "Why is this incident critical?",
  "Show related logons in the last 24h",
  "What processes touched lsass?",
];

const SEED_MESSAGES: CopilotMessage[] = [
  {
    id: "seed-ai",
    who: "ai",
    content: (
      <>
        I&apos;m the grounded NL-Query copilot. Ask about the current workspace
        in plain language — every answer cites its evidence (alert · rule · TI ·
        asset-graph · KB), and any containment I propose stays{" "}
        <b>human-approved</b>.
      </>
    ),
    chips: [
      { id: "why", label: "Why is this incident critical?" },
      { id: "logons", label: "Show related logons in the last 24h" },
      { id: "contain", label: "Propose a containment action", kind: "action" },
    ],
  },
];
