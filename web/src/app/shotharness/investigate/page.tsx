"use client";

/**
 * GITIGNORED screenshot-only harness (WO-U6). NOT application code — it renders
 * the InvestigateTab in isolation with a forced dev role/tier so the tab's
 * DEGRADED modes (locked / readonly) can be captured. Those modes are otherwise
 * unreachable through the real shell: the Investigate tab is hidden from
 * read_only and tier-locked at the sidebar on community, so the tab body's
 * locked/readonly states never surface via normal navigation. This harness
 * mounts the tab directly to prove the modes render. Excluded from git + never
 * shipped (see .gitignore); the real entry point is /dashboard.
 *
 * Usage: /shotharness/investigate?role=read_only&tier=team
 */

import { useEffect, useState } from "react";
import { AuthProvider, useAuth } from "@/lib/auth";
import { InvestigateTab } from "@/components/shell/tabs/InvestigateTab";
import type { Role } from "@/lib/types";

function Forcer() {
  const { setDevRole, setDevTier } = useAuth();
  const [ready, setReady] = useState(false);
  useEffect(() => {
    const p = new URLSearchParams(window.location.search);
    const role = (p.get("role") as Role) || "senior_analyst";
    const tier = p.get("tier") || "team";
    setDevRole(role);
    setDevTier(tier);
    setReady(true);
  }, [setDevRole, setDevTier]);
  if (!ready) return null;
  return (
    <div className="min-h-screen bg-bg px-5 py-4 text-ink">
      <InvestigateTab tabId="investigate" />
    </div>
  );
}

export default function InvestigateShotHarness() {
  return (
    <AuthProvider>
      <Forcer />
    </AuthProvider>
  );
}
