"use client";

/**
 * GITIGNORED screenshot-only harness (WO-U9c). NOT application code — it renders
 * one batch-3 read-view tab in isolation so its populated / empty / locked
 * states can be captured without driving the full shell (whose dev role/tier
 * switcher is memory-heavy to script on a small host). The tabs are pure fixture
 * consumers in NEXT_PUBLIC_DHRUVA_FIXTURES mode, so mounting them directly under
 * an AuthProvider is faithful. Excluded from git + never shipped (see
 * .gitignore); the real entry point is /dashboard.
 *
 * Usage: /shotharness/batch3?tab=hunt   (tab ∈ dailyreview|hunt|feedback|knowledge|reports)
 */

import { useEffect, useState, type ComponentType } from "react";
import { AuthProvider } from "@/lib/auth";
import { DailyReviewTab } from "@/components/shell/tabs/DailyReviewTab";
import { HuntTab } from "@/components/shell/tabs/HuntTab";
import { ClosedLoopTab } from "@/components/shell/tabs/ClosedLoopTab";
import { KnowledgeTab } from "@/components/shell/tabs/KnowledgeTab";
import { ReportsTab } from "@/components/shell/tabs/ReportsTab";
import type { TabProps } from "@/components/shell/tabRegistry";

const TABS: Record<string, ComponentType<TabProps>> = {
  dailyreview: DailyReviewTab,
  hunt: HuntTab,
  feedback: ClosedLoopTab,
  knowledge: KnowledgeTab,
  reports: ReportsTab,
};

function Harness() {
  const [tab, setTab] = useState<string | null>(null);
  useEffect(() => {
    const p = new URLSearchParams(window.location.search);
    setTab(p.get("tab") || "dailyreview");
  }, []);
  if (!tab) return null;
  const Tab = TABS[tab] ?? DailyReviewTab;
  return (
    <div className="min-h-screen bg-bg px-5 py-4 text-ink">
      <Tab tabId={tab} />
    </div>
  );
}

export default function Batch3ShotHarness() {
  return (
    <AuthProvider>
      <Harness />
    </AuthProvider>
  );
}
