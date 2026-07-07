import type { ComponentType } from "react";
import { TabPlaceholder } from "./TabPlaceholder";
import { AdminTab } from "./tabs/AdminTab";
import { AgentGroupsTab } from "./tabs/AgentGroupsTab";
import { ClosedLoopTab } from "./tabs/ClosedLoopTab";
import { DailyReviewTab } from "./tabs/DailyReviewTab";
import { DetectionTab } from "./tabs/DetectionTab";
import { HostIntegrityTab } from "./tabs/HostIntegrityTab";
import { HuntTab } from "./tabs/HuntTab";
import { IncidentsTab } from "./tabs/IncidentsTab";
import { InvestigateTab } from "./tabs/InvestigateTab";
import { KnowledgeTab } from "./tabs/KnowledgeTab";
import { MetricsTab } from "./tabs/MetricsTab";
import { MitreTab } from "./tabs/MitreTab";
import { OverviewTab } from "./tabs/OverviewTab";
import { ReportsTab } from "./tabs/ReportsTab";
import { RespondTab } from "./tabs/RespondTab";
import { SoarTab } from "./tabs/SoarTab";
import { ThreatIntelTab } from "./tabs/ThreatIntelTab";
import { TicketsTab } from "./tabs/TicketsTab";
import { TriageTab } from "./tabs/TriageTab";

/**
 * Tab body registry — `{ tabId: Component }`, falling back to a placeholder.
 *
 * Later WOs slot real bodies in by adding an entry here, e.g.
 *
 *   import { OverviewTab } from "./tabs/OverviewTab";
 *   export const TAB_COMPONENTS = { overview: OverviewTab };
 *
 * The component receives the tab id (so a shared body can serve several tabs)
 * and an `onNavigate` callback wired to the shell's tab switcher — used to open
 * another tab (e.g. Triage's "open ›" navigating to Incidents).
 *
 * `onNavigate` optionally accepts a second `param` (an entity id) so a source
 * tab can DEEP-LINK into a target — e.g. opening the Incidents case for a
 * specific incident id. This is BACKWARD-COMPATIBLE: existing single-arg calls
 * (`onNavigate("incidents")`) still work. The shell threads the param back into
 * the target tab as `navParam`; a tab that does not deep-link simply ignores it.
 */
export interface TabProps {
  tabId: string;
  /**
   * switch the shell to another tab id (mirrors the shell's `setActive`),
   * optionally deep-linking to an entity id within that tab.
   */
  onNavigate?: (tabId: string, param?: string) => void;
  /** deep-link target id passed to THIS tab when it was navigated to with one */
  navParam?: string;
}

export const TAB_COMPONENTS: Record<string, ComponentType<TabProps>> = {
  // WO-U9c (batch 3) — READ-ONLY start-of-shift + intelligence + reporting surfaces:
  dailyreview: DailyReviewTab, // composed digest (dashboard + incidents + triage + overview)
  hunt: HuntTab, // hunt findings + saved-hypothesis library
  feedback: ClosedLoopTab, // mined FP/noisy-rule patterns + deployed-tuning scorecard
  knowledge: KnowledgeTab, // KB docs + type breakdown + GET-backed search
  reports: ReportsTab, // generate-on-demand SOC reports (GET /metrics/reports/{type}, read-only)
  // WO-U3 — Campaign Command: KPI strip + campaign kill-chain map.
  overview: OverviewTab,
  // WO-U5 — worst-first glass-box triage queue.
  triage: TriageTab,
  // WO-U4 — worst-first incident list → glass-box case (master-detail).
  incidents: IncidentsTab,
  // WO-U6 — grounded NL-Query copilot hero + evidence canvas (owns its own rail).
  investigate: InvestigateTab,
  // WO-U8 — MITRE coverage grid + live-campaign overlay + per-campaign chain coverage.
  mitre: MitreTab,
  // WO-U9 (batch 1) — READ-ONLY Wazuh-native + operational surfaces:
  detection: DetectionTab, // AI-proposed rule changes (diff, reasoning, FP-impact)
  threatintel: ThreatIntelTab, // IoC corpus + feed health + CVE/KEV
  fim: HostIntegrityTab, // FIM / rootcheck / registry + host vulnerabilities
  metrics: MetricsTab, // SOC KPIs (MTTD/MTTA/MTTR/SLA/auto-close)
  admin: AdminTab, // users + license + tenants
  // WO-U9b (batch 2) — READ-ONLY response + workflow surfaces:
  soar: SoarTab, // SOAR playbooks + recent executions (no run/approve)
  respond: RespondTab, // active-response queue + audit trail + human-gated approve/reverse
  tickets: TicketsTab, // external-tracker tickets + sync status (no create/sync)
  groups: AgentGroupsTab, // Wazuh Manager agent groups (mssp_admin; no group edit)
};

export function resolveTab(tabId: string): ComponentType<TabProps> {
  return TAB_COMPONENTS[tabId] ?? TabPlaceholder;
}
