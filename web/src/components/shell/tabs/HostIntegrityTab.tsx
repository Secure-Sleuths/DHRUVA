"use client";

/**
 * HostIntegrityTab (WO-U9, `fim`) — READ-ONLY view of file-integrity, policy
 * monitoring, registry FIM, and host vulnerabilities. A key BR-4 surface.
 *
 * Binds TWO independent data planes with DISTINCT license gates:
 *   - Host integrity (analyst+ + `host_integrity`): `GET /api/agents`
 *     (`getAgents`, NOT gated) drives an agent picker; the selected agent's
 *     `GET /api/agents/{id}/{syscheck,rootcheck,registry}` load its FIM /
 *     rootcheck / registry entries.
 *   - Host vulnerabilities (`compliance_sca`): `GET /api/vulnerabilities/summary`
 *     (`getVulnSummary`).
 * Because the two planes are gated separately, each degrades to its OWN locked
 * note — a `compliance_sca` lock never blanks the FIM view and vice-versa.
 *
 * MOSTLY READ-ONLY. The ONE write is WO-U15's admin-only vulnerability
 * remediation (`RemediateAction`, `vuln` view): `POST /api/vulnerabilities/
 * remediate` runs a package-update command on the host via Wazuh active response.
 * It is ACTIVE-RESPONSE-ADJACENT and mirrors the server's `require_admin` gate
 * EXACTLY (via `vulnRemediationGate`) — below admin there is no enabled trigger,
 * only a locked chip. It is confirm-gated (naming host + package), audited
 * server-side, and followed by an explicit verify step (`GET /verify`). Nothing
 * runs until the admin confirms. Everything else on this tab is read-only. (BRD
 * M6b "FIM feeds the verdict" is a BACKEND item — this tab only surfaces data.)
 *
 * States: loading / empty / error+retry / per-section locked; the remediation
 * write handles 400 (platform unsupported → advisory fallback), 429 (rate limit),
 * 402/403 (tier/role → locked), 404 gracefully. PollingStatus (30s, aborts on
 * unmount). Fixtures gate behind NEXT_PUBLIC_DHRUVA_FIXTURES.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Chip,
  Dialog,
  Panel,
  PollingStatus,
  StatusState,
  FeatureLockedState,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
  Tile,
} from "@/components";
import { PageHeading } from "../PageHeading";
import {
  ApiError,
  executeRemediation,
  getAgentCompliance,
  getAgentCompliancePolicy,
  getAgentPackages,
  getAgentPorts,
  getAgentProcesses,
  getAgentRegistry,
  getAgentRootcheck,
  getAgentSyscheck,
  getAgentVulnerabilities,
  getAgents,
  getCriticalVulns,
  getVulnRemediation,
  getVulnSummary,
  verifyRemediation,
} from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { vulnRemediationGate } from "@/lib/rbac";
import { cn, focusRing } from "@/lib/ui";
import { DASH, fmtBytes, fmtDateTime, fmtInt, fmtNum } from "@/lib/format";
import type { TabProps } from "../tabRegistry";
import type {
  AgentPackage,
  AgentPort,
  AgentProcess,
  AgentVulnerability,
  RemediationVerifyResult,
  RootcheckEntry,
  ScaCheck,
  ScaPolicy,
  SyscheckEntry,
  VulnRemediation,
  VulnSummary,
  WazuhAgent,
} from "@/lib/types";

const POLL_MS = 30_000;

function isLockError(e: unknown): boolean {
  return e instanceof ApiError && (e.status === 402 || e.status === 403);
}
function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : "Unknown error";
}
function onUpgrade() {
  if (typeof window !== "undefined") {
    window.open("https://securesleuths.in/pricing", "_blank", "noreferrer");
  }
}

type HostView = "fim" | "rootcheck" | "registry" | "vuln" | "inventory" | "sca";
type InventoryTab = "processes" | "ports" | "packages";

/**
 * Syscollector inventory (WO-U14) — processes / ports / packages. Loaded LAZILY
 * on first entry to the inventory view (never in the eager `loadHost` Promise.all),
 * so picking a host does not fan out extra requests. The three lists ARE fetched
 * together (Promise.all) once inventory is entered. `verify_jwt`-only endpoints,
 * so no license lock in practice.
 */
interface InventoryState {
  processes: AgentProcess[] | null;
  ports: AgentPort[] | null;
  packages: AgentPackage[] | null;
  error: string | null;
  loading: boolean;
  loaded: boolean;
}
const EMPTY_INVENTORY: InventoryState = {
  processes: null,
  ports: null,
  packages: null,
  error: null,
  loading: false,
  loaded: false,
};

/** SCA policy list (WO-U14). Loaded lazily on first entry to the SCA view. */
interface ScaState {
  policies: ScaPolicy[] | null;
  error: string | null;
  loading: boolean;
  loaded: boolean;
}
const EMPTY_SCA: ScaState = {
  policies: null,
  error: null,
  loading: false,
  loaded: false,
};

/** SCA checks for one drilled-into policy (WO-U14). */
interface ScaChecksState {
  policyId: string | null;
  checks: ScaCheck[] | null;
  error: string | null;
  loading: boolean;
}
const EMPTY_SCA_CHECKS: ScaChecksState = {
  policyId: null,
  checks: null,
  error: null,
  loading: false,
};

/**
 * Per-agent vulnerability state — loaded SEPARATELY from the FIM/rootcheck/
 * registry reads because it rides the `compliance_sca` license gate (the others
 * ride `host_integrity`). Keeping it independent means a lock on one plane never
 * blanks the other, even at the per-agent level.
 */
interface HostVulnState {
  vulns: AgentVulnerability[] | null;
  error: string | null;
  locked: boolean;
  loading: boolean;
}

/**
 * WO-U15 (READ half) — fleet-wide Critical vulnerabilities. Loaded LAZILY on first
 * entry to the `vuln` view (never in the eager `loadHost`), poll-refreshed while
 * it stays active. Fleet-wide, so it does NOT reset on agent change. Rides the
 * SAME `compliance_sca` gate as the per-agent vuln reads → degrades to a hidden
 * (locked) section rather than a duplicate lock, since the per-agent panel already
 * shows the lock.
 */
interface CriticalVulnState {
  vulns: AgentVulnerability[] | null;
  error: string | null;
  locked: boolean;
  loading: boolean;
  loaded: boolean;
}
const EMPTY_CRITICAL: CriticalVulnState = {
  vulns: null,
  error: null,
  locked: false,
  loading: false,
  loaded: false,
};

/**
 * WO-U15 (READ half) — per-agent ADVISORY remediation plan. Loaded LAZILY on first
 * entry to the `vuln` view for the selected agent, poll-refreshed while active, and
 * reset on agent change. The `command` strings are DISPLAY ONLY — nothing here
 * executes them (the state-changing `/remediate` execute path is a separate,
 * admin-gated WO deliberately NOT wired). Same `compliance_sca` gate.
 */
interface RemediationState {
  items: VulnRemediation[] | null;
  error: string | null;
  locked: boolean;
  loading: boolean;
  loaded: boolean;
}
const EMPTY_REMEDIATION: RemediationState = {
  items: null,
  error: null,
  locked: false,
  loading: false,
  loaded: false,
};

interface OverviewState {
  agents: WazuhAgent[] | null;
  agentsError: string | null;
  vuln: VulnSummary | null;
  vulnError: string | null;
  vulnLocked: boolean;
  loading: boolean;
}

interface HostState {
  syscheck: SyscheckEntry[] | null;
  rootcheck: RootcheckEntry[] | null;
  registry: SyscheckEntry[] | null;
  error: string | null;
  locked: boolean;
  loading: boolean;
}

export function HostIntegrityTab(_props: TabProps) {
  const [ov, setOv] = useState<OverviewState>({
    agents: null,
    agentsError: null,
    vuln: null,
    vulnError: null,
    vulnLocked: false,
    loading: true,
  });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [view, setView] = useState<HostView>("fim");
  const [host, setHost] = useState<HostState>({
    syscheck: null,
    rootcheck: null,
    registry: null,
    error: null,
    locked: false,
    loading: false,
  });
  const [hostVuln, setHostVuln] = useState<HostVulnState>({
    vulns: null,
    error: null,
    locked: false,
    loading: false,
  });
  const [inventory, setInventory] = useState<InventoryState>(EMPTY_INVENTORY);
  const [invTab, setInvTab] = useState<InventoryTab>("processes");
  const [sca, setSca] = useState<ScaState>(EMPTY_SCA);
  const [scaChecks, setScaChecks] = useState<ScaChecksState>(EMPTY_SCA_CHECKS);
  const [critical, setCritical] = useState<CriticalVulnState>(EMPTY_CRITICAL);
  const [remediation, setRemediation] =
    useState<RemediationState>(EMPTY_REMEDIATION);
  const [secondsAgo, setSecondsAgo] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const [tick, setTick] = useState(0);

  const ovAbort = useRef<AbortController | null>(null);
  const hostAbort = useRef<AbortController | null>(null);
  const vulnAbort = useRef<AbortController | null>(null);
  const invAbort = useRef<AbortController | null>(null);
  const scaAbort = useRef<AbortController | null>(null);
  const scaChecksAbort = useRef<AbortController | null>(null);
  const criticalAbort = useRef<AbortController | null>(null);
  const remediationAbort = useRef<AbortController | null>(null);

  // ---- overview (agents + vuln summary), independent planes ----
  const loadOverview = useCallback(async () => {
    ovAbort.current?.abort();
    const ac = new AbortController();
    ovAbort.current = ac;
    const [agentsRes, vulnRes] = await Promise.allSettled([
      getAgents({}, ac.signal),
      getVulnSummary(ac.signal),
    ]);
    if (ac.signal.aborted) return;

    setOv((prev) => {
      const next: OverviewState = { ...prev, loading: false };
      if (agentsRes.status === "fulfilled") {
        next.agents = agentsRes.value.agents;
        next.agentsError = null;
      } else if (!prev.agents) {
        next.agentsError = errMessage(agentsRes.reason);
      }
      if (vulnRes.status === "fulfilled") {
        next.vuln = vulnRes.value;
        next.vulnError = null;
        next.vulnLocked = false;
      } else if (isLockError(vulnRes.reason)) {
        next.vuln = null;
        next.vulnLocked = true;
        next.vulnError = null;
      } else if (!prev.vuln) {
        next.vulnError = errMessage(vulnRes.reason);
      }
      return next;
    });
    setSecondsAgo(0);

    // Default-select the first agent once we have the list.
    if (agentsRes.status === "fulfilled") {
      const agents = agentsRes.value.agents;
      setSelectedId((cur) =>
        cur && agents.some((a) => a.id === cur)
          ? cur
          : (agents[0]?.id ?? null),
      );
    }
  }, []);

  // ---- per-agent host integrity (host_integrity gate) ----
  const loadHost = useCallback(async (agentId: string) => {
    hostAbort.current?.abort();
    const ac = new AbortController();
    hostAbort.current = ac;
    setHost((h) => ({ ...h, loading: true, error: null }));
    try {
      const [sys, root, reg] = await Promise.all([
        getAgentSyscheck(agentId, ac.signal),
        getAgentRootcheck(agentId, ac.signal),
        getAgentRegistry(agentId, ac.signal),
      ]);
      if (ac.signal.aborted) return;
      setHost({
        syscheck: sys.syscheck,
        rootcheck: root.rootcheck,
        registry: reg.registry,
        error: null,
        locked: false,
        loading: false,
      });
    } catch (e) {
      if (ac.signal.aborted) return;
      if (isLockError(e)) {
        setHost({
          syscheck: null,
          rootcheck: null,
          registry: null,
          error: null,
          locked: true,
          loading: false,
        });
        return;
      }
      setHost({
        syscheck: null,
        rootcheck: null,
        registry: null,
        error: errMessage(e),
        locked: false,
        loading: false,
      });
    }
  }, []);

  // ---- per-agent vulnerabilities (compliance_sca gate) ----
  const loadHostVuln = useCallback(async (agentId: string) => {
    vulnAbort.current?.abort();
    const ac = new AbortController();
    vulnAbort.current = ac;
    setHostVuln((v) => ({ ...v, loading: true, error: null }));
    try {
      const res = await getAgentVulnerabilities(agentId, {}, ac.signal);
      if (ac.signal.aborted) return;
      setHostVuln({
        vulns: res.vulnerabilities,
        error: null,
        locked: false,
        loading: false,
      });
    } catch (e) {
      if (ac.signal.aborted) return;
      if (isLockError(e)) {
        setHostVuln({ vulns: null, error: null, locked: true, loading: false });
        return;
      }
      setHostVuln({
        vulns: null,
        error: errMessage(e),
        locked: false,
        loading: false,
      });
    }
  }, []);

  // ---- per-agent syscollector inventory (WO-U14, verify_jwt) ----
  // Lazily loaded on first entry to the inventory view — the three lists ride a
  // single Promise.all *inside* this loader, but this loader is NOT part of the
  // eager `loadHost`, so picking a host never fires the inventory requests.
  const loadInventory = useCallback(async (agentId: string) => {
    invAbort.current?.abort();
    const ac = new AbortController();
    invAbort.current = ac;
    setInventory((s) => ({ ...s, loading: true, error: null }));
    try {
      const [procs, ports, pkgs] = await Promise.all([
        getAgentProcesses(agentId, ac.signal),
        getAgentPorts(agentId, ac.signal),
        getAgentPackages(agentId, ac.signal),
      ]);
      if (ac.signal.aborted) return;
      setInventory({
        processes: procs.processes,
        ports: ports.ports,
        packages: pkgs.packages,
        error: null,
        loading: false,
        loaded: true,
      });
    } catch (e) {
      if (ac.signal.aborted) return;
      setInventory({
        processes: null,
        ports: null,
        packages: null,
        error: errMessage(e),
        loading: false,
        loaded: true,
      });
    }
  }, []);

  // ---- per-agent SCA policy list (WO-U14, verify_jwt) ----
  const loadSca = useCallback(async (agentId: string) => {
    scaAbort.current?.abort();
    const ac = new AbortController();
    scaAbort.current = ac;
    setSca((s) => ({ ...s, loading: true, error: null }));
    try {
      const res = await getAgentCompliance(agentId, ac.signal);
      if (ac.signal.aborted) return;
      setSca({
        policies: res.policies,
        error: null,
        loading: false,
        loaded: true,
      });
    } catch (e) {
      if (ac.signal.aborted) return;
      setSca({
        policies: null,
        error: errMessage(e),
        loading: false,
        loaded: true,
      });
    }
  }, []);

  // ---- SCA checks for one drilled-into policy (WO-U14, verify_jwt) ----
  const loadScaChecks = useCallback(
    async (agentId: string, policyId: string) => {
      scaChecksAbort.current?.abort();
      const ac = new AbortController();
      scaChecksAbort.current = ac;
      setScaChecks({ policyId, checks: null, error: null, loading: true });
      try {
        const res = await getAgentCompliancePolicy(
          agentId,
          policyId,
          {},
          ac.signal,
        );
        if (ac.signal.aborted) return;
        setScaChecks({
          policyId,
          checks: res.checks,
          error: null,
          loading: false,
        });
      } catch (e) {
        if (ac.signal.aborted) return;
        setScaChecks({
          policyId,
          checks: null,
          error: errMessage(e),
          loading: false,
        });
      }
    },
    [],
  );

  // ---- WO-U15: fleet-wide Critical vulnerabilities (compliance_sca gate) ----
  // Lazily loaded on first entry to the `vuln` view; fleet-wide, so NOT keyed on
  // the selected agent. A compliance_sca lock hides this section (the per-agent
  // vuln panel already surfaces the lock — no duplicate lock note).
  const loadCriticalVulns = useCallback(async () => {
    criticalAbort.current?.abort();
    const ac = new AbortController();
    criticalAbort.current = ac;
    setCritical((s) => ({ ...s, loading: true, error: null }));
    try {
      const res = await getCriticalVulns(50, ac.signal);
      if (ac.signal.aborted) return;
      setCritical({
        vulns: res.vulnerabilities,
        error: null,
        locked: false,
        loading: false,
        loaded: true,
      });
    } catch (e) {
      if (ac.signal.aborted) return;
      if (isLockError(e)) {
        setCritical({
          vulns: null,
          error: null,
          locked: true,
          loading: false,
          loaded: true,
        });
        return;
      }
      setCritical({
        vulns: null,
        error: errMessage(e),
        locked: false,
        loading: false,
        loaded: true,
      });
    }
  }, []);

  // ---- WO-U15: per-agent ADVISORY remediation plan (compliance_sca gate) ----
  // Lazily loaded on first entry to the `vuln` view for the selected agent. The
  // returned `command` strings are DISPLAY ONLY — no execute affordance is wired.
  const loadRemediation = useCallback(async (agentId: string) => {
    remediationAbort.current?.abort();
    const ac = new AbortController();
    remediationAbort.current = ac;
    setRemediation((s) => ({ ...s, loading: true, error: null }));
    try {
      const res = await getVulnRemediation(agentId, 50, ac.signal);
      if (ac.signal.aborted) return;
      setRemediation({
        items: res.remediations,
        error: null,
        locked: false,
        loading: false,
        loaded: true,
      });
    } catch (e) {
      if (ac.signal.aborted) return;
      if (isLockError(e)) {
        setRemediation({
          items: null,
          error: null,
          locked: true,
          loading: false,
          loaded: true,
        });
        return;
      }
      setRemediation({
        items: null,
        error: errMessage(e),
        locked: false,
        loading: false,
        loaded: true,
      });
    }
  }, []);

  // overview: initial + poll
  useEffect(() => {
    loadOverview();
    return () => ovAbort.current?.abort();
  }, [loadOverview, tick]);

  // host: on selected agent change + poll
  useEffect(() => {
    if (!selectedId) {
      setHost({
        syscheck: null,
        rootcheck: null,
        registry: null,
        error: null,
        locked: false,
        loading: false,
      });
      return;
    }
    loadHost(selectedId);
    return () => hostAbort.current?.abort();
  }, [selectedId, loadHost, tick]);

  // per-agent vulns: on selected agent change + poll (independent gate/state)
  useEffect(() => {
    if (!selectedId) {
      setHostVuln({ vulns: null, error: null, locked: false, loading: false });
      return;
    }
    loadHostVuln(selectedId);
    return () => vulnAbort.current?.abort();
  }, [selectedId, loadHostVuln, tick]);

  // WO-U14: reset the lazy inventory/SCA state whenever the host changes, so
  // switching agents never briefly shows the previous host's data. The lazy
  // loaders below re-fetch for the new host only if its view is (re-)entered.
  useEffect(() => {
    invAbort.current?.abort();
    scaAbort.current?.abort();
    scaChecksAbort.current?.abort();
    remediationAbort.current?.abort();
    setInventory(EMPTY_INVENTORY);
    setInvTab("processes");
    setSca(EMPTY_SCA);
    setScaChecks(EMPTY_SCA_CHECKS);
    // WO-U15: remediation is per-agent → reset on agent change so switching
    // hosts never briefly shows the previous agent's plan. Critical vulns are
    // fleet-wide, so they are NOT reset here.
    setRemediation(EMPTY_REMEDIATION);
  }, [selectedId]);

  // WO-U14: inventory is fetched LAZILY — only while its view is active, and
  // refreshed on the poll tick while it stays active. Never fires on host select.
  useEffect(() => {
    if (!selectedId || view !== "inventory") return;
    loadInventory(selectedId);
    return () => invAbort.current?.abort();
  }, [selectedId, view, tick, loadInventory]);

  // WO-U14: SCA policy list — lazy, same cadence as inventory.
  useEffect(() => {
    if (!selectedId || view !== "sca") return;
    loadSca(selectedId);
    return () => scaAbort.current?.abort();
  }, [selectedId, view, tick, loadSca]);

  // WO-U14: SCA check drill — load (and poll-refresh) when a policy is selected.
  useEffect(() => {
    if (!selectedId || view !== "sca" || !scaChecks.policyId) return;
    loadScaChecks(selectedId, scaChecks.policyId);
    return () => scaChecksAbort.current?.abort();
  }, [selectedId, view, scaChecks.policyId, tick, loadScaChecks]);

  // WO-U15: fleet-wide Critical vulns — lazy, only while the vuln view is active,
  // poll-refreshed while it stays active. Fleet-wide → not keyed on the agent.
  useEffect(() => {
    if (view !== "vuln") return;
    loadCriticalVulns();
    return () => criticalAbort.current?.abort();
  }, [view, tick, loadCriticalVulns]);

  // WO-U15: per-agent advisory remediation — lazy, same cadence, keyed on agent.
  useEffect(() => {
    if (!selectedId || view !== "vuln") return;
    loadRemediation(selectedId);
    return () => remediationAbort.current?.abort();
  }, [selectedId, view, tick, loadRemediation]);

  // poll clock
  useEffect(() => {
    const poll = setInterval(() => setTick((t) => t + 1), POLL_MS);
    const clock = setInterval(() => setSecondsAgo((s) => s + 1), 1000);
    return () => {
      clearInterval(poll);
      clearInterval(clock);
    };
  }, []);

  const manualRefresh = useCallback(() => {
    setRefreshing(true);
    setTick((t) => t + 1);
    // clear the spinner shortly after the loads settle
    setTimeout(() => setRefreshing(false), 600);
  }, []);

  const selectedAgent = ov.agents?.find((a) => a.id === selectedId) ?? null;

  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PageHeading
          title="Host integrity"
          sub="File-integrity, policy monitoring, registry changes, and host vulnerabilities — the single pane over what changed on each endpoint."
        />
        <PollingStatus
          className="mt-1"
          secondsAgo={secondsAgo}
          refreshing={refreshing}
          onRefresh={manualRefresh}
        />
      </div>

      {ov.loading && !ov.agents && !ov.vuln ? (
        <StatusState variant="loading" title="Loading host integrity…" />
      ) : (
        <div className="flex flex-col gap-3">
          {/* Vulnerability plane (compliance_sca) */}
          <VulnSection
            summary={ov.vuln}
            locked={ov.vulnLocked}
            error={ov.vulnError}
          />

          {/* Host-integrity plane (host_integrity) */}
          {ov.agentsError && !ov.agents ? (
            <StatusState
              variant="error"
              title="Couldn't load agents"
              description={ov.agentsError}
              action={<Chip onClick={manualRefresh}>Retry</Chip>}
            />
          ) : ov.agents && ov.agents.length === 0 ? (
            <StatusState
              variant="empty"
              title="No agents visible"
              description="No Wazuh agents are mapped to this tenant, so there is no host-integrity data to show."
            />
          ) : ov.agents ? (
            <Panel className="p-4">
              <AgentPicker
                agents={ov.agents}
                selectedId={selectedId}
                onSelect={setSelectedId}
              />
              {selectedAgent && (
                <HostIntegrityBody
                  agent={selectedAgent}
                  host={host}
                  hostVuln={hostVuln}
                  critical={critical}
                  remediation={remediation}
                  inventory={inventory}
                  invTab={invTab}
                  onInvTab={setInvTab}
                  sca={sca}
                  scaChecks={scaChecks}
                  onSelectPolicy={(policyId) =>
                    setScaChecks({
                      policyId,
                      checks: null,
                      error: null,
                      loading: true,
                    })
                  }
                  onBackToPolicies={() => setScaChecks(EMPTY_SCA_CHECKS)}
                  view={view}
                  onView={setView}
                />
              )}
            </Panel>
          ) : null}
        </div>
      )}
    </>
  );
}

function VulnSection({
  summary,
  locked,
  error,
}: {
  summary: VulnSummary | null;
  locked: boolean;
  error: string | null;
}) {
  if (locked) {
    return (
      <Panel className="p-4">
        <div className="mb-2 text-title text-ink">Host vulnerabilities</div>
        <FeatureLockedState feature="Vulnerability data" tier="current" onUpgrade={onUpgrade} />
      </Panel>
    );
  }
  if (error && !summary) {
    return (
      <Panel className="p-4">
        <div className="mb-2 text-title text-ink">Host vulnerabilities</div>
        <StatusState variant="error" title="Couldn't load vulnerability summary" description={error} />
      </Panel>
    );
  }
  if (!summary) return null;

  const sevEntries = Object.entries(summary.by_severity);
  return (
    <Panel className="p-4">
      <div className="mb-2 text-title text-ink">Host vulnerabilities</div>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Tile label="Total vulnerabilities" value={fmtInt(summary.total_vulnerabilities)} />
        <Tile label="Affected agents" value={fmtInt(summary.affected_agents)} />
        <Tile
          label="Critical"
          value={fmtInt(summary.by_severity["Critical"] ?? summary.by_severity["critical"] ?? 0)}
          valueSeverity="crit"
        />
        <Tile
          label="High"
          value={fmtInt(summary.by_severity["High"] ?? summary.by_severity["high"] ?? 0)}
          valueSeverity="high"
        />
      </div>

      {sevEntries.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {sevEntries.map(([sev, count]) => (
            <Chip key={sev} mono aria-label={`${count} ${sev} vulnerabilities`}>
              {sev}: {fmtInt(count)}
            </Chip>
          ))}
        </div>
      )}

      {summary.top_cves.length > 0 && (
        <div className="mt-3">
          <div className="mb-1.5 text-kbd uppercase tracking-wider text-dim2">
            Most frequent CVEs
          </div>
          <div className="flex flex-wrap gap-1.5">
            {summary.top_cves.map((c) => (
              <Chip key={c.cve} mono>
                {c.cve} · {fmtInt(c.count)}
              </Chip>
            ))}
          </div>
        </div>
      )}
      <div className="mt-3 text-kbd text-dim2">
        From the Wazuh vulnerability index, scoped to this tenant&apos;s agents.
        Read-only — remediation is a human-gated action delivered separately.
      </div>
    </Panel>
  );
}

function AgentPicker({
  agents,
  selectedId,
  onSelect,
}: {
  agents: WazuhAgent[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <div>
      <div className="mb-1.5 text-kbd uppercase tracking-wider text-dim2">
        Agent
      </div>
      <div
        className="flex flex-wrap gap-1.5"
        role="group"
        aria-label="Choose an agent to inspect its host integrity"
      >
        {agents.map((a) => {
          const active = a.status === "active";
          const sel = a.id === selectedId;
          return (
            <Chip
              key={a.id}
              variant={sel ? "cite" : "default"}
              onClick={() => onSelect(a.id)}
              aria-label={`Inspect ${a.name ?? a.id} (${a.status ?? "unknown status"})`}
            >
              {/* shape (filled vs hollow) distinguishes status without relying
                  on color alone — the Chip's aria-label carries it for AT. */}
              <span className={active ? "text-teal" : "text-dim2"} aria-hidden="true">
                {active ? "●" : "○"}
              </span>
              {a.name ?? a.id}
              <span className="text-dim2"> · {a.id}</span>
            </Chip>
          );
        })}
      </div>
    </div>
  );
}

function HostIntegrityBody({
  agent,
  host,
  hostVuln,
  critical,
  remediation,
  inventory,
  invTab,
  onInvTab,
  sca,
  scaChecks,
  onSelectPolicy,
  onBackToPolicies,
  view,
  onView,
}: {
  agent: WazuhAgent;
  host: HostState;
  hostVuln: HostVulnState;
  critical: CriticalVulnState;
  remediation: RemediationState;
  inventory: InventoryState;
  invTab: InventoryTab;
  onInvTab: (t: InventoryTab) => void;
  sca: ScaState;
  scaChecks: ScaChecksState;
  onSelectPolicy: (policyId: string) => void;
  onBackToPolicies: () => void;
  view: HostView;
  onView: (v: HostView) => void;
}) {
  const agentLabel = agent.name ?? agent.id;
  const invCount = inventory.loaded
    ? (inventory.processes?.length ?? 0) +
      (inventory.ports?.length ?? 0) +
      (inventory.packages?.length ?? 0)
    : undefined;
  return (
    <div className="mt-3">
      {/* agent summary */}
      <div className="mb-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-kbd text-dim2">
        <span className="font-mono text-dim">{agent.ip ?? DASH}</span>
        <span>{agent.os?.name ?? agent.os?.platform ?? DASH}</span>
        <span>{agent.version ?? DASH}</span>
        <span>last seen {fmtDateTime(agent.lastKeepAlive)}</span>
      </div>

      {/* sub-view selector — always shown. FIM/rootcheck/registry ride the
          host_integrity gate; vulnerabilities ride compliance_sca, so each view
          shows its OWN lock rather than one lock blanking the others. Inventory
          and SCA (WO-U14) are verify_jwt-only and lazily loaded on first entry. */}
      <div className="mb-2 flex flex-wrap gap-1.5" role="group" aria-label="Host integrity view">
        <ViewChip id="fim" view={view} onView={onView} count={host.syscheck?.length}>
          File integrity
        </ViewChip>
        <ViewChip id="rootcheck" view={view} onView={onView} count={host.rootcheck?.length}>
          Policy monitoring
        </ViewChip>
        <ViewChip id="registry" view={view} onView={onView} count={host.registry?.length}>
          Registry
        </ViewChip>
        <ViewChip id="inventory" view={view} onView={onView} count={invCount}>
          Inventory
        </ViewChip>
        <ViewChip id="sca" view={view} onView={onView} count={sca.policies?.length}>
          Configuration assessment
        </ViewChip>
        <ViewChip id="vuln" view={view} onView={onView} count={hostVuln.vulns?.length}>
          Vulnerabilities
        </ViewChip>
      </div>

      {view === "vuln" ? (
        <VulnView
          hostVuln={hostVuln}
          critical={critical}
          remediation={remediation}
          agentId={agent.id}
          agentLabel={agentLabel}
        />
      ) : view === "inventory" ? (
        <InventoryView
          inventory={inventory}
          invTab={invTab}
          onInvTab={onInvTab}
        />
      ) : view === "sca" ? (
        <ScaView
          sca={sca}
          scaChecks={scaChecks}
          onSelectPolicy={onSelectPolicy}
          onBackToPolicies={onBackToPolicies}
        />
      ) : host.locked ? (
        <FeatureLockedState feature="Host integrity (FIM / rootcheck / registry)" tier="current" onUpgrade={onUpgrade} />
      ) : host.loading && !host.syscheck ? (
        <StatusState variant="loading" title="Loading host integrity…" />
      ) : host.error ? (
        <StatusState variant="error" title="Couldn't load host integrity" description={host.error} />
      ) : view === "rootcheck" ? (
        <RootcheckTable rows={host.rootcheck ?? []} />
      ) : (
        <SyscheckTable
          rows={(view === "registry" ? host.registry : host.syscheck) ?? []}
          isRegistry={view === "registry"}
        />
      )}
    </div>
  );
}

function ViewChip({
  id,
  view,
  onView,
  count,
  children,
}: {
  id: HostView;
  view: HostView;
  onView: (v: HostView) => void;
  count?: number;
  children: React.ReactNode;
}) {
  return (
    <Chip
      variant={view === id ? "cite" : "default"}
      onClick={() => onView(id)}
      aria-label={`Show ${String(children)}`}
    >
      {children}
      {count != null && <span className="text-dim2"> · {count}</span>}
    </Chip>
  );
}

function SyscheckTable({
  rows,
  isRegistry,
}: {
  rows: SyscheckEntry[];
  isRegistry: boolean;
}) {
  if (rows.length === 0) {
    return (
      <StatusState
        variant="empty"
        title={isRegistry ? "No registry changes" : "No file-integrity changes"}
        description={
          isRegistry
            ? "No monitored Windows registry keys have changed on this agent (or this is not a Windows host)."
            : "No monitored files have changed on this agent."
        }
      />
    );
  }
  return (
    <div className="max-h-[55vh] overflow-auto rounded-lg border border-line">
      <Table>
        <THead>
          <TR>
            <TH>{isRegistry ? "Key" : "File"}</TH>
            <TH>Change</TH>
            <TH>Modified</TH>
            {!isRegistry && <TH className="text-right">Size</TH>}
            {!isRegistry && <TH>Owner</TH>}
            <TH>SHA-256</TH>
          </TR>
        </THead>
        <TBody>
          {rows.map((r, i) => (
            <TR key={`${r.file ?? i}-${i}`}>
              <TD mono>
                <span className="break-all">{r.file ?? DASH}</span>
              </TD>
              <TD>
                <ChangeGlyph type={r.type} />
              </TD>
              <TD>{fmtDateTime(r.mtime)}</TD>
              {!isRegistry && <TD mono className="text-right">{fmtBytes(r.size)}</TD>}
              {!isRegistry && <TD mono>{r.uname ?? DASH}</TD>}
              <TD mono>
                {r.sha256 ? (
                  <span className="text-dim2" title={r.sha256}>
                    {String(r.sha256).slice(0, 12)}…
                  </span>
                ) : r.md5 ? (
                  <span className="text-dim2" title={`md5 ${r.md5}`}>
                    md5 {String(r.md5).slice(0, 10)}…
                  </span>
                ) : (
                  DASH
                )}
              </TD>
            </TR>
          ))}
        </TBody>
      </Table>
    </div>
  );
}

function ChangeGlyph({ type }: { type?: string | null }) {
  const t = (type ?? "").toLowerCase();
  const cls =
    t === "added"
      ? "text-teal"
      : t === "deleted"
        ? "text-sev-crit"
        : t === "modified"
          ? "text-sev-med"
          : "text-dim";
  return <span className={cls}>{type ?? DASH}</span>;
}

function RootcheckTable({ rows }: { rows: RootcheckEntry[] }) {
  if (rows.length === 0) {
    return (
      <StatusState
        variant="empty"
        title="No policy findings"
        description="Rootcheck / policy-monitoring has no outstanding findings for this agent."
      />
    );
  }
  return (
    <div className="max-h-[55vh] overflow-auto rounded-lg border border-line">
      <Table>
        <THead>
          <TR>
            <TH>Finding</TH>
            <TH>Status</TH>
            <TH>CIS</TH>
            <TH>PCI-DSS</TH>
            <TH>Last seen</TH>
          </TR>
        </THead>
        <TBody>
          {rows.map((r, i) => {
            const outstanding = (r.status ?? "").toLowerCase() !== "solved";
            return (
              <TR key={i}>
                <TD>
                  <div className="text-ink">{r.title ?? r.log ?? DASH}</div>
                  {r.title && r.log && (
                    <div className="max-w-[520px] truncate text-kbd text-dim2" title={r.log}>
                      {r.log}
                    </div>
                  )}
                </TD>
                <TD>
                  <span className={outstanding ? "text-sev-med" : "text-teal"}>
                    {r.status ?? DASH}
                  </span>
                </TD>
                <TD mono>{r.cis ?? DASH}</TD>
                <TD mono>{r.pci_dss ?? DASH}</TD>
                <TD>{fmtDateTime(r.date_last)}</TD>
              </TR>
            );
          })}
        </TBody>
      </Table>
    </div>
  );
}

// ---- per-agent vulnerabilities (compliance_sca) -----------------------------

const VULN_SEV_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

/** Defensively pull the display fields off a raw Wazuh vuln document. */
function vulnFields(v: AgentVulnerability) {
  const asStr = (x: unknown): string | null =>
    typeof x === "string" && x ? x : null;
  const asNum = (x: unknown): number | null =>
    typeof x === "number" ? x : null;
  return {
    cve: asStr(v.vulnerability?.id),
    severity: asStr(v.vulnerability?.severity),
    cvss: asNum(v.vulnerability?.score?.base),
    pkg: asStr(v.package?.name),
    version: asStr(v.package?.version),
    reference: asStr(v.vulnerability?.reference),
  };
}

function vulnSevClass(sev: string | null): string {
  switch ((sev ?? "").toLowerCase()) {
    case "critical":
      return "text-sev-crit";
    case "high":
      return "text-sev-high";
    case "medium":
      return "text-sev-med";
    case "low":
      return "text-sev-low";
    default:
      return "text-dim";
  }
}

function AgentVulnTable({
  rows,
  agentLabel,
}: {
  rows: AgentVulnerability[];
  agentLabel: string;
}) {
  if (rows.length === 0) {
    return (
      <StatusState
        variant="empty"
        title="No vulnerabilities reported"
        description={`The Wazuh vulnerability index has no findings for ${agentLabel} (or this agent has not been scanned).`}
      />
    );
  }
  // Worst-first: by CVSS desc, then severity rank desc.
  const sorted = [...rows].sort((a, b) => {
    const fa = vulnFields(a);
    const fb = vulnFields(b);
    const cvssDelta = (fb.cvss ?? -1) - (fa.cvss ?? -1);
    if (cvssDelta !== 0) return cvssDelta;
    return (
      (VULN_SEV_RANK[(fb.severity ?? "").toLowerCase()] ?? 0) -
      (VULN_SEV_RANK[(fa.severity ?? "").toLowerCase()] ?? 0)
    );
  });
  return (
    <>
      <div className="max-h-[55vh] overflow-auto rounded-lg border border-line">
        <Table>
          <THead>
            <TR>
              <TH>CVE</TH>
              <TH>Severity</TH>
              <TH className="text-right">CVSS</TH>
              <TH>Package</TH>
              <TH>Version</TH>
            </TR>
          </THead>
          <TBody>
            {sorted.map((v, i) => {
              const f = vulnFields(v);
              return (
                <TR key={`${f.cve ?? i}-${f.pkg ?? i}-${i}`}>
                  <TD mono>{f.cve ?? DASH}</TD>
                  <TD>
                    <span className={`font-semibold ${vulnSevClass(f.severity)}`}>
                      {f.severity ?? DASH}
                    </span>
                  </TD>
                  <TD mono className="text-right">
                    {f.cvss == null ? DASH : fmtNum(f.cvss)}
                  </TD>
                  <TD mono>{f.pkg ?? DASH}</TD>
                  <TD mono>{f.version ?? DASH}</TD>
                </TR>
              );
            })}
          </TBody>
        </Table>
      </div>
      <div className="mt-2 text-kbd text-dim2">
        This agent&apos;s vulnerabilities, from the Wazuh vulnerability index
        filtered to <span className="font-mono">{agentLabel}</span>. Read-only —
        remediation is a human-gated action delivered separately.
      </div>
    </>
  );
}

// ---- WO-U15 (READ half): fleet Critical vulns + advisory remediation --------
// Both sections ride the SAME `compliance_sca` gate as the per-agent vuln reads.
// When that gate is locked the per-agent panel already shows the FeatureLockedState,
// so these two supplementary sections render null under a lock rather than stacking
// duplicate lock notes. Everything here is READ-ONLY: the advisory remediation
// `command` is DISPLAY ONLY — there is NO execute/run/apply affordance anywhere.

/**
 * The `vuln` sub-view: the existing per-agent vulnerability table, then the
 * fleet-wide Critical vulns section, then this agent's advisory remediation plan.
 */
function VulnView({
  hostVuln,
  critical,
  remediation,
  agentId,
  agentLabel,
}: {
  hostVuln: HostVulnState;
  critical: CriticalVulnState;
  remediation: RemediationState;
  agentId: string;
  agentLabel: string;
}) {
  return (
    <div className="flex flex-col gap-4">
      {/* per-agent vulnerabilities (unchanged from WO-U9) */}
      <div>
        {hostVuln.locked ? (
          <FeatureLockedState feature="Host vulnerabilities" tier="current" onUpgrade={onUpgrade} />
        ) : hostVuln.loading && !hostVuln.vulns ? (
          <StatusState variant="loading" title="Loading vulnerabilities…" />
        ) : hostVuln.error ? (
          <StatusState
            variant="error"
            title="Couldn't load this agent's vulnerabilities"
            description={hostVuln.error}
          />
        ) : (
          <AgentVulnTable rows={hostVuln.vulns ?? []} agentLabel={agentLabel} />
        )}
      </div>

      <CriticalVulnsSection critical={critical} />
      <RemediationSection
        remediation={remediation}
        agentId={agentId}
        agentLabel={agentLabel}
      />
    </div>
  );
}

/** Agent label for a fleet critical-vuln row (name · id), best-effort. */
function critAgentLabel(v: AgentVulnerability): string {
  const name = typeof v.agent?.name === "string" && v.agent.name ? v.agent.name : null;
  const id = typeof v.agent?.id === "string" && v.agent.id ? v.agent.id : null;
  if (name && id) return `${name} · ${id}`;
  return name ?? id ?? DASH;
}

function CriticalVulnsSection({ critical }: { critical: CriticalVulnState }) {
  // Same compliance_sca gate as the per-agent panel — which already shows the
  // lock — so degrade this supplementary section to nothing under a lock.
  if (critical.locked) return null;
  return (
    <div>
      <div className="mb-2 text-title text-ink">
        Critical vulnerabilities (fleet-wide)
      </div>
      {critical.loading && !critical.loaded ? (
        <StatusState variant="loading" title="Loading critical vulnerabilities…" />
      ) : critical.error ? (
        <StatusState
          variant="error"
          title="Couldn't load critical vulnerabilities"
          description={critical.error}
        />
      ) : (
        <CriticalVulnTable rows={critical.vulns ?? []} />
      )}
    </div>
  );
}

function CriticalVulnTable({ rows }: { rows: AgentVulnerability[] }) {
  if (rows.length === 0) {
    return (
      <StatusState
        variant="empty"
        title="No critical vulnerabilities"
        description="The Wazuh vulnerability index reports no Critical-severity findings across this tenant's agents."
      />
    );
  }
  // Worst-first by CVSS desc (severity is already all Critical here).
  const sorted = [...rows].sort((a, b) => {
    const ca = vulnFields(a).cvss ?? -1;
    const cb = vulnFields(b).cvss ?? -1;
    return cb - ca;
  });
  return (
    <>
      <div className="max-h-[55vh] overflow-auto rounded-lg border border-line">
        <Table>
          <THead>
            <TR>
              <TH>CVE</TH>
              <TH>Severity</TH>
              <TH className="text-right">CVSS</TH>
              <TH>Package</TH>
              <TH>Version</TH>
              <TH>Agent</TH>
              <TH>Title</TH>
            </TR>
          </THead>
          <TBody>
            {sorted.map((v, i) => {
              const f = vulnFields(v);
              const title = cell(v.vulnerability?.title);
              return (
                <TR key={`${f.cve ?? i}-${f.pkg ?? i}-${i}`}>
                  <TD mono>{f.cve ?? DASH}</TD>
                  <TD>
                    <span className={`font-semibold ${vulnSevClass(f.severity)}`}>
                      {f.severity ?? DASH}
                    </span>
                  </TD>
                  <TD mono className="text-right">
                    {f.cvss == null ? DASH : fmtNum(f.cvss)}
                  </TD>
                  <TD mono>{f.pkg ?? DASH}</TD>
                  <TD mono>{f.version ?? DASH}</TD>
                  <TD mono>{critAgentLabel(v)}</TD>
                  <TD>
                    <span className="block max-w-[360px] truncate" title={title}>
                      {title}
                    </span>
                  </TD>
                </TR>
              );
            })}
          </TBody>
        </Table>
      </div>
      <div className="mt-2 text-kbd text-dim2">
        Fleet-wide Critical-severity vulnerabilities from the Wazuh vulnerability
        index, scoped to this tenant&apos;s agents. Read-only.
      </div>
    </>
  );
}

function RemediationSection({
  remediation,
  agentId,
  agentLabel,
}: {
  remediation: RemediationState;
  agentId: string;
  agentLabel: string;
}) {
  if (remediation.locked) return null;
  return (
    <div>
      <div className="mb-1 text-title text-ink">Recommended remediation</div>
      <div className="mb-2 text-kbd text-dim2">
        Recommended package-update commands for{" "}
        <span className="font-mono">{agentLabel}</span>. For most roles this is
        advisory — copy a command and apply it through your own change process. An{" "}
        <span className="text-ink">administrator</span> can instead apply a single
        package update on the host directly via the audited{" "}
        <span className="text-ink">Remediate</span> action on a row below (Wazuh
        active response — human-approved, and logged).
      </div>
      {remediation.loading && !remediation.loaded ? (
        <StatusState variant="loading" title="Loading recommended remediation…" />
      ) : remediation.error ? (
        <StatusState
          variant="error"
          title="Couldn't load recommended remediation"
          description={remediation.error}
        />
      ) : (
        <RemediationList
          rows={remediation.items ?? []}
          agentId={agentId}
          agentLabel={agentLabel}
        />
      )}
    </div>
  );
}

function RemediationList({
  rows,
  agentId,
  agentLabel,
}: {
  rows: VulnRemediation[];
  agentId: string;
  agentLabel: string;
}) {
  if (rows.length === 0) {
    return (
      <StatusState
        variant="empty"
        title="No remediation recommendations"
        description={`No recommended remediation is available for ${agentLabel} (this agent may have no scanned vulnerabilities).`}
      />
    );
  }
  return (
    <div className="flex flex-col gap-2">
      {rows.map((r, i) => {
        const cve = cell(pick(r, "cve_id", "cve", "vulnerability_id", "id"));
        const pkg = cell(pick(r, "package_name", "package", "pkg"));
        const cur = cell(pick(r, "current_version", "version", "installed_version"));
        const fix = cell(pick(r, "fix_version", "fix_hint", "fix"));
        const sev = pick(r, "severity");
        const sevStr = typeof sev === "string" && sev ? sev : null;
        const command = pick(r, "command", "remediation", "fix_command");
        const commandStr =
          typeof command === "string" && command ? command : null;
        return (
          <div
            key={`${cve}-${pkg}-${i}`}
            className="rounded-lg border border-line p-3"
          >
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <span className="font-mono text-ink">{cve}</span>
              {sevStr && (
                <span className={`font-semibold ${vulnSevClass(sevStr)}`}>
                  {sevStr}
                </span>
              )}
              <span className="text-kbd text-dim2">
                {pkg}
                {cur !== DASH ? ` · ${cur}` : ""}
              </span>
              {fix !== DASH && (
                <span className="text-kbd text-teal">→ {fix}</span>
              )}
            </div>
            {commandStr ? (
              // DISPLAY ONLY — selectable/copyable text; the copy path never
              // executes it. The audited execute path is the admin-gated
              // RemediateAction below (a deliberate escalation from advisory).
              <pre className="mt-2 overflow-x-auto rounded-md border border-line bg-field p-2.5 font-mono text-[11.5px] leading-relaxed text-dim whitespace-pre-wrap break-words">
                {commandStr}
              </pre>
            ) : (
              <div className="mt-2 text-kbd text-dim2">
                No remediation command available for this vulnerability.
              </div>
            )}
            {/* WO-U15 EXECUTE half — the ADMIN-ONLY, confirm-gated Remediate
                action. Only where a concrete package name is known (the server
                needs agent_id + package_name). Below admin → a locked chip. */}
            {pkg !== DASH && (
              <RemediateAction
                agentId={agentId}
                agentLabel={agentLabel}
                packageName={pkg}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}

// ---- WO-U15 (EXECUTE half): admin-only, confirm-gated Remediate action -------
// STATE-CHANGING / ACTIVE-RESPONSE-ADJACENT. Mirrors `POST /api/vulnerabilities/
// remediate`'s `require_admin` gate EXACTLY via `vulnRemediationGate` — below
// admin there is NO enabled trigger, only a locked chip. Running it dispatches a
// real package-update command on the host via Wazuh active response; it is human-
// confirmed and server-audited. Nothing runs until the admin confirms in the
// dialog. After a `pending` dispatch the admin confirms the update landed via
// `verifyRemediation` (explicit button; the exec response's `version_before` feeds
// the before→after check). Runtime gates are handled gracefully: 400 (platform /
// agent-id) → advisory fallback, 429 → rate-limited note, 402/403 → locked/denied.

function remediateErrMessage(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 400) {
      return "Automated update isn't supported on this host's OS (only Linux apt/yum/zypper), or the agent id was rejected — apply the advisory command shown above manually through your change process. Nothing changed.";
    }
    if (e.status === 429) {
      return "Remediation is rate-limited (3 per minute). Wait a moment and try again — nothing changed.";
    }
    if (e.status === 402 || e.status === 403) {
      return "Your role or license tier doesn't permit remediation — this action is admin-only and needs the vuln_remediation entitlement. The server denied it; nothing changed.";
    }
    if (e.status === 404) {
      return "The agent was not found on the Wazuh manager — nothing changed.";
    }
    if (e.status === 401) {
      return "Your session has expired — sign in again. Nothing changed.";
    }
  }
  return errMessage(e);
}

function verifyPresentation(r: RemediationVerifyResult): {
  text: string;
  className: string;
} {
  switch (r.status) {
    case "updated":
      return { text: r.message, className: "text-teal" };
    // WO-H41: version unchanged AND a dispatch happened within the last scan
    // interval — UNKNOWN, not a success claim. Either the inventory hasn't
    // refreshed yet or the upgrade did not apply; the operator re-verifies
    // after the next scan. NEUTRAL — neither success nor failure.
    case "pending_inventory_refresh":
      return {
        text:
          r.message ||
          "Version unchanged in Wazuh's inventory — not yet confirmed. Re-verify after the agent's next package scan.",
        className: "text-sev-low",
      };
    case "possibly_updated":
      return { text: r.message, className: "text-sev-low" };
    // WO-H36: version KNOWN and UNCHANGED — the upgrade did not take effect.
    // Treated as a hard negative (like "unchanged"), never a soft maybe.
    case "not_upgraded":
      return { text: r.message, className: "text-sev-high" };
    case "unchanged":
      return { text: r.message, className: "text-sev-med" };
    case "not_found":
      return { text: r.message, className: "text-dim2" };
    default:
      return { text: r.message || `Status: ${r.status}`, className: "text-dim" };
  }
}

function RemediateAction({
  agentId,
  agentLabel,
  packageName,
}: {
  agentId: string;
  agentLabel: string;
  packageName: string;
}) {
  const { role } = useAuth();
  const gate = vulnRemediationGate(role);

  const [open, setOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [dialogError, setDialogError] = useState<string | null>(null);
  const [dispatch, setDispatch] = useState<{
    tone: "ok" | "warn";
    msg: string;
    versionBefore: string | null;
  } | null>(null);
  const [verify, setVerify] = useState<{
    loading: boolean;
    result: RemediationVerifyResult | null;
    error: string | null;
  } | null>(null);

  // Below admin: NO enabled trigger, ever — a locked chip mirrors require_admin.
  // The server re-checks; this only prevents a dead control (never widens).
  if (!gate.canRemediate) {
    return (
      <div className="mt-2">
        <Chip variant="gated" aria-label="Remediation requires an administrator">
          Locked · admin
        </Chip>
      </div>
    );
  }

  const closeConfirm = () => {
    if (submitting) return; // don't let the dialog close mid-dispatch
    setOpen(false);
    setDialogError(null);
  };

  const onExecute = async () => {
    setSubmitting(true);
    setDialogError(null);
    try {
      const res = await executeRemediation(agentId, packageName);
      if (res.status === "failed") {
        setDialogError(
          `The update command failed to dispatch${
            res.result?.error ? `: ${res.result.error}` : "."
          } Nothing changed on ${agentLabel}. The attempt is recorded server-side.`,
        );
        return;
      }
      if (res.status === "not_applied") {
        // WO-H36: Wazuh accepted the call but dispatched it to no agent
        // (total_affected_items=0 — e.g. the remediation AR capability isn't
        // registered on this agent). Nothing was upgraded — surface it as a
        // distinct not-applied state, never as a pending success.
        setDialogError(
          `Wazuh accepted the command but dispatched it to no agent — the remediation active-response capability is not registered on ${agentLabel}, so nothing was upgraded. The attempt is recorded server-side. Register dhruva-pkg-upgrade on the agent (see deploy/wazuh/active-response) and retry.`,
        );
        return;
      }
      if (res.status !== "pending") {
        // WO-H36 QA (fail-CLOSED): only the known "pending" status is a
        // dispatch-accepted success. Any OTHER value (an unexpected/newer
        // server status) must NOT be shown as a pending-success — that would
        // claim the update is in flight when we can't confirm it. Surface a
        // neutral "unknown status" note and let the admin verify.
        setDialogError(
          `The server returned an unexpected remediation status ("${res.status}") for ${packageName} on ${agentLabel}. Do not assume the update was dispatched — check the audit trail and run Verify before trusting it.`,
        );
        return;
      }
      // pending — the AR command was ACCEPTED, not yet confirmed landed.
      setDispatch({
        tone: "ok",
        msg: `Update dispatched for ${packageName} on ${agentLabel} via active response (audited). It is accepted, not yet confirmed — verify once it lands.`,
        versionBefore: res.version_before,
      });
      setVerify(null);
      setOpen(false);
    } catch (e) {
      // Keep the dialog OPEN on a thrown error so the admin sees why nothing ran.
      setDialogError(remediateErrMessage(e));
    } finally {
      setSubmitting(false);
    }
  };

  const onVerify = async () => {
    setVerify({ loading: true, result: null, error: null });
    try {
      const res = await verifyRemediation(
        agentId,
        packageName,
        dispatch?.versionBefore ?? undefined,
      );
      setVerify({ loading: false, result: res, error: null });
    } catch (e) {
      setVerify({
        loading: false,
        result: null,
        error: remediateErrMessage(e),
      });
    }
  };

  const verdict = verify?.result ? verifyPresentation(verify.result) : null;

  return (
    <div className="mt-2">
      {!dispatch ? (
        <button
          type="button"
          onClick={() => {
            setDialogError(null);
            setOpen(true);
          }}
          className={cn(
            "cursor-pointer rounded-md border border-gated-border bg-field px-2.5 py-1 text-meta text-gated-ink hover:brightness-125",
            focusRing,
          )}
        >
          Remediate…
        </button>
      ) : (
        <div
          role="status"
          aria-live="polite"
          className={cn(
            "rounded-lg border bg-panel2 px-3.5 py-2.5 text-data",
            dispatch.tone === "ok"
              ? "border-grounded-border text-grounded-ink"
              : "border-gated-border text-gated-ink",
          )}
        >
          <div>{dispatch.msg}</div>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={onVerify}
              disabled={verify?.loading}
              className={cn(
                "rounded-md border border-line bg-field px-2.5 py-1 text-meta text-ink hover:bg-hover",
                focusRing,
                verify?.loading && "cursor-not-allowed opacity-60",
              )}
            >
              {verify?.loading
                ? "Verifying…"
                : verify?.result
                  ? "Verify again"
                  : "Verify update"}
            </button>
            {verify?.error && (
              <span className="text-kbd text-sev-crit">{verify.error}</span>
            )}
            {verdict && (
              <span className={cn("text-kbd font-semibold", verdict.className)}>
                {verdict.text}
              </span>
            )}
          </div>
        </div>
      )}

      <Dialog
        open={open}
        onClose={closeConfirm}
        maxWidth={540}
        title="Remediate vulnerability — run package update"
      >
        <p className="text-data text-dim">
          This runs a{" "}
          <b>package-update command on the host via Wazuh active response</b> — a
          state-changing action. It is <b>admin-only, audited, and logged
          server-side</b>. Nothing runs until you confirm.
        </p>

        <dl className="mt-3 grid grid-cols-[7rem_1fr] gap-x-3 gap-y-1.5 rounded-lg border border-line bg-panel2 px-3.5 py-3 text-data">
          <dt className="text-dim2">Host</dt>
          <dd className="font-mono text-ink">{agentLabel}</dd>

          <dt className="text-dim2">Agent id</dt>
          <dd className="font-mono text-ink">{agentId}</dd>

          <dt className="text-dim2">Package</dt>
          <dd className="font-mono text-ink">{packageName}</dd>

          <dt className="text-dim2">Action</dt>
          <dd className="text-ink">
            Update <span className="font-mono">{packageName}</span> to its fixed
            version via the host&apos;s package manager (apt / yum / zypper).
          </dd>
        </dl>

        <p className="mt-3 text-kbd text-dim2">
          Only a Linux host with a supported package manager can be updated
          automatically; on any other platform the server declines and you should
          apply the advisory command manually.
        </p>

        {dialogError && (
          <p className="mt-3 text-data text-sev-crit" role="alert">
            {dialogError}
          </p>
        )}

        <div className="mt-4 flex items-center gap-2">
          <button
            type="button"
            onClick={onExecute}
            disabled={submitting}
            className={cn(
              "rounded-md border px-3 py-1.5 text-data",
              focusRing,
              submitting
                ? "cursor-not-allowed border-line bg-field text-dim opacity-60"
                : "cursor-pointer border-gated-border bg-field text-gated-ink hover:brightness-125",
            )}
          >
            {submitting ? "Dispatching…" : "Run update now"}
          </button>
          <button
            type="button"
            onClick={closeConfirm}
            disabled={submitting}
            className={cn(
              "rounded-md border border-line bg-field px-3 py-1.5 text-data text-ink hover:bg-hover",
              focusRing,
              submitting && "cursor-not-allowed opacity-60",
            )}
          >
            Cancel
          </button>
        </div>
      </Dialog>
    </div>
  );
}

// ---- WO-U14: syscollector inventory + SCA -----------------------------------
// All fields below come from RAW Wazuh syscollector / SCA dicts whose exact keys
// vary by Wazuh version and OS, so every cell is read through `cell()` — any
// absent / non-scalar value renders a dash, never crashing the table.

/** Coerce an unknown Wazuh field to a display string, or DASH when absent. */
function cell(v: unknown): string {
  if (v == null) return DASH;
  if (typeof v === "string") return v.length ? v : DASH;
  if (typeof v === "number") return Number.isFinite(v) ? String(v) : DASH;
  if (typeof v === "boolean") return v ? "true" : "false";
  return DASH;
}

/** First present, non-empty scalar among several candidate keys. */
function pick(obj: Record<string, unknown>, ...keys: string[]): unknown {
  for (const k of keys) {
    const v = obj[k];
    if (v != null && v !== "") return v;
  }
  return null;
}

function InventoryView({
  inventory,
  invTab,
  onInvTab,
}: {
  inventory: InventoryState;
  invTab: InventoryTab;
  onInvTab: (t: InventoryTab) => void;
}) {
  if (inventory.loading && !inventory.loaded) {
    return <StatusState variant="loading" title="Loading host inventory…" />;
  }
  if (inventory.error && !inventory.processes) {
    return (
      <StatusState
        variant="error"
        title="Couldn't load host inventory"
        description={inventory.error}
      />
    );
  }
  const counts: Record<InventoryTab, number | undefined> = {
    processes: inventory.processes?.length,
    ports: inventory.ports?.length,
    packages: inventory.packages?.length,
  };
  return (
    <div>
      <div
        className="mb-2 flex flex-wrap gap-1.5"
        role="group"
        aria-label="Inventory category"
      >
        <SubTabChip id="processes" active={invTab} onSelect={onInvTab} count={counts.processes}>
          Processes
        </SubTabChip>
        <SubTabChip id="ports" active={invTab} onSelect={onInvTab} count={counts.ports}>
          Ports
        </SubTabChip>
        <SubTabChip id="packages" active={invTab} onSelect={onInvTab} count={counts.packages}>
          Packages
        </SubTabChip>
      </div>

      {invTab === "processes" ? (
        <ProcessTable rows={inventory.processes ?? []} />
      ) : invTab === "ports" ? (
        <PortTable rows={inventory.ports ?? []} />
      ) : (
        <PackageTable rows={inventory.packages ?? []} />
      )}

      <div className="mt-2 text-kbd text-dim2">
        Point-in-time syscollector inventory for this agent, scoped to this tenant.
        Read-only.
      </div>
    </div>
  );
}

function SubTabChip({
  id,
  active,
  onSelect,
  count,
  children,
}: {
  id: InventoryTab;
  active: InventoryTab;
  onSelect: (t: InventoryTab) => void;
  count?: number;
  children: React.ReactNode;
}) {
  return (
    <Chip
      variant={active === id ? "cite" : "default"}
      onClick={() => onSelect(id)}
      aria-label={`Show ${String(children)}`}
    >
      {children}
      {count != null && <span className="text-dim2"> · {count}</span>}
    </Chip>
  );
}

function ProcessTable({ rows }: { rows: AgentProcess[] }) {
  if (rows.length === 0) {
    return (
      <StatusState
        variant="empty"
        title="No processes reported"
        description="Syscollector has no running-process inventory for this agent (or the module is disabled)."
      />
    );
  }
  return (
    <div className="max-h-[55vh] overflow-auto rounded-lg border border-line">
      <Table>
        <THead>
          <TR>
            <TH>Process</TH>
            <TH className="text-right">PID</TH>
            <TH className="text-right">PPID</TH>
            <TH>User</TH>
            <TH>State</TH>
            <TH>Command</TH>
          </TR>
        </THead>
        <TBody>
          {rows.map((r, i) => (
            <TR key={`${cell(r.pid)}-${i}`}>
              <TD mono>{cell(r.name)}</TD>
              <TD mono className="text-right">{cell(r.pid)}</TD>
              <TD mono className="text-right">{cell(r.ppid)}</TD>
              <TD mono>{cell(pick(r, "euser", "user"))}</TD>
              <TD>{cell(r.state)}</TD>
              <TD mono>
                <span className="block max-w-[420px] truncate" title={cell(pick(r, "cmd", "command"))}>
                  {cell(pick(r, "cmd", "command"))}
                </span>
              </TD>
            </TR>
          ))}
        </TBody>
      </Table>
    </div>
  );
}

/** Local address of a port, tolerant of both `local:{ip,port}` and flat keys. */
function portLocal(p: AgentPort): string {
  const ip = p.local?.ip ?? (pick(p, "local_ip") as string | number | null);
  const port = p.local?.port ?? (pick(p, "local_port") as string | number | null);
  const ipStr = ip == null || ip === "" ? null : String(ip);
  const portStr = port == null || port === "" ? null : String(port);
  if (ipStr && portStr) return `${ipStr}:${portStr}`;
  return ipStr ?? portStr ?? DASH;
}

function PortTable({ rows }: { rows: AgentPort[] }) {
  if (rows.length === 0) {
    return (
      <StatusState
        variant="empty"
        title="No open ports reported"
        description="Syscollector has no open-port / network-connection inventory for this agent."
      />
    );
  }
  return (
    <div className="max-h-[55vh] overflow-auto rounded-lg border border-line">
      <Table>
        <THead>
          <TR>
            <TH>Protocol</TH>
            <TH>Local address</TH>
            <TH>State</TH>
            <TH>Process</TH>
            <TH className="text-right">PID</TH>
          </TR>
        </THead>
        <TBody>
          {rows.map((r, i) => (
            <TR key={`${portLocal(r)}-${cell(r.protocol)}-${i}`}>
              <TD mono>{cell(r.protocol)}</TD>
              <TD mono>{portLocal(r)}</TD>
              <TD>{cell(r.state)}</TD>
              <TD mono>{cell(r.process)}</TD>
              <TD mono className="text-right">{cell(r.pid)}</TD>
            </TR>
          ))}
        </TBody>
      </Table>
    </div>
  );
}

function PackageTable({ rows }: { rows: AgentPackage[] }) {
  if (rows.length === 0) {
    return (
      <StatusState
        variant="empty"
        title="No packages reported"
        description="Syscollector has no installed-package inventory for this agent."
      />
    );
  }
  return (
    <div className="max-h-[55vh] overflow-auto rounded-lg border border-line">
      <Table>
        <THead>
          <TR>
            <TH>Package</TH>
            <TH>Version</TH>
            <TH>Arch</TH>
            <TH>Format</TH>
            <TH>Vendor</TH>
          </TR>
        </THead>
        <TBody>
          {rows.map((r, i) => (
            <TR key={`${cell(r.name)}-${cell(r.version)}-${i}`}>
              <TD mono>{cell(r.name)}</TD>
              <TD mono>{cell(r.version)}</TD>
              <TD mono>{cell(pick(r, "architecture", "arch"))}</TD>
              <TD mono>{cell(r.format)}</TD>
              <TD>{cell(r.vendor)}</TD>
            </TR>
          ))}
        </TBody>
      </Table>
    </div>
  );
}

// ---- SCA (configuration assessment) — policy list → per-policy checks --------

function ScaView({
  sca,
  scaChecks,
  onSelectPolicy,
  onBackToPolicies,
}: {
  sca: ScaState;
  scaChecks: ScaChecksState;
  onSelectPolicy: (policyId: string) => void;
  onBackToPolicies: () => void;
}) {
  const note = (
    <div className="mt-2 text-kbd text-dim2">
      Read-only. A failed configuration check also raises this host&apos;s triage
      risk score, so these findings feed alert prioritisation as well as compliance.
    </div>
  );

  // Drill: a policy is selected → show its checks.
  if (scaChecks.policyId) {
    const policy = sca.policies?.find(
      (p) => String(p.policy_id ?? "") === scaChecks.policyId,
    );
    const title = cell(pick((policy ?? {}) as Record<string, unknown>, "name") ?? scaChecks.policyId);
    return (
      <div>
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <Chip onClick={onBackToPolicies} aria-label="Back to policy list">
            ← Policies
          </Chip>
          <span className="text-title text-ink">{title}</span>
        </div>
        {scaChecks.loading && !scaChecks.checks ? (
          <StatusState variant="loading" title="Loading checks…" />
        ) : scaChecks.error ? (
          <StatusState
            variant="error"
            title="Couldn't load this policy's checks"
            description={scaChecks.error}
          />
        ) : (
          <ScaChecksTable rows={scaChecks.checks ?? []} />
        )}
        {note}
      </div>
    );
  }

  // Policy list.
  if (sca.loading && !sca.loaded) {
    return <StatusState variant="loading" title="Loading configuration assessment…" />;
  }
  if (sca.error && !sca.policies) {
    return (
      <StatusState
        variant="error"
        title="Couldn't load configuration assessment"
        description={sca.error}
      />
    );
  }
  const policies = sca.policies ?? [];
  if (policies.length === 0) {
    return (
      <div>
        <StatusState
          variant="empty"
          title="No SCA policies"
          description="No Security Configuration Assessment policies have been scanned on this agent."
        />
        {note}
      </div>
    );
  }
  return (
    <div>
      <div className="max-h-[55vh] overflow-auto rounded-lg border border-line">
        <Table>
          <THead>
            <TR>
              <TH>Policy</TH>
              <TH className="text-right">Score</TH>
              <TH className="text-right">Pass</TH>
              <TH className="text-right">Fail</TH>
              <TH className="text-right">Invalid</TH>
              <TH>Last scan</TH>
              <TH></TH>
            </TR>
          </THead>
          <TBody>
            {policies.map((p, i) => {
              const pid = p.policy_id == null ? null : String(p.policy_id);
              return (
                <TR key={`${pid ?? i}-${i}`}>
                  <TD>{cell(p.name ?? pid)}</TD>
                  <TD mono className="text-right">
                    {p.score == null ? DASH : `${fmtInt(p.score)}%`}
                  </TD>
                  <TD mono className="text-right text-teal">{cell(p.pass)}</TD>
                  <TD mono className="text-right text-sev-high">{cell(p.fail)}</TD>
                  <TD mono className="text-right text-dim2">{cell(p.invalid)}</TD>
                  <TD>{fmtDateTime(typeof p.end_scan === "string" ? p.end_scan : null)}</TD>
                  <TD>
                    {pid ? (
                      <Chip
                        onClick={() => onSelectPolicy(pid)}
                        aria-label={`View checks for ${cell(p.name ?? pid)}`}
                      >
                        View checks
                      </Chip>
                    ) : (
                      DASH
                    )}
                  </TD>
                </TR>
              );
            })}
          </TBody>
        </Table>
      </div>
      {note}
    </div>
  );
}

function scaResultClass(result: string): string {
  switch (result.toLowerCase()) {
    case "passed":
      return "text-teal";
    case "failed":
      return "text-sev-high";
    default:
      return "text-dim2";
  }
}

function ScaChecksTable({ rows }: { rows: ScaCheck[] }) {
  if (rows.length === 0) {
    return (
      <StatusState
        variant="empty"
        title="No checks"
        description="This policy reported no individual check results."
      />
    );
  }
  return (
    <div className="max-h-[55vh] overflow-auto rounded-lg border border-line">
      <Table>
        <THead>
          <TR>
            <TH>Check</TH>
            <TH>Result</TH>
            <TH>Remediation</TH>
          </TR>
        </THead>
        <TBody>
          {rows.map((r, i) => {
            const result = cell(r.result);
            return (
              <TR key={`${cell(r.id)}-${i}`}>
                <TD>
                  <div className="text-ink">{cell(r.title)}</div>
                  {typeof r.rationale === "string" && r.rationale && (
                    <div className="max-w-[520px] truncate text-kbd text-dim2" title={r.rationale}>
                      {r.rationale}
                    </div>
                  )}
                </TD>
                <TD>
                  <span className={`font-semibold ${scaResultClass(result)}`}>
                    {result}
                  </span>
                </TD>
                <TD>
                  <span className="block max-w-[420px] truncate text-dim" title={cell(r.remediation)}>
                    {cell(r.remediation)}
                  </span>
                </TD>
              </TR>
            );
          })}
        </TBody>
      </Table>
    </div>
  );
}
