"use client";

/**
 * AdminTab (WO-U9) — READ-ONLY admin surface: users, license/tier, and (for
 * mssp_admin) tenants.
 *
 * Binds to `GET /api/admin/users` (`getAdminUsers`, `require_role("admin")`) and
 * `GET /api/admin/tenants` (`getAdminTenants`, `require_role("mssp_admin")`). The
 * tenants call is gated CLIENT-SIDE on the mssp_admin role (mirroring the server)
 * so a plain admin never fires a request the server would 403. The license panel
 * is sourced from the license/tier-info the app already loaded (`useAuth().tier`,
 * i.e. `GET /api/license/tier-info`).
 *
 * READ-ONLY: no user create/edit, no tenant create/edit. Admin is NEVER
 * tier-locked (per the RBAC model), so there is no FeatureLockedState here.
 *
 * States: loading / empty / error+retry; PollingStatus (30s, aborts on unmount).
 * Fixtures gate behind NEXT_PUBLIC_DHRUVA_FIXTURES.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Chip,
  FeatureLockedState,
  Panel,
  PollingStatus,
  StatusState,
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
  getAdminAnonMappings,
  getAdminAuditLog,
  getAdminConfig,
  getAdminDataAccessPolicy,
  getAdminGovernanceCharter,
  getAdminTenants,
  getAdminUsers,
  getLogSources,
  getPipelineHealth,
} from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { roleAtLeast } from "@/lib/rbac";
import {
  AssetsSection,
  IdentitiesSection,
  LocalIocsSection,
  OperationsSection,
  TenantRowActions,
  TenantWriteControls,
  UserRowEdit,
  UserWriteControls,
} from "../AdminActions";
import { cn, focusRing } from "@/lib/ui";
import { asBool, DASH, fmtDate, fmtDateTime, fmtInt, fmtNum, fmtPct } from "@/lib/format";
import type { TabProps } from "../tabRegistry";
import type {
  AdminAnonMapping,
  AdminAuditEntry,
  AdminTenant,
  AdminUser,
  LicenseTierInfo,
  LogSource,
  PipelineHealth,
} from "@/lib/types";

const POLL_MS = 30_000;

function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : "Unknown error";
}

interface State {
  users: AdminUser[] | null;
  usersError: string | null;
  tenants: AdminTenant[] | null;
  tenantsError: string | null;
  loading: boolean;
}

type AdminSection =
  | "overview"
  | "audit"
  | "config"
  | "governance"
  | "settings"
  | "operations"
  | "anon"
  | "pipeline"
  | "tenants";

export function AdminTab(_props: TabProps) {
  const { role, tier } = useAuth();
  const isMssp = roleAtLeast(role, "mssp_admin");
  const [section, setSection] = useState<AdminSection>("overview");

  const [state, setState] = useState<State>({
    users: null,
    usersError: null,
    tenants: null,
    tenantsError: null,
    loading: true,
  });
  const [secondsAgo, setSecondsAgo] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(
    async (manual: boolean) => {
      abortRef.current?.abort();
      const ac = new AbortController();
      abortRef.current = ac;
      if (manual) setRefreshing(true);
      try {
        // Tenants only for mssp_admin (mirror the server — never fire a 403).
        const [usersRes, tenantsRes] = await Promise.allSettled([
          getAdminUsers({ include_inactive: true }, ac.signal),
          isMssp
            ? getAdminTenants(ac.signal)
            : Promise.resolve(null),
        ]);
        if (ac.signal.aborted) return;
        setState((prev) => {
          const next: State = { ...prev, loading: false };
          if (usersRes.status === "fulfilled") {
            next.users = usersRes.value.users;
            next.usersError = null;
          } else if (!prev.users) {
            next.usersError = errMessage(usersRes.reason);
          }
          if (isMssp) {
            if (tenantsRes.status === "fulfilled" && tenantsRes.value) {
              next.tenants = tenantsRes.value.tenants;
              next.tenantsError = null;
            } else if (tenantsRes.status === "rejected" && !prev.tenants) {
              next.tenantsError = errMessage(tenantsRes.reason);
            }
          } else {
            next.tenants = null;
            next.tenantsError = null;
          }
          return next;
        });
        setSecondsAgo(0);
      } finally {
        if (!ac.signal.aborted) setRefreshing(false);
      }
    },
    [isMssp],
  );

  useEffect(() => {
    load(false);
    const poll = setInterval(() => load(false), POLL_MS);
    return () => {
      clearInterval(poll);
      abortRef.current?.abort();
    };
  }, [load]);

  useEffect(() => {
    const t = setInterval(() => setSecondsAgo((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, []);

  const { users, usersError, tenants, tenantsError, loading } = state;

  const sections: { id: AdminSection; label: string }[] = [
    { id: "overview", label: "Users & license" },
    { id: "audit", label: "Audit log" },
    { id: "config", label: "Configuration" },
    { id: "governance", label: "Governance" },
    { id: "settings", label: "Assets & IOCs" },
    { id: "operations", label: "Operations" },
    { id: "anon", label: "Anonymization" },
    // Pipeline Health + Tenants are mssp_admin-only (mirror the server's
    // require_role("mssp_admin") — a plain admin never sees the entry, so never
    // the data). Fail-closed: hidden unless the role is mssp_admin.
    ...(isMssp
      ? [
          { id: "pipeline" as const, label: "Pipeline Health" },
          { id: "tenants" as const, label: "Tenants" },
        ]
      : []),
  ];

  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PageHeading
          title="Administration"
          sub="Manage users, tenants (MSSP), assets/identities/local-IOCs, runtime reloads, and shift handoff. Every write mirrors the server's role gates and is audit-logged; destructive actions confirm first."
        />
        {section === "overview" && (
          <PollingStatus
            className="mt-1"
            secondsAgo={secondsAgo}
            refreshing={refreshing}
            onRefresh={() => load(true)}
          />
        )}
      </div>

      {/* sub-section selector */}
      <div
        className="mb-3 flex flex-wrap gap-1.5"
        role="tablist"
        aria-label="Admin sections"
      >
        {sections.map((s) => (
          <button
            key={s.id}
            type="button"
            role="tab"
            aria-selected={section === s.id}
            onClick={() => setSection(s.id)}
            className={cn(
              "rounded-md border px-2.5 py-1 text-meta",
              section === s.id
                ? "border-cite-border bg-cite-bg text-cite-ink"
                : "border-line bg-field text-ink hover:bg-hover",
              focusRing,
            )}
          >
            {s.label}
          </button>
        ))}
      </div>

      {section === "overview" && (
        <div className="flex flex-col gap-3">
          <LicensePanel tier={tier} />

          {loading && !users ? (
            <StatusState variant="loading" title="Loading users…" />
          ) : usersError && !users ? (
            <StatusState
              variant="error"
              title="Couldn't load users"
              description={usersError}
              action={<Chip onClick={() => load(true)}>Retry</Chip>}
            />
          ) : (
            <UsersPanel users={users ?? []} reload={() => load(true)} />
          )}
        </div>
      )}

      {section === "audit" && <AuditLogSection />}
      {section === "config" && <ConfigSection />}
      {section === "governance" && <GovernanceSection />}
      {section === "settings" && (
        <div className="flex flex-col gap-3">
          <AssetsSection />
          <IdentitiesSection />
          <LocalIocsSection />
        </div>
      )}
      {section === "operations" && <OperationsSection />}
      {section === "anon" && <AnonMappingsSection />}

      {section === "pipeline" &&
        (isMssp ? (
          <PipelineHealthSection />
        ) : (
          <Panel className="p-4">
            <div className="mb-1 text-title text-ink">Pipeline Health</div>
            <div className="text-data text-dim2">
              Pipeline health telemetry is restricted to the MSSP administrator
              role.
            </div>
          </Panel>
        ))}

      {section === "tenants" &&
        (isMssp ? (
          tenantsError && !tenants ? (
            <Panel className="p-4">
              <div className="mb-2 text-title text-ink">Tenants</div>
              <StatusState
                variant="error"
                title="Couldn't load tenants"
                description={tenantsError}
              />
            </Panel>
          ) : (
            <TenantsPanel tenants={tenants ?? []} reload={() => load(true)} />
          )
        ) : (
          <Panel className="p-4">
            <div className="mb-1 text-title text-ink">Tenants</div>
            <div className="text-data text-dim2">
              Tenant management is restricted to the MSSP administrator role.
            </div>
          </Panel>
        ))}
    </>
  );
}

// ---- shared: a self-fetching read-only admin section ------------------------
/**
 * Small hook for the on-demand admin sections (audit/config/governance/anon).
 * Each fetches once when its sub-tab mounts, with abort + loading/error states.
 * The Admin tab is admin/mssp_admin-only (TAB_ACCESS), so these admin-gated
 * endpoints are safe to call — the client mirrors the server, never widens it.
 */
function useAdminSection<T>(fetcher: (signal: AbortSignal) => Promise<T>) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setLoading(true);
    setError(null);
    try {
      const res = await fetcher(ac.signal);
      if (ac.signal.aborted) return;
      setData(res);
    } catch (e) {
      if (ac.signal.aborted) return;
      setError(errMessage(e));
    } finally {
      if (!ac.signal.aborted) setLoading(false);
    }
    // fetcher identity is stable per section (module-level api fn); intentional.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    load();
    return () => abortRef.current?.abort();
  }, [load]);

  return { data, error, loading, reload: load };
}

function SectionShell({
  title,
  note,
  children,
}: {
  title: string;
  note?: string;
  children: React.ReactNode;
}) {
  return (
    <Panel className="p-4">
      <div className="mb-2 text-title text-ink">{title}</div>
      {children}
      {note && <div className="mt-3 text-kbd text-dim2">{note}</div>}
    </Panel>
  );
}

function AuditLogSection() {
  const { data, error, loading, reload } = useAdminSection((s) =>
    getAdminAuditLog({ limit: 200 }, s),
  );
  const entries = data?.entries ?? [];
  return (
    <SectionShell
      title="Audit log"
      note="Append-only trail of who did what — read-only. Actor, action, target, IP, and time are recorded server-side."
    >
      {loading && !data ? (
        <StatusState variant="loading" title="Loading audit log…" />
      ) : error && !data ? (
        <StatusState
          variant="error"
          title="Couldn't load the audit log"
          description={error}
          action={<Chip onClick={reload}>Retry</Chip>}
        />
      ) : entries.length === 0 ? (
        <StatusState variant="empty" title="No audit entries" description="Nothing has been recorded yet." />
      ) : (
        <div className="overflow-hidden rounded-lg border border-line">
          <Table>
            <THead>
              <TR>
                <TH>When</TH>
                <TH>Actor</TH>
                <TH>Action</TH>
                <TH>Target</TH>
                <TH>IP</TH>
              </TR>
            </THead>
            <TBody>
              {entries.map((e: AdminAuditEntry, i) => (
                <TR key={e.id ?? i}>
                  <TD>{fmtDateTime(e.created_at)}</TD>
                  <TD mono>{e.actor ?? DASH}</TD>
                  <TD>
                    <Chip mono>{e.action ?? DASH}</Chip>
                  </TD>
                  <TD mono>
                    {e.target_type ? (
                      <>
                        {e.target_type}
                        {e.target_id && e.target_id !== "-" ? ` · ${e.target_id}` : ""}
                      </>
                    ) : (
                      DASH
                    )}
                  </TD>
                  <TD mono>{e.ip_address ?? DASH}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </div>
      )}
    </SectionShell>
  );
}

function ConfigSection() {
  const { data, error, loading, reload } = useAdminSection((s) => getAdminConfig(s));
  const entries = data ? Object.entries(data.config) : [];
  return (
    <SectionShell
      title="Configuration"
      note="A curated safe subset of runtime configuration — never secrets. Read-only: there is no config-write endpoint (editing config is done out-of-band)."
    >
      {loading && !data ? (
        <StatusState variant="loading" title="Loading configuration…" />
      ) : error && !data ? (
        <StatusState
          variant="error"
          title="Couldn't load configuration"
          description={error}
          action={<Chip onClick={reload}>Retry</Chip>}
        />
      ) : entries.length === 0 ? (
        <StatusState variant="empty" title="No configuration returned" description="The API exposed no config keys." />
      ) : (
        <dl className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          {entries.map(([k, v]) => (
            <div key={k} className="rounded-lg border border-line bg-panel2 px-3 py-2">
              <dt className="text-kbd uppercase tracking-wider text-dim2">
                {k.replace(/_/g, " ")}
              </dt>
              <dd className="mt-0.5 font-mono text-data text-ink">{fmtConfigValue(v)}</dd>
            </div>
          ))}
        </dl>
      )}
    </SectionShell>
  );
}

function GovernanceSection() {
  const charter = useAdminSection((s) => getAdminGovernanceCharter(s));
  const dataAccess = useAdminSection((s) => getAdminDataAccessPolicy(s));
  return (
    <div className="flex flex-col gap-3">
      <SectionShell
        title="SOC charter"
        note="Institutional knowledge the agents read at runtime — read-only. Edits are made to the governance YAML out-of-band."
      >
        {charter.loading && !charter.data ? (
          <StatusState variant="loading" title="Loading charter…" />
        ) : charter.error && !charter.data ? (
          <StatusState
            variant="error"
            title="Couldn't load the charter"
            description={charter.error}
            action={<Chip onClick={charter.reload}>Retry</Chip>}
          />
        ) : charter.data?.charter && Object.keys(charter.data.charter).length > 0 ? (
          <KeyValueList obj={charter.data.charter} />
        ) : (
          <div className="text-data text-dim2">
            {charter.data?.message ?? "No SOC charter is configured for this tenant."}
          </div>
        )}
      </SectionShell>

      <SectionShell
        title="Data-access policy"
        note="How client data is handled at the anonymization / LLM boundary — read-only."
      >
        {dataAccess.loading && !dataAccess.data ? (
          <StatusState variant="loading" title="Loading data-access policy…" />
        ) : dataAccess.error && !dataAccess.data ? (
          <StatusState
            variant="error"
            title="Couldn't load the data-access policy"
            description={dataAccess.error}
            action={<Chip onClick={dataAccess.reload}>Retry</Chip>}
          />
        ) : dataAccess.data && Object.keys(dataAccess.data).length > 0 ? (
          <KeyValueList obj={dataAccess.data} />
        ) : (
          <div className="text-data text-dim2">No data-access policy is configured.</div>
        )}
      </SectionShell>

      <Panel className="p-4">
        <div className="mb-1 text-title text-ink">Guidance files</div>
        <div className="text-data text-dim2">
          Risk criteria, escalation logic, and per-scenario playbooks live in the
          governance/guidance YAMLs the agents read at runtime. They are not
          exposed via a read API — only a reload trigger exists
          (<span className="font-mono">POST /api/guidance/reload</span>), wired as
          a gated confirm-to-reload control in the <b>Operations</b> sub-tab.
          Roles are assigned inline on a user via the gated user-edit action;
          there is no separate roles endpoint.
        </div>
      </Panel>
    </div>
  );
}

function AnonMappingsSection() {
  const { data, error, loading, reload } = useAdminSection((s) =>
    getAdminAnonMappings({ limit: 200 }, s),
  );
  const mappings = data?.mappings ?? [];
  return (
    <SectionShell
      title="Anonymization mappings"
      note="The admin-only token↔value map DHRUVA uses to resolve anonymized AI output back to real identifiers. Anonymization protects the LLM call, not an authenticated admin. Read-only."
    >
      {loading && !data ? (
        <StatusState variant="loading" title="Loading mappings…" />
      ) : error && !data ? (
        <StatusState
          variant="error"
          title="Couldn't load anonymization mappings"
          description={error}
          action={<Chip onClick={reload}>Retry</Chip>}
        />
      ) : mappings.length === 0 ? (
        <StatusState variant="empty" title="No mappings" description="No identifiers have been tokenized yet." />
      ) : (
        <div className="overflow-hidden rounded-lg border border-line">
          <Table>
            <THead>
              <TR>
                <TH>Token</TH>
                <TH>Field</TH>
                <TH>Real value</TH>
                <TH className="text-right">Hits</TH>
                <TH>Last seen</TH>
              </TR>
            </THead>
            <TBody>
              {mappings.map((m: AdminAnonMapping, i) => (
                <TR key={m.token ?? i}>
                  <TD mono>{m.token}</TD>
                  <TD>
                    <Chip mono>{m.field_type ?? DASH}</Chip>
                  </TD>
                  <TD mono>{m.original_value ?? DASH}</TD>
                  <TD mono className="text-right">{fmtInt(m.hit_count)}</TD>
                  <TD>{fmtDateTime(m.last_seen)}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </div>
      )}
    </SectionShell>
  );
}

// ---- Admin → Pipeline Health (mssp_admin + pipeline_health license) ---------
/**
 * Restores the legacy `pipeline` admin sub-tab (`app.js:2626-2712`). READ-ONLY.
 * Binds `GET /api/health/pipeline` + `GET /api/health/log-sources`, both
 * `require_role("mssp_admin")` + `require_license_feature("pipeline_health")`.
 * This component is rendered ONLY for mssp_admin (the section entry is hidden
 * otherwise), so it never fires a request the server would 403 on the ROLE gate;
 * a runtime 402/403 from the LICENSE gate degrades to FeatureLockedState
 * (fail-closed to locked). Shows heartbeats / silent agents, EPS + anomaly,
 * parser fail-rate, automation KPIs, and the Log Sources inventory — nothing is
 * fabricated (every field is what the endpoint returned; sub-status error/
 * insufficient variants are surfaced honestly).
 */
function isLockErr(e: unknown): boolean {
  return e instanceof ApiError && (e.status === 402 || e.status === 403);
}

function PipelineHealthSection() {
  const [health, setHealth] = useState<PipelineHealth | null>(null);
  const [sources, setSources] = useState<LogSource[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [locked, setLocked] = useState(false);
  const [loading, setLoading] = useState(true);
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setLoading(true);
    setError(null);
    try {
      const [h, s] = await Promise.allSettled([
        getPipelineHealth(ac.signal),
        getLogSources(ac.signal),
      ]);
      if (ac.signal.aborted) return;
      // Either call sharing the pipeline_health gate can signal a lock.
      if (
        (h.status === "rejected" && isLockErr(h.reason)) ||
        (s.status === "rejected" && isLockErr(s.reason))
      ) {
        setLocked(true);
        setLoading(false);
        return;
      }
      if (h.status === "fulfilled") setHealth(h.value);
      else setError(errMessage(h.reason));
      if (s.status === "fulfilled") setSources(s.value.sources ?? []);
      setLoading(false);
    } catch (e) {
      if (ac.signal.aborted) return;
      setError(errMessage(e));
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    return () => abortRef.current?.abort();
  }, [load]);

  const onUpgrade = useCallback(() => {
    if (typeof window !== "undefined") {
      window.open("https://securesleuths.in/pricing", "_blank", "noreferrer");
    }
  }, []);

  if (locked) {
    return (
      <FeatureLockedState
        feature="Pipeline health"
        tier="current"
        onUpgrade={onUpgrade}
      />
    );
  }
  if (loading && !health) {
    return <StatusState variant="loading" title="Loading pipeline health…" />;
  }
  if (error && !health) {
    return (
      <StatusState
        variant="error"
        title="Couldn't load pipeline health"
        description={error}
        action={<Chip onClick={load}>Retry</Chip>}
      />
    );
  }

  const hb = health?.heartbeat ?? {};
  const eps = health?.eps ?? {};
  const parser = health?.parser ?? {};
  const auto = health?.automation_health;

  return (
    <div className="flex flex-col gap-3">
      <div className="rounded-lg border border-line bg-panel2 px-3.5 py-2.5 text-kbd text-dim2">
        Global infrastructure telemetry — log-source heartbeats, ingest-rate
        anomaly, parser failure-rate, and automation health. mssp_admin-only,
        read-only. Figures are exactly what the pipeline monitor reported; empty
        or error sub-checks are shown as such, never filled in.
      </div>

      {health?.status === "unavailable" && (
        <Panel className="p-4">
          <div className="text-data text-sev-med">
            {health.message ?? "Pipeline monitor is not initialized."}
          </div>
        </Panel>
      )}

      {/* Heartbeats / silent agents */}
      <SectionShell
        title="Agent heartbeats"
        note={
          hb.window_minutes != null
            ? `Silent = no events within the last ${hb.window_minutes} min window.`
            : undefined
        }
      >
        {hb.error ? (
          <div className="text-data text-sev-med">Heartbeat check error: {hb.error}</div>
        ) : hb.checked_at == null && hb.reporting_agents == null ? (
          <div className="text-data text-dim2">
            No heartbeat check has run yet.
          </div>
        ) : (
          <>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <Tile label="Known active" value={fmtInt(hb.known_active_agents)} sub="agents" />
              <Tile label="Reporting" value={fmtInt(hb.reporting_agents)} sub="sending events" />
              <Tile
                label="Silent"
                value={fmtInt(hb.silent_agents)}
                sub="no recent events"
                valueSeverity={(hb.silent_agents ?? 0) > 0 ? "med" : undefined}
              />
              <Tile label="Window" value={hb.window_minutes != null ? `${hb.window_minutes}m` : DASH} sub="heartbeat" />
            </div>
            {hb.silent_agent_names && hb.silent_agent_names.length > 0 && (
              <div className="mt-3">
                <div className="mb-1.5 text-kbd uppercase tracking-wider text-dim2">
                  Silent agents
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {hb.silent_agent_names.map((n) => (
                    <Chip key={n} mono variant="gated">
                      {n}
                    </Chip>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </SectionShell>

      {/* EPS + anomaly */}
      <SectionShell title="Ingest rate (events / minute)">
        {eps.error ? (
          <div className="text-data text-sev-med">EPS check error: {eps.error}</div>
        ) : eps.status === "insufficient_data" ? (
          <div className="text-data text-dim2">
            Not enough history yet to compute an ingest baseline
            {eps.bucket_count != null ? ` (${eps.bucket_count} buckets)` : ""}.
          </div>
        ) : eps.mean_events_per_minute == null && eps.recent_5min_avg == null ? (
          <div className="text-data text-dim2">No EPS check has run yet.</div>
        ) : (
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Tile label="Recent 5-min avg" value={fmtNum(eps.recent_5min_avg)} sub="events / min" />
            <Tile label="Baseline mean" value={fmtNum(eps.mean_events_per_minute)} sub="events / min" />
            <Tile label="Z-score" value={fmtNum(eps.z_score, 2)} sub={`threshold ${eps.threshold ?? DASH}`} />
            <Tile
              label="Anomaly"
              value={eps.is_anomaly ? "Yes" : "No"}
              sub="vs baseline"
              valueSeverity={eps.is_anomaly ? "high" : undefined}
            />
          </div>
        )}
      </SectionShell>

      {/* Parser failure rate */}
      <SectionShell title="Parser failure rate (last hour)">
        {parser.error ? (
          <div className="text-data text-sev-med">Parser check error: {parser.error}</div>
        ) : parser.status === "no_events" ? (
          <div className="text-data text-dim2">No events in the last hour to assess.</div>
        ) : parser.failure_rate == null ? (
          <div className="text-data text-dim2">No parser check has run yet.</div>
        ) : (
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Tile
              label="Failure rate"
              value={fmtPct(parser.failure_rate, { fraction: true })}
              sub={`threshold ${parser.threshold != null ? fmtPct(parser.threshold, { fraction: true }) : DASH}`}
              valueSeverity={parser.is_above_threshold ? "high" : undefined}
            />
            <Tile label="Events (1h)" value={fmtInt(parser.total_events_1h)} sub="total" />
            <Tile label="Unparsed (1h)" value={fmtInt(parser.unparsed_events_1h)} sub="failed to parse" />
            <Tile
              label="Above threshold"
              value={parser.is_above_threshold ? "Yes" : "No"}
              sub="parser health"
              valueSeverity={parser.is_above_threshold ? "high" : undefined}
            />
          </div>
        )}
      </SectionShell>

      {/* Automation health (route-merged) */}
      {auto && (
        <SectionShell
          title="Automation health · 7 days"
          note="Enrichment latency + active-response outcome rates, merged from the metrics calculator."
        >
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
            <Tile label="Enrichment p50" value={auto.enrichment_latency?.p50_ms != null ? `${fmtNum(auto.enrichment_latency.p50_ms)}ms` : DASH} sub="median" />
            <Tile label="Enrichment p95" value={auto.enrichment_latency?.p95_ms != null ? `${fmtNum(auto.enrichment_latency.p95_ms)}ms` : DASH} sub="tail" />
            <Tile label="Enrichment p99" value={auto.enrichment_latency?.p99_ms != null ? `${fmtNum(auto.enrichment_latency.p99_ms)}ms` : DASH} sub="tail" />
            <Tile
              label="SOAR success"
              value={auto.soar_actions?.success_rate != null ? fmtPct(auto.soar_actions.success_rate) : DASH}
              sub={`${fmtInt(auto.soar_actions?.success_count)} / ${fmtInt(auto.soar_actions?.total_actions)}`}
            />
            <Tile
              label="SOAR failures"
              value={fmtInt(auto.soar_actions?.failure_count)}
              sub="active-response"
              valueSeverity={(auto.soar_actions?.failure_count ?? 0) > 0 ? "med" : undefined}
            />
            <Tile label="Enrichment samples" value={fmtInt(auto.enrichment_latency?.sample_count)} sub="in window" />
          </div>
        </SectionShell>
      )}

      {/* Log source inventory */}
      <Panel className="overflow-hidden">
        <div className="px-4 pt-3 text-title text-ink">Log sources</div>
        <div className="px-4 text-kbd text-dim2">
          Inventory with a live silent/reporting heartbeat stamp. Read-only.
        </div>
        {loading && !sources ? (
          <div className="px-4 py-3">
            <StatusState variant="loading" title="Loading log sources…" />
          </div>
        ) : sources && sources.length > 0 ? (
          <Table className="mt-2">
            <THead>
              <TR>
                <TH>Source</TH>
                <TH>Type</TH>
                <TH>Status</TH>
                <TH className="text-right">Est. EPS</TH>
                <TH className="text-right">Retention</TH>
                <TH>Notes</TH>
              </TR>
            </THead>
            <TBody>
              {sources.map((s, i) => (
                <TR key={s.name ?? i}>
                  <TD>
                    <div className="text-ink">{s.name}</div>
                    {s.description && (
                      <div className="max-w-[360px] truncate text-kbd text-dim2" title={s.description}>
                        {s.description}
                      </div>
                    )}
                  </TD>
                  <TD mono>{s.type ?? DASH}</TD>
                  <TD>
                    <span className={s.status === "reporting" ? "text-teal" : "text-sev-med"}>
                      {s.status ?? DASH}
                    </span>
                  </TD>
                  <TD mono className="text-right">{fmtInt(s.volume_eps_estimate)}</TD>
                  <TD mono className="text-right">
                    {s.retention_days != null ? `${s.retention_days}d` : DASH}
                  </TD>
                  <TD>
                    <span className="text-dim2">{s.notes || DASH}</span>
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        ) : (
          <div className="px-4 py-3 text-data text-dim2">
            No log sources are configured in the inventory.
          </div>
        )}
      </Panel>
    </div>
  );
}

function KeyValueList({ obj }: { obj: Record<string, unknown> }) {
  return (
    <dl className="flex flex-col gap-2">
      {Object.entries(obj).map(([k, v]) => (
        <div key={k}>
          <dt className="text-kbd uppercase tracking-wider text-dim2">
            {k.replace(/_/g, " ")}
          </dt>
          <dd className="mt-0.5 text-data leading-relaxed text-ink">{fmtConfigValue(v)}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Render an unknown config/policy value compactly, never trusted as markup. */
function fmtConfigValue(v: unknown): string {
  if (v == null) return "—";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "string" || typeof v === "number") return String(v);
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}

function LicensePanel({ tier }: { tier: LicenseTierInfo | null }) {
  if (!tier) {
    return (
      <Panel className="p-4">
        <div className="mb-1 text-title text-ink">License</div>
        <div className="text-data text-sev-med">
          License/tier info is unavailable — the platform fails toward locked
          (paid tabs treated as locked) until it loads.
        </div>
      </Panel>
    );
  }
  const limits = tier.limits ?? {};
  const limitRow = (key: string, label: string) => {
    const l = limits[key];
    if (!l) return null;
    return (
      <Tile key={key} label={label} value={l.label} sub={l.max === 0 ? "no cap" : `cap ${l.max}`} />
    );
  };
  return (
    <Panel className="p-4">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <span className="text-title text-ink">License</span>
        <Chip variant="cite">{tier.tier_display ?? tier.tier}</Chip>
        {tier.is_free && <Chip>free tier</Chip>}
        {tier.days_remaining != null && (
          <span className="text-kbd text-dim2">
            {tier.days_remaining} day{tier.days_remaining === 1 ? "" : "s"} remaining
          </span>
        )}
      </div>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {limitRow("agents", "Agents")}
        {limitRow("users", "Users")}
        {limitRow("triage_daily", "Triage / day")}
        {limitRow("nl_queries_daily", "NL queries / day")}
      </div>

      {tier.features && tier.features.length > 0 && (
        <div className="mt-3">
          <div className="mb-1.5 text-kbd uppercase tracking-wider text-dim2">Features</div>
          <div className="flex flex-wrap gap-1.5">
            {tier.features.map((f) => (
              <Chip key={f} mono variant="grounded">
                {f}
              </Chip>
            ))}
          </div>
        </div>
      )}

      {tier.active_response_actions && tier.active_response_actions.length > 0 && (
        <div className="mt-3">
          <div className="mb-1.5 text-kbd uppercase tracking-wider text-dim2">
            Active-response actions (human-approved)
          </div>
          <div className="flex flex-wrap gap-1.5">
            {tier.active_response_actions.map((a) => (
              <Chip key={a} mono variant="gated">
                {a}
              </Chip>
            ))}
          </div>
        </div>
      )}
    </Panel>
  );
}

const ROLE_LABEL: Record<string, string> = {
  mssp_admin: "MSSP admin",
  admin: "Admin",
  senior_analyst: "Senior analyst",
  analyst: "Analyst",
  read_only: "Read-only",
};

function UsersPanel({
  users,
  reload,
}: {
  users: AdminUser[];
  reload: () => void;
}) {
  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-3">
        <div className="text-title text-ink">Users</div>
        <div className="flex items-center gap-3">
          <span className="text-kbd text-dim2">{users.length} total</span>
          <UserWriteControls onChanged={reload} />
        </div>
      </div>
      {users.length === 0 ? (
        <div className="px-4 pb-4 pt-2 text-data text-dim2">
          No users found for this tenant.
        </div>
      ) : (
        <Table className="mt-2">
          <THead>
            <TR>
              <TH>User</TH>
              <TH>Email</TH>
              <TH>Role</TH>
              <TH>Status</TH>
              <TH>Created</TH>
              <TH className="text-right">Action</TH>
            </TR>
          </THead>
          <TBody>
            {users.map((u) => {
              const active = asBool(u.is_active);
              return (
                <TR key={u.id}>
                  <TD>
                    <div className="text-ink">{u.display_name || u.username}</div>
                    <div className="font-mono text-kbd text-dim2">{u.username}</div>
                  </TD>
                  <TD>{u.email ?? DASH}</TD>
                  <TD>
                    <Chip mono>{ROLE_LABEL[String(u.role)] ?? u.role}</Chip>
                  </TD>
                  <TD>
                    <span className={active ? "text-teal" : "text-dim2"}>
                      {active ? "active" : "inactive"}
                    </span>
                  </TD>
                  <TD>{fmtDate(u.created_at)}</TD>
                  <TD className="text-right">
                    <div className="flex justify-end">
                      <UserRowEdit user={u} onChanged={reload} />
                    </div>
                  </TD>
                </TR>
              );
            })}
          </TBody>
        </Table>
      )}
      <div className="px-4 py-2 text-kbd text-dim2">
        Passwords are never returned by the API. Creating a user or resetting a
        password sets it directly (no reset link exists) — the value is never
        displayed or logged. Role choices mirror what your role may assign.
      </div>
    </Panel>
  );
}

function TenantsPanel({
  tenants,
  reload,
}: {
  tenants: AdminTenant[];
  reload: () => void;
}) {
  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-3">
        <div className="text-title text-ink">Tenants</div>
        <div className="flex items-center gap-3">
          <span className="text-kbd text-dim2">{tenants.length} total</span>
          <TenantWriteControls onChanged={reload} />
        </div>
      </div>
      {tenants.length === 0 ? (
        <div className="px-4 pb-4 pt-2 text-data text-dim2">
          No tenants configured.
        </div>
      ) : (
        <Table className="mt-2">
          <THead>
            <TR>
              <TH>Tenant</TH>
              <TH>Slug</TH>
              <TH>Status</TH>
              <TH>Configured</TH>
              <TH>Created</TH>
              <TH className="text-right">Actions</TH>
            </TR>
          </THead>
          <TBody>
            {tenants.map((t) => (
              <TR key={t.id}>
                <TD>{t.name}</TD>
                <TD mono>{t.slug}</TD>
                <TD>
                  <span className={t.active ? "text-teal" : "text-dim2"}>
                    {t.active ? "active" : "inactive"}
                  </span>
                </TD>
                <TD>
                  <div className="flex flex-wrap gap-1">
                    {t.has_wazuh && <Chip mono>wazuh</Chip>}
                    {t.has_claude && <Chip mono>claude</Chip>}
                    {t.has_notifications && <Chip mono>notifications</Chip>}
                    {!t.has_wazuh && !t.has_claude && !t.has_notifications && (
                      <span className="text-dim2">{DASH}</span>
                    )}
                  </div>
                </TD>
                <TD>{fmtDate(t.created_at)}</TD>
                <TD className="text-right">
                  <TenantRowActions tenant={t} onChanged={reload} />
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      )}
      <div className="px-4 py-2 text-kbd text-dim2">
        Config is metadata only — the API returns key names and &quot;is
        configured&quot; flags, never secret values. Secrets (Wazuh, LLM keys)
        are set out-of-band; these controls never handle credentials.
        mssp_admin-only.
      </div>
    </Panel>
  );
}
