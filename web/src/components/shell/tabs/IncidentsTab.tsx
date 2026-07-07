"use client";

/**
 * IncidentsTab (WO-U4) — the glass-box CASE view, as master → detail.
 *
 * Translates the approved mockup's `incidentCard()` + `tIncidents()`: a
 * worst-first incident LIST, and on select the full glass-box case — where
 * every number expands to its source (risk-breakdown math, 5-step reasoning,
 * provenance) and the anonymization boundary is shown FIELD-LEVEL. The
 * reason-required verdict write mirrors the server (WO-B2), including the
 * read_only view-only lock and the WO-B10 admin-only override of an existing
 * human verdict.
 *
 * Composes the WO-U1 design system only (Panel, SeverityBadge, ConfidenceBar,
 * Chip, Table, StatusState, PollingStatus) — no bespoke primitives, no
 * hard-coded hexes. Mirrors TriageTab/OverviewTab: client component, abortable
 * 30s poll on the list, loading/empty/error states, fixtures gated behind
 * NEXT_PUBLIC_DHRUVA_FIXTURES.
 *
 * Data:
 *   - `GET /api/incidents` → the worst-first list.
 *   - `GET /api/incidents/{id}` → the incident + member alerts (each with WO-B4
 *     `glass_box` + WO-B9 `anonymized_fields`) + timeline.
 *   - `POST /api/triage/review` → the reason-required human verdict (per member
 *     decision).
 */

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { GitBranch } from "lucide-react";
import {
  Chip,
  FeatureLockedState,
  Panel,
  PollingStatus,
  SeverityBadge,
  StatusState,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
} from "@/components";
import { PageHeading } from "../PageHeading";
import {
  ApiError,
  getIncident,
  getIncidents,
  getIncidentSla,
  getSlaAtRisk,
  getTicketsForIncident,
  type IncidentEvidenceEntry,
  type IncidentSla,
} from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { DASH, fmtDateTime } from "@/lib/format";
import { SEVERITY, riskSeverity, severityLabel } from "@/lib/severity";
import {
  apiSeverity,
  parseJsonArray,
  sortIncidentsWorstFirst,
} from "@/lib/incident";
import { cn, focusRing } from "@/lib/ui";
import {
  GlassBoxAlertCard,
  errMessage,
  formatWhen,
  humanStatus,
} from "../GlassBoxCase";
import { IncidentActions } from "../IncidentActions";
import type { TabProps } from "../tabRegistry";
import type {
  IncidentDetail,
  IncidentListRow,
  IncidentStatus,
  Ticket,
} from "@/lib/types";

/** Auto-poll cadence (ms). The product polls; there is no push channel. */
const POLL_MS = 30_000;

interface ListState {
  incidents: IncidentListRow[] | null;
  error: string | null;
  loading: boolean;
}

/**
 * Restored segmented list filters (parity gap ②) — OPTIONAL refinement over the
 * worst-first list. Default = no filter = the current worst-first behavior.
 *   - status  → SERVER-SIDE (`GET /api/incidents?status=`); refetches.
 *   - Mine    → client-side (`assigned_to` === JWT sub) — narrowing of the
 *               already-authorized rows, NOT an RBAC change.
 *   - ★       → client-side (`flagged_interesting`) on the loaded rows.
 *   - SLA     → intersect with `GET /api/incidents/sla-at-risk` (license-gated;
 *               the chip disables itself when the SLA feature isn't licensed).
 * All narrow AFTER the worst-first sort, so order is preserved within the set.
 */
type StatusFilter = "all" | IncidentStatus;

const STATUS_FILTERS: { id: StatusFilter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "open", label: "Open" },
  { id: "investigating", label: "Investigating" },
  { id: "resolved", label: "Resolved" },
  { id: "closed", label: "Closed" },
];

/** SLA-at-risk id set + why it might be unavailable (license-gated / error). */
interface SlaFilterState {
  ids: Set<string> | null;
  locked: boolean;
  loading: boolean;
}

export function IncidentsTab({ onNavigate, navParam }: TabProps) {
  const { claims } = useAuth();
  // JWT subject drives the "Mine" filter. Absent in dev-preview (no real token)
  // → Mine can't be derived, so the chip is disabled rather than misleading.
  const sub = typeof claims?.sub === "string" ? claims.sub : null;

  const [state, setState] = useState<ListState>({
    incidents: null,
    error: null,
    loading: true,
  });
  const [secondsAgo, setSecondsAgo] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  // Restored optional segmented filters (parity gap ②). Default = no filter.
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [mine, setMine] = useState(false);
  const [interesting, setInteresting] = useState(false);
  const [slaOnly, setSlaOnly] = useState(false);
  const [sla, setSla] = useState<SlaFilterState>({
    ids: null,
    locked: false,
    loading: true,
  });
  // Deep-link: an incident id forwarded via the tab registry preselects a case.
  const [selectedId, setSelectedId] = useState<string | null>(navParam ?? null);
  const abortRef = useRef<AbortController | null>(null);
  const slaAbortRef = useRef<AbortController | null>(null);

  const load = useCallback(async (manual: boolean) => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    if (manual) setRefreshing(true);
    try {
      // status filter is applied SERVER-SIDE (`?status=`); the worst-first sort
      // then orders whatever the server returns. Mine/★/SLA narrow it client-side.
      const res = await getIncidents(
        { status: statusFilter === "all" ? undefined : statusFilter },
        ac.signal,
      );
      if (ac.signal.aborted) return;
      setState({
        incidents: sortIncidentsWorstFirst(res.incidents),
        error: null,
        loading: false,
      });
      setSecondsAgo(0);
    } catch (e) {
      if (ac.signal.aborted) return;
      const msg = errMessage(e);
      setState((prev) =>
        prev.incidents
          ? { ...prev, loading: false }
          : { incidents: null, error: msg, loading: false },
      );
    } finally {
      if (!ac.signal.aborted) setRefreshing(false);
    }
  }, [statusFilter]);

  // SLA-at-risk id set — fetched ONCE on mount + on manual refresh (NOT on every
  // 30s poll, to keep it light for tenants that never touch the SLA filter). The
  // endpoint is license-gated: a 402/403 → the SLA chip disables itself (locked),
  // never a silently-empty filter. Any other failure → also unavailable (ids
  // null), so the chip stays disabled rather than fabricating an at-risk set.
  const loadSla = useCallback(async () => {
    slaAbortRef.current?.abort();
    const ac = new AbortController();
    slaAbortRef.current = ac;
    setSla((p) => ({ ...p, loading: true }));
    try {
      const res = await getSlaAtRisk(ac.signal);
      if (ac.signal.aborted) return;
      setSla({
        ids: new Set(res.at_risk.map((a) => a.incident_id)),
        locked: false,
        loading: false,
      });
    } catch (e) {
      if (ac.signal.aborted) return;
      const locked = e instanceof ApiError && (e.status === 402 || e.status === 403);
      setSla({ ids: null, locked, loading: false });
    }
  }, []);

  // Initial fetch + auto-poll (keeps the list fresh even while a case is open).
  useEffect(() => {
    load(false);
    const poll = setInterval(() => load(false), POLL_MS);
    return () => {
      clearInterval(poll);
      abortRef.current?.abort();
    };
  }, [load]);

  // SLA-at-risk set: fetched once on mount (and on manual refresh), NOT polled.
  useEffect(() => {
    loadSla();
    return () => slaAbortRef.current?.abort();
  }, [loadSla]);

  const refreshAll = useCallback(() => {
    load(true);
    loadSla();
  }, [load, loadSla]);

  // "refreshed Ns ago" ticker.
  useEffect(() => {
    const t = setInterval(() => setSecondsAgo((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, []);

  // Follow a later deep-link (navParam changing while mounted).
  useEffect(() => {
    if (navParam) setSelectedId(navParam);
  }, [navParam]);

  const { incidents, error, loading } = state;

  // Client-side narrowing of the already-authorized, already-worst-first rows.
  // The sort is preserved (filters keep the incoming order); nothing is widened.
  const slaReady = sla.ids !== null;
  const filtered = useMemo(() => {
    let rows = incidents ?? [];
    if (mine && sub) rows = rows.filter((r) => r.assigned_to === sub);
    if (interesting) rows = rows.filter((r) => !!r.flagged_interesting);
    if (slaOnly && sla.ids) rows = rows.filter((r) => sla.ids!.has(r.id));
    return rows;
  }, [incidents, mine, sub, interesting, slaOnly, sla.ids]);

  const filtersActive =
    statusFilter !== "all" || mine || interesting || (slaOnly && slaReady);
  const clearFilters = () => {
    setStatusFilter("all");
    setMine(false);
    setInteresting(false);
    setSlaOnly(false);
  };

  if (selectedId) {
    return (
      <CaseView
        incidentId={selectedId}
        onBack={() => setSelectedId(null)}
        onNavigate={onNavigate}
      />
    );
  }

  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PageHeading
          title="Incidents"
          sub="Worst-first · open any incident for its glass-box case — the risk math, the AI’s reasoning, its provenance, and what it saw vs what you see."
        />
        <PollingStatus
          className="mt-1"
          secondsAgo={secondsAgo}
          refreshing={refreshing}
          onRefresh={refreshAll}
        />
      </div>

      <IncidentFilterBar
        status={statusFilter}
        onStatus={setStatusFilter}
        mine={mine}
        onMine={() => setMine((v) => !v)}
        mineAvailable={!!sub}
        interesting={interesting}
        onInteresting={() => setInteresting((v) => !v)}
        slaOnly={slaOnly}
        onSla={() => setSlaOnly((v) => !v)}
        slaReady={slaReady}
        slaLocked={sla.locked}
      />

      {loading && !incidents ? (
        <StatusState variant="loading" title="Loading incidents…" />
      ) : error && !incidents ? (
        <StatusState
          variant="error"
          title="Couldn't load incidents"
          description={error}
          action={<Chip onClick={refreshAll}>Retry</Chip>}
        />
      ) : filtered.length === 0 ? (
        filtersActive ? (
          <StatusState
            variant="empty"
            title="No incidents match these filters"
            description="No incident in the worst-first list matches the selected status / Mine / ★ / SLA filters. Clear the filters to see the full list."
            action={<Chip onClick={clearFilters}>Clear filters</Chip>}
          />
        ) : (
          <StatusState
            variant="empty"
            title="No incidents"
            description="Nothing has been grouped into an incident right now."
          />
        )
      ) : (
        <Panel className="overflow-hidden">
          <Table>
            <THead>
              <TR>
                <TH className="w-8" aria-label="Severity" />
                <TH>Incident</TH>
                <TH>Host</TH>
                <TH>Attack chain</TH>
                <TH>Status</TH>
                <TH>Alerts</TH>
                <TH className="w-16" aria-label="Open" />
              </TR>
            </THead>
            <TBody>
              {filtered.map((inc) => (
                <IncidentRow
                  key={inc.id}
                  incident={inc}
                  onOpen={() => setSelectedId(inc.id)}
                />
              ))}
            </TBody>
          </Table>
        </Panel>
      )}

      <div className="mt-2 text-kbd text-dim2">
        Filters refine the worst-first list, they don’t reorder it. Status is
        applied server-side; Mine and ★ narrow the loaded page. 🔒 Changing a
        verdict requires a reason (audit trail). Active response stays
        human-approved — containment is proposed through the gated copilot, never
        triggered from a case.
      </div>
    </>
  );
}

// ---- restored segmented filter bar (parity gap ②) ---------------------------
/**
 * OPTIONAL refinement over the worst-first list: a subtle chip-row (status
 * segmented group + Mine / ★ / SLA toggles). It NEVER changes the sort — the
 * list stays worst-first and these only narrow which rows show. Default = All +
 * all toggles off = the unfiltered worst-first list. Reuses the WO-U1 `Chip`
 * primitive with the selected="cite" convention the case sub-tabs already use.
 * Mine is disabled without a JWT subject; SLA is disabled when the feature is
 * unlicensed / its data is unavailable — honest, never a silently-empty filter.
 */
function StatusFilterChip({
  id,
  active,
  onSelect,
  children,
}: {
  id: StatusFilter;
  active: StatusFilter;
  onSelect: (v: StatusFilter) => void;
  children: ReactNode;
}) {
  const selected = active === id;
  return (
    <Chip
      variant={selected ? "cite" : "default"}
      onClick={() => onSelect(id)}
      aria-label={`Status filter: ${String(children)}${selected ? " (selected)" : ""}`}
    >
      {children}
    </Chip>
  );
}

function IncidentFilterBar({
  status,
  onStatus,
  mine,
  onMine,
  mineAvailable,
  interesting,
  onInteresting,
  slaOnly,
  onSla,
  slaReady,
  slaLocked,
}: {
  status: StatusFilter;
  onStatus: (v: StatusFilter) => void;
  mine: boolean;
  onMine: () => void;
  mineAvailable: boolean;
  interesting: boolean;
  onInteresting: () => void;
  slaOnly: boolean;
  onSla: () => void;
  slaReady: boolean;
  slaLocked: boolean;
}) {
  const slaLabel = slaLocked
    ? "SLA at risk — requires the SLA feature on this plan"
    : !slaReady
      ? "SLA at risk — data unavailable"
      : `SLA at risk${slaOnly ? " (selected)" : ""}`;
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
      <div
        className="flex flex-wrap items-center gap-1.5"
        role="group"
        aria-label="Filter by status"
      >
        <span className="text-micro uppercase tracking-wide text-dim2">
          Status
        </span>
        {STATUS_FILTERS.map((s) => (
          <StatusFilterChip key={s.id} id={s.id} active={status} onSelect={onStatus}>
            {s.label}
          </StatusFilterChip>
        ))}
      </div>
      <div
        className="flex flex-wrap items-center gap-1.5"
        role="group"
        aria-label="Refine"
      >
        <Chip
          variant={mine ? "cite" : "default"}
          onClick={onMine}
          disabled={!mineAvailable}
          aria-label={
            mineAvailable
              ? `Assigned to me${mine ? " (selected)" : ""}`
              : "Assigned to me — sign in to filter by assignee"
          }
        >
          Mine
        </Chip>
        <Chip
          variant={interesting ? "cite" : "default"}
          onClick={onInteresting}
          aria-label={`Flagged interesting${interesting ? " (selected)" : ""}`}
        >
          ★ Interesting
        </Chip>
        <Chip
          variant={slaOnly && slaReady ? "cite" : "default"}
          onClick={onSla}
          disabled={!slaReady}
          aria-label={slaLabel}
        >
          SLA at risk
        </Chip>
      </div>
    </div>
  );
}

// ---- one list row -----------------------------------------------------------

function IncidentRow({
  incident: inc,
  onOpen,
}: {
  incident: IncidentListRow;
  onOpen: () => void;
}) {
  const sev = apiSeverity(inc.severity);
  const hosts = parseJsonArray(inc.affected_hosts);
  const tactics = parseJsonArray(inc.mitre_tactics);
  const chainTitle = tactics.length ? tactics.join(" → ") : "—";

  return (
    <TR onClick={onOpen} aria-label={`Open case ${inc.id}: ${inc.title}`}>
      <TD>
        <SeverityBadge severity={sev} glyphOnly aria-label={severityLabel(sev)} />
      </TD>
      <TD>
        <div>{inc.title}</div>
        <div className="font-mono text-kbd text-dim2">{inc.id}</div>
      </TD>
      <TD mono>
        {hosts.length ? (
          hosts.join(", ")
        ) : (
          <span className="text-dim2">—</span>
        )}
      </TD>
      <TD className="text-kbd">{chainTitle}</TD>
      <TD className="text-kbd text-dim">{humanStatus(inc.status)}</TD>
      <TD mono>{inc.alert_count}</TD>
      <TD className="text-kbd text-dim2">open ›</TD>
    </TR>
  );
}

// ===================== CASE VIEW (glass-box) =================================

interface CaseState {
  detail: IncidentDetail | null;
  error: string | null;
  loading: boolean;
}

function CaseView({
  incidentId,
  onBack,
  onNavigate,
}: {
  incidentId: string;
  onBack: () => void;
  onNavigate?: TabProps["onNavigate"];
}) {
  const [state, setState] = useState<CaseState>({
    detail: null,
    error: null,
    loading: true,
  });
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setState((prev) => ({ ...prev, loading: true, error: null }));
    try {
      const detail = await getIncident(incidentId, ac.signal);
      if (ac.signal.aborted) return;
      setState({ detail, error: null, loading: false });
    } catch (e) {
      if (ac.signal.aborted) return;
      setState({ detail: null, error: errMessage(e), loading: false });
    }
  }, [incidentId]);

  useEffect(() => {
    load();
    return () => abortRef.current?.abort();
  }, [load]);

  const { detail, error, loading } = state;

  return (
    <>
      <button
        type="button"
        onClick={onBack}
        className={cn(
          "mb-3 inline-flex items-center gap-1 rounded-md border border-line bg-field px-2 py-1 text-kbd text-ink hover:bg-hover",
          focusRing,
        )}
      >
        ‹ Incidents
      </button>

      {loading && !detail ? (
        <StatusState variant="loading" title="Loading the case…" />
      ) : error && !detail ? (
        <StatusState
          variant="error"
          title="Couldn't load this incident"
          description={error}
          action={<Chip onClick={load}>Retry</Chip>}
        />
      ) : detail ? (
        <CaseBody detail={detail} onNavigate={onNavigate} onReviewed={load} />
      ) : null}
    </>
  );
}

function CaseBody({
  detail,
  onNavigate,
  onReviewed,
}: {
  detail: IncidentDetail;
  onNavigate?: TabProps["onNavigate"];
  onReviewed: () => void;
}) {
  const sev = apiSeverity(detail.severity);
  const tactics = parseJsonArray(detail.mitre_tactics);
  const hosts = parseJsonArray(detail.affected_hosts);
  const primaryHost = hosts[0];
  const alerts = [...(detail.alerts ?? [])].sort(
    (a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0),
  );
  // The incident risk = the worst member alert's risk (the campaign's driver).
  const incidentRisk = alerts.length ? Math.round(alerts[0].risk_score) : null;

  return (
    <>
      <Panel className="p-4">
      {/* header row */}
      <div className="mb-1.5 flex flex-wrap items-center gap-2.5">
        <Chip mono aria-label={`incident id ${detail.id}`}>
          {detail.id}
        </Chip>
        <SeverityBadge severity={sev} />
        {detail.first_seen && (
          <span className="text-kbd text-dim2">
            opened {formatWhen(detail.first_seen)}
          </span>
        )}
        <Chip>{humanStatus(detail.status)}</Chip>
        {detail.attack_chain_id && (
          <Chip
            variant="violet"
            icon={<GitBranch className="h-3.5 w-3.5" aria-hidden="true" />}
            onClick={() => onNavigate?.("overview")}
            aria-label={`Part of campaign ${detail.attack_chain_id} — open the campaign map`}
          >
            part of campaign {detail.attack_chain_id} →
          </Chip>
        )}
        <span className="flex-1" />
        {incidentRisk !== null && (
          <div className="text-right">
            <div className="text-micro uppercase tracking-wide text-dim2">
              Risk
            </div>
            <div
              className={cn(
                "font-mono text-[22px] font-extrabold tabular",
                SEVERITY[riskSeverity(incidentRisk)].textClass,
              )}
            >
              {incidentRisk}
            </div>
          </div>
        )}
      </div>

      {/* attack-chain title */}
      <div className="text-title font-semibold">
        {primaryHost ? (
          <>
            Attack chain on{" "}
            <span className="font-mono">{primaryHost}</span>
            {tactics.length ? `: ${tactics.join(" → ")}` : ""}
          </>
        ) : (
          detail.title
        )}
      </div>
      <div className="mb-3 text-kbd text-dim2">
        {alerts.length} correlated alert{alerts.length === 1 ? "" : "s"} ·
        kill-chain-ordered{detail.summary ? ` · ${detail.summary}` : ""}
      </div>

      {/* tactic tiles */}
      {tactics.length > 0 && (
        <div className="mb-3 flex flex-wrap items-stretch gap-2">
          {tactics.map((t, i) => (
            <div key={`${t}-${i}`} className="flex items-center gap-2">
              <div className="rounded-lg border border-line bg-panel2 px-3 py-2">
                <div className="text-data font-medium text-ink">{t}</div>
              </div>
              {i < tactics.length - 1 && (
                <span className="text-dim2" aria-hidden="true">
                  →
                </span>
              )}
            </div>
          ))}
        </div>
      )}

      {/* member alert glass-box cards (primary emphasised, others listed) */}
      {alerts.length === 0 ? (
        <StatusState
          variant="empty"
          title="No member alerts on this incident"
          description="The incident has no correlated agent decisions to explain."
        />
      ) : (
        <div className="flex flex-col gap-2.5">
          {alerts.map((alert, i) => (
            <GlassBoxAlertCard
              key={alert.id}
              alert={alert}
              primary={i === 0}
              onReviewed={onReviewed}
            />
          ))}
        </div>
      )}
      </Panel>

      {/* Parity-restore — the legacy case slide-over's read-only inner tabs
          (Timeline / SLA / Tickets / Evidence), READ-ONLY. Kept in this tab (not
          the shared GlassBoxCase, which Triage reuses). */}
      <CaseSubViews detail={detail} />

      {/* WO-U4 case writes — the case-management action rail (status/assign/
          note/flag/escalate/evidence/merge/PIR), RBAC-mirrored + reason-gated. */}
      <IncidentActions detail={detail} onChanged={onReviewed} />
    </>
  );
}

// ===================== CASE INNER SUB-VIEWS (parity-restore) =================
// The legacy incident slide-over had inner tabs; the redesign dropped the
// READ-ONLY ones. These restore Timeline / SLA / Tickets / Evidence as a section
// INSIDE the Incidents case body (never in the shared GlassBoxCase, which Triage
// reuses). All READ-ONLY, no RBAC widening:
//   - Timeline + Evidence ride the ALREADY-LOADED detail (`.timeline` /
//     `.evidence_chain`) — no extra fetch, same verify_jwt gate as the detail
//     (every role that can open the case).
//   - SLA + Tickets each fetch their own LICENSE-gated endpoint and FAIL-CLOSED
//     to a FeatureLockedState on a 402/403 (mirrors the server `sla` /
//     `ticketing` feature gates exactly). Evidence CREATION already lives in the
//     IncidentActions rail; ticket CREATION lives on the Tickets tab — these are
//     the read listings only, never duplicated writes.
// The analyst sees REAL identifiers here (anonymization is the LLM boundary, not
// this surface); nothing reverse-resolves a token.

type CaseSubTab = "timeline" | "sla" | "tickets" | "evidence";

/** Parse the incident detail's raw `evidence_chain` (JSON string or array) into
 *  entries, defensively — an absent/malformed chain yields an empty list. */
function parseEvidenceChain(detail: IncidentDetail): IncidentEvidenceEntry[] {
  const raw = (detail as { evidence_chain?: unknown }).evidence_chain;
  let arr: unknown = raw;
  if (typeof raw === "string") {
    try {
      arr = JSON.parse(raw || "[]");
    } catch {
      return [];
    }
  }
  return Array.isArray(arr) ? (arr as IncidentEvidenceEntry[]) : [];
}

function CaseSubViews({ detail }: { detail: IncidentDetail }) {
  const [sub, setSub] = useState<CaseSubTab>("timeline");
  const timeline = detail.timeline ?? [];
  const evidence = parseEvidenceChain(detail);

  return (
    <Panel className="mt-3 p-4">
      <div
        className="mb-3 flex flex-wrap gap-1.5"
        role="group"
        aria-label="Incident case detail views"
      >
        <SubTabChip id="timeline" sub={sub} onSelect={setSub} count={timeline.length}>
          Timeline
        </SubTabChip>
        <SubTabChip id="sla" sub={sub} onSelect={setSub}>
          SLA
        </SubTabChip>
        <SubTabChip id="tickets" sub={sub} onSelect={setSub}>
          Tickets
        </SubTabChip>
        <SubTabChip id="evidence" sub={sub} onSelect={setSub} count={evidence.length}>
          Evidence
        </SubTabChip>
      </div>

      {sub === "timeline" && <TimelineView entries={timeline} />}
      {sub === "sla" && <SlaView incidentId={detail.id} />}
      {sub === "tickets" && <TicketsView incidentId={detail.id} />}
      {sub === "evidence" && <EvidenceView entries={evidence} />}
    </Panel>
  );
}

function SubTabChip({
  id,
  sub,
  onSelect,
  count,
  children,
}: {
  id: CaseSubTab;
  sub: CaseSubTab;
  onSelect: (v: CaseSubTab) => void;
  count?: number;
  children: ReactNode;
}) {
  return (
    <Chip
      variant={sub === id ? "cite" : "default"}
      onClick={() => onSelect(id)}
      aria-label={`Show ${String(children)}`}
    >
      {children}
      {count != null && <span className="text-dim2"> · {count}</span>}
    </Chip>
  );
}

// ---- Timeline (from detail.timeline — no fetch) -----------------------------
function TimelineView({ entries }: { entries: IncidentDetail["timeline"] }) {
  if (!entries || entries.length === 0) {
    return (
      <StatusState
        variant="empty"
        title="No timeline events"
        description="Nothing has been recorded on this incident's timeline yet."
      />
    );
  }
  return (
    <div className="overflow-hidden rounded-lg border border-line">
      <Table>
        <THead>
          <TR>
            <TH>Event</TH>
            <TH>Detail</TH>
            <TH>Actor</TH>
            <TH>When</TH>
          </TR>
        </THead>
        <TBody>
          {entries.map((e, i) => (
            <TR key={e.id ?? i}>
              <TD>
                <Chip>{humanStatus(e.event_type)}</Chip>
              </TD>
              <TD className="max-w-[420px] text-data text-dim">
                {e.description || DASH}
              </TD>
              <TD className="text-kbd text-dim2">{e.actor || DASH}</TD>
              <TD className="text-kbd text-dim2">
                {e.created_at ? fmtDateTime(e.created_at) : DASH}
              </TD>
            </TR>
          ))}
        </TBody>
      </Table>
    </div>
  );
}

// ---- Evidence (from detail.evidence_chain — no fetch) -----------------------
function EvidenceView({ entries }: { entries: IncidentEvidenceEntry[] }) {
  if (entries.length === 0) {
    return (
      <StatusState
        variant="empty"
        title="No evidence recorded"
        description="No evidence has been attached to this incident's chain yet. Evidence is added from the actions rail below (analyst or higher)."
      />
    );
  }
  return (
    <div className="overflow-hidden rounded-lg border border-line">
      <Table>
        <THead>
          <TR>
            <TH>Type</TH>
            <TH>Description</TH>
            <TH>Reference</TH>
            <TH>Added by</TH>
            <TH>When</TH>
          </TR>
        </THead>
        <TBody>
          {entries.map((ev, i) => (
            <TR key={i}>
              <TD>
                <Chip>{humanStatus(ev.type ?? "")}</Chip>
              </TD>
              <TD className="max-w-[360px] text-data text-dim">
                {ev.description || DASH}
              </TD>
              <TD mono className="text-kbd">
                {ev.ref_id || DASH}
              </TD>
              <TD className="text-kbd text-dim2">{ev.added_by || DASH}</TD>
              <TD className="text-kbd text-dim2">
                {ev.added_at ? fmtDateTime(ev.added_at) : DASH}
              </TD>
            </TR>
          ))}
        </TBody>
      </Table>
    </div>
  );
}

// ---- SLA (fetch — license-gated `sla`, fail-closed to locked) ---------------
function humanRemaining(sec: number | null | undefined): string {
  if (sec == null) return DASH;
  if (sec <= 0) return "overdue";
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return h > 0 ? `${h}h ${m}m left` : `${m}m left`;
}

function SlaTimer({
  label,
  due,
  remaining,
  met,
}: {
  label: string;
  due?: string | null;
  remaining?: number | null;
  met?: boolean | null;
}) {
  const overdue = remaining != null && remaining <= 0;
  const metState = met === true ? "met" : met === false ? "missed" : "pending";
  return (
    <Panel inset className="p-3">
      <div className="text-micro uppercase tracking-wide text-dim2">
        {label} SLA
      </div>
      <div
        className={cn(
          "mt-1 font-mono text-title tabular",
          overdue ? "text-sev-crit" : "text-ink",
        )}
      >
        {humanRemaining(remaining)}
      </div>
      <div className="text-kbd text-dim2">
        due {due ? fmtDateTime(due) : DASH} · {metState}
      </div>
    </Panel>
  );
}

interface SlaState {
  sla: IncidentSla | null;
  error: string | null;
  locked: boolean;
  loading: boolean;
}

function SlaView({ incidentId }: { incidentId: string }) {
  const [state, setState] = useState<SlaState>({
    sla: null,
    error: null,
    locked: false,
    loading: true,
  });
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setState((p) => ({ ...p, loading: true, error: null }));
    try {
      const sla = await getIncidentSla(incidentId, ac.signal);
      if (ac.signal.aborted) return;
      setState({ sla, error: null, locked: false, loading: false });
    } catch (e) {
      if (ac.signal.aborted) return;
      if (e instanceof ApiError && (e.status === 402 || e.status === 403)) {
        setState({ sla: null, error: null, locked: true, loading: false });
      } else {
        setState({ sla: null, error: errMessage(e), locked: false, loading: false });
      }
    }
  }, [incidentId]);

  useEffect(() => {
    load();
    return () => abortRef.current?.abort();
  }, [load]);

  const { sla, error, locked, loading } = state;
  if (locked) return <FeatureLockedState feature="SLA tracking" tier="current" />;
  if (loading && !sla) return <StatusState variant="loading" title="Loading SLA…" />;
  if (error)
    return (
      <StatusState
        variant="error"
        title="Couldn't load SLA"
        description={error}
        action={<Chip onClick={load}>Retry</Chip>}
      />
    );
  if (!sla) return null;

  const breaches = sla.breaches ?? [];
  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        <SlaTimer
          label="Response"
          due={sla.sla_response_due}
          remaining={sla.response_remaining_sec}
          met={sla.sla_response_met}
        />
        <SlaTimer
          label="Resolution"
          due={sla.sla_resolution_due}
          remaining={sla.resolution_remaining_sec}
          met={sla.sla_resolution_met}
        />
        <Panel inset className="p-3">
          <div className="text-micro uppercase tracking-wide text-dim2">
            Tier · escalations
          </div>
          <div className="mt-1 text-title text-ink">{sla.tier ?? DASH}</div>
          <div className="text-kbd text-dim2">
            first response{" "}
            {sla.first_response_at ? fmtDateTime(sla.first_response_at) : "not yet"}{" "}
            · escalated ×{sla.escalation_count ?? 0}
          </div>
        </Panel>
      </div>

      {breaches.length === 0 ? (
        <div className="text-kbd text-dim2">
          No SLA breaches recorded for this incident.
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-line">
          <Table>
            <THead>
              <TR>
                <TH>Breach</TH>
                <TH>Severity</TH>
                <TH>Tier</TH>
                <TH>Due</TH>
                <TH>Breached</TH>
              </TR>
            </THead>
            <TBody>
              {breaches.map((b, i) => (
                <TR key={b.id ?? i}>
                  <TD>
                    <Chip>{humanStatus(b.sla_type ?? "breach")}</Chip>
                  </TD>
                  <TD className="text-kbd">{b.severity ?? DASH}</TD>
                  <TD className="text-kbd">{b.tier ?? DASH}</TD>
                  <TD className="text-kbd text-dim2">
                    {b.due_at ? fmtDateTime(b.due_at) : DASH}
                  </TD>
                  <TD className="text-kbd text-dim2">
                    {b.breached_at ? fmtDateTime(b.breached_at) : DASH}
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </div>
      )}
    </div>
  );
}

// ---- Tickets (fetch — license-gated `ticketing`, fail-closed to locked) -----
interface TicketsState {
  tickets: Ticket[] | null;
  error: string | null;
  locked: boolean;
  loading: boolean;
}

function TicketsView({ incidentId }: { incidentId: string }) {
  const [state, setState] = useState<TicketsState>({
    tickets: null,
    error: null,
    locked: false,
    loading: true,
  });
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setState((p) => ({ ...p, loading: true, error: null }));
    try {
      const res = await getTicketsForIncident(incidentId, ac.signal);
      if (ac.signal.aborted) return;
      setState({ tickets: res.tickets, error: null, locked: false, loading: false });
    } catch (e) {
      if (ac.signal.aborted) return;
      if (e instanceof ApiError && (e.status === 402 || e.status === 403)) {
        setState({ tickets: null, error: null, locked: true, loading: false });
      } else {
        setState({ tickets: null, error: errMessage(e), locked: false, loading: false });
      }
    }
  }, [incidentId]);

  useEffect(() => {
    load();
    return () => abortRef.current?.abort();
  }, [load]);

  const { tickets, error, locked, loading } = state;
  if (locked) return <FeatureLockedState feature="Ticketing" tier="current" />;
  if (loading && !tickets)
    return <StatusState variant="loading" title="Loading tickets…" />;
  if (error)
    return (
      <StatusState
        variant="error"
        title="Couldn't load tickets"
        description={error}
        action={<Chip onClick={load}>Retry</Chip>}
      />
    );
  if (!tickets || tickets.length === 0) {
    return (
      <StatusState
        variant="empty"
        title="No linked tickets"
        description="No tickets have been created for this incident. Create one from the Tickets tab."
      />
    );
  }
  return (
    <div className="overflow-hidden rounded-lg border border-line">
      <Table>
        <THead>
          <TR>
            <TH>Provider</TH>
            <TH>External</TH>
            <TH>Status</TH>
            <TH>Summary</TH>
            <TH>Created</TH>
          </TR>
        </THead>
        <TBody>
          {tickets.map((t) => (
            <TR key={t.id}>
              <TD className="text-kbd">{t.provider}</TD>
              <TD className="text-kbd">
                {t.external_url ? (
                  <a
                    href={t.external_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className={cn("text-acc underline", focusRing)}
                  >
                    {t.external_id ?? "open ↗"}
                  </a>
                ) : (
                  (t.external_id ?? DASH)
                )}
              </TD>
              <TD className="text-kbd">
                {humanStatus(t.platform_status)}
                {t.external_status ? (
                  <span className="text-dim2"> · {t.external_status}</span>
                ) : null}
              </TD>
              <TD className="max-w-[360px] text-data text-dim">
                {t.summary || DASH}
              </TD>
              <TD className="text-kbd text-dim2">{fmtDateTime(t.created_at)}</TD>
            </TR>
          ))}
        </TBody>
      </Table>
    </div>
  );
}
