"use client";

/**
 * DailyReviewTab — a plain-English start-of-day briefing for a NON-technical
 * reader (a manager / client executive / business owner). READ-ONLY.
 *
 * The audience can't use raw Wazuh rule names, "true positives", "avg confidence
 * 0.47" or MITRE tactic chains — so this tab reframes everything in plain words
 * and, for each incident that needs attention, shows the backend's AI-generated
 * PLAIN-ENGLISH summary as the primary text (worst-first). Clicking an item opens
 * an in-place plain explanation panel — it never redirects to the technical grid.
 *
 * There is NO single "daily review" endpoint, so the digest is COMPOSED from
 * existing reads (via `@/lib/api`), loaded with `Promise.allSettled` so a
 * per-source failure/denial degrades ONLY that section:
 *   - `GET /api/dashboard/stats`            — overnight counts (plain KPIs)
 *   - `GET /api/incidents?status=open`      — open incidents, worst-first
 *   - `GET /api/triage/decisions?sort=risk` — worst AI decisions (de-jargoned)
 *   - `GET /api/overview/summary`           — worst campaign (plain story)
 *   - `GET /api/agents` + `/api/threat-intel/stats` — system-health parity
 *
 * PLAIN SUMMARIES (token cost is the constraint):
 *   - `POST /api/incidents/{id}/plain-summary` (analyst+) generates + returns the
 *     summary; the backend CACHES it in the incident timeline, so repeat calls
 *     cost no tokens (`cached:true`).
 *   - `POST /api/incidents/batch-plain-summary` (senior_analyst+) pre-warms the
 *     cache; fired ONCE per load, fire-and-forget.
 *   - Client-side we cache every summary by incident id and fetch it ONCE (on
 *     first appearance / manual Refresh) — NEVER on the 30s poll. `summariesRef`
 *     is the source of truth for "already fetched", so a poll that returns the
 *     same incidents refetches nothing. Fail-closed: read_only (no summary role)
 *     never fetches and shows an honest note + the technical title, never a
 *     fabricated summary.
 *
 * Anonymization: identifiers are anonymized before the AI analyses them; the
 * reader sees the REAL names the backend returns. STRICTLY READ-ONLY.
 * Fixtures gate behind NEXT_PUBLIC_DHRUVA_FIXTURES.
 */

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  Chip,
  Dialog,
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
  batchPlainSummary,
  getAgents,
  getDashboardStats,
  getIncidents,
  getOverviewSummary,
  getPlainSummary,
  getTIStats,
  getTriageDecisions,
} from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { roleAtLeast } from "@/lib/rbac";
import { apiSeverity, parseJsonArray, sortIncidentsWorstFirst } from "@/lib/incident";
import { isLowGrounding } from "@/lib/grounding";
import { riskSeverity, type Severity } from "@/lib/severity";
import { decisionPresentation } from "@/lib/triage";
import { DASH, fmtInt, fmtDateTime } from "@/lib/format";
import type { TabProps } from "../tabRegistry";
import type {
  AgentsResponse,
  DashboardStats,
  DashboardStatsToday,
  IncidentListRow,
  OverviewSummary,
  TIStatsResponse,
  TriageDecision,
} from "@/lib/types";

const POLL_MS = 30_000;
const TOP_INCIDENTS = 6;
const TOP_VERDICTS = 6;

function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : "Unknown error";
}
/** A per-source 401/402/403 → the section shows an honest "not available" note. */
function isDeniedError(e: unknown): boolean {
  return e instanceof ApiError && (e.status === 401 || e.status === 402 || e.status === 403);
}

/** One composed source: either a value, or "denied" (role/tier), or an error. */
type Source<T> =
  | { kind: "ok"; value: T }
  | { kind: "denied" }
  | { kind: "error"; message: string };

function settle<T, R>(r: PromiseSettledResult<T>, pick: (v: T) => R): Source<R> {
  if (r.status === "fulfilled") return { kind: "ok", value: pick(r.value) };
  if (isDeniedError(r.reason)) return { kind: "denied" };
  return { kind: "error", message: errMessage(r.reason) };
}

/** Per-incident plain-summary state, cached client-side by incident id. */
type PlainEntry =
  | { kind: "pending" }
  | { kind: "ok"; text: string }
  | { kind: "denied" }
  | { kind: "error" };

interface State {
  dash: Source<DashboardStats> | null;
  incidents: Source<IncidentListRow[]> | null;
  decisions: Source<TriageDecision[]> | null;
  overview: Source<OverviewSummary> | null;
  agents: Source<AgentsResponse> | null;
  ti: Source<TIStatsResponse> | null;
  loading: boolean;
}

// ---- plain-language helpers -------------------------------------------------

/** Turn a technical severity into a calm, plain instruction word. */
function plainSeverity(sev: Severity): { label: string; sev: Severity } {
  switch (sev) {
    case "crit":
      return { label: "Needs urgent attention", sev };
    case "high":
      return { label: "Important — please review", sev };
    case "med":
      return { label: "Worth a look", sev };
    case "low":
      return { label: "Minor", sev };
    default:
      return { label: "For your awareness", sev };
  }
}

/** A friendly relative time ("about 2 hours ago") for a non-technical reader. */
function plainAgo(iso?: string | null): string {
  if (!iso) return "recently";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "recently";
  const secs = Math.max(0, (Date.now() - t) / 1000);
  if (secs < 90) return "just now";
  const mins = secs / 60;
  if (mins < 60) {
    const m = Math.round(mins);
    return `about ${m} minute${m === 1 ? "" : "s"} ago`;
  }
  const hrs = mins / 60;
  if (hrs < 24) {
    const h = Math.round(hrs);
    return `about ${h} hour${h === 1 ? "" : "s"} ago`;
  }
  const d = Math.round(hrs / 24);
  return `about ${d} day${d === 1 ? "" : "s"} ago`;
}

/** One plain-English sentence summarising the night, from the overnight counts. */
function nightHeadline(t: DashboardStatsToday): string {
  const total = t.total ?? 0;
  const tps = t.tps ?? 0;
  const esc = t.escalated ?? 0;
  if (total === 0) {
    return "It was a quiet night — no new security alerts came in.";
  }
  if (tps === 0) {
    return `Good news — overnight the AI checked ${fmtInt(
      total,
    )} security alerts and found no real threats. Everything looked routine.`;
  }
  const threats = `${fmtInt(tps)} real threat${tps === 1 ? "" : "s"}`;
  const raised =
    esc > 0
      ? ` ${fmtInt(esc)} ${esc === 1 ? "was" : "were"} raised to your team.`
      : "";
  return `Overnight the AI checked ${fmtInt(
    total,
  )} alerts and flagged ${threats} that need${
    tps === 1 ? "s" : ""
  } attention.${raised}`;
}

const SUMMARY_HEADINGS = [
  "WHAT HAPPENED",
  "WHAT IS AT RISK",
  "HOW SERIOUS IS THIS",
  "WHAT YOU SHOULD DO",
] as const;

interface SummarySection {
  heading: string | null;
  body: string;
}

/**
 * Split the AI plain summary into its (prompted) headings. The model is asked to
 * emit them but may not comply — so this is defensive: if no heading is found the
 * whole text is returned as one section (never fabricated, never dropped).
 */
function parsePlainSummary(text: string): SummarySection[] {
  const clean = text.trim();
  if (!clean) return [];
  // Case-insensitive search for the known headings on their own line-ish.
  const positions: { heading: string; index: number }[] = [];
  const upper = clean.toUpperCase();
  for (const h of SUMMARY_HEADINGS) {
    const i = upper.indexOf(h);
    if (i !== -1) positions.push({ heading: h, index: i });
  }
  if (positions.length === 0) return [{ heading: null, body: clean }];
  positions.sort((a, b) => a.index - b.index);
  const sections: SummarySection[] = [];
  // Any preamble before the first heading is kept as an unlabelled section.
  if (positions[0].index > 0) {
    const pre = clean.slice(0, positions[0].index).trim();
    if (pre) sections.push({ heading: null, body: pre });
  }
  positions.forEach((p, idx) => {
    const start = p.index + p.heading.length;
    const end = idx + 1 < positions.length ? positions[idx + 1].index : clean.length;
    const body = clean.slice(start, end).trim();
    // Title-case the heading for display ("WHAT HAPPENED" → "What happened").
    const label = p.heading.charAt(0) + p.heading.slice(1).toLowerCase();
    sections.push({ heading: label, body });
  });
  return sections;
}

/** The short lead line for a card: the "what happened" body, else a snippet. */
function summaryLead(text: string): string {
  const sections = parsePlainSummary(text);
  const what = sections.find((s) => s.heading?.toLowerCase() === "what happened");
  const source = (what?.body || sections[0]?.body || text).trim();
  if (source.length <= 200) return source;
  return source.slice(0, 197).trimEnd() + "…";
}

// ---- component --------------------------------------------------------------

export function DailyReviewTab({ onNavigate }: TabProps) {
  const { role } = useAuth();
  const canSummarize = roleAtLeast(role, "analyst");
  const canBatchWarm = roleAtLeast(role, "senior_analyst");

  const [state, setState] = useState<State>({
    dash: null,
    incidents: null,
    decisions: null,
    overview: null,
    agents: null,
    ti: null,
    loading: true,
  });
  const [secondsAgo, setSecondsAgo] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  // Plain-summary cache — the ONLY place summaries are fetched, keyed by id.
  const [summaries, setSummaries] = useState<Record<string, PlainEntry>>({});
  const summariesRef = useRef<Record<string, PlainEntry>>({});
  const batchFiredRef = useRef(false);
  // Bumped on manual Refresh so cleared (errored/pending) ids get one retry.
  const [summaryEpoch, setSummaryEpoch] = useState(0);
  // Which incident's plain panel is open (in-place, no redirect).
  const [openId, setOpenId] = useState<string | null>(null);

  const setSummary = useCallback((id: string, entry: PlainEntry) => {
    setSummaries((prev) => {
      const next = { ...prev, [id]: entry };
      summariesRef.current = next;
      return next;
    });
  }, []);

  const load = useCallback(async (manual: boolean) => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    if (manual) setRefreshing(true);
    try {
      const [dash, incidents, decisions, overview, agents, ti] =
        await Promise.allSettled([
          getDashboardStats(ac.signal),
          getIncidents({ status: "open" }, ac.signal),
          getTriageDecisions({ sort: "risk" }, ac.signal),
          getOverviewSummary(ac.signal),
          getAgents({}, ac.signal),
          getTIStats(ac.signal),
        ]);
      if (ac.signal.aborted) return;
      setState({
        dash: settle(dash, (v) => v),
        incidents: settle(incidents, (v) => v.incidents),
        decisions: settle(decisions, (v) => v.decisions),
        overview: settle(overview, (v) => v),
        agents: settle(agents, (v) => v),
        ti: settle(ti, (v) => v),
        loading: false,
      });
      setSecondsAgo(0);
    } finally {
      if (!ac.signal.aborted) setRefreshing(false);
    }
  }, []);

  // Manual refresh: reload the digest AND re-arm the plain-summary fetch so any
  // errored/pending summaries get one more try (cached "ok" ones are kept — no
  // needless LLM spend).
  const handleRefresh = useCallback(() => {
    setSummaries((prev) => {
      const next: Record<string, PlainEntry> = {};
      for (const [id, e] of Object.entries(prev)) {
        if (e.kind === "ok") next[id] = e; // keep cached; drop pending/error/denied
      }
      summariesRef.current = next;
      return next;
    });
    batchFiredRef.current = false;
    setSummaryEpoch((n) => n + 1);
    load(true);
  }, [load]);

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

  const { dash, incidents, decisions, overview, agents, ti, loading } = state;

  // Worst-first incidents shown in "what needs you now" (and clickable → panel).
  const topIncidents = useMemo<IncidentListRow[]>(() => {
    if (!incidents || incidents.kind !== "ok") return [];
    return sortIncidentsWorstFirst(incidents.value).slice(0, TOP_INCIDENTS);
  }, [incidents]);
  // Stable dependency: only re-run the summary fetch when the SET of visible ids
  // changes — a poll returning the same incidents leaves this key untouched, so
  // nothing is refetched (no per-poll LLM spend).
  const topIdsKey = topIncidents.map((i) => i.id).join(",");

  /**
   * Fetch the plain summary for each visible incident EXACTLY ONCE (missing ids
   * only). Fail-closed for roles without the summary permission. Fires the batch
   * pre-warm once. Never fetches an id already ok/pending/denied.
   */
  const ensureSummaries = useCallback(
    (ids: string[]) => {
      if (ids.length === 0) return;
      if (!canSummarize) {
        // Mirror the server 403 (analyst+ only): mark denied, never fetch.
        setSummaries((prev) => {
          let changed = false;
          const next = { ...prev };
          for (const id of ids) {
            if (!next[id]) {
              next[id] = { kind: "denied" };
              changed = true;
            }
          }
          if (changed) summariesRef.current = next;
          return changed ? next : prev;
        });
        return;
      }
      const toFetch = ids.filter((id) => !summariesRef.current[id]);
      if (toFetch.length === 0) return;

      // Best-effort server-side pre-warm (senior_analyst+), ONCE per load cycle.
      // Fire-and-forget: a role/tier denial or any error is irrelevant because
      // the per-incident path below still works for analyst+.
      if (!batchFiredRef.current && canBatchWarm) {
        batchFiredRef.current = true;
        batchPlainSummary(toFetch.slice(0, 10)).catch(() => {});
      }

      // Mark pending, then fetch each once.
      setSummaries((prev) => {
        const next = { ...prev };
        for (const id of toFetch) next[id] = { kind: "pending" };
        summariesRef.current = next;
        return next;
      });
      for (const id of toFetch) {
        getPlainSummary(id)
          .then((r) => setSummary(id, { kind: "ok", text: r.summary }))
          .catch((e) =>
            setSummary(id, isDeniedError(e) ? { kind: "denied" } : { kind: "error" }),
          );
      }
    },
    [canSummarize, canBatchWarm, setSummary],
  );

  useEffect(() => {
    ensureSummaries(topIncidents.map((i) => i.id));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [topIdsKey, summaryEpoch, ensureSummaries]);

  const openIncident = openId
    ? topIncidents.find((i) => i.id === openId) ?? null
    : null;

  // First paint: nothing resolved yet.
  const anyResolved = dash || incidents || decisions || overview;
  const allErrored =
    !loading &&
    [dash, incidents, decisions, overview].every((s) => s?.kind === "error");

  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PageHeading
          title="Daily review"
          sub="Your plain-English briefing — what happened overnight and what needs you now, in everyday language."
        />
        <PollingStatus
          className="mt-1"
          secondsAgo={secondsAgo}
          refreshing={refreshing}
          onRefresh={handleRefresh}
        />
      </div>

      {loading && !anyResolved ? (
        <StatusState variant="loading" title="Putting your briefing together…" />
      ) : allErrored ? (
        <StatusState
          variant="error"
          title="Couldn't put your briefing together"
          description="None of the underlying information sources responded."
          action={<Chip onClick={handleRefresh}>Retry</Chip>}
        />
      ) : (
        <div className="flex flex-col gap-3">
          <Headline dash={dash} />
          <OvernightTiles dash={dash} />
          <NeedsYouNow
            incidents={incidents}
            topIncidents={topIncidents}
            summaries={summaries}
            overview={overview}
            dash={dash}
            decisions={decisions}
            canSummarize={canSummarize}
            onOpen={setOpenId}
            onNavigate={onNavigate}
          />
          <OvernightDecisions decisions={decisions} onNavigate={onNavigate} />
          <HealthSection agents={agents} ti={ti} dash={dash} />
        </div>
      )}

      <PlainPanel
        incident={openIncident}
        entry={openIncident ? summaries[openIncident.id] ?? null : null}
        canSummarize={canSummarize}
        onClose={() => setOpenId(null)}
        onNavigate={onNavigate}
      />
    </>
  );
}

// ---- plain narrative headline ----------------------------------------------
function Headline({ dash }: { dash: State["dash"] }) {
  if (!dash || dash.kind !== "ok") {
    // No overnight counts (denied / error / not yet) → a neutral, honest line.
    return (
      <div className="rounded-lg border border-line bg-panel2 px-4 py-3 text-data text-dim">
        Here is your plain-English briefing. Each section below loads on its own,
        so anything your access doesn&apos;t cover simply shows a short note.
      </div>
    );
  }
  return (
    <div
      role="status"
      className="rounded-lg border border-line bg-panel2 px-4 py-3 text-body text-ink"
    >
      {nightHeadline(dash.value.today)}
    </div>
  );
}

// ---- plain KPI tiles --------------------------------------------------------
function OvernightTiles({ dash }: { dash: State["dash"] }) {
  if (!dash) return null;
  if (dash.kind === "denied") {
    return <SectionNote text="The overnight numbers aren't available to your access level." />;
  }
  if (dash.kind === "error") {
    return (
      <SectionNote
        text={`The overnight numbers are temporarily unavailable: ${dash.message}`}
        tone="error"
      />
    );
  }
  const t = dash.value.today;
  const confPct = Math.round((t.avg_confidence ?? 0) * 100);
  return (
    <div>
      <SectionTitle>What happened overnight</SectionTitle>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
        <Tile label="Alerts checked" value={fmtInt(t.total)} sub="in the last 24 hours" />
        <Tile
          label="Real threats found"
          value={fmtInt(t.tps)}
          sub="confirmed as genuine"
          valueSeverity={(t.tps ?? 0) > 0 ? "high" : undefined}
        />
        <Tile label="False alarms" value={fmtInt(t.fps)} sub="turned out to be nothing" />
        <Tile
          label="Handled automatically"
          value={fmtInt(t.auto_closed)}
          sub="no one needed"
        />
        <Tile
          label="Raised to your team"
          value={fmtInt(t.escalated)}
          sub="passed to a person"
          valueSeverity={(t.escalated ?? 0) > 0 ? "med" : undefined}
        />
        <Tile
          label="How sure the AI was"
          value={`${confPct}%`}
          sub="on average"
          math={
            <>
              On average, how confident the AI was in its own decisions across
              the night. It&apos;s a rough self-check, not a measure of how
              dangerous anything is — treat it as background context.
            </>
          }
        />
      </div>
    </div>
  );
}

// ---- what needs you now -----------------------------------------------------
function NeedsYouNow({
  incidents,
  topIncidents,
  summaries,
  overview,
  dash,
  decisions,
  canSummarize,
  onOpen,
  onNavigate,
}: {
  incidents: State["incidents"];
  topIncidents: IncidentListRow[];
  summaries: Record<string, PlainEntry>;
  overview: State["overview"];
  dash: State["dash"];
  decisions: State["decisions"];
  canSummarize: boolean;
  onOpen: (id: string) => void;
  onNavigate?: TabProps["onNavigate"];
}) {
  const pendingReviews = dash && dash.kind === "ok" ? dash.value.pending_reviews : null;

  return (
    <div>
      <SectionTitle>What needs you now</SectionTitle>
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <NeedsList
            incidents={incidents}
            topIncidents={topIncidents}
            summaries={summaries}
            canSummarize={canSummarize}
            onOpen={onOpen}
          />
        </div>
        <div className="flex flex-col gap-3">
          <WorstCampaignPanel overview={overview} />
          <PeopleAskingPanel pendingReviews={pendingReviews} onNavigate={onNavigate} />
          <LowGroundingPanel decisions={decisions} onNavigate={onNavigate} />
        </div>
      </div>
    </div>
  );
}

/**
 * AIS2 — how many recent AI decisions the AI's OWN grounding self-check flagged
 * as low-confidence. Composed client-side from the same `/api/triage/decisions?
 * sort=risk` read the digest already loads (no new endpoint), and deep-links to
 * the Triage tab via the SAME `onNavigate("triage")` mechanism the other tiles
 * use. Read-only / decorative: it never changes a verdict. Rendered only when the
 * decisions source resolved (its denied/error states are already shown by the
 * "What the AI decided overnight" section — no duplicate error copy here).
 */
function LowGroundingPanel({
  decisions,
  onNavigate,
}: {
  decisions: State["decisions"];
  onNavigate?: TabProps["onNavigate"];
}) {
  if (!decisions || decisions.kind !== "ok") return null;
  const count = decisions.value.reduce(
    (n, d) => n + (isLowGrounding(d.grounding) ? 1 : 0),
    0,
  );
  return (
    <Panel className="p-4">
      <div className="text-title text-ink">Where the AI wasn&apos;t sure</div>
      <p className="mt-2 text-data text-dim">
        {count === 0
          ? "The AI was confident in its recent calls — none were flagged by its own self-check for a closer human look."
          : `${fmtInt(count)} recent AI decision${count === 1 ? "" : "s"} ${
              count === 1 ? "was" : "were"
            } flagged by the AI's own self-check as low-confidence — worth a human look.`}
      </p>
      {onNavigate && count > 0 && (
        <div className="mt-3">
          <Chip variant="gated" onClick={() => onNavigate("triage")}>
            Review these in Triage ›
          </Chip>
        </div>
      )}
    </Panel>
  );
}

function NeedsList({
  incidents,
  topIncidents,
  summaries,
  canSummarize,
  onOpen,
}: {
  incidents: State["incidents"];
  topIncidents: IncidentListRow[];
  summaries: Record<string, PlainEntry>;
  canSummarize: boolean;
  onOpen: (id: string) => void;
}) {
  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-3">
        <div className="text-title text-ink">Things that need attention</div>
        <span className="text-kbd text-dim2">worst first</span>
      </div>
      {!incidents ? null : incidents.kind === "denied" ? (
        <BodyNote text="Open items aren't available to your access level." />
      ) : incidents.kind === "error" ? (
        <BodyNote text={`Couldn't load open items: ${incidents.message}`} tone="error" />
      ) : topIncidents.length === 0 ? (
        <BodyNote text="Nothing needs you right now — everything is clear." />
      ) : (
        <ul className="mt-2 flex flex-col divide-y divide-line border-t border-line">
          {topIncidents.map((inc) => (
            <NeedsRow
              key={inc.id}
              inc={inc}
              entry={summaries[inc.id] ?? null}
              canSummarize={canSummarize}
              onOpen={onOpen}
            />
          ))}
        </ul>
      )}
    </Panel>
  );
}

function NeedsRow({
  inc,
  entry,
  canSummarize,
  onOpen,
}: {
  inc: IncidentListRow;
  entry: PlainEntry | null;
  canSummarize: boolean;
  onOpen: (id: string) => void;
}) {
  const sev = apiSeverity(inc.severity);
  const plain = plainSeverity(sev);
  const hosts = parseJsonArray(inc.affected_hosts);
  const machine = hosts.length > 0 ? hosts[0] : null;
  const when = plainAgo(inc.last_seen ?? inc.first_seen);

  // Primary text = the AI plain summary; honest fallbacks otherwise.
  let primary: React.ReactNode;
  if (entry?.kind === "ok") {
    primary = <span className="text-ink">{summaryLead(entry.text)}</span>;
  } else if (entry?.kind === "pending") {
    primary = (
      <span className="text-dim2">
        <span className="animate-pulse">Summarising in plain English…</span>
      </span>
    );
  } else if (entry?.kind === "denied" || !canSummarize) {
    primary = (
      <span className="text-dim">
        {inc.title}
        <span className="ml-1 text-kbd text-dim2">
          (plain-English summary needs analyst access)
        </span>
      </span>
    );
  } else if (entry?.kind === "error") {
    primary = (
      <span className="text-dim">
        {inc.title}
        <span className="ml-1 text-kbd text-dim2">
          (couldn&apos;t generate a plain summary — showing the technical title)
        </span>
      </span>
    );
  } else {
    primary = <span className="text-dim2">{inc.title}</span>;
  }

  return (
    <li>
      <button
        type="button"
        onClick={() => onOpen(inc.id)}
        aria-label={`Open plain explanation: ${inc.title}`}
        className="flex w-full items-start gap-3 px-4 py-3 text-left hover:bg-panel2 focus:bg-panel2 focus:outline-none"
      >
        <PlainSeverityChip sev={plain.sev} label={plain.label} />
        <span className="min-w-0 flex-1">
          <span className="block text-data">{primary}</span>
          <span className="mt-1 block text-kbd text-dim2">
            {machine ? `On ${machine} · ` : ""}
            {when}
            {inc.alert_count > 0
              ? ` · ${fmtInt(inc.alert_count)} related alert${inc.alert_count === 1 ? "" : "s"}`
              : ""}
          </span>
        </span>
        <span aria-hidden="true" className="mt-0.5 text-dim2">
          ›
        </span>
      </button>
    </li>
  );
}

/** A calm, labelled severity chip — colour NEVER carries meaning alone. */
function PlainSeverityChip({ sev, label }: { sev: Severity; label: string }) {
  const tone: Record<Severity, string> = {
    crit: "border-sev-crit/40 text-sev-crit",
    high: "border-sev-high/40 text-sev-high",
    med: "border-sev-med/40 text-sev-med",
    low: "border-line text-dim",
    info: "border-line text-dim2",
  };
  return (
    <span
      className={`mt-0.5 inline-block shrink-0 rounded-md border px-2 py-1 text-kbd font-semibold ${tone[sev]}`}
    >
      {label}
    </span>
  );
}

function WorstCampaignPanel({ overview }: { overview: State["overview"] }) {
  return (
    <Panel className="p-4">
      <div className="text-title text-ink">The situation to watch</div>
      {!overview ? null : overview.kind === "denied" ? (
        <div role="status" className="mt-2 text-kbd text-dim2">
          Not available to your access level.
        </div>
      ) : overview.kind === "error" ? (
        <div role="alert" className="mt-2 text-kbd text-sev-med">
          Temporarily unavailable: {overview.message}
        </div>
      ) : (
        <CampaignStory o={overview.value} />
      )}
    </Panel>
  );
}

/**
 * Plain-language telling of the worst campaign — NO MITRE tactic IDs. Composed
 * from the overview fields the backend already returns.
 */
function CampaignStory({ o }: { o: OverviewSummary }) {
  const active = o.active_campaigns.value;
  if (active === 0) {
    return (
      <p className="mt-2 text-data text-dim">
        No coordinated attacks are in progress right now. The pieces we&apos;re
        seeing look isolated rather than part of one campaign.
      </p>
    );
  }
  const advancing = o.active_campaigns.advancing;
  const furthest = o.furthest_tactic;
  const dwell = o.estate_dwell_worst;
  const campaignName = furthest.campaign?.name ?? dwell.campaign?.name ?? null;
  const serious = furthest.exfil_or_impact_reached;

  return (
    <div className="mt-2 flex flex-col gap-2 text-data text-dim">
      <p>
        {active === 1
          ? "One coordinated attack is in progress"
          : `${fmtInt(active)} coordinated attacks are in progress`}
        {advancing > 0
          ? `, and ${fmtInt(advancing)} ${advancing === 1 ? "is" : "are"} still moving forward.`
          : ", and they appear to have stalled for now."}
        {campaignName ? ` The one to watch involves ${campaignName}.` : ""}
      </p>
      {dwell.value ? (
        <p>
          It has been going on for roughly{" "}
          <span className="text-ink">{dwell.value}</span> — the longer it runs,
          the more chance the attacker has to cause harm.
        </p>
      ) : null}
      <p className={serious ? "text-sev-crit" : "text-dim"}>
        {serious
          ? "This is serious: the attacker may have reached your data or disrupted a system. It should be looked at right away."
          : "So far it has been caught in its early stages, before any real damage."}
      </p>
    </div>
  );
}

function PeopleAskingPanel({
  pendingReviews,
  onNavigate,
}: {
  pendingReviews: number | null;
  onNavigate?: TabProps["onNavigate"];
}) {
  const n = pendingReviews ?? 0;
  return (
    <Panel className="p-4">
      <div className="text-title text-ink">Waiting on a decision</div>
      <p className="mt-2 text-data text-dim">
        {pendingReviews == null
          ? "We couldn't check the review queue right now."
          : n === 0
            ? "Nothing is waiting on a human decision — the team is caught up."
            : `${fmtInt(n)} item${n === 1 ? "" : "s"} ${
                n === 1 ? "is" : "are"
              } waiting for someone on the team to make a call.`}
      </p>
      {onNavigate && n > 0 && (
        <div className="mt-3">
          <Chip variant="cite" onClick={() => onNavigate("triage")}>
            Team review queue ›
          </Chip>
        </div>
      )}
    </Panel>
  );
}

// ---- what the AI decided overnight (de-jargoned) ----------------------------
function OvernightDecisions({
  decisions,
  onNavigate,
}: {
  decisions: State["decisions"];
  onNavigate?: TabProps["onNavigate"];
}) {
  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-3">
        <div className="text-title text-ink">What the AI decided overnight</div>
        {onNavigate && (
          <Chip variant="cite" onClick={() => onNavigate("triage")}>
            Full review queue ›
          </Chip>
        )}
      </div>
      {!decisions ? null : decisions.kind === "denied" ? (
        <BodyNote text="The AI's overnight decisions aren't available to your access level." />
      ) : decisions.kind === "error" ? (
        <BodyNote text={`Couldn't load the AI's decisions: ${decisions.message}`} tone="error" />
      ) : decisions.value.length === 0 ? (
        <BodyNote text="The AI hasn't recorded any decisions yet." />
      ) : (
        <Table className="mt-2">
          <THead>
            <TR>
              <TH>Concern level</TH>
              <TH>What the AI concluded</TH>
              <TH>Machine</TH>
              <TH>When</TH>
            </TR>
          </THead>
          <TBody>
            {decisions.value.slice(0, TOP_VERDICTS).map((d) => {
              const vp = decisionPresentation({
                verdict: String(d.verdict),
                llm_failed: d.llm_failed,
              });
              const plain = plainSeverity(riskSeverity(d.risk_score));
              return (
                <TR key={d.id}>
                  <TD>
                    <span className="text-meta text-dim">{plain.label}</span>
                  </TD>
                  <TD>
                    <span className={`text-meta font-semibold ${vp.className}`}>
                      <span aria-hidden="true">{vp.glyph}</span> {vp.label}
                    </span>
                  </TD>
                  <TD>{d.host ?? <span className="text-dim2">{DASH}</span>}</TD>
                  <TD>{plainAgo(d.created_at)}</TD>
                </TR>
              );
            })}
          </TBody>
        </Table>
      )}
    </Panel>
  );
}

// ---- click → in-place plain explanation panel -------------------------------
function PlainPanel({
  incident,
  entry,
  canSummarize,
  onClose,
  onNavigate,
}: {
  incident: IncidentListRow | null;
  entry: PlainEntry | null;
  canSummarize: boolean;
  onClose: () => void;
  onNavigate?: TabProps["onNavigate"];
}) {
  const open = incident !== null;
  const sev = incident ? apiSeverity(incident.severity) : "info";
  const plain = plainSeverity(sev);
  const hosts = incident ? parseJsonArray(incident.affected_hosts) : [];

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth={560}
      title={incident ? "In plain English" : undefined}
    >
      {incident && (
        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            <PlainSeverityChip sev={plain.sev} label={plain.label} />
            <div className="text-body font-semibold text-ink">{incident.title}</div>
            <div className="text-kbd text-dim2">
              {hosts.length > 0 ? `On ${hosts.join(", ")} · ` : ""}
              {plainAgo(incident.last_seen ?? incident.first_seen)}
              {incident.alert_count > 0
                ? ` · ${fmtInt(incident.alert_count)} related alert${
                    incident.alert_count === 1 ? "" : "s"
                  }`
                : ""}
            </div>
          </div>

          <PlainPanelBody entry={entry} canSummarize={canSummarize} title={incident.title} />

          <div className="rounded-lg border border-line bg-panel2 px-3 py-2 text-kbd text-dim2">
            The names above are real. Identifying details are anonymized before
            the AI analyses anything, then restored for you here.
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2">
            <Chip onClick={onClose}>Close</Chip>
            {onNavigate && (
              <button
                type="button"
                onClick={() => {
                  onNavigate("incidents", incident.id);
                  onClose();
                }}
                className="text-kbd text-dim underline decoration-dotted underline-offset-2 hover:text-ink focus:text-ink focus:outline-none"
              >
                Open the technical view (for analysts) ›
              </button>
            )}
          </div>
        </div>
      )}
    </Dialog>
  );
}

function PlainPanelBody({
  entry,
  canSummarize,
  title,
}: {
  entry: PlainEntry | null;
  canSummarize: boolean;
  title: string;
}) {
  if (entry?.kind === "ok") {
    const sections = parsePlainSummary(entry.text);
    return (
      <div className="flex flex-col gap-3">
        {sections.map((s, i) => (
          <div key={i}>
            {s.heading && (
              <div className="mb-1 text-kbd uppercase tracking-wider text-dim2">
                {s.heading}
              </div>
            )}
            <p className="whitespace-pre-wrap text-data leading-relaxed text-ink">
              {s.body}
            </p>
          </div>
        ))}
      </div>
    );
  }
  if (entry?.kind === "pending") {
    return (
      <div role="status" className="animate-pulse text-data text-dim2">
        Writing a plain-English explanation… this can take a few seconds.
      </div>
    );
  }
  // Honest fallbacks — never fabricate a summary.
  if (entry?.kind === "denied" || !canSummarize) {
    return (
      <div className="text-data text-dim">
        <p className="text-ink">{title}</p>
        <p className="mt-2 text-dim2">
          A plain-English summary of this item needs analyst access, so we can
          only show its technical title here.
        </p>
      </div>
    );
  }
  return (
    <div className="text-data text-dim">
      <p className="text-ink">{title}</p>
      <p className="mt-2 text-dim2">
        We couldn&apos;t generate a plain-English summary for this one right now.
        Use Refresh to try again, or open the technical view below.
      </p>
    </div>
  );
}

// ---- system health (parity-restore of legacy Daily Review → System Health) --
// Legacy `renderDRHealth` (app.js) fanned out to /agents, /dashboard/stats and
// /threat-intel/stats. READ-ONLY. RBAC/tier mirrored: /agents + /dashboard/stats
// are verify_jwt (all roles); /threat-intel/stats rides `ti_feeds_tier1` — a
// 402/403 lands as `denied` so its panel shows an honest "not licensed" note.
function HealthSection({
  agents,
  ti,
  dash,
}: {
  agents: State["agents"];
  ti: State["ti"];
  dash: State["dash"];
}) {
  const today: DashboardStatsToday | null =
    dash && dash.kind === "ok" ? dash.value.today : null;
  return (
    <div>
      <SectionTitle>Is everything running?</SectionTitle>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
        <EndpointsHealth agents={agents} />
        <AlertActivityHealth today={today} dash={dash} />
        <ThreatIntelHealth ti={ti} />
        <AiEngineHealth today={today} />
      </div>
    </div>
  );
}

function HealthPanel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Panel className="p-4">
      <div className="text-micro uppercase tracking-wide text-dim2">{title}</div>
      {children}
    </Panel>
  );
}

function EndpointsHealth({ agents }: { agents: State["agents"] }) {
  return (
    <HealthPanel title="Computers being watched">
      {!agents ? null : agents.kind === "denied" ? (
        <div className="mt-2 text-kbd text-dim2">Not available to your access level.</div>
      ) : agents.kind === "error" ? (
        <div className="mt-2 text-kbd text-sev-med">Unavailable: {agents.message}</div>
      ) : (
        (() => {
          const list = agents.value.agents ?? [];
          const online = list.filter(
            (a) => a.status === "active" || a.status === "connected",
          );
          const offline = list.filter(
            (a) => a.status !== "active" && a.status !== "connected",
          );
          const tone =
            list.length === 0
              ? "text-dim2"
              : offline.length === 0
                ? "text-ink"
                : offline.length <= 2
                  ? "text-sev-med"
                  : "text-sev-crit";
          return (
            <>
              <div className={`mt-2 font-mono text-title tabular ${tone}`}>
                {online.length} / {list.length} reporting in
              </div>
              <div className="text-kbd text-dim2">
                {list.length === 0
                  ? "No computers are reporting in yet."
                  : offline.length === 0
                    ? "Every computer is online and protected."
                    : `Not reporting: ${offline
                        .slice(0, 5)
                        .map((a) => a.name ?? a.id)
                        .join(", ")}${offline.length > 5 ? "…" : ""}`}
              </div>
            </>
          );
        })()
      )}
    </HealthPanel>
  );
}

function AlertActivityHealth({
  today,
  dash,
}: {
  today: DashboardStatsToday | null;
  dash: State["dash"];
}) {
  return (
    <HealthPanel title="Alerts in the last 24h">
      {dash && dash.kind === "denied" ? (
        <div className="mt-2 text-kbd text-dim2">Not available to your access level.</div>
      ) : dash && dash.kind === "error" ? (
        <div className="mt-2 text-kbd text-sev-med">Unavailable: {dash.message}</div>
      ) : today ? (
        <>
          <div className="mt-2 font-mono text-title tabular text-ink">
            {fmtInt(today.total)} checked
          </div>
          <div className="text-kbd text-dim2">
            {fmtInt(today.auto_closed)} cleared automatically · {fmtInt(today.escalated)}{" "}
            sent to the team · {fmtInt(today.tps)} confirmed real
          </div>
        </>
      ) : null}
    </HealthPanel>
  );
}

function ThreatIntelHealth({ ti }: { ti: State["ti"] }) {
  return (
    <HealthPanel title="Threat intelligence">
      {!ti ? null : ti.kind === "denied" ? (
        <div className="mt-2 text-kbd text-dim2">Not included in this plan.</div>
      ) : ti.kind === "error" ? (
        <div className="mt-2 text-kbd text-sev-med">Unavailable: {ti.message}</div>
      ) : (
        (() => {
          const feeds = ti.value.feeds ?? [];
          const healthy = feeds.filter((f) => f.status === "active");
          const iocs = ti.value.stats?.total_iocs ?? 0;
          return (
            <div className="mt-2 flex flex-col gap-1">
              <div className="font-mono text-title tabular text-ink">
                {fmtInt(iocs)}{" "}
                <span className="text-kbd text-dim2">known bad indicators</span>
              </div>
              <div className="text-kbd text-dim2">
                {healthy.length}/{feeds.length} intelligence sources up to date
              </div>
            </div>
          );
        })()
      )}
    </HealthPanel>
  );
}

function AiEngineHealth({ today }: { today: DashboardStatsToday | null }) {
  const active = (today?.total ?? 0) > 0;
  return (
    <HealthPanel title="The AI analyst">
      <div className="mt-2 flex items-center gap-2">
        <span className={active ? "text-acc" : "text-dim2"} aria-hidden="true">
          ●
        </span>
        <span className="text-title text-ink">
          {active ? "Working and reviewing alerts" : "Quiet — nothing to review"}
        </span>
      </div>
      <div className="text-kbd text-dim2">
        Identifying details are anonymized before the AI looks at anything.
      </div>
    </HealthPanel>
  );
}

// ---- small shared bits ------------------------------------------------------
function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <div className="mb-1.5 text-kbd uppercase tracking-wider text-dim2">{children}</div>
  );
}
function SectionNote({ text, tone }: { text: string; tone?: "error" }) {
  return (
    <div
      role={tone === "error" ? "alert" : "status"}
      className={`rounded-lg border border-line bg-panel px-4 py-3 text-data ${
        tone === "error" ? "text-sev-med" : "text-dim2"
      }`}
    >
      {text}
    </div>
  );
}
function BodyNote({ text, tone }: { text: string; tone?: "error" }) {
  return (
    <div
      role={tone === "error" ? "alert" : "status"}
      className={`px-4 pb-4 pt-2 text-data ${tone === "error" ? "text-sev-med" : "text-dim2"}`}
    >
      {text}
    </div>
  );
}
