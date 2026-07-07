"use client";

/**
 * ThreatIntelTab (WO-U9) — READ-ONLY view of the platform's threat intelligence.
 *
 * Binds to `GET /api/threat-intel/stats` (`getTIStats`) and
 * `GET /api/threat-intel/cve` (`getTICves`), both `verify_jwt` +
 * `require_license_feature("ti_feeds_tier1")` (all roles per the shell ACL).
 * Shows: IoC totals + breakdowns (source / type / severity), feed health, and a
 * CVE table (CVSS / EPSS / CISA-KEV) with a KEV-only filter.
 *
 * The one WRITE (WO-U12): the manual "Run collection now" trigger
 * (`POST /api/threat-intel/collect`, `triggerTICollection`) —
 * `require_role("admin","senior_analyst")` ⇒ senior_analyst+ (mirrored by
 * `rbac.ts::tiCollectGate`; below that the control is a disabled locked chip),
 * same `ti_feeds_tier1` gate, rate-limited 2/min server-side. It is confirm-
 * gated, kicks a background collection cycle, then refetches so updated feed
 * statuses appear. Everything else here is READ-ONLY — the KEV toggle is a
 * client-side filter (a GET), the IOC lookup is a user-initiated read.
 *
 * TIER GATE: a runtime 402/403 degrades the whole surface to FeatureLockedState.
 * States: loading / empty / error+retry / locked; write submitting + typed error
 * (402/403 → role/tier denied, 429 → rate-limited); PollingStatus (30s, aborts).
 * Fixtures gate behind NEXT_PUBLIC_DHRUVA_FIXTURES (the trigger short-circuits to
 * synthetic success, NO real collection).
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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
  getTICves,
  getTIStats,
  lookupIoc,
  triggerTICollection,
} from "@/lib/api";
import { tiCollectGate } from "@/lib/rbac";
import { useAuth } from "@/lib/auth";
import { parseJsonArray } from "@/lib/incident";
import { cn, focusRing } from "@/lib/ui";
import { asBool, DASH, fmtDate, fmtDateTime, fmtInt, fmtNum } from "@/lib/format";
import type { TabProps } from "../tabRegistry";
import type {
  IocLookupResponse,
  TICve,
  TIFeed,
  TIStatsResponse,
} from "@/lib/types";

const POLL_MS = 30_000;

function isLockError(e: unknown): boolean {
  return e instanceof ApiError && (e.status === 402 || e.status === 403);
}
function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : "Unknown error";
}

interface State {
  stats: TIStatsResponse | null;
  cves: TICve[] | null;
  error: string | null;
  locked: boolean;
  lockMessage: string | null;
  loading: boolean;
}

type Flash = { tone: "ok" | "warn"; msg: string };

export function ThreatIntelTab(_props: TabProps) {
  const { role } = useAuth();
  const collectGate = tiCollectGate(role);

  const [kevOnly, setKevOnly] = useState(false);
  const [state, setState] = useState<State>({
    stats: null,
    cves: null,
    error: null,
    locked: false,
    lockMessage: null,
    loading: true,
  });
  const [secondsAgo, setSecondsAgo] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  // ---- write state (WO-U12 "Run collection now") --------------------------
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [flash, setFlash] = useState<Flash | null>(null);

  const load = useCallback(
    async (manual: boolean, kev: boolean) => {
      abortRef.current?.abort();
      const ac = new AbortController();
      abortRef.current = ac;
      if (manual) setRefreshing(true);
      try {
        const [stats, cvesRes] = await Promise.all([
          getTIStats(ac.signal),
          getTICves({ kev_only: kev, limit: 100 }, ac.signal),
        ]);
        if (ac.signal.aborted) return;
        setState({
          stats,
          cves: cvesRes.cves,
          error: null,
          locked: false,
          lockMessage: null,
          loading: false,
        });
        setSecondsAgo(0);
      } catch (e) {
        if (ac.signal.aborted) return;
        if (isLockError(e)) {
          setState({
            stats: null,
            cves: null,
            error: null,
            locked: true,
            lockMessage: errMessage(e),
            loading: false,
          });
          return;
        }
        const msg = errMessage(e);
        setState((prev) =>
          prev.stats
            ? { ...prev, loading: false }
            : {
                stats: null,
                cves: null,
                error: msg,
                locked: false,
                lockMessage: null,
                loading: false,
              },
        );
      } finally {
        if (!ac.signal.aborted) setRefreshing(false);
      }
    },
    [],
  );

  useEffect(() => {
    load(false, kevOnly);
    const poll = setInterval(() => load(false, kevOnly), POLL_MS);
    return () => {
      clearInterval(poll);
      abortRef.current?.abort();
    };
  }, [load, kevOnly]);

  useEffect(() => {
    const t = setInterval(() => setSecondsAgo((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, []);

  const onUpgrade = useCallback(() => {
    if (typeof window !== "undefined") {
      window.open("https://securesleuths.in/pricing", "_blank", "noreferrer");
    }
  }, []);

  const submitCollect = useCallback(async () => {
    setSubmitting(true);
    setActionError(null);
    try {
      const res = await triggerTICollection();
      // The server returns {status:"collection_started"} on success, or
      // {status:"error", message} if the collector is not initialized — treat
      // anything but a clear "error" as a started cycle (defensive).
      if (res.status === "error") {
        setFlash({
          tone: "warn",
          msg:
            res.message ||
            "The threat-intel collector is not available right now — nothing was collected.",
        });
      } else {
        setFlash({
          tone: "ok",
          msg: "Threat-intel collection started in the background — updated feed statuses will appear on the next refresh.",
        });
      }
      setConfirmOpen(false);
      // Give the background collect thread a moment, then refetch feed statuses.
      await load(true, kevOnly);
    } catch (e) {
      if (isLockError(e)) {
        setActionError(
          "Running a collection cycle requires a senior analyst or higher, on a tier with threat-intel feeds — the server denied it. Nothing changed.",
        );
      } else if (e instanceof ApiError && e.status === 429) {
        setActionError(
          "A collection was triggered very recently (the server rate-limits this to twice a minute). A cycle may already be running — wait a moment and try again.",
        );
      } else {
        setActionError(errMessage(e));
      }
    } finally {
      setSubmitting(false);
    }
  }, [load, kevOnly]);

  const { stats, cves, error, locked, lockMessage, loading } = state;

  const healthyFeeds = useMemo(
    () => (stats ? stats.feeds.filter((f) => asBool(f.enabled)).length : 0),
    [stats],
  );

  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PageHeading
          title="Threat intelligence"
          sub="The IoC corpus, feed health, and CVE/KEV context the platform enriches alerts with — read-only except the collection trigger."
        />
        {!locked && (
          <div className="mt-1 flex items-center gap-2">
            {stats &&
              (collectGate.canCollect ? (
                <button
                  type="button"
                  onClick={() => {
                    setActionError(null);
                    setConfirmOpen(true);
                  }}
                  className={cn(
                    "cursor-pointer rounded-md border border-grounded-border bg-grounded-border/40 px-2.5 py-1 text-meta text-grounded-ink hover:brightness-125",
                    focusRing,
                  )}
                >
                  Run collection now…
                </button>
              ) : (
                <Chip variant="gated" aria-label={collectGate.lockNote}>
                  Locked · senior_analyst+
                </Chip>
              ))}
            <PollingStatus
              secondsAgo={secondsAgo}
              refreshing={refreshing}
              onRefresh={() => load(true, kevOnly)}
            />
          </div>
        )}
      </div>

      {locked ? (
        <FeatureLockedState feature="Threat intelligence" tier="current" onUpgrade={onUpgrade} />
      ) : loading && !stats ? (
        <StatusState variant="loading" title="Loading threat intel…" />
      ) : error && !stats ? (
        <StatusState
          variant="error"
          title="Couldn't load threat intel"
          description={error}
          action={<Chip onClick={() => load(true, kevOnly)}>Retry</Chip>}
        />
      ) : stats ? (
        <div className="flex flex-col gap-3">
          {flash && <FlashBanner flash={flash} onDismiss={() => setFlash(null)} />}
          {/* KPI strip */}
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            <Tile
              label="Indicators of compromise"
              value={fmtInt(stats.stats.total_iocs)}
              sub={`${stats.feeds.length} feed${stats.feeds.length === 1 ? "" : "s"} · ${healthyFeeds} enabled`}
            />
            <Tile
              label="CISA KEV entries"
              value={fmtInt(stats.kev_count)}
              sub="known exploited vulnerabilities"
            />
            <Tile
              label="Feeds configured"
              value={fmtInt(stats.feeds.length)}
              sub={`${healthyFeeds} enabled`}
            />
          </div>

          <IocBreakdown stats={stats} />
          <IocLookupPanel />
          <FeedHealth feeds={stats.feeds} />
          <CveTable
            cves={cves ?? []}
            kevOnly={kevOnly}
            onToggleKev={setKevOnly}
          />
        </div>
      ) : null}

      {lockMessage && locked && (
        <div className="mt-2 text-kbd text-dim2">{lockMessage}</div>
      )}

      <RunCollectionDialog
        open={confirmOpen}
        submitting={submitting}
        error={actionError}
        onConfirm={submitCollect}
        onClose={() => {
          if (submitting) return;
          setConfirmOpen(false);
          setActionError(null);
        }}
      />
    </>
  );
}

/**
 * The transient result banner for the "Run collection now" write. `ok` = the
 * background cycle was accepted; `warn` = the server reported the collector is
 * unavailable. Dismissible; polite live region.
 */
function FlashBanner({
  flash,
  onDismiss,
}: {
  flash: Flash;
  onDismiss: () => void;
}) {
  const tone =
    flash.tone === "ok"
      ? "border-grounded-border text-grounded-ink"
      : "border-gated-border text-gated-ink";
  return (
    <div
      role="status"
      aria-live="polite"
      className={cn(
        "flex items-start gap-3 rounded-lg border bg-panel2 px-3.5 py-2.5 text-data",
        tone,
      )}
    >
      <span className="flex-1">{flash.msg}</span>
      <button
        type="button"
        onClick={onDismiss}
        className={cn("shrink-0 text-kbd text-dim hover:text-ink", focusRing)}
      >
        Dismiss
      </button>
    </div>
  );
}

/**
 * Confirm-to-run dialog for `POST /api/threat-intel/collect`. Collection only
 * refreshes the feeds (fetches IoCs/CVEs from the configured sources) — it takes
 * no active-response action — so this is an informational confirm, not a danger
 * gate. The primary button is the only path that fires the trigger.
 */
function RunCollectionDialog({
  open,
  submitting,
  error,
  onConfirm,
  onClose,
}: {
  open: boolean;
  submitting: boolean;
  error: string | null;
  onConfirm: () => void;
  onClose: () => void;
}) {
  if (!open) return null;
  return (
    <Dialog open onClose={onClose} maxWidth={520} title="Run a threat-intel collection cycle">
      <p className="text-data text-dim">
        This triggers a threat-intel <b>collection cycle</b> in the background: the
        platform re-fetches its configured feeds and refreshes the IoC / CVE corpus
        used to enrich alerts. It changes no rules and takes no response action. The
        server rate-limits this to twice a minute; updated feed statuses appear here
        on the next refresh.
      </p>

      {error && (
        <p className="mt-3 text-data text-sev-crit" role="alert">
          {error}
        </p>
      )}

      <div className="mt-4 flex items-center gap-2">
        <button
          type="button"
          onClick={onConfirm}
          disabled={submitting}
          className={cn(
            "rounded-md border px-3 py-1.5 text-data",
            focusRing,
            submitting
              ? "cursor-not-allowed border-line bg-field text-dim opacity-60"
              : "cursor-pointer border-grounded-border bg-grounded-border/40 text-grounded-ink hover:brightness-125",
          )}
        >
          {submitting ? "Starting…" : "Run collection now"}
        </button>
        <button
          type="button"
          onClick={onClose}
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
  );
}

/**
 * IOC LOOKUP (restored parity sub-panel — legacy app.js:5240-5273 `tiIocLookup`).
 * A USER-INITIATED read: the analyst types an indicator (IP / domain / hash) and
 * the panel queries the local threat-intel store via
 * `GET /api/threat-intel/ioc/{ioc_value}` (same `ti_feeds_tier1` gate as the rest
 * of the tab). It looks up THREAT indicators, never client PII / anon tokens —
 * the anonymization reverse-lookup boundary is deliberately NOT wired here.
 *
 * READ-ONLY: no write. Own fetch + AbortController + loading / empty ("not in the
 * local corpus") / typed-error states. A 402/403 here (same gate that already
 * loaded the tab) surfaces inline rather than tearing down the surface.
 */
function IocLookupPanel() {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<IocLookupResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const run = useCallback(async (raw: string) => {
    const value = raw.trim();
    if (value === "") return;
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setLoading(true);
    setError(null);
    try {
      const res = await lookupIoc(value, ac.signal);
      if (ac.signal.aborted) return;
      setResult(res);
    } catch (e) {
      if (ac.signal.aborted) return;
      setResult(null);
      setError(
        e instanceof ApiError && (e.status === 402 || e.status === 403)
          ? "Your license tier does not permit IOC lookup — the server denied it."
          : e instanceof Error
            ? e.message
            : "Lookup failed.",
      );
    } finally {
      if (!ac.signal.aborted) setLoading(false);
    }
  }, []);

  useEffect(() => () => abortRef.current?.abort(), []);

  return (
    <Panel className="p-4">
      <div className="mb-1 text-title text-ink">IOC lookup</div>
      <div className="mb-2.5 text-kbd text-dim2">
        Check whether a specific indicator (IP, domain, URL or file hash) is in the
        platform&apos;s local threat-intel corpus. Read-only — this looks up threat
        indicators, not client identities.
      </div>
      <form
        className="flex flex-wrap items-center gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          run(query);
        }}
      >
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="e.g. 185.220.101.4  ·  evil.example.com  ·  44d88612…"
          aria-label="Indicator to look up"
          spellCheck={false}
          autoComplete="off"
          className="min-w-[240px] flex-1 rounded-md border border-line bg-field px-3 py-1.5 text-data text-ink placeholder:text-dim2 focus:outline-none focus-visible:ring-2 focus-visible:ring-acc"
        />
        <button
          type="submit"
          disabled={loading || query.trim() === ""}
          className={`rounded-md border px-3 py-1.5 text-data ${
            loading || query.trim() === ""
              ? "cursor-not-allowed border-line bg-field text-dim opacity-60"
              : "cursor-pointer border-grounded-border bg-grounded-border/40 text-grounded-ink hover:brightness-125 focus:outline-none focus-visible:ring-2 focus-visible:ring-acc"
          }`}
        >
          {loading ? "Looking up…" : "Look up"}
        </button>
      </form>

      <div className="mt-3">
        {loading ? (
          <StatusState variant="loading" title="Querying the IOC store…" />
        ) : error ? (
          <StatusState
            variant="error"
            title="Couldn't look that up"
            description={error}
            action={<Chip onClick={() => run(query)}>Retry</Chip>}
          />
        ) : result ? (
          <IocLookupResult result={result} />
        ) : (
          <div className="text-data text-dim2">
            Enter an indicator above to search the local corpus.
          </div>
        )}
      </div>
    </Panel>
  );
}

function IocLookupResult({ result }: { result: IocLookupResponse }) {
  if (result.total === 0 || result.matches.length === 0) {
    return (
      <div className="rounded-lg border border-line bg-panel2 px-3.5 py-3 text-data text-dim">
        <span className="font-mono text-ink">{result.ioc_value}</span> is not in
        the local threat-intel corpus. That is not a verdict — it only means the
        platform&apos;s feeds and local IOCs have no record of it.
      </div>
    );
  }
  return (
    <div>
      <div className="mb-1.5 text-kbd text-dim2">
        <span className="font-mono text-ink">{result.ioc_value}</span> —{" "}
        {fmtInt(result.total)} match{result.total === 1 ? "" : "es"} in the local
        corpus.
      </div>
      <Table>
        <THead>
          <TR>
            <TH>Type</TH>
            <TH>Source</TH>
            <TH>Severity</TH>
            <TH className="text-right">Confidence</TH>
            <TH>First seen</TH>
            <TH>Tags</TH>
          </TR>
        </THead>
        <TBody>
          {result.matches.map((m, i) => {
            const tagList = parseJsonArray(m.tags);
            return (
              <TR key={`${m.source ?? "src"}-${m.ioc_type ?? "t"}-${i}`}>
                <TD mono>{m.ioc_type ?? DASH}</TD>
                <TD>{m.source ?? DASH}</TD>
                <TD>{m.severity ?? DASH}</TD>
                <TD mono className="text-right">
                  {m.confidence == null ? DASH : fmtInt(m.confidence)}
                </TD>
                <TD>{fmtDateTime(m.first_seen)}</TD>
                <TD>
                  {tagList.length === 0 ? (
                    DASH
                  ) : (
                    <div className="flex flex-wrap gap-1">
                      {tagList.map((t, j) => (
                        <span
                          key={`${t}-${j}`}
                          className="rounded border border-line px-1.5 py-0.5 text-kbd text-dim"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  )}
                </TD>
              </TR>
            );
          })}
        </TBody>
      </Table>
    </div>
  );
}

function IocBreakdown({ stats }: { stats: TIStatsResponse }) {
  const s = stats.stats;
  const groups: { title: string; rows: { label: string; count: number }[] }[] = [
    { title: "By source", rows: s.by_source.map((r) => ({ label: r.source, count: r.count })) },
    { title: "By type", rows: s.by_type.map((r) => ({ label: r.ioc_type, count: r.count })) },
    { title: "By severity", rows: s.by_severity.map((r) => ({ label: r.severity, count: r.count })) },
  ];
  if (groups.every((g) => g.rows.length === 0)) return null;

  return (
    <Panel className="p-4">
      <div className="mb-2 text-title text-ink">IoC breakdown</div>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        {groups.map((g) => {
          const max = Math.max(1, ...g.rows.map((r) => r.count));
          return (
            <div key={g.title}>
              <div className="mb-1.5 text-kbd uppercase tracking-wider text-dim2">
                {g.title}
              </div>
              {g.rows.length === 0 ? (
                <div className="text-data text-dim2">{DASH}</div>
              ) : (
                <ul className="flex flex-col gap-1.5">
                  {g.rows.map((r) => (
                    <li key={r.label}>
                      <div className="flex items-center justify-between text-data">
                        <span className="text-ink">{r.label || DASH}</span>
                        <span className="tabular text-dim">{fmtInt(r.count)}</span>
                      </div>
                      <div className="mt-0.5 h-1.5 w-full overflow-hidden rounded-pill bg-bar">
                        <div
                          className="h-full rounded-pill bg-acc"
                          style={{ width: `${(r.count / max) * 100}%` }}
                        />
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

/**
 * Feed-health status classifier — makes error vs active VISUALLY DISTINCT and
 * never colour-alone (each state pairs a glyph + a text label, per the design
 * system's severity-glyph rule). A feed with a `last_error` (e.g. cisa_kev's 403)
 * or a positive error_count or an error-like status reads as sev-crit/red ◆; a
 * healthy enabled feed reads as grounded/teal ●; a disabled feed is dim ○.
 */
const ERROR_STATUSES = new Set(["error", "failed", "failing", "unhealthy", "degraded"]);

function feedHealth(f: TIFeed): {
  kind: "disabled" | "error" | "active";
  glyph: string;
  label: string;
  className: string;
} {
  if (!asBool(f.enabled)) {
    return { kind: "disabled", glyph: "○", label: "disabled", className: "text-dim2" };
  }
  const statusStr = (f.status ?? "").toLowerCase();
  const isError =
    (f.error_count ?? 0) > 0 ||
    !!f.last_error ||
    (statusStr !== "" && ERROR_STATUSES.has(statusStr));
  if (isError) {
    return {
      kind: "error",
      glyph: "◆",
      label: f.status && !ERROR_STATUSES.has(statusStr) ? f.status : "error",
      className: "text-sev-crit",
    };
  }
  return {
    kind: "active",
    glyph: "●",
    label: f.status ?? "active",
    className: "text-teal",
  };
}

function FeedHealth({ feeds }: { feeds: TIFeed[] }) {
  return (
    <Panel className="overflow-hidden">
      <div className="px-4 pt-3 text-title text-ink">Feed health</div>
      {feeds.length === 0 ? (
        <div className="px-4 pb-4 pt-2 text-data text-dim2">
          No feeds configured for this tenant.
        </div>
      ) : (
        <Table className="mt-2">
          <THead>
            <TR>
              <TH>Feed</TH>
              <TH>Type</TH>
              <TH>Status</TH>
              <TH>Last success</TH>
              <TH className="text-right">Last batch</TH>
              <TH className="text-right">Total IoCs</TH>
              <TH className="text-right">Errors</TH>
            </TR>
          </THead>
          <TBody>
            {feeds.map((f) => {
              const health = feedHealth(f);
              return (
                <TR key={f.id}>
                  <TD>
                    <div className="text-ink">{f.feed_name}</div>
                    {f.tier != null && (
                      <div className="text-kbd text-dim2">tier {f.tier}</div>
                    )}
                  </TD>
                  <TD mono>{f.feed_type ?? DASH}</TD>
                  <TD>
                    <span
                      className={`inline-flex items-center gap-1 font-semibold ${health.className}`}
                      aria-label={`feed status: ${health.label}`}
                    >
                      <span aria-hidden="true">{health.glyph}</span>
                      <span>{health.label}</span>
                    </span>
                    {f.last_error && (
                      <div
                        className="max-w-[240px] truncate text-kbd text-sev-crit"
                        title={f.last_error}
                      >
                        {f.last_error}
                      </div>
                    )}
                  </TD>
                  <TD>{fmtDateTime(f.last_success_at)}</TD>
                  <TD mono className="text-right">{fmtInt(f.last_ioc_count)}</TD>
                  <TD mono className="text-right">{fmtInt(f.total_ioc_count)}</TD>
                  <TD
                    mono
                    className={`text-right ${(f.error_count ?? 0) > 0 ? "text-sev-med" : "text-dim2"}`}
                  >
                    {fmtInt(f.error_count)}
                  </TD>
                </TR>
              );
            })}
          </TBody>
        </Table>
      )}
    </Panel>
  );
}

function CveTable({
  cves,
  kevOnly,
  onToggleKev,
}: {
  cves: TICve[];
  kevOnly: boolean;
  onToggleKev: (v: boolean) => void;
}) {
  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-3">
        <div className="text-title text-ink">CVE intelligence</div>
        <div className="flex items-center gap-1.5" role="group" aria-label="Filter CVEs">
          <Chip
            variant={kevOnly ? "default" : "cite"}
            onClick={() => onToggleKev(false)}
            aria-label="Show all CVEs"
          >
            All
          </Chip>
          <Chip
            variant={kevOnly ? "cite" : "default"}
            onClick={() => onToggleKev(true)}
            aria-label="Show only CISA-KEV CVEs"
          >
            KEV only
          </Chip>
        </div>
      </div>
      {cves.length === 0 ? (
        <div className="px-4 pb-4 pt-2 text-data text-dim2">
          {kevOnly
            ? "No CISA-KEV CVEs in the local catalog."
            : "No CVE data collected yet."}
        </div>
      ) : (
        <Table className="mt-2">
          <THead>
            <TR>
              <TH>CVE</TH>
              <TH>Severity</TH>
              <TH className="text-right">CVSS</TH>
              <TH className="text-right">EPSS</TH>
              <TH>KEV</TH>
              <TH>Vendor / product</TH>
            </TR>
          </THead>
          <TBody>
            {cves.map((c) => {
              const kev = asBool(c.in_cisa_kev);
              const ransom = asBool(c.kev_ransomware);
              return (
                <TR key={c.cve_id}>
                  <TD mono>
                    <div className="text-ink">{c.cve_id}</div>
                    {c.description && (
                      <div
                        className="max-w-[420px] truncate font-sans text-kbd text-dim2"
                        title={c.description}
                      >
                        {c.description}
                      </div>
                    )}
                  </TD>
                  <TD>{c.severity ?? DASH}</TD>
                  <TD mono className="text-right">{fmtNum(c.cvss_score)}</TD>
                  <TD mono className="text-right">
                    {c.epss_score == null ? DASH : fmtNum(c.epss_score, 3)}
                  </TD>
                  <TD>
                    {kev ? (
                      <span className="text-sev-high">
                        ▲ KEV{ransom ? " · ransomware" : ""}
                        {c.kev_date_added ? (
                          <div className="text-kbd text-dim2">
                            added {fmtDate(c.kev_date_added)}
                          </div>
                        ) : null}
                      </span>
                    ) : (
                      <span className="text-dim2">—</span>
                    )}
                  </TD>
                  <TD>
                    {c.vendor || c.product ? (
                      <span className="text-dim">
                        {[c.vendor, c.product].filter(Boolean).join(" · ")}
                      </span>
                    ) : (
                      DASH
                    )}
                  </TD>
                </TR>
              );
            })}
          </TBody>
        </Table>
      )}
      <div className="px-4 py-2 text-kbd text-dim2">
        EPSS is the exploit-prediction probability (0–1). ▲ KEV = present in the
        CISA Known-Exploited-Vulnerabilities catalog. Read-only.
      </div>
    </Panel>
  );
}
