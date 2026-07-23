"use client";

/**
 * DecisionCacheTab (WO-H57) — governance surface for the persistent decision
 * cache. The cache lets a recurring, structurally-identical alert reuse its
 * stored triage verdict for $0 instead of re-calling the LLM. Because a cache
 * that silently skips work is exactly the kind of "the AI did something I can't
 * see" that erodes trust, EVERY cached verdict is visible here and an admin /
 * senior analyst can DISABLE (stop reuse), EDIT (downgrade/annotate), or DELETE
 * any entry — the next matching alert then goes back to the LLM.
 *
 * Binds to `GET /api/admin/decision-cache` (list + savings summary),
 * `PATCH /api/admin/decision-cache/{id}`, `DELETE /api/admin/decision-cache/{id}`,
 * and `POST /api/admin/decision-cache/purge` — all senior_analyst+ and
 * audit-logged server-side (the shell ACL mirrors the gate).
 *
 * States: loading / empty / error+retry. The cache is OFF by default on the
 * server; when empty this tab explains that rather than implying a fault.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Panel,
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
import { useAuth } from "@/lib/auth";
import {
  ApiError,
  deleteDecisionCacheEntry,
  getDecisionCache,
  purgeDecisionCache,
  updateDecisionCacheEntry,
} from "@/lib/api";
import { DASH, fmtDateTime, fmtInt } from "@/lib/format";
import { cn, focusRing } from "@/lib/ui";
import type { TabProps } from "../tabRegistry";
import type { DecisionCacheEntry, DecisionCacheSummary } from "@/lib/types";

const BTN_NEUTRAL =
  "rounded-md border border-line bg-field px-2.5 py-1 text-meta text-ink hover:bg-hover";
const BTN_DANGER =
  "rounded-md border border-sev-crit/40 bg-field px-2.5 py-1 text-meta text-sev-crit hover:bg-hover";

// Verdicts an analyst may set on a cached entry — mirrors the server's
// ALLOWED_CACHE_VERDICTS (benign / non-escalating only).
const EDITABLE_VERDICTS = [
  "auto_close",
  "false_positive",
  "benign",
  "needs_investigation",
];

function errMessage(e: unknown): string {
  return e instanceof ApiError ? e.message : e instanceof Error ? e.message : "Unknown error";
}

function SourceBadge({ source }: { source: string }) {
  const label =
    source === "human_confirmed"
      ? "human-confirmed"
      : source === "seed_noise"
        ? "seed noise"
        : "LLM-cached";
  const tone =
    source === "human_confirmed"
      ? "border-grounded-border text-grounded-ink"
      : "border-line text-dim";
  return (
    <span className={cn("rounded border px-1.5 py-0.5 text-micro", tone)}>
      {label}
    </span>
  );
}

export function DecisionCacheTab(_props: TabProps) {
  const { role } = useAuth();
  const canWrite = role !== "read_only";

  const [entries, setEntries] = useState<DecisionCacheEntry[]>([]);
  const [summary, setSummary] = useState<DecisionCacheSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ ok: boolean; msg: string } | null>(
    null,
  );
  const [busyId, setBusyId] = useState<string | null>(null);
  const [editing, setEditing] = useState<{ id: string; verdict: string } | null>(
    null,
  );
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setLoading(true);
    setError(null);
    try {
      const res = await getDecisionCache({ includeDisabled: true }, ac.signal);
      setEntries(res.entries);
      setSummary(res.summary);
    } catch (e) {
      if (ac.signal.aborted) return;
      setError(errMessage(e));
    } finally {
      if (!ac.signal.aborted) setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    return () => abortRef.current?.abort();
  }, [load]);

  // ---- writes (each refreshes on success) ----
  const runWrite = useCallback(
    async (id: string, fn: () => Promise<void>, okMsg: string) => {
      setBusyId(id);
      setNotice(null);
      try {
        await fn();
        setNotice({ ok: true, msg: okMsg });
        await load();
      } catch (e) {
        setNotice({ ok: false, msg: errMessage(e) });
      } finally {
        setBusyId(null);
      }
    },
    [load],
  );

  const toggleEnabled = (e: DecisionCacheEntry) =>
    runWrite(
      e.id,
      async () => {
        await updateDecisionCacheEntry(e.id, { enabled: !e.enabled });
      },
      e.enabled ? "Entry disabled — the next match goes to the LLM." : "Entry re-enabled.",
    );

  const saveVerdict = (e: DecisionCacheEntry, verdict: string) =>
    runWrite(
      e.id,
      async () => {
        await updateDecisionCacheEntry(e.id, { verdict });
      },
      "Verdict updated.",
    ).then(() => setEditing(null));

  const removeEntry = (e: DecisionCacheEntry) => {
    if (
      typeof window !== "undefined" &&
      !window.confirm(
        "Delete this cached verdict? The next matching alert will be re-triaged by the LLM.",
      )
    )
      return;
    return runWrite(
      e.id,
      async () => {
        await deleteDecisionCacheEntry(e.id);
      },
      "Entry deleted.",
    );
  };

  const purge = (scope: "expired" | "all") => {
    if (
      scope === "all" &&
      typeof window !== "undefined" &&
      !window.confirm(
        "Clear the ENTIRE decision cache for this tenant? Every future match will be re-triaged by the LLM until the cache re-learns.",
      )
    )
      return;
    return runWrite(
      `__purge_${scope}`,
      async () => {
        await purgeDecisionCache(scope);
      },
      scope === "all" ? "Cache cleared." : "Expired entries purged.",
    );
  };

  return (
    <div className="flex flex-col gap-4">
      <PageHeading
        title="Decision Cache"
        sub="Stored triage verdicts DHRUVA reuses for recurring alerts — each reuse is one LLM call (and its cost) saved. A cached verdict is only ever reused for an alert carrying no new threat signal; disable, edit, or delete any entry and the next match goes back to the LLM."
      />

      {loading && entries.length === 0 ? (
        <StatusState variant="loading" title="Loading the decision cache…" />
      ) : error ? (
        <StatusState
          variant="error"
          title="Couldn't load the decision cache"
          description={error}
          action={
            <button type="button" onClick={load} className={cn(BTN_NEUTRAL, focusRing)}>
              Retry
            </button>
          }
        />
      ) : (
        <>
          {summary && <SummaryStrip summary={summary} />}

          {notice && (
            <div
              className={cn(
                "text-kbd",
                notice.ok ? "text-grounded-ink" : "text-sev-crit",
              )}
              role={notice.ok ? "status" : "alert"}
            >
              {notice.ok ? "✓ " : ""}
              {notice.msg}
            </div>
          )}

          {entries.length === 0 ? (
            <StatusState
              variant="empty"
              title="Nothing cached yet"
              description="The persistent decision cache is off or hasn't stored a verdict yet. When enabled (cost_controls.decision_cache in config), confident benign verdicts are stored here so recurring alerts reuse them instead of re-calling the LLM."
            />
          ) : (
            <Panel className="overflow-x-auto p-0">
              <Table>
                <THead>
                  <TR>
                    <TH>Match</TH>
                    <TH>Verdict</TH>
                    <TH>Source</TH>
                    <TH className="text-right">Reuses</TH>
                    <TH className="text-right">Tokens saved</TH>
                    <TH>Last reused</TH>
                    <TH>Expires</TH>
                    <TH>State</TH>
                    {canWrite && <TH className="text-right">Actions</TH>}
                  </TR>
                </THead>
                <TBody>
                  {entries.map((e) => {
                    const busy = busyId === e.id;
                    const isEditing = editing?.id === e.id;
                    return (
                      <TR key={e.id} className={e.enabled ? "" : "opacity-60"}>
                        <TD>
                          <div className="text-data text-ink">
                            {e.rule_id != null ? `Rule ${e.rule_id}` : "—"}
                            {e.rule_description ? ` · ${e.rule_description}` : ""}
                          </div>
                          {e.entity_summary && (
                            <div className="text-micro text-dim2">
                              {e.entity_summary}
                            </div>
                          )}
                        </TD>
                        <TD>
                          {isEditing ? (
                            <div className="flex items-center gap-1.5">
                              <select
                                value={editing.verdict}
                                onChange={(ev) =>
                                  setEditing({ id: e.id, verdict: ev.target.value })
                                }
                                className="rounded-md border border-line bg-field px-1.5 py-1 text-meta text-ink"
                              >
                                {EDITABLE_VERDICTS.map((v) => (
                                  <option key={v} value={v}>
                                    {v}
                                  </option>
                                ))}
                              </select>
                              <button
                                type="button"
                                disabled={busy}
                                onClick={() => saveVerdict(e, editing.verdict)}
                                className={cn(BTN_NEUTRAL, focusRing)}
                              >
                                Save
                              </button>
                              <button
                                type="button"
                                onClick={() => setEditing(null)}
                                className={cn(BTN_NEUTRAL, focusRing)}
                              >
                                Cancel
                              </button>
                            </div>
                          ) : (
                            <div className="flex flex-col">
                              <span className="text-data text-ink">{e.verdict}</span>
                              <span className="text-micro text-dim2">
                                {Math.round((e.confidence ?? 0) * 100)}% conf
                              </span>
                            </div>
                          )}
                        </TD>
                        <TD>
                          <SourceBadge source={e.source} />
                        </TD>
                        <TD className="text-right tabular-nums">
                          {fmtInt(e.hit_count)}
                        </TD>
                        <TD className="text-right tabular-nums">
                          {fmtInt(e.tokens_saved_est)}
                        </TD>
                        <TD className="text-meta text-dim">
                          {e.last_hit_at ? fmtDateTime(e.last_hit_at) : DASH}
                        </TD>
                        <TD className="text-meta text-dim">
                          {e.expires_at ? fmtDateTime(e.expires_at) : "never"}
                        </TD>
                        <TD>
                          {e.enabled ? (
                            <span className="text-micro text-grounded-ink">active</span>
                          ) : (
                            <span className="text-micro text-dim2">disabled</span>
                          )}
                        </TD>
                        {canWrite && (
                          <TD>
                            <div className="flex items-center justify-end gap-1.5">
                              <button
                                type="button"
                                disabled={busy}
                                onClick={() => toggleEnabled(e)}
                                className={cn(BTN_NEUTRAL, focusRing)}
                              >
                                {e.enabled ? "Disable" : "Enable"}
                              </button>
                              {!isEditing && (
                                <button
                                  type="button"
                                  disabled={busy}
                                  onClick={() =>
                                    setEditing({ id: e.id, verdict: e.verdict })
                                  }
                                  className={cn(BTN_NEUTRAL, focusRing)}
                                >
                                  Edit
                                </button>
                              )}
                              <button
                                type="button"
                                disabled={busy}
                                onClick={() => removeEntry(e)}
                                className={cn(BTN_DANGER, focusRing)}
                              >
                                Delete
                              </button>
                            </div>
                          </TD>
                        )}
                      </TR>
                    );
                  })}
                </TBody>
              </Table>
            </Panel>
          )}

          {canWrite && entries.length > 0 && (
            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={busyId === "__purge_expired"}
                onClick={() => purge("expired")}
                className={cn(BTN_NEUTRAL, focusRing)}
              >
                Purge expired
              </button>
              <button
                type="button"
                disabled={busyId === "__purge_all"}
                onClick={() => purge("all")}
                className={cn(BTN_DANGER, focusRing)}
              >
                Clear all
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function SummaryStrip({ summary }: { summary: DecisionCacheSummary }) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
      <Tile
        label="Cached verdicts"
        value={fmtInt(summary.total)}
        sub={`${fmtInt(summary.enabled)} active · ${fmtInt(summary.disabled)} disabled`}
      />
      <Tile
        label="Reuses"
        value={fmtInt(summary.total_hits)}
        sub="LLM calls averted"
        math="Each reuse is one triage that did not call the LLM (the verdict was served from this cache)."
      />
      <Tile
        label="Est. tokens saved"
        value={fmtInt(summary.tokens_saved)}
        sub="cumulative estimate"
        math="An estimate (reuses × per-call token estimate), for direction — real spend is metered on the Metrics/Reports LLM-usage panel."
      />
      <Tile
        label="Active entries"
        value={fmtInt(summary.enabled)}
        sub="eligible for reuse"
      />
    </div>
  );
}
