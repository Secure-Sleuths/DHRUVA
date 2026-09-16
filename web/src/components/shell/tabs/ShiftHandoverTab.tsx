"use client";
/**
 * ShiftHandoverTab — what is outstanding now, and what happened recently.
 *
 * Binds to `GET /api/admin/shifts/handoff-report` —
 * `require_role("admin", "senior_analyst")` + `require_license_feature("sla")`.
 *
 * DELIBERATELY NOT A ROSTER. The team rotates rather than working fixed shifts,
 * so the surface never asks "whose shift is it": the analyst picks their own
 * look-back window and reads what landed in it. That is why `hours` is a
 * control here rather than a config file — a roster would have to be
 * maintained, and a stale roster is worse than none.
 *
 * The lists are CAPPED server-side (`limit`), while the counts come from
 * separate COUNT(*) queries. So "showing 25 of 3,079" is honest in both halves:
 * the list is short, the backlog number is real. Never present the list length
 * as the backlog — the whole point of the cap is that they differ.
 *
 * States: loading / error+retry / locked (402/403 from the SLA gate) /
 * role-restricted. Read-only: this surface records nothing. Saving a handoff
 * note is a separate POST and is not wired here.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import {
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
  SeverityBadge,
} from "@/components";
import { PageHeading } from "../PageHeading";
import { ApiError, getHandoffReport } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { roleAtLeast } from "@/lib/rbac";
import { DASH, fmtInt } from "@/lib/format";
import { apiSeverity } from "@/lib/incident";
import type { TabProps } from "../tabRegistry";
import type { HandoffReport } from "@/lib/types";

/** Look-back choices. Rotating shifts are rarely longer than 12h; 24h covers
 *  "what did I miss since yesterday" after a day off. */
const WINDOWS = [4, 8, 12, 24] as const;

function ago(iso?: string | null): string {
  if (!iso) return DASH;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return DASH;
  const mins = Math.max(0, Math.round((Date.now() - t) / 60000));
  if (mins < 60) return `${mins}m`;
  const h = Math.round(mins / 60);
  return h < 48 ? `${h}h` : `${Math.round(h / 24)}d`;
}

export function ShiftHandoverTab({ onNavigate }: TabProps) {
  const { role } = useAuth();
  const allowed = roleAtLeast(role, "senior_analyst");

  const [hours, setHours] = useState<number>(8);
  const [data, setData] = useState<HandoffReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [locked, setLocked] = useState(false);
  const [secondsAgo, setSecondsAgo] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(
    async (h: number, isRefresh = false) => {
      abortRef.current?.abort();
      const ac = new AbortController();
      abortRef.current = ac;
      if (isRefresh) setRefreshing(true);
      else setLoading(true);
      try {
        const res = await getHandoffReport({ hours: h, limit: 25 }, ac.signal);
        if (ac.signal.aborted) return;
        setData(res);
        setError(null);
        setLocked(false);
        setSecondsAgo(0);
      } catch (e) {
        if (ac.signal.aborted) return;
        // 402/403 from the licence gate is a LOCKED surface, not an error —
        // showing a retry button for something the plan does not include just
        // invites the analyst to click it forever.
        if (e instanceof ApiError && (e.status === 402 || e.status === 403)) {
          setLocked(true);
          setError(null);
        } else {
          setError(e instanceof Error ? e.message : "Could not load the handover");
        }
      } finally {
        if (!ac.signal.aborted) {
          setLoading(false);
          setRefreshing(false);
        }
      }
    },
    [],
  );

  useEffect(() => {
    if (!allowed) return;
    void load(hours);
    return () => abortRef.current?.abort();
  }, [allowed, hours, load]);

  useEffect(() => {
    const t = setInterval(() => setSecondsAgo((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, [data]);

  if (!allowed) {
    return (
      <StatusState
        variant="empty"
        title="Not available for your role"
        description="The shift handover is limited to senior analysts and admins."
      />
    );
  }
  if (locked) {
    return (
      <FeatureLockedState feature="Shift handover" tier="Enterprise" />
    );
  }
  if (loading && !data) {
    return <StatusState variant="loading" title="Building the handover…" />;
  }
  if (error && !data) {
    return (
      <StatusState
        variant="error"
        title="Could not load the handover"
        description={error}
        action={
          <button
            type="button"
            onClick={() => void load(hours)}
            className="rounded border border-line px-2 py-1 text-micro text-fg hover:bg-panel"
          >
            Try again
          </button>
        }
      />
    );
  }
  if (!data) return null;

  const verdicts = data.recent_verdict_summary ?? {};
  const verdictTotal = Object.values(verdicts).reduce((a, b) => a + (b || 0), 0);
  const incidents = data.open_incidents ?? [];
  const soar = data.pending_soar_approvals ?? [];

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <PageHeading
          title="Shift handover"
          sub="What is outstanding, and what happened in your window"
        />
        <PollingStatus
          secondsAgo={secondsAgo}
          polling={false}
          refreshing={refreshing}
          onRefresh={() => void load(hours, true)}
        />
      </div>

      <div
        className="flex flex-wrap items-center gap-1.5"
        role="group"
        aria-label="Look-back window"
      >
        <span className="text-micro uppercase tracking-wide text-dim2">
          Window
        </span>
        {WINDOWS.map((h) => (
          <button
            key={h}
            type="button"
            onClick={() => setHours(h)}
            aria-pressed={hours === h}
            aria-label={`Last ${h} hours${hours === h ? " (selected)" : ""}`}
            className={
              "rounded border px-2 py-0.5 text-micro " +
              (hours === h
                ? "border-accent bg-accent/10 text-fg"
                : "border-line text-dim2 hover:text-fg")
            }
          >
            {h}h
          </button>
        ))}
        <span className="ml-1 text-micro text-dim2">
          you pick your own — the team rotates
        </span>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Tile
          label="Open incidents"
          value={fmtInt(data.open_incident_count)}
          sub={`${fmtInt(data.critical_count)} critical`}
          valueSeverity={data.critical_count > 0 ? "crit" : undefined}
        />
        <Tile
          label="Waiting on approval"
          value={fmtInt(data.pending_soar_count ?? soar.length)}
          sub="SOAR actions"
        />
        <Tile
          label="SLA breaches"
          value={fmtInt((data.recent_sla_breaches ?? []).length)}
          sub="last 24h"
        />
        <Tile
          label={`Decisions in ${data.window_hours ?? hours}h`}
          value={fmtInt(verdictTotal)}
          sub={
            Object.entries(verdicts)
              .map(([k, v]) => `${k.replace(/_/g, " ")} ${v}`)
              .join(" · ") || "none"
          }
        />
      </div>

      <Panel>
        <div className="mb-2 flex items-center justify-between">
          <h3 className="text-sm font-medium text-fg">Open incidents</h3>
          {data.open_incidents_truncated ? (
            <span className="text-micro text-dim2">
              showing {incidents.length} of {fmtInt(data.open_incident_count)} —
              worst first
            </span>
          ) : null}
        </div>
        {incidents.length === 0 ? (
          <StatusState variant="empty" title="Nothing open" />
        ) : (
          <Table>
            <THead>
              <TR>
                <TH className="w-20">Severity</TH>
                <TH>Title</TH>
                <TH className="w-16">Alerts</TH>
                <TH className="w-20">Assigned</TH>
                <TH className="w-14">Age</TH>
              </TR>
            </THead>
            <TBody>
              {incidents.map((inc) => (
                <TR
                  key={inc.id}
                  onClick={
                    onNavigate ? () => onNavigate("incidents", inc.id) : undefined
                  }
                  className={onNavigate ? "cursor-pointer" : undefined}
                >
                  <TD>
                    <SeverityBadge severity={apiSeverity(inc.severity)} />
                  </TD>
                  <TD className="truncate">{inc.title}</TD>
                  <TD>{fmtInt(inc.alert_count)}</TD>
                  <TD className={inc.assigned_to ? undefined : "text-dim2"}>
                    {inc.assigned_to || "unassigned"}
                  </TD>
                  <TD className="text-dim2">{ago(inc.created_at)}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Panel>

      {soar.length > 0 ? (
        <Panel>
          <div className="mb-2 flex items-center justify-between">
            <h3 className="text-sm font-medium text-fg">
              Waiting for a human decision
            </h3>
            {data.pending_soar_truncated ? (
              <span className="text-micro text-dim2">
                showing {soar.length} of {fmtInt(data.pending_soar_count)}
              </span>
            ) : null}
          </div>
          <Table>
            <THead>
              <TR>
                <TH>Playbook</TH>
                <TH className="w-40">Incident</TH>
                <TH className="w-14">Age</TH>
              </TR>
            </THead>
            <TBody>
              {soar.map((s) => (
                <TR key={s.id}>
                  <TD>{s.playbook}</TD>
                  <TD className="truncate text-dim2">{s.incident_id ?? DASH}</TD>
                  <TD className="text-dim2">{ago(s.created_at)}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </Panel>
      ) : null}
    </div>
  );
}
