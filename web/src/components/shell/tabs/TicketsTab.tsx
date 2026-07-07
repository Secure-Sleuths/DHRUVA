"use client";

/**
 * TicketsTab — ticket list synced to external trackers, with the three
 * endpoint-backed WRITES wired (RBAC mirrored, server-enforced):
 *
 * Reads:
 *   - `GET /api/tickets` (`getTickets`) + `GET /api/tickets/stats`
 *     (`getTicketStats`) — `verify_jwt` + `require_license_feature("ticketing")`,
 *     visible to all roles per the shell ACL.
 *
 * Writes (this WO — each mirrors `src/api/routes/tickets.py` + lib/rbac
 * `ticketActionGate`, and is confirm/form-gated; the server re-checks and stays
 * the enforcement point):
 *   - CREATE `POST /api/tickets` (analyst+; read_only has no write path) — a form
 *     with a REQUIRED incident_id, optional provider (jira|servicenow|pagerduty)
 *     and summary. No reason.
 *   - FORCE-SYNC `POST /api/tickets/{id}/sync` (senior_analyst+) — refresh a
 *     ticket's status from the tracker.
 *   - RETRY `POST /api/tickets/{id}/retry` (senior_analyst+) — re-push a FAILED
 *     (error-state) ticket. Offered ONLY on error rows (the server 400s
 *     otherwise), behind an explicit confirm.
 *
 * There is NO ticket status/assignee/comment WRITE on this server — those flow
 * INBOUND from the tracker via the HMAC webhook; DHRUVA never pushes them. That
 * is surfaced honestly in the note, not faked client-side.
 *
 * Controls below a role's server gate are HIDDEN (read_only sees no New-ticket
 * button; analyst sees no sync/retry) so the UI never offers a write the server
 * rejects. TIER GATE: a runtime 402/403 from the `ticketing` gate degrades the
 * whole surface to FeatureLockedState. States: loading / empty / error+retry /
 * locked; per-action submitting + typed error (402/403 → locked, 400/404 →
 * "changed, refreshing"); PollingStatus (30s, aborts on unmount). Fixtures gate
 * behind NEXT_PUBLIC_DHRUVA_FIXTURES (writes short-circuit to synthetic success,
 * NO real mutation).
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Chip,
  Dialog,
  Panel,
  PollingStatus,
  SeverityBadge,
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
  createTicket,
  getTicketStats,
  getTickets,
  retryTicket,
  syncTicket,
} from "@/lib/api";
import { ticketActionGate, type TicketActionGate } from "@/lib/rbac";
import { useAuth } from "@/lib/auth";
import { ticketPrioritySeverity, ticketStatusPresentation } from "@/lib/tickets";
import { cn, focusRing } from "@/lib/ui";
import { DASH, fmtDateTime, fmtInt } from "@/lib/format";
import type { TabProps } from "../tabRegistry";
import type { Ticket, TicketStats } from "@/lib/types";

const POLL_MS = 30_000;
const PROVIDERS = ["", "jira", "servicenow", "pagerduty"] as const;

function isLockError(e: unknown): boolean {
  return e instanceof ApiError && (e.status === 402 || e.status === 403);
}
function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : "Unknown error";
}

interface State {
  tickets: Ticket[] | null;
  stats: TicketStats | null;
  error: string | null;
  locked: boolean;
  loading: boolean;
}

type Flash = { tone: "ok" | "warn"; msg: string };
/** A pending row action awaiting confirm. */
type RowAction = { kind: "sync" | "retry"; row: Ticket };

export function TicketsTab(_props: TabProps) {
  const { role } = useAuth();
  const gate = ticketActionGate(role);

  const [state, setState] = useState<State>({
    tickets: null,
    stats: null,
    error: null,
    locked: false,
    loading: true,
  });
  const [secondsAgo, setSecondsAgo] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  // ---- write state --------------------------------------------------------
  const [createOpen, setCreateOpen] = useState(false);
  const [rowAction, setRowAction] = useState<RowAction | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [flash, setFlash] = useState<Flash | null>(null);

  const load = useCallback(async (manual: boolean) => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    if (manual) setRefreshing(true);
    try {
      const [tickets, stats] = await Promise.all([
        getTickets({ limit: 100 }, ac.signal),
        getTicketStats(ac.signal),
      ]);
      if (ac.signal.aborted) return;
      setState({
        tickets: tickets.tickets,
        stats,
        error: null,
        locked: false,
        loading: false,
      });
      setSecondsAgo(0);
    } catch (e) {
      if (ac.signal.aborted) return;
      if (isLockError(e)) {
        setState({
          tickets: null,
          stats: null,
          error: null,
          locked: true,
          loading: false,
        });
        return;
      }
      const msg = errMessage(e);
      setState((prev) =>
        prev.tickets
          ? { ...prev, loading: false }
          : {
              tickets: null,
              stats: null,
              error: msg,
              locked: false,
              loading: false,
            },
      );
    } finally {
      if (!ac.signal.aborted) setRefreshing(false);
    }
  }, []);

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

  const onUpgrade = useCallback(() => {
    if (typeof window !== "undefined") {
      window.open("https://securesleuths.in/pricing", "_blank", "noreferrer");
    }
  }, []);

  // ---- create -------------------------------------------------------------
  const submitCreate = useCallback(
    async (body: { incident_id: string; provider?: string; summary?: string }) => {
      setSubmitting(true);
      setActionError(null);
      try {
        const res = await createTicket(body);
        setFlash({
          tone: "ok",
          msg: `Ticket created for incident ${body.incident_id}${
            res.external_id ? ` — ${res.external_id}` : ""
          }. It will sync on the next cycle.`,
        });
        setCreateOpen(false);
        await load(true);
      } catch (e) {
        if (isLockError(e)) {
          setActionError(
            "Your role or license tier does not permit creating a ticket — the server denied it. Nothing changed.",
          );
        } else if (e instanceof ApiError && e.status === 503) {
          setActionError(
            "Ticketing integration is disabled on the server, so no ticket can be created. Nothing changed.",
          );
        } else {
          setActionError(errMessage(e));
        }
      } finally {
        setSubmitting(false);
      }
    },
    [load],
  );

  // ---- sync / retry -------------------------------------------------------
  const submitRowAction = useCallback(async () => {
    if (!rowAction) return;
    const { kind, row } = rowAction;
    setSubmitting(true);
    setActionError(null);
    try {
      if (kind === "sync") {
        await syncTicket(row.id);
        setFlash({
          tone: "ok",
          msg: `Re-sync requested for ${row.external_id ?? "the ticket"} — its status will refresh.`,
        });
      } else {
        const res = await retryTicket(row.id);
        setFlash({
          tone: "ok",
          msg: `Retried the push for incident ${row.incident_id}${
            res.external_id ? ` — ${res.external_id}` : ""
          }.`,
        });
      }
      setRowAction(null);
      await load(true);
    } catch (e) {
      if (isLockError(e)) {
        setActionError(
          "Your role or license tier does not permit this action — the server denied it (this control mirrors the server). Nothing changed.",
        );
      } else if (
        e instanceof ApiError &&
        (e.status === 400 || e.status === 404)
      ) {
        setActionError(
          "This ticket changed since you loaded it — it may no longer be in a failed state, or was removed. Refreshing the list.",
        );
        setRowAction(null);
        await load(true);
      } else if (e instanceof ApiError && e.status === 502) {
        setActionError(
          "The tracker rejected the push (a sync error is recorded on the ticket). Nothing else changed.",
        );
        await load(true);
      } else {
        setActionError(errMessage(e));
      }
    } finally {
      setSubmitting(false);
    }
  }, [rowAction, load]);

  const { tickets, stats, error, locked, loading } = state;

  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PageHeading
          title="Tickets"
          sub="Incidents pushed to your external tracker, with the sync status DHRUVA sees — and the actions you can take on them."
        />
        <div className="mt-1 flex items-center gap-2">
          {!locked && gate.canCreate && tickets && (
            <button
              type="button"
              onClick={() => {
                setActionError(null);
                setCreateOpen(true);
              }}
              className={cn(
                "cursor-pointer rounded-md border border-grounded-border bg-grounded-border/40 px-2.5 py-1 text-meta text-grounded-ink hover:brightness-125",
                focusRing,
              )}
            >
              New ticket…
            </button>
          )}
          {!locked && (
            <PollingStatus
              secondsAgo={secondsAgo}
              refreshing={refreshing}
              onRefresh={() => load(true)}
            />
          )}
        </div>
      </div>

      {locked ? (
        <FeatureLockedState
          feature="Ticketing"
          tier="current"
          onUpgrade={onUpgrade}
        />
      ) : loading && !tickets ? (
        <StatusState variant="loading" title="Loading tickets…" />
      ) : error && !tickets ? (
        <StatusState
          variant="error"
          title="Couldn't load tickets"
          description={error}
          action={<Chip onClick={() => load(true)}>Retry</Chip>}
        />
      ) : tickets ? (
        <div className="flex flex-col gap-3">
          <ActionNote gate={gate} />
          {flash && <FlashBanner flash={flash} onDismiss={() => setFlash(null)} />}
          {stats && <StatsTiles stats={stats} />}
          <TicketsPanel
            tickets={tickets}
            gate={gate}
            onSync={(row) => {
              setActionError(null);
              setRowAction({ kind: "sync", row });
            }}
            onRetry={(row) => {
              setActionError(null);
              setRowAction({ kind: "retry", row });
            }}
          />
        </div>
      ) : null}

      <CreateTicketDialog
        open={createOpen}
        submitting={submitting}
        error={actionError}
        onSubmit={submitCreate}
        onClose={() => {
          if (submitting) return;
          setCreateOpen(false);
          setActionError(null);
        }}
      />

      <RowActionDialog
        pending={rowAction}
        submitting={submitting}
        error={actionError}
        onConfirm={submitRowAction}
        onClose={() => {
          if (submitting) return;
          setRowAction(null);
          setActionError(null);
        }}
      />
    </>
  );
}

function ActionNote({ gate }: { gate: TicketActionGate }) {
  return (
    <div className="rounded-lg border border-line bg-panel2 px-3.5 py-2.5 text-kbd text-dim2">
      Creating a ticket is an analyst+ action; forcing a re-sync or retrying a
      failed push is senior_analyst+ — the server enforces both, and controls you
      can&apos;t use are hidden. Ticket <b>status and assignee are read-only
      here</b>: they flow in from your tracker (via its webhook), DHRUVA never
      pushes them back — so there is no status/assignee/comment control by design.
      {gate.createLockNote && (
        <span className="mt-1 block text-dim2">{gate.createLockNote}</span>
      )}
    </div>
  );
}

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

function StatsTiles({ stats }: { stats: TicketStats }) {
  const providers = Object.entries(stats.by_provider ?? {});
  return (
    <div className="flex flex-col gap-2">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
        <Tile label="Tickets" value={fmtInt(stats.total)} sub="total" />
        <Tile label="Synced" value={fmtInt(stats.synced)} sub="created / synced" />
        <Tile label="Pending" value={fmtInt(stats.pending)} sub="awaiting sync" />
        <Tile
          label="Errors"
          value={fmtInt(stats.errors)}
          sub="failed to sync"
          valueSeverity={stats.errors > 0 ? "high" : undefined}
        />
        <Tile label="Closed" value={fmtInt(stats.closed)} sub="resolved" />
      </div>
      {providers.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-kbd uppercase tracking-wider text-dim2">
            By provider
          </span>
          {providers.map(([prov, count]) => (
            <Chip key={prov} mono>
              {prov} · {fmtInt(count)}
            </Chip>
          ))}
        </div>
      )}
    </div>
  );
}

function TicketsPanel({
  tickets,
  gate,
  onSync,
  onRetry,
}: {
  tickets: Ticket[];
  gate: TicketActionGate;
  onSync: (row: Ticket) => void;
  onRetry: (row: Ticket) => void;
}) {
  const showActions = gate.canSync; // senior_analyst+ (sync/retry share the gate)
  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-3">
        <div className="text-title text-ink">Tickets</div>
        <span className="text-kbd text-dim2">{tickets.length} shown</span>
      </div>
      {tickets.length === 0 ? (
        <div className="px-4 pb-4 pt-2 text-data text-dim2">
          No tickets have been created for this tenant yet.
        </div>
      ) : (
        <Table className="mt-2">
          <THead>
            <TR>
              <TH>Ticket</TH>
              <TH>Priority</TH>
              <TH>Provider</TH>
              <TH>Sync status</TH>
              <TH>Assignee</TH>
              <TH>Created</TH>
              {showActions && <TH>Actions</TH>}
            </TR>
          </THead>
          <TBody>
            {tickets.map((t) => {
              const st = ticketStatusPresentation(t.platform_status);
              const sev = ticketPrioritySeverity(t.priority);
              const isError = t.platform_status === "error";
              return (
                <TR key={t.id}>
                  <TD>
                    <div className="text-ink">{t.summary}</div>
                    <div className="flex flex-wrap items-center gap-2 text-kbd text-dim2">
                      {t.external_id && t.external_url ? (
                        <a
                          href={t.external_url}
                          target="_blank"
                          rel="noreferrer"
                          className="font-mono text-cite-ink hover:underline"
                        >
                          {t.external_id}
                        </a>
                      ) : t.external_id ? (
                        <span className="font-mono">{t.external_id}</span>
                      ) : (
                        <span>not yet created externally</span>
                      )}
                      {t.incident_id && (
                        <span className="font-mono">
                          incident {t.incident_id}
                        </span>
                      )}
                    </div>
                  </TD>
                  <TD>
                    {sev ? (
                      <SeverityBadge severity={sev} label={t.priority ?? undefined} />
                    ) : (
                      <span className="text-dim2">{t.priority || DASH}</span>
                    )}
                  </TD>
                  <TD mono>{t.provider}</TD>
                  <TD>
                    <div className={`text-meta font-semibold ${st.className}`}>
                      {st.label}
                    </div>
                    {t.external_status && (
                      <div className="text-kbd text-dim2">
                        provider: {t.external_status}
                      </div>
                    )}
                    {isError && t.sync_error && (
                      <div className="max-w-[320px] text-kbd text-sev-crit">
                        {t.sync_error}
                      </div>
                    )}
                  </TD>
                  <TD>
                    {t.assigned_to_external ? (
                      <span className="text-dim">{t.assigned_to_external}</span>
                    ) : (
                      <span className="text-dim2">{DASH}</span>
                    )}
                  </TD>
                  <TD>{fmtDateTime(t.created_at)}</TD>
                  {showActions && (
                    <TD>
                      <div className="flex flex-wrap items-center gap-1.5">
                        {isError ? (
                          <ActionButton
                            label="Retry…"
                            tone="warn"
                            onClick={() => onRetry(t)}
                          />
                        ) : (
                          <ActionButton
                            label="Sync…"
                            tone="neutral"
                            onClick={() => onSync(t)}
                          />
                        )}
                      </div>
                    </TD>
                  )}
                </TR>
              );
            })}
          </TBody>
        </Table>
      )}
    </Panel>
  );
}

function ActionButton({
  label,
  tone,
  onClick,
}: {
  label: string;
  tone: "neutral" | "warn";
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "cursor-pointer rounded-md border px-2.5 py-1 text-meta hover:brightness-125",
        focusRing,
        tone === "warn"
          ? "border-gated-border bg-field text-gated-ink"
          : "border-line bg-field text-ink",
      )}
    >
      {label}
    </button>
  );
}

function CreateTicketDialog({
  open,
  submitting,
  error,
  onSubmit,
  onClose,
}: {
  open: boolean;
  submitting: boolean;
  error: string | null;
  onSubmit: (b: { incident_id: string; provider?: string; summary?: string }) => void;
  onClose: () => void;
}) {
  const [incidentId, setIncidentId] = useState("");
  const [provider, setProvider] = useState<string>("");
  const [summary, setSummary] = useState("");

  // reset the form whenever the dialog is (re)opened
  useEffect(() => {
    if (open) {
      setIncidentId("");
      setProvider("");
      setSummary("");
    }
  }, [open]);

  if (!open) return null;
  const canSubmit = incidentId.trim().length > 0 && !submitting;

  return (
    <Dialog open onClose={onClose} maxWidth={540} title="Create a ticket">
      <p className="text-data text-dim">
        Push an incident to your external tracker. The incident id is required;
        the provider and summary are optional (the server generates a summary from
        the incident when you leave it blank).
      </p>

      <div className="mt-3 flex flex-col gap-3">
        <label className="flex flex-col gap-1 text-data">
          <span className="text-dim2">
            Incident id <span className="text-sev-crit">*</span>
          </span>
          <input
            type="text"
            value={incidentId}
            onChange={(e) => setIncidentId(e.target.value)}
            placeholder="inc-4821"
            className={cn(
              "rounded-md border border-line bg-field px-2.5 py-1.5 font-mono text-ink placeholder:text-dim2",
              focusRing,
            )}
          />
        </label>

        <label className="flex flex-col gap-1 text-data">
          <span className="text-dim2">Provider</span>
          <select
            value={provider}
            onChange={(e) => setProvider(e.target.value)}
            className={cn(
              "rounded-md border border-line bg-field px-2.5 py-1.5 text-ink",
              focusRing,
            )}
          >
            {PROVIDERS.map((p) => (
              <option key={p || "default"} value={p}>
                {p === "" ? "Default provider" : p}
              </option>
            ))}
          </select>
        </label>

        <label className="flex flex-col gap-1 text-data">
          <span className="text-dim2">Summary (optional)</span>
          <textarea
            value={summary}
            onChange={(e) => setSummary(e.target.value)}
            rows={2}
            placeholder="Leave blank to auto-generate from the incident"
            className={cn(
              "rounded-md border border-line bg-field px-2.5 py-1.5 text-ink placeholder:text-dim2",
              focusRing,
            )}
          />
        </label>
      </div>

      {error && (
        <p className="mt-3 text-data text-sev-crit" role="alert">
          {error}
        </p>
      )}

      <div className="mt-4 flex items-center gap-2">
        <button
          type="button"
          disabled={!canSubmit}
          onClick={() =>
            onSubmit({
              incident_id: incidentId.trim(),
              provider: provider || undefined,
              summary: summary.trim() || undefined,
            })
          }
          className={cn(
            "rounded-md border px-3 py-1.5 text-data",
            focusRing,
            canSubmit
              ? "cursor-pointer border-grounded-border bg-grounded-border/40 text-grounded-ink hover:brightness-125"
              : "cursor-not-allowed border-line bg-field text-dim opacity-60",
          )}
        >
          {submitting ? "Creating…" : "Create ticket"}
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

function RowActionDialog({
  pending,
  submitting,
  error,
  onConfirm,
  onClose,
}: {
  pending: RowAction | null;
  submitting: boolean;
  error: string | null;
  onConfirm: () => void;
  onClose: () => void;
}) {
  if (!pending) return null;
  const { kind, row } = pending;
  const retry = kind === "retry";
  return (
    <Dialog
      open
      onClose={onClose}
      maxWidth={520}
      title={retry ? "Retry failed ticket push" : "Force re-sync"}
    >
      <p className="text-data text-dim">
        {retry ? (
          <>
            This <b>re-pushes</b> the failed ticket below to its provider. It is a
            senior_analyst+ action; nothing happens until you confirm.
          </>
        ) : (
          <>
            This <b>refreshes</b> the ticket&apos;s status from the provider. It
            changes only what DHRUVA has synced; nothing runs until you confirm.
          </>
        )}
      </p>

      <dl className="mt-3 grid grid-cols-[7rem_1fr] gap-x-3 gap-y-1.5 rounded-lg border border-line bg-panel2 px-3.5 py-3 text-data">
        <dt className="text-dim2">Ticket</dt>
        <dd className="text-ink">{row.summary}</dd>
        <dt className="text-dim2">External id</dt>
        <dd className="font-mono text-ink">{row.external_id ?? DASH}</dd>
        <dt className="text-dim2">Provider</dt>
        <dd className="font-mono text-ink">{row.provider}</dd>
        <dt className="text-dim2">Incident</dt>
        <dd className="font-mono text-ink">{row.incident_id}</dd>
        {retry && row.sync_error && (
          <>
            <dt className="text-dim2">Last error</dt>
            <dd className="text-sev-crit">{row.sync_error}</dd>
          </>
        )}
      </dl>

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
          {submitting
            ? retry
              ? "Retrying…"
              : "Syncing…"
            : retry
              ? "Retry now"
              : "Sync now"}
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
