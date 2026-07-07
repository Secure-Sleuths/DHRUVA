/**
 * Tickets FIXTURE — screenshot / dev-preview only (WO-U9b).
 *
 * Reached solely from `api.ts::getTickets` / `getTicketStats` when
 * `NEXT_PUBLIC_DHRUVA_FIXTURES` is set, via dynamic import so it is
 * dead-code-eliminated from a normal production bundle. The real path calls the
 * live `GET /api/tickets`; this only lets the UI states be captured without a
 * backend.
 *
 * Fabricates NO capability — it mirrors the `tickets` row shape exactly
 * (`store.py::get_tickets`): `platform_status` (DHRUVA's sync view) vs
 * `external_status` (the provider's), priority, provider, linked incident_id,
 * external_url. `locked: true` (env `NEXT_PUBLIC_DHRUVA_FIXTURES=locked`) THROWS
 * an ApiError(403) shaped like the real `require_license_feature("ticketing")` gate.
 */

import { ApiError } from "../api";
import type { Ticket, TicketsResponse, TicketStats } from "../types";

interface Opts {
  empty?: boolean;
  locked?: boolean;
}

function lockedError(): never {
  throw new ApiError(
    403,
    "Ticketing is not available on this plan. Contact SecureSleuths to upgrade.",
  );
}

const TICKETS: Ticket[] = [
  {
    id: "tkt-1001",
    incident_id: "inc-4790",
    provider: "jira",
    external_id: "SOC-2214",
    external_url: "https://acme.atlassian.net/browse/SOC-2214",
    external_status: "In Progress",
    platform_status: "synced",
    summary: "Ransomware detonation on FIN-WKS-11 — host isolated",
    description: null,
    priority: "critical",
    assigned_to_external: "ir-team",
    sync_direction: "outbound",
    last_synced_at: "2026-07-02T04:30:00Z",
    sync_error: null,
    retry_count: 0,
    created_by: "s.okafor",
    created_at: "2026-07-01T22:20:00Z",
    updated_at: "2026-07-02T04:30:00Z",
  },
  {
    id: "tkt-1002",
    incident_id: "inc-4821",
    provider: "jira",
    external_id: "SOC-2219",
    external_url: "https://acme.atlassian.net/browse/SOC-2219",
    external_status: "Open",
    platform_status: "created",
    summary: "SSH brute-force from 203.0.113.44 — block proposed",
    description: null,
    priority: "high",
    assigned_to_external: null,
    sync_direction: "outbound",
    last_synced_at: "2026-07-02T05:50:00Z",
    sync_error: null,
    retry_count: 0,
    created_by: "j.rivera",
    created_at: "2026-07-02T05:49:00Z",
    updated_at: "2026-07-02T05:50:00Z",
  },
  {
    id: "tkt-1003",
    incident_id: "inc-4771",
    provider: "servicenow",
    external_id: null,
    external_url: null,
    external_status: null,
    platform_status: "error",
    summary: "Suspicious login from new geography — awaiting analyst review",
    description: null,
    priority: "medium",
    assigned_to_external: null,
    sync_direction: "outbound",
    last_synced_at: "2026-07-01T12:05:00Z",
    sync_error: "ServiceNow 401: integration token expired",
    retry_count: 3,
    created_by: "a.mehra",
    created_at: "2026-07-01T12:00:00Z",
    updated_at: "2026-07-01T12:05:00Z",
  },
  {
    id: "tkt-1004",
    incident_id: "inc-4702",
    provider: "jira",
    external_id: "SOC-2190",
    external_url: "https://acme.atlassian.net/browse/SOC-2190",
    external_status: "Done",
    platform_status: "closed",
    summary: "False-positive VPN alert cluster — rule tuning tracked",
    description: null,
    priority: "low",
    assigned_to_external: "soc-l2",
    sync_direction: "outbound",
    last_synced_at: "2026-06-28T16:00:00Z",
    sync_error: null,
    retry_count: 0,
    created_by: "s.okafor",
    created_at: "2026-06-27T09:00:00Z",
    updated_at: "2026-06-28T16:00:00Z",
  },
];

export function ticketsFixture(opts: Opts): TicketsResponse {
  if (opts.locked) lockedError();
  if (opts.empty) return { tickets: [], total: 0 };
  return { tickets: TICKETS, total: TICKETS.length };
}

export function ticketStatsFixture(opts: Opts): TicketStats {
  if (opts.locked) lockedError();
  if (opts.empty) {
    return { total: 0, synced: 0, pending: 0, errors: 0, closed: 0, by_provider: {} };
  }
  return {
    total: 4,
    synced: 2,
    pending: 0,
    errors: 1,
    closed: 1,
    by_provider: { jira: 3, servicenow: 1 },
  };
}
