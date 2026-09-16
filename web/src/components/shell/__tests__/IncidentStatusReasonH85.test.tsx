/**
 * WO-H85 — `status_reason` must reach the analyst.
 *
 * `grep -rn "status_reason" web/src/` used to return nothing: every closure
 * reason written on the platform (6,400+ on one tenant, each carrying a specific
 * finding) existed only in the database. The analyst who wrote one could not
 * read it back and the next shift could not see why anything was closed.
 *
 * This renders the Incidents case view straight from a deep-linked id and
 * asserts the reason is on screen, and that a case without one degrades quietly
 * rather than showing an empty box.
 */
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { IncidentDetail } from "@/lib/types";

vi.mock("@/lib/auth", () => ({
  useAuth: () => ({
    role: "analyst",
    roleIsPreview: false,
    claims: { sub: "analyst-two" },
    tier: null,
  }),
}));

vi.mock("@/lib/api", () => ({
  ApiError: class ApiError extends Error {
    status: number;
    constructor(status: number, message: string) {
      super(message);
      this.name = "ApiError";
      this.status = status;
    }
  },
  getIncident: vi.fn(),
  getIncidents: vi.fn(async () => ({ incidents: [], total: 0 })),
  getIncidentSla: vi.fn(),
  getSlaAtRisk: vi.fn(async () => ({ at_risk: [] })),
  getTicketsForIncident: vi.fn(async () => ({ tickets: [] })),
  // pulled in transitively by GlassBoxCase / IncidentActions
  getRuleStats: vi.fn(),
  submitTriageReview: vi.fn(),
  lookupIoc: vi.fn(),
  getDecisionRawAlert: vi.fn(),
  getDecisionPlaybook: vi.fn(),
  getDecisionReviews: vi.fn(async (id: string) => ({
    decision_id: id,
    reviews: [],
    count: 0,
  })),
  addIncidentEvidence: vi.fn(),
  addIncidentNote: vi.fn(),
  assignIncident: vi.fn(),
  changeIncidentStatus: vi.fn(),
  escalateIncident: vi.fn(),
  flagIncidentInteresting: vi.fn(),
  mergeIncidents: vi.fn(),
  propagateIncidentVerdict: vi.fn(),
  saveIncidentReview: vi.fn(),
}));

import { getIncident } from "@/lib/api";
import { IncidentsTab } from "../tabs/IncidentsTab";

const mockedGetIncident = vi.mocked(getIncident);

afterEach(cleanup);
beforeEach(() => vi.clearAllMocks());

function detail(over: Partial<IncidentDetail> = {}): IncidentDetail {
  return {
    id: "inc-1",
    title: "Attack chain on vpn-gw-01",
    severity: "high",
    status: "closed",
    first_seen: "2026-08-14T09:00:00Z",
    last_seen: "2026-08-14T09:30:00Z",
    alert_count: 1,
    assigned_to: "analyst-two",
    affected_hosts: "[]",
    mitre_tactics: "[]",
    alerts: [],
    timeline: [],
    ...over,
  } as IncidentDetail;
}

describe("WO-H85 status_reason on the incident case view", () => {
  it("renders the reason the incident is in its current state", async () => {
    mockedGetIncident.mockResolvedValue(
      detail({
        status_reason:
          "48 checksum changes inside a three-second window, the signature of package management",
      }),
    );

    render(<IncidentsTab tabId="incidents" navParam="inc-1" />);

    await waitFor(() =>
      expect(
        screen.getByText(
          /48 checksum changes inside a three-second window, the signature of package management/,
        ),
      ).toBeTruthy(),
    );
    expect(screen.getByText(/Why it is closed/i)).toBeTruthy();
  });

  it("shows nothing rather than an empty box when no reason was recorded", async () => {
    mockedGetIncident.mockResolvedValue(detail({ status_reason: null }));

    render(<IncidentsTab tabId="incidents" navParam="inc-1" />);

    await waitFor(() => expect(mockedGetIncident).toHaveBeenCalled());
    await waitFor(() =>
      expect(screen.getByText(/Attack chain on/)).toBeTruthy(),
    );
    expect(screen.queryByText(/Why it is/i)).toBeNull();
  });
});
