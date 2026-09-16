/**
 * WO-H85 — the incident-level verdict propagation control.
 *
 * The rule this encodes: closing an incident is a WORK-ITEM state change and
 * cascades; putting a verdict on every alert the incident grouped is a separate,
 * far bigger claim and must be deliberate. So the control is opt-in with the
 * confirmation OFF by default, states the exact alert count it would touch,
 * warns when the members do not already agree with each other, and never
 * reports success when the server refused every member.
 *
 * The API module is mocked (render/wiring contract, not a network test).
 */
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { IncidentDetail } from "@/lib/types";

let mockRole = "admin";
vi.mock("@/lib/auth", () => ({
  useAuth: () => ({
    role: mockRole,
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

import { propagateIncidentVerdict } from "@/lib/api";
import { IncidentActions } from "../IncidentActions";

const mockedPropagate = vi.mocked(propagateIncidentVerdict);

afterEach(cleanup);
beforeEach(() => {
  mockRole = "admin";
  vi.clearAllMocks();
});

function detail(over: Partial<IncidentDetail> = {}): IncidentDetail {
  return {
    id: "inc-1",
    title: "Attack chain on vpn-gw-01",
    severity: "high",
    status: "open",
    first_seen: "2026-08-14T09:00:00Z",
    alert_count: 3,
    assigned_to: "analyst-two",
    alerts: [],
    timeline: [],
    verdict_propagation: {
      total: 3,
      eligible: 2,
      protected: 1,
      distinct_verdicts: ["false_positive", "true_positive"],
      agree: false,
    },
    ...over,
  } as IncidentDetail;
}

/** The whole rendered rail as one whitespace-normalised string — the copy under
 *  test is split across <b> spans, which `getByText` cannot match across. */
function bodyText(): string {
  return (document.body.textContent ?? "").replace(/\s+/g, " ");
}

/** Open the (collapsed) propagation section and return its submit button. */
function openPanel() {
  fireEvent.click(screen.getByText("Apply a verdict to member alerts"));
  return screen.getByRole("button", { name: /Apply to \d+ unreviewed alert/ });
}

describe("WO-H85 verdict propagation control", () => {
  it("is a SEPARATE section from the status change", () => {
    render(<IncidentActions detail={detail()} onChanged={() => {}} />);
    // "Change status" appears as both the section title and its submit button.
    expect(screen.getAllByText("Change status").length).toBeGreaterThan(0);
    expect(screen.getByText("Apply a verdict to member alerts")).toBeTruthy();
  });

  it("states the alert count it would touch and what it will refuse", () => {
    render(<IncidentActions detail={detail()} onChanged={() => {}} />);
    openPanel();
    expect(bodyText()).toContain("This incident groups");
    expect(bodyText()).toContain("will not be overwritten");
    expect(
      screen.getByRole("button", { name: "Apply to 2 unreviewed alerts" }),
    ).toBeTruthy();
  });

  it("warns when the member alerts do not already agree", () => {
    render(<IncidentActions detail={detail()} onChanged={() => {}} />);
    openPanel();
    expect(bodyText()).toContain("do not currently agree with each other");
    expect(bodyText()).toContain("false_positive, true_positive");
  });

  it("does not warn when the members already agree", () => {
    render(
      <IncidentActions
        detail={detail({
          verdict_propagation: {
            total: 2,
            eligible: 2,
            protected: 0,
            distinct_verdicts: ["false_positive"],
            agree: true,
          },
        })}
        onChanged={() => {}}
      />,
    );
    openPanel();
    expect(bodyText()).not.toContain("do not currently agree");
  });

  it("defaults the confirmation OFF and keeps submit disabled", () => {
    render(<IncidentActions detail={detail()} onChanged={() => {}} />);
    const submit = openPanel();

    const confirm = screen.getByRole("checkbox") as HTMLInputElement;
    expect(confirm.checked).toBe(false);
    expect((submit as HTMLButtonElement).disabled).toBe(true);

    // even a full verdict + reason is not enough without the explicit opt-in
    fireEvent.click(screen.getByRole("radio", { name: "False positive" }));
    fireEvent.change(screen.getByPlaceholderText(/Recorded on every alert/), {
      target: { value: "package management window" },
    });
    expect((submit as HTMLButtonElement).disabled).toBe(true);
    expect(mockedPropagate).not.toHaveBeenCalled();
  });

  it("sends confirm:true only after the analyst opts in", async () => {
    mockedPropagate.mockResolvedValue({
      status: "ok",
      incident_id: "inc-1",
      total: 3,
      applied: 2,
      skipped: 1,
      applied_ids: ["a", "b"],
      skipped_ids: ["c"],
    });

    render(<IncidentActions detail={detail()} onChanged={() => {}} />);
    const submit = openPanel();
    fireEvent.click(screen.getByRole("radio", { name: "False positive" }));
    fireEvent.change(screen.getByPlaceholderText(/Recorded on every alert/), {
      target: { value: "package management window" },
    });
    fireEvent.click(screen.getByRole("checkbox"));
    expect((submit as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(submit);

    await waitFor(() => expect(mockedPropagate).toHaveBeenCalledTimes(1));
    expect(mockedPropagate.mock.calls[0][1]).toEqual({
      human_verdict: "false_positive",
      reason: "package management window",
      confirm: true,
    });
    // the outcome is reported with the REFUSALS, not a bare "saved"
    await waitFor(() =>
      expect(screen.getByText(/2 alert\(s\) labelled/)).toBeTruthy(),
    );
    expect(screen.getByText(/1 left unchanged/)).toBeTruthy();
  });

  it("resets the opt-in to OFF after a successful apply", async () => {
    mockedPropagate.mockResolvedValue({
      status: "ok",
      incident_id: "inc-1",
      total: 2,
      applied: 2,
      skipped: 0,
      applied_ids: ["a", "b"],
      skipped_ids: [],
    });

    render(<IncidentActions detail={detail()} onChanged={() => {}} />);
    const submit = openPanel();
    fireEvent.click(screen.getByRole("radio", { name: "False positive" }));
    fireEvent.change(screen.getByPlaceholderText(/Recorded on every alert/), {
      target: { value: "noise" },
    });
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(submit);

    await waitFor(() => expect(mockedPropagate).toHaveBeenCalled());
    await waitFor(() =>
      expect(
        (screen.getByRole("checkbox") as HTMLInputElement).checked,
      ).toBe(false),
    );
  });

  it("reports 'nothing applied' as a FAILURE, not a green tick", async () => {
    mockedPropagate.mockResolvedValue({
      status: "ok",
      incident_id: "inc-1",
      total: 2,
      applied: 0,
      skipped: 2,
      applied_ids: [],
      skipped_ids: ["a", "b"],
    });

    render(<IncidentActions detail={detail()} onChanged={() => {}} />);
    const submit = openPanel();
    fireEvent.click(screen.getByRole("radio", { name: "False positive" }));
    fireEvent.change(screen.getByPlaceholderText(/Recorded on every alert/), {
      target: { value: "noise" },
    });
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(submit);

    await waitFor(() =>
      expect(screen.getByText(/Nothing was applied/)).toBeTruthy(),
    );
    expect(screen.getByText(/never overwritten/)).toBeTruthy();
  });

  it("offers nothing to apply when every member is already judged", () => {
    render(
      <IncidentActions
        detail={detail({
          verdict_propagation: {
            total: 2,
            eligible: 0,
            protected: 2,
            distinct_verdicts: ["false_positive"],
            agree: true,
          },
        })}
        onChanged={() => {}}
      />,
    );
    fireEvent.click(screen.getByText("Apply a verdict to member alerts"));
    expect(
      (
        screen.getByRole("button", {
          name: /Apply to 0 unreviewed alerts/,
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(screen.getByText(/Nothing to apply/)).toBeTruthy();
  });

  it("tells the analyst that closing cascades work-item state, not verdicts", () => {
    render(<IncidentActions detail={detail()} onChanged={() => {}} />);
    // the status section is open by default
    expect(bodyText()).toContain("stamps resolved_at on its member alerts");
    expect(bodyText()).toContain("It records no verdict on them");
  });

  it("does NOT claim closing empties the review queue (it does not)", () => {
    // The pending queue is `escalated = 1 AND human_verdict = ''` and the
    // dashboard stat is `human_verdict IS NULL AND escalated = 1`. Neither
    // reads `resolved_at`, so closing an incident changes nothing an analyst
    // sees. The copy used to say the opposite.
    render(<IncidentActions detail={detail()} onChanged={() => {}} />);
    const body = bodyText();
    expect(body).not.toContain("leave the unreviewed queue");
    expect(body).toContain(
      "escalated and still awaiting a human verdict are left open",
    );
    expect(body).toContain(
      "does not by itself change the pending-review count",
    );
  });

  it("hides the control from read_only (server rejects the write)", () => {
    mockRole = "read_only";
    render(<IncidentActions detail={detail()} onChanged={() => {}} />);
    expect(screen.queryByText("Apply a verdict to member alerts")).toBeNull();
  });

  it("shows it disabled for an analyst who does not own the incident", () => {
    mockRole = "analyst";
    render(
      <IncidentActions
        detail={detail({ assigned_to: "someone-else" })}
        onChanged={() => {}}
      />,
    );
    fireEvent.click(screen.getByText("Apply a verdict to member alerts"));
    const submit = screen.getByRole("button", {
      name: /Apply to 2 unreviewed alerts/,
    }) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
  });
});
