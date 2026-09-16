/**
 * WO-H85 — the alert case must show WHO reviewed before you, and WHAT they
 * said, BEFORE you can override them.
 *
 * Overriding used to be a bare overwrite: the previous reviewer's name and
 * reasoning were destroyed. The server now keeps an append-only history; these
 * tests prove the case view renders it, renders the current `review_reason`,
 * and puts the history AHEAD of the verdict form in the document — the whole
 * point is that it is readable before the decision, not after it.
 *
 * The API module is mocked (render contract, not network). `useAuth` is a plain
 * analyst — READING the history has no role gate, and nothing here changes who
 * may write.
 */
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DecisionReview, IncidentAlert } from "@/lib/types";

vi.mock("@/lib/auth", () => ({
  useAuth: () => ({ role: "analyst", roleIsPreview: false }),
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
  getRuleStats: vi.fn(),
  submitTriageReview: vi.fn(),
  lookupIoc: vi.fn(),
  getDecisionRawAlert: vi.fn(),
  getDecisionPlaybook: vi.fn(),
  getDecisionReviews: vi.fn(),
}));

import { getDecisionReviews } from "@/lib/api";
import { GlassBoxAlertCard } from "../GlassBoxCase";

const mockedReviews = vi.mocked(getDecisionReviews);

afterEach(cleanup);
beforeEach(() => vi.clearAllMocks());

function review(over: Partial<DecisionReview> = {}): DecisionReview {
  return {
    id: `rev-${Math.random()}`,
    decision_id: "dec-1",
    reviewer: "analyst-two",
    human_verdict: "false_positive",
    reason: "48 checksum changes inside a three-second window",
    previous_verdict: null,
    source: "human_review",
    created_at: "2026-08-13T10:00:00Z",
    ...over,
  };
}

function alert(over: Partial<IncidentAlert> = {}): IncidentAlert {
  return {
    id: "dec-1",
    rule_id: 5710,
    rule_description: "sshd: authentication success",
    verdict: "true_positive",
    confidence: 0.9,
    risk_score: 60,
    reasoning: "seeded",
    enrichment_summary: JSON.stringify({}),
    ...over,
  } as IncidentAlert;
}

describe("WO-H85 review history on the alert case", () => {
  it("renders an attached history without a second request", async () => {
    render(
      <GlassBoxAlertCard
        alert={alert({
          review_history: [
            review({ reviewer: "analyst-two" }),
            review({
              reviewer: "analyst-three",
              human_verdict: "true_positive",
              previous_verdict: "false_positive",
              reason: "the same window also carried an outbound beacon",
            }),
          ],
        })}
        primary
        onReviewed={() => {}}
      />,
    );

    expect(screen.getByText("analyst-two")).toBeTruthy();
    expect(screen.getByText("analyst-three")).toBeTruthy();
    expect(
      screen.getByText(/48 checksum changes inside a three-second window/),
    ).toBeTruthy();
    expect(screen.getByText(/outbound beacon/)).toBeTruthy();
    // The incident case batches the history server-side — never re-fetch it.
    expect(mockedReviews).not.toHaveBeenCalled();
  });

  it("keeps BOTH reviewers, in order, when a second override happened", () => {
    render(
      <GlassBoxAlertCard
        alert={alert({
          review_history: [
            review({ reviewer: "analyst-two", reason: "first reasoning" }),
            review({
              reviewer: "analyst-three",
              reason: "second reasoning",
              previous_verdict: "false_positive",
              human_verdict: "true_positive",
            }),
          ],
        })}
        primary
        onReviewed={() => {}}
      />,
    );

    const body = document.body.textContent ?? "";
    expect(body.indexOf("first reasoning")).toBeGreaterThan(-1);
    expect(body.indexOf("second reasoning")).toBeGreaterThan(
      body.indexOf("first reasoning"),
    );
    // and the disagreement is stated, not merely implied
    expect(screen.getByText(/changed from/)).toBeTruthy();
  });

  it("puts the history BEFORE the override form in the document", () => {
    render(
      <GlassBoxAlertCard
        alert={alert({ review_history: [review({ reviewer: "analyst-two" })] })}
        primary
        onReviewed={() => {}}
      />,
    );

    const body = document.body.textContent ?? "";
    const historyAt = body.indexOf("Review history");
    const formAt = body.indexOf("Reason *required");
    expect(historyAt).toBeGreaterThan(-1);
    expect(formAt).toBeGreaterThan(-1);
    expect(historyAt).toBeLessThan(formAt);
  });

  it("warns that someone already reviewed the alert", () => {
    render(
      <GlassBoxAlertCard
        alert={alert({ review_history: [review({ reviewer: "analyst-three" })] })}
        primary
        onReviewed={() => {}}
      />,
    );
    expect(
      screen.getByText(/analyst-three already reviewed this alert/),
    ).toBeTruthy();
  });

  it("flags an inherited (incident-propagated) label as not alert-by-alert", () => {
    render(
      <GlassBoxAlertCard
        alert={alert({
          review_history: [
            review({ source: "incident_verdict_propagation" }),
          ],
        })}
        primary
        onReviewed={() => {}}
      />,
    );
    expect(screen.getByText(/not judged alert-by-alert/)).toBeTruthy();
  });

  it("renders the CURRENT review_reason on the panel", () => {
    render(
      <GlassBoxAlertCard
        alert={alert({
          review_reason: "known-good backup job, benign",
          review_history: [],
        })}
        primary
        onReviewed={() => {}}
      />,
    );
    expect(screen.getByText("known-good backup job, benign")).toBeTruthy();
  });

  it("fetches the history by id when the caller attached none (triage case)", async () => {
    mockedReviews.mockResolvedValue({
      decision_id: "dec-1",
      reviews: [review({ reviewer: "analyst-three", reason: "fetched reasoning" })],
      count: 1,
    });

    render(<GlassBoxAlertCard alert={alert()} primary onReviewed={() => {}} />);

    await waitFor(() => expect(mockedReviews).toHaveBeenCalledTimes(1));
    expect(mockedReviews.mock.calls[0][0]).toBe("dec-1");
    await waitFor(() =>
      expect(screen.getByText(/fetched reasoning/)).toBeTruthy(),
    );
  });

  it("says so honestly when nobody has reviewed the alert", async () => {
    render(
      <GlassBoxAlertCard
        alert={alert({ review_history: [] })}
        primary
        onReviewed={() => {}}
      />,
    );
    expect(
      screen.getByText(/No previous human review recorded/),
    ).toBeTruthy();
  });

  it("does not silently claim 'no reviews' when the fetch fails", async () => {
    mockedReviews.mockRejectedValue(new Error("network down"));

    render(<GlassBoxAlertCard alert={alert()} primary onReviewed={() => {}} />);

    await waitFor(() =>
      expect(
        screen.getByText(/Couldn't load the review history/),
      ).toBeTruthy(),
    );
    expect(screen.queryByText(/No previous human review recorded/)).toBeNull();
  });
});
