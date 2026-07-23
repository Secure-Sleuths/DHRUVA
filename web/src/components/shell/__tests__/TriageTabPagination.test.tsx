/**
 * WO-H33 — TriageTab pagination render contract:
 *   - a first page with `has_more` shows the "Load more" pager;
 *   - clicking it fetches the NEXT window (server-echoed offset) and APPENDS
 *     (deduped) instead of replacing the analyst's working set;
 *   - `has_more: false` (and older servers that omit it) shows no pager.
 * The API module is mocked — this is a render/wiring test, not a network test.
 */
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { TriageDecision, TriageDecisionsResponse } from "@/lib/types";

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
  getTriageDecisionsFiltered: vi.fn(),
  getTriageDecision: vi.fn(),
  getPendingReview: vi.fn(),
  getDecisionAuditTrail: vi.fn(),
  // Pulled in transitively by GlassBoxCase / DecisionClaim.
  getRuleStats: vi.fn(),
  submitTriageReview: vi.fn(),
  lookupIoc: vi.fn(),
  getDecisionRawAlert: vi.fn(),
  getDecisionPlaybook: vi.fn(),
  claimDecision: vi.fn(),
  unclaimDecision: vi.fn(),
}));

import { getTriageDecisionsFiltered } from "@/lib/api";
import { TriageTab } from "../tabs/TriageTab";

const mockedList = vi.mocked(getTriageDecisionsFiltered);

function decision(id: string, risk: number): TriageDecision {
  return {
    id,
    rule_id: 5710,
    rule_description: `rule for ${id}`,
    verdict: "true_positive",
    confidence: 0.9,
    risk_score: risk,
    created_at: "2026-07-11T00:00:00Z",
    host: null,
    src_ip: null,
    technique_ids: [],
    tactic_ids: [],
  } as unknown as TriageDecision;
}

function page(
  ids: string[],
  opts: { offset: number; limit: number; hasMore: boolean },
): TriageDecisionsResponse {
  return {
    decisions: ids.map((id, i) => decision(id, 95 - opts.offset - i)),
    total: ids.length,
    offset: opts.offset,
    limit: opts.limit,
    has_more: opts.hasMore,
  };
}

afterEach(cleanup);
beforeEach(() => vi.clearAllMocks());

describe("WO-H33 TriageTab pager", () => {
  it("shows the pager when the server reports more rows", async () => {
    mockedList.mockResolvedValue(
      page(["d1", "d2"], { offset: 0, limit: 200, hasMore: true }),
    );
    render(<TriageTab tabId="triage" navParam={undefined} />);
    await screen.findByText("rule for d1");
    expect(screen.getByText("Load more")).toBeTruthy();
  });

  it("hides the pager when has_more is false or absent (older server)", async () => {
    mockedList.mockResolvedValue({
      decisions: [decision("d1", 95)],
      total: 1,
    });
    render(<TriageTab tabId="triage" navParam={undefined} />);
    await screen.findByText("rule for d1");
    expect(screen.queryByText("Load more")).toBeNull();
  });

  it("Load more fetches the next offset and appends (deduped)", async () => {
    mockedList.mockResolvedValueOnce(
      page(["d1", "d2"], { offset: 0, limit: 2, hasMore: true }),
    );
    // Next window: d2 slid down into page 2 (live queue shifted) — it must
    // not render twice.
    mockedList.mockResolvedValueOnce(
      page(["d2", "d3"], { offset: 2, limit: 2, hasMore: false }),
    );
    render(<TriageTab tabId="triage" navParam={undefined} />);
    await screen.findByText("rule for d1");

    fireEvent.click(screen.getByText("Load more"));
    await screen.findByText("rule for d3");

    // Second call paged from the server-echoed next offset (0 + limit 2).
    const secondCall = mockedList.mock.calls[1][0];
    expect(secondCall?.offset).toBe(2);
    // Appended, not replaced; d2 deduped.
    expect(screen.getByText("rule for d1")).toBeTruthy();
    expect(screen.getAllByText("rule for d2")).toHaveLength(1);
    // The final window has no further page → pager gone.
    await waitFor(() => expect(screen.queryByText("Load more")).toBeNull());
  });
});
