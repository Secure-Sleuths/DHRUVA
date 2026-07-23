/**
 * WO-H25 — DecisionClaim component tests: the claim affordance renders
 * "claimed by X" / "Unclaimed" honestly, offers Claim only when the server
 * would accept it (analyst+, unowned or own), locks it with the owner named
 * when a colleague holds the claim, and fires the body-less claim/unclaim
 * API calls. The API module and useAuth are mocked (render contract test,
 * not a network test) — useAuth is re-mockable per test via `mockAuth`.
 */
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Role } from "@/lib/types";

const mockAuth = vi.hoisted(() => ({
  role: "analyst" as Role,
  claims: { sub: "alice" } as { sub?: string } | null,
}));

vi.mock("@/lib/auth", () => ({
  useAuth: () => ({
    role: mockAuth.role,
    claims: mockAuth.claims,
    roleIsPreview: false,
  }),
}));

const claimDecision = vi.hoisted(() =>
  vi.fn(async (id: string) => ({
    status: "ok",
    decision_id: id,
    claimed_by: "alice",
  })),
);
const unclaimDecision = vi.hoisted(() =>
  vi.fn(async (id: string) => ({
    status: "ok",
    decision_id: id,
    claimed_by: null,
  })),
);

vi.mock("@/lib/api", () => ({
  ApiError: class ApiError extends Error {
    status: number;
    constructor(status: number, message: string) {
      super(message);
      this.status = status;
    }
  },
  claimDecision,
  unclaimDecision,
}));

import { DecisionClaim, claimedLabel } from "../DecisionClaim";

afterEach(cleanup);
beforeEach(() => {
  mockAuth.role = "analyst";
  mockAuth.claims = { sub: "alice" };
  claimDecision.mockClear();
  unclaimDecision.mockClear();
});

describe("claimedLabel", () => {
  it("names the owner when claimed and says Unclaimed otherwise", () => {
    expect(claimedLabel("bob")).toBe("Claimed by bob");
    expect(claimedLabel(null)).toBe("Unclaimed");
    expect(claimedLabel(undefined)).toBe("Unclaimed");
  });
});

describe("WO-H25 DecisionClaim", () => {
  it("unclaimed + analyst → shows Unclaimed and an enabled Claim button", () => {
    render(
      <DecisionClaim decisionId="dec-1" claimedBy={null} onChanged={() => {}} />,
    );
    expect(screen.getByText("Unclaimed")).toBeDefined();
    const btn = screen.getByRole("button", { name: "Claim" });
    expect((btn as HTMLButtonElement).disabled).toBe(false);
  });

  it("clicking Claim fires the body-less claim call and refetches", async () => {
    const onChanged = vi.fn();
    render(
      <DecisionClaim decisionId="dec-1" claimedBy={null} onChanged={onChanged} />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Claim" }));
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
    expect(claimDecision).toHaveBeenCalledWith("dec-1");
  });

  it("claimed by a COLLEAGUE → no Claim button, owner named in the lock note", () => {
    render(
      <DecisionClaim decisionId="dec-1" claimedBy="bob" onChanged={() => {}} />,
    );
    expect(screen.queryByRole("button", { name: "Claim" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Release claim" })).toBeNull();
    expect(screen.getByText("Claimed by bob")).toBeDefined();
    expect(screen.getByText(/only they can release it/i)).toBeDefined();
  });

  it("claimed by SELF → 'Claimed by you' + a Release control, no Claim button", () => {
    render(
      <DecisionClaim decisionId="dec-1" claimedBy="alice" onChanged={() => {}} />,
    );
    expect(screen.getByText("you")).toBeDefined();
    expect(screen.queryByRole("button", { name: "Claim" })).toBeNull();
    const release = screen.getByRole("button", { name: "Release claim" });
    fireEvent.click(release);
    expect(unclaimDecision).toHaveBeenCalledWith("dec-1");
  });

  it("read_only → no claim/release controls at all (fail-closed)", () => {
    mockAuth.role = "read_only";
    mockAuth.claims = { sub: "ro" };
    render(
      <DecisionClaim decisionId="dec-1" claimedBy={null} onChanged={() => {}} />,
    );
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("unknown self (no sub claim) → no Claim button offered", () => {
    mockAuth.claims = null;
    render(
      <DecisionClaim decisionId="dec-1" claimedBy={null} onChanged={() => {}} />,
    );
    expect(screen.queryByRole("button", { name: "Claim" })).toBeNull();
  });

  it("a failed claim surfaces a typed error, never a crash", async () => {
    claimDecision.mockRejectedValueOnce(
      new Error("Decision is already claimed by another analyst"),
    );
    render(
      <DecisionClaim decisionId="dec-1" claimedBy={null} onChanged={() => {}} />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Claim" }));
    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toMatch(/already claimed/i),
    );
  });
});
