/**
 * WO-H25 — alert-level claim: client-side RBAC mirror.
 *
 * Proves `rbac.ts::triageClaimGate` matches the server gate on
 * `POST /api/triage/decisions/{id}/claim|unclaim` (src/api/routes/triage.py):
 *   - analyst+ may claim; read_only (and unknown roles) get nothing (fail-closed).
 *   - self-claim, UNOWNED-only: owned-by-another locks the claim for EVERY
 *     role — admin included (the server 409s; the owner releases).
 *   - re-claim own → still claimable (idempotent), and unclaim is owner-only.
 *   - unknown self (no JWT `sub`) → no claim control (fail toward no control).
 */
import { describe, expect, it } from "vitest";
import { triageClaimGate } from "../rbac";
import type { Role } from "../types";

describe("WO-H25 triageClaimGate — role gate (fail-closed)", () => {
  it("analyst can claim an unclaimed decision", () => {
    const g = triageClaimGate("analyst", null, "alice");
    expect(g.canClaim).toBe(true);
    expect(g.canUnclaim).toBe(false);
    expect(g.ownedByOther).toBe(false);
  });

  it("senior_analyst / admin / mssp_admin can claim an unclaimed decision", () => {
    for (const r of ["senior_analyst", "admin", "mssp_admin"] as Role[]) {
      expect(triageClaimGate(r, null, "alice").canClaim).toBe(true);
    }
  });

  it("read_only gets neither verb, with a lock note", () => {
    const g = triageClaimGate("read_only", null, "ro");
    expect(g.canClaim).toBe(false);
    expect(g.canUnclaim).toBe(false);
    expect(g.lockNote).toMatch(/analyst or higher/i);
  });

  it("an UNKNOWN role fails closed (gets nothing)", () => {
    const g = triageClaimGate("intern" as Role, null, "alice");
    expect(g.canClaim).toBe(false);
    expect(g.canUnclaim).toBe(false);
  });
});

describe("WO-H25 triageClaimGate — ownership (self-claim, unowned-only)", () => {
  it("already owned by ANOTHER user → claim locked, with the owner named", () => {
    const g = triageClaimGate("analyst", "bob", "alice");
    expect(g.canClaim).toBe(false);
    expect(g.canUnclaim).toBe(false);
    expect(g.ownedByOther).toBe(true);
    expect(g.lockNote).toContain("bob");
  });

  it("owned-by-other locks the claim even for admin (no take-over)", () => {
    for (const r of ["senior_analyst", "admin", "mssp_admin"] as Role[]) {
      const g = triageClaimGate(r, "bob", "root");
      expect(g.canClaim).toBe(false);
      expect(g.ownedByOther).toBe(true);
    }
  });

  it("owned by SELF → re-claim stays allowed (idempotent) and unclaim opens", () => {
    const g = triageClaimGate("analyst", "alice", "alice");
    expect(g.canClaim).toBe(true);
    expect(g.canUnclaim).toBe(true);
    expect(g.ownedBySelf).toBe(true);
    expect(g.ownedByOther).toBe(false);
  });

  it("empty-string owner is treated as unclaimed", () => {
    const g = triageClaimGate("analyst", "", "alice");
    expect(g.canClaim).toBe(true);
    expect(g.ownedByOther).toBe(false);
  });

  it("absent claimed_by (older backend) is treated as unclaimed — never a crash", () => {
    const g = triageClaimGate("analyst", undefined, "alice");
    expect(g.canClaim).toBe(true);
  });

  it("unknown self (no JWT sub) → no claim control, fail toward nothing", () => {
    const g = triageClaimGate("analyst", null, null);
    expect(g.canClaim).toBe(false);
    expect(g.canUnclaim).toBe(false);
    expect(g.lockNote).toBeTruthy();
  });

  it("unknown self on a claimed decision still reports ownedByOther", () => {
    const g = triageClaimGate("analyst", "bob", null);
    expect(g.canClaim).toBe(false);
    expect(g.ownedByOther).toBe(true);
  });
});
