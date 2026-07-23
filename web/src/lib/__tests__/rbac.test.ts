/**
 * WO-H24 — L1 as operator: client-side RBAC mirror.
 *
 * Proves the `rbac.ts` mirror matches the widened server gates:
 *   - escalate  → analyst+ (was senior+); read_only still hidden.
 *   - assign    → analyst+ visible, but ASYMMETRIC via `incidentAssignGate`:
 *                 senior+ assign-anyone, analyst self-claim only, read_only none.
 *   - active response (`responseActionGate`) UNCHANGED — analyst still cannot
 *     approve/reverse (regression guard: WO-H24 didn't leak into containment).
 */
import { describe, expect, it } from "vitest";
import {
  incidentActionGate,
  incidentAssignGate,
  responseActionGate,
} from "../rbac";
import type { Role } from "../types";

const ROLES: Role[] = [
  "read_only",
  "analyst",
  "senior_analyst",
  "admin",
  "mssp_admin",
];

describe("WO-H24 escalate — opened to analyst", () => {
  it("analyst can escalate (visible + canSubmit)", () => {
    const g = incidentActionGate("analyst", "escalate", null);
    expect(g.visible).toBe(true);
    expect(g.canSubmit).toBe(true);
  });

  it("escalate has NO ownership block for a non-owner analyst", () => {
    // escalate is not an OWNERSHIP_ACTION → isOwner=false must NOT block.
    const g = incidentActionGate("analyst", "escalate", false);
    expect(g.visible).toBe(true);
    expect(g.canSubmit).toBe(true);
  });

  it("read_only cannot escalate (hidden)", () => {
    const g = incidentActionGate("read_only", "escalate", null);
    expect(g.visible).toBe(false);
    expect(g.canSubmit).toBe(false);
  });

  it("senior_analyst+ still escalate", () => {
    for (const r of ["senior_analyst", "admin", "mssp_admin"] as Role[]) {
      expect(incidentActionGate(r, "escalate", null).canSubmit).toBe(true);
    }
  });
});

describe("WO-H24 assign — self-claim asymmetry", () => {
  it("analyst may self-claim but NOT assign anyone", () => {
    const g = incidentAssignGate("analyst");
    expect(g.canSelfClaim).toBe(true);
    expect(g.canAssignAnyone).toBe(false);
    expect(g.selfOnlyNote).toBeTruthy();
  });

  it("senior_analyst+ may assign anyone (no self-only note)", () => {
    for (const r of ["senior_analyst", "admin", "mssp_admin"] as Role[]) {
      const g = incidentAssignGate(r);
      expect(g.canAssignAnyone).toBe(true);
      expect(g.canSelfClaim).toBe(true);
      expect(g.selfOnlyNote).toBeUndefined();
    }
  });

  it("read_only gets neither (fail closed)", () => {
    const g = incidentAssignGate("read_only");
    expect(g.canSelfClaim).toBe(false);
    expect(g.canAssignAnyone).toBe(false);
  });

  it("assign section is visible to analyst+ but hidden from read_only", () => {
    expect(incidentActionGate("analyst", "assign", null).visible).toBe(true);
    expect(incidentActionGate("read_only", "assign", null).visible).toBe(false);
  });
});

describe("WO-H24 regression — active response NOT loosened", () => {
  it("analyst still cannot approve/reverse containment", () => {
    const g = responseActionGate("analyst");
    expect(g.canApprove).toBe(false);
    expect(g.canReverse).toBe(false);
    expect(g.lockNote).toBeTruthy();
  });

  it("read_only still cannot approve/reverse", () => {
    const g = responseActionGate("read_only");
    expect(g.canApprove).toBe(false);
    expect(g.canReverse).toBe(false);
  });

  it("senior_analyst+ keep containment approve/reverse", () => {
    for (const r of ["senior_analyst", "admin", "mssp_admin"] as Role[]) {
      const g = responseActionGate(r);
      expect(g.canApprove).toBe(true);
      expect(g.canReverse).toBe(true);
    }
  });
});

describe("merge/review stay senior+ (unchanged by WO-H24)", () => {
  it("analyst cannot merge or review", () => {
    for (const action of ["merge", "review"] as const) {
      expect(incidentActionGate("analyst", action, null).visible).toBe(false);
    }
  });

  it.each(ROLES)("fail-closed: no crash for role %s", (role) => {
    expect(() => incidentAssignGate(role)).not.toThrow();
  });
});
