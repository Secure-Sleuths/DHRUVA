/**
 * WO-H85 — RBAC for the incident verdict-propagation control MUST NOT widen
 * anything.
 *
 * The DoD is explicit: "who may override is not widened by any of this." Two
 * separate claims are checked here:
 *
 *  1. `propagate_verdict` is gated EXACTLY like `status` — analyst+ and, for a
 *     plain analyst, only on an incident assigned to them. It is a distinct
 *     `IncidentAction` purely so the control can render as its own section.
 *  2. `triageReviewGate` — the WO-B10 rule that OVERRIDING an existing human
 *     verdict is admin-only — is untouched. Propagation can never override
 *     (the server refuses any member that already carries a human verdict), so
 *     nothing here gives an analyst a new way to change a colleague's verdict.
 */
import { describe, expect, it } from "vitest";
import { incidentActionGate, triageReviewGate } from "@/lib/rbac";
import type { Role } from "@/lib/types";

const ROLES: Role[] = ["read_only", "analyst", "senior_analyst", "admin"];
const OWNERSHIP: Array<boolean | null> = [true, false, null];

describe("WO-H85 propagate_verdict gate mirrors the status gate exactly", () => {
  for (const role of ROLES) {
    for (const isOwner of OWNERSHIP) {
      it(`${role} / owner=${String(isOwner)} matches "status"`, () => {
        const status = incidentActionGate(role, "status", isOwner);
        const propagate = incidentActionGate(role, "propagate_verdict", isOwner);
        expect(propagate.visible).toBe(status.visible);
        expect(propagate.canSubmit).toBe(status.canSubmit);
        expect(propagate.reason).toBe(status.reason);
      });
    }
  }

  it("hides the control from read_only entirely", () => {
    const gate = incidentActionGate("read_only", "propagate_verdict", true);
    expect(gate.visible).toBe(false);
    expect(gate.canSubmit).toBe(false);
  });

  it("blocks a non-assignee analyst (server `_check_incident_access`)", () => {
    const gate = incidentActionGate("analyst", "propagate_verdict", false);
    expect(gate.visible).toBe(true); // shown, so the reason can be explained
    expect(gate.canSubmit).toBe(false);
    expect(gate.reason).toBe("ownership");
  });

  it("lets senior_analyst+ act regardless of assignment", () => {
    for (const role of ["senior_analyst", "admin"] as Role[]) {
      expect(
        incidentActionGate(role, "propagate_verdict", false).canSubmit,
      ).toBe(true);
    }
  });
});

describe("WO-H85 does not widen the WO-B10 override rule", () => {
  it("overriding an EXISTING human verdict is still admin-only", () => {
    expect(triageReviewGate("analyst", true).canSubmit).toBe(false);
    expect(triageReviewGate("analyst", true).mode).toBe("override-denied");
    expect(triageReviewGate("senior_analyst", true).canSubmit).toBe(false);
    expect(triageReviewGate("admin", true).canSubmit).toBe(true);
  });

  it("setting the FIRST human verdict is still analyst+", () => {
    expect(triageReviewGate("read_only", false).canSubmit).toBe(false);
    expect(triageReviewGate("analyst", false).canSubmit).toBe(true);
    expect(triageReviewGate("analyst", false).mode).toBe("first");
  });
});
