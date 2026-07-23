/**
 * WO-H30 — mode-aware detection deploy/rollback authority: client-side mirror.
 *
 * Proves `detectionActionGate` matches the server's `require_deploy_authority()`:
 *   - single-tenant → admin+ may deploy/rollback (admin, mssp_admin true).
 *   - multi-tenant  → mssp_admin ONLY (admin false — proves multi-tenant is NOT
 *                     loosened; a widened gate would fail this).
 *   - unknown/absent mode → FAIL CLOSED to multi-tenant (admin false).
 *   - review/test gates are mode-INVARIANT (regression guard).
 *   - senior_analyst and below NEVER deploy in either mode.
 */
import { describe, expect, it } from "vitest";
import { detectionActionGate } from "../rbac";
import type { Role } from "../types";

describe("WO-H30 deploy authority — single-tenant", () => {
  it("admin CAN deploy and rollback", () => {
    const g = detectionActionGate("admin", "single_tenant");
    expect(g.canDeploy).toBe(true);
    expect(g.canRollback).toBe(true);
    expect(g.deployLockNote).toBeUndefined();
  });

  it("mssp_admin CAN deploy and rollback (superuser, both modes)", () => {
    const g = detectionActionGate("mssp_admin", "single_tenant");
    expect(g.canDeploy).toBe(true);
    expect(g.canRollback).toBe(true);
  });

  it("senior_analyst / analyst / read_only CANNOT deploy", () => {
    for (const role of ["senior_analyst", "analyst", "read_only"] as Role[]) {
      const g = detectionActionGate(role, "single_tenant");
      expect(g.canDeploy).toBe(false);
      expect(g.canRollback).toBe(false);
      expect(g.deployLockNote).toBeTruthy();
    }
  });
});

describe("WO-H30 deploy authority — multi-tenant (NOT loosened)", () => {
  it("admin CANNOT deploy or rollback (still mssp_admin-only)", () => {
    const g = detectionActionGate("admin", "multi_tenant");
    expect(g.canDeploy).toBe(false);
    expect(g.canRollback).toBe(false);
    expect(g.deployLockNote).toBeTruthy();
  });

  it("mssp_admin CAN deploy and rollback", () => {
    const g = detectionActionGate("mssp_admin", "multi_tenant");
    expect(g.canDeploy).toBe(true);
    expect(g.canRollback).toBe(true);
  });

  it("senior_analyst and below CANNOT deploy", () => {
    for (const role of ["senior_analyst", "analyst", "read_only"] as Role[]) {
      const g = detectionActionGate(role, "multi_tenant");
      expect(g.canDeploy).toBe(false);
    }
  });
});

describe("WO-H30 deploy authority — fail closed on unknown mode", () => {
  it("admin CANNOT deploy when mode is undefined (→ multi-tenant)", () => {
    expect(detectionActionGate("admin").canDeploy).toBe(false);
    expect(detectionActionGate("admin", undefined).canDeploy).toBe(false);
    expect(detectionActionGate("admin", null).canDeploy).toBe(false);
  });

  it("admin CANNOT deploy on any non-'single_tenant' string", () => {
    expect(detectionActionGate("admin", "").canDeploy).toBe(false);
    expect(detectionActionGate("admin", "unknown").canDeploy).toBe(false);
    expect(detectionActionGate("admin", "SINGLE_TENANT").canDeploy).toBe(false);
  });

  it("mssp_admin still deploys under unknown mode (superuser)", () => {
    expect(detectionActionGate("mssp_admin").canDeploy).toBe(true);
  });
});

describe("WO-H30 review/test gates are mode-invariant (regression)", () => {
  it("canReview / canTest identical across both modes", () => {
    for (const role of [
      "read_only",
      "analyst",
      "senior_analyst",
      "admin",
      "mssp_admin",
    ] as Role[]) {
      const single = detectionActionGate(role, "single_tenant");
      const multi = detectionActionGate(role, "multi_tenant");
      expect(single.canReview).toBe(multi.canReview);
      expect(single.canTest).toBe(multi.canTest);
    }
  });

  it("review is senior_analyst+, test is admin+ (unchanged)", () => {
    const g = detectionActionGate("senior_analyst", "single_tenant");
    expect(g.canReview).toBe(true);
    expect(g.canTest).toBe(false); // admin+ only
  });
});
