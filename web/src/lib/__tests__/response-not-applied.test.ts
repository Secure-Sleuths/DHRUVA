/**
 * WO-H34 — active-response honesty: the `not_applied` outcome.
 *
 * When Wazuh accepts an AR command but dispatches it to no agent
 * (total_affected_items=0 — e.g. the manager host, agent 000), the server
 * returns status "not_applied" instead of success. The Respond tab must
 * present that as a distinct not-applied state, never as executed/active.
 */
import { describe, expect, it } from "vitest";
import { arStatusPresentation } from "../response";

describe("WO-H34 arStatusPresentation — not_applied", () => {
  it("renders not_applied as a distinct 'Not applied' state", () => {
    const p = arStatusPresentation("not_applied");
    expect(p.label).toBe("Not applied · no agent target");
  });

  it("does not present not_applied as executed/active", () => {
    const notApplied = arStatusPresentation("not_applied");
    const executed = arStatusPresentation("executed");
    expect(notApplied.label).not.toBe(executed.label);
    expect(notApplied.className).not.toBe(executed.className);
  });

  it("keeps the executed presentation unchanged", () => {
    const p = arStatusPresentation("executed");
    expect(p.label).toBe("Executed · active");
  });
});
