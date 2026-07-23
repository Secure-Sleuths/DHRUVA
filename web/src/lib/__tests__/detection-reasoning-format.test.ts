/**
 * WO-H49 — the deploy confirm must stay readable and reachable.
 *
 * The Detection agent's `reasoning` is usually a JSON envelope
 * (tp_coverage_risk / changes_made / expected_fp_reduction / alternatives),
 * not prose. Rendered raw it filled the deploy confirm dialog with a wall of
 * braces and escapes — and because the Dialog panel had no max-height, the
 * dialog outgrew the viewport and pushed the Deploy button out of reach. An
 * operator could neither read what they were approving nor click approve.
 *
 * These cover the formatting half. The height/scroll half is a CSS constraint
 * on the shared Dialog panel (max-h-[85vh] + overflow-y-auto).
 */

import { describe, expect, it } from "vitest";

import { formatReasoning } from "@/lib/detectionReasoning";

describe("formatReasoning (WO-H49)", () => {
  it("turns a JSON envelope into readable Key: value lines", () => {
    const raw = JSON.stringify({
      expected_fp_reduction: "~33% of the rule-510 FPs",
      coverage_impact: "minimal",
    });
    const out = formatReasoning(raw);
    expect(out).toContain("Expected fp reduction:");
    expect(out).toContain("~33% of the rule-510 FPs");
    expect(out).not.toContain("{");
    expect(out).not.toContain('\\"');
  });

  it("renders array fields as bullets rather than one long line", () => {
    const raw = JSON.stringify({ changes_made: ["Added a child rule", "Scoped the exclusion"] });
    const out = formatReasoning(raw);
    expect(out).toContain("• Added a child rule");
    expect(out).toContain("• Scoped the exclusion");
  });

  it("leaves plain prose completely untouched", () => {
    const prose = "Rule 5407 is noisy on this host; propose a level-0 child.";
    expect(formatReasoning(prose)).toBe(prose);
  });

  it("falls back to the raw string when JSON is malformed", () => {
    // Must NEVER throw — a formatting helper cannot break a deploy confirm.
    const broken = '{"changes_made": ["unterminated';
    expect(formatReasoning(broken)).toBe(broken);
  });

  it("handles empty / missing reasoning without throwing", () => {
    expect(formatReasoning("")).toBe("");
    expect(formatReasoning(null)).toBe("");
    expect(formatReasoning(undefined)).toBe("");
  });

  it("does not mangle a JSON scalar that is not an object", () => {
    expect(formatReasoning("[1, 2, 3]")).toContain("1");
  });
});
