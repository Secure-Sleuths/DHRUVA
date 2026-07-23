/**
 * WO-H46-c — a failed triage must never render as a considered verdict.
 *
 * When the LLM backend is unreachable, triage fails CLOSED: the row carries
 * `verdict: 'needs_investigation'`, `escalated: true`, `confidence: 0` — the
 * alert was escalated WITHOUT being analyzed. Rendering that as "Needs
 * investigation" repeats the lie that caused the incident: on one install a
 * dead backend produced 1398 un-analyzed rows that looked like a busy queue.
 */

import { describe, expect, it } from "vitest";

import {
  NOT_ANALYZED,
  decisionPresentation,
  verdictPresentation,
} from "@/lib/triage";

describe("decisionPresentation (WO-H46-c)", () => {
  it("labels a failed triage 'Not analyzed', not the stored verdict", () => {
    const p = decisionPresentation({
      verdict: "needs_investigation",
      llm_failed: true,
    });
    expect(p.label).toBe("Not analyzed");
    expect(p.label).not.toBe(verdictPresentation("needs_investigation").label);
  });

  it("is visually distinct from a real needs_investigation", () => {
    const failed = decisionPresentation({
      verdict: "needs_investigation",
      llm_failed: true,
    });
    const real = decisionPresentation({
      verdict: "needs_investigation",
      llm_failed: false,
    });
    expect(failed.glyph).not.toBe(real.glyph);
    expect(failed.className).not.toBe(real.className);
  });

  it("passes real verdicts through untouched", () => {
    for (const v of [
      "true_positive",
      "false_positive",
      "needs_investigation",
      "auto_close",
    ]) {
      expect(decisionPresentation({ verdict: v })).toEqual(
        verdictPresentation(v),
      );
    }
  });

  it("treats a missing llm_failed as a real verdict (back-compat)", () => {
    // Rows written before the flag existed have no property at all.
    expect(decisionPresentation({ verdict: "true_positive" }).label).toBe(
      "True positive",
    );
  });

  it("never claims a severity for an un-analyzed alert", () => {
    // Nothing assessed this alert, so it must not borrow the critical styling
    // that a real true_positive earns.
    expect(NOT_ANALYZED.className).not.toBe(
      verdictPresentation("true_positive").className,
    );
  });

  it("overrides regardless of the stored verdict value", () => {
    // Defensive: a failure row should read as unanalyzed even if some future
    // path stored a different verdict alongside the flag.
    expect(
      decisionPresentation({ verdict: "true_positive", llm_failed: true }).label,
    ).toBe("Not analyzed");
  });
});
