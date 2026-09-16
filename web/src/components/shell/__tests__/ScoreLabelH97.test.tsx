/**
 * WO-H97 — the number in the case view is labelled as what it MEASURES.
 *
 * THE FAILURE THIS FIXES. An analyst opened a case for thirty `404`s from
 * LeakIX's public crawler, saw **99.41** under the word "risk", and concluded
 * the product was broken. They were right to. That figure is a truthful answer
 * to "how often has a human confirmed this rule fired correctly?" — 443 of 443
 * on rule 31516 — displayed under a label that reads "how dangerous is this?".
 *
 * Nothing in the maths moves (WO-H71's bounded scorer is untouched). These
 * tests pin the WORDS, and the one deliberate colour decision: a rule-precision
 * figure is not painted on the severity ramp, because a 99 in critical-red IS
 * the misreading.
 */
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { IncidentAlert, RiskBreakdown } from "@/lib/types";
import {
  decisionRiskBreakdown,
  ruleAccuracy,
  scorePresentation,
} from "@/lib/incident";

vi.mock("@/lib/auth", () => ({
  useAuth: () => ({ role: "analyst", roleIsPreview: false }),
}));

vi.mock("@/lib/api", () => ({
  ApiError: class ApiError extends Error {
    status: number;
    constructor(status: number, message: string) {
      super(message);
      this.status = status;
    }
  },
  getRuleStats: vi.fn(),
  submitTriageReview: vi.fn(),
  getDecisionReviews: vi.fn(async (decisionId: string) => ({
    decision_id: decisionId,
    reviews: [],
    count: 0,
  })),
  lookupIoc: vi.fn(),
  getDecisionRawAlert: vi.fn(),
  getDecisionPlaybook: vi.fn(),
}));

import { GlassBoxAlertCard } from "../GlassBoxCase";

afterEach(cleanup);
beforeEach(() => vi.clearAllMocks());

/** The live scanner decision: rule 31516, 443 of 443 human labels, 99.41. */
const SCANNER_BREAKDOWN: RiskBreakdown = {
  model: "bounded",
  rule_tp_rate_human: 1.0,
  rule_human_labels: 443,
  rule_human_tp: 443,
  base_rate: 0.5,
  unknown_rule_rate: null,
  smoothed_p: 0.9941,
  adjustment_total: 0,
  log_odds: 5.2417,
  confident: true,
  confidence_reason: "",
};

/** A rule DHRUVA has never seen labelled — the cold-start prior, 75.00. */
const UNLEARNED_BREAKDOWN: RiskBreakdown = {
  model: "bounded",
  rule_tp_rate_human: null,
  rule_human_labels: 0,
  rule_human_tp: 0,
  base_rate: 0.5,
  unknown_rule_rate: 0.75,
  smoothed_p: 0.75,
  confident: false,
  confidence_reason: "rule has 0 human label(s); 3 required",
};

/** The legacy multiplicative model — a genuinely different quantity. */
const LEGACY_BREAKDOWN: RiskBreakdown = {
  base_severity: 66.7,
  asset_multiplier: 2.0,
  raw_score: 133.4,
  clamped_score: 100,
};

function makeAlert(
  breakdown: RiskBreakdown | undefined,
  overrides: Partial<IncidentAlert> = {},
): IncidentAlert {
  return {
    id: "dec-h97",
    rule_id: 31516,
    rule_description: "Suspicious URL access.",
    verdict: "true_positive",
    confidence: 0.6,
    risk_score: 99.41,
    reasoning: "Automated web reconnaissance; every request answered 404.",
    enrichment_summary: JSON.stringify({ agent_name: "WIN-WKS-07" }),
    glass_box: breakdown
      ? {
          risk_breakdown: breakdown,
          provenance: {
            playbook_version: null,
            guidance_hash: null,
            model: "llama-3.3-70b",
            latency_ms: 900,
          },
        }
      : undefined,
    ...overrides,
  };
}

describe("ruleAccuracy — reads the bounded breakdown, guesses nothing", () => {
  it("reports rule precision for a rule with a track record", () => {
    expect(ruleAccuracy(SCANNER_BREAKDOWN)).toEqual({
      confident: true,
      pct: 99,
      labels: 443,
      tp: 443,
      reason: "",
    });
  });

  it("never invents a percentage for a rule nobody has labelled", () => {
    const accuracy = ruleAccuracy(UNLEARNED_BREAKDOWN);
    expect(accuracy?.confident).toBe(false);
    expect(accuracy?.pct).toBeNull();
    expect(accuracy?.reason).toMatch(/0 human label/);
  });

  it("returns null for the legacy model, which is a different quantity", () => {
    expect(ruleAccuracy(LEGACY_BREAKDOWN)).toBeNull();
  });

  it("returns null when no breakdown was recorded", () => {
    expect(ruleAccuracy(undefined)).toBeNull();
    expect(ruleAccuracy(null)).toBeNull();
    expect(ruleAccuracy({} as RiskBreakdown)).toBeNull();
  });
});

describe("the case header labels the number honestly", () => {
  it("calls 99 what it is: how often this rule is right", () => {
    render(
      <GlassBoxAlertCard
        alert={makeAlert(SCANNER_BREAKDOWN)}
        primary
        onReviewed={() => {}}
      />,
    );
    expect(screen.getByText("99%")).toBeTruthy();
    expect(
      screen.getByText(/how often this rule is right/i),
    ).toBeTruthy();
    // and it shows the evidence behind the figure
    expect(screen.getByText(/443 of 443 human labels/)).toBeTruthy();
  });

  it("no longer calls it 'risk', which is what misled the analyst", () => {
    render(
      <GlassBoxAlertCard
        alert={makeAlert(SCANNER_BREAKDOWN)}
        primary
        onReviewed={() => {}}
      />,
    );
    expect(screen.queryByText(/^risk 99$/)).toBeNull();
    expect(screen.queryByText("platform score")).toBeNull();
  });

  it("does not paint rule precision on the severity ramp", () => {
    /* A 99 in critical-red says "danger" louder than any caption can undo.
       The VERDICT badge keeps its own severity colour — that one really is a
       statement about the verdict — so this asserts on the figure itself. */
    render(
      <GlassBoxAlertCard
        alert={makeAlert(SCANNER_BREAKDOWN)}
        primary
        onReviewed={() => {}}
      />,
    );
    const figure = screen.getByText("99%");
    expect(figure.className).not.toMatch(/text-sev-/);
    expect(figure.className).toMatch(/text-ink/);
  });

  it("says plainly when a rule has no track record yet", () => {
    render(
      <GlassBoxAlertCard
        alert={makeAlert(UNLEARNED_BREAKDOWN, { risk_score: 75 })}
        primary
        onReviewed={() => {}}
      />,
    );
    expect(screen.getByText("75")).toBeTruthy();
    expect(
      screen.getByText(/no track record for this rule yet/i),
    ).toBeTruthy();
  });

  it("keeps the old wording for the legacy multiplicative score", () => {
    render(
      <GlassBoxAlertCard
        alert={makeAlert(LEGACY_BREAKDOWN)}
        primary
        onReviewed={() => {}}
      />,
    );
    expect(screen.getByText("risk 99")).toBeTruthy();
    expect(screen.getByText("platform score")).toBeTruthy();
  });
});

describe("the breakdown expander stops claiming nothing was recorded", () => {
  function openDetail() {
    fireEvent.click(
      screen.getByRole("button", { name: /Scoring & enrichment detail/ }),
    );
  }

  it("renders the bounded record instead of 'no breakdown recorded'", () => {
    render(
      <GlassBoxAlertCard
        alert={makeAlert(SCANNER_BREAKDOWN)}
        primary
        onReviewed={() => {}}
      />,
    );
    openDetail();
    fireEvent.click(
      screen.getByRole("button", { name: /Where did this number come from\?/ }),
    );
    expect(
      screen.queryByText(/No per-enricher risk breakdown was recorded/),
    ).toBeNull();
    expect(screen.getByText(/say it fired correctly/)).toBeTruthy();
    expect(
      screen.getByText(/not a measure of how dangerous this alert is/i),
    ).toBeTruthy();
  });

  it("says the enrichment factors contributed nothing, because they did not", () => {
    render(
      <GlassBoxAlertCard
        alert={makeAlert(SCANNER_BREAKDOWN)}
        primary
        onReviewed={() => {}}
      />,
    );
    openDetail();
    fireEvent.click(
      screen.getByRole("button", { name: /Where did this number come from\?/ }),
    );
    expect(
      screen.getByText(/none of them separated true from false positives/i),
    ).toBeTruthy();
  });

  it("keeps the legacy multiplier chain for legacy decisions", () => {
    render(
      <GlassBoxAlertCard
        alert={makeAlert(LEGACY_BREAKDOWN)}
        primary
        onReviewed={() => {}}
      />,
    );
    openDetail();
    fireEvent.click(
      screen.getByRole("button", { name: /How was risk = 99 computed\?/ }),
    );
    expect(screen.getByText("asset")).toBeTruthy();
  });
});

/**
 * WO-H97 QA (D7) — the wording lives in ONE place, so an incident cannot show a
 * MEDIUM severity badge beside a critical-red 99 captioned "Risk". Every
 * surface that prints the stored score (case view, incident header, triage
 * queue, daily review) reads `scorePresentation`.
 */
describe("scorePresentation — one wording for every surface", () => {
  it("names a bounded score after the rule's track record, untinted", () => {
    expect(scorePresentation(99.41, SCANNER_BREAKDOWN)).toEqual({
      figure: "99%",
      label: "Rule accuracy",
      caption: "how often this rule is right (443 of 443 human labels)",
      tinted: false,
    });
  });

  it("does not invent a percentage for an unlearned rule", () => {
    const p = scorePresentation(75, UNLEARNED_BREAKDOWN);
    expect(p.figure).toBe("75");
    expect(p.label).toBe("Starting score");
    expect(p.tinted).toBe(false);
  });

  it("leaves the legacy composite figure exactly as it was", () => {
    expect(scorePresentation(99.41, LEGACY_BREAKDOWN)).toEqual({
      figure: "99",
      label: "Risk",
      caption: "platform score",
      tinted: true,
    });
  });

  it("falls back to the legacy wording when nothing was recorded", () => {
    expect(scorePresentation(50, null).label).toBe("Risk");
    expect(scorePresentation(50, undefined).tinted).toBe(true);
  });

  it("never tints a rule-precision figure on the severity ramp", () => {
    /* A 99 in critical-red IS the misreading, in colour. */
    for (const b of [SCANNER_BREAKDOWN, UNLEARNED_BREAKDOWN]) {
      expect(scorePresentation(99.41, b).tinted).toBe(false);
    }
  });
});

describe("decisionRiskBreakdown — every surface can find the record", () => {
  it("reads the incident detail's glass_box", () => {
    expect(
      decisionRiskBreakdown({
        glass_box: { risk_breakdown: SCANNER_BREAKDOWN },
      }),
    ).toEqual(SCANNER_BREAKDOWN);
  });

  it("reads the enrichment blob the triage queue actually serves", () => {
    /* `/api/triage/decisions` has no glass_box, but `_flatten_enrichment`
       passes `enrichment_summary` through untouched and the blob has always
       carried `risk_breakdown`. Without this the queue could not tell a
       rule-precision figure from a legacy risk figure. */
    expect(
      decisionRiskBreakdown({
        enrichment_summary: JSON.stringify({
          agent_name: "WIN-WKS-07",
          risk_breakdown: SCANNER_BREAKDOWN,
        }),
      }),
    ).toEqual(SCANNER_BREAKDOWN);
  });

  it("returns null rather than guessing when neither is present", () => {
    expect(decisionRiskBreakdown({})).toBeNull();
    expect(decisionRiskBreakdown({ enrichment_summary: "not json" })).toBeNull();
    expect(
      decisionRiskBreakdown({ enrichment_summary: JSON.stringify({}) }),
    ).toBeNull();
  });
});
