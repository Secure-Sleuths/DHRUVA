/**
 * WO-H97 QA (D7) — RENDERED, not just unit-tested.
 *
 * The incident case header used to paint the score on the severity ramp right
 * next to `sev`, the incident's AUTHORITATIVE stored severity (the risk band
 * plus the guidance floors and ceilings, computed by the backend). So a capped
 * incident showed a **MEDIUM** badge beside a **critical-red 99** captioned
 * "Risk" — the exact display this work order was filed about, sitting next to
 * its own correction.
 *
 * The previous round fixed it but only unit-tested `scorePresentation()`, which
 * would have stayed green if the component stopped calling it. This renders the
 * real case view.
 */
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { IncidentAlert, IncidentDetail } from "@/lib/types";

vi.mock("@/lib/auth", () => ({
  useAuth: () => ({
    role: "analyst",
    roleIsPreview: false,
    claims: { sub: "analyst-two" },
    tier: null,
  }),
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
  getIncident: vi.fn(),
  getIncidents: vi.fn(async () => ({ incidents: [], total: 0 })),
  getIncidentSla: vi.fn(),
  getSlaAtRisk: vi.fn(async () => ({ at_risk: [] })),
  getTicketsForIncident: vi.fn(async () => ({ tickets: [] })),
  getRuleStats: vi.fn(),
  submitTriageReview: vi.fn(),
  lookupIoc: vi.fn(),
  getDecisionRawAlert: vi.fn(),
  getDecisionPlaybook: vi.fn(),
  getDecisionReviews: vi.fn(async (id: string) => ({
    decision_id: id,
    reviews: [],
    count: 0,
  })),
  addIncidentEvidence: vi.fn(),
  addIncidentNote: vi.fn(),
  assignIncident: vi.fn(),
  changeIncidentStatus: vi.fn(),
  escalateIncident: vi.fn(),
  flagIncidentInteresting: vi.fn(),
  mergeIncidents: vi.fn(),
  propagateIncidentVerdict: vi.fn(),
  saveIncidentReview: vi.fn(),
}));

import { getIncident } from "@/lib/api";
import { IncidentsTab } from "../tabs/IncidentsTab";

const mockedGetIncident = vi.mocked(getIncident);

afterEach(cleanup);
beforeEach(() => vi.clearAllMocks());

/** The live scanner decision: 443 of 443 human labels, stored score 99.41. */
const BOUNDED = {
  model: "bounded",
  rule_tp_rate_human: 1.0,
  rule_human_labels: 443,
  rule_human_tp: 443,
  smoothed_p: 0.9941,
  confident: true,
  confidence_reason: "",
};

/** Pre-WO-H71 rows (22,991 of them on the live tenant, all before
 *  2026-08-12) really were scored by the multiplicative model, so the old
 *  "Risk" wording is correct for them — not a gap. */
const LEGACY = { base_severity: 66.7, asset_multiplier: 2.0, raw_score: 133.4 };

function alert(over: Partial<IncidentAlert> = {}): IncidentAlert {
  return {
    id: "dec-1",
    rule_id: 31516,
    rule_description: "Suspicious URL access.",
    verdict: "true_positive",
    confidence: 0.6,
    risk_score: 99.41,
    reasoning: "Automated web reconnaissance; every request answered 404.",
    enrichment_summary: JSON.stringify({ agent_name: "WIN-WKS-07" }),
    ...over,
  } as IncidentAlert;
}

/** A CAPPED incident: the backend's floors/ceilings put it at medium. */
function detail(over: Partial<IncidentDetail> = {}): IncidentDetail {
  return {
    id: "inc-1",
    title: "Suspicious URL access from 87.58.199.134",
    severity: "medium",
    status: "open",
    first_seen: "2026-08-23T23:49:16Z",
    last_seen: "2026-08-23T23:49:16Z",
    alert_count: 30,
    assigned_to: null,
    affected_hosts: '["WIN-WKS-07"]',
    mitre_tactics: "[]",
    alerts: [alert()],
    timeline: [],
    ...over,
  } as IncidentDetail;
}

describe("the incident case header no longer contradicts its own severity", () => {
  it("labels the number as the rule's track record, not 'Risk'", async () => {
    mockedGetIncident.mockResolvedValue(
      detail({
        alerts: [
          alert({
            glass_box: {
              risk_breakdown: BOUNDED,
              provenance: {
                playbook_version: null,
                guidance_hash: null,
                model: "llama-3.3-70b",
                latency_ms: 900,
              },
            },
          }),
        ],
      }),
    );

    render(<IncidentsTab tabId="incidents" navParam="inc-1" />);

    /* BOTH surfaces render it — the incident header and the member alert's
       glass-box card — and they say the same thing, which is the point of
       routing every one of them through `scorePresentation`. */
    await waitFor(() =>
      expect(screen.getAllByText("99%").length).toBeGreaterThan(0),
    );
    expect(screen.getAllByText("99%").length).toBe(2);
    expect(screen.getByText("Rule accuracy")).toBeTruthy();
    // ...and the old caption is gone from the header
    expect(screen.queryByText(/^Risk$/)).toBeNull();
  });

  it("does not paint that number on the severity ramp", async () => {
    mockedGetIncident.mockResolvedValue(
      detail({
        alerts: [
          alert({
            glass_box: {
              risk_breakdown: BOUNDED,
              provenance: {
                playbook_version: null,
                guidance_hash: null,
                model: "x",
                latency_ms: 1,
              },
            },
          }),
        ],
      }),
    );

    render(<IncidentsTab tabId="incidents" navParam="inc-1" />);

    await waitFor(() =>
      expect(screen.getAllByText("99%").length).toBeGreaterThan(0),
    );
    for (const figure of screen.getAllByText("99%")) {
      expect(figure.className).not.toMatch(/text-sev-/);
      expect(figure.className).toMatch(/text-ink/);
    }
  });

  it("still shows the AUTHORITATIVE severity beside it", async () => {
    /* The whole point: a capped incident reads Medium, and the 99 next to it
       no longer argues with that. */
    mockedGetIncident.mockResolvedValue(
      detail({
        alerts: [
          alert({
            glass_box: {
              risk_breakdown: BOUNDED,
              provenance: {
                playbook_version: null,
                guidance_hash: null,
                model: "x",
                latency_ms: 1,
              },
            },
          }),
        ],
      }),
    );

    render(<IncidentsTab tabId="incidents" navParam="inc-1" />);

    await waitFor(() =>
      expect(screen.getAllByText("99%").length).toBeGreaterThan(0),
    );
    expect(screen.getAllByText(/Medium/).length).toBeGreaterThan(0);
  });

  it("reads the breakdown from the enrichment blob when there is no glass_box", async () => {
    mockedGetIncident.mockResolvedValue(
      detail({
        alerts: [
          alert({
            enrichment_summary: JSON.stringify({
              agent_name: "WIN-WKS-07",
              risk_breakdown: BOUNDED,
            }),
          }),
        ],
      }),
    );

    render(<IncidentsTab tabId="incidents" navParam="inc-1" />);

    await waitFor(() =>
      expect(screen.getAllByText("99%").length).toBeGreaterThan(0),
    );
    expect(screen.getByText("Rule accuracy")).toBeTruthy();
  });

  it("keeps the old wording for a pre-WO-H71 decision", async () => {
    mockedGetIncident.mockResolvedValue(
      detail({
        alerts: [
          alert({
            enrichment_summary: JSON.stringify({ risk_breakdown: LEGACY }),
          }),
        ],
      }),
    );

    render(<IncidentsTab tabId="incidents" navParam="inc-1" />);

    await waitFor(() => expect(screen.getByText("Risk")).toBeTruthy());
    expect(screen.getAllByText("99").length).toBeGreaterThan(0);
  });
});
