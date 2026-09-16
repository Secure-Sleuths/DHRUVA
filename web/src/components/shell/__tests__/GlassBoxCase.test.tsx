/**
 * WO-H21 — GlassBoxAlertCard component tests: the case renders each inline
 * context record when present, honest empty states when the enrichment blob is
 * missing/malformed, and the lazy raw-event + playbook drills. The API module
 * is mocked (this is a render contract test, not a network test); RBAC's
 * useAuth is mocked to a plain analyst — viewing context has NO role gate.
 */
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { IncidentAlert } from "@/lib/types";

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
  // WO-H85 — the card reads the append-only review history when the caller did
  // not attach one. Default: no prior reviews.
  getDecisionReviews: vi.fn(async (decisionId: string) => ({
    decision_id: decisionId,
    reviews: [],
    count: 0,
  })),
  lookupIoc: vi.fn(async () => ({
    ioc_value: "185.220.101.34",
    matches: [
      {
        ioc_value: "185.220.101.34",
        ioc_type: "ip",
        source: "alienvault_otx",
        severity: "high",
        confidence: 90,
        last_seen: "2026-07-01T00:00:00Z",
        description: "Known Tor exit node used in brute-force campaigns",
        tags: '["tor","bruteforce"]',
      },
    ],
    total: 1,
  })),
  getDecisionRawAlert: vi.fn(async () => ({
    found: true,
    alert: {
      alert_id: "1234567890.123456",
      rule_id: 5710,
      full_log:
        "Apr 19 10:30:00 prod-db-01 sshd[1234]: Accepted publickey for root",
      data: { srcip: "185.220.101.34" },
    },
    reason: null,
  })),
  getDecisionPlaybook: vi.fn(async () => ({
    matched: true,
    playbook: {
      key: "suspicious_login",
      name: "Suspicious Login Investigation",
      trigger_rule_groups: ["sshd"],
      trigger_rule_ids: [5710],
      investigation_steps: [
        {
          step: 1,
          name: "Identify the user and source",
          assess: "- How many unique source IPs?",
          query_template: "",
        },
      ],
      verdict_criteria: {
        true_positive: ["Successful auth following brute force"],
        false_positive: ["Known CI/CD auth patterns"],
        needs_investigation: ["New user account with login anomalies"],
      },
      escalation_criteria: ["New user account with login anomalies"],
      recommended_actions: { if_true_positive: ["Force password reset"] },
    },
    reason: null,
  })),
}));

import { GlassBoxAlertCard } from "../GlassBoxCase";
import {
  getDecisionPlaybook,
  getDecisionRawAlert,
  getRuleStats,
  lookupIoc,
} from "@/lib/api";

afterEach(cleanup);
// Call counts are asserted per test (the lazy-drill guarantees) — never let
// one test's expands leak into the next test's "was not fetched" assertion.
beforeEach(() => vi.clearAllMocks());

const FULL_BLOB = {
  agent_name: "prod-db-01",
  agent_ip: "192.168.1.100",
  src_ip: "185.220.101.34",
  rule_mitre_techniques: ["T1078"],
  rule_mitre_tactics: ["Initial Access"],
  asset_tier: "tier_1_critical",
  asset_owner: "platform-team",
  asset_environment: "production",
  user_risk_level: "privileged",
  user_roles: ["dba"],
  user_has_admin: true,
  user_is_service_account: false,
  user_department: "engineering",
  time_context: "outside_business_hours",
  is_business_hours: false,
  is_weekend: false,
  is_maintenance_window: false,
  threat_intel_hits: 2,
  threat_intel_sources: ["local", "abuseipdb"],
  is_known_malicious: true,
  highest_ti_severity: "high",
  threat_intel_match: [
    {
      indicator: "185.220.101.34",
      type: "ip",
      source: "abuseipdb",
      severity: "high",
      last_seen: "2026-07-01",
    },
  ],
  historical_fp_rate: 0.6,
  same_rule_last_7d: 4,
  same_source_last_7d: 12,
  same_user_last_7d: 3,
  baseline_anomaly: true,
  baseline_deviation: 3.4,
  baseline_anomaly_details: [
    {
      dimension: "src_ip",
      value: "185.220.101.34",
      current_24h: 40,
      baseline_mean: 4.2,
      baseline_std: 2.1,
      z_score: 3.4,
      sample_days: 21,
    },
  ],
  host_vulnerabilities_critical: 2,
  host_vulnerabilities_high: 5,
  host_sca_failed_checks: 7,
  host_top_critical_cves: ["CVE-2025-1234"],
  vuln_context_reason: "host has critical CVE-2025-1234 (unpatched)",
  host_top_cve_details: [
    {
      cve: "CVE-2025-1234",
      severity: "critical",
      cvss: 9.8,
      cvss_version: "3.1",
      epss: 0.87,
      kev: true,
    },
  ],
  host_rootcheck_findings: 1,
  host_fim_recent_changes: 14,
  host_integrity_reason: "host has 1 open rootcheck finding(s)",
  host_rootcheck_signatures: ["Rootkit 'Adore' detected"],
  host_fim_changed_paths: ["/etc/passwd"],
};

/** Breakdown in which EVERY factor moved, so every record row must render. */
const FULL_BREAKDOWN = {
  base_severity: 66.7,
  asset_multiplier: 2.0,
  user_multiplier: 1.8,
  time_multiplier: 1.5,
  mitre_boost: 1.5,
  ti_boost: 2.0,
  fp_discount: 0.6,
  anomaly_boost: 1.3,
  vuln_context_multiplier: 1.8,
  host_integrity_multiplier: 1.5,
  raw_score: 500,
  clamped_score: 100,
};

function makeAlert(overrides: Partial<IncidentAlert> = {}): IncidentAlert {
  return {
    id: "dec-1",
    rule_id: 5710,
    rule_description: "sshd: authentication success.",
    verdict: "true_positive",
    confidence: 0.9,
    risk_score: 88,
    reasoning: "Login from a known-malicious IP onto a tier-1 host.",
    enrichment_summary: JSON.stringify(FULL_BLOB),
    glass_box: {
      risk_breakdown: FULL_BREAKDOWN,
      provenance: {
        playbook_version: "## Investigation Playbook: Suspicious Login",
        guidance_hash: null,
        model: "cli",
        latency_ms: 900,
      },
    },
    ...overrides,
  };
}

function expandRow(name: RegExp) {
  fireEvent.click(screen.getByRole("button", { name }));
}

/**
 * WO-H86 — the risk maths, the nine context records, the playbook, the rule
 * stats, the raw event and the provenance/anonymization panels now live behind
 * ONE collapsed "Scoring & enrichment detail" box, so the reasoning and the
 * recommended action own the top of the case. Everything below therefore opens
 * that box first; nothing was removed, it moved one click deeper.
 */
function openDetail() {
  fireEvent.click(
    screen.getByRole("button", { name: /Scoring & enrichment detail/ }),
  );
}

describe("ContextRecordsSection — every moved factor exposes its record", () => {
  it("renders one expandable row per context dimension, with its multiplier", () => {
    render(<GlassBoxAlertCard alert={makeAlert()} primary onReviewed={() => {}} />);
    openDetail();
    for (const label of [
      /Asset — ×2/,
      /Identity — ×1\.8/,
      /Time context — ×1\.5/,
      /MITRE — ×1\.5/,
      /Threat intel — ×2/,
      /FP history — ×0\.6/,
      /Baseline anomaly — ×1\.3/,
      /Vulnerabilities — ×1\.8/,
      /Host integrity — ×1\.5/,
    ]) {
      expect(screen.getByRole("button", { name: label })).toBeTruthy();
    }
  });

  it("asset row expands into the asset record card", () => {
    render(<GlassBoxAlertCard alert={makeAlert()} primary onReviewed={() => {}} />);
    openDetail();
    expandRow(/Asset — ×2/);
    expect(screen.getByText("prod-db-01")).toBeTruthy();
    expect(screen.getByText("tier_1_critical")).toBeTruthy();
    expect(screen.getByText("platform-team")).toBeTruthy();
  });

  it("identity row shows the principal (privileged? account type)", () => {
    render(<GlassBoxAlertCard alert={makeAlert()} primary onReviewed={() => {}} />);
    openDetail();
    expandRow(/Identity — ×1\.8/);
    expect(screen.getByText("yes — admin roles")).toBeTruthy();
    expect(screen.getByText("user account")).toBeTruthy();
    // "privileged" appears as both a label and the risk-level value
    expect(screen.getAllByText("privileged").length).toBeGreaterThan(0);
  });

  it("vuln row shows the CVEs; host-integrity row shows the finding", () => {
    render(<GlassBoxAlertCard alert={makeAlert()} primary onReviewed={() => {}} />);
    openDetail();
    expandRow(/Vulnerabilities — ×1\.8/);
    expect(screen.getByText("CVE-2025-1234")).toBeTruthy();
    expandRow(/Host integrity — ×1\.5/);
    expect(
      screen.getByText("host has 1 open rootcheck finding(s)"),
    ).toBeTruthy();
  });

  it("WO-H23: vuln row shows per-CVE CVSS / EPSS / KEV inline", () => {
    render(<GlassBoxAlertCard alert={makeAlert()} primary onReviewed={() => {}} />);
    openDetail();
    expandRow(/Vulnerabilities — ×1\.8/);
    expect(screen.getByText("Top critical CVEs — CVSS / EPSS / KEV")).toBeTruthy();
    expect(screen.getByText("9.8 (v3.1)")).toBeTruthy(); // CVSS + version
    expect(screen.getByText("87.0%")).toBeTruthy(); // EPSS as percent
    expect(screen.getByText("CISA KEV")).toBeTruthy();
  });

  it("WO-H23: host-integrity row shows FIM paths + rootcheck signatures", () => {
    render(<GlassBoxAlertCard alert={makeAlert()} primary onReviewed={() => {}} />);
    openDetail();
    expandRow(/Host integrity — ×1\.5/);
    expect(screen.getByText("Rootkit 'Adore' detected")).toBeTruthy();
    expect(screen.getByText("/etc/passwd")).toBeTruthy();
  });

  it("WO-H23: unknown CVSS/EPSS/KEV renders honestly, not a fake zero/negative", () => {
    const blob = {
      ...FULL_BLOB,
      // No CVSS/EPSS and no `kev` field → KEV status is UNKNOWN.
      host_top_cve_details: [{ cve: "CVE-2025-0001", severity: "critical" }],
    };
    render(
      <GlassBoxAlertCard
        alert={makeAlert({ enrichment_summary: JSON.stringify(blob) })}
        primary
        onReviewed={() => {}}
      />,
    );
    openDetail();
    expandRow(/Vulnerabilities — ×1\.8/);
    expect(screen.getByText("CVE-2025-0001")).toBeTruthy();
    // No fabricated KEV verdict: neither the positive badge NOR a definitive
    // "not in KEV" — an unknown is shown as "KEV data unavailable".
    expect(screen.queryByText("CISA KEV")).toBeNull();
    expect(screen.queryByText("not in KEV")).toBeNull();
    expect(screen.getByText("KEV data unavailable")).toBeTruthy();
  });

  it("WO-H23: a genuine known-negative renders 'not in KEV'", () => {
    const blob = {
      ...FULL_BLOB,
      host_top_cve_details: [
        { cve: "CVE-2025-0002", severity: "critical", cvss: 5.0, kev: false },
      ],
    };
    render(
      <GlassBoxAlertCard
        alert={makeAlert({ enrichment_summary: JSON.stringify(blob) })}
        primary
        onReviewed={() => {}}
      />,
    );
    openDetail();
    expandRow(/Vulnerabilities — ×1\.8/);
    expect(screen.getByText("not in KEV")).toBeTruthy();
    expect(screen.queryByText("KEV data unavailable")).toBeNull();
  });

  it("TI row shows the exact matched indicator + lazy-loads the IOC lookup", async () => {
    render(<GlassBoxAlertCard alert={makeAlert()} primary onReviewed={() => {}} />);
    openDetail();
    expandRow(/Threat intel — ×2/);
    // WO-H23: the stored matched indicator record renders without a fetch.
    expect(screen.getByText(/Matched indicator/)).toBeTruthy();
    expect(screen.getByText("2026-07-01")).toBeTruthy(); // last seen
    expect(lookupIoc).not.toHaveBeenCalled();
    expandRow(/IOC lookup — 185\.220\.101\.34/);
    expect(await screen.findByText("alienvault_otx")).toBeTruthy();
    expect(
      screen.getByText("Known Tor exit node used in brute-force campaigns"),
    ).toBeTruthy();
    expect(lookupIoc).toHaveBeenCalledTimes(1);
  });

  it("missing blob → rows still render with an honest empty state", () => {
    render(
      <GlassBoxAlertCard
        alert={makeAlert({ enrichment_summary: null })}
        primary
        onReviewed={() => {}}
      />,
    );
    openDetail();
    expandRow(/Asset — ×2/);
    expect(screen.getAllByText(/No asset record was stored/).length).toBe(1);
  });

  it("malformed blob → renders empty states, never crashes", () => {
    render(
      <GlassBoxAlertCard
        alert={makeAlert({ enrichment_summary: "{broken json" })}
        primary
        onReviewed={() => {}}
      />,
    );
    openDetail();
    expandRow(/Identity — ×1\.8/);
    expect(screen.getAllByText(/No identity record was stored/).length).toBe(1);
  });

  /**
   * REPLACES "no breakdown → falls back to the dimensions that HAVE records".
   * WO-H86 changed this deliberately: the section no longer shows a SUBSET of
   * dimensions. A missing row cannot tell an analyst whether we checked and
   * found nothing or never checked at all, so all nine always render and each
   * one states its own emptiness. The multiplier suffix is still only present
   * when a breakdown was recorded — that part is unchanged.
   */
  it("no breakdown → all nine dimensions still render, with plain titles", () => {
    // A PARTIAL blob is required: against FULL_BLOB the old `present(ctx)`
    // filter yields the same nine rows, so reverting `contextRows` left this
    // green. Here only three dimensions have a record — the other six exist
    // solely because we now refuse to filter on emptiness.
    render(
      <GlassBoxAlertCard
        alert={makeAlert({
          glass_box: undefined,
          enrichment_summary: JSON.stringify({
            agent_name: "prod-db-01",
            asset_tier: "tier_1_critical",
            user_risk_level: "standard",
            user_roles: [],
            host_rootcheck_findings: 3,
            host_fim_recent_changes: 0,
          }),
        })}
        primary
        onReviewed={() => {}}
      />,
    );
    openDetail();
    // six of the nine have NO record at all and say so, rather than vanishing
    expect(screen.getAllByText("no record stored").length).toBe(6);
    // No multiplier suffix without a recorded breakdown — plain titles.
    // (Accessible names concatenate the summary + preview spans.)
    for (const title of [
      /^Asset/,
      /^Identity/,
      /^Time context/,
      /^MITRE/,
      /^Threat intel/,
      /^FP history/,
      /^Baseline anomaly/,
      /^Vulnerabilities/,
      /^Host integrity/,
    ]) {
      expect(screen.getByRole("button", { name: title })).toBeTruthy();
    }
    expect(screen.queryByRole("button", { name: /×/ })).toBeNull();
  });

  it("neither breakdown nor records → the section renders nothing", () => {
    render(
      <GlassBoxAlertCard
        alert={makeAlert({ enrichment_summary: null, glass_box: undefined })}
        primary
        onReviewed={() => {}}
      />,
    );
    openDetail();
    expect(
      screen.queryByText(/Context behind the score/),
    ).toBeNull();
  });
});

describe("RawEventExpander — the raw Wazuh event, lazy", () => {
  it("fetches only on first expand and renders full_log + JSON", async () => {
    render(<GlassBoxAlertCard alert={makeAlert()} primary onReviewed={() => {}} />);
    openDetail();
    expect(getDecisionRawAlert).not.toHaveBeenCalled();
    expandRow(/Raw Wazuh event/);
    // full_log renders both as the highlighted line and inside the JSON doc
    expect(
      (await screen.findAllByText(/Accepted publickey for root/)).length,
    ).toBeGreaterThan(0);
    expect(getDecisionRawAlert).toHaveBeenCalledWith(
      "dec-1",
      expect.anything(),
    );
  });

  it("renders the honest reason when the event is not found", async () => {
    vi.mocked(getDecisionRawAlert).mockResolvedValueOnce({
      found: false,
      alert: null,
      reason: "The underlying event was not found in the enriched-alert index.",
    });
    render(<GlassBoxAlertCard alert={makeAlert()} primary onReviewed={() => {}} />);
    openDetail();
    expandRow(/Raw Wazuh event/);
    expect(
      await screen.findByText(/was not found in the enriched-alert index/),
    ).toBeTruthy();
  });
});

describe("PlaybookExpander — matched playbook content, lazy", () => {
  it("renders steps + escalation criteria on expand", async () => {
    render(<GlassBoxAlertCard alert={makeAlert()} primary onReviewed={() => {}} />);
    openDetail();
    expect(getDecisionPlaybook).not.toHaveBeenCalled();
    expandRow(/Matched playbook/);
    expect(
      await screen.findByText("Suspicious Login Investigation"),
    ).toBeTruthy();
    expect(screen.getByText(/Identify the user and source/)).toBeTruthy();
    expect(screen.getByText(/Escalate \/ needs investigation when/)).toBeTruthy();
    expect(
      screen.getByText("New user account with login anomalies"),
    ).toBeTruthy();
  });

  it("renders the honest reason when no playbook matched", async () => {
    vi.mocked(getDecisionPlaybook).mockResolvedValueOnce({
      matched: false,
      playbook: null,
      reason:
        "No specific playbook matched this alert — the AI applied the general investigation methodology.",
    });
    render(<GlassBoxAlertCard alert={makeAlert()} primary onReviewed={() => {}} />);
    openDetail();
    expandRow(/Matched playbook/);
    expect(
      await screen.findByText(/general investigation methodology/),
    ).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// WO-H86 — the case view buried the reasoning and the remediation.
//
// The operator's complaint, working a live case: "in each alert entire screen
// is covered with this, hence a user gets confused what to check and what needs
// my eyes". On a real case (rule 31104) the nine context rows filled the
// viewport and pushed the recommended action ("block 160.250.132.238 at the WAF
// and firewall") off-screen — while the one genuinely alarming fact (500 open
// rootcheck findings on the host) sat behind a row that looked exactly like the
// four EMPTY ones next to it.
// ---------------------------------------------------------------------------

/** The operator's real case: four empty dimensions, one very loud one. */
const THIN_CASE_BLOB = {
  agent_name: "WIN-WKS-12",
  agent_ip: "10.0.0.44",
  src_ip: "160.250.132.238",
  // asset is on file but carries nothing usable
  asset_tier: "unknown",
  asset_owner: "unknown",
  asset_environment: "unknown",
  // a plain account with no roles
  user_risk_level: "standard",
  user_roles: [],
  user_has_admin: false,
  user_is_service_account: false,
  time_context: "outside_business_hours",
  is_business_hours: false,
  is_weekend: false,
  is_maintenance_window: false,
  // TI was consulted and found nothing
  threat_intel_hits: 0,
  threat_intel_sources: [],
  is_known_malicious: false,
  historical_fp_rate: 0,
  same_rule_last_7d: 12,
  // baseline was computed and flagged nothing
  baseline_anomaly: false,
  baseline_deviation: 0,
  baseline_anomaly_details: [],
  // …and the host is a mess
  host_rootcheck_findings: 500,
  host_fim_recent_changes: 0,
  host_integrity_reason: "host has 500 open rootcheck finding(s)",
  // NOTE: no MITRE keys and no vuln keys at all → genuinely NO record stored.
};

function thinCase(over: Partial<IncidentAlert> = {}): IncidentAlert {
  return makeAlert({
    id: "dec-31104",
    rule_id: 31104,
    rule_description: "Common web attack.",
    risk_score: 96,
    confidence: 0.9184,
    reasoning:
      "The source attempted a SQL injection against the public web tier; the composite risk score is 86.54/100.",
    actions_taken: JSON.stringify([
      "Block 160.250.132.238 at the WAF and firewall",
      "Review web server access logs for the same source",
    ]),
    grounding: JSON.stringify({
      grounding: "low",
      score: 0.3,
      reasons: ["little supporting evidence in the alert payload"],
      unsupported: ["attribution to a known campaign"],
    }),
    enrichment_summary: JSON.stringify(THIN_CASE_BLOB),
    glass_box: undefined,
    ...over,
  });
}

/** Where a string sits in the rendered document (-1 when absent). */
function at(text: string): number {
  return (document.body.textContent ?? "").indexOf(text);
}

/** The classes carrying a preview line's visual weight. */
function previewWeight(text: string): string {
  const el = screen.getAllByText(text)[0];
  return `${el.className} ${el.parentElement?.className ?? ""}`;
}

describe("WO-H86 reading order — reasoning and remediation come first", () => {
  it("puts reasoning, then the recommended action, ahead of the collapsed detail box", () => {
    // A case with ALL NINE context dimensions present — the worst case for
    // the old layout, where nine rows filled a 1080p viewport.
    render(<GlassBoxAlertCard alert={makeAlert({
      actions_taken: JSON.stringify([
        "Block 160.250.132.238 at the WAF and firewall",
      ]),
    })} primary onReviewed={() => {}} />);

    const reasoningAt = at("Login from a known-malicious IP onto a tier-1 host.");
    const actionAt = at("Block 160.250.132.238 at the WAF and firewall");
    const detailAt = at("Scoring & enrichment detail");

    expect(reasoningAt).toBeGreaterThan(-1);
    expect(actionAt).toBeGreaterThan(reasoningAt);
    expect(detailAt).toBeGreaterThan(actionAt);

    // Both are OPEN on arrival — the analyst reads them without a click…
    expect(
      screen.getByRole("button", { name: /Why did the AI decide this\?/ })
        .getAttribute("aria-expanded"),
    ).toBe("true");
    expect(
      screen.getByRole("button", { name: /Recommended actions/ })
        .getAttribute("aria-expanded"),
    ).toBe("true");

    // …and every scoring/enrichment row is behind ONE closed box, so nothing
    // between the top of the card and the recommended action can push it down.
    expect(
      screen.getByRole("button", { name: /Scoring & enrichment detail/ })
        .getAttribute("aria-expanded"),
    ).toBe("false");
    expect(screen.queryByRole("button", { name: /^Asset/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Host integrity/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Raw Wazuh event/ })).toBeNull();
  });

  it("keeps the analyst's action (review history + override form) OUT of the detail box", () => {
    // A history fixture is REQUIRED here. With the default empty-review mock
    // the string "Review history" never renders, `at()` returns -1, and the
    // ordering assertion passes even if ReviewHistoryPanel is deleted outright.
    render(
      <GlassBoxAlertCard
        alert={makeAlert({
          review_history: [
            {
              id: "rev-1",
              decision_id: "dec-1",
              reviewer: "analyst-two",
              human_verdict: "false_positive",
              reason: "known-good backup job",
              previous_verdict: null,
              source: "human_review",
              created_at: "2026-08-13T10:00:00Z",
            },
          ],
        })}
        primary
        onReviewed={() => {}}
      />,
    );
    // Visible with the detail box still closed — it is the action, not detail.
    const detailAt = at("Scoring & enrichment detail");
    const historyAt = at("Review history");
    const formAt = at("Reason *required");
    expect(historyAt).toBeGreaterThan(-1);
    expect(formAt).toBeGreaterThan(-1);
    expect(screen.getByText("analyst-two")).toBeTruthy();
    expect(screen.getByText("known-good backup job")).toBeTruthy();
    expect(formAt).toBeGreaterThan(detailAt);
    expect(screen.getByRole("radiogroup", { name: "Human verdict" })).toBeTruthy();
    // WO-H85 ordering survives: history is readable BEFORE the override form.
    expect(historyAt).toBeGreaterThan(detailAt);
    expect(historyAt).toBeLessThan(formAt);
  });

  it("says so honestly when no recommended action was stored, instead of vanishing", () => {
    render(
      <GlassBoxAlertCard
        alert={makeAlert({ actions_taken: null })}
        primary
        onReviewed={() => {}}
      />,
    );
    expect(screen.getByRole("button", { name: /Recommended actions/ })).toBeTruthy();
    expect(
      screen.getByText(/No recommended actions were stored with this decision/),
    ).toBeTruthy();
  });
});

describe("WO-H86 — the detail box is collapsed AND lazy", () => {
  it("triggers no drill fetch on mount or while collapsed", () => {
    render(<GlassBoxAlertCard alert={makeAlert()} primary onReviewed={() => {}} />);
    expect(getDecisionRawAlert).not.toHaveBeenCalled();
    expect(getDecisionPlaybook).not.toHaveBeenCalled();
    expect(getRuleStats).not.toHaveBeenCalled();
    expect(lookupIoc).not.toHaveBeenCalled();
  });

  it("still fetches nothing when the box is OPENED — each drill stays lazy", () => {
    render(<GlassBoxAlertCard alert={makeAlert()} primary onReviewed={() => {}} />);
    openDetail();
    // The drills are now mounted, but re-parenting them must not have made
    // any of them eager: they fetch on their OWN first expand only.
    expect(getDecisionRawAlert).not.toHaveBeenCalled();
    expect(getDecisionPlaybook).not.toHaveBeenCalled();
    expect(getRuleStats).not.toHaveBeenCalled();
    expect(lookupIoc).not.toHaveBeenCalled();
    // Only expanding a drill fetches it.
    expandRow(/Rule 5710 stats \(7d\)/);
    expect(getRuleStats).toHaveBeenCalledTimes(1);
    expect(getDecisionRawAlert).not.toHaveBeenCalled();
    expect(getDecisionPlaybook).not.toHaveBeenCalled();
  });

  it("keeps the anonymization boundary panel reachable inside the box", () => {
    render(<GlassBoxAlertCard alert={makeAlert()} primary onReviewed={() => {}} />);
    expect(screen.queryByText("What the AI saw vs what you see")).toBeNull();
    openDetail();
    expect(screen.getByText("What the AI saw vs what you see")).toBeTruthy();
    expect(
      screen.getByText(/Anonymization is the LLM boundary/),
    ).toBeTruthy();
    // provenance moved with it, not away
    expect(screen.getByText("Provenance — this exact verdict")).toBeTruthy();
  });
});

describe("WO-H86 — nine scannable previews, not nine identical hints", () => {
  it("gives every dimension its own one-line preview", () => {
    render(<GlassBoxAlertCard alert={thinCase()} primary onReviewed={() => {}} />);
    openDetail();
    // one row per dimension, each with a DIFFERENT preview computed from its
    // own record — the old build put the constant "underlying record" on all 9
    expect(screen.queryByText("underlying record")).toBeNull();
    expect(
      screen.getByText("no tier, owner or environment on file"),
    ).toBeTruthy();
    // N3: `user_roles: []` is a PRE-SEED, so an unmatched principal may not be
    // described as having "no roles" — the store was never shown to hold any.
    expect(screen.queryByText("identity: standard, no roles")).toBeNull();
    // (also the value inside the row body, which is mounted but hidden)
    expect(
      screen.getAllByText("outside business hours").length,
    ).toBeGreaterThan(0);
    expect(
      screen.getByText("no feed hit recorded for 160.250.132.238"),
    ).toBeTruthy();
    // counts are restated verbatim; no rate is claimed, because this blob
    // carries no `historical_window_days` to prove the FP query ran
    expect(screen.getByText("12 same rule in 7d")).toBeTruthy();
    expect(screen.getByText("500 open rootcheck findings")).toBeTruthy();
  });

  /**
   * REPLACES "distinguishes 'checked and found nothing' from 'no record
   * stored'". That framing was itself the bug QA blocked: the UI was asserting
   * a check had RUN from a stored 0, and almost every enricher pre-seeds its
   * keys to 0/false and swallows its own failures. The honest distinction the
   * card can actually support is three-way.
   */
  it("keeps 'no record', 'no signal' and 'check errored' apart", () => {
    render(
      <GlassBoxAlertCard
        alert={thinCase({
          enrichment_summary: JSON.stringify({
            ...THIN_CASE_BLOB,
            // the enrichment service recorded that THIS enricher raised
            degraded_enrichers: ["threat_intel"],
          }),
        })}
        primary
        onReviewed={() => {}}
      />,
    );
    openDetail();

    // 1. the enricher RAISED — the only state we can positively prove
    expect(
      screen.getByText("check failed — enrichment degraded"),
    ).toBeTruthy();

    // 2. a record exists but holds nothing → claims nothing either way
    expect(screen.getAllByText("no signal recorded").length).toBeGreaterThan(0);

    // 3. no record was stored at all → a different fact, still rendered
    expect(screen.getByRole("button", { name: /^MITRE/ })).toBeTruthy();
    expect(screen.getByRole("button", { name: /^Vulnerabilities/ })).toBeTruthy();
    expect(screen.getAllByText("no record stored").length).toBe(2);

    expandRow(/^Vulnerabilities/);
    expect(
      screen.getByText(/No vulnerability record was stored with this decision/),
    ).toBeTruthy();
  });

  it("weights an alarming row so it cannot look like an empty one", () => {
    render(<GlassBoxAlertCard alert={thinCase()} primary onReviewed={() => {}} />);
    openDetail();

    // 500 open rootcheck findings — critical weight on the shared severity scale
    const loud = previewWeight("500 open rootcheck findings");
    expect(loud).toContain("text-sev-crit");

    // the quiet rows carry no severity weight at all
    for (const quiet of [
      "no tier, owner or environment on file",
      "no feed hit recorded for 160.250.132.238",
      "no signal recorded",
    ]) {
      expect(previewWeight(quiet)).not.toContain("text-sev-");
    }
  });

  it("lifts the alarming finding onto the CLOSED box so collapsing hides nothing that matters", () => {
    render(<GlassBoxAlertCard alert={thinCase()} primary onReviewed={() => {}} />);
    // still collapsed — but the host's state is already readable
    expect(screen.getByText("inside, worth your eyes")).toBeTruthy();
    expect(
      screen.getByText("500 open rootcheck findings"),
    ).toBeTruthy();
    // nothing quiet is promoted
    expect(screen.queryByText("identity: standard, no roles")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// QA block, item 1 — a stored 0 is NOT evidence that a check ran.
//
// `HostIntegrityEnricher._empty()` (enrichers/__init__.py:1857) and the vuln
// equivalent (:1343) are returned on FIVE paths that are not findings: feature
// disabled, missing or "000" agent_id, TenantConfigUnavailable (M2
// fail-closed), a null client, and any exception out of `_compute`. Verified
// against `_compute`: a genuinely CLEAN host produces byte-identical output —
// counts 0 and an EMPTY `reason` — so `reason` cannot separate them either.
// ThreatIntel pre-seeds hits to 0 and only builds an indicator set from PUBLIC
// IPs/hashes; Historical pre-seeds fp_rate 0.0 and baseline_anomaly False.
// The UI must therefore claim nothing in any of these cases.
// ---------------------------------------------------------------------------

/** The literal `_empty()` / pre-seeded output of every ambiguous enricher. */
const EMPTY_ENRICHER_BLOB = {
  agent_name: "WIN-WKS-12",
  // HostIntegrityEnricher._empty()
  host_rootcheck_findings: 0,
  host_fim_recent_changes: 0,
  host_integrity_multiplier: 1.0,
  host_integrity_reason: "",
  host_rootcheck_signatures: [],
  host_fim_changed_paths: [],
  // VulnerabilityContextEnricher._empty()
  host_vulnerabilities_critical: 0,
  host_vulnerabilities_high: 0,
  host_sca_failed_checks: 0,
  host_top_critical_cves: [],
  vuln_context_multiplier: 1.0,
  vuln_context_reason: "",
  host_top_cve_details: [],
  // ThreatIntelEnricher pre-seed (no indicator was ever looked up)
  threat_intel_hits: 0,
  threat_intel_sources: [],
  is_known_malicious: false,
  highest_ti_severity: "none",
  // HistoricalEnricher pre-seed with NO db handle. `historical_occurrence_count`
  // IS pre-seeded (to 0) just like `historical_fp_rate`; the key that is NOT
  // pre-seeded, and therefore the only proof the query ran, is
  // `historical_window_days` — deliberately absent here.
  historical_fp_rate: 0.0,
  historical_occurrence_count: 0,
  same_rule_last_7d: 0,
  same_source_last_7d: 0,
  same_user_last_7d: 0,
  baseline_anomaly: false,
  baseline_deviation: 0.0,
  baseline_anomaly_details: [],
};

describe("QA item 1 — a pre-seeded zero never becomes an assurance", () => {
  function renderEmpty(extra: Record<string, unknown> = {}) {
    render(
      <GlassBoxAlertCard
        alert={makeAlert({
          glass_box: undefined,
          enrichment_summary: JSON.stringify({
            ...EMPTY_ENRICHER_BLOB,
            ...extra,
          }),
        })}
        primary
        onReviewed={() => {}}
      />,
    );
    openDetail();
  }

  it("never claims a check ran, a host is clean, or nothing is known", () => {
    renderEmpty();
    const body = document.body.textContent ?? "";
    for (const forbidden of [
      "checked",
      "host clean",
      "nothing known",
      "nothing unusual",
      "0% false-positive",
    ]) {
      expect(body).not.toContain(forbidden);
    }
  });

  it("says 'no signal recorded' for host integrity, vuln, baseline and history", () => {
    renderEmpty();
    // four ambiguous dimensions, all neutral. (TI has its own wording below
    // because it CAN say something factual about the missing indicator.)
    expect(screen.getAllByText("no signal recorded").length).toBe(4);
  });

  it("agrees with the TI row body when no indicator was stored to look up", () => {
    renderEmpty();
    expect(
      screen.getByText("no external indicator stored to look up"),
    ).toBeTruthy();
    // the row body one click below says the same thing — they used to
    // contradict each other ("checked, nothing known" vs "nothing to look up")
    expandRow(/^Threat intel/);
    expect(
      screen.getByText(/No external indicator \(source IP\) was stored/),
    ).toBeTruthy();
  });

  it("does not call a host clean while its own row lists a CVE", () => {
    // count keys absent/zero but a CVE IS listed — the old text read
    // "0 critical, 0 high CVEs — checked, host clean" directly above it
    renderEmpty({ host_top_critical_cves: ["CVE-2025-9999"] });
    expect(screen.getByText("1 critical CVE listed")).toBeTruthy();
    expandRow(/^Vulnerabilities/);
    expect(screen.getByText("CVE-2025-9999")).toBeTruthy();
  });

  it("only states a zero FP history when the query PROVABLY ran", () => {
    // `historical_window_days` is written only inside the enricher's
    // `if self.db and rule_id:` branch → positive proof of the lookup.
    renderEmpty({ historical_window_days: 14, historical_occurrence_count: 0 });
    expect(
      screen.getByText("no prior decisions for this rule in 14d"),
    ).toBeTruthy();
  });

  it("reports a proven FP rate with the sample size it was measured over", () => {
    renderEmpty({
      historical_window_days: 7,
      historical_occurrence_count: 40,
      historical_fp_rate: 0.6,
    });
    expect(
      screen.getByText("60% false-positive over 40 prior decisions (7d)"),
    ).toBeTruthy();
  });

  it("surfaces a degraded enricher as its own state, in amber not severity red", () => {
    renderEmpty({ degraded_enrichers: ["asset", "threat_intel", "time"] });
    const flags = screen.getAllByText("check failed — enrichment degraded");
    expect(flags.length).toBe(3);
    const weight = previewWeight("check failed — enrichment degraded");
    expect(weight).toContain("gated");
    expect(weight).not.toContain("text-sev-");
  });
});

describe("QA item 3 — the closed box surfaces findings, not routine context", () => {
  it("keeps the rootcheck finding on the strip on a tier-1 host with TI + CVE", () => {
    render(
      <GlassBoxAlertCard
        alert={makeAlert({
          glass_box: undefined,
          enrichment_summary: JSON.stringify({
            ...THIN_CASE_BLOB,
            // routine context that used to eat the crit slots
            asset_tier: "tier_1_critical",
            asset_owner: "platform-team",
            asset_environment: "production",
            user_has_admin: true,
            user_roles: ["dba"],
            // …alongside three genuine findings
            threat_intel_hits: 3,
            is_known_malicious: true,
            highest_ti_severity: "high",
            host_vulnerabilities_critical: 2,
            host_vulnerabilities_high: 4,
          }),
        })}
        primary
        onReviewed={() => {}}
      />,
    );
    // box still CLOSED — the strip must carry the host finding
    expect(screen.getByText("inside, worth your eyes")).toBeTruthy();
    expect(screen.getByText("500 open rootcheck findings")).toBeTruthy();
    // …and routine context must not have taken a slot
    expect(
      screen.queryByText("tier_1_critical · production · platform-team"),
    ).toBeNull();
    expect(
      screen.queryByText(/identity: standard, admin roles/),
    ).toBeNull();
  });
});

describe("WO-H86 — the three contradictions on one screen", () => {
  it("labels the grounding flag as a self-check, not as low confidence", () => {
    render(<GlassBoxAlertCard alert={thinCase()} primary onReviewed={() => {}} />);
    // confidence 0.9184 + a LOW grounding self-check: both true, neither
    // contradicts the other once each is labelled.
    expect(screen.getByText("Confident, but on thin evidence")).toBeTruthy();
    expect(
      screen.getByText(/the AI's own self-check, not its confidence/),
    ).toBeTruthy();
    expect(screen.queryByText(/AI not confident/)).toBeNull();
    // the confidence meter is named as such
    expect(screen.getByText("confidence")).toBeTruthy();
  });

  it("reads 'unsure, and on thin evidence' when the model was NOT confident", () => {
    render(
      <GlassBoxAlertCard
        alert={thinCase({ confidence: 0.31 })}
        primary
        onReviewed={() => {}}
      />,
    );
    expect(screen.getByText("Unsure, and on thin evidence")).toBeTruthy();
    expect(screen.queryByText("Confident, but on thin evidence")).toBeNull();
  });

  it("names the header risk number as the platform's, and the AI's figure as the model's", () => {
    render(<GlassBoxAlertCard alert={thinCase()} primary onReviewed={() => {}} />);
    // the header number is labelled where it is shown
    expect(screen.getByText("risk 96")).toBeTruthy();
    expect(screen.getByText("platform score")).toBeTruthy();

    // …and the risk-math section states which number is authoritative without
    // pretending the AI's own "86.54/100" agrees with it.
    openDetail();
    expandRow(/How was risk = 96 computed\?/);
    expect(screen.getByText(/Which number is authoritative/)).toBeTruthy();
    expect(
      screen.getByText(/that is the model's arithmetic, not\s+this score/),
    ).toBeTruthy();
  });
});

describe("WO-H86 — a collapsed disclosure must actually collapse", () => {
  /**
   * jsdom does not evaluate Tailwind, so this is asserted STRUCTURALLY. The
   * bug it pins was real and visible: `[hidden]` is a user-agent rule, and a
   * Tailwind `flex` on the same element is an author-origin `display: flex`
   * that beats it — so a "collapsed" card rendered its entire body anyway and
   * every member alert in an incident was fully expanded regardless of its
   * own button. The `hidden` element must therefore carry no display utility.
   */
  function hiddenContainersWithDisplayUtility(): string[] {
    return Array.from(document.querySelectorAll("[hidden]"))
      .map((el) => el.className)
      .filter((c) => /(^|\s)(flex|grid|block|inline-flex|table)(\s|$)/.test(c));
  }

  it("never puts a display utility on a hidden container — box CLOSED", () => {
    // The previous version opened the box first, so NEITHER fixed container
    // was carrying `hidden` and the assertion could not see the bug at all:
    // reintroducing `className="mt-2 flex flex-col"` on CaseDetailBox left the
    // whole file green. The detail box must be inspected while COLLAPSED.
    render(<GlassBoxAlertCard alert={makeAlert()} primary onReviewed={() => {}} />);
    const box = screen.getByRole("button", {
      name: /Scoring & enrichment detail/,
    });
    expect(box.getAttribute("aria-expanded")).toBe("false");
    const panel = document.getElementById(
      box.getAttribute("aria-controls") as string,
    );
    expect(panel?.hasAttribute("hidden")).toBe(true);
    expect(panel?.className ?? "").not.toMatch(
      /(^|\s)(flex|grid|block|inline-flex|table)(\s|$)/,
    );
    expect(hiddenContainersWithDisplayUtility()).toEqual([]);
  });

  it("keeps the box hidden after it is opened and closed again", () => {
    // The `everOpened` mount-gate makes the FIRST collapsed state safe even
    // with the bug present; only the second collapse exposes it.
    render(<GlassBoxAlertCard alert={makeAlert()} primary onReviewed={() => {}} />);
    openDetail(); // open  (children mount)
    openDetail(); // close (children stay mounted — `hidden` must do the work)
    const box = screen.getByRole("button", {
      name: /Scoring & enrichment detail/,
    });
    expect(box.getAttribute("aria-expanded")).toBe("false");
    const panel = document.getElementById(
      box.getAttribute("aria-controls") as string,
    );
    expect(panel?.hasAttribute("hidden")).toBe(true);
    // the risk-math row is still in the DOM, so `hidden` is the only thing
    // stopping it from painting — it must not be defeated by a display utility
    expect(panel?.textContent ?? "").toContain("How was risk");
    expect(hiddenContainersWithDisplayUtility()).toEqual([]);
  });

  it("a non-primary card keeps its whole body hidden until asked", () => {
    render(
      <GlassBoxAlertCard alert={makeAlert()} primary={false} onReviewed={() => {}} />,
    );
    const toggle = screen.getByRole("button", { name: "Show glass-box detail" });
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    const body = document.getElementById(
      toggle.getAttribute("aria-controls") as string,
    );
    expect(body?.hasAttribute("hidden")).toBe(true);
    expect(body?.className ?? "").not.toMatch(/(^|\s)flex(\s|$)/);
  });
});

// ---------------------------------------------------------------------------
// Re-audit residuals N1–N5.
// ---------------------------------------------------------------------------

describe("N3 — identity never describes a principal the store did not match", () => {
  function identityPreview(blob: Record<string, unknown>) {
    render(
      <GlassBoxAlertCard
        alert={makeAlert({
          glass_box: undefined,
          enrichment_summary: JSON.stringify(blob),
        })}
        primary
        onReviewed={() => {}}
      />,
    );
    openDetail();
    return (
      screen.getByRole("button", { name: /^Identity/ }).textContent ?? ""
    ).replace(/\s+/g, " ");
  }

  it("does not claim 'no roles' for an UNKNOWN user (roles are pre-seeded [])", () => {
    // The enricher writes user_risk_level "elevated" for an unresolved
    // username and never touches the pre-seeded empty roles list.
    const text = identityPreview({ user_risk_level: "elevated" });
    expect(text).not.toContain("no roles");
    // …and it states the one thing that IS provable: "elevated" is written
    // only in the `identity is None` branch, so the lookup ran and missed.
    expect(text).toContain("account not found in the identity store");
  });

  it("describes roles only when the store PROVABLY matched the principal", () => {
    // user_normal_hours / user_normal_ips / user_onboarded_date exist only
    // inside the `identity is not None` branch — they are the proof keys.
    const text = identityPreview({
      user_risk_level: "privileged",
      user_roles: ["dba"],
      user_has_admin: true,
      user_normal_hours: { start: 9, end: 18 },
      user_normal_ips: ["10.0.0.5"],
      user_onboarded_date: "2024-01-01",
    });
    expect(text).toContain("identity: privileged");
    expect(text).toContain("admin roles");
    expect(text).toContain("dba");
  });

  it("says 'no roles on file' — not 'no roles' — even on a matched record", () => {
    const text = identityPreview({
      user_risk_level: "standard",
      user_roles: [],
      user_normal_hours: {},
      user_normal_ips: [],
      user_onboarded_date: "",
    });
    expect(text).toContain("no roles on file");
  });

  it("stays neutral on the untouched pre-seed (system account / no user)", () => {
    const text = identityPreview({
      user_risk_level: "standard",
      user_roles: [],
      user_has_admin: false,
    });
    expect(text).toContain("no signal recorded");
    expect(text).not.toContain("no roles");
  });
});

describe("N1 — the closed strip never drops a failed check without a trace", () => {
  /** The auditor's reproduction: two degraded markers + four real findings. */
  function busyAlert() {
    return makeAlert({
      glass_box: undefined,
      enrichment_summary: JSON.stringify({
        agent_name: "WIN-WKS-12",
        src_ip: "160.250.132.238",
        degraded_enrichers: ["time", "asset"],
        asset_tier: "unknown",
        time_context: "outside_business_hours",
        threat_intel_hits: 3,
        is_known_malicious: true,
        highest_ti_severity: "high",
        host_vulnerabilities_critical: 0,
        host_vulnerabilities_high: 4,
        host_rootcheck_findings: 1,
        host_fim_recent_changes: 0,
        baseline_anomaly: true,
        baseline_deviation: 5,
        baseline_anomaly_details: [{ dimension: "src_ip", value: "x" }],
      }),
    });
  }

  it("puts BOTH degraded markers on the strip, ahead of every finding", () => {
    render(<GlassBoxAlertCard alert={busyAlert()} primary onReviewed={() => {}} />);
    // box CLOSED
    const strip = screen.getByText("inside, worth your eyes").parentElement;
    const text = (strip?.textContent ?? "").replace(/\s+/g, " ");
    // a failed check outranks a finding — it used to sort last and be capped off
    expect(text).toContain("Asset:");
    expect(text).toContain("Time context:");
    expect(text.match(/check failed — enrichment degraded/g)?.length).toBe(2);
    // …and they come BEFORE any finding on the strip
    const firstFinding = Math.min(
      ...["Threat intel:", "Vulnerabilities:"]
        .map((t) => text.indexOf(t))
        .filter((i) => i > -1),
    );
    expect(text.indexOf("Asset:")).toBeLessThan(firstFinding);
    expect(text.indexOf("Time context:")).toBeLessThan(firstFinding);
  });

  it("leaves a '+N more' trace naming everything the cap dropped", () => {
    render(<GlassBoxAlertCard alert={busyAlert()} primary onReviewed={() => {}} />);
    const more = screen.getByRole("button", { name: /\+\d+ more/ });
    const label = more.textContent ?? "";
    // the 5-sigma anomaly and the rootcheck finding vanished entirely before
    expect(label).toContain("Baseline anomaly");
    expect(label).toContain("Host integrity");
    // and the trace opens the box rather than being a dead end
    fireEvent.click(more);
    expect(
      screen
        .getByRole("button", { name: /Scoring & enrichment detail/ })
        .getAttribute("aria-expanded"),
    ).toBe("true");
  });
});

describe("N2 — an unrecognised degraded marker never reads as 'no signal'", () => {
  it("surfaces a mapped-but-previously-unhandled enricher on its own row", () => {
    // `host_integrity` is not one of the three the service emits today, but
    // the marker is a plain string list and WO-H89 adds more.
    render(
      <GlassBoxAlertCard
        alert={makeAlert({
          glass_box: undefined,
          enrichment_summary: JSON.stringify({
            agent_name: "host-a",
            degraded_enrichers: ["host_integrity", "historical"],
            host_rootcheck_findings: 0,
            host_fim_recent_changes: 0,
            historical_fp_rate: 0.0,
          }),
        })}
        primary
        onReviewed={() => {}}
      />,
    );
    openDetail();
    const hi = screen.getByRole("button", { name: /^Host integrity/ }).textContent ?? "";
    const hist = screen.getByRole("button", { name: /^FP history/ }).textContent ?? "";
    // both records would otherwise read "no signal recorded" over data that
    // positively proves their check errored
    expect(hi).toContain("check failed — enrichment degraded");
    expect(hi).not.toContain("no signal recorded");
    expect(hist).toContain("check failed — enrichment degraded");
    expect(hist).not.toContain("no signal recorded");
  });
});

describe("N4 — host integrity never renders a blank preview", () => {
  it("describes the listed findings when the count keys are 0/absent", () => {
    render(
      <GlassBoxAlertCard
        alert={makeAlert({
          glass_box: undefined,
          enrichment_summary: JSON.stringify({
            agent_name: "host-a",
            host_rootcheck_findings: 0,
            host_fim_recent_changes: 0,
            host_rootcheck_signatures: ["Rootkit Adore"],
          }),
        })}
        primary
        onReviewed={() => {}}
      />,
    );
    openDetail();
    const row = screen.getByRole("button", { name: /^Host integrity/ });
    // the row used to show NO hint at all — `parts` stayed empty and the
    // preview was "", which `Expander` renders as nothing
    expect(row.textContent).toContain("1 rootcheck finding listed");
    expect((row.textContent ?? "").trim()).not.toBe("›Host integrity");
  });
});

describe("N5 — an absent count key is never printed as a measured zero", () => {
  it("does not render '0 high CVEs' when the key was never written", () => {
    render(
      <GlassBoxAlertCard
        alert={makeAlert({
          glass_box: undefined,
          enrichment_summary: JSON.stringify({
            agent_name: "host-a",
            host_vulnerabilities_critical: 2,
            // host_vulnerabilities_high deliberately ABSENT
          }),
        })}
        primary
        onReviewed={() => {}}
      />,
    );
    openDetail();
    const row = screen.getByRole("button", { name: /^Vulnerabilities/ });
    expect(row.textContent).toContain("2 critical");
    expect(row.textContent).not.toContain("0 high CVEs");
    // and the record body shows an honest em-dash, not a fabricated 0
    expandRow(/^Vulnerabilities/);
    const line = screen.getByText("high CVEs on host").parentElement;
    expect(line?.textContent).toContain("—");
  });
});
