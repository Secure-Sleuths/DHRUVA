/**
 * WO-H21 — GlassBoxAlertCard component tests: the case renders each inline
 * context record when present, honest empty states when the enrichment blob is
 * missing/malformed, and the lazy raw-event + playbook drills. The API module
 * is mocked (this is a render contract test, not a network test); RBAC's
 * useAuth is mocked to a plain analyst — viewing context has NO role gate.
 */
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
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
  lookupIoc,
} from "@/lib/api";

afterEach(cleanup);

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

describe("ContextRecordsSection — every moved factor exposes its record", () => {
  it("renders one expandable row per moved risk factor", () => {
    render(<GlassBoxAlertCard alert={makeAlert()} primary onReviewed={() => {}} />);
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
    expandRow(/Asset — ×2/);
    expect(screen.getByText("prod-db-01")).toBeTruthy();
    expect(screen.getByText("tier_1_critical")).toBeTruthy();
    expect(screen.getByText("platform-team")).toBeTruthy();
  });

  it("identity row shows the principal (privileged? account type)", () => {
    render(<GlassBoxAlertCard alert={makeAlert()} primary onReviewed={() => {}} />);
    expandRow(/Identity — ×1\.8/);
    expect(screen.getByText("yes — admin roles")).toBeTruthy();
    expect(screen.getByText("user account")).toBeTruthy();
    // "privileged" appears as both a label and the risk-level value
    expect(screen.getAllByText("privileged").length).toBeGreaterThan(0);
  });

  it("vuln row shows the CVEs; host-integrity row shows the finding", () => {
    render(<GlassBoxAlertCard alert={makeAlert()} primary onReviewed={() => {}} />);
    expandRow(/Vulnerabilities — ×1\.8/);
    expect(screen.getByText("CVE-2025-1234")).toBeTruthy();
    expandRow(/Host integrity — ×1\.5/);
    expect(
      screen.getByText("host has 1 open rootcheck finding(s)"),
    ).toBeTruthy();
  });

  it("WO-H23: vuln row shows per-CVE CVSS / EPSS / KEV inline", () => {
    render(<GlassBoxAlertCard alert={makeAlert()} primary onReviewed={() => {}} />);
    expandRow(/Vulnerabilities — ×1\.8/);
    expect(screen.getByText("Top critical CVEs — CVSS / EPSS / KEV")).toBeTruthy();
    expect(screen.getByText("9.8 (v3.1)")).toBeTruthy(); // CVSS + version
    expect(screen.getByText("87.0%")).toBeTruthy(); // EPSS as percent
    expect(screen.getByText("CISA KEV")).toBeTruthy();
  });

  it("WO-H23: host-integrity row shows FIM paths + rootcheck signatures", () => {
    render(<GlassBoxAlertCard alert={makeAlert()} primary onReviewed={() => {}} />);
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
    expandRow(/Vulnerabilities — ×1\.8/);
    expect(screen.getByText("not in KEV")).toBeTruthy();
    expect(screen.queryByText("KEV data unavailable")).toBeNull();
  });

  it("TI row shows the exact matched indicator + lazy-loads the IOC lookup", async () => {
    render(<GlassBoxAlertCard alert={makeAlert()} primary onReviewed={() => {}} />);
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
    expandRow(/Identity — ×1\.8/);
    expect(screen.getAllByText(/No identity record was stored/).length).toBe(1);
  });

  it("no breakdown → falls back to the dimensions that HAVE records", () => {
    render(
      <GlassBoxAlertCard
        alert={makeAlert({ glass_box: undefined })}
        primary
        onReviewed={() => {}}
      />,
    );
    // No multiplier suffix without a recorded breakdown — plain titles.
    // (Accessible names concatenate the summary + hint spans.)
    expect(screen.getByRole("button", { name: /^Asset/ })).toBeTruthy();
    expect(
      screen.getByRole("button", { name: /^Host integrity/ }),
    ).toBeTruthy();
  });

  it("neither breakdown nor records → the section renders nothing", () => {
    render(
      <GlassBoxAlertCard
        alert={makeAlert({ enrichment_summary: null, glass_box: undefined })}
        primary
        onReviewed={() => {}}
      />,
    );
    expect(
      screen.queryByText(/Context behind the score/),
    ).toBeNull();
  });
});

describe("RawEventExpander — the raw Wazuh event, lazy", () => {
  it("fetches only on first expand and renders full_log + JSON", async () => {
    render(<GlassBoxAlertCard alert={makeAlert()} primary onReviewed={() => {}} />);
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
    expandRow(/Raw Wazuh event/);
    expect(
      await screen.findByText(/was not found in the enriched-alert index/),
    ).toBeTruthy();
  });
});

describe("PlaybookExpander — matched playbook content, lazy", () => {
  it("renders steps + escalation criteria on expand", async () => {
    render(<GlassBoxAlertCard alert={makeAlert()} primary onReviewed={() => {}} />);
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
    expandRow(/Matched playbook/);
    expect(
      await screen.findByText(/general investigation methodology/),
    ).toBeTruthy();
  });
});
