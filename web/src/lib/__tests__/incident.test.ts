/**
 * WO-H21 — `caseContext` / `parseEnrichmentBlob` / `riskMath` unit tests.
 * The contract under test: the stored `enrichment_summary` blob parses into
 * per-dimension context RECORDS, defensively — a missing/malformed blob yields
 * all-null (the UI's empty state), never a throw or a fabricated value.
 */
import { describe, expect, it } from "vitest";
import {
  caseContext,
  parseEnrichmentBlob,
  riskMath,
} from "../incident";
import type { IncidentAlert } from "../types";

/** A full enrichment blob with every WO-H21 dimension populated. */
const FULL_BLOB = {
  agent_name: "prod-db-01",
  agent_ip: "192.168.1.100",
  src_ip: "185.220.101.34",
  rule_mitre_techniques: ["T1078"],
  rule_mitre_tactics: ["Initial Access"],
  // asset
  asset_tier: "tier_1_critical",
  asset_owner: "platform-team",
  asset_environment: "production",
  asset_tags: ["pci", "db"],
  asset_services: ["postgres"],
  asset_criticality_multiplier: 2.0,
  // identity
  user_risk_level: "privileged",
  user_risk_multiplier: 1.8,
  user_roles: ["dba", "sudoers"],
  user_has_admin: true,
  user_is_service_account: false,
  user_department: "engineering",
  // time
  time_context: "outside_business_hours",
  is_business_hours: false,
  is_weekend: true,
  is_maintenance_window: false,
  time_risk_multiplier: 1.5,
  // TI
  threat_intel_hits: 2,
  threat_intel_sources: ["local", "abuseipdb", "local"],
  is_known_malicious: true,
  highest_ti_severity: "high",
  threat_intel_match: [
    {
      indicator: "185.220.101.34",
      type: "ip",
      source: "abuseipdb",
      severity: "high",
      last_seen: "2026-07-01",
      isp: "should-be-dropped-by-server", // server trims; parser ignores extras
    },
  ],
  // historical
  historical_fp_rate: 0.1,
  same_rule_last_7d: 4,
  same_source_last_7d: 12,
  same_user_last_7d: 3,
  previously_seen_pattern: true,
  // anomaly
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
  // vuln
  host_vulnerabilities_critical: 2,
  host_vulnerabilities_high: 5,
  host_sca_failed_checks: 7,
  host_top_critical_cves: ["CVE-2025-1234", "CVE-2025-9999"],
  vuln_context_multiplier: 1.8,
  vuln_context_reason: "host has critical CVE-2025-1234 (unpatched)",
  host_top_cve_details: [
    {
      cve: "CVE-2025-1234",
      severity: "critical",
      cvss: 9.8,
      cvss_version: "3.1",
      epss: 0.87,
      epss_percentile: 0.99,
      kev: true,
    },
    { cve: "CVE-2025-9999", severity: "critical" }, // no CVSS/EPSS/KEV → absent
  ],
  // host integrity
  host_rootcheck_findings: 1,
  host_fim_recent_changes: 14,
  host_integrity_multiplier: 1.5,
  host_integrity_reason: "host has 1 open rootcheck finding(s)",
  host_rootcheck_signatures: ["Rootkit 'Adore' detected"],
  host_fim_changed_paths: ["/etc/passwd", "/etc/shadow"],
};

function alertWith(
  enrichment_summary: IncidentAlert["enrichment_summary"],
): IncidentAlert {
  return {
    id: "dec-1",
    rule_id: 5710,
    rule_description: "sshd: authentication success.",
    verdict: "true_positive",
    confidence: 0.9,
    risk_score: 88,
    reasoning: "r",
    enrichment_summary,
  };
}

describe("parseEnrichmentBlob", () => {
  it("parses a JSON string and passes through an object", () => {
    expect(parseEnrichmentBlob(JSON.stringify({ a: 1 }))).toEqual({ a: 1 });
    expect(parseEnrichmentBlob({ a: 1 })).toEqual({ a: 1 });
  });

  it("yields null for null / empty / malformed / non-object JSON", () => {
    expect(parseEnrichmentBlob(null)).toBeNull();
    expect(parseEnrichmentBlob(undefined)).toBeNull();
    expect(parseEnrichmentBlob("")).toBeNull();
    expect(parseEnrichmentBlob("{not json")).toBeNull();
    expect(parseEnrichmentBlob("[1,2]")).toBeNull();
    expect(parseEnrichmentBlob('"scalar"')).toBeNull();
  });
});

describe("caseContext — full blob", () => {
  const ctx = caseContext(alertWith(JSON.stringify(FULL_BLOB)));

  it("extracts the asset record (hostname, criticality, owner)", () => {
    expect(ctx.asset).toEqual({
      hostname: "prod-db-01",
      agentIp: "192.168.1.100",
      tier: "tier_1_critical",
      owner: "platform-team",
      environment: "production",
      tags: ["pci", "db"],
      services: ["postgres"],
    });
  });

  it("extracts the identity record (privileged? account type)", () => {
    expect(ctx.identity).toEqual({
      riskLevel: "privileged",
      roles: ["dba", "sudoers"],
      hasAdmin: true,
      isServiceAccount: false,
      department: "engineering",
    });
  });

  it("extracts time, MITRE and TI records (TI sources deduped)", () => {
    expect(ctx.time?.context).toBe("outside_business_hours");
    expect(ctx.time?.isWeekend).toBe(true);
    expect(ctx.mitre).toEqual({
      techniqueIds: ["T1078"],
      tacticIds: ["Initial Access"],
    });
    expect(ctx.ti).toEqual({
      hits: 2,
      sources: ["local", "abuseipdb"],
      highestSeverity: "high",
      isKnownMalicious: true,
      srcIp: "185.220.101.34",
      matches: [
        {
          indicator: "185.220.101.34",
          type: "ip",
          source: "abuseipdb",
          severity: "high",
          category: null,
          lastSeen: "2026-07-01",
          description: null,
        },
      ],
    });
  });

  it("extracts historical + anomaly records", () => {
    expect(ctx.historical?.fpRate).toBe(0.1);
    expect(ctx.historical?.sameSource7d).toBe(12);
    expect(ctx.anomaly?.isAnomaly).toBe(true);
    expect(ctx.anomaly?.deviation).toBe(3.4);
    expect(ctx.anomaly?.details).toHaveLength(1);
    expect(ctx.anomaly?.details[0].dimension).toBe("src_ip");
    expect(ctx.anomaly?.details[0].zScore).toBe(3.4);
  });

  it("extracts vuln (CVEs) + host-integrity (FIM/rootcheck) records", () => {
    expect(ctx.vuln).toEqual({
      critical: 2,
      high: 5,
      scaFailed: 7,
      topCves: ["CVE-2025-1234", "CVE-2025-9999"],
      reason: "host has critical CVE-2025-1234 (unpatched)",
      topCveDetails: [
        {
          cve: "CVE-2025-1234",
          severity: "critical",
          cvss: 9.8,
          cvssVersion: "3.1",
          epss: 0.87,
          epssPercentile: 0.99,
          kev: true,
        },
        {
          cve: "CVE-2025-9999",
          severity: "critical",
          cvss: null,
          cvssVersion: null,
          epss: null,
          epssPercentile: null,
          kev: null, // no `kev` in the blob → unknown, not a definitive false
        },
      ],
    });
    expect(ctx.hostIntegrity).toEqual({
      rootcheckFindings: 1,
      fimRecentChanges: 14,
      reason: "host has 1 open rootcheck finding(s)",
      rootcheckSignatures: ["Rootkit 'Adore' detected"],
      fimChangedPaths: ["/etc/passwd", "/etc/shadow"],
    });
  });

  it("WO-H23: TI match trims to the whitelist (drops server-side extras)", () => {
    // The `isp` field in the blob is NOT surfaced — the parser whitelists keys.
    expect(ctx.ti?.matches[0]).not.toHaveProperty("isp");
  });
});

describe("caseContext — degraded blobs", () => {
  it("missing blob → every dimension null (the UI empty state)", () => {
    const ctx = caseContext(alertWith(null));
    expect(Object.values(ctx).every((v) => v === null)).toBe(true);
  });

  it("malformed JSON → every dimension null, never a throw", () => {
    const ctx = caseContext(alertWith("{definitely not json"));
    expect(Object.values(ctx).every((v) => v === null)).toBe(true);
  });

  it("partial blob → only the present dimensions, honest field defaults", () => {
    const ctx = caseContext(
      alertWith(JSON.stringify({ asset_tier: "unknown" })),
    );
    expect(ctx.asset).not.toBeNull();
    expect(ctx.asset?.tier).toBe("unknown");
    expect(ctx.asset?.owner).toBeNull();
    expect(ctx.identity).toBeNull();
    expect(ctx.ti).toBeNull();
    expect(ctx.vuln).toBeNull();
    expect(ctx.hostIntegrity).toBeNull();
  });

  it("wrong-typed fields degrade per-field, never fabricate", () => {
    const ctx = caseContext(
      alertWith(
        JSON.stringify({
          threat_intel_hits: "lots",
          threat_intel_sources: 42,
          baseline_anomaly: "yes",
          baseline_anomaly_details: "not-a-list",
        }),
      ),
    );
    expect(ctx.ti?.hits).toBe(0);
    expect(ctx.ti?.sources).toEqual(["42"]);
    expect(ctx.anomaly?.isAnomaly).toBe(false);
    expect(ctx.anomaly?.details).toEqual([]);
  });
});

describe("caseContext — WO-H23 finding-level detail", () => {
  it("parses TI matches, CVE details and FIM/rootcheck detail when present", () => {
    const ctx = caseContext(
      alertWith(
        JSON.stringify({
          threat_intel_match: [
            { indicator: "9.9.9.9", type: "ip", source: "otx",
              category: "APT29" },
          ],
          host_top_cve_details: [
            { cve: "CVE-1", severity: "critical", cvss: 7.5, kev: false },
          ],
          host_rootcheck_signatures: ["rootkit X"],
          host_fim_changed_paths: ["/etc/hosts"],
        }),
      ),
    );
    expect(ctx.ti?.matches).toEqual([
      { indicator: "9.9.9.9", type: "ip", source: "otx", severity: null,
        category: "APT29", lastSeen: null, description: null },
    ]);
    expect(ctx.vuln?.topCveDetails[0]).toMatchObject({
      cve: "CVE-1", cvss: 7.5, kev: false, epss: null,
    });
    expect(ctx.hostIntegrity?.rootcheckSignatures).toEqual(["rootkit X"]);
    expect(ctx.hostIntegrity?.fimChangedPaths).toEqual(["/etc/hosts"]);
  });

  it("parses KEV as a tri-state (true / false / unknown), never a guess", () => {
    const ctx = caseContext(
      alertWith(
        JSON.stringify({
          host_vulnerabilities_critical: 3,
          host_top_cve_details: [
            { cve: "CVE-A", kev: true }, // genuinely in KEV
            { cve: "CVE-B", kev: false }, // catalog populated, not in KEV
            { cve: "CVE-C" }, // no kev field → unknown
          ],
        }),
      ),
    );
    const d = ctx.vuln?.topCveDetails ?? [];
    expect(d[0].kev).toBe(true);
    expect(d[1].kev).toBe(false);
    expect(d[2].kev).toBeNull(); // unknown, NOT coerced to false
  });

  it("degrades finding detail to empty on missing / malformed values", () => {
    // Present base dimensions but malformed finding-detail fields.
    const ctx = caseContext(
      alertWith(
        JSON.stringify({
          threat_intel_hits: 1,
          threat_intel_match: "not-a-list",
          host_vulnerabilities_critical: 1,
          host_top_cve_details: [{ noCve: true }, 5, null],
          host_rootcheck_findings: 1,
          host_rootcheck_signatures: [1, "", "ok"],
          host_fim_changed_paths: 42,
        }),
      ),
    );
    // TI dimension still present (from hits), but matches empty — never a throw.
    expect(ctx.ti?.matches).toEqual([]);
    // CVE entries with no `cve` are dropped; bad entries ignored.
    expect(ctx.vuln?.topCveDetails).toEqual([]);
    // Non-string signatures filtered; non-array paths → [].
    expect(ctx.hostIntegrity?.rootcheckSignatures).toEqual(["ok"]);
    expect(ctx.hostIntegrity?.fimChangedPaths).toEqual([]);
  });

  it("older decision without the new keys → empty finding detail, no crash", () => {
    const ctx = caseContext(
      alertWith(
        JSON.stringify({
          threat_intel_hits: 1,
          host_vulnerabilities_critical: 1,
          host_rootcheck_findings: 1,
        }),
      ),
    );
    expect(ctx.ti?.matches).toEqual([]);
    expect(ctx.vuln?.topCveDetails).toEqual([]);
    expect(ctx.hostIntegrity?.rootcheckSignatures).toEqual([]);
    expect(ctx.hostIntegrity?.fimChangedPaths).toEqual([]);
  });
});

describe("riskMath — host-integrity factor (M6b) is in the chain", () => {
  it("surfaces host_integrity_multiplier when it moved the score", () => {
    const math = riskMath({
      base_severity: 66.7,
      asset_multiplier: 2.0,
      host_integrity_multiplier: 1.5,
      raw_score: 200,
      clamped_score: 100,
    });
    expect(math?.factors.map((f) => f.key)).toEqual([
      "asset_multiplier",
      "host_integrity_multiplier",
    ]);
  });

  it("elides a no-op host-integrity multiplier (1.0)", () => {
    const math = riskMath({
      base_severity: 40,
      host_integrity_multiplier: 1.0,
    });
    expect(math?.factors).toEqual([]);
  });
});
