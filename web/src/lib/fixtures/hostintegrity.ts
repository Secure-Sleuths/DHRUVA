/**
 * Host Integrity FIXTURE — screenshot / dev-preview only (WO-U9).
 *
 * Reached solely from `api.ts::{getAgents,getAgentSyscheck,getAgentRootcheck,
 * getAgentRegistry,getVulnSummary}` when `NEXT_PUBLIC_DHRUVA_FIXTURES` is set, via
 * dynamic import so it is dead-code-eliminated from a normal production bundle.
 *
 * Fabricates NO capability — mirrors the Wazuh 4.x native passthrough shapes
 * (`enrichment/wazuh_client.py`) and the `/api/vulnerabilities/summary` computed
 * dict (`response.py`).
 *
 * Under `locked` the HOST-INTEGRITY reads (syscheck/rootcheck/registry) and the
 * VULN summary each THROW ApiError(403) — matching the distinct `host_integrity`
 * and `compliance_sca` gates — while the agent list still returns populated
 * (agents are not license-gated), so the tab's per-section degradation is real.
 */

import { ApiError } from "../api";
import type {
  AgentsResponse,
  AgentPackagesResponse,
  AgentPortsResponse,
  AgentProcessesResponse,
  AgentVulnerability,
  AgentVulnerabilitiesResponse,
  CriticalVulnerabilitiesResponse,
  VulnRemediation,
  VulnRemediationResponse,
  RegistryResponse,
  RootcheckResponse,
  ScaChecksResponse,
  ScaPoliciesResponse,
  SyscheckResponse,
  VulnSummary,
} from "../types";

interface Opts {
  empty?: boolean;
  locked?: boolean;
}

function hostIntegrityLocked(): never {
  throw new ApiError(
    403,
    "Host integrity (FIM / rootcheck / registry) is not available on this plan. Contact SecureSleuths to upgrade.",
  );
}

function complianceLocked(): never {
  throw new ApiError(
    403,
    "Vulnerability data is not available on this plan. Contact SecureSleuths to upgrade.",
  );
}

const AGENTS: AgentsResponse = {
  agents: [
    {
      id: "001",
      name: "WIN-APP-03",
      ip: "10.4.2.19",
      status: "active",
      os: { name: "Microsoft Windows Server 2022", platform: "windows", version: "10.0.20348" },
      version: "Wazuh v4.9.0",
      lastKeepAlive: "2026-07-02T05:58:00Z",
      group: ["default", "windows"],
    },
    {
      id: "002",
      name: "FIN-WKS-11",
      ip: "10.4.7.51",
      status: "active",
      os: { name: "Microsoft Windows 11 Pro", platform: "windows", version: "10.0.22631" },
      version: "Wazuh v4.9.0",
      lastKeepAlive: "2026-07-02T05:57:30Z",
      group: ["default", "workstations"],
    },
    {
      id: "003",
      name: "VPN-GW-01",
      ip: "10.4.0.2",
      status: "disconnected",
      os: { name: "Ubuntu", platform: "ubuntu", version: "22.04.4 LTS" },
      version: "Wazuh v4.8.2",
      lastKeepAlive: "2026-07-01T22:14:00Z",
      group: ["default", "linux"],
    },
  ],
  total: 3,
};

const SYSCHECK: SyscheckResponse = {
  syscheck: [
    {
      file: "C:\\Windows\\System32\\drivers\\etc\\hosts",
      type: "modified",
      mtime: "2026-07-02T03:41:12Z",
      size: 842,
      perm: "rw-rw-rw-",
      uname: "SYSTEM",
      md5: "3b1c2d9f0a7e5b4c8d6f1a2e3b4c5d6e",
      sha1: "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
      sha256:
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      date: "2026-07-02T03:41:20Z",
    },
    {
      file: "C:\\ProgramData\\svc-deploy\\agent.conf",
      type: "added",
      mtime: "2026-07-02T02:39:00Z",
      size: 1204,
      perm: "rw-r--r--",
      uname: "svc-deploy",
      md5: "7d793037a0760186574b0282f2f435e7",
      sha1: "b7e23ec29af22b0b4e41da31e868d57226121c84",
      sha256:
        "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
      date: "2026-07-02T02:39:10Z",
    },
    {
      file: "C:\\Windows\\Temp\\m.dmp",
      type: "added",
      mtime: "2026-07-02T02:41:55Z",
      size: 41336320,
      perm: "rw-rw-rw-",
      uname: "svc-deploy",
      md5: "e2fc714c4727ee9395f324cd2e7f331f",
      sha1: "c3499c2729730a7f807efb8676a92dcb6f8a3f8f",
      sha256:
        "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730",
      date: "2026-07-02T02:42:00Z",
    },
  ],
  total: 3,
};

const ROOTCHECK: RootcheckResponse = {
  rootcheck: [
    {
      title: "SSH Hardening: Root login is allowed",
      log: "SSH Configuration - Root can log in: /etc/ssh/sshd_config",
      status: "outstanding",
      cis: "5.2.10",
      pci_dss: "2.2.4",
      date_first: "2026-06-20T10:00:00Z",
      date_last: "2026-07-02T04:00:00Z",
      event: "policy monitoring",
    },
    {
      title: "System audit: Password expiration not set",
      log: "System Audit - /etc/login.defs PASS_MAX_DAYS unset",
      status: "outstanding",
      cis: "5.4.1.1",
      pci_dss: "8.2.4",
      date_first: "2026-06-20T10:00:00Z",
      date_last: "2026-07-02T04:00:00Z",
      event: "policy monitoring",
    },
    {
      title: "Web directory world-writable",
      log: "Trojan/anomaly check - /var/www writable by others",
      status: "solved",
      cis: null,
      pci_dss: "2.2.4",
      date_first: "2026-06-18T10:00:00Z",
      date_last: "2026-06-30T04:00:00Z",
      event: "policy monitoring",
    },
  ],
  total: 3,
};

const REGISTRY: RegistryResponse = {
  registry: [
    {
      file: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
      type: "added",
      mtime: "2026-07-02T02:38:00Z",
      size: 96,
      perm: "-",
      md5: "c4ca4238a0b923820dcc509a6f75849b",
      sha1: "356a192b7913b04c54574d18c28d46e6395428ab",
      date: "2026-07-02T02:38:20Z",
    },
    {
      file: "HKLM\\System\\CurrentControlSet\\Services\\WinDefend\\Start",
      type: "modified",
      mtime: "2026-07-02T02:40:10Z",
      size: 4,
      perm: "-",
      md5: "eccbc87e4b5ce2fe28308fd9f2a7baf3",
      sha1: "77de68daecd823babbb58edb1c8e14d7106e83bb",
      date: "2026-07-02T02:40:15Z",
    },
  ],
  total: 2,
};

const VULN_SUMMARY: VulnSummary = {
  total_vulnerabilities: 1387,
  by_severity: { Critical: 42, High: 318, Medium: 771, Low: 256 },
  affected_agents: 3,
  top_cves: [
    { cve: "CVE-2024-3400", count: 3 },
    { cve: "CVE-2024-21762", count: 2 },
    { cve: "CVE-2023-4966", count: 2 },
    { cve: "CVE-2025-0282", count: 1 },
  ],
};

export function agentsFixture(opts: { empty?: boolean }): AgentsResponse {
  return opts.empty ? { agents: [], total: 0 } : AGENTS;
}

export function syscheckFixture(opts: Opts): SyscheckResponse {
  if (opts.locked) hostIntegrityLocked();
  return opts.empty ? { syscheck: [], total: 0 } : SYSCHECK;
}

export function rootcheckFixture(opts: Opts): RootcheckResponse {
  if (opts.locked) hostIntegrityLocked();
  return opts.empty ? { rootcheck: [], total: 0 } : ROOTCHECK;
}

export function registryFixture(opts: Opts): RegistryResponse {
  if (opts.locked) hostIntegrityLocked();
  return opts.empty ? { registry: [], total: 0 } : REGISTRY;
}

export function vulnSummaryFixture(opts: Opts): VulnSummary {
  if (opts.locked) complianceLocked();
  return opts.empty
    ? { total_vulnerabilities: 0, by_severity: {}, affected_agents: 0, top_cves: [] }
    : VULN_SUMMARY;
}

// Raw Wazuh vuln docs (ECS-style nested passthrough), keyed by agent id. Mirrors
// the `_source` shape `response.py` returns verbatim from OpenSearch.
const vuln = (
  agentId: string,
  agentName: string,
  cve: string,
  severity: string,
  base: number,
  pkg: string,
  version: string,
  platform: string,
): AgentVulnerability => ({
  agent: { id: agentId, name: agentName },
  vulnerability: {
    id: cve,
    severity,
    score: { base, version: "3.1" },
    reference: `https://nvd.nist.gov/vuln/detail/${cve}`,
  },
  package: { name: pkg, version },
  host: { os: { platform } },
});

const AGENT_VULNS: Record<string, AgentVulnerability[]> = {
  "001": [
    vuln("001", "WIN-APP-03", "CVE-2024-3400", "Critical", 10.0, "GlobalProtect", "11.0.1", "windows"),
    vuln("001", "WIN-APP-03", "CVE-2023-4966", "High", 7.5, "netscaler-gateway", "13.1-49.13", "windows"),
    vuln("001", "WIN-APP-03", "CVE-2024-21762", "High", 8.6, "openssl", "3.0.11", "windows"),
    vuln("001", "WIN-APP-03", "CVE-2025-0282", "Medium", 5.4, "curl", "8.4.0", "windows"),
  ],
  "002": [
    vuln("002", "FIN-WKS-11", "CVE-2024-38063", "Critical", 9.8, "tcpip.sys", "10.0.22631.3007", "windows"),
    vuln("002", "FIN-WKS-11", "CVE-2024-30078", "High", 8.8, "wifi-driver", "22.180.0", "windows"),
  ],
  "003": [
    vuln("003", "VPN-GW-01", "CVE-2024-6387", "High", 8.1, "openssh-server", "8.9p1-3ubuntu0.6", "ubuntu"),
  ],
};

export function agentVulnerabilitiesFixture(
  agentId: string,
  opts: Opts,
): AgentVulnerabilitiesResponse {
  if (opts.locked) complianceLocked();
  if (opts.empty) return { vulnerabilities: [], total: 0 };
  const rows = AGENT_VULNS[agentId] ?? [];
  return { vulnerabilities: rows, total: rows.length };
}

// ---- WO-U15 (READ half): fleet critical vulns + advisory remediation --------
// `criticalVulnsFixture` mirrors the raw Wazuh `_source` passthrough of
// `/api/vulnerabilities/critical` (with `agent` + optional `vulnerability.title`);
// `vulnRemediationFixture` mirrors the `_generate_remediation` dict of
// `/api/vulnerabilities/remediation` — ADVISORY only, no execute path. Both ride
// the `compliance_sca` gate, so under `locked` they THROW like the vuln reads.

const CRITICAL_VULNS: AgentVulnerability[] = [
  {
    agent: { id: "001", name: "WIN-APP-03" },
    vulnerability: {
      id: "CVE-2024-3400",
      severity: "Critical",
      score: { base: 10.0, version: "3.1" },
      reference: "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
      title: "PAN-OS GlobalProtect OS command injection",
    },
    package: { name: "GlobalProtect", version: "11.0.1" },
    host: { os: { platform: "windows" } },
  },
  {
    agent: { id: "002", name: "FIN-WKS-11" },
    vulnerability: {
      id: "CVE-2024-38063",
      severity: "Critical",
      score: { base: 9.8, version: "3.1" },
      reference: "https://nvd.nist.gov/vuln/detail/CVE-2024-38063",
      title: "Windows TCP/IP remote code execution",
    },
    package: { name: "tcpip.sys", version: "10.0.22631.3007" },
    host: { os: { platform: "windows" } },
  },
  {
    // Sparse doc — missing package + title exercise the dash fallbacks.
    agent: { id: "003", name: "VPN-GW-01" },
    vulnerability: {
      id: "CVE-2025-0282",
      severity: "Critical",
      score: { base: 9.0, version: "3.1" },
    },
    host: { os: { platform: "ubuntu" } },
  },
];

export function criticalVulnsFixture(
  opts: Opts,
): CriticalVulnerabilitiesResponse {
  if (opts.locked) complianceLocked();
  if (opts.empty) return { vulnerabilities: [], total: 0 };
  return { vulnerabilities: CRITICAL_VULNS, total: CRITICAL_VULNS.length };
}

const REMEDIATIONS: Record<string, VulnRemediation[]> = {
  "001": [
    {
      cve_id: "CVE-2024-3400",
      package_name: "GlobalProtect",
      current_version: "11.0.1",
      fix_version: "11.0.2",
      fix_hint: "Update to version >= 11.0.2",
      cvss_score: 10.0,
      severity: "Critical",
      command:
        '# Windows — update via vendor or package manager:\nwinget upgrade "GlobalProtect"\n# Or download latest from: https://nvd.nist.gov/vuln/detail/CVE-2024-3400',
      method: "winget / vendor update",
      platform: "windows",
      reference: "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
    },
    {
      cve_id: "CVE-2024-21762",
      package_name: "openssl",
      current_version: "3.0.11",
      fix_hint: "Update to latest version",
      cvss_score: 8.6,
      severity: "High",
      // Sparse remediation — no command exercises the dash fallback.
      method: "manual",
      platform: "windows",
    },
  ],
  "003": [
    {
      cve_id: "CVE-2024-6387",
      package_name: "openssh-server",
      current_version: "8.9p1-3ubuntu0.6",
      fix_hint: "Update to latest version",
      cvss_score: 8.1,
      severity: "High",
      command:
        "sudo apt update && sudo apt install --only-upgrade openssh-server",
      method: "apt",
      platform: "ubuntu",
    },
  ],
};

export function vulnRemediationFixture(
  agentId: string,
  opts: Opts,
): VulnRemediationResponse {
  if (opts.locked) complianceLocked();
  if (opts.empty) return { remediations: [], total: 0 };
  const rows = REMEDIATIONS[agentId] ?? [];
  return { remediations: rows, total: rows.length };
}

// ---- WO-U14: syscollector inventory + SCA -----------------------------------
// These endpoints are `verify_jwt` only (no license gate), so — like the agent
// list — they stay POPULATED under `locked` and never throw. Shapes mirror the
// Wazuh 4.x syscollector / SCA `affected_items` passthrough.

const PROCESSES: AgentProcessesResponse = {
  processes: [
    { name: "System", pid: 4, ppid: 0, state: "R", euser: "SYSTEM", cmd: null },
    { name: "svchost.exe", pid: 812, ppid: 660, state: "R", euser: "SYSTEM", cmd: "C:\\Windows\\System32\\svchost.exe -k netsvcs" },
    { name: "powershell.exe", pid: 5140, ppid: 4820, state: "R", euser: "svc-deploy", cmd: "powershell.exe -nop -w hidden -enc ..." },
    { name: "sshd", pid: 1188, ppid: 1, state: "S", euser: "root", command: "/usr/sbin/sshd -D" },
  ],
  total: 4,
};

const PORTS: AgentPortsResponse = {
  ports: [
    { protocol: "tcp", local: { ip: "0.0.0.0", port: 22 }, state: "listening", process: "sshd", pid: 1188 },
    { protocol: "tcp", local: { ip: "0.0.0.0", port: 3389 }, state: "listening", process: "svchost.exe", pid: 812 },
    { protocol: "tcp", local: { ip: "10.4.2.19", port: 49712 }, state: "established", process: "powershell.exe", pid: 5140 },
    { protocol: "udp", local_ip: "0.0.0.0", local_port: 123, state: null, process: "w32time", pid: 900 },
  ],
  total: 4,
};

const PACKAGES: AgentPackagesResponse = {
  packages: [
    { name: "openssl", version: "3.0.11", architecture: "x86_64", format: "rpm", vendor: "Red Hat, Inc." },
    { name: "openssh-server", version: "8.9p1-3ubuntu0.6", arch: "amd64", format: "deb", vendor: "Ubuntu" },
    { name: "Microsoft Edge", version: "126.0.2592.87", architecture: "x86_64", format: "win", vendor: "Microsoft Corporation" },
    { name: "curl", version: "8.4.0", architecture: null, format: "deb", vendor: null },
  ],
  total: 4,
};

const SCA_POLICIES: ScaPoliciesResponse = {
  policies: [
    {
      policy_id: "cis_win2022",
      name: "CIS Microsoft Windows Server 2022 Benchmark",
      pass: 214,
      fail: 63,
      invalid: 4,
      score: 77,
      total_checks: 281,
      end_scan: "2026-07-02T04:12:00Z",
    },
    {
      policy_id: "cis_ubuntu2204",
      name: "CIS Ubuntu Linux 22.04 LTS Benchmark",
      pass: 158,
      fail: 41,
      invalid: 0,
      score: 79,
      total_checks: 199,
      end_scan: "2026-07-02T04:05:00Z",
    },
  ],
  total: 2,
};

const SCA_CHECKS: Record<string, ScaChecksResponse> = {
  cis_win2022: {
    checks: [
      {
        id: 15000,
        title: "Ensure 'Enforce password history' is set to '24 or more password(s)'",
        result: "passed",
        rationale: "Prevents reuse of recent passwords, reducing credential-stuffing success.",
        remediation: "Set Enforce password history to 24 via Group Policy.",
        compliance: [{ cis: ["1.1.1"] }],
      },
      {
        id: 15044,
        title: "Ensure 'Allow Basic authentication' for WinRM Client is 'Disabled'",
        result: "failed",
        rationale: "Basic auth sends credentials in clear-text-equivalent encoding.",
        remediation: "Set WinRM Client Basic authentication to Disabled.",
        compliance: [{ cis: ["18.9.97.1.1"] }],
      },
      {
        id: 15102,
        title: "Ensure 'Configure SMB v1 client driver' is set to 'Disable driver'",
        result: "failed",
        rationale: "SMBv1 is deprecated and exploitable (EternalBlue).",
        remediation: "Disable the SMBv1 client driver.",
        compliance: null,
      },
      {
        id: 15210,
        title: "Ensure 'Bluetooth' audit policy applies (workstation only)",
        result: "not applicable",
        rationale: null,
        remediation: null,
        compliance: null,
      },
    ],
    total: 4,
  },
  cis_ubuntu2204: {
    checks: [
      {
        id: 27001,
        title: "Ensure permissions on /etc/ssh/sshd_config are configured",
        result: "passed",
        rationale: "Protects the SSH daemon configuration from tampering.",
        remediation: "chown root:root /etc/ssh/sshd_config && chmod 600 …",
        compliance: [{ cis: ["5.2.1"] }],
      },
      {
        id: 27014,
        title: "Ensure SSH root login is disabled",
        result: "failed",
        rationale: "Direct root SSH removes per-user accountability and widens attack surface.",
        remediation: "Set PermitRootLogin no in /etc/ssh/sshd_config and reload sshd.",
        compliance: [{ cis: ["5.2.10"] }],
      },
    ],
    total: 2,
  },
};

export function agentProcessesFixture(
  _agentId: string,
  opts: { empty?: boolean },
): AgentProcessesResponse {
  return opts.empty ? { processes: [], total: 0 } : PROCESSES;
}

export function agentPortsFixture(
  _agentId: string,
  opts: { empty?: boolean },
): AgentPortsResponse {
  return opts.empty ? { ports: [], total: 0 } : PORTS;
}

export function agentPackagesFixture(
  _agentId: string,
  opts: { empty?: boolean },
): AgentPackagesResponse {
  return opts.empty ? { packages: [], total: 0 } : PACKAGES;
}

export function agentComplianceFixture(
  _agentId: string,
  opts: { empty?: boolean },
): ScaPoliciesResponse {
  return opts.empty ? { policies: [], total: 0 } : SCA_POLICIES;
}

export function agentCompliancePolicyFixture(
  _agentId: string,
  policyId: string,
  opts: { empty?: boolean },
): ScaChecksResponse {
  if (opts.empty) return { checks: [], total: 0 };
  return SCA_CHECKS[policyId] ?? { checks: [], total: 0 };
}
