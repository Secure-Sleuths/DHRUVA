/**
 * Admin FIXTURE — screenshot / dev-preview only (WO-U9).
 *
 * Reached solely from `api.ts::{getAdminUsers,getAdminTenants}` when
 * `NEXT_PUBLIC_DHRUVA_FIXTURES` is set, via dynamic import so it is
 * dead-code-eliminated from a normal production bundle. The real path calls the
 * live `GET /api/admin/users` + `GET /api/admin/tenants`.
 *
 * Fabricates NO capability — mirrors `store.py::get_all_users` (safe column set,
 * NO password_hash/salt, is_active int 0/1) and the `admin.py::list_tenants`
 * metadata-only projection (config KEY names + boolean flags, never values).
 * The Admin tab's license panel is sourced from the license/tier-info the app
 * already loaded (`useAuth().tier`), so it needs no separate fixture here.
 */

import type {
  AdminAnonMappingsResponse,
  AdminAssetsResponse,
  AdminAuditLogResponse,
  AdminConfigResponse,
  AdminDataAccessPolicy,
  AdminGovernanceCharterResponse,
  AdminIdentitiesResponse,
  AdminLocalIocsResponse,
  AdminTenantsResponse,
  AdminUsersResponse,
  DecisionCacheResponse,
  TenantAgentsResponse,
} from "../types";

interface Opts {
  empty?: boolean;
}

const USERS: AdminUsersResponse = {
  users: [
    {
      id: "u-001",
      username: "a.mehra",
      display_name: "Aditi Mehra",
      email: "aditi@acme.example",
      role: "admin",
      is_active: 1,
      created_at: "2026-01-14T09:00:00Z",
      updated_at: "2026-06-30T12:00:00Z",
    },
    {
      id: "u-002",
      username: "s.okafor",
      display_name: "Sam Okafor",
      email: "sam@acme.example",
      role: "senior_analyst",
      is_active: 1,
      created_at: "2026-02-02T09:00:00Z",
      updated_at: "2026-07-01T08:00:00Z",
    },
    {
      id: "u-003",
      username: "r.kim",
      display_name: "Riya Kim",
      email: "riya@acme.example",
      role: "analyst",
      is_active: 1,
      created_at: "2026-03-18T09:00:00Z",
      updated_at: "2026-06-28T16:00:00Z",
    },
    {
      id: "u-004",
      username: "auditor",
      display_name: "Compliance Auditor",
      email: "audit@acme.example",
      role: "read_only",
      is_active: 0,
      created_at: "2026-04-01T09:00:00Z",
      updated_at: "2026-05-20T10:00:00Z",
    },
  ],
  total: 4,
};

const TENANTS: AdminTenantsResponse = {
  tenants: [
    {
      id: "t-acme",
      name: "Acme Corp",
      slug: "acme",
      active: true,
      created_at: "2026-01-10T00:00:00Z",
      updated_at: "2026-06-30T00:00:00Z",
      config_keys: ["wazuh", "claude", "notifications"],
      has_wazuh: true,
      has_claude: true,
      has_notifications: true,
    },
    {
      id: "t-globex",
      name: "Globex Ltd",
      slug: "globex",
      active: true,
      created_at: "2026-03-22T00:00:00Z",
      updated_at: "2026-06-15T00:00:00Z",
      config_keys: ["wazuh", "claude"],
      has_wazuh: true,
      has_claude: true,
      has_notifications: false,
    },
    {
      id: "t-initech",
      name: "Initech (onboarding)",
      slug: "initech",
      active: false,
      created_at: "2026-06-28T00:00:00Z",
      updated_at: "2026-06-28T00:00:00Z",
      config_keys: [],
      has_wazuh: false,
      has_claude: false,
      has_notifications: false,
    },
  ],
};

const AUDIT_LOG: AdminAuditLogResponse = {
  entries: [
    {
      id: 1204,
      actor: "s.okafor",
      action: "review",
      target_type: "decision",
      target_id: "dec_9f2a04a1",
      ip_address: "10.4.0.31",
      details: { verdict: "true_positive", is_override: false },
      created_at: "2026-07-02T02:31:00Z",
    },
    {
      id: 1203,
      actor: "a.mehra",
      action: "login",
      target_type: "session",
      target_id: "-",
      ip_address: "10.4.0.12",
      details: null,
      created_at: "2026-07-02T02:05:00Z",
    },
    {
      id: 1202,
      actor: "a.mehra",
      action: "update_user",
      target_type: "user",
      target_id: "u-003",
      ip_address: "10.4.0.12",
      details: { role: "analyst" },
      created_at: "2026-07-01T16:20:00Z",
    },
  ],
  total: 3,
};

const CONFIG: AdminConfigResponse = {
  config: {
    auto_close_threshold: 0.9,
    escalation_threshold: 0.7,
    poll_interval_seconds: 60,
    grouping_window_minutes: 30,
    notifications_enabled: true,
  },
};

const CHARTER: AdminGovernanceCharterResponse = {
  charter: {
    mission: "Detect, triage, and contain threats to the client estate with a human in the loop.",
    escalation_policy: "P0/P1 verdicts page the on-call senior analyst within 15 minutes.",
    active_response: "Human-approved by default; only blessed action types may auto-execute.",
    review_cadence: "Daily start-of-shift review; weekly detection-tuning retro.",
  },
};

const DATA_ACCESS: AdminDataAccessPolicy = {
  anonymization: "Client identifiers (host, internal IP, user) are tokenized before any LLM call.",
  retention_days: 365,
  pii_handling: "Raw identifiers never leave the tenant boundary; only tokens reach the provider.",
  llm_provider_rule: "One provider per client, end-to-end.",
};

const ANON_MAPPINGS: AdminAnonMappingsResponse = {
  mappings: [
    {
      token: "HOST-7f3a",
      original_value: "WIN-APP-03",
      field_type: "HOST",
      first_seen: "2026-07-02T02:14:00Z",
      last_seen: "2026-07-02T02:41:00Z",
      hit_count: 12,
      client_id: "acme",
    },
    {
      token: "INT-IP-1c9d",
      original_value: "10.4.2.19",
      field_type: "INT-IP",
      first_seen: "2026-07-02T02:14:00Z",
      last_seen: "2026-07-02T02:41:00Z",
      hit_count: 9,
      client_id: "acme",
    },
    {
      token: "USER-4b21",
      original_value: "svc-deploy",
      field_type: "USER",
      first_seen: "2026-07-02T02:18:00Z",
      last_seen: "2026-07-02T02:22:00Z",
      hit_count: 4,
      client_id: "acme",
    },
  ],
  total: 3,
};

export function adminUsersFixture(opts: Opts): AdminUsersResponse {
  return opts.empty ? { users: [], total: 0 } : USERS;
}

export function adminTenantsFixture(opts: Opts): AdminTenantsResponse {
  return opts.empty ? { tenants: [] } : TENANTS;
}

export function adminAuditLogFixture(opts: Opts): AdminAuditLogResponse {
  return opts.empty ? { entries: [], total: 0 } : AUDIT_LOG;
}

export function adminConfigFixture(opts: Opts): AdminConfigResponse {
  return opts.empty ? { config: {} } : CONFIG;
}

export function adminGovernanceCharterFixture(
  opts: Opts,
): AdminGovernanceCharterResponse {
  return opts.empty
    ? { charter: null, message: "No SOC charter is configured for this tenant." }
    : CHARTER;
}

export function adminDataAccessFixture(opts: Opts): AdminDataAccessPolicy {
  return opts.empty ? {} : DATA_ACCESS;
}

export function adminAnonMappingsFixture(
  opts: Opts,
): AdminAnonMappingsResponse {
  return opts.empty ? { mappings: [], total: 0 } : ANON_MAPPINGS;
}

// ---- Write-surface read lists (assets / identities / IOCs / tenant-agents) ---
// Mirror the store SELECT-* projections; fabricate NO capability the server
// lacks (assets: id+hostname+tier+…, tags/services JSON arrays; local-iocs have
// create+delete only; tenant-agents are {agent_id, added_at}).

const ASSETS: AdminAssetsResponse = {
  assets: [
    {
      id: "asset-01",
      hostname: "prod-db-01",
      tier: "tier_1_critical",
      owner: "platform-team",
      environment: "production",
      criticality_multiplier: 2.5,
      tags: ["pci", "database"],
      services: ["postgres"],
      created_at: "2026-02-01T09:00:00Z",
      updated_at: "2026-06-20T09:00:00Z",
    },
    {
      id: "asset-02",
      hostname: "win-app-03",
      tier: "tier_2_important",
      owner: "app-team",
      environment: "production",
      criticality_multiplier: 1.5,
      tags: ["iis"],
      services: ["http"],
      created_at: "2026-03-11T09:00:00Z",
      updated_at: "2026-06-18T09:00:00Z",
    },
  ],
};

const IDENTITIES: AdminIdentitiesResponse = {
  identities: [
    {
      id: "idn-01",
      username: "svc-deploy",
      risk_level: "elevated",
      risk_multiplier: 1.8,
      is_admin: false,
      is_service_account: true,
      roles: ["ci"],
      known_ips: ["10.4.2.19"],
      department: "platform",
      onboarded_date: "2026-01-05",
    },
    {
      id: "idn-02",
      username: "a.mehra",
      risk_level: "high_risk",
      risk_multiplier: 2.0,
      is_admin: true,
      is_service_account: false,
      roles: ["domain-admin"],
      known_ips: ["10.4.0.12"],
      department: "security",
      onboarded_date: "2026-01-14",
    },
  ],
};

const LOCAL_IOCS: AdminLocalIocsResponse = {
  iocs: [
    {
      id: "ioc-01",
      ioc_type: "ip",
      value: "203.0.113.66",
      severity: "high",
      description: "Known C2 from last month's incident",
      updated_at: "2026-06-30T09:00:00Z",
    },
    {
      id: "ioc-02",
      ioc_type: "domain",
      value: "evil.example",
      severity: "critical",
      description: "Phishing kit host",
      updated_at: "2026-07-01T09:00:00Z",
    },
  ],
};

const TENANT_AGENTS: Record<string, TenantAgentsResponse> = {
  "t-acme": {
    tenant_id: "t-acme",
    agents: [
      { agent_id: "001", added_at: "2026-01-10T00:00:00Z" },
      { agent_id: "002", added_at: "2026-02-14T00:00:00Z" },
    ],
    total: 2,
  },
};

export function adminAssetsFixture(opts: Opts): AdminAssetsResponse {
  return opts.empty ? { assets: [] } : ASSETS;
}

export function adminIdentitiesFixture(opts: Opts): AdminIdentitiesResponse {
  return opts.empty ? { identities: [] } : IDENTITIES;
}

const DECISION_CACHE: DecisionCacheResponse = {
  entries: [
    {
      id: "dc_1",
      fingerprint: "rule:5710|src_ip:10.0.0.9|...",
      rule_id: 5710,
      rule_description: "sshd: authentication success",
      entity_summary: "host=prod-db-01, user=deploybot",
      verdict: "false_positive",
      confidence: 0.94,
      risk_score: 12,
      source: "llm_cached",
      enabled: true,
      hit_count: 41,
      tokens_saved_est: 61500,
      created_at: "2026-07-20T08:14:00Z",
      created_by: "triage",
      last_hit_at: "2026-07-22T06:02:00Z",
      expires_at: "2026-07-27T08:14:00Z",
    },
    {
      id: "dc_2",
      fingerprint: "rule:5402|agent_id:004|...",
      rule_id: 5402,
      rule_description: "Successful sudo to ROOT executed",
      entity_summary: "agent=004, user=ansible",
      verdict: "auto_close",
      confidence: 0.9,
      risk_score: 8,
      source: "human_confirmed",
      enabled: false,
      hit_count: 12,
      tokens_saved_est: 18000,
      created_at: "2026-07-19T11:30:00Z",
      created_by: "senior.analyst",
      last_hit_at: "2026-07-21T22:41:00Z",
      expires_at: null,
    },
  ],
  summary: {
    total: 2,
    enabled: 1,
    disabled: 1,
    total_hits: 53,
    tokens_saved: 79500,
  },
};

export function decisionCacheFixture(opts: Opts): DecisionCacheResponse {
  return opts.empty
    ? {
        entries: [],
        summary: {
          total: 0,
          enabled: 0,
          disabled: 0,
          total_hits: 0,
          tokens_saved: 0,
        },
      }
    : DECISION_CACHE;
}

export function adminLocalIocsFixture(opts: Opts): AdminLocalIocsResponse {
  return opts.empty ? { iocs: [] } : LOCAL_IOCS;
}

export function tenantAgentsFixture(
  tenantId: string,
  opts: Opts,
): TenantAgentsResponse {
  if (opts.empty) return { tenant_id: tenantId, agents: [], total: 0 };
  return (
    TENANT_AGENTS[tenantId] ?? { tenant_id: tenantId, agents: [], total: 0 }
  );
}
