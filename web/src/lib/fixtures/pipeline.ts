/**
 * Pipeline Health FIXTURE — screenshot / dev-preview only (parity-restore:
 * Admin → Pipeline Health).
 *
 * Reached solely from `api.ts::getPipelineHealth` / `getLogSources` when
 * `NEXT_PUBLIC_DHRUVA_FIXTURES` is set, via dynamic import so it is
 * dead-code-eliminated from a normal production bundle. The real path calls the
 * live `GET /api/health/pipeline` + `/api/health/log-sources` (mssp_admin +
 * `pipeline_health` license).
 *
 * Mirrors `PipelineHealthMonitor.get_pipeline_status()` (the route MERGES
 * `automation_health`) + `get_log_source_inventory()` EXACTLY. Fabricates NO
 * capability the backend lacks. `locked: true`
 * (env `NEXT_PUBLIC_DHRUVA_FIXTURES=locked`) THROWS an ApiError(403) shaped like
 * the real `require_license_feature("pipeline_health")` gate.
 */

import { ApiError } from "../api";
import type { LogSourcesResponse, PipelineHealth } from "../types";

interface Opts {
  empty?: boolean;
  locked?: boolean;
}

/** The exact 403 the `require_license_feature("pipeline_health")` gate raises. */
function lockedError(): never {
  throw new ApiError(
    403,
    "Pipeline health telemetry is not available on this plan. Contact SecureSleuths to upgrade.",
  );
}

const HEALTHY: PipelineHealth = {
  heartbeat: {
    checked_at: "2026-07-03T05:58:00Z",
    window_minutes: 15,
    known_active_agents: 42,
    reporting_agents: 40,
    silent_agents: 2,
    silent_agent_names: ["DB-REPLICA-02", "VPN-GW-03"],
  },
  eps: {
    checked_at: "2026-07-03T05:58:00Z",
    mean_events_per_minute: 1820.4,
    std_dev: 240.1,
    recent_5min_avg: 1955.0,
    z_score: 0.56,
    is_anomaly: false,
    threshold: 3,
  },
  parser: {
    checked_at: "2026-07-03T05:58:00Z",
    total_events_1h: 109_400,
    unparsed_events_1h: 318,
    failure_rate: 0.0029,
    threshold: 0.05,
    is_above_threshold: false,
  },
  automation_health: {
    period_days: 7,
    enrichment_latency: {
      sample_count: 6120,
      p50_ms: 412.0,
      p95_ms: 1180.0,
      p99_ms: 2640.0,
      avg_ms: 503.7,
    },
    soar_actions: {
      total_actions: 214,
      success_count: 207,
      failure_count: 7,
      success_rate: 96.7,
    },
  },
};

const EMPTY: PipelineHealth = {
  // A freshly-started monitor whose periodic checks have not run yet: each
  // sub-status is present-but-empty (mirrors the real `{}` default).
  heartbeat: {},
  eps: { status: "insufficient_data", bucket_count: 2 },
  parser: { status: "no_events" },
  automation_health: { period_days: 7, enrichment_latency: {}, soar_actions: {} },
};

const SOURCES: LogSourcesResponse = {
  sources: [
    {
      name: "Windows Security (WEF)",
      type: "windows_eventlog",
      description: "Domain-controller + workstation security channel via WEF",
      collection_method: "wazuh-agent",
      volume_eps_estimate: 640,
      retention_days: 90,
      reliability: "critical",
      parser: "eventchannel",
      notes: "Primary auth + process-creation telemetry.",
      status: "reporting",
    },
    {
      name: "Linux auditd",
      type: "auditd",
      description: "Execve + file integrity on the server fleet",
      collection_method: "wazuh-agent",
      volume_eps_estimate: 380,
      retention_days: 90,
      reliability: "critical",
      parser: "auditd",
      notes: "",
      status: "reporting",
    },
    {
      name: "Palo Alto NGFW",
      type: "firewall",
      description: "Perimeter traffic + threat logs",
      collection_method: "syslog",
      volume_eps_estimate: 720,
      retention_days: 30,
      reliability: "high",
      parser: "panos",
      notes: "Egress + IPS signal.",
      status: "silent",
    },
  ],
};

export function pipelineHealthFixture(opts: Opts): PipelineHealth {
  if (opts.locked) lockedError();
  if (opts.empty) return EMPTY;
  return HEALTHY;
}

export function logSourcesFixture(opts: Opts): LogSourcesResponse {
  if (opts.locked) lockedError();
  if (opts.empty) return { sources: [] };
  return SOURCES;
}
