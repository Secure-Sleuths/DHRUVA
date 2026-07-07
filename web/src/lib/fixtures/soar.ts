/**
 * SOAR FIXTURE — screenshot / dev-preview only (WO-U9b).
 *
 * Reached solely from `api.ts::getSoar*` when `NEXT_PUBLIC_DHRUVA_FIXTURES` is
 * set, via dynamic import so it is dead-code-eliminated from a normal production
 * bundle. The real path calls the live `GET /api/soar/*`; this only lets the UI
 * states be captured without a backend.
 *
 * Fabricates NO capability — it mirrors the `soar_playbooks` / `soar_executions`
 * row shapes exactly (`store.py`): trigger columns + `actions` as JSON strings,
 * `enabled`/`require_approval` as int 0/1, executions denormalizing
 * `playbook_name` with `current_step`/`total_steps` progress and `error_message`.
 *
 * `locked: true` (env `NEXT_PUBLIC_DHRUVA_FIXTURES=locked`) THROWS an ApiError(403)
 * shaped like the real `require_license_feature("soar")` gate.
 */

import { ApiError } from "../api";
import type {
  SoarExecution,
  SoarExecutionsResponse,
  SoarPlaybook,
  SoarPlaybooksResponse,
  SoarStats,
} from "../types";

interface Opts {
  empty?: boolean;
  locked?: boolean;
}

function lockedError(): never {
  throw new ApiError(
    403,
    "SOAR is not available on this plan. Contact SecureSleuths to upgrade.",
  );
}

const PLAYBOOKS: SoarPlaybook[] = [
  {
    id: "pb-ransomware-contain",
    name: "ransomware_containment",
    display_name: "Ransomware containment",
    description:
      "On a high-confidence ransomware verdict, isolate the host and quarantine the offending binary, then notify the on-call analyst.",
    enabled: 1,
    trigger_verdicts: '["true_positive"]',
    trigger_min_confidence: 0.92,
    trigger_min_risk_score: 85,
    trigger_mitre_techniques: '["T1486","T1490"]',
    trigger_rule_groups: "[]",
    trigger_ti_required: 0,
    actions: '["isolate_host","quarantine_file","notify_oncall"]',
    rollback_actions: '["unisolate_host"]',
    require_approval: 1,
    cooldown_minutes: 30,
    max_executions_per_hour: 5,
    priority: 10,
    created_at: "2026-05-14T09:00:00Z",
    updated_at: "2026-06-28T12:30:00Z",
  },
  {
    id: "pb-bruteforce-block",
    name: "external_bruteforce_block",
    display_name: "External brute-force block",
    description:
      "When threat intel confirms an external IP is brute-forcing SSH, propose a time-boxed block for analyst approval.",
    enabled: 1,
    trigger_verdicts: '["true_positive","needs_investigation"]',
    trigger_min_confidence: 0.8,
    trigger_min_risk_score: 70,
    trigger_mitre_techniques: '["T1110"]',
    trigger_rule_groups: '["authentication_failed"]',
    trigger_ti_required: 1,
    actions: '["block_ip","notify_oncall"]',
    rollback_actions: '["unblock_ip"]',
    require_approval: 1,
    cooldown_minutes: 15,
    max_executions_per_hour: 10,
    priority: 30,
    created_at: "2026-04-02T11:00:00Z",
    updated_at: "2026-06-19T08:10:00Z",
  },
  {
    id: "pb-phish-user-disable",
    name: "phished_account_disable",
    display_name: "Phished account disable",
    description:
      "On a confirmed credential-phishing true positive, disable the affected user pending password reset.",
    enabled: 0,
    trigger_verdicts: '["true_positive"]',
    trigger_min_confidence: 0.9,
    trigger_min_risk_score: 75,
    trigger_mitre_techniques: '["T1078"]',
    trigger_rule_groups: "[]",
    trigger_ti_required: 0,
    actions: '["disable_user","notify_oncall"]',
    rollback_actions: '["enable_user"]',
    require_approval: 1,
    cooldown_minutes: 60,
    max_executions_per_hour: 3,
    priority: 40,
    created_at: "2026-03-20T15:30:00Z",
    updated_at: "2026-05-01T09:45:00Z",
  },
];

const EXECUTIONS: SoarExecution[] = [
  {
    id: "exec-7c21",
    playbook_id: "pb-bruteforce-block",
    playbook_name: "External brute-force block",
    incident_id: "inc-4821",
    decision_id: "dec-90a1",
    status: "pending_approval",
    trigger_data: '{"src_ip":"203.0.113.44","rule_id":5716}',
    actions_planned: '["block_ip","notify_oncall"]',
    actions_completed: "[]",
    current_step: 0,
    total_steps: 2,
    approved_by: null,
    approved_at: null,
    started_at: null,
    completed_at: null,
    error_message: null,
    created_at: "2026-07-02T05:48:00Z",
    updated_at: "2026-07-02T05:48:00Z",
  },
  {
    id: "exec-5b09",
    playbook_id: "pb-ransomware-contain",
    playbook_name: "Ransomware containment",
    incident_id: "inc-4790",
    decision_id: "dec-88f2",
    status: "completed",
    trigger_data: '{"host":"FIN-WKS-11","technique":"T1486"}',
    actions_planned: '["isolate_host","quarantine_file","notify_oncall"]',
    actions_completed: '["isolate_host","quarantine_file","notify_oncall"]',
    current_step: 3,
    total_steps: 3,
    approved_by: "s.okafor",
    approved_at: "2026-07-01T22:14:00Z",
    started_at: "2026-07-01T22:14:10Z",
    completed_at: "2026-07-01T22:14:52Z",
    error_message: null,
    created_at: "2026-07-01T22:12:00Z",
    updated_at: "2026-07-01T22:14:52Z",
  },
  {
    id: "exec-3f44",
    playbook_id: "pb-bruteforce-block",
    playbook_name: "External brute-force block",
    incident_id: "inc-4771",
    decision_id: "dec-81c0",
    status: "partial",
    trigger_data: '{"src_ip":"198.51.100.9"}',
    actions_planned: '["block_ip","notify_oncall"]',
    actions_completed: '["block_ip"]',
    current_step: 1,
    total_steps: 2,
    approved_by: "a.mehra",
    approved_at: "2026-06-30T16:02:00Z",
    started_at: "2026-06-30T16:02:05Z",
    completed_at: "2026-06-30T16:02:20Z",
    error_message: "notify_oncall failed: Slack webhook timed out",
    created_at: "2026-06-30T16:00:00Z",
    updated_at: "2026-06-30T16:02:20Z",
  },
];

export function soarPlaybooksFixture(opts: Opts): SoarPlaybooksResponse {
  if (opts.locked) lockedError();
  if (opts.empty) return { playbooks: [] };
  return { playbooks: PLAYBOOKS };
}

export function soarExecutionsFixture(opts: Opts): SoarExecutionsResponse {
  if (opts.locked) lockedError();
  if (opts.empty) return { executions: [] };
  return { executions: EXECUTIONS };
}

export function soarStatsFixture(opts: Opts): SoarStats {
  if (opts.locked) lockedError();
  if (opts.empty) {
    return {
      total_playbooks: 0,
      active_playbooks: 0,
      pending_approvals: 0,
      executions_today: 0,
      success_rate: 0,
    };
  }
  return {
    total_playbooks: 3,
    active_playbooks: 2,
    pending_approvals: 1,
    executions_today: 2,
    success_rate: 66.7,
  };
}
