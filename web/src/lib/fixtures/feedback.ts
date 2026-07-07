/**
 * CLOSED-LOOP / FEEDBACK FIXTURE — screenshot / dev-preview only (WO-U9c).
 *
 * Reached solely from `api.ts::{getFeedbackPatterns,getProposalEffectiveness}`
 * when `NEXT_PUBLIC_DHRUVA_FIXTURES` is set, via dynamic import so it is
 * dead-code-eliminated from a normal production bundle. The real path calls the
 * live `GET /api/feedback/{patterns,effectiveness}`.
 *
 * Fabricates NO capability — it mirrors the `feedback_patterns` row shape and
 * the `track_proposal_effectiveness` list element exactly (`store.py` /
 * `feedback/loop.py`). One effectiveness row has `effective: null` to exercise
 * the honest "not enough data yet" state; rates are 0..1 fractions.
 *
 * `locked: true` (env `NEXT_PUBLIC_DHRUVA_FIXTURES=locked`) THROWS an ApiError(403)
 * shaped like the real `require_license_feature("feedback_loop")` gate.
 */

import { ApiError } from "../api";
import type {
  FeedbackPattern,
  FeedbackPatternsResponse,
  ProposalEffectiveness,
} from "../types";

interface Opts {
  empty?: boolean;
  locked?: boolean;
}

function lockedError(): never {
  throw new ApiError(
    403,
    "The feedback loop is not available on this plan. Contact SecureSleuths to upgrade.",
  );
}

const PATTERNS: FeedbackPattern[] = [
  {
    id: "fp-01",
    pattern_type: "recurring_fp",
    rule_id: 5716,
    description:
      "SSH auth-failure alerts from the vulnerability scanner's scan window are consistently marked false-positive.",
    occurrence_count: 143,
    first_seen: "2026-05-02T00:00:00Z",
    last_seen: "2026-07-01T22:00:00Z",
    auto_action_taken: "confidence_lowered",
    status: "active",
  },
  {
    id: "fp-02",
    pattern_type: "noisy_rule",
    rule_id: 61103,
    description:
      "Windows Defender 'action taken' informational events fire in bulk after signature updates.",
    occurrence_count: 88,
    first_seen: "2026-05-20T00:00:00Z",
    last_seen: "2026-06-30T11:00:00Z",
    auto_action_taken: null,
    status: "active",
  },
  {
    id: "fp-03",
    pattern_type: "recurring_fp",
    rule_id: 31530,
    description:
      "Web-server 400s from an internal uptime monitor repeatedly triaged as benign.",
    occurrence_count: 51,
    first_seen: "2026-06-01T00:00:00Z",
    last_seen: "2026-07-02T04:00:00Z",
    auto_action_taken: "tuning_proposed",
    status: "active",
  },
];

const EFFECTIVENESS: ProposalEffectiveness[] = [
  {
    rule_id: 5716,
    proposal_id: "dp-5716-a",
    deployed_at: "2026-06-10T09:00:00Z",
    pre_fp_count: 143,
    pre_tp_rate: 0.02,
    post_total_decisions: 210,
    post_fp_count: 12,
    post_tp_count: 4,
    post_fp_rate: 0.057,
    post_tp_rate: 0.019,
    effective: true,
  },
  {
    rule_id: 31530,
    proposal_id: "dp-31530-b",
    deployed_at: "2026-06-25T09:00:00Z",
    pre_fp_count: 51,
    pre_tp_rate: 0.0,
    post_total_decisions: 40,
    post_fp_count: 18,
    post_tp_count: 0,
    post_fp_rate: 0.45,
    post_tp_rate: 0.0,
    effective: false,
  },
  {
    rule_id: 61103,
    proposal_id: "dp-61103-c",
    deployed_at: "2026-06-30T09:00:00Z",
    pre_fp_count: 88,
    pre_tp_rate: 0.0,
    post_total_decisions: 3,
    post_fp_count: 1,
    post_tp_count: 0,
    post_fp_rate: 0.333,
    post_tp_rate: 0.0,
    effective: null,
  },
];

export function feedbackPatternsFixture(opts: Opts): FeedbackPatternsResponse {
  if (opts.locked) lockedError();
  if (opts.empty) return { patterns: [], total: 0 };
  return { patterns: PATTERNS, total: PATTERNS.length };
}

export function proposalEffectivenessFixture(opts: Opts): ProposalEffectiveness[] {
  if (opts.locked) lockedError();
  if (opts.empty) return [];
  return EFFECTIVENESS;
}
