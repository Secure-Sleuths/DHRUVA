/**
 * Detection proposals FIXTURE — screenshot / dev-preview only (WO-U9).
 *
 * Reached solely from `api.ts::getDetectionProposals` when
 * `NEXT_PUBLIC_DHRUVA_FIXTURES` is set, via dynamic import so it is
 * dead-code-eliminated from a normal production bundle. The real path calls the
 * live `GET /api/detection/proposals`; this only lets the UI states be captured
 * without a backend.
 *
 * Fabricates NO capability — it mirrors the `detection_proposals` row shape
 * exactly (`store.py::get_all_proposals`): keyed on `id`, XML carried as
 * `original_xml` + `proposed_xml` (no pre-computed diff — the UI diffs them),
 * false-positive context only `fp_count_trigger` / `fp_window_days`, no stored
 * logtest result / confidence.
 *
 * `locked: true` (env `NEXT_PUBLIC_DHRUVA_FIXTURES=locked`) THROWS an
 * ApiError(403) shaped like the real `detection` license gate.
 */

import { ApiError } from "../api";
import type { DetectionProposal, DetectionProposalsResponse } from "../types";

interface Opts {
  empty?: boolean;
  locked?: boolean;
}

/** The exact 403 the `require_license_feature("detection")` gate raises. */
function lockedError(): never {
  throw new ApiError(
    403,
    "Detection engineering is not available on this plan. Contact SecureSleuths to upgrade.",
  );
}

const PROPOSALS: DetectionProposal[] = [
  {
    id: "prop-8a41",
    rule_id: 100210,
    rule_file: "local_rules.xml",
    change_type: "tune",
    original_xml:
      '<rule id="100210" level="7">\n  <if_sid>5716</if_sid>\n  <match>authentication failure</match>\n  <description>SSH authentication failure</description>\n</rule>',
    proposed_xml:
      '<rule id="100210" level="7" frequency="8" timeframe="120">\n  <if_sid>5716</if_sid>\n  <match>authentication failure</match>\n  <description>SSH authentication failure (burst)</description>\n</rule>',
    reasoning:
      "This rule fired 214 times in the last 7 days on VPN-GW-01, all closed as false positives by analysts — a monitoring agent re-authenticates on a short interval. Adding a frequency/timeframe threshold suppresses the single-failure noise while still catching a genuine brute-force burst.",
    fp_count_trigger: 214,
    fp_window_days: 7,
    status: "proposed",
    proposed_at: "2026-07-02T04:12:00Z",
    reviewed_by: null,
    reviewed_at: null,
  },
  {
    id: "prop-2f90",
    rule_id: 100355,
    rule_file: "local_rules.xml",
    change_type: "modify",
    original_xml:
      '<rule id="100355" level="10">\n  <decoded_as>json</decoded_as>\n  <field name="event.action">process_creation</field>\n  <description>Suspicious process creation</description>\n</rule>',
    proposed_xml:
      '<rule id="100355" level="12">\n  <decoded_as>json</decoded_as>\n  <field name="event.action">process_creation</field>\n  <field name="process.parent.name">winword.exe|excel.exe</field>\n  <description>Office application spawned a child process</description>\n  <mitre>\n    <id>T1204.002</id>\n  </mitre>\n</rule>',
    reasoning:
      "Feedback loop flagged 3 confirmed true positives (macro execution on FIN-WKS-11) that this rule scored too low to escalate. Narrowing the parent-process match to Office apps and raising the level surfaces the macro-exec pattern and maps it to T1204.002.",
    fp_count_trigger: 0,
    fp_window_days: 14,
    status: "approved",
    proposed_at: "2026-07-01T18:40:00Z",
    reviewed_by: "s.okafor",
    reviewed_at: "2026-07-02T01:05:00Z",
  },
  {
    id: "prop-1c7d",
    rule_id: 100120,
    rule_file: "local_rules.xml",
    change_type: "disable",
    original_xml:
      '<rule id="100120" level="5">\n  <if_sid>530</if_sid>\n  <match>ossec: agent started</match>\n  <description>OSSEC agent started</description>\n</rule>',
    proposed_xml:
      '<!-- rule 100120 disabled: pure operational noise, never actioned -->',
    reasoning:
      "100% false-positive rate over 30 days (1,880 alerts, 0 escalations). This is an operational lifecycle event, not a security signal. Disabling removes it from the triage queue entirely.",
    fp_count_trigger: 1880,
    fp_window_days: 30,
    status: "deployed",
    proposed_at: "2026-06-28T09:15:00Z",
    reviewed_by: "a.mehra",
    reviewed_at: "2026-06-29T10:20:00Z",
    deployed_at: "2026-06-29T11:02:00Z",
  },
  {
    id: "prop-9b03",
    rule_id: 100412,
    rule_file: "local_rules.xml",
    change_type: "new_rule",
    original_xml: null,
    proposed_xml:
      '<rule id="100412" level="9">\n  <decoded_as>json</decoded_as>\n  <field name="event.category">authentication</field>\n  <field name="source.geo.country_iso_code">!IN</field>\n  <description>Successful login from outside expected geography</description>\n  <mitre>\n    <id>T1078</id>\n  </mitre>\n</rule>',
    reasoning:
      "No existing coverage for impossible-travel style logins. Proposing a new rule keyed on geo mismatch for accounts that should only sign in from India. Flagged as a coverage gap by the MITRE analyzer (T1078 Valid Accounts).",
    fp_count_trigger: 0,
    fp_window_days: 7,
    status: "rejected",
    proposed_at: "2026-06-30T14:22:00Z",
    reviewed_by: "s.okafor",
    reviewed_at: "2026-07-01T08:11:00Z",
    rejection_notes:
      "Geo data unreliable for our VPN egress — would generate constant FPs. Revisit once we tag corporate egress IPs as an allowlist.",
  },
];

export function detectionProposalsFixture(
  opts: Opts,
): DetectionProposalsResponse {
  if (opts.locked) lockedError();
  if (opts.empty) return { proposals: [], count: 0 };
  return { proposals: PROPOSALS, count: PROPOSALS.length };
}
