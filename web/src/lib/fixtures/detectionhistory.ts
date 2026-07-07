/**
 * Detection Deployment-History + Rule-Versions FIXTURE — screenshot /
 * dev-preview only (parity-restore: Detection → Deployment History / Rule
 * Versions).
 *
 * Reached solely from `api.ts::getDeploymentHistory` / `getRuleVersions` when
 * `NEXT_PUBLIC_DHRUVA_FIXTURES` is set, via dynamic import so it is
 * dead-code-eliminated from a normal production bundle. The real path calls the
 * live `GET /api/detection/history` + `/history/{rule_file}/versions`
 * (require_role("admin","senior_analyst") + `detection` license).
 *
 * Mirrors `rule_deployment_history` rows EXACTLY; the /versions projection
 * strips XML to `has_xml_before`. Fabricates NO capability the backend lacks.
 * `locked: true` (env `NEXT_PUBLIC_DHRUVA_FIXTURES=locked`) THROWS an
 * ApiError(403) shaped like the real `require_license_feature("detection")` gate.
 */

import { ApiError } from "../api";
import type {
  DeploymentHistoryResponse,
  RuleVersionsResponse,
} from "../types";

interface HistOpts {
  empty?: boolean;
  locked?: boolean;
}
interface VersionsOpts {
  empty?: boolean;
  locked?: boolean;
  ruleFile: string;
}

/** The exact 403 the `require_license_feature("detection")` gate raises. */
function lockedError(): never {
  throw new ApiError(
    403,
    "Detection engineering is not available on this plan. Contact SecureSleuths to upgrade.",
  );
}

const HISTORY: DeploymentHistoryResponse = {
  history: [
    {
      id: "dh-9021",
      proposal_id: "prop-1c7d",
      rule_id: 100120,
      rule_file: "local_rules.xml",
      version: 3,
      xml_before: '<rule id="100120" level="5">…</rule>',
      xml_after: "<!-- rule 100120 disabled: pure operational noise -->",
      deployed_by: "a.mehra",
      deployed_at: "2026-06-29T11:02:00Z",
      rolled_back_at: null,
    },
    {
      id: "dh-8890",
      proposal_id: "prop-55a2",
      rule_id: 100355,
      rule_file: "local_rules.xml",
      version: 2,
      xml_before: '<rule id="100355" level="10">…</rule>',
      xml_after: '<rule id="100355" level="12">…</rule>',
      deployed_by: "s.okafor",
      deployed_at: "2026-06-24T09:41:00Z",
      rolled_back_at: "2026-06-25T14:10:00Z",
    },
    {
      id: "dh-8712",
      proposal_id: "prop-3300",
      rule_id: 100210,
      rule_file: "local_rules.xml",
      version: 1,
      xml_before: null,
      xml_after: '<rule id="100210" level="7" frequency="8">…</rule>',
      deployed_by: "a.mehra",
      deployed_at: "2026-06-18T16:20:00Z",
      rolled_back_at: null,
    },
  ],
  count: 3,
};

const VERSIONS: RuleVersionsResponse = {
  rule_file: "local_rules.xml",
  versions: [
    {
      version: 3,
      proposal_id: "prop-1c7d",
      rule_id: 100120,
      deployed_by: "a.mehra",
      deployed_at: "2026-06-29T11:02:00Z",
      rolled_back_at: null,
      has_xml_before: true,
    },
    {
      version: 2,
      proposal_id: "prop-55a2",
      rule_id: 100355,
      deployed_by: "s.okafor",
      deployed_at: "2026-06-24T09:41:00Z",
      rolled_back_at: "2026-06-25T14:10:00Z",
      has_xml_before: true,
    },
    {
      version: 1,
      proposal_id: "prop-3300",
      rule_id: 100210,
      deployed_by: "a.mehra",
      deployed_at: "2026-06-18T16:20:00Z",
      rolled_back_at: null,
      has_xml_before: false,
    },
  ],
};

export function deploymentHistoryFixture(
  opts: HistOpts,
): DeploymentHistoryResponse {
  if (opts.locked) lockedError();
  if (opts.empty) return { history: [], count: 0 };
  return HISTORY;
}

export function ruleVersionsFixture(opts: VersionsOpts): RuleVersionsResponse {
  if (opts.locked) lockedError();
  if (opts.empty) return { rule_file: opts.ruleFile, versions: [] };
  return { ...VERSIONS, rule_file: opts.ruleFile };
}
