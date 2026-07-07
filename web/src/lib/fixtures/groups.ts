/**
 * Agent Groups FIXTURE — screenshot / dev-preview only (WO-U9b).
 *
 * Reached solely from `api.ts::getAgentGroups` when `NEXT_PUBLIC_DHRUVA_FIXTURES`
 * is set, via dynamic import so it is dead-code-eliminated from a normal
 * production bundle. The real path calls the live `GET /api/groups`; this only
 * lets the UI states be captured without a backend.
 *
 * Fabricates NO capability — it mirrors the Wazuh 4.x `GET /groups`
 * `affected_items` passthrough exactly (`wazuh_client.get_agent_groups`): `name`
 * + `count` are the reliably-present keys, `mergedSum` / `configSum` the standard
 * checksums. `locked: true` (env `NEXT_PUBLIC_DHRUVA_FIXTURES=locked`) THROWS an
 * ApiError(403) shaped like the real `require_license_feature("host_integrity")`
 * gate.
 */

import { ApiError } from "../api";
import type { AgentGroup, GroupsResponse } from "../types";

interface Opts {
  empty?: boolean;
  locked?: boolean;
}

function lockedError(): never {
  throw new ApiError(
    403,
    "Host Integrity is not available on this plan. Contact SecureSleuths to upgrade.",
  );
}

const GROUPS: AgentGroup[] = [
  {
    name: "default",
    count: 42,
    mergedSum: "ab73c9f1e2d4a5b6c7d8e9f0a1b2c3d4",
    configSum: "1f2e3d4c5b6a7988990a1b2c3d4e5f60",
  },
  {
    name: "windows-servers",
    count: 18,
    mergedSum: "cd84e0f2f3e5b6c7d8e9f0a1b2c3d4e5",
    configSum: "2a3b4c5d6e7f8091a2b3c4d5e6f70819",
  },
  {
    name: "linux-web",
    count: 27,
    mergedSum: "ef95f1030405c7d8e9f0a1b2c3d4e5f6",
    configSum: "3b4c5d6e7f8091a2b3c4d5e6f708192a",
  },
  {
    name: "finance-workstations",
    count: 11,
    mergedSum: "0a06020415160809f0a1b2c3d4e5f607",
    configSum: "4c5d6e7f8091a2b3c4d5e6f708192a3b",
  },
];

export function groupsFixture(opts: Opts): GroupsResponse {
  if (opts.locked) lockedError();
  if (opts.empty) return { groups: [], total: 0 };
  return { groups: GROUPS, total: GROUPS.length };
}
