"use client";

/**
 * AgentGroupsTab (WO-U9b) — READ-ONLY view of the Wazuh Manager's agent groups.
 *
 * Binds to `GET /api/groups` (`getAgentGroups`) — `require_role("mssp_admin")` +
 * `require_license_feature("host_integrity")`. The Wazuh group list is
 * Manager-GLOBAL (a group list would leak other tenants' group names/membership),
 * so it is a structural mssp_admin-only boundary. The tab gates the call on the
 * mssp_admin role CLIENT-SIDE (mirroring the server) so a lower role never fires a
 * request the server would 403. Shows each group and its membership count.
 *
 * STRICTLY READ-ONLY: no group create / edit / assign. Group management is a gated
 * action delivered separately — this surface only lists.
 *
 * TIER GATE: a runtime 402/403 from the `host_integrity` gate degrades the whole
 * surface to FeatureLockedState. States: loading / empty / error+retry / locked /
 * role-restricted; PollingStatus (30s, aborts on unmount). Fixtures gate behind
 * NEXT_PUBLIC_DHRUVA_FIXTURES.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Chip,
  Panel,
  PollingStatus,
  StatusState,
  FeatureLockedState,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
  Tile,
} from "@/components";
import { PageHeading } from "../PageHeading";
import { ApiError, getAgentGroups } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { roleAtLeast } from "@/lib/rbac";
import { DASH, fmtInt } from "@/lib/format";
import type { TabProps } from "../tabRegistry";
import type { AgentGroup } from "@/lib/types";

const POLL_MS = 30_000;

function isLockError(e: unknown): boolean {
  return e instanceof ApiError && (e.status === 402 || e.status === 403);
}
function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : "Unknown error";
}

interface State {
  groups: AgentGroup[] | null;
  error: string | null;
  locked: boolean;
  loading: boolean;
}

export function AgentGroupsTab(_props: TabProps) {
  const { role } = useAuth();
  const isMssp = roleAtLeast(role, "mssp_admin");

  const [state, setState] = useState<State>({
    groups: null,
    error: null,
    locked: false,
    loading: isMssp,
  });
  const [secondsAgo, setSecondsAgo] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(
    async (manual: boolean) => {
      // Mirror the server: only mssp_admin may read the Manager-global group list.
      if (!isMssp) return;
      abortRef.current?.abort();
      const ac = new AbortController();
      abortRef.current = ac;
      if (manual) setRefreshing(true);
      try {
        const res = await getAgentGroups({ limit: 500 }, ac.signal);
        if (ac.signal.aborted) return;
        setState({
          groups: res.groups,
          error: null,
          locked: false,
          loading: false,
        });
        setSecondsAgo(0);
      } catch (e) {
        if (ac.signal.aborted) return;
        if (isLockError(e)) {
          setState({ groups: null, error: null, locked: true, loading: false });
          return;
        }
        const msg = errMessage(e);
        setState((prev) =>
          prev.groups
            ? { ...prev, loading: false }
            : { groups: null, error: msg, locked: false, loading: false },
        );
      } finally {
        if (!ac.signal.aborted) setRefreshing(false);
      }
    },
    [isMssp],
  );

  useEffect(() => {
    load(false);
    const poll = setInterval(() => load(false), POLL_MS);
    return () => {
      clearInterval(poll);
      abortRef.current?.abort();
    };
  }, [load]);

  useEffect(() => {
    const t = setInterval(() => setSecondsAgo((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, []);

  const onUpgrade = useCallback(() => {
    if (typeof window !== "undefined") {
      window.open("https://securesleuths.in/pricing", "_blank", "noreferrer");
    }
  }, []);

  const { groups, error, locked, loading } = state;
  const totalMembers = (groups ?? []).reduce((sum, g) => sum + (g.count ?? 0), 0);

  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PageHeading
          title="Agent groups"
          sub="The Wazuh Manager's agent groups and their membership. Manager-global and restricted to the MSSP administrator. Read-only."
        />
        {isMssp && !locked && (
          <PollingStatus
            className="mt-1"
            secondsAgo={secondsAgo}
            refreshing={refreshing}
            onRefresh={() => load(true)}
          />
        )}
      </div>

      {!isMssp ? (
        <Panel className="p-4">
          <div className="mb-1 text-title text-ink">Restricted</div>
          <div className="text-data text-dim2">
            Agent groups are Manager-global, so the list is restricted to the MSSP
            administrator role — it would otherwise leak other tenants&apos; group
            names and membership. Your role cannot view this list.
          </div>
        </Panel>
      ) : locked ? (
        <FeatureLockedState
          feature="Agent groups"
          tier="current"
          onUpgrade={onUpgrade}
        />
      ) : loading && !groups ? (
        <StatusState variant="loading" title="Loading agent groups…" />
      ) : error && !groups ? (
        <StatusState
          variant="error"
          title="Couldn't load agent groups"
          description={error}
          action={<Chip onClick={() => load(true)}>Retry</Chip>}
        />
      ) : groups ? (
        <div className="flex flex-col gap-3">
          <ReadOnlyNote />
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            <Tile label="Groups" value={fmtInt(groups.length)} sub="Manager-global" />
            <Tile
              label="Members"
              value={fmtInt(totalMembers)}
              sub="agents across groups"
              math={
                <>
                  Sum of each group&apos;s `count` as reported by the Wazuh Manager.
                  An agent may belong to more than one group, so this can exceed the
                  distinct agent count — it is a per-group membership total, not a
                  unique-host count.
                </>
              }
            />
          </div>
          <GroupsPanel groups={groups} />
        </div>
      ) : null}
    </>
  );
}

function ReadOnlyNote() {
  return (
    <div className="rounded-lg border border-line bg-panel2 px-3.5 py-2.5 text-kbd text-dim2">
      Read-only view. Creating, editing, or assigning agents to a group is a gated
      action delivered separately. This surface only lists the Manager&apos;s groups
      and their membership counts.
    </div>
  );
}

function GroupsPanel({ groups }: { groups: AgentGroup[] }) {
  return (
    <Panel className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-3">
        <div className="text-title text-ink">Groups</div>
        <span className="text-kbd text-dim2">{groups.length} total</span>
      </div>
      {groups.length === 0 ? (
        <div className="px-4 pb-4 pt-2 text-data text-dim2">
          The Wazuh Manager reports no agent groups.
        </div>
      ) : (
        <Table className="mt-2">
          <THead>
            <TR>
              <TH>Group</TH>
              <TH className="text-right">Members</TH>
              <TH>Config checksum</TH>
            </TR>
          </THead>
          <TBody>
            {groups.map((g) => (
              <TR key={g.name}>
                <TD mono>{g.name}</TD>
                <TD mono className="text-right">
                  {g.count == null ? DASH : fmtInt(g.count)}
                </TD>
                <TD>
                  {g.configSum ? (
                    <span className="font-mono text-kbd text-dim2" title={g.configSum}>
                      {String(g.configSum).slice(0, 12)}…
                    </span>
                  ) : (
                    <span className="text-dim2">{DASH}</span>
                  )}
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      )}
    </Panel>
  );
}
