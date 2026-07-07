"use client";

/**
 * Component gallery (dev-only) — WO-U1 design-system.
 *
 * Renders every primitive with mock props in its key states so the system can
 * be eyeballed / screenshotted. No backend calls: all handlers are stubs.
 *
 * NOTE ON THE ROUTE: Next.js treats `_`-prefixed folders as PRIVATE (excluded
 * from routing), so the WO's suggested `/_gallery` would 404. This lives at
 * `/gallery` so it actually renders. It is not linked from the product IA.
 */

import { useState } from "react";
import {
  Building2,
  EyeOff,
  GitBranch,
  Server,
  Timer,
} from "lucide-react";
import {
  Chip,
  Citation,
  ConfidenceBar,
  ContainmentActionCard,
  CopilotRail,
  Dialog,
  FeatureLockedState,
  KillChainLane,
  KillChainLegend,
  Panel,
  Pill,
  PollingStatus,
  SeverityBadge,
  StatusState,
  Table,
  TBody,
  TD,
  TH,
  THead,
  Tile,
  TR,
} from "@/components";
import { SEVERITY_ORDER, severityLabel } from "@/lib/severity";
import type { Campaign } from "@/lib/campaign";
import type {
  CopilotCitation,
  CopilotMessage,
  CopilotMode,
} from "@/lib/copilot";
import type { KillChainNodeRef } from "@/components";

// ---- mock data (ported from the approved mockup) ----------------------------

const CAMPAIGN: Campaign = {
  id: "INC-204",
  name: "Credential harvest on WIN-APP-03",
  severity: "crit",
  p: "P0",
  plabel: "Critical",
  chain: "attack_chain_id 7f3a-204",
  status: "Active · Lateral Movement",
  progress: 70,
  dwell: "6h 12m",
  hosts: ["WIN-APP-03", "svc-deploy", "10.4.2.19"],
  alerts: 3,
  steps: [
    {
      t: "credaccess",
      tid: "T1003",
      tname: "OS Credential Dumping (LSASS)",
      host: "WIN-APP-03",
      x: 14,
      when: "02:14",
      alert: "INC-204·a1",
      severity: "crit",
      conf: "0.86",
      why: "LSASS handle opened by a non-EDR process on an app server adjacent to a domain controller.",
    },
    {
      t: "persist",
      tid: "T1136",
      tname: "Create Account",
      host: "WIN-APP-03",
      x: 42,
      when: "02:18",
      alert: "INC-204·a2",
      severity: "high",
      conf: "0.71",
      why: "New local admin account created 4 minutes after the LSASS access — service identity, off-hours.",
    },
    {
      t: "lateral",
      tid: "T1021",
      tname: "Remote Services (SMB)",
      host: "svc-deploy",
      x: 70,
      when: "02:41",
      alert: "INC-204·a3",
      severity: "high",
      conf: "0.79",
      why: "Authenticated SMB session from WIN-APP-03 to peer host svc-deploy using the new account.",
    },
  ],
  proj: [
    {
      t: "discovery",
      tid: "T1087",
      tname: "Account Discovery",
      host: "svc-deploy",
      x: 86,
      prob: "likely",
    },
    {
      t: "exfil",
      tid: "T1048",
      tname: "Exfil over alt protocol",
      host: "10.4.2.19",
      x: 96,
      prob: "possible",
    },
  ],
};

const CITES: Record<string, CopilotCitation> = {
  a92003: {
    id: "a92003",
    kind: "alert",
    title: "Alert 92003 · WIN-APP-03",
    detail:
      "Wazuh rule 92003 fired 02:14:07 — a process opened a handle to lsass.exe with PROCESS_VM_READ; the opener is not an EDR/AV allow-listed image.",
    openLabel: "Open Triage",
  },
  r5710: {
    id: "r5710",
    kind: "rule",
    title: "Rule 5710 · new admin account",
    detail:
      'Windows Security 4720/4732 — account "svc-deploy-2" added to local Administrators at 02:18. Correlated as persistence.',
    openLabel: "Open Detection",
  },
  enrAsset: {
    id: "enrAsset",
    kind: "asset-graph",
    title: "Asset graph · WIN-APP-03",
    detail:
      "App server sits one hop from a domain controller (asset criticality 2.1×). Business tag: payments.",
    openLabel: "Open Incident",
  },
};

const stub = () => {};

// ---- gallery scaffolding ----------------------------------------------------

function Section({
  title,
  note,
  children,
}: {
  title: string;
  note?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="mb-10">
      <h2 className="mb-1 text-h1">{title}</h2>
      {note && <p className="mb-3 max-w-3xl text-data text-dim">{note}</p>}
      <div className="rounded-xl border border-line bg-panel/40 p-4">
        {children}
      </div>
    </section>
  );
}

export default function GalleryPage() {
  const [lockOpen, setLockOpen] = useState(false);
  const [nodeDetail, setNodeDetail] = useState<KillChainNodeRef | null>(null);
  const [copilotMode, setCopilotMode] = useState<CopilotMode>("normal");
  const [seconds, setSeconds] = useState(22);

  const messages: CopilotMessage[] = [
    { id: "u1", who: "user", content: "Why is INC-204 critical?" },
    {
      id: "a1",
      who: "ai",
      content: (
        <>
          <b>Verdict: true_positive · confidence 0.86.</b> INC-204 is an attack
          chain on <span className="font-mono">WIN-APP-03</span> across three
          ATT&amp;CK stages. It scores{" "}
          <span className="font-mono text-sev-crit">P0 · 87</span> because the
          host is one hop from a domain controller{" "}
          <Citation citation={CITES.enrAsset} onOpenSource={stub} /> and a
          non-EDR process read lsass memory at 02:14{" "}
          <Citation citation={CITES.a92003} onOpenSource={stub} />, then a new
          admin account was created{" "}
          <Citation citation={CITES.r5710} onOpenSource={stub} />.
          <div className="mt-2 border-t border-aibd pt-1.5 text-kbd text-dim2">
            🔒 I reasoned over anonymized tokens (HOST_7f3a, USER_2b); the names
            above are re-mapped for you only. Anonymization is the LLM boundary —
            you see the real values.
          </div>
        </>
      ),
      chips: [
        { id: "logons", label: "Show other logons by svc-deploy in the last 24h" },
        { id: "lsass", label: "What processes had lsass.exe as parent?" },
        { id: "contain", label: "Propose a containment action", kind: "action" },
      ],
    },
    {
      id: "a2",
      who: "ai",
      content: (
        <>
          Here is a containment option scoped to this incident. It stays gated
          behind your approval:
          <ContainmentActionCard
            title="Isolate WIN-APP-03"
            description={
              <>
                Host containment via EDR (blocks all lateral SMB) to stop the
                pivot. Recommended because the next hop is DC-adjacent{" "}
                <Citation citation={CITES.enrAsset} onOpenSource={stub} />.
              </>
            }
            canApprove={copilotMode === "normal"}
            gateHint={
              copilotMode === "normal" ? "you can approve" : "needs senior_analyst+"
            }
            onApprove={stub}
            onDecline={stub}
          />
        </>
      ),
    },
  ];

  return (
    <main className="min-h-screen bg-bg p-6 text-ink md:p-10">
      <header className="mb-8">
        <h1 className="text-[22px] font-bold">DHRUVA AI-SOC — Component gallery</h1>
        <p className="mt-1 max-w-3xl text-data text-dim">
          WO-U1 design system: tokens + primitives every later screen composes.
          Mock props, stubbed handlers, no backend. Severity = glyph + label +
          colour (never colour alone); confidence rides a separate neutral ramp.
        </p>
      </header>

      {/* SEVERITY */}
      <Section
        title="SeverityBadge"
        note="The p-scale as glyph + label + colour. Colour is redundant reinforcement — the glyph and word always carry the meaning."
      >
        <div className="flex flex-wrap items-center gap-4">
          {SEVERITY_ORDER.map((s) => (
            <SeverityBadge key={s} severity={s} label={severityLabel(s)} />
          ))}
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-4">
          <span className="text-kbd text-dim2">glyph-only (dense cells):</span>
          {SEVERITY_ORDER.map((s) => (
            <SeverityBadge key={s} severity={s} glyphOnly />
          ))}
        </div>
      </Section>

      {/* CONFIDENCE */}
      <Section
        title="ConfidenceBar"
        note="Neutral blue→teal ramp, kept off the severity scale so it never reads as 'critical'. Tabular-nums value."
      >
        <div className="max-w-md space-y-3">
          {[0.95, 0.86, 0.71, 0.55, 0.32].map((v) => (
            <ConfidenceBar key={v} value={v} />
          ))}
          <div className="flex items-center gap-3">
            <span className="text-kbd text-dim2">fixed width, no value:</span>
            <ConfidenceBar value={0.79} width={56} showValue={false} />
          </div>
        </div>
      </Section>

      {/* CHIPS + PILLS */}
      <Section title="Chip · Pill" note="Metadata tokens and inline actions.">
        <div className="flex flex-wrap items-center gap-2">
          <Chip icon={<Building2 className="h-3.5 w-3.5" />}>
            Tenant <b className="text-white">Acme Corp</b>
          </Chip>
          <Chip variant="grounded" icon={<EyeOff className="h-3.5 w-3.5" />}>
            Anonymization = LLM boundary
          </Chip>
          <Chip variant="violet" icon={<GitBranch className="h-3.5 w-3.5" />}>
            part of campaign 7f3a-204 →
          </Chip>
          <Chip variant="cite" mono onClick={stub}>
            Open Triage ›
          </Chip>
          <Chip variant="gated">gated</Chip>
          <Chip mono>INC-204</Chip>
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <Pill mono>T1003</Pill>
          <Pill>WIN-APP-03</Pill>
          <Pill mono dashed color="#a78bfa" borderColor="#a78bfa55">
            T1087
          </Pill>
          <Pill className="text-dim2">possible</Pill>
        </div>
      </Section>

      {/* TILES */}
      <Section
        title="Tile (KPI · expand-to-math)"
        note="Nothing is a bare number — every KPI opens to how it was computed (click a tile)."
      >
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Tile
            label="Active campaigns"
            value="3"
            valueSeverity="crit"
            sub="2 advancing · 1 contained"
            icon={<GitBranch className="h-4 w-4" />}
            math="1 per campaign · groups alerts by attack_chain_id · 3 distinct chains live now (INC-204, INC-198, INC-176)."
          />
          <Tile
            label="Estate dwell (worst)"
            value="6h 12m"
            valueSeverity="high"
            sub="INC-204 · still lateral"
            icon={<Timer className="h-4 w-4" />}
            math="worst-of open campaigns = now − first correlated alert on the chain (02:14 → 08:26). Contained chains excluded."
          />
          <Tile
            label="Hosts on a chain"
            value="5"
            valueSeverity="med"
            sub="of 214 monitored"
            icon={<Server className="h-4 w-4" />}
            math="distinct assets appearing in any active campaign step."
          />
          <Tile
            label="LLM cost (24h)"
            value="$3.10*"
            sub="token approximation"
          />
        </div>
      </Section>

      {/* TABLE */}
      <Section
        title="Table"
        note="SOC data table. Rows with an onClick are keyboard-operable (Enter/Space) and carry an aria-label."
      >
        <Panel className="overflow-hidden">
          <Table>
            <THead>
              <TR>
                <TH className="w-8" />
                <TH>Alert</TH>
                <TH>Host</TH>
                <TH>AI verdict</TH>
                <TH>Conf</TH>
                <TH>Risk</TH>
              </TR>
            </THead>
            <TBody>
              {CAMPAIGN.steps.map((s) => (
                <TR key={s.alert} onClick={stub} aria-label={`Open ${s.alert}`}>
                  <TD>
                    <SeverityBadge severity={s.severity} glyphOnly />
                  </TD>
                  <TD>
                    <div>{s.tname}</div>
                    <div className="font-mono text-kbd text-dim2">{s.alert}</div>
                  </TD>
                  <TD mono>{s.host}</TD>
                  <TD>
                    <SeverityBadge severity={s.severity} label="Needs review" />
                  </TD>
                  <TD>
                    <ConfidenceBar value={Number(s.conf)} width={56} showValue={false} />
                  </TD>
                  <TD mono className="font-bold text-sev-crit">
                    87
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </Panel>
      </Section>

      {/* KILL-CHAIN LANE */}
      <Section
        title="KillChainLane"
        note="Campaign hero viz. Observed nodes (severity dot + T-code + host) then dashed violet projections. Click any node."
      >
        <Panel className="p-4">
          <div className="mb-2 flex items-center justify-between">
            <b className="text-title">Campaign map — {CAMPAIGN.id}</b>
            <KillChainLegend />
          </div>
          <KillChainLane campaign={CAMPAIGN} onNodeClick={setNodeDetail} />
        </Panel>
      </Section>

      {/* STATUS STATES */}
      <Section
        title="Status states + polling"
        note="The product polls (no push channel) — hence the 'refreshed Ns ago · refresh' affordance."
      >
        <div className="mb-4 flex flex-wrap items-center gap-6">
          <PollingStatus
            secondsAgo={seconds}
            onRefresh={() => setSeconds(0)}
          />
          <PollingStatus secondsAgo={140} stale onRefresh={stub} />
        </div>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <StatusState variant="empty" title="No alerts in the queue" description="Nothing needs triage right now." />
          <StatusState variant="loading" title="Loading triage queue…" />
          <StatusState
            variant="error"
            title="Couldn't load incidents"
            description="The API didn't respond."
            action={
              <Chip onClick={stub}>Retry</Chip>
            }
          />
          <FeatureLockedState feature="NL-Query Copilot" tier="community" onUpgrade={() => setLockOpen(true)} />
        </div>
      </Section>

      {/* DIALOG */}
      <Section title="Dialog" note="Accessible modal: role=dialog, focus trap, Esc / backdrop close, focus restore.">
        <Chip onClick={() => setLockOpen(true)}>Open tier-lock dialog</Chip>
      </Section>

      {/* COPILOT RAIL */}
      <Section
        title="CopilotRail"
        note="Grounded rail with three degraded states. Toggle the mode to see: normal / read-only role / tier-locked."
      >
        <div className="mb-3 flex flex-wrap gap-2">
          {(["normal", "readonly", "locked"] as CopilotMode[]).map((m) => (
            <Chip
              key={m}
              onClick={() => setCopilotMode(m)}
              variant={copilotMode === m ? "cite" : "default"}
            >
              {m}
            </Chip>
          ))}
        </div>
        <div className="h-[560px] w-full max-w-[420px] overflow-hidden rounded-xl border border-line">
          <CopilotRail
            mode={copilotMode}
            role={copilotMode === "readonly" ? "read_only" : "senior_analyst"}
            tier={copilotMode === "locked" ? "community" : "team"}
            contextLabel="INC-204"
            messages={messages}
            previewQueries={[
              "Why is INC-204 critical?",
              "Show other logons by svc-deploy",
              "What processes had lsass as parent?",
            ]}
            onSend={stub}
            onRunQuery={stub}
            onUpgrade={() => setLockOpen(true)}
            onClose={stub}
          />
        </div>
      </Section>

      {/* overlays */}
      <Dialog
        open={lockOpen}
        onClose={() => setLockOpen(false)}
        title="NL-Query Copilot — not in community tier"
        maxWidth={460}
      >
        <p className="text-data text-dim">
          Upgrade to unlock the copilot. Community physically strips paid
          modules; Team/Enterprise progressively unlock. This is a license gate,
          independent of your role.
        </p>
        <div className="mt-4 flex justify-end">
          <Chip onClick={() => setLockOpen(false)}>Close</Chip>
        </div>
      </Dialog>

      <Dialog
        open={nodeDetail !== null}
        onClose={() => setNodeDetail(null)}
        title={
          nodeDetail
            ? `${nodeDetail.node.tid} · ${nodeDetail.node.tname}`
            : undefined
        }
        maxWidth={520}
      >
        {nodeDetail &&
          (nodeDetail.projected ? (
            <div>
              <Chip variant="violet" className="mb-2">
                Projected
              </Chip>
              <p className="text-data text-dim">
                The correlation engine extrapolates this step from observed
                T-codes against known playbooks. It has <b>not fired</b> — a
                heuristic hint to prioritise hunting. No response is taken on
                projections.
              </p>
            </div>
          ) : (
            <div>
              <SeverityBadge
                severity={"severity" in nodeDetail.node ? nodeDetail.node.severity : "crit"}
                label={severityLabel(
                  "severity" in nodeDetail.node ? nodeDetail.node.severity : "crit",
                )}
              />
              <p className="mt-2 text-data text-dim">
                {"why" in nodeDetail.node ? nodeDetail.node.why : ""}
              </p>
              {"conf" in nodeDetail.node && (
                <div className="mt-3">
                  <ConfidenceBar value={Number(nodeDetail.node.conf)} />
                </div>
              )}
            </div>
          ))}
      </Dialog>
    </main>
  );
}
