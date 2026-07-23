"use client";

/**
 * InvestigateTab (WO-U6, refactored in WO-U7) — the grounded NL-Query copilot as
 * the hero, with an evidence canvas beside it.
 *
 * WO-U7: the copilot CONVERSATION (thread, grounded `POST /api/query` + answer-
 * level citations, degraded modes, runtime 402/403 handling, and the PROPOSE-ONLY
 * containment flow) now lives in the shared `useCopilotConversation` hook — the
 * SAME engine the shell's "Ask copilot" launcher rail uses, so there is ONE
 * copilot implementation, not two. This tab keeps its OWN hero layout + evidence
 * canvas and simply renders that shared conversation.
 *
 * GROUNDING (unchanged core invariant — "never an uncited claim"):
 *   - answers cite their `sources` (answer-level); empty sources → an honest
 *     "not grounded, won't invent a citation" note; per-claim cites are a marked
 *     fast-follow, never fabricated. (Enforced in the shared hook + this canvas.)
 *
 * DEGRADED (paid + role): locked (paid gate) → LockedCanvas + locked rail;
 * read_only → readonly rail; else normal. PROPOSE-ONLY, human-approved: the rail
 * can only queue a containment for approval (analyst+), never execute it.
 */

import { useCallback } from "react";
import {
  BookOpen,
  Database,
  FileSearch,
  Search,
  Server,
} from "lucide-react";
import {
  Chip,
  Citation,
  CopilotRail,
  Panel,
  StatusState,
} from "@/components";
import { PageHeading } from "../PageHeading";
import { useAuth } from "@/lib/auth";
import {
  confidenceLabel,
  queryMeta,
  sourceCiteLabel,
  sourceKindLabel,
  sourceToCitation,
} from "@/lib/investigate";
import { useCopilotConversation } from "@/lib/useCopilotConversation";
import type { TabProps } from "../tabRegistry";
import type { CopilotMessage, SuggestedQuery } from "@/lib/copilot";
import type { NLQueryFinding, NLQueryResponse, NLQuerySource } from "@/lib/types";

/** Honest seed / preview investigation queries (no fabricated results). */
const SEED_QUERIES: SuggestedQuery[] = [
  { id: "seed-1", label: "Show high-risk decisions in the last 24h", kind: "query" },
  { id: "seed-2", label: "Which hosts are on an active attack chain?", kind: "query" },
  { id: "seed-3", label: "What processes accessed lsass recently?", kind: "query" },
];

/** The intro turn — states the grounding + human-approved contract up front. */
const SEED_MESSAGES: CopilotMessage[] = [
  {
    id: "seed-ai",
    who: "ai",
    content: (
      <>
        I&apos;m the grounded NL-Query copilot. Ask about your SOC data in plain
        language — every answer cites the sources that informed it (OpenSearch ·
        Wazuh API · Knowledge base), and any containment I propose stays{" "}
        <b>human-approved</b>: I queue it for approval, I never execute it.
      </>
    ),
    chips: SEED_QUERIES,
  },
];

export function InvestigateTab(_props: TabProps) {
  const { role, tier } = useAuth();

  const { mode, messages, lastResult, canvasError, busy, onSend, onRunQuery } =
    useCopilotConversation({
      role,
      tier,
      seedMessages: SEED_MESSAGES,
      // Investigate is grounded to the whole SOC — no single-entity prefix.
    });

  const onUpgrade = useCallback(() => {
    const url = tier?.upgrade_url ?? "https://securesleuths.in/pricing";
    if (typeof window !== "undefined") window.open(url, "_blank", "noreferrer");
  }, [tier]);

  return (
    <div className="flex flex-col gap-4 lg:flex-row lg:items-start">
      {/* ===== evidence canvas (left) ===== */}
      <div className="flex min-w-0 flex-1 flex-col">
        <PageHeading
          title="Investigate"
          sub="Ask in natural language; the copilot runs queries and cites every result. This canvas holds the evidence it pulls in — click any citation for its source."
        />

        {mode === "locked" ? (
          <LockedCanvas tierName={tier?.tier_display ?? tier?.tier ?? "current"} />
        ) : (
          <EvidenceCanvas result={lastResult} error={canvasError} busy={busy} />
        )}

      </div>

      {/* ===== copilot rail (hero, right) ===== */}
      <div className="w-full lg:sticky lg:top-0 lg:w-[400px] lg:shrink-0">
        <CopilotRail
          mode={mode}
          role={role}
          tier={tier?.tier ?? "community"}
          contextLabel="your SOC data"
          messages={messages}
          previewQueries={SEED_QUERIES.map((q) => q.label)}
          onSend={onSend}
          onRunQuery={onRunQuery}
          onUpgrade={onUpgrade}
          className="h-[72vh] rounded-xl border border-line lg:h-[calc(100vh-7.5rem)]"
        />
      </div>
    </div>
  );
}

// ============================================================================
// Evidence canvas
// ============================================================================

function EvidenceCanvas({
  result,
  error,
  busy,
}: {
  result: NLQueryResponse | null;
  error: string | null;
  busy: boolean;
}) {
  if (!result && error) {
    return (
      <StatusState
        variant="error"
        title="Couldn't run that query"
        description={error}
      />
    );
  }

  if (!result) {
    return (
      <StatusState
        variant="empty"
        icon={<Search className="h-7 w-7" aria-hidden="true" />}
        title="Ask the copilot to start investigating"
        description="The evidence it pulls in appears here — each source a citation you can open. Nothing is shown until a grounded query returns; results are only what the API returned."
      />
    );
  }

  const meta = queryMeta(result);

  return (
    <div
      className="flex flex-col gap-3"
      aria-busy={busy}
      role="status"
      aria-live="polite"
    >
      {/* grounded-summary strip */}
      <Panel className="p-3">
        <div className="mb-1.5 text-micro uppercase tracking-wide text-dim2">
          Latest grounded answer
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Chip variant="grounded">{confidenceLabel(result.confidence)}</Chip>
          {result.risk_assessment && (
            <span className="text-data text-dim">{result.risk_assessment}</span>
          )}
        </div>
        {meta && <div className="mt-1.5 text-kbd text-dim2">{meta}</div>}
      </Panel>

      {/* sources pulled in */}
      <Panel className="p-3">
        <div className="mb-2 text-kbd text-dim2">
          Evidence pulled into this investigation (each is a copilot citation)
        </div>
        {result.sources.length === 0 ? (
          <div className="text-kbd text-sev-med" role="note">
            No sources returned — this answer isn&apos;t grounded in retrieved
            evidence. The copilot won&apos;t invent one.
          </div>
        ) : (
          <ul className="flex flex-col gap-2">
            {result.sources.map((s) => (
              <SourceRow key={s.id} source={s} />
            ))}
          </ul>
        )}
      </Panel>

      {/* findings (rendered defensively — never fabricated) */}
      {result.findings.length > 0 && (
        <Panel className="p-3">
          <div className="mb-2 text-kbd text-dim2">
            Findings ({result.findings.length})
          </div>
          <ul className="flex flex-col gap-1.5">
            {result.findings.map((f, i) => (
              <FindingRow key={i} finding={f} />
            ))}
          </ul>
        </Panel>
      )}
    </div>
  );
}

function SourceKindIcon({ source }: { source: string }) {
  const cls = "h-4 w-4 shrink-0 text-teal";
  switch (source) {
    case "opensearch":
      return <Database className={cls} aria-hidden="true" />;
    case "wazuh_api":
      return <Server className={cls} aria-hidden="true" />;
    case "knowledge_base":
      return <BookOpen className={cls} aria-hidden="true" />;
    default:
      return <FileSearch className={cls} aria-hidden="true" />;
  }
}

function SourceRow({ source }: { source: NLQuerySource }) {
  return (
    <li className="flex items-center gap-2.5 rounded-lg border border-line bg-panel2 px-3 py-2">
      <SourceKindIcon source={source.source} />
      <div className="min-w-0 flex-1">
        <div className="truncate text-data font-medium text-ink">
          {source.description || sourceKindLabel(source.source)}
        </div>
        <div className="text-kbd text-dim2">
          {sourceKindLabel(source.source)} · {source.count} record
          {source.count === 1 ? "" : "s"}
          {source.error ? (
            <span className="text-sev-med"> · retrieval error</span>
          ) : null}
        </div>
      </div>
      <Citation
        citation={sourceToCitation(source)}
        label={sourceCiteLabel(source)}
      />
    </li>
  );
}

function FindingRow({ finding }: { finding: NLQueryFinding }) {
  const { title, meta } = findingSummary(finding);
  return (
    <li className="text-data">
      <span className="text-ink">{title}</span>
      {meta && <span className="ml-2 text-kbd text-dim2">{meta}</span>}
    </li>
  );
}

// ============================================================================
// Locked (paid-gate) canvas — honest, no fabricated evidence
// ============================================================================

function LockedCanvas({ tierName }: { tierName: string }) {
  return (
    <StatusState
      variant="degraded"
      title="The NL-Query copilot is a paid module"
      description={`It isn't in the ${tierName} tier. You can still see the questions analysts ask in the rail — upgrade to run them and get cited, grounded answers. Nothing here is fabricated while locked.`}
    />
  );
}

// ============================================================================
// helpers (evidence-canvas presentation only)
// ============================================================================

/** Defensive finding → { title, meta } (never assumes a field is present). */
function findingSummary(f: NLQueryFinding): { title: string; meta: string } {
  // The common backend shape: `findings` is a string[] — the string IS the title.
  if (typeof f === "string") {
    return { title: f, meta: "" };
  }

  const str = (k: string): string | undefined =>
    typeof f[k] === "string" && f[k] ? (f[k] as string) : undefined;
  const num = (k: string): number | undefined =>
    typeof f[k] === "number" ? (f[k] as number) : undefined;

  const title =
    str("rule_description") ??
    str("description") ??
    str("title") ??
    str("message") ??
    (f.rule_id != null ? `Rule ${String(f.rule_id)}` : "Finding");

  const parts: string[] = [];
  const host = str("host") ?? str("agent_name");
  if (host) parts.push(host);
  if (f.rule_id != null && !title.startsWith("Rule ")) parts.push(`rule ${String(f.rule_id)}`);
  const risk = num("risk_score");
  if (risk != null) parts.push(`risk ${Math.round(risk)}`);
  const ts = str("timestamp") ?? str("created_at");
  if (ts) parts.push(ts);

  return { title, meta: parts.join(" · ") };
}
