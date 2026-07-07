"use client";

/**
 * useCopilotConversation (WO-U7) — the ONE grounded-copilot conversation engine.
 *
 * Extracted from InvestigateTab (WO-U6) so the Investigate hero AND the shell's
 * "Ask copilot" launcher rail (Incidents/Triage) share a SINGLE implementation of
 * the grounded NL-Query flow — never two divergent copies. It owns:
 *
 *   - the message thread (seeded by the caller);
 *   - `runQuery` → `POST /api/query` + ANSWER-LEVEL citation rendering from
 *     `sources` (NO fabricated per-claim citations; empty sources → an honest
 *     "not grounded, won't invent a citation" note);
 *   - the paid / read_only / normal degraded-mode selection (mirrors the server);
 *   - runtime 402/403 handling (surfaced as an honest gate note, never a
 *     fabricated answer);
 *   - the PROPOSE-ONLY containment flow → `POST /api/response/propose`
 *     (`pending_approval`; reason-required; analyst+). There is NO
 *     approve/execute/reverse/auto path here — the two endpoints this hook can
 *     ever hit are `/api/query` and `/api/response/propose`.
 *
 * Layout is NOT owned here: the Investigate hero keeps its evidence canvas, and
 * the shell keeps its slide-in rail. Both just render a <CopilotRail> from the
 * `mode` / `messages` / `onSend` / `onRunQuery` this hook returns, and Investigate
 * additionally reads `lastResult` / `canvasError` / `busy` for its canvas.
 *
 * Both data calls (`postQuery`, `proposeContainment`) are fixture-gated behind
 * NEXT_PUBLIC_DHRUVA_FIXTURES in `@/lib/api` (propose short-circuits — NO real
 * mutation), so this hook is safe to drive in screenshot/dev mode.
 */

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { Chip, Citation, ContainmentActionCard, Markdown } from "@/components";
import { ApiError, postQuery, proposeContainment } from "@/lib/api";
import { copilotAvailable, roleAtLeast } from "@/lib/rbac";
import {
  confidenceLabel,
  followUpsToQueries,
  normalizeSuggestedActions,
  proposalTitle,
  queryMeta,
  sourceCiteLabel,
  sourceToCitation,
  type ProposableContainment,
} from "@/lib/investigate";
import type { CopilotMessage, CopilotMode, SuggestedQuery } from "@/lib/copilot";
import type { LicenseTierInfo, NLQueryResponse, Role } from "@/lib/types";

export interface UseCopilotConversationOptions {
  /** active role — mirrors the server; gates propose (analyst+) + readonly mode. */
  role: Role;
  /** active tier — gates the paid copilot module (locked when absent). */
  tier: LicenseTierInfo | null;
  /** the intro turn(s) — surface-specific copy (Investigate vs shell launcher). */
  seedMessages: CopilotMessage[];
  /**
   * Optional short context hint for the CURRENT surface, e.g. "INC-204". The
   * backend `/api/query` takes a free-form `{question}` (NO context param), so
   * this is used ONLY as a lightweight prefix on the analyst's question ("About
   * INC-204: …") — it does NOT fabricate a backend capability, and the analyst's
   * message in the thread shows exactly what they typed. Omit for no prefix.
   */
  contextHint?: string;
}

export interface CopilotConversation {
  /** paid-gate + role degraded mode (locked | readonly | normal). */
  mode: CopilotMode;
  /** true iff the role may PROPOSE containment (analyst+). Mirrors the server. */
  canPropose: boolean;
  /** the live message thread to render in a <CopilotRail>. */
  messages: CopilotMessage[];
  /** the latest grounded response — for the Investigate evidence canvas. */
  lastResult: NLQueryResponse | null;
  /** the latest query error (for the canvas error state). */
  canvasError: string | null;
  /** a query is in flight. */
  busy: boolean;
  /** free-text ask handler for <CopilotRail onSend>. */
  onSend: (text: string) => void;
  /** suggested-query chip handler for <CopilotRail onRunQuery>. */
  onRunQuery: (q: SuggestedQuery) => void;
}

export function useCopilotConversation({
  role,
  tier,
  seedMessages,
  contextHint,
}: UseCopilotConversationOptions): CopilotConversation {
  const available = copilotAvailable(tier);
  const mode: CopilotMode = !available
    ? "locked"
    : role === "read_only"
      ? "readonly"
      : "normal";
  const canPropose = roleAtLeast(role, "analyst");

  const [messages, setMessages] = useState<CopilotMessage[]>(seedMessages);
  const [lastResult, setLastResult] = useState<NLQueryResponse | null>(null);
  const [canvasError, setCanvasError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => () => abortRef.current?.abort(), []);

  // ---- propose containment (PROPOSE-ONLY; reason required; analyst+) --------
  const onDeclineProposal = useCallback(() => {
    setMessages((prev) => [
      ...prev,
      {
        id: `a-decline-${prev.length}`,
        who: "ai",
        content:
          "Understood — nothing was proposed or executed. Want me to keep watching, or draft a ticket instead?",
      },
    ]);
  }, []);

  const onPropose = useCallback(
    async (p: ProposableContainment, reason: string) => {
      // Mirror the server gate; the server remains the source of truth.
      if (!canPropose) return;
      try {
        const res = await proposeContainment({
          action: p.action,
          agent_id: p.agent_id,
          target: p.target,
          timeout: p.timeout,
          alert_id: p.alert_id,
          incident_id: p.incident_id,
          reason,
        });
        setMessages((prev) => [
          ...prev,
          {
            id: `a-proposed-${prev.length}`,
            who: "ai",
            content: (
              <>
                Queued <b>{proposalTitle(p)}</b> as{" "}
                <span className="font-mono">{res.id}</span> —{" "}
                <b>{humanStatus(res.status)}</b>. It is now waiting for a human to
                approve in the <b>Respond</b> queue; nothing has executed. Your
                reason is on the audit trail.
              </>
            ),
          },
        ]);
      } catch (e) {
        setMessages((prev) => [
          ...prev,
          {
            id: `a-propose-err-${prev.length}`,
            who: "ai",
            content: <ErrorNote>{proposeErr(e)}</ErrorNote>,
          },
        ]);
      }
    },
    [canPropose],
  );

  // ---- run an NL query (grounded, cited) ------------------------------------
  const runQuery = useCallback(
    async (question: string) => {
      const q = question.trim();
      if (!q || mode !== "normal" || busyRef.current) return;
      busyRef.current = true;
      setBusy(true);
      setCanvasError(null);

      abortRef.current?.abort();
      const ac = new AbortController();
      abortRef.current = ac;

      // Lightweight context prefix (display shows the analyst's original text).
      const sent = contextHint ? `About ${contextHint}: ${q}` : q;

      const pendingId = `a-pending-${Date.now()}`;
      setMessages((prev) => [
        ...prev,
        { id: `u-${prev.length}`, who: "user", content: q },
        {
          id: pendingId,
          who: "ai",
          content: <span className="text-dim">Running a grounded query…</span>,
        },
      ]);

      try {
        const res = await postQuery(sent, ac.signal);
        if (ac.signal.aborted) return;
        const answer = buildAnswerMessage(pendingId, res, {
          canPropose,
          onPropose,
          onDecline: onDeclineProposal,
        });
        setMessages((prev) => prev.map((m) => (m.id === pendingId ? answer : m)));
        setLastResult(res);
      } catch (e) {
        if (ac.signal.aborted) return;
        const msg = queryErr(e);
        setMessages((prev) =>
          prev.map((m) =>
            m.id === pendingId
              ? { id: pendingId, who: "ai", content: <ErrorNote>{msg}</ErrorNote> }
              : m,
          ),
        );
        setCanvasError(msg);
      } finally {
        if (!ac.signal.aborted) {
          busyRef.current = false;
          setBusy(false);
        }
      }
    },
    [mode, contextHint, canPropose, onPropose, onDeclineProposal],
  );

  const onSend = useCallback((t: string) => runQuery(t), [runQuery]);
  const onRunQuery = useCallback(
    (qq: SuggestedQuery) => runQuery(qq.label),
    [runQuery],
  );

  return {
    mode,
    canPropose,
    messages,
    lastResult,
    canvasError,
    busy,
    onSend,
    onRunQuery,
  };
}

// ============================================================================
// Answer message builder — answer-level grounding, NO fabricated per-claim cites
// ============================================================================

function buildAnswerMessage(
  id: string,
  res: NLQueryResponse,
  opts: {
    canPropose: boolean;
    onPropose: (p: ProposableContainment, reason: string) => void;
    onDecline: () => void;
  },
): CopilotMessage {
  const { proposals, notes } = normalizeSuggestedActions(res.suggested_actions);
  const meta = queryMeta(res);

  return {
    id,
    who: "ai",
    content: (
      <>
        {/* the answer — the backend synthesizes MARKDOWN (tables, **bold**,
            bullets). Rendered through the shared <Markdown> (GFM, no raw HTML —
            the answer is derived from untrusted alert data). We do NOT inject
            inline per-claim cites. */}
        <Markdown>{res.answer}</Markdown>

        {res.risk_assessment && (
          <p className="mt-2 text-data text-dim">
            <span className="text-dim2">Risk assessment: </span>
            {res.risk_assessment}
          </p>
        )}

        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          <Chip aria-label={confidenceLabel(res.confidence)}>
            {confidenceLabel(res.confidence)}
          </Chip>
          {meta && <span className="text-kbd text-dim2">{meta}</span>}
        </div>

        {/* answer-level grounded citations */}
        <div className="mt-2.5 border-t border-aibd pt-2">
          {res.sources.length > 0 ? (
            <>
              <div className="mb-1 text-kbd text-dim2">
                Grounded sources (answer-level) — this answer was informed by:
              </div>
              <div className="flex flex-wrap gap-1.5">
                {res.sources.map((s) => (
                  <Citation
                    key={s.id}
                    citation={sourceToCitation(s)}
                    label={sourceCiteLabel(s)}
                  />
                ))}
              </div>
            </>
          ) : (
            <div className="text-kbd text-sev-med" role="note">
              No sources returned — this answer isn&apos;t grounded in retrieved
              evidence. Treat it with caution; I won&apos;t invent a citation.
            </div>
          )}
        </div>

        {/* informational suggested actions (non-proposable) */}
        {notes.length > 0 && (
          <ul className="mt-2 list-disc pl-4 text-data text-dim">
            {notes.map((n, i) => (
              <li key={i}>{n}</li>
            ))}
          </ul>
        )}

        {/* proposable containment(s) — PROPOSE-ONLY, human-approved */}
        {proposals.map((p, i) => (
          <ContainmentActionCard
            key={`${p.action}-${p.agent_id}-${i}`}
            mode="propose"
            title={proposalTitle(p)}
            description={p.description}
            canApprove={opts.canPropose}
            gateHint={opts.canPropose ? "you can propose" : "needs analyst+"}
            onApprove={(reason) => opts.onPropose(p, reason)}
            onDecline={opts.onDecline}
          />
        ))}
      </>
    ),
    chips: followUpsToQueries(res.follow_up_queries),
  };
}

// ============================================================================
// helpers
// ============================================================================

function ErrorNote({ children }: { children: ReactNode }) {
  return (
    <span className="text-sev-crit" role="alert">
      {children}
    </span>
  );
}

function humanStatus(status: string): string {
  const s = (status ?? "").replace(/[_-]+/g, " ").trim();
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : "pending approval";
}

/** Query error → honest message; 402/403 = the paid/quota gate. */
function queryErr(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 402 || e.status === 403) {
      return `The NL-Query copilot is gated (${e.status}) — this tier/quota can't run it. ${e.message}`;
    }
    return e.message;
  }
  if (e instanceof Error) return e.message;
  return "Unknown error";
}

function proposeErr(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 403)
      return `The server rejected the proposal (403) — proposing containment needs analyst or higher. Nothing was queued or executed.`;
    return `Couldn't queue the proposal: ${e.message}. Nothing was executed.`;
  }
  if (e instanceof Error)
    return `Couldn't queue the proposal: ${e.message}. Nothing was executed.`;
  return "Couldn't queue the proposal. Nothing was executed.";
}
