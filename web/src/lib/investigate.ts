/**
 * Investigate (grounded copilot) presentation + adapter helpers — WO-U6.
 *
 * Pure functions that translate the WO-B8 `POST /api/query` response into the
 * copilot rail's data shapes WITHOUT ever fabricating grounding:
 *   - `sources` → answer-level `Citation` chips (the MVP grounding granularity —
 *     per-claim inline citations are a marked fast-follow, NOT invented here);
 *   - `follow_up_queries` → suggested-investigation-query chips;
 *   - `suggested_actions` → a proposable containment ONLY when the backend gives
 *     us the fields the propose endpoint needs (`action` + `agent_id`); a bare
 *     label renders as an informational note, never a fabricated proposal.
 *
 * Nothing here calls the API or holds React state — the tab wires the handlers.
 */

import type { CopilotCitation, SuggestedQuery } from "./copilot";
import type {
  NLQueryConfidence,
  NLQueryResponse,
  NLQuerySource,
  NLQuerySuggestedAction,
} from "./types";

// ---- source-plane labels ----------------------------------------------------
/** Human label for a WO-B8 source plane (falls back to the raw value). */
export function sourceKindLabel(source: string): string {
  switch (source) {
    case "opensearch":
      return "OpenSearch";
    case "wazuh_api":
      return "Wazuh API";
    case "knowledge_base":
      return "Knowledge base";
    default:
      return source;
  }
}

/**
 * A COMPACT label for the inline citation chip — prefer the concrete locator
 * (index / dataset), else the plane label. Keeps the chip short while the
 * popover carries the full description.
 */
export function sourceCiteLabel(s: NLQuerySource): string {
  return s.index || s.dataset || sourceKindLabel(s.source);
}

/**
 * Map a WO-B8 `source` onto the `CopilotCitation` the `Citation` chip renders.
 * `detail` is composed from the metadata the contract guarantees (count + index/
 * dataset + any per-source error) — NEVER a raw hit body (the contract carries
 * none). This is honest grounding: only what the API returned.
 */
export function sourceToCitation(s: NLQuerySource): CopilotCitation {
  const bits: string[] = [
    `${s.count} matching record${s.count === 1 ? "" : "s"}`,
  ];
  if (s.index) bits.push(`index ${s.index}`);
  if (s.dataset) bits.push(`dataset ${s.dataset}`);
  if (s.error) bits.push(`retrieval error: ${s.error}`);
  return {
    id: s.id,
    kind: sourceKindLabel(s.source),
    title: s.description || sourceKindLabel(s.source),
    detail: bits.join(" · "),
  };
}

// ---- confidence (coarse 3-level, NEUTRAL ramp) ------------------------------
/** Present the coarse answer confidence — plain word, never a severity colour. */
export function confidenceLabel(c: NLQueryConfidence | string): string {
  switch (c) {
    case "high":
      return "High confidence";
    case "medium":
      return "Medium confidence";
    case "low":
      return "Low confidence";
    default:
      return `Confidence: ${c}`;
  }
}

// ---- follow-up queries → chips ----------------------------------------------
/** Turn `follow_up_queries` into suggested-query chips (deduped, non-empty). */
export function followUpsToQueries(queries: readonly string[]): SuggestedQuery[] {
  const seen = new Set<string>();
  const out: SuggestedQuery[] = [];
  for (const q of queries) {
    const label = (q ?? "").trim();
    if (!label || seen.has(label)) continue;
    seen.add(label);
    out.push({ id: `fq-${out.length}`, label, kind: "query" });
  }
  return out;
}

// ---- suggested actions → proposable containment -----------------------------
/**
 * A containment the copilot proposed, normalized to exactly the fields
 * `POST /api/response/propose` needs. Only produced when the backend supplied
 * both `action` and `agent_id` — otherwise we do NOT fabricate a target.
 */
export interface ProposableContainment {
  action: string;
  agent_id: string;
  target?: string;
  incident_id?: string;
  alert_id?: string;
  timeout?: number;
  /** rationale copy to show on the card (falls back to a generic line) */
  description: string;
}

/**
 * Split `suggested_actions` into proposable containments (structured, with the
 * required propose fields) and plain informational notes (bare strings / actions
 * missing a target). This is the guard that keeps the propose flow honest: the
 * UI only ever offers a containment the backend actually scoped.
 */
export function normalizeSuggestedActions(
  actions: readonly NLQuerySuggestedAction[] | undefined | null,
): { proposals: ProposableContainment[]; notes: string[] } {
  const proposals: ProposableContainment[] = [];
  const notes: string[] = [];
  if (!Array.isArray(actions)) return { proposals, notes };

  for (const a of actions) {
    if (typeof a === "string") {
      const s = a.trim();
      if (s) notes.push(s);
      continue;
    }
    if (!a || typeof a !== "object") continue;

    const action = typeof a.action === "string" ? a.action.trim() : "";
    const agentId = typeof a.agent_id === "string" ? a.agent_id.trim() : "";
    // Proposable ONLY with both the action verb and a concrete agent to act on.
    // Missing either → surface as a note, never a fabricated proposal.
    if (action && agentId) {
      proposals.push({
        action,
        agent_id: agentId,
        target:
          (typeof a.target === "string" && a.target) ||
          (typeof a.host === "string" && a.host) ||
          undefined,
        incident_id:
          typeof a.incident_id === "string" ? a.incident_id : undefined,
        alert_id: typeof a.alert_id === "string" ? a.alert_id : undefined,
        timeout: typeof a.timeout === "number" ? a.timeout : undefined,
        description:
          (typeof a.description === "string" && a.description) ||
          (typeof a.label === "string" && a.label) ||
          `Propose containment: ${action}`,
      });
    } else {
      const note =
        (typeof a.description === "string" && a.description) ||
        (typeof a.label === "string" && a.label) ||
        (action ? `Suggested action: ${action}` : "");
      if (note) notes.push(note);
    }
  }
  return { proposals, notes };
}

/** A human title for a proposed containment, e.g. "Isolate host WIN-APP-03". */
export function proposalTitle(p: ProposableContainment): string {
  const verb = p.action.replace(/[_-]+/g, " ").trim();
  const label = verb.charAt(0).toUpperCase() + verb.slice(1);
  return p.target ? `${label} — ${p.target}` : label;
}

// ---- query metadata footer --------------------------------------------------
/**
 * One-line query metadata footer, e.g. "3 queries run · 7 hits · 1840 ms".
 * Pure + defensive — only renders the fields the API actually returned, never a
 * fabricated count. Shared by the copilot answer bubble and the evidence canvas.
 */
export function queryMeta(res: NLQueryResponse): string {
  const parts: string[] = [];
  if (typeof res.queries_executed === "number")
    parts.push(
      `${res.queries_executed} quer${res.queries_executed === 1 ? "y" : "ies"} run`,
    );
  if (typeof res.total_hits === "number") parts.push(`${res.total_hits} hits`);
  if (typeof res.duration_ms === "number") parts.push(`${res.duration_ms} ms`);
  return parts.join(" · ");
}
