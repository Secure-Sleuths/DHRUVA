/**
 * Triage presentation helpers.
 *
 * The backend emits 4 canonical verdicts (see types.ts::TriageVerdict). The
 * queue relabels them for display exactly as the approved mockup does
 * ("◆ True positive", "Needs investigation", …). This is a PRESENTATION map
 * only — it never invents a verdict the backend can't produce.
 *
 * Colour rule: only `true_positive` carries the crit tone (mockup-faithful —
 * the most actionable verdict). Every verdict is always shown as glyph + word,
 * so colour is never the sole carrier of meaning; the neutral verdicts stay off
 * the severity red so red keeps meaning "severity". Row severity + the risk
 * number come from `risk_score` (see severity.ts::riskSeverity), not the verdict.
 */

export interface VerdictPresentation {
  /** plain-language label (human words, not the raw snake_case value) */
  label: string;
  /** shape that carries meaning without colour */
  glyph: string;
  /** tailwind text-colour utility */
  className: string;
}

const VERDICTS: Record<string, VerdictPresentation> = {
  true_positive: {
    label: "True positive",
    glyph: "◆",
    className: "text-sev-crit",
  },
  needs_investigation: {
    label: "Needs investigation",
    glyph: "◇",
    className: "text-ink",
  },
  false_positive: {
    label: "False positive",
    glyph: "○",
    className: "text-dim",
  },
  auto_close: {
    label: "Auto-closed",
    glyph: "✓",
    className: "text-dim2",
  },
};

/**
 * WO-H46-c: presentation for a decision the AI never actually made.
 *
 * When the LLM backend is unreachable, triage fails CLOSED — it escalates with
 * `verdict: 'needs_investigation'` and `confidence: 0` WITHOUT analyzing the
 * alert. On the wire that is indistinguishable from a considered escalation,
 * which is how a backend outage came to masquerade as a busy queue (1398
 * un-analyzed rows on one install before anyone noticed).
 *
 * Rendering it as "Needs investigation" would repeat that lie in the UI, so it
 * gets its own label. `text-sev-med` deliberately reads as a caution state:
 * this is not a severity claim about the alert (nothing assessed its severity)
 * — it is a warning that the queue entry is unprocessed work, not a judgement.
 */
export const NOT_ANALYZED: VerdictPresentation = {
  label: "Not analyzed",
  glyph: "⚠",
  className: "text-sev-med",
};

/**
 * Presentation for a whole decision row — prefer this over
 * `verdictPresentation()` anywhere a `TriageDecision` is in hand, so a failed
 * triage can never be displayed as if the AI had reached a conclusion.
 */
export function decisionPresentation(decision: {
  verdict: string;
  llm_failed?: boolean;
}): VerdictPresentation {
  if (decision.llm_failed) return NOT_ANALYZED;
  return verdictPresentation(decision.verdict);
}

/** Humanise an unexpected/newer verdict value ("some_new" → "Some new"). */
function humanize(value: string): string {
  const s = value.replace(/[_-]+/g, " ").trim();
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : "Unknown";
}

/** Presentation for a verdict, degrading gracefully for unknown values. */
export function verdictPresentation(verdict: string): VerdictPresentation {
  return (
    VERDICTS[verdict] ?? {
      label: humanize(verdict),
      glyph: "•",
      className: "text-dim",
    }
  );
}
