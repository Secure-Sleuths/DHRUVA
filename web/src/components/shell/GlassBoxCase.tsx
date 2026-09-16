"use client";

/**
 * GlassBoxCase — the shared glass-box card for ONE AI decision (WO-U4 / WO-U5).
 *
 * Extracted from IncidentsTab so the SAME glass-box case renders in TWO places
 * from ONE implementation:
 *   - the Incidents case view (a member alert of an incident), and
 *   - the Triage queue (opening a triage row → THAT decision's glass-box case).
 *
 * A triage decision and an incident "member alert" are the SAME entity (an
 * `agent_decisions` row keyed on `id`), so both surfaces build an
 * `IncidentAlert` and render `<GlassBoxAlertCard>`: verdict + confidence + risk
 * math + 5-step reasoning + provenance + the field-level anonymization boundary,
 * plus the reason-required review form (analyst+; overriding an EXISTING human
 * verdict is admin-only per WO-B10). The RBAC gate is identical in both places —
 * it lives in `triageReviewGate` and is mirrored from the server, never widened.
 *
 * WO-H86 reordered the card body. It used to be a flat list of ~16 siblings in
 * which nine context rows and the risk maths came BEFORE the reasoning and the
 * recommended action, so on a real case the remediation was pushed off a 1080p
 * screen and the analyst could not tell what needed their eyes. The body is now:
 *
 *   1. reasoning                (open by default)
 *   2. recommended actions      (open by default)
 *   3. ONE collapsed box        — risk maths, all nine context records, the
 *                                 playbook, rule stats, the raw event,
 *                                 provenance and the anonymization boundary
 *   4. review history + the override form (the ACTION, never detail)
 *
 * Nothing was removed and nothing is hidden on emptiness: every context
 * dimension still renders, and each one states in one scannable line what the
 * stored record actually holds. It keeps THREE things apart — "no record
 * stored", "a record that holds nothing" (`no signal recorded`) and "the check
 * errored" (`degraded_enrichers`) — and never upgrades a pre-seeded zero into
 * a claim that a check ran, because for most enrichers a clean result and a
 * never-ran result are byte-identical on disk.
 */

import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { Chip, ConfidenceBar, Panel, StatusState } from "@/components";
import {
  ApiError,
  getDecisionPlaybook,
  getDecisionRawAlert,
  getDecisionReviews,
  getRuleStats,
  lookupIoc,
  submitTriageReview,
} from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { triageReviewGate } from "@/lib/rbac";
import {
  SEVERITY,
  SEVERITY_ORDER,
  riskSeverity,
  type Severity,
} from "@/lib/severity";
import { verdictPresentation, decisionPresentation } from "@/lib/triage";
import {
  alertEnrichment,
  anonymizationCopy,
  caseContext,
  parseJsonArray,
  riskMath,
  ruleAccuracy,
  scorePresentation,
  type CaseContext,
} from "@/lib/incident";
import { parseGrounding, type GroundingAssessment } from "@/lib/grounding";
import { cn, focusRing } from "@/lib/ui";
import type {
  DecisionPlaybookResponse,
  DecisionReview,
  IncidentAlert,
  IocLookupResponse,
  RawAlertResponse,
  RuleStats,
  TriageVerdict,
} from "@/lib/types";

// ---- one member alert / decision as a glass-box card ------------------------

export function GlassBoxAlertCard({
  alert,
  primary,
  onReviewed,
}: {
  alert: IncidentAlert;
  primary: boolean;
  onReviewed: () => void;
}) {
  // Non-primary cards start collapsed to keep the case focused on the driver.
  const [open, setOpen] = useState(primary);
  const bodyId = useId();
  const verdict = decisionPresentation({
    verdict: String(alert.verdict),
    llm_failed: alert.llm_failed,
  });
  const enr = alertEnrichment(alert);
  const stage = enr.tactic_ids[0];

  return (
    <Panel inset className="p-3">
      {/* header: verdict + confidence + grounding + score + stage.
          WO-H86 contradiction #1/#2: the confidence meter and the grounding
          self-check are LABELLED so they cannot be read as arguing.
          WO-H97: and the number is labelled as what it actually measures —
          see ScoreBadge. */}
      <div className="flex flex-wrap items-center gap-2.5">
        <span
          className={cn(
            "inline-flex items-center gap-1 text-data font-semibold",
            verdict.className,
          )}
        >
          <span aria-hidden="true">{verdict.glyph}</span>
          <span>AI verdict — {verdict.label}</span>
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="text-kbd text-dim2">confidence</span>
          <ConfidenceBar value={alert.confidence} width={72} />
        </span>
        <GroundingBadge
          grounding={alert.grounding}
          confidence={alert.confidence}
        />
        <span className="flex-1" />
        {stage && <Chip>stage: {stage}</Chip>}
        <ScoreBadge alert={alert} />
        {!primary && (
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
            aria-controls={bodyId}
            className={cn(
              "rounded-md border border-line bg-field px-2 py-0.5 text-kbd text-ink hover:bg-hover",
              focusRing,
            )}
          >
            {open ? "Hide detail" : "Show glass-box detail"}
          </button>
        )}
      </div>
      <div className="mt-0.5 font-mono text-kbd text-dim2">
        {alert.rule_description ?? `Alert ${alert.id}`}
        {alert.rule_id != null ? ` · rule ${alert.rule_id}` : ""} · {alert.id}
      </div>

      {/* detail body — WO-H86 reading order.
          Before: nine sibling context rows + seven more expanders sat ABOVE
          the reasoning and the recommended action, so on a real case the
          remediation ("block x.x.x.x at the WAF") was pushed off-screen.
          Now: what the AI concluded → what to do about it → ONE collapsed box
          holding every piece of scoring/enrichment detail → the analyst's
          action (review history + override form), which is never detail. */}
      {/* NOTE: the `hidden` element itself must carry NO display utility. A
          Tailwind `flex` on this div is an AUTHOR-origin `display: flex`, which
          beats the user-agent's `[hidden] { display: none }` — so a collapsed
          card rendered its whole body anyway, and every member alert in a case
          was fully expanded no matter what its button said. The flex column
          moves to an inner wrapper. */}
      <div id={bodyId} hidden={!open}>
        <div className="mt-3 flex flex-col gap-2.5">
          <ReasoningExpander alert={alert} />
          <RecommendedActionsExpander alert={alert} />
          <CaseDetailBox alert={alert} />
          <TriageDecisionPanel alert={alert} onReviewed={onReviewed} />
        </div>
      </div>
    </Panel>
  );
}

/**
 * WO-H97 — the number, labelled as what it actually measures.
 *
 * THE FAILURE THIS FIXES. An analyst opened a case for thirty `404`s from
 * `l9explore` (LeakIX's public internet crawler), saw **99.41** in this exact
 * spot under the word "risk", and concluded the product was broken. They were
 * right to. The figure is a truthful answer to "how often has a human confirmed
 * this rule fired correctly?" — 443 of 443 on rule 31516 — displayed under a
 * label that reads "how dangerous is this?".
 *
 * NOTHING IN THE MATHS MOVES. WO-H71's bounded scorer is untouched. This is a
 * labelling fix, plus one deliberate colour decision: under the bounded model
 * the number is NOT painted on the severity ramp. A rule-precision figure
 * rendered in critical-red *is* the misreading, in colour. Severity has its own
 * badge, computed by the backend from the risk band and the guidance floors and
 * ceilings (src/incidents/severity.py) — this is not it.
 *
 * The LEGACY multiplicative model is a different quantity (a composite risk
 * figure), so it keeps the old wording AND the old tint. An absent or
 * unrecognised breakdown falls back to the same honest legacy wording rather
 * than claiming a precision the record does not support.
 */
function ScoreBadge({ alert }: { alert: IncidentAlert }) {
  const p = scorePresentation(
    alert.risk_score,
    alert.glass_box?.risk_breakdown,
  );
  return (
    <span className="inline-flex items-baseline gap-1">
      <span
        className={cn(
          "font-mono text-data font-bold tabular",
          p.tinted
            ? SEVERITY[riskSeverity(alert.risk_score)].textClass
            : "text-ink",
        )}
      >
        {p.tinted ? `risk ${p.figure}` : p.figure}
      </span>
      <span className="text-micro text-dim2">{p.caption}</span>
    </span>
  );
}

// ---- expandable: how was risk = N computed? ---------------------------------

/**
 * A collapsible row. `hint` is the one-line preview shown next to the summary
 * so the row can be SCANNED without opening it (WO-H86).
 *
 * `tone` gives that preview visual weight on the shared severity scale: a row
 * whose preview is alarming ("500 open rootcheck findings") must not look
 * identical to one whose preview is nothing ("0 feed hits — checked, nothing
 * known"). Severity is ALWAYS glyph + word + colour, never colour alone (the
 * `@/lib/severity` accessibility invariant) — the glyph is drawn and the
 * severity word is exposed to assistive tech.
 */
function Expander({
  summary,
  hint,
  tone,
  children,
  defaultOpen = false,
}: {
  summary: string;
  hint?: string;
  tone?: PreviewTone;
  children: ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const id = useId();
  return (
    <div className="rounded-lg border border-line bg-panel px-3 py-2">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-controls={id}
        className={cn(
          "flex w-full flex-wrap items-center gap-x-2 gap-y-0.5 text-left text-data text-teal",
          focusRing,
        )}
      >
        <span aria-hidden="true">{open ? "⌄" : "›"}</span>
        <span>{summary}</span>
        {hint && <PreviewLine text={hint} tone={tone ?? null} />}
      </button>
      <div id={id} hidden={!open} className="mt-2">
        {children}
      </div>
    </div>
  );
}

/** The scannable one-line preview, weighted by severity when it matters. */
function PreviewLine({
  text,
  tone,
  className,
}: {
  text: string;
  tone: PreviewTone;
  className?: string;
}) {
  if (!tone) {
    return (
      <span className={cn("text-kbd text-dim2", className)}>{text}</span>
    );
  }
  // "The check errored" is NOT a severity — it is an absence of knowledge. It
  // uses the amber `gated` surface (the same one the grounding flag uses),
  // never the severity scale, so red stays reserved for severity (WO-U1).
  if (tone === "degraded") {
    return (
      <span
        className={cn(
          "inline-flex items-center gap-1 rounded-md border border-gated-border bg-gated-bg px-1.5 text-kbd font-semibold text-gated-ink",
          className,
        )}
      >
        <span aria-hidden="true">⚠</span>
        <span>{text}</span>
        <span className="sr-only"> (enrichment degraded — result unknown)</span>
      </span>
    );
  }
  const meta = SEVERITY[tone];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 text-kbd font-semibold",
        meta.textClass,
        className,
      )}
    >
      <span aria-hidden="true">{meta.glyph}</span>
      <span>{text}</span>
      <span className="sr-only"> ({meta.label} — needs attention)</span>
    </span>
  );
}

/**
 * WO-H97: the bounded scorer (the default since WO-H71) records a COMPLETELY
 * different breakdown from the legacy multiplier chain — rule label counts, not
 * per-enricher multipliers. `riskMath` returns null for it, so this expander
 * used to tell the analyst "no per-enricher risk breakdown was recorded", over
 * a decision whose breakdown was recorded in full. This renders it.
 *
 * It says out loud that the enrichment factors contributed NOTHING, because
 * that is true and is deliberate: every multiplier measured at or below 0.5 AUC
 * on this estate, so none of them carries a weight (WO-H71).
 */
function BoundedScoreDetail({
  accuracy,
  score,
}: {
  accuracy: NonNullable<ReturnType<typeof ruleAccuracy>>;
  score: number;
}) {
  return (
    <>
      {accuracy.confident && accuracy.pct !== null ? (
        <div className="font-mono text-body leading-relaxed">
          <b className="tabular">{`${accuracy.pct}%`}</b>{" "}
          <span className="text-dim2">
            of the {accuracy.labels ?? "—"} human label
            {accuracy.labels === 1 ? "" : "s"} on this rule say it fired
            correctly
          </span>
          {accuracy.tp !== null && accuracy.labels !== null && (
            <span className="text-dim2">
              {" "}
              ({accuracy.tp} of {accuracy.labels})
            </span>
          )}{" "}
          → <b className="tabular">{score}</b>{" "}
          <span className="text-kbd text-dim2">score</span>
        </div>
      ) : (
        <div className="font-mono text-body leading-relaxed">
          <span className="text-dim2">
            No track record for this rule yet
            {accuracy.reason ? ` — ${accuracy.reason}` : ""}. The score{" "}
          </span>
          <b className="tabular">{score}</b>{" "}
          <span className="text-dim2">
            is the platform&apos;s starting value for an unlearned rule, not a
            measurement of this rule.
          </span>
        </div>
      )}
      <div className="mt-1.5 text-kbd text-dim2">
        This is <b>rule precision</b> — how often a human has confirmed this rule
        fired correctly. It is not a measure of how dangerous this alert is, and
        a rule can be right every single time about something harmless. Severity
        is decided separately. The enrichment factors (asset, identity, time,
        vulnerabilities, host integrity) contributed nothing here: none of them
        separated true from false positives on this estate, so none of them
        carries a weight.
      </div>
    </>
  );
}

function RiskMathExpander({ alert }: { alert: IncidentAlert }) {
  const math = riskMath(alert.glass_box?.risk_breakdown);
  const accuracy = ruleAccuracy(alert.glass_box?.risk_breakdown);
  const score = Math.round(alert.risk_score);
  return (
    <Expander
      summary={
        accuracy
          ? "Where did this number come from?"
          : `How was risk = ${score} computed?`
      }
      hint={accuracy ? "rule track record" : "per-enricher breakdown"}
      defaultOpen={false}
    >
      {accuracy ? (
        <BoundedScoreDetail accuracy={accuracy} score={score} />
      ) : math ? (
        <>
          <div className="font-mono text-body leading-relaxed">
            <span className="tabular">{fmtNum(math.base.value)}</span>{" "}
            <span className="text-dim2">base</span>
            {math.factors.map((f) => (
              <span key={f.key}>
                {" "}
                × <span className={toneClass(f.tone)}>{fmtNum(f.value)}</span>{" "}
                <span className="text-dim2">{f.label}</span>
              </span>
            ))}
            {math.raw !== null && (
              <>
                {" "}
                = <span className="tabular">{fmtNum(math.raw)}</span>
              </>
            )}
            {math.clamped !== null && (
              <>
                {" "}
                → <b className="tabular">{Math.round(math.clamped)}</b>{" "}
                <span className="text-kbd text-dim2">normalized</span>
              </>
            )}
          </div>
          <div className="mt-1.5 text-kbd text-dim2">
            Each factor multiplies the base severity; remove one (e.g. the asset
            criticality or the TI hit) and the score recomputes. Multipliers
            below 1.0 are historical-FP discounts that pull the score down.
          </div>
        </>
      ) : (
        <div className="text-kbd text-dim">
          No per-enricher risk breakdown was recorded for this decision (older
          decision, or no audit trail). The score {score} is the stored value.
        </div>
      )}
      <WhichRiskNumberNote score={score} isRulePrecision={accuracy !== null} />
    </Expander>
  );
}

/**
 * WO-H86 contradiction #2: the card header shows `risk 96` while the AI's own
 * prose may say "composite risk score is 86.54/100". Both statements are on
 * screen and they are not the same quantity — the header is DHRUVA's stored,
 * bounded score; the figure inside the narrative is the model's own arithmetic,
 * which nothing validates and which we cannot edit. Say so plainly rather than
 * fabricating agreement between them.
 */
function WhichRiskNumberNote({
  score,
  isRulePrecision,
}: {
  score: number;
  isRulePrecision: boolean;
}) {
  return (
    <div className="mt-2 border-t border-line pt-2 text-kbd text-dim2">
      Which number is authoritative:{" "}
      <b className="text-dim">
        {isRulePrecision ? `${score}` : `risk ${score}`}
      </b>{" "}
      in the card header is the platform&apos;s stored score for this decision —
      computed by the chain above and bounded
      {isRulePrecision
        ? ", and it measures how often this RULE is right, not how dangerous"
          + " this alert is"
        : ""}
      . If the AI quotes a risk figure inside its own reasoning text, that is
      the model&apos;s arithmetic, not this score, and the two may differ.
    </div>
  );
}

function ReasoningExpander({ alert }: { alert: IncidentAlert }) {
  // AIS2 self-check on THIS verdict's reasoning. Only surfaced for low/medium
  // with recorded detail — a high/absent assessment adds nothing here.
  const g = parseGrounding(alert.grounding);
  const showGrounding =
    g != null &&
    g.grounding !== "high" &&
    (g.reasons.length > 0 || g.unsupported.length > 0);
  return (
    <Expander
      summary="Why did the AI decide this?"
      hint="5-step reasoning (stored anonymized)"
      // WO-H86: the analyst's first question. Open by default, first in the body.
      defaultOpen
    >
      {alert.reasoning ? (
        <p className="text-data leading-relaxed text-dim">{alert.reasoning}</p>
      ) : (
        <div className="text-kbd text-dim">
          No reasoning was stored for this decision.
        </div>
      )}
      {showGrounding && <GroundingDetail g={g} />}
    </Expander>
  );
}

/** Parse `actions_taken` (JSON string array, an already-parsed array, or
 * null/malformed) into a clean list of non-empty strings. Never throws. */
function parseActions(raw?: string | string[] | null): string[] {
  if (!raw) return [];
  let arr: unknown = raw;
  if (typeof raw === "string") {
    try {
      arr = JSON.parse(raw);
    } catch {
      return [];
    }
  }
  if (!Array.isArray(arr)) return [];
  return arr
    .map((a) => (typeof a === "string" ? a.trim() : ""))
    .filter((a) => a.length > 0);
}

// ---- the AI's recommended next-steps (legacy "Recommended Actions") ----------
/**
 * The verdict's suggested next-steps, from the `actions_taken` column. Read-only
 * and advisory — this lists what the AI recommends; DHRUVA does not run them.
 *
 * WO-H86: SECOND in the body and open by default — the remediation is the thing
 * the analyst acts on, and it used to be pushed off-screen by nine context rows.
 * It no longer disappears when empty either: "we stored no recommendation" is a
 * fact the analyst should be able to read, not an absent box they must infer.
 */
function RecommendedActionsExpander({ alert }: { alert: IncidentAlert }) {
  const actions = parseActions(alert.actions_taken);
  return (
    <Expander
      summary="Recommended actions"
      hint={
        actions.length > 0
          ? `${actions.length} suggested · advisory`
          : "none recorded"
      }
      defaultOpen
    >
      {actions.length > 0 ? (
        <ul className="flex flex-col gap-1">
          {actions.map((a, i) => (
            <li
              key={i}
              className="flex gap-2 text-data leading-relaxed text-dim"
            >
              <span aria-hidden="true" className="text-teal">
                •
              </span>
              <span>{a}</span>
            </li>
          ))}
        </ul>
      ) : (
        <div className="text-kbd text-dim">
          No recommended actions were stored with this decision — the AI
          returned none, or this is an older decision from before they were
          persisted. Fall back to the matched playbook in the detail below.
        </div>
      )}
    </Expander>
  );
}

// ---- AIS2 grounding self-check (FLAG-ONLY, decorative) ----------------------
/**
 * A decorative attention flag driven by the AI's OWN grounding self-check
 * (`grounding.ts::parseGrounding`). It never mutates the verdict, escalates, or
 * changes any decision state — it only tells the analyst where the AI was unsure.
 *
 * Colour discipline (WO-U1): `low` uses the AMBER `gated` warm surface, never the
 * severity red — red stays reserved for severity. `medium` is a muted note;
 * `high` / null / absent / malformed render NOTHING.
 *
 * WO-H86 contradiction #1: this badge used to read "AI not confident — needs
 * your eyes" while the header next to it showed a 0.92 confidence meter, so the
 * screen appeared to argue with itself. It never read confidence at all: this
 * is the model's grounding SELF-CHECK — how well its stated reasoning is tied
 * to the evidence it was given. The label is now written against the actual
 * confidence value so an analyst reads the true, non-contradictory statement:
 * "confident, but on thin evidence".
 */

/** Confidence at/above this reads as "the model was sure of itself". */
const CONFIDENT_AT = 0.75;

function GroundingBadge({
  grounding,
  confidence,
}: {
  grounding?: string | null;
  confidence?: number | null;
}) {
  const g = parseGrounding(grounding);
  if (!g || g.grounding === "high") return null;

  const sure = typeof confidence === "number" && confidence >= CONFIDENT_AT;

  if (g.grounding === "low") {
    return (
      <span
        role="note"
        className="inline-flex flex-wrap items-center gap-x-1.5 gap-y-0.5 rounded-md border border-gated-border bg-gated-bg px-2 py-0.5 text-meta font-semibold text-gated-ink"
      >
        <span aria-hidden="true">⚠</span>
        <span>
          {sure
            ? "Confident, but on thin evidence"
            : "Unsure, and on thin evidence"}
        </span>
        <span className="font-normal opacity-80">
          — the AI&apos;s own self-check, not its confidence
        </span>
      </span>
    );
  }

  // medium → muted/subtle note (no amber prominence)
  return (
    <span className="inline-flex items-center gap-1 text-kbd text-dim2">
      <span aria-hidden="true">◔</span>
      Evidence only partly grounded (AI self-check)
    </span>
  );
}

function GroundingDetail({ g }: { g: GroundingAssessment }) {
  const low = g.grounding === "low";
  return (
    <div
      className={cn(
        "mt-2 rounded-lg border px-3 py-2",
        low ? "border-gated-border bg-gated-bg" : "border-line bg-panel",
      )}
    >
      <div
        className={cn(
          "flex items-center gap-1.5 text-kbd font-semibold",
          low ? "text-gated-ink" : "text-dim",
        )}
      >
        <span aria-hidden="true">{low ? "⚠" : "◔"}</span>
        {low
          ? "The AI's own self-check could not tie this reasoning back to the evidence"
          : "The AI's own self-check tied only part of this reasoning back to the evidence"}
      </div>
      {g.reasons.length > 0 && (
        <ul className="mt-1.5 list-disc pl-4 text-kbd leading-relaxed text-dim">
          {g.reasons.map((r, i) => (
            <li key={i}>{r}</li>
          ))}
        </ul>
      )}
      {g.unsupported.length > 0 && (
        <div className="mt-1.5 text-kbd text-dim2">
          <span className="text-dim">Claims it couldn&apos;t tie to evidence:</span>{" "}
          {g.unsupported.join("; ")}
        </div>
      )}
      <div className="mt-1.5 text-micro text-dim2">
        An automated check on the AI&apos;s output — it flags for your review only
        and never changes the verdict. It measures how well the reasoning is tied
        to the evidence, which is a DIFFERENT question from the confidence score
        in the header: a model can be very confident on thin evidence.
      </div>
    </div>
  );
}

// ---- rule-stats drill (WO-U13, LAZY on first expand, READ-ONLY) -------------
/**
 * Collapsible "Rule N stats (7d)" drill on the decision card. Mirrors the local
 * `Expander` markup but is LAZY: the children (and therefore the
 * `getRuleStats(rule_id)` fetch) mount only on the FIRST expand — never up-front
 * per card. Renders total / TP / FP / auto-closed counts, FP-rate as a percent,
 * and avg-confidence; handles loading / error / empty. If the decision has no
 * `rule_id` (nullable / non-numeric) the whole panel renders nothing.
 * READ-ONLY — this is a per-rule stats read, it never mutates a verdict.
 */
function RuleStatsExpander({ alert }: { alert: IncidentAlert }) {
  const raw = alert.rule_id;
  const ruleId = raw == null ? NaN : Number(raw);
  const id = useId();
  const [open, setOpen] = useState(false);
  const [fetched, setFetched] = useState(false);
  const [stats, setStats] = useState<RuleStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(async () => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setLoading(true);
    setError(null);
    try {
      // days omitted → server default (7). Rule id is guaranteed finite here.
      const res = await getRuleStats(ruleId, undefined, ac.signal);
      if (ac.signal.aborted) return;
      setStats(res);
    } catch (e) {
      if (ac.signal.aborted) return;
      setError(errMessage(e));
    } finally {
      if (!ac.signal.aborted) setLoading(false);
    }
  }, [ruleId]);

  useEffect(() => () => abortRef.current?.abort(), []);

  // No rule_id (nullable / non-numeric) → no panel at all.
  if (!Number.isFinite(ruleId)) return null;

  const toggle = () => {
    const next = !open;
    setOpen(next);
    // Fetch only on the FIRST expand — the drill is lazy per WO-U13.
    if (next && !fetched) {
      setFetched(true);
      load();
    }
  };

  return (
    <div className="rounded-lg border border-line bg-panel px-3 py-2">
      <button
        type="button"
        onClick={toggle}
        aria-expanded={open}
        aria-controls={id}
        className={cn(
          "flex w-full items-center gap-1.5 text-left text-data text-teal",
          focusRing,
        )}
      >
        <span aria-hidden="true">{open ? "⌄" : "›"}</span>
        <span>Rule {ruleId} stats (7d)</span>
        <span className="text-kbd text-dim2">TP / FP · noisiness</span>
      </button>
      <div id={id} hidden={!open} className="mt-2">
        {!fetched ? null : loading ? (
          <StatusState variant="loading" title="Loading rule stats…" />
        ) : error ? (
          <StatusState
            variant="error"
            title="Couldn't load rule stats"
            description={error}
            action={<Chip onClick={load}>Retry</Chip>}
          />
        ) : !stats || stats.total === 0 ? (
          <div className="text-kbd text-dim">
            No decisions for rule {ruleId} in the last 7 days.
          </div>
        ) : (
          <RuleStatsBody stats={stats} />
        )}
      </div>
    </div>
  );
}

function RuleStatsBody({ stats }: { stats: RuleStats }) {
  const fpPct = Math.round(stats.fp_rate * 100);
  const confPct = Math.round(stats.avg_confidence * 100);
  // A high FP rate = a noisy rule (a candidate for the Detection feedback loop).
  const noisy = stats.fp_rate >= 0.5 && stats.total >= 5;
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap gap-x-4 gap-y-1 font-mono text-kbd">
        <RuleStat label="total" value={String(stats.total)} />
        <RuleStat label="TP" value={String(stats.tp_count)} />
        <RuleStat label="FP" value={String(stats.fp_count)} />
        <RuleStat label="auto-closed" value={String(stats.auto_closed)} />
        <RuleStat label="FP rate" value={`${fpPct}%`} />
        <RuleStat label="avg confidence" value={`${confPct}%`} />
      </div>
      <div className="text-kbd text-dim2">
        {noisy ? (
          <>
            High false-positive rate over the last 7 days — a noisy rule the
            Detection feedback loop may propose tuning.
          </>
        ) : (
          <>Per-rule verdict history over the last 7 days (tenant-scoped).</>
        )}
      </div>
    </div>
  );
}

function RuleStat({ label, value }: { label: string; value: string }) {
  return (
    <span>
      <span className="text-dim2">{label} </span>
      <b className="tabular text-ink">{value}</b>
    </span>
  );
}

// ---- WO-H21: complete-context case view --------------------------------------
// The records BEHIND each risk factor, the matched playbook's content, and the
// raw underlying Wazuh event — inline in the case so no team member has to
// pivot to Admin config / ThreatIntel / HostIntegrity / the copilot for them.
// DISPLAY-ONLY on the human (deanonymized) side: everything here is a read of
// already-stored data; nothing feeds the LLM and no action gains a new path.
// No role gate beyond seeing the case itself (whole-team visibility).

/**
 * Shared lazy drill: collapsible panel whose `load` fetch fires only on the
 * FIRST expand (mirrors the WO-U13 RuleStatsExpander pattern — never an
 * up-front fetch per card). Handles loading / error(+retry) / loaded states;
 * `children` renders the loaded value.
 */
function LazyDrill<T>({
  summary,
  hint,
  load,
  children,
}: {
  summary: string;
  hint?: string;
  load: (signal: AbortSignal) => Promise<T>;
  children: (data: T) => ReactNode;
}) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const [fetched, setFetched] = useState(false);
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const run = useCallback(async () => {
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setLoading(true);
    setError(null);
    try {
      const res = await load(ac.signal);
      if (ac.signal.aborted) return;
      setData(res);
    } catch (e) {
      if (ac.signal.aborted) return;
      setError(errMessage(e));
    } finally {
      if (!ac.signal.aborted) setLoading(false);
    }
  }, [load]);

  useEffect(() => () => abortRef.current?.abort(), []);

  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (next && !fetched) {
      setFetched(true);
      run();
    }
  };

  return (
    <div className="rounded-lg border border-line bg-panel px-3 py-2">
      <button
        type="button"
        onClick={toggle}
        aria-expanded={open}
        aria-controls={id}
        className={cn(
          "flex w-full items-center gap-1.5 text-left text-data text-teal",
          focusRing,
        )}
      >
        <span aria-hidden="true">{open ? "⌄" : "›"}</span>
        <span>{summary}</span>
        {hint && <span className="text-kbd text-dim2">{hint}</span>}
      </button>
      <div id={id} hidden={!open} className="mt-2">
        {!fetched ? null : loading ? (
          <StatusState variant="loading" title="Loading…" />
        ) : error ? (
          <StatusState
            variant="error"
            title="Couldn't load"
            description={error}
            action={<Chip onClick={run}>Retry</Chip>}
          />
        ) : data !== null ? (
          children(data)
        ) : null}
      </div>
    </div>
  );
}

/** One `label value` line in a record card (em-dash when absent). */
function RecordLine({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div>
      <span className="text-dim2">{label} </span>
      {value != null && value !== "" ? (
        <span className="text-ink">{value}</span>
      ) : (
        <span className="text-dim2">—</span>
      )}
    </div>
  );
}

function RecordEmpty({ what }: { what: string }) {
  return (
    <div className="text-kbd text-dim">
      No {what} record was stored with this decision (older decision, or the
      enrichment blob is missing/degraded).
    </div>
  );
}

/** The per-dimension record renderers. Pure display of the stored record. */
function AssetRecordBody({ ctx }: { ctx: CaseContext }) {
  const a = ctx.asset;
  if (!a) return <RecordEmpty what="asset" />;
  return (
    <div className="font-mono text-kbd leading-relaxed">
      <RecordLine label="hostname" value={a.hostname} />
      <RecordLine label="agent IP" value={a.agentIp} />
      <RecordLine label="criticality tier" value={a.tier} />
      <RecordLine label="owner / business tag" value={a.owner} />
      <RecordLine label="environment" value={a.environment} />
      {a.tags.length > 0 && (
        <RecordLine label="tags" value={a.tags.join(", ")} />
      )}
      {a.services.length > 0 && (
        <RecordLine label="services" value={a.services.join(", ")} />
      )}
    </div>
  );
}

function IdentityRecordBody({ ctx }: { ctx: CaseContext }) {
  const u = ctx.identity;
  if (!u) return <RecordEmpty what="identity" />;
  return (
    <div className="font-mono text-kbd leading-relaxed">
      <RecordLine
        label="privileged"
        value={u.hasAdmin ? "yes — admin roles" : "no"}
      />
      <RecordLine
        label="account type"
        value={u.isServiceAccount ? "service account" : "user account"}
      />
      <RecordLine label="risk level" value={u.riskLevel} />
      {u.roles.length > 0 && (
        <RecordLine label="roles" value={u.roles.join(", ")} />
      )}
      <RecordLine label="department" value={u.department} />
      <div className="mt-1 text-dim2">
        Principal context from the identity inventory at enrichment time. An
        &quot;elevated&quot; level with no roles means the account was unknown
        to the inventory.
      </div>
    </div>
  );
}

function TimeRecordBody({ ctx }: { ctx: CaseContext }) {
  const t = ctx.time;
  if (!t) return <RecordEmpty what="time-context" />;
  const yn = (v: boolean | null) => (v == null ? null : v ? "yes" : "no");
  return (
    <div className="font-mono text-kbd leading-relaxed">
      <RecordLine
        label="context"
        value={t.context ? t.context.replace(/_/g, " ") : null}
      />
      <RecordLine label="business hours" value={yn(t.isBusinessHours)} />
      <RecordLine label="weekend" value={yn(t.isWeekend)} />
      <RecordLine
        label="maintenance window"
        value={yn(t.isMaintenanceWindow)}
      />
    </div>
  );
}

function MitreRecordBody({ ctx }: { ctx: CaseContext }) {
  const m = ctx.mitre;
  if (!m) return <RecordEmpty what="MITRE" />;
  return (
    <div className="flex flex-col gap-1.5 text-kbd">
      {m.techniqueIds.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-dim2">techniques</span>
          {m.techniqueIds.map((t) => (
            <Chip key={t}>{t}</Chip>
          ))}
        </div>
      )}
      {m.tacticIds.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-dim2">tactics</span>
          {m.tacticIds.map((t) => (
            <Chip key={t}>{t}</Chip>
          ))}
        </div>
      )}
      <div className="text-dim2">
        The boost engages when a technique is on the guidance&apos;s
        critical-techniques list.
      </div>
    </div>
  );
}

function TiRecordBody({ ctx }: { ctx: CaseContext }) {
  const ti = ctx.ti;
  if (!ti) return <RecordEmpty what="threat-intel" />;
  return (
    <div className="flex flex-col gap-2">
      <div className="font-mono text-kbd leading-relaxed">
        <RecordLine
          label="feed hits"
          value={ti.hits != null ? String(ti.hits) : null}
        />
        {ti.sources.length > 0 && (
          <RecordLine label="sources" value={ti.sources.join(", ")} />
        )}
        <RecordLine label="highest severity" value={ti.highestSeverity} />
        <RecordLine
          label="known malicious"
          value={ti.isKnownMalicious ? "yes" : "no"}
        />
      </div>

      {/* WO-H23: the EXACT matched indicator(s) behind known-malicious — the
          trimmed match stored at triage time, so the analyst sees WHICH
          indicator and feed matched without pivoting to the ThreatIntel tab. */}
      {ti.matches.length > 0 && (
        <div className="rounded-md border border-line bg-field px-2.5 py-2">
          <div className="mb-1 text-micro uppercase tracking-wide text-dim2">
            Matched indicator{ti.matches.length > 1 ? "s" : ""} (as of triage)
          </div>
          <div className="flex flex-col gap-2">
            {ti.matches.map((m, i) => (
              <div key={i} className="font-mono text-kbd leading-relaxed">
                <RecordLine label="indicator" value={m.indicator} />
                <RecordLine label="type" value={m.type} />
                <RecordLine label="feed source" value={m.source} />
                <RecordLine label="severity" value={m.severity} />
                <RecordLine label="category" value={m.category} />
                <RecordLine label="last seen" value={m.lastSeen} />
                <RecordLine label="description" value={m.description} />
              </div>
            ))}
          </div>
        </div>
      )}

      {ti.srcIp ? (
        <LazyDrill<IocLookupResponse>
          summary={`IOC lookup — ${ti.srcIp}`}
          hint="local IOC store · lazy"
          load={(signal) => lookupIoc(ti.srcIp as string, signal)}
        >
          {(res) =>
            res.matches.length === 0 ? (
              <div className="text-kbd text-dim">
                No matches for {res.ioc_value} in the local IOC store (the
                feed hit above may have come from a live feed lookup at
                enrichment time).
              </div>
            ) : (
              <div className="flex flex-col gap-2">
                {res.matches.map((m, i) => (
                  <div key={i} className="font-mono text-kbd leading-relaxed">
                    <RecordLine label="source" value={m.source} />
                    <RecordLine label="type" value={m.ioc_type} />
                    <RecordLine label="severity" value={m.severity} />
                    <RecordLine
                      label="confidence"
                      value={m.confidence != null ? String(m.confidence) : null}
                    />
                    <RecordLine label="last seen" value={m.last_seen} />
                    <RecordLine label="description" value={m.description} />
                    {parseJsonArray(m.tags).length > 0 && (
                      <RecordLine
                        label="tags"
                        value={parseJsonArray(m.tags).join(", ")}
                      />
                    )}
                  </div>
                ))}
              </div>
            )
          }
        </LazyDrill>
      ) : (
        <div className="text-kbd text-dim2">
          No external indicator (source IP) was stored on this decision to
          look up.
        </div>
      )}
    </div>
  );
}

function HistoricalRecordBody({ ctx }: { ctx: CaseContext }) {
  const h = ctx.historical;
  if (!h) return <RecordEmpty what="historical" />;
  return (
    <div className="font-mono text-kbd leading-relaxed">
      <RecordLine
        label="FP rate (7d, this rule)"
        value={h.fpRate != null ? `${Math.round(h.fpRate * 100)}%` : null}
      />
      <RecordLine
        label="same rule (7d)"
        value={h.sameRule7d != null ? String(h.sameRule7d) : null}
      />
      <RecordLine
        label="same source (7d)"
        value={h.sameSource7d != null ? String(h.sameSource7d) : null}
      />
      <RecordLine
        label="same user (7d)"
        value={h.sameUser7d != null ? String(h.sameUser7d) : null}
      />
      <RecordLine
        label="pattern seen before"
        value={h.previouslySeenPattern ? "yes" : "no"}
      />
      <div className="mt-1 text-dim2">
        As-of-enrichment snapshot. The &quot;Rule stats (7d)&quot; drill below
        shows the live per-rule history.
      </div>
    </div>
  );
}

function AnomalyRecordBody({ ctx }: { ctx: CaseContext }) {
  const a = ctx.anomaly;
  if (!a) return <RecordEmpty what="baseline-anomaly" />;
  if (!a.isAnomaly && a.details.length === 0) {
    return (
      <div className="text-kbd text-dim">
        No baseline anomaly was flagged for this alert.
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-1.5 text-kbd">
      <div className="font-mono leading-relaxed">
        <RecordLine
          label="max deviation"
          value={a.deviation != null ? `${a.deviation}σ` : null}
        />
      </div>
      {a.details.map((d, i) => (
        <div key={i} className="font-mono leading-relaxed">
          <span className="text-dim2">{d.dimension} </span>
          <span className="text-ink">{d.value}</span>
          <span className="text-dim2">
            {" — "}
            {d.current24h != null ? `${d.current24h} in 24h` : "—"}
            {d.baselineMean != null ? ` vs baseline ${d.baselineMean}` : ""}
            {d.zScore != null ? ` (z ${d.zScore}` : ""}
            {d.zScore != null && d.sampleDays != null
              ? `, ${d.sampleDays} sample days)`
              : d.zScore != null
                ? ")"
                : ""}
          </span>
        </div>
      ))}
    </div>
  );
}

function VulnRecordBody({ ctx }: { ctx: CaseContext }) {
  const v = ctx.vuln;
  if (!v) return <RecordEmpty what="vulnerability" />;
  return (
    <div className="flex flex-col gap-2">
      <div className="font-mono text-kbd leading-relaxed">
        <RecordLine
          label="critical CVEs on host"
          value={v.critical != null ? String(v.critical) : null}
        />
        <RecordLine
          label="high CVEs on host"
          value={v.high != null ? String(v.high) : null}
        />
        {/* Fall back to bare CVE-id chips only when no per-CVE detail exists
            (older decision) — otherwise the detail table below supersedes it. */}
        {v.topCveDetails.length === 0 && v.topCves.length > 0 && (
          <div className="mt-0.5 flex flex-wrap items-center gap-1.5">
            <span className="text-dim2">top critical</span>
            {v.topCves.map((c) => (
              <Chip key={c}>{c}</Chip>
            ))}
          </div>
        )}
        <RecordLine
          label="failed SCA checks"
          value={v.scaFailed != null ? String(v.scaFailed) : null}
        />
        {v.reason && <RecordLine label="why it engaged" value={v.reason} />}
      </div>

      {/* WO-H23: per-CVE CVSS / EPSS / KEV so the analyst sees exploitability
          inline instead of pivoting to the Vuln tab. Missing scores show an
          honest em-dash — never a fabricated 0.0. */}
      {v.topCveDetails.length > 0 && (
        <div className="rounded-md border border-line bg-field px-2.5 py-2">
          <div className="mb-1 text-micro uppercase tracking-wide text-dim2">
            Top critical CVEs — CVSS / EPSS / KEV
          </div>
          <div className="flex flex-col gap-1.5">
            {v.topCveDetails.map((d) => (
              <div
                key={d.cve}
                className="flex flex-wrap items-center gap-x-3 gap-y-0.5 font-mono text-kbd"
              >
                <Chip>{d.cve}</Chip>
                <span>
                  <span className="text-dim2">CVSS </span>
                  {d.cvss != null ? (
                    <b className="tabular text-ink">
                      {d.cvss}
                      {d.cvssVersion ? ` (v${d.cvssVersion})` : ""}
                    </b>
                  ) : (
                    <span className="text-dim2">—</span>
                  )}
                </span>
                <span>
                  <span className="text-dim2">EPSS </span>
                  {d.epss != null ? (
                    <b className="tabular text-ink">
                      {(d.epss * 100).toFixed(1)}%
                    </b>
                  ) : (
                    <span className="text-dim2">—</span>
                  )}
                </span>
                {d.kev === true ? (
                  <span className="rounded border border-sev-crit px-1 text-micro font-semibold text-sev-crit">
                    CISA KEV
                  </span>
                ) : d.kev === false ? (
                  <span className="text-dim2">not in KEV</span>
                ) : (
                  <span className="text-dim2">KEV data unavailable</span>
                )}
              </div>
            ))}
          </div>
          <div className="mt-1.5 text-micro text-dim2">
            CVSS from the host vuln record; EPSS/KEV from the CVE intel feed. A
            dash means that score was not available (not zero).
          </div>
        </div>
      )}
    </div>
  );
}

function HostIntegrityRecordBody({ ctx }: { ctx: CaseContext }) {
  const hi = ctx.hostIntegrity;
  if (!hi) return <RecordEmpty what="host-integrity" />;
  return (
    <div className="flex flex-col gap-2">
      <div className="font-mono text-kbd leading-relaxed">
        <RecordLine
          label="open rootcheck findings"
          value={
            hi.rootcheckFindings != null ? String(hi.rootcheckFindings) : null
          }
        />
        <RecordLine
          label="recent FIM changes"
          value={
            hi.fimRecentChanges != null ? String(hi.fimRecentChanges) : null
          }
        />
        {hi.reason && <RecordLine label="why it engaged" value={hi.reason} />}
      </div>

      {/* WO-H23: the specific rootcheck signature(s) behind the count. */}
      {hi.rootcheckSignatures.length > 0 && (
        <div>
          <div className="mb-1 text-micro uppercase tracking-wide text-dim2">
            Rootcheck finding{hi.rootcheckSignatures.length > 1 ? "s" : ""}
          </div>
          <ul className="flex flex-col gap-1">
            {hi.rootcheckSignatures.map((s, i) => (
              <li
                key={i}
                className="flex gap-2 font-mono text-kbd leading-relaxed text-ink"
              >
                <span aria-hidden="true" className="text-teal">
                  •
                </span>
                <span className="break-all">{s}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* WO-H23: the specific recently-changed FIM file path(s). */}
      {hi.fimChangedPaths.length > 0 && (
        <div>
          <div className="mb-1 text-micro uppercase tracking-wide text-dim2">
            Recently changed files (FIM)
          </div>
          <ul className="flex flex-col gap-0.5">
            {hi.fimChangedPaths.map((p, i) => (
              <li
                key={i}
                className="break-all font-mono text-kbd leading-relaxed text-ink"
              >
                {p}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="text-dim2">
        FIM/rootcheck posture of the host at enrichment time (rootcheck is the
        primary driver; FIM engages only above the recent-change threshold).
      </div>
    </div>
  );
}

// ---- WO-H86: the one-line preview on each context row -----------------------
/**
 * Every context row used to carry the SAME constant hint, `"underlying record"`
 * — nine identical strings carrying zero information, so nine rows could only be
 * opened, never scanned. Each dimension now computes a one-line preview from its
 * OWN stored record.
 *
 * The preview must keep two facts APART, because analysts reason from the
 * difference and an absent section cannot express it:
 *
 *   "no record stored"                  → we have nothing; we cannot say we
 *                                         looked (older decision / degraded or
 *                                         missing enrichment blob).
 *   "0 feed hits — checked, nothing known" → we DID look and found nothing.
 *
 * Rows are therefore never filtered out on emptiness; an empty row states its
 * emptiness. Nothing here recomputes or invents data — every preview is a
 * restatement of values already in the stored record.
 */
const NO_RECORD_PREVIEW = "no record stored";

/**
 * The wording for a record that exists but holds nothing.
 *
 * It is deliberately NOT "checked, nothing found". Almost every enricher
 * pre-seeds its keys to 0 / false / "" and then swallows its own failures, so a
 * stored zero is genuinely ambiguous. `HostIntegrityEnricher._empty()` is
 * returned on FIVE separate paths — feature disabled, missing or `"000"`
 * agent_id, `TenantConfigUnavailable` (M2 fail-closed), a null client, and any
 * exception out of `_compute` — and `_compute` on a genuinely CLEAN host
 * produces byte-identical output to it (counts 0, `reason` ""). The same holds
 * for the vuln enricher. So `reason` cannot separate them either, and there is
 * no field anywhere in those records that can.
 *
 * "We checked and found nothing" is therefore a claim the stored data does not
 * support, and it is the more dangerous of the two errors: it tells an analyst
 * a control was exercised when it may never have run. This phrase asserts
 * nothing in either direction.
 */
const NO_SIGNAL_PREVIEW = "no signal recorded";

/**
 * The third state, and the only one we can prove: the enricher RAISED.
 * `degraded_enrichers` is recorded for `asset`, `threat_intel` and `time` only.
 */
const DEGRADED_PREVIEW = "check failed — enrichment degraded";

/**
 * `degraded_enrichers` name → the context dimension it belongs to.
 *
 * The service records only `asset`, `threat_intel` and `time` today, but the
 * marker is a plain string list and the contract will grow (WO-H89). Anything
 * mapped here is surfaced on its own row automatically; anything NOT mapped is
 * surfaced separately by `unmappedDegraded` rather than silently vanishing —
 * the failure mode being that a row over a record which PROVES its check
 * errored would otherwise read "no signal recorded".
 */
const DEGRADED_TO_FACTOR: Readonly<Record<string, string>> = {
  asset: "asset_multiplier",
  identity: "user_multiplier",
  time: "time_multiplier",
  mitre: "mitre_boost",
  threat_intel: "ti_boost",
  historical: "fp_discount",
  baseline: "anomaly_boost",
  anomaly: "anomaly_boost",
  vuln_context: "vuln_context_multiplier",
  vulnerability: "vuln_context_multiplier",
  host_integrity: "host_integrity_multiplier",
};

/** The factor keys whose enricher was recorded as having RAISED. */
function degradedFactors(ctx: CaseContext): Set<string> {
  const out = new Set<string>();
  for (const name of ctx.degraded) {
    const factor = DEGRADED_TO_FACTOR[name];
    if (factor) out.add(factor);
  }
  return out;
}

/**
 * Degraded markers we could not attribute to a row. They must still reach the
 * analyst: the record says a check errored, and "no signal recorded" would be
 * a strictly worse statement than the truth.
 */
function unmappedDegraded(ctx: CaseContext): string[] {
  return ctx.degraded.filter((n) => !DEGRADED_TO_FACTOR[n]);
}

/**
 * Presentation-only emphasis thresholds. These decide which rows get severity
 * WEIGHT so an alarming row cannot look identical to an empty one; they do not
 * feed, alter or second-guess the backend's risk score. The exact underlying
 * numbers are always printed in the preview text itself.
 */
const LOUD_ROOTCHECK = 25;
const LOUD_FIM_CHANGES = 25;
const LOUD_DEVIATION = 3;

/**
 * How worth-surfacing a dimension is when the closed box has to choose which
 * previews to lift onto its header. Ordering by array position let routine
 * context ("this is a tier-1 box") take the slots and push a real finding back
 * into the box. Only genuine FINDINGS score here; asset and identity are
 * context and never compete for a slot.
 */
/** How many previews the closed box's strip shows before it summarises. */
const STRIP_MAX = 3;

const FINDING_WEIGHT: Readonly<Record<string, number>> = {
  host_integrity_multiplier: 4,
  ti_boost: 3,
  vuln_context_multiplier: 3,
  anomaly_boost: 2,
};

/** Risk-factor key → its record's title, one-line preview, weight and body. */
const CONTEXT_DIMENSIONS: ReadonlyArray<{
  factorKey: string;
  title: string;
  body: (ctx: CaseContext) => ReactNode;
  present: (ctx: CaseContext) => boolean;
  /** the scannable one-liner; distinguishes "checked, nothing" from "no record" */
  preview: (ctx: CaseContext) => string;
  /** weight for that preview — severity, "degraded", or null */
  tone: (ctx: CaseContext) => PreviewTone;
}> = [
  {
    factorKey: "asset_multiplier",
    title: "Asset",
    body: (ctx) => <AssetRecordBody ctx={ctx} />,
    present: (ctx) => ctx.asset != null,
    preview: (ctx) => {
      const a = ctx.asset;
      if (!a) return NO_RECORD_PREVIEW;
      const parts = [a.tier, a.environment, a.owner].filter(
        (v): v is string => !!v && v.toLowerCase() !== "unknown",
      );
      // A pure restatement of the stored fields. NOT "unregistered", which
      // would claim the inventory was consulted and came back empty.
      return parts.length > 0
        ? parts.join(" · ")
        : "no tier, owner or environment on file";
    },
    // Asset criticality is CONTEXT, not a finding. Spending crit weight on
    // "this is a tier-1 box" made routine facts outrank 500 rootcheck
    // findings in the closed box's summary strip.
    tone: () => null,
  },
  {
    factorKey: "user_multiplier",
    title: "Identity",
    body: (ctx) => <IdentityRecordBody ctx={ctx} />,
    present: (ctx) => ctx.identity != null,
    preview: (ctx) => {
      const u = ctx.identity;
      if (!u) return NO_RECORD_PREVIEW;

      // Only a MATCHED record may be described. `user_roles` is pre-seeded to
      // [], so "no roles" over an unmatched principal claims the account has
      // none when in truth the store held nothing about it — the same mistake
      // "asset unregistered" was making, in the one dimension the first pass
      // never visited.
      if (u.storeMatched) {
        const parts = [
          u.riskLevel ? `identity: ${u.riskLevel}` : "identity: level unknown",
        ];
        if (u.hasAdmin) parts.push("admin roles");
        parts.push(u.roles.length > 0 ? u.roles.join(", ") : "no roles on file");
        if (u.isServiceAccount) parts.push("service account");
        return parts.join(", ");
      }

      // "elevated" is written ONLY in the enricher's `else` branch — the
      // identity lookup ran and returned nothing for a non-system username.
      // That IS provable, so it is the one thing we may state here.
      if ((u.riskLevel ?? "").toLowerCase() === "elevated") {
        return "account not found in the identity store";
      }

      // Everything else is the untouched pre-seed: no user on the alert, a
      // system account, or an enricher that never ran. Claim nothing.
      return NO_SIGNAL_PREVIEW;
    },
    // Like asset: whose account it is, is context. It does not compete with a
    // finding for a slot on the closed box's summary strip.
    tone: () => null,
  },
  {
    factorKey: "time_multiplier",
    title: "Time context",
    body: (ctx) => <TimeRecordBody ctx={ctx} />,
    present: (ctx) => ctx.time != null,
    preview: (ctx) => {
      const t = ctx.time;
      if (!t) return NO_RECORD_PREVIEW;
      const parts: string[] = [];
      if (t.context) parts.push(t.context.replace(/_/g, " "));
      else if (t.isBusinessHours != null)
        parts.push(
          t.isBusinessHours ? "business hours" : "outside business hours",
        );
      if (t.isWeekend === true) parts.push("weekend");
      if (t.isMaintenanceWindow === true) parts.push("maintenance window");
      return parts.length > 0 ? parts.join(" · ") : NO_SIGNAL_PREVIEW;
    },
    // When the alert fired is context, not an alarm — it never shouts.
    tone: () => null,
  },
  {
    factorKey: "mitre_boost",
    title: "MITRE",
    body: (ctx) => <MitreRecordBody ctx={ctx} />,
    present: (ctx) => ctx.mitre != null,
    preview: (ctx) => {
      const m = ctx.mitre;
      if (!m) return NO_RECORD_PREVIEW;
      const parts: string[] = [];
      if (m.techniqueIds.length === 1) parts.push(m.techniqueIds[0]);
      else if (m.techniqueIds.length > 1)
        parts.push(`${m.techniqueIds.length} techniques`);
      if (m.tacticIds.length === 1) parts.push(m.tacticIds[0]);
      else if (m.tacticIds.length > 1)
        parts.push(`${m.tacticIds.length} tactics`);
      return parts.length > 0 ? parts.join(" · ") : NO_SIGNAL_PREVIEW;
    },
    tone: () => null,
  },
  {
    factorKey: "ti_boost",
    title: "Threat intel",
    body: (ctx) => <TiRecordBody ctx={ctx} />,
    present: (ctx) => ctx.ti != null,
    preview: (ctx) => {
      const ti = ctx.ti;
      if (!ti) return NO_RECORD_PREVIEW;
      const hits = ti.hits ?? 0;
      if (ti.isKnownMalicious) {
        const sev = ti.highestSeverity ? ` · ${ti.highestSeverity} severity` : "";
        const n =
          ti.hits != null ? `${hits} feed hit${hits === 1 ? "" : "s"}` : "feed hit recorded";
        return `known malicious — ${n}${sev}`;
      }
      if (hits > 0) {
        return `${hits} feed hit${hits === 1 ? "" : "s"}, none rated malicious`;
      }
      if (ti.matches.length > 0) {
        return `${ti.matches.length} matched indicator${ti.matches.length === 1 ? "" : "s"} stored`;
      }
      // Zero hits proves nothing: the enricher only builds an indicator set
      // from PUBLIC src/dst IPs and hashes, so an internal-only alert (sudo,
      // PAM, 5501/5402 — a large share of real traffic) is never looked up at
      // all, and per-feed HTTP errors are swallowed. Say what the record
      // actually holds, and agree with the row body one click below, which
      // reads "No external indicator (source IP) was stored ... to look up."
      return ti.srcIp
        ? `no feed hit recorded for ${ti.srcIp}`
        : "no external indicator stored to look up";
    },
    tone: (ctx) => {
      const ti = ctx.ti;
      if (!ti) return null;
      if (ti.isKnownMalicious) return "crit";
      return (ti.hits ?? 0) > 0 ? "high" : null;
    },
  },
  {
    factorKey: "fp_discount",
    title: "FP history",
    body: (ctx) => <HistoricalRecordBody ctx={ctx} />,
    present: (ctx) => ctx.historical != null,
    preview: (ctx) => {
      const h = ctx.historical;
      if (!h) return NO_RECORD_PREVIEW;

      // `windowDays` is written ONLY inside the enricher's
      // `if self.db and rule_id:` branch, so its presence is positive proof
      // that the FP-rate query actually ran. `historical_fp_rate` is NOT —
      // it is pre-seeded to 0.0 and survives a missing db handle untouched.
      const proven = h.windowDays != null;
      const n = h.occurrenceCount;
      if (proven && n != null && n > 0) {
        const window = `${h.windowDays}d`;
        const rate =
          h.fpRate != null ? `${Math.round(h.fpRate * 100)}% false-positive` : null;
        const seen = `${n} prior decision${n === 1 ? "" : "s"} (${window})`;
        return rate ? `${rate} over ${seen}` : seen;
      }
      if (proven && n === 0) {
        // Proven query, genuinely zero rows — the one case where we may say so.
        return `no prior decisions for this rule in ${h.windowDays}d`;
      }
      // Unproven. Never render a "0%" rate: a rate over zero samples is not a
      // measurement, and here we cannot even show the query happened.
      const counts: string[] = [];
      if (h.sameRule7d) counts.push(`${h.sameRule7d} same rule in 7d`);
      if (h.sameSource7d) counts.push(`${h.sameSource7d} same source in 7d`);
      if (h.sameUser7d) counts.push(`${h.sameUser7d} same user in 7d`);
      if (counts.length > 0) return counts.join(" · ");
      if (h.previouslySeenPattern) return "pattern seen before";
      return NO_SIGNAL_PREVIEW;
    },
    // A high FP rate DISCOUNTS the score — it is not an alarm.
    tone: () => null,
  },
  {
    factorKey: "anomaly_boost",
    title: "Baseline anomaly",
    body: (ctx) => <AnomalyRecordBody ctx={ctx} />,
    present: (ctx) => ctx.anomaly != null,
    preview: (ctx) => {
      const a = ctx.anomaly;
      if (!a) return NO_RECORD_PREVIEW;
      // `baseline_anomaly` is pre-seeded False and stays False when the
      // enricher has no OpenSearch handle or its query throws — so "false"
      // cannot be reported as "checked, nothing unusual".
      if (!a.isAnomaly && a.details.length === 0) return NO_SIGNAL_PREVIEW;
      const dev =
        a.deviation != null ? `${a.deviation}σ deviation` : "deviation flagged";
      const top = a.details[0];
      return top ? `${dev} on ${top.dimension}` : dev;
    },
    tone: (ctx) => {
      const a = ctx.anomaly;
      if (!a || (!a.isAnomaly && a.details.length === 0)) return null;
      return (a.deviation ?? 0) >= LOUD_DEVIATION ? "high" : "med";
    },
  },
  {
    factorKey: "vuln_context_multiplier",
    title: "Vulnerabilities",
    body: (ctx) => <VulnRecordBody ctx={ctx} />,
    present: (ctx) => ctx.vuln != null,
    preview: (ctx) => {
      const v = ctx.vuln;
      if (!v) return NO_RECORD_PREVIEW;
      // Judge on ANY positive content, not on the counts alone: a record can
      // carry `host_top_critical_cves` while the count keys are absent, and
      // the old text then claimed "host clean" directly above a listed CVE.
      const hasContent =
        (v.critical ?? 0) > 0 ||
        (v.high ?? 0) > 0 ||
        (v.scaFailed ?? 0) > 0 ||
        v.topCves.length > 0 ||
        v.topCveDetails.length > 0;
      // All-zero is `_empty()`'s exact output, returned on five non-finding
      // paths as well as on a genuinely clean host. Claim nothing.
      if (!hasContent) return NO_SIGNAL_PREVIEW;
      const parts: string[] = [];
      // Print a count ONLY for a key that is actually present — an absent key
      // is not a measured zero.
      if (v.critical != null && v.critical > 0) {
        parts.push(`${v.critical} critical`);
      }
      if (v.high != null && v.high > 0) parts.push(`${v.high} high CVEs`);
      if (parts.length === 0 && (v.topCves.length > 0 || v.topCveDetails.length > 0)) {
        const n = Math.max(v.topCves.length, v.topCveDetails.length);
        parts.push(`${n} critical CVE${n === 1 ? "" : "s"} listed`);
      }
      if (v.scaFailed != null && v.scaFailed > 0) {
        parts.push(`${v.scaFailed} failed SCA checks`);
      }
      if (v.topCveDetails.some((d) => d.kev === true)) parts.push("in CISA KEV");
      return parts.join(" · ");
    },
    tone: (ctx) => {
      const v = ctx.vuln;
      if (!v) return null;
      if (
        (v.critical ?? 0) > 0 ||
        v.topCves.length > 0 ||
        v.topCveDetails.some((d) => d.kev === true)
      )
        return "crit";
      if ((v.high ?? 0) > 0) return "high";
      return (v.scaFailed ?? 0) > 0 ? "med" : null;
    },
  },
  {
    factorKey: "host_integrity_multiplier",
    title: "Host integrity",
    body: (ctx) => <HostIntegrityRecordBody ctx={ctx} />,
    present: (ctx) => ctx.hostIntegrity != null,
    preview: (ctx) => {
      const hi = ctx.hostIntegrity;
      if (!hi) return NO_RECORD_PREVIEW;
      // VERIFIED against the enricher: `_compute` on a genuinely clean host
      // returns counts 0 AND an empty `reason` — byte-identical to `_empty()`,
      // which is also what a disabled feature, a missing/`"000"` agent_id, an
      // M2 fail-closed tenant, a null client and any `_compute` exception all
      // return. `reason` therefore cannot distinguish them, and no other field
      // can either. Stay neutral.
      const r = hi.rootcheckFindings ?? 0;
      const f = hi.fimRecentChanges ?? 0;
      const quiet =
        r === 0 &&
        f === 0 &&
        hi.rootcheckSignatures.length === 0 &&
        hi.fimChangedPaths.length === 0;
      if (quiet) return NO_SIGNAL_PREVIEW;

      // Only the non-zero halves, and only for keys that are actually present:
      // a red "0 recent FIM changes" reads as an alarm about a number that is
      // fine, and an absent key is not a measured zero.
      const parts: string[] = [];
      if (hi.rootcheckFindings != null && hi.rootcheckFindings > 0) {
        parts.push(
          `${r} open rootcheck finding${r === 1 ? "" : "s"}`,
        );
      }
      if (hi.fimRecentChanges != null && hi.fimRecentChanges > 0) {
        parts.push(`${f} recent FIM change${f === 1 ? "" : "s"}`);
      }
      // A record can carry the finding DETAIL while the count keys are absent
      // or zero (the mirror of the vuln `host_top_critical_cves` case). Without
      // this the row rendered an EMPTY hint and showed nothing at all.
      if (parts.length === 0) {
        const sig = hi.rootcheckSignatures.length;
        const fim = hi.fimChangedPaths.length;
        if (sig > 0) parts.push(`${sig} rootcheck finding${sig === 1 ? "" : "s"} listed`);
        if (fim > 0) parts.push(`${fim} changed file${fim === 1 ? "" : "s"} listed`);
      }
      return parts.join(" · ");
    },
    tone: (ctx) => {
      const hi = ctx.hostIntegrity;
      if (!hi) return null;
      const r = hi.rootcheckFindings ?? 0;
      if (r >= LOUD_ROOTCHECK) return "crit";
      if (r > 0 || hi.rootcheckSignatures.length > 0) return "high";
      if ((hi.fimRecentChanges ?? 0) >= LOUD_FIM_CHANGES) return "med";
      return hi.fimChangedPaths.length > 0 ? "med" : null;
    },
  },
];

/**
 * A preview's weight. `Severity` = a real finding on the shared severity scale;
 * `"degraded"` = the check ERRORED and we know nothing (amber, not severity);
 * `null` = nothing to shout about.
 */
type PreviewTone = Severity | "degraded" | null;

/** One scannable context row, resolved from a dimension + the case context. */
interface ContextRow {
  factorKey: string;
  title: string;
  preview: string;
  tone: PreviewTone;
  /** the multiplier this dimension contributed, when a breakdown was recorded */
  multiplier: number | null;
  body: ReactNode;
}

/**
 * Resolve every context dimension against the stored records.
 *
 * ALL NINE dimensions are returned whenever the decision carries either a risk
 * breakdown or any record at all — including the ones with nothing in them. A
 * missing row is unreadable; a row that is present can say which of the three
 * states it is in ("no record stored" / "no signal recorded" / "check failed —
 * enrichment degraded"), and analysts act on that difference. Returns `[]` only
 * when there is neither a breakdown nor a single record, in which case the
 * risk-math section already carries the honest "not recorded" line.
 */
function contextRows(alert: IncidentAlert): ContextRow[] {
  const math = riskMath(alert.glass_box?.risk_breakdown);
  const ctx = caseContext(alert);
  const anyRecord = CONTEXT_DIMENSIONS.some((d) => d.present(ctx));
  if (!math && !anyRecord) return [];

  const moved = math ? new Map(math.factors.map((f) => [f.key, f.value])) : null;
  // A recorded failure OVERRIDES whatever the record's contents would suggest,
  // for every dimension uniformly — so a newly-added `degraded_enrichers` name
  // surfaces on its row the day it ships, with no per-dimension edit.
  const failed = degradedFactors(ctx);
  return CONTEXT_DIMENSIONS.map((d) => {
    const isDegraded = failed.has(d.factorKey);
    return {
      factorKey: d.factorKey,
      title: d.title,
      preview: isDegraded ? DEGRADED_PREVIEW : d.preview(ctx),
      tone: isDegraded ? ("degraded" as const) : d.tone(ctx),
      multiplier: moved?.get(d.factorKey) ?? null,
      body: d.body(ctx),
    };
  });
}

/**
 * The rows worth pulling onto the collapsed box's header, worst first.
 *
 * Ordering is by SEVERITY, then by how much the dimension is a finding rather
 * than context — never by position in `CONTEXT_DIMENSIONS`. Sorting by array
 * order meant that on a tier-1 host with a TI hit and a critical CVE the three
 * slots went to Asset, Threat intel and Vulnerabilities, and "500 open
 * rootcheck findings" was pushed off the strip and back into the closed box —
 * the operator's own case on a slightly richer alert.
 *
 * A degraded (errored) check is also surfaced: "we do not know" is exactly the
 * kind of thing that must not be swallowed by collapsing the box.
 */
function loudRows(rows: readonly ContextRow[]): ContextRow[] {
  // A FAILED check outranks every finding. "We do not know" cannot be traded
  // off against "we know something bad": the service's own comment calls a TI
  // outage reading as clean "the most dangerous possible default"
  // (service.py:580-584), and a degraded row previously sorted LAST inside its
  // rank (no FINDING_WEIGHT entry → 0) and was the first thing the cap dropped.
  const rank = (r: ContextRow) =>
    r.tone === "degraded" ? -1 : SEVERITY_ORDER.indexOf(r.tone as Severity);
  return rows
    .filter(
      (r) => r.tone === "crit" || r.tone === "high" || r.tone === "degraded",
    )
    .sort(
      (a, b) =>
        rank(a) - rank(b) ||
        (FINDING_WEIGHT[b.factorKey] ?? 0) - (FINDING_WEIGHT[a.factorKey] ?? 0),
    );
}

/**
 * WO-H21 core: each risk factor expands inline into the underlying record it
 * was computed from (asset card, principal, TI verdict, CVEs, FIM/rootcheck
 * finding, …), with the multiplier it contributed when a breakdown was
 * recorded. WO-H86 adds the scannable preview + severity weight per row.
 */
function ContextRecordsSection({ rows }: { rows: readonly ContextRow[] }) {
  if (rows.length === 0) return null;
  return (
    <div className="flex flex-col gap-1.5">
      <div className="text-micro uppercase tracking-wide text-dim2">
        Context behind the score — every dimension we check, and what each one
        found
      </div>
      {rows.map((r) => (
        <Expander
          key={r.factorKey}
          summary={
            r.multiplier != null
              ? `${r.title} — ×${fmtNum(r.multiplier)}`
              : r.title
          }
          hint={r.preview}
          tone={r.tone}
        >
          {r.body}
        </Expander>
      ))}
    </div>
  );
}

// ---- WO-H86: ONE collapsed box for all scoring / enrichment detail ----------
/**
 * Everything that explains HOW the verdict was scored, behind a single
 * disclosure: the risk maths, all nine context records, the matched playbook,
 * the rule's 7-day stats, the raw Wazuh event, provenance and the
 * anonymization boundary. Collapsed by default so the reasoning and the
 * recommended action own the top of the case.
 *
 * Two things this box must NOT do:
 *  - hide something alarming. The loudest context previews (a KEV'd critical
 *    CVE, 500 open rootcheck findings) are lifted onto the closed header, so
 *    burying the detail never buries the finding.
 *  - fetch anything. Its children are mounted only on FIRST open and then kept
 *    mounted, so the lazy drills inside (`RuleStatsExpander`, `PlaybookExpander`,
 *    `RawEventExpander`, the IOC lookup) still fetch on their own first expand
 *    and NEVER on card mount — see the WO-H86 test that asserts this.
 */
function CaseDetailBox({ alert }: { alert: IncidentAlert }) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const [everOpened, setEverOpened] = useState(false);
  const rows = contextRows(alert);
  const loud = loudRows(rows);

  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (next) setEverOpened(true);
  };

  return (
    <Panel inset className="px-3 py-2">
      <button
        type="button"
        onClick={toggle}
        aria-expanded={open}
        aria-controls={id}
        className={cn(
          "flex w-full flex-wrap items-center gap-x-2 gap-y-0.5 text-left text-data text-teal",
          focusRing,
        )}
      >
        <span aria-hidden="true">{open ? "⌄" : "›"}</span>
        <span>Scoring &amp; enrichment detail</span>
        <span className="text-kbd text-dim2">
          {rows.length > 0
            ? `risk maths · ${rows.length} context records · playbook · rule stats · raw event`
            : "risk maths · playbook · rule stats · raw event"}
        </span>
      </button>

      {/* What the box is hiding that you would not want hidden. Only while
          closed — once open the rows themselves carry it. The strip is capped
          for legibility, so anything over the cap MUST leave a trace: a bare
          `slice(0, 3)` silently dropped a 5-sigma anomaly and both degraded
          markers on a busy alert. */}
      {!open && loud.length > 0 && (
        <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className="text-micro uppercase tracking-wide text-dim2">
            inside, worth your eyes
          </span>
          {loud.slice(0, STRIP_MAX).map((r) => (
            <span key={r.factorKey} className="inline-flex items-center gap-1">
              <span className="text-kbd text-dim2">{r.title}:</span>
              <PreviewLine text={r.preview} tone={r.tone} />
            </span>
          ))}
          {loud.length > STRIP_MAX && (
            <button
              type="button"
              onClick={toggle}
              className={cn(
                "rounded-md border border-line bg-field px-1.5 text-kbd text-ink hover:bg-hover",
                focusRing,
              )}
            >
              +{loud.length - STRIP_MAX} more —{" "}
              {loud
                .slice(STRIP_MAX)
                .map((r) => r.title)
                .join(", ")}
            </button>
          )}
        </div>
      )}

      {/* Same rule as the card body: no display utility on the `hidden`
          element, or collapsing the box after opening it once would leave the
          whole detail on screen. */}
      <div id={id} hidden={!open}>
        {everOpened && (
          <div className="mt-2 flex flex-col gap-2.5">
            <RiskMathExpander alert={alert} />
            <ContextRecordsSection rows={rows} />
            <PlaybookExpander alert={alert} />
            <RuleStatsExpander alert={alert} />
            <RawEventExpander alert={alert} />
            <div className="flex flex-col gap-2.5 sm:flex-row">
              <ProvenancePanel alert={alert} />
              <AnonymizationPanel alert={alert} />
            </div>
          </div>
        )}
      </div>
    </Panel>
  );
}

// ---- WO-H21: matched playbook content (LAZY, READ-ONLY) ----------------------
/**
 * The matched playbook's steps + escalation criteria — the content, not just
 * the `playbook_version` string in provenance. Lazy on first expand; a
 * no-match / degraded deployment renders the server's honest `reason`.
 */
function PlaybookExpander({ alert }: { alert: IncidentAlert }) {
  return (
    <LazyDrill<DecisionPlaybookResponse>
      summary="Matched playbook"
      hint="steps + escalation criteria · read-only"
      load={(signal) => getDecisionPlaybook(String(alert.id), signal)}
    >
      {(res) =>
        !res.matched || !res.playbook ? (
          <div className="text-kbd text-dim">
            {res.reason ?? "No playbook was recorded for this decision."}
          </div>
        ) : (
          <PlaybookBody pb={res.playbook} />
        )
      }
    </LazyDrill>
  );
}

function PlaybookBody({
  pb,
}: {
  pb: NonNullable<DecisionPlaybookResponse["playbook"]>;
}) {
  return (
    <div className="flex flex-col gap-2.5">
      <div className="text-data font-semibold text-ink">{pb.name}</div>

      {pb.investigation_steps.length > 0 && (
        <div>
          <div className="mb-1 text-micro uppercase tracking-wide text-dim2">
            Investigation steps
          </div>
          <ol className="flex flex-col gap-1.5">
            {pb.investigation_steps.map((s, i) => (
              <li key={i} className="text-data leading-relaxed">
                <span className="font-semibold text-ink">
                  {s.step != null ? `${s.step}. ` : ""}
                  {s.name}
                </span>
                {s.assess && (
                  <div className="whitespace-pre-line pl-4 text-kbd text-dim">
                    {s.assess.trim()}
                  </div>
                )}
              </li>
            ))}
          </ol>
        </div>
      )}

      {pb.escalation_criteria.length > 0 && (
        <div>
          <div className="mb-1 text-micro uppercase tracking-wide text-dim2">
            Escalate / needs investigation when
          </div>
          <ul className="flex flex-col gap-1">
            {pb.escalation_criteria.map((c, i) => (
              <li key={i} className="flex gap-2 text-data text-dim">
                <span aria-hidden="true" className="text-teal">
                  •
                </span>
                <span>{c}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {(pb.verdict_criteria.true_positive?.length ?? 0) +
        (pb.verdict_criteria.false_positive?.length ?? 0) >
        0 && (
        <div className="flex flex-col gap-2 sm:flex-row">
          {pb.verdict_criteria.true_positive?.length ? (
            <div className="flex-1">
              <div className="mb-1 text-micro uppercase tracking-wide text-dim2">
                True positive when
              </div>
              <ul className="flex flex-col gap-1">
                {pb.verdict_criteria.true_positive.map((c, i) => (
                  <li key={i} className="text-kbd text-dim">
                    {c}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          {pb.verdict_criteria.false_positive?.length ? (
            <div className="flex-1">
              <div className="mb-1 text-micro uppercase tracking-wide text-dim2">
                False positive when
              </div>
              <ul className="flex flex-col gap-1">
                {pb.verdict_criteria.false_positive.map((c, i) => (
                  <li key={i} className="text-kbd text-dim">
                    {c}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      )}

      <div className="text-micro text-dim2">
        Read-only institutional guidance ({pb.key}) — the playbook the AI was
        given for this alert class. Editing lives in config/guidance.
      </div>
    </div>
  );
}

// ---- WO-H21: raw underlying Wazuh event (LAZY, READ-ONLY) ---------------------
/**
 * The raw event behind the decision — `full_log` up front, the full document
 * as collapsible JSON below. Lazy on first expand; a degraded deployment or a
 * rotated-out event renders the server's honest `reason` as an empty state.
 */
function RawEventExpander({ alert }: { alert: IncidentAlert }) {
  return (
    <LazyDrill<RawAlertResponse>
      summary="Raw Wazuh event"
      hint="as ingested · lazy"
      load={(signal) => getDecisionRawAlert(String(alert.id), signal)}
    >
      {(res) =>
        !res.found || !res.alert ? (
          <div className="text-kbd text-dim">
            {res.reason ?? "The underlying event could not be loaded."}
          </div>
        ) : (
          <RawEventBody doc={res.alert} />
        )
      }
    </LazyDrill>
  );
}

function RawEventBody({ doc }: { doc: Record<string, unknown> }) {
  const fullLog = typeof doc.full_log === "string" ? doc.full_log : "";
  let json = "";
  try {
    json = JSON.stringify(doc, null, 2);
  } catch {
    json = String(doc);
  }
  return (
    <div className="flex flex-col gap-2">
      {fullLog && (
        <div>
          <div className="mb-1 text-micro uppercase tracking-wide text-dim2">
            full_log
          </div>
          <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-md border border-line bg-field px-2.5 py-2 font-mono text-kbd text-ink">
            {fullLog}
          </pre>
        </div>
      )}
      <div>
        <div className="mb-1 text-micro uppercase tracking-wide text-dim2">
          full event document
        </div>
        <pre className="max-h-80 overflow-auto rounded-md border border-line bg-field px-2.5 py-2 font-mono text-kbd leading-relaxed text-dim">
          {json}
        </pre>
      </div>
      <div className="text-micro text-dim2">
        The event as ingested from Wazuh (host, user and IP fields shown are
        the real values — anonymization applies only on the path to the AI).
      </div>
    </div>
  );
}

// ---- provenance panel -------------------------------------------------------

function ProvenancePanel({ alert }: { alert: IncidentAlert }) {
  const p = alert.glass_box?.provenance;
  return (
    <Panel className="flex-1 p-3">
      <div className="mb-1.5 text-micro uppercase tracking-wide text-dim2">
        Provenance — this exact verdict
      </div>
      {p ? (
        <div className="font-mono text-kbd leading-relaxed">
          <ProvLine label="playbook" value={p.playbook_version} bold />
          <ProvLine label="guidance hash" value={fmtGuidance(p.guidance_hash)} />
          <ProvLine label="model" value={p.model} />
          <ProvLine
            label="latency"
            value={p.latency_ms != null ? `${p.latency_ms} ms` : null}
          />
          <div className="mt-1 text-dim2">reasoning store: anonymized ✓</div>
        </div>
      ) : (
        <div className="text-kbd text-dim">
          No provenance was recorded for this decision.
        </div>
      )}
    </Panel>
  );
}

function ProvLine({
  label,
  value,
  bold,
}: {
  label: string;
  value: ReactNode;
  bold?: boolean;
}) {
  return (
    <div>
      <span className="text-dim2">{label} </span>
      {value != null && value !== "" ? (
        bold ? (
          <b>{value}</b>
        ) : (
          <span>{value}</span>
        )
      ) : (
        <span className="text-dim2">—</span>
      )}
    </div>
  );
}

// ---- "what the AI saw vs what you see" panel (WO-B9, FIELD-LEVEL) -----------

function AnonymizationPanel({ alert }: { alert: IncidentAlert }) {
  const copy = anonymizationCopy(alert.anonymized_fields);
  return (
    <Panel className="flex-1 p-3">
      <div className="mb-1.5 text-micro uppercase tracking-wide text-dim2">
        What the AI saw vs what you see
      </div>
      <p className="text-data leading-relaxed text-dim">{copy.primary}</p>
      <p className="mt-1.5 text-kbd text-dim2">{copy.passThrough}</p>
      <p className="mt-1.5 text-kbd text-dim2">
        Anonymization is the LLM boundary — identifiers are tokenized before AI
        analysis and mapped back to the real values only in your view.
      </p>
    </Panel>
  );
}

// ---- review history (WO-H85) — READ-ONLY, shown BEFORE the override form ----
/**
 * The append-only review history for this alert (`decision_reviews`).
 *
 * Overriding used to DESTROY the previous reviewer's reasoning — a bare
 * `UPDATE ... SET human_verdict = %s, review_reason = %s`. The history is now
 * kept server-side, and this renders it ABOVE the verdict form so a reviewer
 * can see they are disagreeing with a colleague, and read what that person
 * said, BEFORE they submit.
 *
 * Source of the data:
 *   - the Incidents case view attaches `alert.review_history` (batched
 *     server-side on the incident detail) → rendered with NO extra request;
 *   - the Triage decision case has no such field → the history is fetched by
 *     decision id.
 * Both are READ-ONLY (`verify_jwt`) — this widens no write authority.
 */
function ReviewHistoryPanel({ alert }: { alert: IncidentAlert }) {
  const attached = alert.review_history;
  const [fetched, setFetched] = useState<DecisionReview[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Only fetch when the caller did NOT attach the history (the incident case
    // view already batched it — never re-request it per member alert).
    if (attached !== undefined) return;
    const ac = new AbortController();
    setLoading(true);
    setError(null);
    getDecisionReviews(alert.id, ac.signal)
      .then((res) => {
        if (!ac.signal.aborted) setFetched(res.reviews ?? []);
      })
      .catch((e) => {
        if (!ac.signal.aborted) setError(errMessage(e));
      })
      .finally(() => {
        if (!ac.signal.aborted) setLoading(false);
      });
    return () => ac.abort();
  }, [alert.id, attached]);

  const entries = attached ?? fetched;

  if (loading && !entries) {
    return (
      <div className="rounded-lg border border-line bg-panel2 px-3 py-2 text-kbd text-dim2">
        Loading who reviewed this before you…
      </div>
    );
  }
  if (error && !entries) {
    return (
      <div className="rounded-lg border border-line bg-panel2 px-3 py-2 text-kbd text-sev-med" role="alert">
        Couldn&apos;t load the review history ({error}) — assume someone may
        have judged this alert already and check before you override.
      </div>
    );
  }
  if (!entries || entries.length === 0) {
    return (
      <div className="rounded-lg border border-line bg-panel2 px-3 py-2 text-kbd text-dim2">
        No previous human review recorded on this alert.
      </div>
    );
  }

  const latest = entries[entries.length - 1];
  return (
    <div className="rounded-lg border border-line bg-panel2 px-3 py-2">
      <div className="mb-1 flex flex-wrap items-center gap-2">
        <span className="text-micro uppercase tracking-wide text-dim2">
          Review history — append-only
        </span>
        <span className="text-kbd text-sev-med font-semibold" role="note">
          {entries.length === 1
            ? `${latest.reviewer} already reviewed this alert`
            : `${entries.length} reviews — most recently by ${latest.reviewer}`}
          . Read it before you override.
        </span>
      </div>
      <ol className="flex flex-col gap-1.5">
        {entries.map((e, i) => (
          <li
            key={e.id ?? `${e.reviewer}-${i}`}
            className="border-l-2 border-line pl-2"
          >
            <div className="flex flex-wrap items-center gap-1.5 text-kbd">
              <b className="text-ink">{e.reviewer}</b>
              {e.created_at && (
                <span className="text-dim2">{formatWhen(e.created_at)}</span>
              )}
              {e.human_verdict && (
                <Chip aria-label={`verdict ${e.human_verdict}`}>
                  {verdictPresentation(String(e.human_verdict)).label}
                </Chip>
              )}
              {e.previous_verdict && (
                <span className="text-dim2">
                  (changed from{" "}
                  {verdictPresentation(String(e.previous_verdict)).label})
                </span>
              )}
              {e.source === "incident_verdict_propagation" && (
                <span className="text-dim2">
                  · applied from the incident, not judged alert-by-alert
                </span>
              )}
            </div>
            {e.reason && (
              <div className="mt-0.5 text-data leading-relaxed text-dim">
                {e.reason}
              </div>
            )}
          </li>
        ))}
      </ol>
    </div>
  );
}

// ---- triage decision panel (reason-required WRITE; RBAC-gated) --------------

const REVIEW_CHOICES: ReadonlyArray<{ verdict: TriageVerdict; label: string }> = [
  { verdict: "true_positive", label: "Confirm true positive" },
  { verdict: "needs_investigation", label: "Needs investigation" },
  { verdict: "false_positive", label: "False positive" },
];

function TriageDecisionPanel({
  alert,
  onReviewed,
}: {
  alert: IncidentAlert;
  onReviewed: () => void;
}) {
  const { role } = useAuth();
  const hasExisting =
    alert.human_verdict != null && alert.human_verdict !== "";
  const gate = triageReviewGate(role, hasExisting);

  const [choice, setChoice] = useState<TriageVerdict | null>(null);
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<
    { ok: true } | { ok: false; message: string } | null
  >(null);
  const reasonId = useId();
  const reasonErrId = useId();

  const reasonEmpty = reason.trim().length === 0;
  const canSubmit = gate.canSubmit && choice !== null && !reasonEmpty && !submitting;

  const submit = useCallback(async () => {
    if (!gate.canSubmit || choice === null || reasonEmpty) return;
    setSubmitting(true);
    setResult(null);
    try {
      await submitTriageReview({
        decision_id: alert.id,
        human_verdict: choice,
        reason: reason.trim(),
      });
      setResult({ ok: true });
      setReason("");
      setChoice(null);
      onReviewed(); // refetch the case so the recorded verdict is reflected
    } catch (e) {
      setResult({ ok: false, message: errMessage(e) });
    } finally {
      setSubmitting(false);
    }
  }, [gate.canSubmit, choice, reason, reasonEmpty, alert.id, onReviewed]);

  const disabled = !gate.canSubmit;

  return (
    <Panel className="p-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="text-micro uppercase tracking-wide text-dim2">
          Triage decision — role gates writes
        </div>
        {hasExisting && (
          <Chip aria-label={`current human verdict ${alert.human_verdict}`}>
            recorded: {verdictPresentation(String(alert.human_verdict)).label}
          </Chip>
        )}
        {gate.mode === "readonly" && (
          <span className="text-kbd text-sev-high font-semibold">
            read-only: disabled
          </span>
        )}
        {gate.mode === "override-denied" && (
          <span className="text-kbd text-sev-med font-semibold">
            requires admin to override
          </span>
        )}
      </div>

      {/* WO-H85 — the CURRENT reviewer's reason. It was written on 6,400+
          closures and rendered nowhere, so the analyst who wrote one could not
          read it back and the next shift could not see why anything was
          closed. */}
      {alert.review_reason && (
        <div className="mt-2 text-kbd text-dim">
          Recorded reason:{" "}
          <span className="text-data text-ink">{alert.review_reason}</span>
        </div>
      )}

      {/* WO-H85 — who judged this before you, and what they said. Deliberately
          ABOVE the form: the point is to read it BEFORE overriding. */}
      <div className="mt-2">
        <ReviewHistoryPanel alert={alert} />
      </div>

      {/* verdict choices */}
      <div
        role="radiogroup"
        aria-label="Human verdict"
        className="mt-2 flex flex-wrap gap-2"
      >
        {REVIEW_CHOICES.map((c) => {
          const selected = choice === c.verdict;
          return (
            <button
              key={c.verdict}
              type="button"
              role="radio"
              aria-checked={selected}
              disabled={disabled}
              onClick={() => setChoice(c.verdict)}
              className={cn(
                "rounded-md border px-2.5 py-1 text-meta",
                selected
                  ? "border-cite-border bg-cite-bg text-cite-ink"
                  : "border-line bg-field text-ink hover:bg-hover",
                disabled && "cursor-not-allowed opacity-50",
                focusRing,
              )}
            >
              {c.label}
            </button>
          );
        })}
      </div>

      {/* reason (required) */}
      <div className="mt-2">
        <label htmlFor={reasonId} className="text-kbd text-dim">
          Reason <span className="text-sev-crit">*required</span>
        </label>
        <textarea
          id={reasonId}
          value={reason}
          disabled={disabled}
          onChange={(e) => setReason(e.target.value)}
          rows={2}
          placeholder="Recorded to the audit trail and attached to the verdict…"
          aria-describedby={reasonEmpty ? reasonErrId : undefined}
          aria-invalid={!disabled && choice !== null && reasonEmpty}
          className={cn(
            "mt-1 w-full rounded-lg border border-line bg-field px-2.5 py-2 text-data text-ink placeholder:text-dim2",
            disabled && "cursor-not-allowed opacity-50",
            focusRing,
          )}
        />
      </div>

      {/* submit + gate/why messages */}
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={submit}
          disabled={!canSubmit}
          className={cn(
            "rounded-md border-none bg-[#25406a] px-3 py-1.5 text-data text-white hover:brightness-110",
            !canSubmit && "cursor-not-allowed opacity-50",
            focusRing,
          )}
        >
          {submitting ? "Recording…" : hasExisting ? "Override verdict" : "Record verdict"}
        </button>
        {!disabled && choice !== null && reasonEmpty && (
          <span id={reasonErrId} className="text-kbd text-sev-med" role="alert">
            A reason is required — the server rejects a verdict without one (422).
          </span>
        )}
        {disabled && gate.lockNote && (
          <span className="text-kbd text-dim2">{gate.lockNote}</span>
        )}
        {result?.ok && (
          <span className="text-kbd text-grounded-ink" role="status">
            ✓ Verdict recorded to the audit trail.
          </span>
        )}
        {result && !result.ok && (
          <span className="text-kbd text-sev-crit" role="alert">
            {result.message}
          </span>
        )}
      </div>

      <div className="mt-2 border-t border-line pt-2 text-kbd text-dim2">
        🔒 Active response stays human-approved — containment is not triggered
        here. Ask the copilot (top bar) to propose a gated containment action.
        Reversing an existing containment is a senior-analyst-or-higher action.
      </div>
    </Panel>
  );
}

// ---- shared small helpers (used by both the incident + decision case views) --

export function errMessage(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  if (e instanceof Error) return e.message;
  return "Unknown error";
}

export function humanStatus(status: string): string {
  const s = (status ?? "").replace(/[_-]+/g, " ").trim();
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : "—";
}

export function formatWhen(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(+d)) return iso;
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function fmtNum(n: number): string {
  return Number.isInteger(n) ? String(n) : n.toFixed(2).replace(/\.?0+$/, "");
}

function fmtGuidance(v: unknown): string | null {
  if (v == null) return null;
  if (typeof v === "string") return v;
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}

function toneClass(tone: Severity | "neutral"): string {
  return tone === "neutral" ? "text-ink" : SEVERITY[tone].textClass;
}
