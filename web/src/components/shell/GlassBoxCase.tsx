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
import { ApiError, getRuleStats, submitTriageReview } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { triageReviewGate } from "@/lib/rbac";
import { SEVERITY, riskSeverity, type Severity } from "@/lib/severity";
import { verdictPresentation } from "@/lib/triage";
import { alertEnrichment, anonymizationCopy, riskMath } from "@/lib/incident";
import { parseGrounding, type GroundingAssessment } from "@/lib/grounding";
import { cn, focusRing } from "@/lib/ui";
import type { IncidentAlert, RuleStats, TriageVerdict } from "@/lib/types";

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
  const verdict = verdictPresentation(String(alert.verdict));
  const enr = alertEnrichment(alert);
  const stage = enr.tactic_ids[0];

  return (
    <Panel inset className="p-3">
      {/* header: verdict + confidence + risk + stage */}
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
        <ConfidenceBar value={alert.confidence} width={72} />
        <GroundingBadge grounding={alert.grounding} />
        <span className="flex-1" />
        {stage && <Chip>stage: {stage}</Chip>}
        <span
          className={cn(
            "font-mono text-data font-bold tabular",
            SEVERITY[riskSeverity(alert.risk_score)].textClass,
          )}
        >
          risk {Math.round(alert.risk_score)}
        </span>
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

      {/* detail body */}
      <div id={bodyId} hidden={!open} className="mt-3 flex flex-col gap-2.5">
        <RiskMathExpander alert={alert} />
        <ReasoningExpander alert={alert} />
        <RecommendedActionsExpander alert={alert} />
        <RuleStatsExpander alert={alert} />
        <div className="flex flex-col gap-2.5 sm:flex-row">
          <ProvenancePanel alert={alert} />
          <AnonymizationPanel alert={alert} />
        </div>
        <TriageDecisionPanel alert={alert} onReviewed={onReviewed} />
      </div>
    </Panel>
  );
}

// ---- expandable: how was risk = N computed? ---------------------------------

function Expander({
  summary,
  hint,
  children,
  defaultOpen = false,
}: {
  summary: string;
  hint?: string;
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
          "flex w-full items-center gap-1.5 text-left text-data text-teal",
          focusRing,
        )}
      >
        <span aria-hidden="true">{open ? "⌄" : "›"}</span>
        <span>{summary}</span>
        {hint && <span className="text-kbd text-dim2">{hint}</span>}
      </button>
      <div id={id} hidden={!open} className="mt-2">
        {children}
      </div>
    </div>
  );
}

function RiskMathExpander({ alert }: { alert: IncidentAlert }) {
  const math = riskMath(alert.glass_box?.risk_breakdown);
  const score = Math.round(alert.risk_score);
  return (
    <Expander
      summary={`How was risk = ${score} computed?`}
      hint="per-enricher breakdown"
      defaultOpen={false}
    >
      {math ? (
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
    </Expander>
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
      defaultOpen={false}
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
 * Defaults open (like the legacy always-visible box) but only renders when the
 * decision actually carries actions.
 */
function RecommendedActionsExpander({ alert }: { alert: IncidentAlert }) {
  const actions = parseActions(alert.actions_taken);
  if (actions.length === 0) return null;
  return (
    <Expander
      summary="Recommended actions"
      hint={`${actions.length} suggested · advisory`}
      defaultOpen
    >
      <ul className="flex flex-col gap-1">
        {actions.map((a, i) => (
          <li key={i} className="flex gap-2 text-data leading-relaxed text-dim">
            <span aria-hidden="true" className="text-teal">
              •
            </span>
            <span>{a}</span>
          </li>
        ))}
      </ul>
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
 */
function GroundingBadge({ grounding }: { grounding?: string | null }) {
  const g = parseGrounding(grounding);
  if (!g || g.grounding === "high") return null;

  if (g.grounding === "low") {
    return (
      <span
        role="note"
        className="inline-flex items-center gap-1 rounded-md border border-gated-border bg-gated-bg px-2 py-0.5 text-meta font-semibold text-gated-ink"
      >
        <span aria-hidden="true">⚠</span>
        AI not confident — needs your eyes
      </span>
    );
  }

  // medium → muted/subtle note (no amber prominence)
  return (
    <span className="inline-flex items-center gap-1 text-kbd text-dim2">
      <span aria-hidden="true">◔</span>
      AI grounding: partial
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
          ? "The AI's own self-check flagged this reasoning as low-confidence"
          : "The AI's own self-check flagged this reasoning as only partly grounded"}
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
        and never changes the verdict.
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
