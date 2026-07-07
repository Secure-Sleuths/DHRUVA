"use client";

/**
 * IncidentActions (WO-U4 case writes) — the case-management WRITE rail for the
 * glass-box Incidents case view. This is the piece that turns the redesign's
 * read-only Incidents case into a real analyst workstation: status change,
 * assign, note, flag-interesting, escalate, evidence, merge and post-incident
 * review — every one wired to its real `/api/incidents/*` endpoint.
 *
 * DISCIPLINE (mirrors the server, never widens):
 *   - RBAC per action is mirrored from `src/api/routes/incidents.py` via
 *     `rbac.ts::incidentActionGate`. Role-denied controls are HIDDEN (dead
 *     controls the server would 403); an ownership block on an `analyst` (the
 *     server's `_check_incident_access`) shows the control DISABLED with the
 *     reason. The server always re-checks — this only prevents dead controls.
 *   - STATUS is reason-required (WO-B3, server-mandatory). Its panel reuses the
 *     SAME reason-required interaction as the triage-review panel in
 *     `GlassBoxCase.tsx` — a choice radiogroup + a required reason textarea +
 *     submit disabled until both are present — so the UI never fires a request
 *     the server rejects with a 422.
 *   - MERGE is IRREVERSIBLE → a confirm Dialog gates it, and it also mirrors the
 *     `incidents_merge` license gate (`mergeLicensed`).
 *   - Every panel has explicit submitting / typed-error / success states and
 *     refetches the case on success (via `onChanged`) so the header reflects the
 *     new state. No optimistic fabrication.
 *   - Active response is NOT here — containment stays human-approved via the
 *     gated copilot, exactly as the case view already states.
 */

import { useCallback, useId, useState, type ReactNode } from "react";
import { Chip, Dialog, Panel } from "@/components";
import {
  addIncidentEvidence,
  addIncidentNote,
  assignIncident,
  changeIncidentStatus,
  escalateIncident,
  flagIncidentInteresting,
  mergeIncidents,
  saveIncidentReview,
} from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { incidentActionGate, mergeLicensed } from "@/lib/rbac";
import { cn, focusRing } from "@/lib/ui";
import { errMessage, humanStatus } from "./GlassBoxCase";
import type {
  EvidenceType,
  IncidentDetail,
  IncidentStatus,
  PirStatus,
} from "@/lib/types";

// ---- shared field styling (matches GlassBoxCase form controls) --------------

const FIELD_CLS =
  "mt-1 w-full rounded-lg border border-line bg-field px-2.5 py-2 text-data text-ink placeholder:text-dim2";
const BTN_PRIMARY =
  "rounded-md border-none bg-[#25406a] px-3 py-1.5 text-data text-white hover:brightness-110";
const BTN_NEUTRAL =
  "rounded-md border border-line bg-field px-2.5 py-1 text-meta text-ink hover:bg-hover";

function disabledCls(disabled: boolean): string {
  return disabled ? "cursor-not-allowed opacity-50" : "";
}

// ---- a per-action write state hook (DRY across the panels) ------------------

type WriteResult =
  | { ok: true; message?: string }
  | { ok: false; message: string }
  | null;

function useWrite(onChanged: () => void) {
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<WriteResult>(null);

  const run = useCallback(
    async (fn: () => Promise<void>, successMsg?: string): Promise<boolean> => {
      setSubmitting(true);
      setResult(null);
      try {
        await fn();
        setResult({ ok: true, message: successMsg });
        onChanged(); // refetch the case so the header reflects the new state
        return true;
      } catch (e) {
        setResult({ ok: false, message: errMessage(e) });
        return false;
      } finally {
        setSubmitting(false);
      }
    },
    [onChanged],
  );

  return { submitting, result, run };
}

function ResultLine({ result }: { result: WriteResult }) {
  if (!result) return null;
  return result.ok ? (
    <span className="text-kbd text-grounded-ink" role="status">
      ✓ {result.message ?? "Saved to the case."}
    </span>
  ) : (
    <span className="text-kbd text-sev-crit" role="alert">
      {result.message}
    </span>
  );
}

// ---- collapsible action section --------------------------------------------

function Section({
  title,
  hint,
  disabled,
  lockNote,
  defaultOpen = false,
  children,
}: {
  title: string;
  hint?: string;
  /** ownership-disabled (role is allowed, but not on THIS incident) */
  disabled?: boolean;
  lockNote?: string;
  defaultOpen?: boolean;
  children: ReactNode;
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
        <span className="font-medium">{title}</span>
        {hint && <span className="text-kbd text-dim2">{hint}</span>}
        {disabled && (
          <span className="ml-auto text-kbd text-sev-med font-semibold">
            not available for this incident
          </span>
        )}
      </button>
      <div id={id} hidden={!open} className="mt-2">
        {disabled && lockNote && (
          <div className="mb-2 text-kbd text-dim2">{lockNote}</div>
        )}
        {children}
      </div>
    </div>
  );
}

// ---- STATUS (reason-required — mirrors the triage-review panel pattern) ------

const STATUS_CHOICES: ReadonlyArray<{ status: IncidentStatus; label: string }> = [
  { status: "open", label: "Re-open" },
  { status: "investigating", label: "Investigating" },
  { status: "resolved", label: "Resolved" },
  { status: "closed", label: "Closed" },
];

function StatusPanel({
  detail,
  disabled,
  onChanged,
}: {
  detail: IncidentDetail;
  disabled: boolean;
  onChanged: () => void;
}) {
  const current = (detail.status ?? "open") as string;
  const isClosed = current === "closed";
  const [choice, setChoice] = useState<IncidentStatus | null>(null);
  const [reason, setReason] = useState("");
  const { submitting, result, run } = useWrite(onChanged);
  const reasonId = useId();
  const reasonErrId = useId();

  const reasonEmpty = reason.trim().length === 0;
  const canSubmit = !disabled && choice !== null && !reasonEmpty && !submitting;

  // The server forbids reopening a closed incident (400): once closed, only
  // "closed" is a legal target. Also disable the current status (no-op).
  const isChoiceBlocked = (s: IncidentStatus) =>
    disabled || s === current || (isClosed && s !== "closed");

  const submit = async () => {
    if (choice === null || reasonEmpty) return;
    const ok = await run(
      () =>
        changeIncidentStatus(detail.id, {
          status: choice,
          reason: reason.trim(),
        }).then(() => undefined),
      `Status changed to ${humanStatus(choice)}.`,
    );
    if (ok) {
      setReason("");
      setChoice(null);
    }
  };

  return (
    <div>
      <div className="text-kbd text-dim">
        Current: <b>{humanStatus(current)}</b>
        {isClosed && (
          <span className="ml-2 text-sev-med">
            closed incidents can’t be re-opened (server-enforced)
          </span>
        )}
      </div>

      <div
        role="radiogroup"
        aria-label="New status"
        className="mt-2 flex flex-wrap gap-2"
      >
        {STATUS_CHOICES.map((c) => {
          const blocked = isChoiceBlocked(c.status);
          const selected = choice === c.status;
          return (
            <button
              key={c.status}
              type="button"
              role="radio"
              aria-checked={selected}
              disabled={blocked}
              onClick={() => setChoice(c.status)}
              className={cn(
                "rounded-md border px-2.5 py-1 text-meta",
                selected
                  ? "border-cite-border bg-cite-bg text-cite-ink"
                  : "border-line bg-field text-ink hover:bg-hover",
                disabledCls(blocked),
                focusRing,
              )}
            >
              {c.label}
            </button>
          );
        })}
      </div>

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
          placeholder="Recorded to the audit trail with the status change…"
          aria-describedby={reasonEmpty ? reasonErrId : undefined}
          aria-invalid={!disabled && choice !== null && reasonEmpty}
          className={cn(FIELD_CLS, disabledCls(disabled), focusRing)}
        />
      </div>

      <div className="mt-2 flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={submit}
          disabled={!canSubmit}
          className={cn(BTN_PRIMARY, disabledCls(!canSubmit), focusRing)}
        >
          {submitting ? "Recording…" : "Change status"}
        </button>
        {!disabled && choice !== null && reasonEmpty && (
          <span id={reasonErrId} className="text-kbd text-sev-med" role="alert">
            A reason is required — the server rejects a status change without one
            (422).
          </span>
        )}
        <ResultLine result={result} />
      </div>
    </div>
  );
}

// ---- ASSIGN -----------------------------------------------------------------

function AssignPanel({
  detail,
  onChanged,
}: {
  detail: IncidentDetail;
  onChanged: () => void;
}) {
  const [who, setWho] = useState("");
  const { submitting, result, run } = useWrite(onChanged);
  const inputId = useId();
  const empty = who.trim().length === 0;
  const canSubmit = !empty && !submitting;

  const submit = async () => {
    if (empty) return;
    const ok = await run(
      () =>
        assignIncident(detail.id, { assigned_to: who.trim() }).then(
          () => undefined,
        ),
      `Assigned to ${who.trim()}.`,
    );
    if (ok) setWho("");
  };

  return (
    <div>
      <div className="text-kbd text-dim">
        Currently:{" "}
        <b>{detail.assigned_to ? detail.assigned_to : "Unassigned"}</b>
      </div>
      <label htmlFor={inputId} className="mt-2 block text-kbd text-dim">
        Assign to (username)
      </label>
      <input
        id={inputId}
        type="text"
        value={who}
        onChange={(e) => setWho(e.target.value)}
        placeholder="analyst username"
        maxLength={100}
        className={cn(FIELD_CLS, focusRing)}
      />
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={submit}
          disabled={!canSubmit}
          className={cn(BTN_PRIMARY, disabledCls(!canSubmit), focusRing)}
        >
          {submitting ? "Assigning…" : "Assign"}
        </button>
        <span className="text-kbd text-dim2">
          The server verifies the user exists and is active.
        </span>
        <ResultLine result={result} />
      </div>
    </div>
  );
}

// ---- NOTE -------------------------------------------------------------------

function NotePanel({
  detail,
  disabled,
  onChanged,
}: {
  detail: IncidentDetail;
  disabled: boolean;
  onChanged: () => void;
}) {
  const [note, setNote] = useState("");
  const { submitting, result, run } = useWrite(onChanged);
  const inputId = useId();
  const empty = note.trim().length === 0;
  const canSubmit = !disabled && !empty && !submitting;

  const submit = async () => {
    if (empty) return;
    const ok = await run(
      () => addIncidentNote(detail.id, { note: note.trim() }).then(() => undefined),
      "Note added to the case timeline.",
    );
    if (ok) setNote("");
  };

  return (
    <div>
      <label htmlFor={inputId} className="text-kbd text-dim">
        Analyst note
      </label>
      <textarea
        id={inputId}
        value={note}
        disabled={disabled}
        onChange={(e) => setNote(e.target.value)}
        rows={3}
        maxLength={5000}
        placeholder="Appended to the incident timeline (audit-logged)…"
        className={cn(FIELD_CLS, disabledCls(disabled), focusRing)}
      />
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={submit}
          disabled={!canSubmit}
          className={cn(BTN_PRIMARY, disabledCls(!canSubmit), focusRing)}
        >
          {submitting ? "Adding…" : "Add note"}
        </button>
        <ResultLine result={result} />
      </div>
    </div>
  );
}

// ---- FLAG INTERESTING -------------------------------------------------------

function FlagPanel({
  detail,
  onChanged,
}: {
  detail: IncidentDetail;
  onChanged: () => void;
}) {
  const flaggedNow =
    detail.flagged_interesting === true || detail.flagged_interesting === 1;
  const [notes, setNotes] = useState(detail.interesting_notes ?? "");
  const { submitting, result, run } = useWrite(onChanged);
  const inputId = useId();

  const setFlag = async (flagged: boolean) => {
    await run(
      () =>
        flagIncidentInteresting(detail.id, {
          flagged,
          notes: flagged ? notes.trim().slice(0, 500) : "",
        }).then(() => undefined),
      flagged ? "Flagged as interesting." : "Un-flagged.",
    );
  };

  return (
    <div>
      <div className="text-kbd text-dim">
        Currently:{" "}
        <b>{flaggedNow ? "flagged (case of the week)" : "not flagged"}</b>
      </div>
      <label htmlFor={inputId} className="mt-2 block text-kbd text-dim">
        Why is this interesting? (max 500 chars)
      </label>
      <textarea
        id={inputId}
        value={notes}
        onChange={(e) => setNotes(e.target.value)}
        rows={2}
        maxLength={500}
        placeholder="Used for the case-of-the-week write-up…"
        className={cn(FIELD_CLS, focusRing)}
      />
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => setFlag(true)}
          disabled={submitting}
          className={cn(BTN_PRIMARY, disabledCls(submitting), focusRing)}
        >
          {submitting ? "Saving…" : flaggedNow ? "Update notes" : "Flag interesting"}
        </button>
        {flaggedNow && (
          <button
            type="button"
            onClick={() => setFlag(false)}
            disabled={submitting}
            className={cn(BTN_NEUTRAL, disabledCls(submitting), focusRing)}
          >
            Un-flag
          </button>
        )}
        <ResultLine result={result} />
      </div>
    </div>
  );
}

// ---- ESCALATE ---------------------------------------------------------------

const ESCALATE_TIERS: ReadonlyArray<"L2" | "L3"> = ["L2", "L3"];

function EscalatePanel({
  detail,
  onChanged,
}: {
  detail: IncidentDetail;
  onChanged: () => void;
}) {
  const currentTier = (detail.tier ?? "L1") as string;
  const [tier, setTier] = useState<"L2" | "L3" | null>(null);
  const [handoff, setHandoff] = useState("");
  const { submitting, result, run } = useWrite(onChanged);
  const inputId = useId();
  const canSubmit = tier !== null && !submitting;

  // Can't escalate to the same or a lower tier (server 400). L1→L2/L3, L2→L3.
  const tierBlocked = (t: "L2" | "L3") =>
    (currentTier === "L2" && t === "L2") || currentTier === "L3";

  const submit = async () => {
    if (tier === null) return;
    const ok = await run(
      () =>
        escalateIncident(detail.id, {
          tier,
          handoff_notes: handoff.trim(),
        }).then(() => undefined),
      `Escalated to ${tier}.`,
    );
    if (ok) {
      setTier(null);
      setHandoff("");
    }
  };

  return (
    <div>
      <div className="text-kbd text-dim">
        Current tier: <b>{currentTier}</b>
      </div>
      <div
        role="radiogroup"
        aria-label="Escalate to tier"
        className="mt-2 flex flex-wrap gap-2"
      >
        {ESCALATE_TIERS.map((t) => {
          const blocked = tierBlocked(t);
          const selected = tier === t;
          return (
            <button
              key={t}
              type="button"
              role="radio"
              aria-checked={selected}
              disabled={blocked}
              onClick={() => setTier(t)}
              className={cn(
                "rounded-md border px-2.5 py-1 text-meta",
                selected
                  ? "border-cite-border bg-cite-bg text-cite-ink"
                  : "border-line bg-field text-ink hover:bg-hover",
                disabledCls(blocked),
                focusRing,
              )}
            >
              {t}
            </button>
          );
        })}
      </div>
      <label htmlFor={inputId} className="mt-2 block text-kbd text-dim">
        Handoff notes (what you tried, why escalating)
      </label>
      <textarea
        id={inputId}
        value={handoff}
        onChange={(e) => setHandoff(e.target.value)}
        rows={2}
        placeholder="Optional but recommended for the receiving tier…"
        className={cn(FIELD_CLS, focusRing)}
      />
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={submit}
          disabled={!canSubmit}
          className={cn(BTN_PRIMARY, disabledCls(!canSubmit), focusRing)}
        >
          {submitting ? "Escalating…" : "Escalate"}
        </button>
        <ResultLine result={result} />
      </div>
    </div>
  );
}

// ---- EVIDENCE ---------------------------------------------------------------

const EVIDENCE_TYPES: readonly EvidenceType[] = [
  "note",
  "artifact",
  "screenshot",
  "log",
  "ioc",
  "file",
  "other",
];

function EvidencePanel({
  detail,
  disabled,
  onChanged,
}: {
  detail: IncidentDetail;
  disabled: boolean;
  onChanged: () => void;
}) {
  const [type, setType] = useState<EvidenceType>("note");
  const [description, setDescription] = useState("");
  const [refId, setRefId] = useState("");
  const { submitting, result, run } = useWrite(onChanged);
  const typeId = useId();
  const descId = useId();
  const refIdId = useId();
  const empty = description.trim().length === 0;
  const canSubmit = !disabled && !empty && !submitting;

  const submit = async () => {
    if (empty) return;
    const ok = await run(
      () =>
        addIncidentEvidence(detail.id, {
          type,
          description: description.trim(),
          ref_id: refId.trim() || undefined,
        }).then(() => undefined),
      "Evidence added to the chain.",
    );
    if (ok) {
      setDescription("");
      setRefId("");
    }
  };

  return (
    <div className="flex flex-col gap-2">
      <div>
        <label htmlFor={typeId} className="text-kbd text-dim">
          Type
        </label>
        <select
          id={typeId}
          value={type}
          disabled={disabled}
          onChange={(e) => setType(e.target.value as EvidenceType)}
          className={cn(FIELD_CLS, disabledCls(disabled), focusRing)}
        >
          {EVIDENCE_TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
      </div>
      <div>
        <label htmlFor={descId} className="text-kbd text-dim">
          Description <span className="text-sev-crit">*required</span>
        </label>
        <textarea
          id={descId}
          value={description}
          disabled={disabled}
          onChange={(e) => setDescription(e.target.value)}
          rows={2}
          maxLength={5000}
          placeholder="What the artifact is and where it came from…"
          className={cn(FIELD_CLS, disabledCls(disabled), focusRing)}
        />
      </div>
      <div>
        <label htmlFor={refIdId} className="text-kbd text-dim">
          Reference ID (optional)
        </label>
        <input
          id={refIdId}
          type="text"
          value={refId}
          disabled={disabled}
          onChange={(e) => setRefId(e.target.value)}
          maxLength={200}
          placeholder="alert id, ticket ref, file hash…"
          className={cn(FIELD_CLS, disabledCls(disabled), focusRing)}
        />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={submit}
          disabled={!canSubmit}
          className={cn(BTN_PRIMARY, disabledCls(!canSubmit), focusRing)}
        >
          {submitting ? "Adding…" : "Add evidence"}
        </button>
        <ResultLine result={result} />
      </div>
    </div>
  );
}

// ---- POST-INCIDENT REVIEW ---------------------------------------------------

const PIR_STATUSES: readonly PirStatus[] = ["draft", "in_review", "completed"];

function ReviewPanel({
  detail,
  onChanged,
}: {
  detail: IncidentDetail;
  onChanged: () => void;
}) {
  const [participants, setParticipants] = useState("");
  const [timeline, setTimeline] = useState("");
  const [gap, setGap] = useState("");
  const [effectiveness, setEffectiveness] = useState("");
  const [lessons, setLessons] = useState("");
  const [status, setStatus] = useState<PirStatus>("draft");
  const { submitting, result, run } = useWrite(onChanged);
  const statusId = useId();

  const submit = async () => {
    await run(
      () =>
        saveIncidentReview(detail.id, {
          participants: participants
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean),
          timeline_accuracy: timeline,
          detection_gap: gap,
          response_effectiveness: effectiveness,
          lessons_learned: lessons,
          action_items: [],
          detection_backlog_items: [],
          status,
        }).then(() => undefined),
      "Post-incident review saved.",
    );
  };

  const textAreas: ReadonlyArray<{
    label: string;
    value: string;
    set: (v: string) => void;
  }> = [
    { label: "Timeline accuracy", value: timeline, set: setTimeline },
    { label: "Detection gap", value: gap, set: setGap },
    {
      label: "Response effectiveness",
      value: effectiveness,
      set: setEffectiveness,
    },
    { label: "Lessons learned", value: lessons, set: setLessons },
  ];

  return (
    <div className="flex flex-col gap-2">
      <div>
        <label className="text-kbd text-dim">
          Participants (comma-separated)
        </label>
        <input
          type="text"
          value={participants}
          onChange={(e) => setParticipants(e.target.value)}
          placeholder="a.rivera, s.chen…"
          className={cn(FIELD_CLS, focusRing)}
        />
      </div>
      {textAreas.map((ta) => (
        <div key={ta.label}>
          <label className="text-kbd text-dim">{ta.label}</label>
          <textarea
            value={ta.value}
            onChange={(e) => ta.set(e.target.value)}
            rows={2}
            className={cn(FIELD_CLS, focusRing)}
          />
        </div>
      ))}
      <div>
        <label htmlFor={statusId} className="text-kbd text-dim">
          Review status
        </label>
        <select
          id={statusId}
          value={status}
          onChange={(e) => setStatus(e.target.value as PirStatus)}
          className={cn(FIELD_CLS, focusRing)}
        >
          {PIR_STATUSES.map((s) => (
            <option key={s} value={s}>
              {s.replace(/_/g, " ")}
            </option>
          ))}
        </select>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={submit}
          disabled={submitting}
          className={cn(BTN_PRIMARY, disabledCls(submitting), focusRing)}
        >
          {submitting ? "Saving…" : "Save review"}
        </button>
        <ResultLine result={result} />
      </div>
    </div>
  );
}

// ---- MERGE (irreversible — confirm dialog + license gate) -------------------

function MergePanel({
  detail,
  licensed,
  onChanged,
}: {
  detail: IncidentDetail;
  licensed: boolean;
  onChanged: () => void;
}) {
  const [raw, setRaw] = useState("");
  const [confirmOpen, setConfirmOpen] = useState(false);
  const { submitting, result, run } = useWrite(onChanged);
  const inputId = useId();

  const sources = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const canOpen = licensed && sources.length > 0 && !submitting;

  const doMerge = async () => {
    setConfirmOpen(false);
    const ok = await run(
      () =>
        mergeIncidents({
          target_id: detail.id,
          source_ids: sources,
        }).then(() => undefined),
      `Merged ${sources.length} incident(s) into ${detail.id}.`,
    );
    if (ok) setRaw("");
  };

  if (!licensed) {
    return (
      <div className="text-kbd text-dim2">
        Merge requires the <b>incidents_merge</b> license feature, which isn’t
        enabled on this tier. The server rejects the merge (403) without it.
      </div>
    );
  }

  return (
    <div>
      <label htmlFor={inputId} className="text-kbd text-dim">
        Source incident IDs to merge INTO{" "}
        <span className="font-mono">{detail.id}</span> (comma-separated)
      </label>
      <input
        id={inputId}
        type="text"
        value={raw}
        onChange={(e) => setRaw(e.target.value)}
        placeholder="inc_123, inc_456"
        className={cn(FIELD_CLS, focusRing)}
      />
      <div className="mt-1 text-kbd text-sev-med">
        ⚠ Irreversible — source incidents are closed and their alerts re-linked
        to this one.
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => setConfirmOpen(true)}
          disabled={!canOpen}
          className={cn(BTN_PRIMARY, disabledCls(!canOpen), focusRing)}
        >
          {submitting ? "Merging…" : "Merge…"}
        </button>
        <ResultLine result={result} />
      </div>

      <Dialog
        open={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        title="Confirm merge"
        maxWidth={420}
      >
        <p className="text-data text-ink">
          Merge <b>{sources.length}</b> incident(s) into{" "}
          <span className="font-mono">{detail.id}</span>?
        </p>
        <p className="mt-2 text-kbd text-dim2">
          This is <b>irreversible</b>: the source incidents will be closed and
          their alerts re-linked to this incident.
        </p>
        <div className="mt-3 flex justify-end gap-2">
          <button
            type="button"
            onClick={() => setConfirmOpen(false)}
            className={cn(BTN_NEUTRAL, focusRing)}
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={doMerge}
            className={cn(BTN_PRIMARY, focusRing)}
          >
            Merge incidents
          </button>
        </div>
      </Dialog>
    </div>
  );
}

// ---- the case-management rail ----------------------------------------------

export function IncidentActions({
  detail,
  onChanged,
}: {
  detail: IncidentDetail;
  onChanged: () => void;
}) {
  const { role, claims, tier } = useAuth();

  // Ownership mirror of the server's `_check_incident_access`: an `analyst` may
  // only act on an incident assigned to them. `sub` is the JWT subject; when it
  // is absent (dev-preview, no real token) ownership is UNKNOWN (null) and is
  // not blocked client-side — the server remains the enforcement point.
  const sub = typeof claims?.sub === "string" ? claims.sub : null;
  const isOwner: boolean | null = sub
    ? !!detail.assigned_to && detail.assigned_to === sub
    : null;

  const gate = {
    status: incidentActionGate(role, "status", isOwner),
    assign: incidentActionGate(role, "assign", isOwner),
    note: incidentActionGate(role, "note", isOwner),
    flag: incidentActionGate(role, "flag", isOwner),
    escalate: incidentActionGate(role, "escalate", isOwner),
    evidence: incidentActionGate(role, "evidence", isOwner),
    merge: incidentActionGate(role, "merge", isOwner),
    review: incidentActionGate(role, "review", isOwner),
  } as const;

  const anyVisible = Object.values(gate).some((g) => g.visible);
  const licensedMerge = mergeLicensed(tier);

  return (
    <Panel className="mt-2.5 p-4">
      <div className="mb-1.5 flex flex-wrap items-center gap-2">
        <div className="text-micro uppercase tracking-wide text-dim2">
          Case management — role gates every write
        </div>
        <Chip aria-label={`your role ${role}`}>{role}</Chip>
      </div>

      {!anyVisible ? (
        <div className="text-kbd text-dim2">
          Your role is read-only for case actions — the server rejects writes
          from it, so none are shown. You still see the full glass-box case
          above.
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          {gate.status.visible && (
            <Section
              title="Change status"
              hint="reason-required · audited"
              defaultOpen
              disabled={!gate.status.canSubmit}
              lockNote={gate.status.lockNote}
            >
              <StatusPanel
                detail={detail}
                disabled={!gate.status.canSubmit}
                onChanged={onChanged}
              />
            </Section>
          )}

          {gate.assign.visible && (
            <Section title="Assign" hint="senior analyst+">
              <AssignPanel detail={detail} onChanged={onChanged} />
            </Section>
          )}

          {gate.note.visible && (
            <Section
              title="Add note"
              disabled={!gate.note.canSubmit}
              lockNote={gate.note.lockNote}
            >
              <NotePanel
                detail={detail}
                disabled={!gate.note.canSubmit}
                onChanged={onChanged}
              />
            </Section>
          )}

          {gate.flag.visible && (
            <Section title="Flag interesting" hint="case of the week">
              <FlagPanel detail={detail} onChanged={onChanged} />
            </Section>
          )}

          {gate.escalate.visible && (
            <Section title="Escalate tier" hint="senior analyst+">
              <EscalatePanel detail={detail} onChanged={onChanged} />
            </Section>
          )}

          {gate.evidence.visible && (
            <Section
              title="Add evidence"
              disabled={!gate.evidence.canSubmit}
              lockNote={gate.evidence.lockNote}
            >
              <EvidencePanel
                detail={detail}
                disabled={!gate.evidence.canSubmit}
                onChanged={onChanged}
              />
            </Section>
          )}

          {gate.review.visible && (
            <Section title="Post-incident review" hint="senior analyst+">
              <ReviewPanel detail={detail} onChanged={onChanged} />
            </Section>
          )}

          {gate.merge.visible && (
            <Section title="Merge incidents" hint="irreversible · licensed">
              <MergePanel
                detail={detail}
                licensed={licensedMerge}
                onChanged={onChanged}
              />
            </Section>
          )}
        </div>
      )}

      <div className="mt-2 border-t border-line pt-2 text-kbd text-dim2">
        🔒 Active response stays human-approved — containment is proposed through
        the gated copilot, never triggered from a case. Case writes here are
        audit-logged; the server re-checks role, ownership and reason on every
        one.
      </div>
    </Panel>
  );
}
