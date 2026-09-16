"use client";

/**
 * ShiftScheduleEditor (WO-H79) — the Admin surface that staffs the rota.
 *
 * Binds `GET|PUT /api/admin/shifts/schedule` (`require_role("admin")` +
 * `require_license_feature("sla")`) and `GET /api/admin/users`
 * (`require_role("admin")`).
 *
 * WHY IT EXISTS: nothing in the platform could write
 * `config/guidance/shift_schedule.yaml`, so staffing a shift meant SSH-ing to
 * the box and hand-editing YAML. Two failure modes came from that:
 *
 *   - Analyst names were FREE TEXT with no relation to `platform_users`. A typo
 *     or a departed account produced a shift staffed by somebody who does not
 *     exist, and it failed silently — `get_least_loaded_analyst()`
 *     AUTO-ASSIGNS incidents to whoever is on duty. So every analyst here is
 *     PICKED from the real user list; there is no free-text name field, and
 *     `on_call_primary` is chosen from that shift's own assigned analysts.
 *   - Times are stored UTC-only. India is UTC+5:30, so every boundary on that
 *     tenant is a half hour (02:30 / 10:30 / 18:30) and an operator entering
 *     "8 am" had to convert in their head, three times, correctly. Times are
 *     entered LOCAL here with the resulting UTC shown live beside them.
 *
 * DISCIPLINE:
 *   - RBAC mirrors the server via `adminActionGate(role, "shift_schedule")` —
 *     admin+ only, deliberately STRICTER than the handover read
 *     (senior_analyst+). Never widen; the server re-checks every call.
 *   - The SERVER is the validation gate. The inline notes below are convenience
 *     and never block a save; a rejected save renders the server's own specific
 *     reasons (`scheduleRejectionReasons`).
 *   - 402/403 (licence) → FeatureLockedState. 404 (Community build, module
 *     stripped) is surfaced as "not on this tier" rather than "Not Found".
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Chip, FeatureLockedState, Panel, StatusState } from "@/components";
import {
  ApiError,
  getAdminUsers,
  getShiftSchedule,
  saveShiftSchedule,
  scheduleBlock,
  scheduleRejectionReasons,
} from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { adminActionGate, roleAtLeast } from "@/lib/rbac";
import { cn, focusRing } from "@/lib/ui";
import { asBool } from "@/lib/format";
import type { AdminUser, Role, ShiftDefinition } from "@/lib/types";

// ---- time helpers (pure — unit-tested) --------------------------------------

export const WEEKDAYS = [
  "monday",
  "tuesday",
  "wednesday",
  "thursday",
  "friday",
  "saturday",
  "sunday",
] as const;

const MINUTES_PER_DAY = 24 * 60;

/**
 * Parse a stored schedule boundary into minutes-since-UTC-midnight. Mirrors the
 * server's `_parse_shift_time`: a whole hour (`14`) or `"HH:MM"` (`"18:30"`).
 * Returns null for anything else — the caller shows the raw value rather than
 * inventing a time.
 */
export function parseUtcMinutes(value: string | number): number | null {
  if (typeof value === "number") {
    return Number.isFinite(value) && value >= 0 && value <= 24
      ? Math.round(value * 60)
      : null;
  }
  if (typeof value !== "string") return null;
  const text = value.trim();
  const m = /^(\d{1,2})(?::(\d{2}))?$/.exec(text);
  if (!m) return null;
  const h = Number(m[1]);
  const min = m[2] === undefined ? 0 : Number(m[2]);
  if (h < 0 || h > 24 || min < 0 || min > 59) return null;
  return h * 60 + min;
}

/** Minutes-of-day → "HH:MM" (1440 renders as 24:00, which the server accepts). */
export function fmtHHMM(minutes: number): string {
  const m = minutes === MINUTES_PER_DAY ? MINUTES_PER_DAY : mod(minutes);
  return `${String(Math.floor(m / 60)).padStart(2, "0")}:${String(m % 60).padStart(2, "0")}`;
}

function mod(minutes: number): number {
  return ((minutes % MINUTES_PER_DAY) + MINUTES_PER_DAY) % MINUTES_PER_DAY;
}

/** UTC minutes → local minutes, for an offset in minutes AHEAD of UTC (IST = 330). */
export function utcToLocalMinutes(utcMinutes: number, offsetMin: number): number {
  return mod(utcMinutes + offsetMin);
}

/** Local minutes → UTC minutes (the inverse). */
export function localToUtcMinutes(localMinutes: number, offsetMin: number): number {
  return mod(localMinutes - offsetMin);
}

/** The browser's CURRENT offset in minutes ahead of UTC (IST → 330). */
export function currentOffsetMinutes(now: Date = new Date()): number {
  return -now.getTimezoneOffset();
}

export function offsetLabel(offsetMin: number): string {
  const sign = offsetMin < 0 ? "-" : "+";
  const abs = Math.abs(offsetMin);
  return `UTC${sign}${String(Math.floor(abs / 60)).padStart(2, "0")}:${String(abs % 60).padStart(2, "0")}`;
}

function localZoneName(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "";
  } catch {
    return "";
  }
}

/** Analyst-or-above, active accounts — the only names a shift may carry. */
export function eligibleAnalysts(users: AdminUser[]): AdminUser[] {
  return users
    .filter((u) => asBool(u.is_active))
    .filter((u) => roleAtLeast((u.role ?? "read_only") as Role, "analyst"));
}

// ---- editable row model -----------------------------------------------------

interface DraftShift {
  key: string;
  name: string;
  /** local "HH:MM" as typed by the operator */
  localStart: string;
  localEnd: string;
  /**
   * A 24/7 shift — the simplest valid rota there is, and one `<input
   * type="time">` cannot express: it maxes at 23:59, and 00:00 → 00:00 is a
   * zero-length shift the server rightly refuses. Stored as the schema's own
   * whole-hour form (`0` → `24`), which is timezone-independent by definition.
   */
  allDay: boolean;
  days: string[];
  analysts: string[];
  onCallPrimary: string;
}

/** Does this stored shift cover the whole day (00:00 → 24:00 UTC)? */
export function isAllDay(shift: ShiftDefinition): boolean {
  return (
    parseUtcMinutes(shift.start_utc) === 0 &&
    parseUtcMinutes(shift.end_utc) === MINUTES_PER_DAY
  );
}

let keySeq = 0;
function newKey(): string {
  keySeq += 1;
  return `shift-${keySeq}`;
}

export function toDraft(shift: ShiftDefinition, offsetMin: number): DraftShift {
  const allDay = isAllDay(shift);
  const start = parseUtcMinutes(shift.start_utc);
  const end = parseUtcMinutes(shift.end_utc);
  return {
    key: newKey(),
    name: shift.name ?? "",
    localStart:
      allDay || start === null ? "" : fmtHHMM(utcToLocalMinutes(start, offsetMin)),
    localEnd:
      allDay || end === null ? "" : fmtHHMM(utcToLocalMinutes(end, offsetMin)),
    allDay,
    days: [...(shift.days ?? [])],
    analysts: [...(shift.analysts ?? [])],
    onCallPrimary: shift.on_call_primary ?? "",
  };
}

/** Draft → the wire shape. Times go out as UTC; never local. */
export function toWire(draft: DraftShift, offsetMin: number): ShiftDefinition {
  const start = parseUtcMinutes(draft.localStart);
  const end = parseUtcMinutes(draft.localEnd);
  return {
    name: draft.name.trim(),
    // A 24/7 shift is the same instant-set in every timezone, so it is written
    // as 0 → 24 UTC rather than being converted through the local offset.
    start_utc: draft.allDay
      ? 0
      : start === null
        ? draft.localStart
        : fmtHHMM(localToUtcMinutes(start, offsetMin)),
    end_utc: draft.allDay
      ? 24
      : end === null
        ? draft.localEnd
        : fmtHHMM(localToUtcMinutes(end, offsetMin)),
    days: [...draft.days],
    analysts: [...draft.analysts],
    on_call_primary: draft.onCallPrimary,
  };
}

/**
 * Convenience notes only — the SERVER is the gate and re-checks everything
 * (unknown/inactive analyst, unstaffed shift, primary off-shift, an analyst
 * double-booked, and 24h tiling per day). These never block a save.
 */
export function localNotes(draft: DraftShift): string[] {
  const notes: string[] = [];
  if (!draft.name.trim()) notes.push("This shift has no name.");
  if (!draft.allDay && parseUtcMinutes(draft.localStart) === null) {
    notes.push("Start time is not set.");
  }
  if (!draft.allDay && parseUtcMinutes(draft.localEnd) === null) {
    notes.push("End time is not set.");
  }
  if (draft.analysts.length === 0) {
    notes.push("Nobody is assigned — the server refuses an unstaffed shift.");
  } else if (!draft.analysts.includes(draft.onCallPrimary)) {
    notes.push("Pick an on-call primary from this shift's analysts.");
  }
  return notes;
}

// ---- styling (matches AdminActions) -----------------------------------------

const FIELD_CLS =
  "mt-1 w-full rounded-lg border border-line bg-field px-2.5 py-2 text-data text-ink placeholder:text-dim2";
const BTN_PRIMARY =
  "rounded-md border-none bg-[#25406a] px-3 py-1.5 text-data text-white hover:brightness-110";
const BTN_NEUTRAL =
  "rounded-md border border-line bg-field px-2.5 py-1 text-meta text-ink hover:bg-hover";
const BTN_DANGER =
  "rounded-md border border-sev-crit/40 bg-field px-2.5 py-1 text-meta text-sev-crit hover:bg-hover";

function errMessage(e: unknown): string {
  return e instanceof Error ? e.message : "Unknown error";
}

function isLockErr(e: unknown): boolean {
  return (
    e instanceof ApiError &&
    (e.status === 402 || e.status === 403 || e.status === 404)
  );
}

// ---- the editor -------------------------------------------------------------

export function ShiftScheduleEditor() {
  const { role } = useAuth();
  const gate = adminActionGate(role, "shift_schedule");

  const [offsetMin, setOffsetMin] = useState(0);
  const [zone, setZone] = useState("");
  const [drafts, setDrafts] = useState<DraftShift[] | null>(null);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [path, setPath] = useState("");
  const [fileErrors, setFileErrors] = useState<string[]>([]);
  const [unreadable, setUnreadable] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [confirmOverwrite, setConfirmOverwrite] = useState(false);
  const [writeBlocked, setWriteBlocked] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [locked, setLocked] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState<string | null>(null);
  const [reasons, setReasons] = useState<string[]>([]);
  const abortRef = useRef<AbortController | null>(null);

  // Resolved client-side so the server never has to guess the operator's zone.
  useEffect(() => {
    setOffsetMin(currentOffsetMinutes());
    setZone(localZoneName());
  }, []);

  const load = useCallback(
    async (offset: number) => {
      abortRef.current?.abort();
      const ac = new AbortController();
      abortRef.current = ac;
      setLoading(true);
      setError(null);
      setReasons([]);
      setSaved(null);
      try {
        const [schedule, userList] = await Promise.all([
          getShiftSchedule(ac.signal),
          getAdminUsers({ include_inactive: false }, ac.signal),
        ]);
        if (ac.signal.aborted) return;
        setDrafts(schedule.shifts.map((s) => toDraft(s, offset)));
        setPath(schedule.path);
        setFileErrors(schedule.valid ? [] : (schedule.validation_errors ?? []));
        // An unreadable file is NOT an empty rota — see the note on the type.
        setUnreadable(schedule.unreadable === true);
        setLoadError(schedule.load_error ?? "");
        setConfirmOverwrite(false);
        setWriteBlocked(
          schedule.writable === false ? (schedule.write_blocked_reason ?? "") : "",
        );
        setUsers(userList.users ?? []);
        setLocked(false);
      } catch (e) {
        if (ac.signal.aborted) return;
        if (isLockErr(e)) setLocked(true);
        else setError(errMessage(e));
      } finally {
        if (!ac.signal.aborted) setLoading(false);
      }
    },
    [],
  );

  useEffect(() => {
    if (!gate.visible) return;
    void load(offsetMin);
    return () => abortRef.current?.abort();
  }, [gate.visible, offsetMin, load]);

  const analysts = useMemo(() => eligibleAnalysts(users), [users]);

  const update = useCallback((key: string, patch: Partial<DraftShift>) => {
    setDrafts((prev) =>
      (prev ?? []).map((d) => (d.key === key ? { ...d, ...patch } : d)),
    );
    setSaved(null);
  }, []);

  const save = async () => {
    if (!drafts) return;
    setSaving(true);
    setReasons([]);
    setError(null);
    setSaved(null);
    try {
      const body = {
        shifts: drafts.map((d) => toWire(d, offsetMin)),
        timezone: zone || undefined,
        // Only ever sent when the operator ticked the box for an unreadable
        // file — never a default, never implicit.
        overwrite_unreadable: unreadable && confirmOverwrite ? true : undefined,
      };
      const res = await saveShiftSchedule(body);
      setSaved(
        `Saved to ${res.path}. It applies to the next shift lookup — no restart.` +
          (res.audited === false
            ? " WARNING: the change was written but could NOT be audit-logged — record it manually and check the audit log."
            : ""),
      );
      setFileErrors([]);
      setUnreadable(false);
      setLoadError("");
      setConfirmOverwrite(false);
    } catch (e) {
      const serverReasons = scheduleRejectionReasons(e);
      const block = scheduleBlock(e);
      if (serverReasons.length > 0) setReasons(serverReasons);
      else if (block?.kind === "unreadable") {
        setUnreadable(true);
        setError(block.message);
      } else if (block?.kind === "not_writable") {
        setWriteBlocked(block.message);
      } else if (isLockErr(e)) setLocked(true);
      else setError(errMessage(e));
    } finally {
      setSaving(false);
    }
  };

  if (!gate.visible) {
    return (
      <Panel className="p-4">
        <div className="mb-1 text-title text-ink">Shift schedule</div>
        <div className="text-data text-dim2">
          {gate.lockNote ??
            "Editing the rota is restricted to administrators — the server rejects it (403) from your role."}
        </div>
      </Panel>
    );
  }
  if (locked) {
    return <FeatureLockedState feature="Shift schedule" tier="Enterprise" />;
  }
  if (loading && !drafts) {
    return <StatusState variant="loading" title="Loading the shift schedule…" />;
  }
  if (error && !drafts) {
    return (
      <StatusState
        variant="error"
        title="Couldn't load the shift schedule"
        description={error}
        action={<Chip onClick={() => void load(offsetMin)}>Retry</Chip>}
      />
    );
  }
  if (!drafts) return null;

  // The save is offered only when it can actually succeed: not while a write
  // is in flight, not on a read-only guidance mount, and not over an
  // unreadable file until the operator has explicitly accepted replacing it.
  const saveBlocked =
    saving || !!writeBlocked || (unreadable && !confirmOverwrite);
  const saveBlockedNote = writeBlocked
    ? writeBlocked
    : unreadable && !confirmOverwrite
      ? "Tick the box above to confirm replacing the unreadable file — the server refuses this save (409) otherwise."
      : undefined;

  return (
    <div className="flex flex-col gap-3">
      <Panel className="p-4">
        <div className="mb-1 text-title text-ink">Shift schedule</div>
        <div className="text-kbd text-dim2">
          Who is on duty, and when. Incidents are auto-assigned to the
          least-loaded analyst on the CURRENT shift, so a name here has real
          routing consequences — which is why analysts are picked from your user
          list rather than typed. Times are entered in your local timezone
          {zone ? ` (${zone}, ${offsetLabel(offsetMin)})` : ""} and stored as
          UTC, shown beside each field. Saved to{" "}
          <span className="font-mono">{path || "config/guidance/shift_schedule.yaml"}</span>.
        </div>
        {analysts.length === 0 && (
          <div className="mt-2 text-kbd text-sev-med">
            No active analyst-or-above users exist yet — create users first, or
            every shift will be refused as unstaffed.
          </div>
        )}
        {writeBlocked && (
          <div
            className="mt-3 rounded-lg border border-sev-crit/40 bg-panel2 p-2.5"
            role="alert"
          >
            <div className="text-kbd text-sev-crit">
              This install cannot save the schedule from the UI.
            </div>
            <div className="mt-1 text-kbd text-ink">{writeBlocked}</div>
          </div>
        )}

        {unreadable && (
          <div
            className="mt-3 rounded-lg border border-sev-crit/40 bg-panel2 p-2.5"
            role="alert"
          >
            <div className="text-kbd text-sev-crit">
              The schedule file could not be read — this is NOT an empty rota.
            </div>
            <div className="mt-1 text-kbd text-ink">
              {loadError ||
                "The file exists but could not be parsed, so what is on disk is unknown."}{" "}
              The shifts below are empty because nothing could be loaded. Fixing
              the file directly keeps the existing rota; saving from here
              REPLACES it with whatever you build below.
            </div>
            <label className="mt-2 flex items-center gap-2 text-kbd text-ink">
              <input
                type="checkbox"
                checked={confirmOverwrite}
                onChange={(e) => setConfirmOverwrite(e.target.checked)}
                className={cn(focusRing)}
              />
              I understand — replace the unreadable file with what I build here.
            </label>
          </div>
        )}

        {fileErrors.length > 0 && !unreadable && (
          <div className="mt-3 rounded-lg border border-sev-med/40 bg-panel2 p-2.5">
            <div className="text-kbd text-sev-med">
              The schedule currently on disk does not validate. It is shown as-is
              so you can fix it; saving will refuse it until these are resolved:
            </div>
            <ul className="mt-1 list-disc pl-5 text-kbd text-dim">
              {fileErrors.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          </div>
        )}
      </Panel>

      {drafts.length === 0 && !unreadable && (
        <StatusState
          variant="empty"
          title="No shifts configured"
          description="Nobody is on duty, so nothing is auto-assigned. Add a shift to staff the rota."
        />
      )}

      {drafts.map((draft, index) => (
        <ShiftCard
          key={draft.key}
          draft={draft}
          index={index}
          analysts={analysts}
          offsetMin={offsetMin}
          onChange={(patch) => update(draft.key, patch)}
          onRemove={() =>
            setDrafts((prev) => (prev ?? []).filter((d) => d.key !== draft.key))
          }
        />
      ))}

      <Panel className="p-4">
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            className={cn(BTN_NEUTRAL, focusRing)}
            onClick={() =>
              setDrafts((prev) => [
                ...(prev ?? []),
                {
                  key: newKey(),
                  name: "",
                  localStart: "",
                  localEnd: "",
                  allDay: false,
                  days: [],
                  analysts: [],
                  onCallPrimary: "",
                },
              ])
            }
          >
            Add shift
          </button>
          <button
            type="button"
            onClick={save}
            disabled={saveBlocked}
            title={saveBlockedNote}
            className={cn(
              BTN_PRIMARY,
              saveBlocked ? "cursor-not-allowed opacity-50" : "",
              focusRing,
            )}
          >
            {saving ? "Saving…" : "Save schedule"}
          </button>
          <button
            type="button"
            onClick={() => void load(offsetMin)}
            disabled={saving}
            className={cn(BTN_NEUTRAL, focusRing)}
          >
            Discard changes
          </button>
          {saved && (
            <span className="text-kbd text-grounded-ink" role="status">
              ✓ {saved}
            </span>
          )}
          {error && (
            <span className="text-kbd text-sev-crit" role="alert">
              {error}
            </span>
          )}
        </div>

        {reasons.length > 0 && (
          <div className="mt-3 rounded-lg border border-sev-crit/40 bg-panel2 p-2.5" role="alert">
            <div className="text-kbd text-sev-crit">
              The server refused this schedule:
            </div>
            <ul className="mt-1 list-disc pl-5 text-kbd text-ink">
              {reasons.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          </div>
        )}

        <div className="mt-2 text-kbd text-dim2">
          The server is the gate: it refuses an analyst who is not an active
          user, an unstaffed shift, an on-call primary who is not on that shift,
          an analyst double-booked across overlapping shifts, and any day that
          does not tile 24 hours (gap or overlap). Writes are atomic and
          audit-logged; rate-limited to 5/min.
        </div>
      </Panel>
    </div>
  );
}

function ShiftCard({
  draft,
  index,
  analysts,
  offsetMin,
  onChange,
  onRemove,
}: {
  draft: DraftShift;
  index: number;
  analysts: AdminUser[];
  offsetMin: number;
  onChange: (patch: Partial<DraftShift>) => void;
  onRemove: () => void;
}) {
  const notes = localNotes(draft);
  const startUtc = parseUtcMinutes(draft.localStart);
  const endUtc = parseUtcMinutes(draft.localEnd);

  const toggleAnalyst = (username: string) => {
    const next = draft.analysts.includes(username)
      ? draft.analysts.filter((a) => a !== username)
      : [...draft.analysts, username];
    onChange({
      analysts: next,
      // The primary can only ever be one of THIS shift's analysts — dropping
      // someone must drop them as primary too, never leave a stale name.
      onCallPrimary: next.includes(draft.onCallPrimary) ? draft.onCallPrimary : "",
    });
  };

  const toggleDay = (day: string) => {
    onChange({
      days: draft.days.includes(day)
        ? draft.days.filter((d) => d !== day)
        : [...draft.days, day],
    });
  };

  return (
    <Panel className="p-4">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div className="text-title text-ink">
          {draft.name.trim() || `Shift ${index + 1}`}
        </div>
        <button type="button" onClick={onRemove} className={cn(BTN_DANGER, focusRing)}>
          Remove
        </button>
      </div>

      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        <div>
          <label className="text-kbd text-dim" htmlFor={`${draft.key}-name`}>
            Name
          </label>
          <input
            id={`${draft.key}-name`}
            type="text"
            value={draft.name}
            onChange={(e) => onChange({ name: e.target.value })}
            placeholder="e.g. Morning"
            className={cn(FIELD_CLS, focusRing)}
          />
        </div>
        <div>
          <label className="text-kbd text-dim" htmlFor={`${draft.key}-start`}>
            Starts (your time)
          </label>
          <input
            id={`${draft.key}-start`}
            type="time"
            value={draft.localStart}
            disabled={draft.allDay}
            onChange={(e) => onChange({ localStart: e.target.value })}
            className={cn(FIELD_CLS, draft.allDay ? "opacity-50" : "", focusRing)}
          />
          <div className="mt-1 font-mono text-kbd text-dim2">
            {draft.allDay
              ? "00:00 UTC"
              : startUtc === null
                ? "— UTC"
                : `${fmtHHMM(localToUtcMinutes(startUtc, offsetMin))} UTC`}
          </div>
        </div>
        <div>
          <label className="text-kbd text-dim" htmlFor={`${draft.key}-end`}>
            Ends (your time)
          </label>
          <input
            id={`${draft.key}-end`}
            type="time"
            value={draft.localEnd}
            disabled={draft.allDay}
            onChange={(e) => onChange({ localEnd: e.target.value })}
            className={cn(FIELD_CLS, draft.allDay ? "opacity-50" : "", focusRing)}
          />
          <div className="mt-1 font-mono text-kbd text-dim2">
            {draft.allDay
              ? "24:00 UTC"
              : endUtc === null
                ? "— UTC"
                : `${fmtHHMM(localToUtcMinutes(endUtc, offsetMin))} UTC`}
          </div>
        </div>
      </div>

      {/* A 24/7 shift cannot be typed into a time input (it maxes at 23:59,
          and 00:00 → 00:00 is a zero-length shift), yet a single always-on
          shift is the simplest valid rota there is. */}
      <label className="mt-2 flex items-center gap-2 text-kbd text-ink">
        <input
          type="checkbox"
          checked={draft.allDay}
          onChange={(e) =>
            onChange({
              allDay: e.target.checked,
              localStart: e.target.checked ? "" : draft.localStart,
              localEnd: e.target.checked ? "" : draft.localEnd,
            })
          }
          className={cn(focusRing)}
        />
        Runs the full 24 hours (00:00 → 24:00 UTC — the same everywhere, so no
        local conversion applies)
      </label>

      <div className="mt-3">
        <div className="text-kbd text-dim">Days</div>
        <div className="mt-1 flex flex-wrap gap-1.5">
          {WEEKDAYS.map((day) => {
            const on = draft.days.includes(day);
            return (
              <button
                key={day}
                type="button"
                aria-pressed={on}
                onClick={() => toggleDay(day)}
                className={cn(
                  "rounded-md border px-2 py-0.5 text-meta capitalize",
                  on
                    ? "border-cite-border bg-cite-bg text-cite-ink"
                    : "border-line bg-field text-ink hover:bg-hover",
                  focusRing,
                )}
              >
                {day.slice(0, 3)}
              </button>
            );
          })}
          <span className="ml-1 self-center text-kbd text-dim2">
            {draft.days.length === 0 ? "none selected = every day" : ""}
          </span>
        </div>
      </div>

      <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div>
          <div className="text-kbd text-dim">
            Analysts on this shift ({draft.analysts.length})
          </div>
          <div className="mt-1 flex flex-col gap-1 rounded-lg border border-line bg-field p-2">
            {analysts.length === 0 ? (
              <span className="text-kbd text-dim2">
                No eligible users — analyst role or above, and active.
              </span>
            ) : (
              analysts.map((u) => (
                <label
                  key={u.id ?? u.username}
                  className="flex items-center gap-2 text-data text-ink"
                >
                  <input
                    type="checkbox"
                    checked={draft.analysts.includes(String(u.username))}
                    onChange={() => toggleAnalyst(String(u.username))}
                    className={cn(focusRing)}
                  />
                  <span className="font-mono">{u.username}</span>
                  <Chip mono>{String(u.role)}</Chip>
                </label>
              ))
            )}
          </div>
          {draft.analysts.some(
            (a) => !analysts.some((u) => String(u.username) === a),
          ) && (
            <div className="mt-1 text-kbd text-sev-med">
              This shift names{" "}
              {draft.analysts
                .filter((a) => !analysts.some((u) => String(u.username) === a))
                .join(", ")}
              , who is not an active analyst-or-above user. The server refuses
              that — untick to remove.
            </div>
          )}
        </div>

        <div>
          <label className="text-kbd text-dim" htmlFor={`${draft.key}-primary`}>
            On-call primary
          </label>
          <select
            id={`${draft.key}-primary`}
            value={draft.onCallPrimary}
            onChange={(e) => onChange({ onCallPrimary: e.target.value })}
            className={cn(FIELD_CLS, focusRing)}
          >
            <option value="">— pick one —</option>
            {draft.analysts.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
          <div className="mt-1 text-kbd text-dim2">
            Only this shift&apos;s own analysts are offered — the server rejects
            anyone else.
          </div>
        </div>
      </div>

      {notes.length > 0 && (
        <ul className="mt-3 list-disc pl-5 text-kbd text-sev-med">
          {notes.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
