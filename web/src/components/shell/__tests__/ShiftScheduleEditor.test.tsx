/**
 * WO-H79 — the Shift Schedule editor.
 *
 * Two client-side jobs are worth pinning down (the SERVER remains the gate for
 * every validation rule):
 *
 *   1. LOCAL → UTC conversion. India is UTC+5:30, so "8 am" is 02:30 UTC. The
 *      operator used to do that arithmetic in their head, three times, and a
 *      slip silently drifted the rota — `get_least_loaded_analyst()`
 *      auto-assigns incidents to whoever the schedule says is on duty.
 *   2. The analyst picker is backed by `GET /api/admin/users`, filtered to
 *      analyst-and-above ACTIVE accounts — there is no free-text name field,
 *      which is what removes the "shift staffed by somebody who does not
 *      exist" failure mode entirely.
 *
 * Also asserts the RBAC mirror: editing the rota is admin+, deliberately
 * stricter than READING a handover (senior_analyst+).
 */
import { describe, expect, it } from "vitest";
import { ApiError, scheduleBlock, scheduleRejectionReasons } from "@/lib/api";
import { adminActionGate } from "@/lib/rbac";
import type { AdminUser, Role } from "@/lib/types";
import {
  eligibleAnalysts,
  fmtHHMM,
  isAllDay,
  toDraft,
  localNotes,
  localToUtcMinutes,
  offsetLabel,
  parseUtcMinutes,
  toWire,
  utcToLocalMinutes,
} from "../tabs/ShiftScheduleEditor";

const IST = 330; // UTC+5:30

describe("parsing stored boundaries", () => {
  it("accepts the original whole-hour schema", () => {
    expect(parseUtcMinutes(14)).toBe(840);
    expect(parseUtcMinutes(0)).toBe(0);
    expect(parseUtcMinutes(24)).toBe(1440);
  });

  it('accepts "HH:MM" — the form a half-hour offset needs', () => {
    expect(parseUtcMinutes("02:30")).toBe(150);
    expect(parseUtcMinutes("18:30")).toBe(1110);
    expect(parseUtcMinutes("05:45")).toBe(345); // Nepal, UTC+5:45
    expect(parseUtcMinutes("7")).toBe(420);
  });

  it("returns null rather than inventing a time", () => {
    for (const bad of ["25:00", "12:60", "abc", "", "-1"]) {
      expect(parseUtcMinutes(bad)).toBeNull();
    }
  });
});

describe("local ↔ UTC", () => {
  it("converts a UTC+5:30 rota the way the server stores it", () => {
    // 08:00 / 16:00 / 00:00 IST → 02:30 / 10:30 / 18:30 UTC
    expect(fmtHHMM(localToUtcMinutes(8 * 60, IST))).toBe("02:30");
    expect(fmtHHMM(localToUtcMinutes(16 * 60, IST))).toBe("10:30");
    expect(fmtHHMM(localToUtcMinutes(0, IST))).toBe("18:30");
  });

  it("round-trips both ways across midnight", () => {
    for (const minute of [0, 1, 150, 719, 1110, 1439]) {
      expect(utcToLocalMinutes(localToUtcMinutes(minute, IST), IST)).toBe(minute);
    }
  });

  it("handles a negative offset (Newfoundland, -3:30)", () => {
    expect(fmtHHMM(localToUtcMinutes(8 * 60, -210))).toBe("11:30");
  });

  it("labels the offset for the operator", () => {
    expect(offsetLabel(IST)).toBe("UTC+05:30");
    expect(offsetLabel(-210)).toBe("UTC-03:30");
  });
});

describe("the wire shape", () => {
  const draft = {
    key: "k",
    name: " Morning ",
    localStart: "08:00",
    localEnd: "16:00",
    allDay: false,
    days: ["monday"],
    analysts: ["analyst-one"],
    onCallPrimary: "analyst-one",
  };

  it("sends UTC, never the operator's local time", () => {
    expect(toWire(draft, IST)).toEqual({
      name: "Morning",
      start_utc: "02:30",
      end_utc: "10:30",
      days: ["monday"],
      analysts: ["analyst-one"],
      on_call_primary: "analyst-one",
    });
  });

  /**
   * A single always-on shift is the simplest valid rota there is, and it was
   * unreachable from the UI: `<input type="time">` maxes at 23:59 and
   * 00:00 → 00:00 is a zero-length shift the server rightly refuses — so the
   * only way to get one was SSH, which is the problem this WO set out to
   * remove.
   */
  it("expresses a 24/7 shift as 0 → 24 UTC, not via the local offset", () => {
    const wire = toWire({ ...draft, allDay: true, localStart: "", localEnd: "" }, IST);
    expect(wire.start_utc).toBe(0);
    expect(wire.end_utc).toBe(24);
  });

  it("is timezone-independent for a 24/7 shift", () => {
    for (const offset of [0, IST, -210, 345]) {
      const wire = toWire({ ...draft, allDay: true }, offset);
      expect([wire.start_utc, wire.end_utc]).toEqual([0, 24]);
    }
  });

  it("round-trips a stored 24/7 shift back into the all-day control", () => {
    const stored = {
      name: "Round the clock",
      start_utc: 0,
      end_utc: 24,
      days: [],
      analysts: ["analyst-one"],
      on_call_primary: "analyst-one",
    };
    expect(isAllDay(stored)).toBe(true);
    expect(toDraft(stored, IST).allDay).toBe(true);
    expect(toWire(toDraft(stored, IST), IST)).toEqual(stored);
  });

  it("does not mistake an 8-hour shift for an all-day one", () => {
    expect(
      isAllDay({
        name: "Morning",
        start_utc: "02:30",
        end_utc: "10:30",
        days: [],
        analysts: [],
        on_call_primary: "",
      }),
    ).toBe(false);
  });
});

/**
 * The server's two structured refusals must reach the operator as sentences,
 * not as raw JSON. 409 `schedule_unreadable` is the one that matters most: the
 * file on disk could not be parsed, so what would be replaced is a rota of
 * UNKNOWN content — never "nothing".
 */
describe("unpacking the server's structured refusals", () => {
  const apiErr = (status: number, detail: unknown) =>
    new ApiError(status, JSON.stringify(detail));

  it("names an unreadable existing file", () => {
    const block = scheduleBlock(
      apiErr(409, {
        error: "schedule_unreadable",
        load_error: "mapping values are not allowed here",
        message: "The existing schedule could not be parsed …",
      }),
    );
    expect(block?.kind).toBe("unreadable");
    expect(block?.message).toContain("could not be parsed");
  });

  it("names a read-only guidance mount", () => {
    const block = scheduleBlock(
      apiErr(503, {
        error: "schedule_not_writable",
        message: "Cannot save the shift schedule: … mounts ./config/guidance read-only (':ro') …",
      }),
    );
    expect(block?.kind).toBe("not_writable");
    expect(block?.message).toContain(":ro");
  });

  it("leaves anything else to normal error handling", () => {
    expect(scheduleBlock(apiErr(500, { error: "boom" }))).toBeNull();
    expect(scheduleBlock(new Error("network"))).toBeNull();
    expect(scheduleBlock(apiErr(409, "plain string"))).toBeNull();
  });

  it("still unpacks a 422's per-rule reasons", () => {
    expect(
      scheduleRejectionReasons(
        apiErr(422, {
          error: "invalid_shift_schedule",
          reasons: ["Shift 'Morning': 'reader' is a read_only account"],
        }),
      ),
    ).toEqual(["Shift 'Morning': 'reader' is a read_only account"]);
  });
});

describe("the analyst picker is backed by platform_users", () => {
  const users: AdminUser[] = [
    { id: "1", username: "analyst-one", role: "analyst", is_active: 1 },
    { id: "2", username: "analyst-two", role: "senior_analyst", is_active: 1 },
    { id: "3", username: "boss", role: "admin", is_active: 1 },
    { id: "4", username: "watcher", role: "read_only", is_active: 1 },
    { id: "5", username: "departed", role: "analyst", is_active: 0 },
  ] as unknown as AdminUser[];

  it("offers analyst-and-above, active accounts only", () => {
    expect(eligibleAnalysts(users).map((u) => u.username)).toEqual([
      "analyst-one",
      "analyst-two",
      "boss",
    ]);
  });

  it("excludes a deactivated account — the server rejects it too", () => {
    expect(eligibleAnalysts(users).some((u) => u.username === "departed")).toBe(
      false,
    );
  });
});

describe("inline notes (convenience only — the server is the gate)", () => {
  const base = {
    key: "k",
    name: "Morning",
    localStart: "08:00",
    localEnd: "16:00",
    allDay: false,
    days: [],
    analysts: ["analyst-one"],
    onCallPrimary: "analyst-one",
  };

  it("is silent on a well-formed shift", () => {
    expect(localNotes(base)).toEqual([]);
  });

  it("flags an unstaffed shift", () => {
    expect(localNotes({ ...base, analysts: [], onCallPrimary: "" }).join(" ")).toContain(
      "Nobody is assigned",
    );
  });

  it("flags an on-call primary who is not on the shift", () => {
    expect(localNotes({ ...base, onCallPrimary: "analyst-two" }).join(" ")).toContain(
      "on-call primary",
    );
  });

  it("flags a missing time", () => {
    expect(localNotes({ ...base, localStart: "" }).join(" ")).toContain(
      "Start time is not set",
    );
  });
});

describe("RBAC mirror — editing the rota is admin+", () => {
  const gateFor = (role: Role) => adminActionGate(role, "shift_schedule");

  it("admin and mssp_admin may edit", () => {
    expect(gateFor("admin").canSubmit).toBe(true);
    expect(gateFor("mssp_admin").canSubmit).toBe(true);
  });

  it("senior_analyst may NOT edit, though it may read a handover", () => {
    expect(gateFor("senior_analyst").visible).toBe(false);
    expect(adminActionGate("senior_analyst", "handoff").visible).toBe(true);
  });

  it("analyst and read_only may do neither", () => {
    for (const role of ["analyst", "read_only"] as Role[]) {
      expect(gateFor(role).visible).toBe(false);
      expect(adminActionGate(role, "handoff").visible).toBe(false);
    }
  });
});
