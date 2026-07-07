/**
 * Small display formatters shared by the WO-U9 read-view tabs (Detection,
 * Threat Intel, Host Integrity, Metrics, Admin). Pure presentation — never a
 * source of truth, never fabricates a value (renders an em-dash for missing data).
 */

/** The em-dash placeholder used everywhere a value is genuinely absent. */
export const DASH = "—";

/** Format an ISO-ish timestamp as a compact "Jul 2, 04:12" (UTC). Null → dash. */
export function fmtDateTime(v: string | null | undefined): string {
  if (!v) return DASH;
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return String(v);
  return d.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    timeZone: "UTC",
  });
}

/** Format a date only, "Jul 2 2026" (UTC). Null → dash. */
export function fmtDate(v: string | null | undefined): string {
  if (!v) return DASH;
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return String(v);
  return d.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    timeZone: "UTC",
  });
}

/** Coerce a Postgres int-0/1-or-bool flag to a boolean. */
export function asBool(v: number | boolean | null | undefined): boolean {
  return v === true || v === 1;
}

/** Integer with thousands separators. Null → dash. */
export function fmtInt(v: number | null | undefined): string {
  if (v == null || Number.isNaN(v)) return DASH;
  return Math.round(v).toLocaleString("en-US");
}

/** One-decimal number. Null → dash. */
export function fmtNum(v: number | null | undefined, digits = 1): string {
  if (v == null || Number.isNaN(v)) return DASH;
  return v.toFixed(digits);
}

/** A 0..1 fraction or a 0..100 value rendered as "N%". Null → dash. */
export function fmtPct(v: number | null | undefined, opts: { fraction?: boolean } = {}): string {
  if (v == null || Number.isNaN(v)) return DASH;
  const pct = opts.fraction ? v * 100 : v;
  return `${Math.round(pct * 10) / 10}%`;
}

/**
 * Human-friendly minutes → "4.2m" / "1h 36m" / "2d 5h". Used for MTT figures.
 * Null → dash.
 */
export function fmtMinutes(v: number | null | undefined): string {
  if (v == null || Number.isNaN(v)) return DASH;
  if (v < 60) return `${Math.round(v * 10) / 10}m`;
  const totalMin = Math.round(v);
  const days = Math.floor(totalMin / 1440);
  const hours = Math.floor((totalMin % 1440) / 60);
  const mins = totalMin % 60;
  if (days > 0) return `${days}d ${hours}h`;
  return `${hours}h ${mins}m`;
}

/** Bytes → "40.4 MB" style. Accepts numeric or numeric-string. Null → dash. */
export function fmtBytes(v: number | string | null | undefined): string {
  if (v == null) return DASH;
  const n = typeof v === "string" ? Number(v) : v;
  if (Number.isNaN(n)) return String(v);
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = n / 1024;
  let i = 0;
  while (size >= 1024 && i < units.length - 1) {
    size /= 1024;
    i++;
  }
  return `${Math.round(size * 10) / 10} ${units[i]}`;
}
