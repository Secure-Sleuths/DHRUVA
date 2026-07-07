/**
 * Knowledge-Base presentation helpers (WO-U9c) — parse the JSON-encoded TEXT
 * list columns (`tags`, `mitre_techniques`) defensively and label the doc type.
 *
 * Pure presentation of `GET /api/kb/{documents,search,stats}` — it derives
 * nothing and fabricates nothing (a missing/empty list → `[]`). READ-ONLY: no
 * create/edit/delete affordance (those are gated writes). A GET-backed search
 * box is the only interaction and it is a read.
 */

import type { KbDocument } from "./types";

/**
 * Parse a KB list column that may be a JSON-encoded string (`'["a"]'`), an
 * actual array, or null/empty → always a `string[]`. Never throws. (Mirrors
 * `incident.ts::parseJsonArray` for the KB row shape.)
 */
export function parseKbList(
  value: string | string[] | null | undefined,
): string[] {
  if (Array.isArray(value)) return value.map((v) => String(v));
  if (typeof value !== "string") return [];
  const trimmed = value.trim();
  if (!trimmed || trimmed === "[]") return [];
  try {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed)) return parsed.map((v) => String(v));
    return [String(parsed)];
  } catch {
    return [trimmed];
  }
}

/** Plain-language name for a KB `doc_type`. Unknown types fall back to a tidy form. */
export function docTypeLabel(t: string | null | undefined): string {
  switch ((t ?? "").toLowerCase()) {
    case "analyst_note":
      return "Analyst note";
    case "playbook":
      return "Playbook";
    case "runbook":
      return "Runbook";
    case "hunt_finding":
      return "Hunt finding";
    case "incident":
      return "Incident record";
    case "guidance":
      return "Guidance";
    case "ioc":
      return "IoC note";
    case "threat_intel":
      return "Threat intel";
    default:
      return t ? String(t).replace(/_/g, " ") : "Document";
  }
}

/** A short, safe content preview for a KB doc (single line, trimmed). */
export function kbPreview(doc: KbDocument, max = 180): string {
  const c = (doc.content ?? "").replace(/\s+/g, " ").trim();
  if (!c) return "";
  return c.length > max ? `${c.slice(0, max)}…` : c;
}
