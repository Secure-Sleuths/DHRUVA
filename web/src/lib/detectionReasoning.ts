/**
 * WO-H49: render the Detection agent's `reasoning` readably.
 *
 * It is usually a JSON envelope rather than prose — keys like
 * `tp_coverage_risk`, `changes_made`, `expected_fp_reduction`, `alternatives`.
 * Shown raw it is an unreadable wall of braces and escapes in the middle of a
 * deploy confirm, which is the worst possible place to make an operator squint
 * at a rule change they are about to push to a live Wazuh manager.
 *
 * Parses it when it IS JSON and lays it out as "Key: value" lines; falls back
 * to the original string untouched when it is plain prose or unparseable.
 * NEVER throws — a formatting helper must not be able to break a
 * safety-critical dialog.
 */
export function formatReasoning(raw: string | null | undefined): string {
  if (!raw) return "";
  const text = String(raw).trim();
  if (!text.startsWith("{") && !text.startsWith("[")) return text;
  try {
    const parsed = JSON.parse(text);
    if (parsed === null || typeof parsed !== "object") return text;
    if (Array.isArray(parsed)) {
      return parsed.map((item) => `• ${String(item)}`).join("\n");
    }
    return Object.entries(parsed as Record<string, unknown>)
      .map(([k, v]) => {
        const label = k.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());
        if (Array.isArray(v)) {
          const body = v.map((item) => `  • ${String(item)}`).join("\n");
          return `${label}:\n${body}`;
        }
        const body =
          typeof v === "object" && v !== null
            ? JSON.stringify(v, null, 2)
            : String(v);
        return `${label}:\n  ${body}`;
      })
      .join("\n\n");
  } catch {
    return text;
  }
}
