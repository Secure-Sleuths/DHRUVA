"""Deterministic MITRE ATT&CK technique-reference loader (AIS3).

Grounds triage-prompt technique explanations in a curated, checked-in
ATT&CK reference (``data/attack_technique_reference.json``) instead of the
model's parametric recall. Keyed by exact technique ID — NO embeddings, NO
vector store, NO network call, NO third-party dependency (stdlib + structlog
only). The ``mitre`` package is always-on (free/community), so this asset and
loader ship in every build profile and must never crash triage: a
missing/malformed asset degrades to an empty reference.

Public API:
  * ``get_technique_reference(technique_id)`` — exact-ID lookup, ``None`` for
    unknown.
  * ``format_technique_refs(technique_ids, ...)`` — build the bounded grounded
    block for exactly the techniques on one alert, in input order, deduped.
"""

from __future__ import annotations

import json
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)

_DATA_PATH = Path(__file__).parent / "data" / "attack_technique_reference.json"

# Token-budget bounds for the injected block. This text goes into EVERY triage
# prompt for matching alerts, so the block is capped regardless of how many
# techniques an alert carries. Defaults chosen so the worst case stays a few
# hundred tokens (see tests/test_technique_reference.py::test_token_budget_bounded).
DEFAULT_MAX_TECHNIQUES = 8

# Marker emitted for a requested ID that has no curated entry, so the model is
# steered AWAY from inventing details rather than silently dropping the ID.
_NO_REFERENCE_MARKER = "no grounded reference available — do not fabricate details for this technique"

_REQUIRED_FIELDS = ("name", "description", "detection", "mitigation")


def _load_reference() -> dict:
    """Load and validate the technique reference JSON once.

    Returns ``{technique_id: {name, description, detection, mitigation}}``.
    Any failure (missing file, malformed JSON, wrong shape) is logged and
    yields an empty map so triage degrades gracefully instead of crashing.
    """
    try:
        raw = json.loads(_DATA_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        logger.warning("attack_reference_missing", path=str(_DATA_PATH))
        return {}
    except (json.JSONDecodeError, OSError, ValueError) as e:
        logger.warning("attack_reference_load_failed",
                       path=str(_DATA_PATH), error=str(e))
        return {}

    techniques = raw.get("techniques") if isinstance(raw, dict) else None
    if not isinstance(techniques, dict):
        logger.warning("attack_reference_malformed", path=str(_DATA_PATH))
        return {}

    cleaned: dict = {}
    for tid, entry in techniques.items():
        if not isinstance(entry, dict):
            continue
        if not all(entry.get(f) for f in _REQUIRED_FIELDS):
            continue
        cleaned[_normalize_id(tid)] = {f: str(entry[f]) for f in _REQUIRED_FIELDS}

    logger.info("attack_reference_loaded",
                techniques=len(cleaned),
                attack_version=(raw.get("_meta") or {}).get("attack_version"))
    return cleaned


def _normalize_id(technique_id) -> str:
    """Normalize a technique ID for exact-match keying (upper, trimmed)."""
    return str(technique_id).strip().upper()


# Module-level cache — loaded once at import. Kept private; callers use the
# functions below so the cache detail can change without breaking them.
_REFERENCE: dict = _load_reference()


def get_technique_reference(technique_id: str) -> "dict | None":
    """Return the curated reference dict for ``technique_id`` or ``None``.

    Exact-ID lookup after case/whitespace normalization. Returns a copy so
    callers cannot mutate the module cache.
    """
    if not technique_id:
        return None
    entry = _REFERENCE.get(_normalize_id(technique_id))
    return dict(entry) if entry is not None else None


def _format_one(technique_id: str, entry: dict) -> str:
    """Render a single grounded reference entry as a compact markdown block."""
    return (
        f"### {technique_id} — {entry['name']}\n"
        f"- Description: {entry['description']}\n"
        f"- Detection: {entry['detection']}\n"
        f"- Mitigation: {entry['mitigation']}"
    )


def format_technique_refs(
    technique_ids: "list[str]",
    max_techniques: int = DEFAULT_MAX_TECHNIQUES,
    max_chars: "int | None" = None,
) -> str:
    """Build the grounded ATT&CK reference block for ONE alert's techniques.

    Only the given ``technique_ids`` are rendered — never the whole matrix —
    in input order, de-duplicated (first occurrence wins). Bounded so token
    cost stays fixed even if an alert carries many techniques:

      * at most ``max_techniques`` techniques are rendered; the rest are
        summarized in a trailing "(+N more … truncated)" note.
      * if ``max_chars`` is given, rendering stops once the block would exceed
        it (a truncation note is appended).

    IDs with no curated entry are NOT silently dropped — they are listed under
    an explicit "no grounded reference" marker so the model is steered away
    from fabricating details. Returns ``""`` when there is nothing to render
    (empty input, or all inputs were blank).
    """
    if not technique_ids:
        return ""

    # Preserve input order, dedupe on normalized ID, drop blanks.
    seen: set = set()
    ordered: list = []
    for tid in technique_ids:
        if not tid:
            continue
        norm = _normalize_id(tid)
        if not norm or norm in seen:
            continue
        seen.add(norm)
        ordered.append(norm)

    if not ordered:
        return ""

    resolved: list = []      # (id, entry) with a curated reference
    unresolved: list = []    # ids with no curated reference
    for norm in ordered:
        entry = _REFERENCE.get(norm)
        if entry is not None:
            resolved.append((norm, entry))
        else:
            unresolved.append(norm)

    if not resolved and not unresolved:
        return ""

    blocks: list = []
    rendered = 0
    char_budget_hit = False
    running = 0
    for norm, entry in resolved:
        if rendered >= max_techniques:
            break
        block = _format_one(norm, entry)
        if max_chars is not None and running + len(block) > max_chars and rendered > 0:
            char_budget_hit = True
            break
        blocks.append(block)
        running += len(block)
        rendered += 1

    omitted = len(resolved) - rendered
    if omitted > 0 or char_budget_hit:
        blocks.append(
            f"(+{omitted} more resolved technique(s) omitted to bound prompt size — "
            f"request their reference explicitly if needed.)"
            if omitted > 0 else
            "(additional resolved techniques omitted to bound prompt size.)"
        )

    if unresolved:
        joined = ", ".join(unresolved)
        blocks.append(f"### {joined} — {_NO_REFERENCE_MARKER}")

    return "\n\n".join(blocks)
