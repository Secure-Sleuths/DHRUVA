"""AIS2 — AI output faithfulness / grounding checks (deterministic-first).

DHRUVA's AI outputs (the triage verdict and the NL-query answer) otherwise
carry only the model's OWN self-reported ``confidence``. Confidence is
self-reported and unverified: a confident-but-wrong verdict, or a fabricated
query finding, misleads a non-technical analyst reading the plain-language
output.

This module adds an INDEPENDENT, EVIDENCE-DERIVED grounding signal that checks
each output's claims against the evidence that was actually available, so that
low-grounding output is never rendered as "confident" and an observability
metric can be emitted.

Design constraints (see AIS2 work order):
  * Deterministic-first — no LLM-judge / second model call here (deferred).
  * No third-party dependency (LangKit is the deferred richer option); this is
    a lightweight in-house pass built from ``re`` + ``structlog`` only.
  * Community-safe: this module imports NO paid module. ``triage_agent`` (a
    free/community module) imports it, so it must stay paid-import-clean.
  * It FLAGS output for human attention; it never auto-closes or auto-escalates
    and never mutates the evidence.

Three pure entry points:
  * :func:`assess_query_grounding`  — per-claim citation verification for NL answers.
  * :func:`assess_triage_grounding` — verdict-vs-enrichment faithfulness tripwire.
  * :func:`output_safety_metrics`   — cheap PII-token-leak / injection-echo scan.
"""

from __future__ import annotations

import re

import structlog

logger = structlog.get_logger(__name__)


# ── Query-answer grounding ────────────────────────────────────────────────

def assess_query_grounding(findings, sources, per_claim_map=None) -> dict:
    """Deterministically verify a NL answer's per-claim citations.

    For each finding (claim) we check whether it cites at least one source ``id``
    that (a) EXISTS in ``sources`` and (b) actually returned data (``count > 0``).
    A claim that has no citation, only invalid citations (id not present in
    ``sources``), or only empty/errored citations (zero-hit sources) is treated
    as ``low_grounding`` — the evidence does not support it.

    ``findings`` accepts both shapes for backward compatibility:
      * new: ``{"claim": "...", "source_ids": ["q1", "kb1"]}``
      * old: a plain ``str`` (no citation) — parsed, never crashes, counted as
        uncited/ungrounded rather than raising.
    ``per_claim_map`` is an optional parallel ``{finding_index: [ids]}`` map used
    to supplement a finding that carries no inline ``source_ids``.

    Bands (explicit):
      * ``high``         — every claim is grounded.
      * ``medium``       — some claims grounded, but ungrounded are not the majority.
      * ``low``          — no claims grounded, OR ungrounded claims are the majority.
      * ``not_assessed`` — there were NO findings to check. This is deliberately a
        distinct neutral band (NOT ``high``): an answer that states conclusions
        only in its prose and returns ``findings=[]`` has not been shown to be
        grounded, so it must not be surfaced as fully grounded / confident.

    Returns ``{grounding, grounded_claims, ungrounded_claims, ungrounded, score}``
    where ``score`` is ``None`` for the ``not_assessed`` band (no ratio exists).
    """
    # Build a lookup of source id -> hit count. Sources without a usable id are
    # ignored; a source is "supporting" only when it actually returned data.
    source_counts: dict[str, int] = {}
    for s in sources or []:
        if not isinstance(s, dict):
            continue
        sid = s.get("id")
        if sid is None:
            continue
        try:
            source_counts[str(sid)] = int(s.get("count", 0) or 0)
        except (TypeError, ValueError):
            source_counts[str(sid)] = 0

    per_claim_map = per_claim_map or {}

    grounded = 0
    ungrounded: list[str] = []

    for idx, finding in enumerate(findings or []):
        claim_text, ids = _normalize_finding(finding)

        # Supplement inline ids with the parallel map (by index) when the
        # finding carried none of its own.
        if not ids:
            mapped = per_claim_map.get(idx)
            if mapped is None:
                mapped = per_claim_map.get(str(idx))
            if mapped:
                ids = [str(i) for i in mapped]

        # A citation supports the claim only if the id exists AND that source
        # returned data (count > 0). Invalid ids and zero-hit/errored sources
        # do not support anything.
        supporting = [i for i in ids
                      if i in source_counts and source_counts[i] > 0]

        if supporting:
            grounded += 1
        else:
            ungrounded.append(claim_text)

    total = grounded + len(ungrounded)
    ungrounded_count = len(ungrounded)

    if total == 0:
        # No findings to verify — grounding could not be established. Neutral
        # band, NOT high; score is undefined (None) rather than a misleading ratio.
        return {
            "grounding": "not_assessed",
            "grounded_claims": 0,
            "ungrounded_claims": 0,
            "ungrounded": [],
            "score": None,
        }

    score = grounded / total
    if ungrounded_count == 0:
        grounding = "high"
    elif grounded == 0 or ungrounded_count > grounded:
        grounding = "low"
    else:
        grounding = "medium"

    return {
        "grounding": grounding,
        "grounded_claims": grounded,
        "ungrounded_claims": ungrounded_count,
        "ungrounded": ungrounded,
        "score": round(score, 4),
    }


def _normalize_finding(finding):
    """Return ``(claim_text, [source_ids])`` for a finding of either shape.

    Never raises: a plain-string finding yields no ids; an unexpected type is
    coerced to its ``str()`` with no ids.
    """
    if isinstance(finding, str):
        return finding, []
    if isinstance(finding, dict):
        claim = (finding.get("claim")
                 or finding.get("finding")
                 or finding.get("text")
                 or "")
        raw_ids = finding.get("source_ids") or finding.get("sources") or []
        if isinstance(raw_ids, (str, int)):
            raw_ids = [raw_ids]
        ids = [str(i) for i in raw_ids] if isinstance(raw_ids, (list, tuple)) else []
        return (str(claim) if claim else str(finding)), ids
    return str(finding), []


# ── Triage-verdict grounding ──────────────────────────────────────────────

# A risk_score at/above this floor counts as supporting a high-severity verdict.
_HIGH_RISK_FLOOR = 70.0

# Every enrichment signal a triage verdict may legitimately name in
# ``evidence_refs``. Each entry maps a signal name to a predicate answering
# "is this signal PRESENT and non-empty in the enrichment?". Used to detect
# FABRICATED evidence_refs (a cited name that isn't present is fabricated).
# This is the broad set — it includes contextual signals like asset_tier and
# historical_fp_rate that are valid to cite even though they don't, on their
# own, evidence maliciousness.
_KNOWN_SIGNALS = {
    "threat_intel_hits": lambda e: _as_number(e.get("threat_intel_hits")) > 0,
    "is_known_malicious": lambda e: bool(e.get("is_known_malicious")),
    "baseline_anomaly": lambda e: bool(e.get("baseline_anomaly")),
    "baseline_anomaly_details": lambda e: bool(e.get("baseline_anomaly_details")),
    "escalation_trigger": lambda e: bool(e.get("escalation_trigger")
                                         or e.get("escalation_triggered")
                                         or e.get("always_escalate")),
    "risk_score": lambda e: _as_number(e.get("risk_score")) >= _HIGH_RISK_FLOOR,
    "user_risk_level": lambda e: str(e.get("user_risk_level", "")).lower()
    in ("high", "elevated", "critical"),
    "historical_fp_rate": lambda e: _as_number(e.get("historical_fp_rate")) > 0,
    "asset_tier": lambda e: str(e.get("asset_tier", "")).lower()
    not in ("", "unknown", "none"),
}

# The NARROWER subset whose presence actually SUPPORTS a high-severity /
# true_positive verdict. asset_tier (impact, not maliciousness) and
# historical_fp_rate (argues the other way) are deliberately excluded: a
# true_positive resting on nothing but these is still "severity not supported
# by evidence".
_SEVERITY_SUPPORT = (
    "threat_intel_hits", "is_known_malicious", "baseline_anomaly",
    "baseline_anomaly_details", "escalation_trigger", "risk_score",
    "user_risk_level",
)

# Verdicts that DISMISS an alert (close it as benign / auto-close it).
_DISMISSAL_VERDICTS = frozenset({"false_positive", "auto_close"})

# The STRONG maliciousness signals whose presence should stop an alert from
# being dismissed. A benign verdict laid over any of these — a TI hit, a
# known-malicious IOC, a high risk_score, or an explicit escalation trigger —
# is a hallucinated dismissal (the model waved away hard evidence). Narrower
# than _SEVERITY_SUPPORT on purpose: baseline anomaly / elevated user risk are
# softer context that a human may legitimately dismiss, so they don't trip this.
_DISMISSAL_CONTRADICTING = (
    "threat_intel_hits", "is_known_malicious", "risk_score", "escalation_trigger",
)


def _as_number(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _signal_present(enrichment: dict, name: str) -> bool:
    """True when ``name`` is a known enrichment signal that is present + non-empty.

    A name we don't recognise, or a recognised signal that is absent/empty, is
    NOT present — a verdict citing it is treated as fabricated.
    """
    predicate = _KNOWN_SIGNALS.get(name)
    if predicate is None:
        # Unknown/aliased name: accept only if the key exists with a non-empty,
        # truthy value; otherwise it's fabricated.
        if name not in enrichment:
            return False
        return _nonempty(enrichment.get(name))
    try:
        return bool(predicate(enrichment or {}))
    except Exception:  # pragma: no cover - predicate must never break grounding
        return False


def _nonempty(value) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() not in ("", "unknown", "none")
    if isinstance(value, (list, dict, tuple, set)):
        return len(value) > 0
    return bool(value)


def assess_triage_grounding(verdict: str, confidence: float,
                            evidence_refs, enrichment: dict) -> dict:
    """Deterministic faithfulness tripwire for a triage verdict.

    This is a HEURISTIC tripwire, not a scoring model. Three explicit checks:

    (i) Fabricated-citation check — if the model supplied ``evidence_refs``
        (names of enrichment signals it relied on), each ref must name a signal
        that is actually PRESENT and non-empty in ``enrichment``. A cited signal
        that does not exist / is empty is fabricated and lowers grounding.

    (ii) Severity-vs-evidence check — a ``true_positive`` verdict that has NO
         supporting signal at all (no TI hit, no known-malicious IOC, risk_score
         below the high floor, no escalation trigger, no baseline anomaly, no
         elevated user risk) is flagged "severity not supported by evidence".
         This check does not depend on the model's cooperation.

    (iii) Dismissal-vs-evidence check (WO-H8) — the mirror image of (ii): a
          ``false_positive`` / ``auto_close`` verdict that DISMISSES an alert
          which still carries a STRONG maliciousness signal (a TI hit, a
          known-malicious IOC, a high risk_score, or an explicit escalation
          trigger) is flagged "dismissal contradicts strong signal". A confident
          auto-dismissal of hard evidence is exactly the hallucination a
          non-technical analyst is least equipped to catch. Cooperation-free.

    Bands:
      * ``low``    — severity unsupported, OR dismissal contradicts strong
                     signal, OR every supplied ref is fabricated.
      * ``medium`` — some (but not all) supplied refs are fabricated.
      * ``high``   — no tripwire fired.

    Returns ``{grounding, score, unsupported, reasons}`` where ``unsupported`` is
    the list of fabricated evidence_refs and ``reasons`` explains each flag.
    """
    enrichment = enrichment or {}
    refs = [str(r) for r in (evidence_refs or [])]

    reasons: list[str] = []

    # (i) fabricated evidence_refs
    fabricated = [r for r in refs if not _signal_present(enrichment, r)]
    if fabricated:
        reasons.append(
            "cited evidence signal(s) absent/empty in enrichment: "
            + ", ".join(fabricated))

    # (ii) severity not supported by any evidence (true_positive only) —
    # evaluated against the NARROW severity-support subset.
    has_support = any(_KNOWN_SIGNALS[name](enrichment)
                      for name in _SEVERITY_SUPPORT)
    severity_unsupported = (verdict == "true_positive" and not has_support)
    if severity_unsupported:
        reasons.append(
            "verdict 'true_positive' has no supporting enrichment evidence "
            "(no TI hit, low risk_score, no escalation trigger, no anomaly)")

    # (iii) dismissal contradicts strong signal (false_positive / auto_close) —
    # the model closed an alert that still carries hard maliciousness evidence.
    contradicting = [name for name in _DISMISSAL_CONTRADICTING
                     if _KNOWN_SIGNALS[name](enrichment)]
    dismissal_unsupported = (verdict in _DISMISSAL_VERDICTS
                             and bool(contradicting))
    if dismissal_unsupported:
        reasons.append(
            f"verdict '{verdict}' dismisses an alert carrying strong signal(s) "
            + ", ".join(contradicting)
            + " with no support")

    # Score: fraction of supplied refs that are real, floored hard by either
    # cooperation-free tripwire (severity or dismissal).
    if refs:
        score = (len(refs) - len(fabricated)) / len(refs)
    else:
        score = 1.0
    if severity_unsupported or dismissal_unsupported:
        score = min(score, 0.2)

    if severity_unsupported or dismissal_unsupported:
        grounding = "low"
    elif refs and len(fabricated) == len(refs):
        grounding = "low"
    elif fabricated:
        grounding = "medium"
    else:
        grounding = "high"

    return {
        "grounding": grounding,
        "score": round(score, 4),
        "unsupported": fabricated,
        "reasons": reasons,
    }


# ── Output-safety observability metrics ───────────────────────────────────

# Anon-token families produced by AlertAnonymizer._tokenize (prefix-<12 hex>).
# INT-IP contains an internal hyphen, so it's listed explicitly. This is a
# cheap residual-leak tripwire; the anonymizer's deanonymize step should have
# already resolved every token before analyst-facing text is rendered.
_ANON_TOKEN_RE = re.compile(
    r"\b(?:INT-IP|API-KEY|HOST|USER|OWNER|EMAIL|PHONE|NID|SYSTEM|CRED)"
    r"-[0-9a-f]{12}\b")

# Cheap injection-echo tripwire: phrases that, if they appear in analyst-facing
# output, suggest the model echoed an injection directive from untrusted data.
_INJECTION_ECHO_RE = re.compile(
    r"(?:ignore (?:all |the )?(?:previous|above|prior) (?:instructions|prompts?)"
    r"|disregard (?:all |the )?(?:previous|above|prior) (?:instructions|prompts?)"
    r"|you are now (?:a|an|in)"
    r"|new instructions\s*:"
    r"|system prompt\s*:)",
    re.IGNORECASE)

# Trust-envelope breakout tripwire: a premature ``</untrusted_data>`` closing
# marker in analyst-facing output means the model echoed the trust envelope's
# closing tag — the tell-tale of a prompt-injection breakout attempt in the
# alert data (an attacker planting ``</untrusted_data>`` in an alert field to
# close the envelope early and inject instructions). Whitespace-tolerant so
# ``</ untrusted_data >`` variants are also caught (WO-H3).
_BREAKOUT_MARKER_RE = re.compile(r"<\s*/\s*untrusted_data\s*>", re.IGNORECASE)


def output_safety_metrics(text: str, anonymizer=None) -> dict:
    """Lightweight in-house safety scan of FINAL analyst-facing output text.

    Checks, cheaply and without raising:
      (a) did an anonymization TOKEN leak through un-deanonymized (a residual
          ``EMAIL-<hex>`` / ``HOST-<hex>`` / ``INT-IP-<hex>`` etc.)?  When an
          ``anonymizer`` is supplied, its live token table is also consulted for
          an exact-match check on top of the regex family scan.
      (b) does the output appear to echo an injection directive from untrusted
          data (an "ignore previous instructions"-class phrase)?
      (c) did the output emit a premature ``</untrusted_data>`` breakout marker,
          the signature of a trust-envelope escape attempt from the alert data?

    Returns counts only (``{token_leaks, injection_echoes, breakout_markers,
    leaked_tokens, flagged}``); LangKit is the deferred richer option for this
    surface.
    """
    if not isinstance(text, str) or not text:
        return {"token_leaks": 0, "injection_echoes": 0,
                "breakout_markers": 0, "leaked_tokens": [], "flagged": False}

    leaked = set(_ANON_TOKEN_RE.findall(text))

    # Exact-match against the anonymizer's live token map, if available — catches
    # any token family the regex above doesn't enumerate. ``_to_original`` maps
    # token -> original, so its KEYS are the opaque tokens we scan for.
    live_map = getattr(anonymizer, "_to_original", None)
    if isinstance(live_map, dict):
        for tok in live_map.keys():
            if isinstance(tok, str) and tok and tok in text:
                leaked.add(tok)

    injection_echoes = len(_INJECTION_ECHO_RE.findall(text))
    breakout_markers = len(_BREAKOUT_MARKER_RE.findall(text))

    return {
        "token_leaks": len(leaked),
        "injection_echoes": injection_echoes,
        "breakout_markers": breakout_markers,
        "leaked_tokens": sorted(leaked),
        "flagged": bool(leaked) or injection_echoes > 0 or breakout_markers > 0,
    }
