"""Deterministic verdict guard — a hard floor under the LLM's triage verdict.

WHY THIS EXISTS
---------------
The triage system prompt wraps attacker-controlled alert fields in
``<untrusted_data>`` and instructs the model never to obey instructions found
inside them. The MECHANICAL half of that boundary is enforced in code
(:func:`src.agents.prompts.escape_for_prompt` escapes every angle bracket, so a
``</untrusted_data>`` breakout tag cannot close the envelope early). The
INSTRUCTIONAL half — "do not comply with injected directives" — depends entirely
on the model honouring it.

Local/small models do not reliably honour it. Measured on dhruva-granite
(IBM Granite 4.0 Micro, 3.4B, Q4_K_M), an injection planted in ``full_log`` and
``agent_name`` flipped the verdict to ``false_positive`` @ 0.99 confidence with
``escalation_required: false`` in 5 of 5 trials — on an alert carrying 2 threat-
intel hits, ``is_known_malicious: true``, a ``tier_1_critical`` asset and
``risk_score: 78``. With an auto-close threshold below 0.99 that alert closes
itself. The attacker silences their own alert.

This module removes the model from that decision. It reads ONLY the structured
enrichment produced by the enrichment pipeline — never the LLM's output, never
free text — and refuses to let a dismissal verdict stand on top of hard
evidence. It cannot be argued out of by anything a threat actor can write into
an alert field, because injected text does not reach it.

RELATIONSHIP TO ``grounding.assess_triage_grounding``
-----------------------------------------------------
Grounding is a *tripwire*: it FLAGS a confident-but-unsupported verdict for
analyst attention and deliberately never changes the outcome. This guard is a
*control*: it CHANGES the outcome. They are complementary and independent —
grounding still scores the model's original verdict, which is what you want for
measuring model quality over time.

SCOPE
-----
Reads enrichment; returns a decision record. No DB, no LLM, no I/O, no config —
so it is trivially testable and cannot fail open on a network or DB error. Risk
scoring, enrichment and incident learning are untouched.
"""

import structlog

logger = structlog.get_logger(__name__)

# The asset tier that, on its own, forbids an automated dismissal. Matches the
# tier name used by config/guidance/risk_criteria.yaml.
TIER_1 = "tier_1_critical"

# Verdicts that DISMISS an alert. Both are guarded, not just false_positive:
# they are the same risk class (an alert leaving the queue without a human), and
# grounding.py already treats them as one set (``_DISMISSAL_VERDICTS``). Guarding
# only false_positive would leave an equivalent auto_close path open, so a future
# injection would simply target the other word.
GUARDED_DISMISSALS = frozenset({"false_positive", "auto_close"})

# What a blocked dismissal becomes. needs_investigation is the codebase's
# existing "a human must look at this" verdict — the same one the fail-closed
# LLM-error path uses — so downstream queue/incident behaviour is unchanged.
FORCED_VERDICT = "needs_investigation"

# String forms that must read as False. Plain bool() gets this catastrophically
# wrong: bool("false") is True, which would make the guard trip on every alert
# whose is_known_malicious arrived as the string "false" (JSON round-trips
# through OpenSearch and the ticketing layer can produce exactly that).
_FALSEY_STRINGS = frozenset({
    "", "false", "0", "no", "none", "null", "n", "f", "unknown",
})


def _as_number(value) -> float:
    """Coerce to float; anything uncoercible is 0.0 (i.e. "no hits")."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _as_bool(value) -> bool:
    """Coerce to bool, treating falsey STRINGS as False (see _FALSEY_STRINGS)."""
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() not in _FALSEY_STRINGS
    if isinstance(value, (list, dict, tuple, set)):
        return len(value) > 0
    return bool(value)


def _tier_of(enrichment: dict) -> str:
    return str(enrichment.get("asset_tier", "") or "").strip().lower()


# Enrichers that PRODUCE the evidence this guard reads. If one of them failed,
# its keys are simply absent from the enrichment dict — and an absent key is
# indistinguishable from a genuine negative ("0 hits", "not tier 1"). That would
# turn the guard off silently during a TI or asset-lookup outage, on exactly the
# alerts it exists to protect. src/enrichment/service.py records the failure in
# ``degraded_enrichers`` so the guard can tell "no" from "don't know".
EVIDENCE_ENRICHERS = frozenset({"asset", "threat_intel"})

DEGRADED_TRIGGER = "enrichment_degraded"


def blocking_evidence(enrichment) -> list:
    """Return the hard-evidence conditions that forbid an automated dismissal.

    THE single definition of that policy. It is deliberately shared, because the
    LLM path is not the only way an alert can be dismissed: ``NoisePreFilter``
    and the dedup/decision-cache reuse path both dismiss WITHOUT calling a
    model, and so never reach :func:`evaluate_verdict_guard`. Those gates import
    this function, so all three paths enforce one policy and cannot drift apart
    again — which is precisely how ``tier_1_critical`` came to be enforced on
    only one of the three.

    Covers POSITIVE evidence only — a signal that is actually present. "We could
    not look" is a different condition with different consequences and lives in
    :func:`evidence_unavailable`; callers decide which of the two applies to
    them. Keeping them separate matters: treating an enrichment outage as though
    every alert carried a threat signal disables the duplicate-collapsing cost
    controls fleet-wide at the exact moment the platform is already degraded.

    Returns a list of trigger names, in a fixed order. Empty means "nothing here
    forbids a dismissal". Never raises.
    """
    if not isinstance(enrichment, dict):
        return []

    triggers = []
    if _as_number(enrichment.get("threat_intel_hits")) > 0:
        triggers.append("threat_intel_hits")
    if _as_bool(enrichment.get("is_known_malicious")):
        triggers.append("is_known_malicious")
    if _tier_of(enrichment) == TIER_1:
        triggers.append("tier_1_critical_asset")

    return triggers


def evidence_unavailable(enrichment) -> list:
    """Return a degradation trigger when the evidence this guard reads is UNKNOWN.

    Unknown evidence is not benign evidence. When an enricher that feeds a trip
    condition fails, its keys are absent or zero-valued, and an absent key is
    indistinguishable from a genuine negative ("0 hits", "not tier 1") — so the
    guard silently switches off during exactly the outage it exists to cover.

    Detected two ways, because enrichers fail in two different shapes:

    * ``degraded_enrichers`` — an enricher RAISED out of ``enrich_alert``.
    * ``<name>_lookup_ok: False`` — an enricher completed but could not actually
      look anything up. These raise nothing: ``AssetEnricher.enrich`` is pure
      dict lookups with effectively no raise path, so a fix that only watched
      the exception boundary would have been close to dead code.

    KNOWN GAP — live threat-intel feeds are NOT covered. ``threat_intel_lookup_ok``
    reflects the LOCAL IOC-store lookup only. The live feed clients swallow their
    own errors and return ``None``, and ``_RateLimiter.allow()`` skips a lookup
    silently under burst — both indistinguishable from "clean indicator" at this
    layer. So an outage of the live feeds alone will NOT trip this guard. Closing
    it means having ``_try_live_lookups`` report why it returned nothing, which
    is a change to the feed layer rather than to this module. Do not read this
    function as covering a TI feed outage; it does not.

    SEPARATE from :func:`blocking_evidence` on purpose — see the note there.
    Never raises.
    """
    if not isinstance(enrichment, dict):
        return []

    degraded = enrichment.get("degraded_enrichers")
    if isinstance(degraded, str):
        # A bare string is iterable but would compare character-by-character and
        # silently match nothing. Fail CLOSED on the malformed shape rather than
        # reading it as "nothing degraded".
        degraded = [degraded]
    if isinstance(degraded, (list, tuple, set)):
        if EVIDENCE_ENRICHERS & {str(d) for d in degraded}:
            return [DEGRADED_TRIGGER]

    for name in EVIDENCE_ENRICHERS:
        flag = enrichment.get("%s_lookup_ok" % name)
        if flag is not None and not _as_bool(flag):
            return [DEGRADED_TRIGGER]

    return []


def degraded_evidence_sources(enrichment) -> list:
    """Names of the evidence enrichers reporting degradation (for logs/metrics)."""
    if not isinstance(enrichment, dict):
        return []
    names = set()
    degraded = enrichment.get("degraded_enrichers")
    if isinstance(degraded, str):
        degraded = [degraded]
    if isinstance(degraded, (list, tuple, set)):
        names |= EVIDENCE_ENRICHERS & {str(d) for d in degraded}
    for name in EVIDENCE_ENRICHERS:
        flag = enrichment.get("%s_lookup_ok" % name)
        if flag is not None and not _as_bool(flag):
            names.add(name)
    return sorted(names)


def evaluate_verdict_guard(verdict, enrichment: dict) -> dict:
    """Decide whether ``verdict`` may stand, based only on hard enrichment.

    Trips when the verdict is a dismissal AND at least one of:

    * ``threat_intel_hits > 0``       — a feed matched an indicator on this alert
    * ``is_known_malicious`` is true  — an indicator is confirmed malicious
    * ``asset_tier == tier_1_critical`` — production DB / auth / payments / secrets
    * an evidence-producing enricher DEGRADED — the guard cannot see whether any
      of the above hold, so it must not allow the dismissal (see
      :data:`EVIDENCE_ENRICHERS`)

    Returns a record with a stable shape (always the same keys, whether or not
    it tripped) so callers can persist it unconditionally::

        {
          "triggered": bool,          # did the guard change the outcome?
          "original_verdict": str,    # exactly what the LLM said
          "verdict": str,             # what must be used instead (or unchanged)
          "force_escalate": bool,
          "triggers": [str, ...],     # which conditions fired, in a fixed order
          "evidence": {...},          # the enrichment values the decision used
          "reason": str,              # human-readable, safe for escalation_reason
        }

    Never raises. A guard that crashed would take the whole triage path down
    with it.

    NOTE on the not-triggered fallback for a STRUCTURALLY unusable ``enrichment``
    (not a dict at all): that case genuinely cannot be evaluated, and the earlier
    justification for letting it pass — "the confidence thresholds and the
    prompt's never-auto-close-when-context-is-missing rule will catch it" — was
    circular. A 0.99 dismissal clears a 0.92 threshold, and "the prompt's rule"
    is the very instructional boundary this module exists because models do not
    honour. It is left as not-triggered only because a non-dict enrichment means
    the pipeline is broken upstream in a way that produces no alert data either.
    The reachable degradation case — a dict with keys missing because an
    enricher failed — is handled properly above, via ``degraded_enrichers``.
    """
    original = str(verdict or "").strip().lower()
    record = {
        "triggered": False,
        "original_verdict": original,
        "verdict": original,
        "force_escalate": False,
        "triggers": [],
        "evidence": {},
        "reason": "",
    }

    if not isinstance(enrichment, dict):
        logger.warning("verdict_guard_enrichment_unusable",
                       enrichment_type=type(enrichment).__name__,
                       verdict=original,
                       detail="Guard evaluated as not-triggered; verdict left "
                              "to the confidence thresholds.")
        return record

    if original not in GUARDED_DISMISSALS:
        return record

    ti_hits = _as_number(enrichment.get("threat_intel_hits"))
    known_malicious = _as_bool(enrichment.get("is_known_malicious"))
    tier = _tier_of(enrichment)

    # The LLM path trips on BOTH present evidence and unavailable evidence: a
    # model may not dismiss an alert whose contradicting evidence merely could
    # not be looked up. The cost-control gates make a narrower choice — see
    # evidence_unavailable().
    triggers = blocking_evidence(enrichment) + evidence_unavailable(enrichment)

    if not triggers:
        return record

    degraded = degraded_evidence_sources(enrichment)
    detail = {
        "threat_intel_hits": "threat_intel_hits=%g" % ti_hits,
        "is_known_malicious": "is_known_malicious=true",
        "tier_1_critical_asset": "asset_tier=%s" % TIER_1,
        DEGRADED_TRIGGER: "evidence unavailable — degraded enricher(s): %s"
                          % ",".join(sorted(degraded)),
    }
    record.update({
        "triggered": True,
        "verdict": FORCED_VERDICT,
        "force_escalate": True,
        "triggers": triggers,
        "evidence": {
            "threat_intel_hits": ti_hits,
            "is_known_malicious": known_malicious,
            "asset_tier": tier or "unknown",
            "degraded_enrichers": sorted(degraded),
        },
        "reason": (
            "Verdict guard: LLM returned '%s' but hard enrichment evidence "
            "forbids an automated dismissal (%s). Forced to %s for human "
            "review." % (original, ", ".join(detail[t] for t in triggers),
                         FORCED_VERDICT)
        ),
    })
    return record
