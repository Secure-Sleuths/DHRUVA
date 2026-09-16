"""WO-H97 — the one severity ladder, and the deterministic policy around it.

THE PROBLEM THIS FIXES. ``risk_score`` answers *"how often has a human agreed
this rule fired correctly?"* — that is what ``get_rule_human_outcomes`` measures
and what WO-H71's bounded scorer composes. Every consumer of ``severity`` reads
it as *"how dangerous is this?"*. Those are different questions, and until this
module existed nothing in the pipeline separated them:

  * A LeakIX crawler asking for ``/.env.bak`` and getting **404** thirty times
    scored **99.41** and opened CRITICAL, because 443 of 443 human labels on
    rule 31516 say ``true_positive`` — analysts correctly confirming that the
    rule fired correctly, on requests the server refused.
  * A host that stopped reporting scored **15.62** and filed LOW, because 0 of
    11 human labels on rule 110129 say ``true_positive`` — analysts correctly
    saying "this is not an attack". No amount of further learning will ever
    raise it, because the label is true.

Measured on a live tenant 2026-08-24: **5,854 of 8,553 incidents
(68.4%) were critical.** A severity that is nearly always the same value carries
no information, and SLA deadlines, notification routing and the Overview KPIs
are all keyed on it.

WHAT THIS MODULE DOES, IN ORDER:

  1. ``risk_band`` — the ONE ladder (see ``RISK_THRESHOLDS``).
  2. ``SeverityPolicy.apply`` — deterministic ceilings, then floors, read from
     ``config/guidance/escalation_logic.yaml``. Structured alert/enrichment
     facts only: rule id, rule group, the HTTP status the server actually
     returned, and the TI verdict. NEVER the model's output, never free text.

Nothing here reads ``verdict``, ``response_urgency`` or ``kill_chain_stage``.
Deriving severity from the model's ``response_urgency`` is WO-H97 Phase 2 and is
deliberately NOT implemented — a shadow replay of 24 stored decisions answered
``24h`` 21 times and returned ``immediate`` for a stored false positive, so the
field has not earned a role in severity. It is stored and measured first.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)

# ── the ladder ───────────────────────────────────────────────────────────────
# THIS IS THE SINGLE SOURCE OF TRUTH FOR THE BACKEND, AND IT MUST STAY EQUAL TO
# ``web/src/lib/severity.ts::RISK_THRESHOLDS``.
# ``tests/test_severity_ladder.py`` parses the TypeScript and fails if the two
# drift. Two ladders is how the same 75.00 alert read "High" in the triage queue
# and became a "Critical" incident:
#     backend  (engine.py, before this WO): true_positive OR >=75 / 50 / 25
#     frontend (severity.ts):                              >=80 / 55 / 30
#
# WHICH NUMBERS WON, AND WHY THE FRONTEND'S DID:
#
#   * The analyst already reads 80/55/30 — it is what the triage queue has
#     rendered since the redesign. Moving the backend to it means the incident
#     label changes to agree with the queue, rather than the queue suddenly
#     re-colouring every row in the estate.
#
#   * BUT SEPARATE THE MANDATORY FROM THE DISCRETIONARY, because they were
#     reported together once and that was misleading. Measured on the live
#     tenant, by component, in incidents that lose their notification entirely
#     (``notify_incident_created`` sends only for critical/high):
#
#         removing `verdict == "true_positive" -> critical`   104   REQUIRED
#         moving `critical` 75 -> 80                            0   REQUIRED
#         moving `medium`   25 -> 30                            0   free
#         moving `high`     50 -> 55                          622   DISCRETIONARY
#
#     Only the `critical` boundary is load-bearing — it is what stops the
#     cold-start prior opening a critical incident, and it costs nothing. The
#     `high` move is 75% of the entire cost of this work order and it buys only
#     agreement with the SPA's existing number. Its 622 look like noise (sshd
#     auth success x250, PAM login opened x149, web 400 x113) but the tail is
#     not empty — one is "Falco Critical: drop and execute new binary in
#     container". If an operator wants those notifications back, set `high`
#     to 50.0 HERE and in web/src/lib/severity.ts (the ladder test enforces
#     both); the 75.00 collision fix survives untouched, because it lives
#     entirely in the `critical` boundary.
#
#   * It puts a deliberate GAP between the cold-start prior and "critical".
#     ``unknown_rule_tp_rate = 0.75`` (enrichment/service.py) with empty
#     adjustments produces sigmoid(logit(0.75)) = exactly **75.00**, and the old
#     backend ladder opened critical at ``>= 75``. Two independently sensible
#     constants happened to be equal, so EVERY alert on a rule DHRUVA has not
#     learned yet opened critical: 3,208 of 35,129 decisions (9.1%) sit at
#     exactly 75.00.
#
#     The prior is NOT lowered to fix that — WO-H71 is explicit that a
#     low-confidence score is not a low score, and "unknown" really is
#     mid-scale. Instead **critical must be EARNED by evidence the scorer
#     actually has**: a band boundary must never sit on the value the scorer
#     emits when it knows NOTHING. An unlearned rule now lands in HIGH — the
#     second band, escalated, at a 60-minute SLA, and labelled in the case view
#     as "no track record for this rule yet" — not critical, and not invisible.
#
#     BE PRECISE ABOUT WHAT THAT CLAIM IS, though. It is NOT "no score can ever
#     land exactly on a boundary" — the smoothed posterior
#     ``p = (k + 2.5) / (n + 5)`` reaches 55.00 (n=5, k=3) and 30.00 (n=10, k=2;
#     n=20, k=5; ...) exactly. Those are fine: the bands are ``>=``, so a value
#     ON a boundary lands in the HIGHER band, which is the safe direction, and
#     unlike the 75.00 case it is a MEASURED rate rather than the constant the
#     scorer emits in the absence of evidence. The defect was a boundary
#     colliding with the "I do not know" value, not with an arithmetic result.
RISK_THRESHOLDS: dict = {"critical": 80.0, "high": 55.0, "medium": 30.0}

#: least → worst. Index is the rank used by every comparison here and by the
#: incident-merge ``max()`` in ``engine.py``.
SEVERITY_ORDER: tuple = ("low", "medium", "high", "critical")

_VALID_SEVERITIES = frozenset(SEVERITY_ORDER)

#: The highest ``max_rule_level`` a GROUP-selecting ceiling may declare.
#: Wazuh's level 10+ is the "multiple / frequency / high-impact" tier — rules
#: like 31151 "multiple 400 error codes FROM SAME SOURCE IP" — which is exactly
#: what a broad ceiling must never be able to silence. Naming rule ids carries
#: no such limit: naming a rule is a deliberate, reviewable act.
_GROUP_CEILING_MAX_LEVEL = 9


def severity_rank(severity: str) -> int:
    """Rank on ``SEVERITY_ORDER``; an unknown value ranks lowest (0)."""
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return 0


def worst(*severities: str) -> str:
    """The most severe of the given severities. Unknown values rank as ``low``."""
    return max(severities, key=severity_rank) if severities else "low"


def risk_band(risk_score: float) -> str:
    """Map a 0..100 risk score onto the ladder. The ONLY input is the score.

    Deliberately does not take ``verdict``. ``verdict == "true_positive" ->
    critical`` was removed by WO-H97: a confirmed "a port is exposed" and a
    confirmed intrusion are not the same severity, and on a live tenant
    1,444 decisions were critical solely via that clause.
    """
    try:
        score = float(risk_score)
    except (TypeError, ValueError):
        # A score we cannot read is not evidence of safety. Escalate to the
        # unlearned-rule band rather than silently filing it low.
        logger.warning("severity_unreadable_risk_score", risk_score=risk_score)
        return "high"
    if score >= RISK_THRESHOLDS["critical"]:
        return "critical"
    if score >= RISK_THRESHOLDS["high"]:
        return "high"
    if score >= RISK_THRESHOLDS["medium"]:
        return "medium"
    return "low"


# ── HTTP status, read from the alert itself ──────────────────────────────────
# Wazuh's web-accesslog decoder puts the response code in ``data.id`` (verified
# against a live rule 31516 alert, 2026-08-24:
#   data = {"protocol": "GET", "srcip": "...", "id": "404", "url": "/.env.swp"}
# ). The other keys are accepted because other decoders/webhook shapes use them.
_STATUS_KEYS = ("id", "status", "http_status", "response_code", "status_code")


def http_status(alert: dict) -> Optional[str]:
    """The exact status code the server returned (e.g. ``"404"``), or ``None``.

    ``None`` means "we do not know", NEVER "it succeeded" and never "it failed"
    — a ceiling conditioned on the response does not apply without one.

    WO-H97 QA (D1): the CODE matters, not just the class. Measured on the live
    tenant, ``4xx`` is not one thing:

        rule 31101 (148,696 alerts)   401: 80,603   404: 61,713   400: 6,326
        rule 31516 (2,561 alerts)     404:  1,485   401:  1,041   400:    32

    A 404 is "you asked for something that is not there". A **401 is a failed
    credential**, and a burst of them from one source is credential stuffing;
    a **403 is an authenticated session being refused**, which is not a crawler
    finding nothing. Lumping all three together under ``4xx`` is what made the
    first cut of this ceiling wrong, so the config can name codes.
    """
    data = alert.get("data")
    if not isinstance(data, dict):
        return None
    for key in _STATUS_KEYS:
        raw = data.get(key)
        if raw is None:
            continue
        text = str(raw).strip()
        if not re.fullmatch(r"[1-5]\d{2}", text):
            # ``data.id`` is only a status code on web decoders; on other rules
            # it is an arbitrary id. Anything that is not a 3-digit HTTP status
            # is not one.
            continue
        return text
    return None


def http_status_class(alert: dict) -> Optional[str]:
    """``"2xx"``/``"3xx"``/``"4xx"``/``"5xx"``, or ``None`` — see ``http_status``.

    Kept because a class is the right granularity for some rules, but the
    shipped ceiling uses explicit codes: on this estate ``4xx`` would have
    swept 80,603 credential failures in with the crawler noise.
    """
    code = http_status(alert)
    return f"{code[0]}xx" if code else None


# ── the FIM path, read from the alert itself ─────────────────────────────────
# Wazuh's syscheck decoders put the changed file under ``syscheck.path``
# (verified against a live rule 110128 alert, 2026-08-24). The other
# keys are accepted because webhook/normalized shapes vary.
_PATH_KEYS = ("path", "file", "syscheck_path")


def file_path(alert: dict) -> Optional[str]:
    """The file an alert is ABOUT, or ``None`` when it names none.

    STRUCTURED FIELDS ONLY — ``syscheck.path`` / ``data.path``. Never
    ``full_log`` and never the rule description: both carry attacker-influenced
    text, and an exclusion driven from them could be talked into muting an
    alert by writing a path into a log line.

    ``None`` means "this alert names no file", which never satisfies an
    exclusion — see ``_excluded``.
    """
    for container in (alert.get("syscheck"), alert.get("data")):
        if not isinstance(container, dict):
            continue
        for key in _PATH_KEYS:
            raw = container.get(key)
            if raw is None:
                continue
            text = str(raw).strip()
            if text:
                return text
    return None


def _path_matches(path: str, pattern: str) -> bool:
    """Glob a filesystem path where ``*`` does NOT cross a ``/``.

    WO-H97 re-audit (F3). Plain ``fnmatch`` treats ``/`` as an ordinary
    character, so the exclusion ``*/_ai_soc_validation_temp.xml`` also matched
    ``/home/attacker/_ai_soc_validation_temp.xml`` — anyone able to write
    anywhere on the box could name a file after our probe and drop out of the
    very floor that exists to catch them. Matching segment by segment gives the
    shell/`pathlib` semantics an operator expects: a ``*`` covers one path
    component, never a subtree.
    """
    p_seg = path.split("/")
    g_seg = pattern.split("/")
    if len(p_seg) != len(g_seg):
        return False
    return all(fnmatch.fnmatch(a, b) for a, b in zip(p_seg, g_seg))


class SeverityPolicy:
    """Deterministic floors and ceilings, owned by the guidance YAML.

    WHY THIS LIVES IN ``config/guidance/escalation_logic.yaml`` AND NOT IN CODE
    (CLAUDE.md: the guidance YAMLs are the institutional knowledge): "a blind
    endpoint matters even though it is not an attack" and "a request the server
    refused is not a page-someone event" are SOC judgements, they differ per
    client, and they need to be tunable through ``/api/guidance/reload`` without
    a release. Only the lookup is here. No rule id is hardcoded in Python.

    Shape (both lists optional; an entry with no selector matches nothing):

        severity_policy:
          floors:
            - name: "Loss of visibility"
              rule_ids: [110129]
              rule_groups: ["service_availability"]
              severity: "medium"
              reason: "..."
          ceilings:
            - name: "Web request the server refused"
              rule_ids: [31101, 31516]
              http_status: ["404", "400"]
              max_rule_level: 6
              severity: "medium"
              reason: "..."

    Matching. An entry matches when the alert's rule id is in ``rule_ids`` OR
    one of its rule groups is in ``rule_groups``, AND every condition present
    also holds:

      * ``http_status`` — the exact code the server returned is in the list.
      * ``http_status_class`` — its class (``"4xx"``) is in the list.
      * ``max_rule_level`` — the rule's own level is at or below this.

    A missing status means NO match: "we do not know" is never "it failed".

    **A CEILING SHOULD SELECT ON RULE IDS.** ``rule_groups`` on a ceiling is a
    loaded gun and the first cut of this file fired it: ``rule_groups: ["web"]``
    read as 8 rules and was actually **15 rules / 164,241 alerts**, including
    Wazuh's level-10 frequency rules 31151/31153/31154 ("multiple 400s / common
    web attacks / XSS attempts FROM SAME SOURCE IP"). Those are composite rules
    built on 4xx children, so their alert always carries a 4xx and they were
    **permanently** capped — the burst detector, silenced, by a rule meant for
    a crawler getting a 404. A group-selecting ceiling must now declare
    ``max_rule_level``, and that cap may not exceed
    ``_GROUP_CEILING_MAX_LEVEL`` (9) — because ``max_rule_level: 999`` loads
    clean and is no cap at all, which is the same defect wearing a hat. To
    silence a level-10 rule you have to name its id, which is reviewable —
    and a named id is never subject to the cap, for the same reason.

    **A CEILING IS NOT "LOWER PRIORITY". IT IS SILENCE.**
    ``notifications/service.py::notify_incident_created`` returns early unless
    the severity is ``critical`` or ``high``, so capping to ``medium`` means no
    creation notification is sent at all. Every ceiling entry is a decision to
    stop telling anyone.

    Precedence, in this order and for these reasons:

      1. **A ceiling never applies over confirmed malicious intelligence.**
         ``is_known_malicious`` / ``threat_intel_hits > 0`` is hard, structured
         evidence; a per-rule ceiling is a prior. Evidence wins — the same
         discipline as ``verdict_guard``. **Do not mistake this for a safety
         net:** measured on this estate, ``is_known_malicious`` was true on 1 of
         2,486 covered web alerts. It is a correctness rule, not a backstop —
         the selector itself has to be right.
      2. Ceilings lower the band (the LOWEST matching ceiling wins).
      3. Floors raise it (the HIGHEST matching floor wins), and are applied
         LAST, so a floor always beats a ceiling. "We have lost sight of this
         host" is never argued down by a rule-shaped exception.

    ``rejected`` lists every entry that was thrown away as unusable. It is
    non-empty ONLY when the YAML is wrong, and the reload path reports it as a
    failure — a typo'd ``severity:`` used to disable a floor silently while the
    API answered "Guidance reloaded".
    """

    def __init__(self, floors: list = None, ceilings: list = None):
        self.rejected: list = []
        #: dedup for _note_cap_bypassed — one line per (entry name, rule id).
        self._cap_notices: set = set()
        self.floors = self._clean(floors, kind="floor")
        self.ceilings = self._clean(ceilings, kind="ceiling")

    @classmethod
    def from_guidance(cls, escalation_logic: dict) -> "SeverityPolicy":
        """Build from a parsed ``escalation_logic.yaml``. Never raises: a
        malformed or absent block degrades to an empty policy (pure risk bands),
        because a severity computation must not be able to take triage down."""
        if not isinstance(escalation_logic, dict):
            return cls()
        block = escalation_logic.get("severity_policy")
        if not isinstance(block, dict):
            return cls()
        return cls(floors=block.get("floors"), ceilings=block.get("ceilings"))

    def _reject(self, kind: str, name: str, reason: str, **kv) -> None:
        """Record AND log an entry that was thrown away.

        Recording it matters as much as logging it. WO-H97 QA (D2): a typo'd
        ``severity: "meduim"`` dropped the loss-of-visibility floor, the reload
        returned ``{"status": "ok", "floors": 0}``, and the API answered
        "Guidance reloaded" — so a dark host quietly went back to ``low``, which
        is the exact defect this work order exists to fix. A warning in a log
        nobody is reading is not a report.
        """
        self.rejected.append({"kind": kind, "entry": name, "reason": reason})
        logger.warning("severity_policy_entry_rejected",
                       kind=kind, entry=name, reason=reason, **kv)

    def _clean(self, entries, kind: str) -> list:
        """Drop entries that cannot do anything, loudly and reportably."""
        cleaned = []
        if not isinstance(entries, list):
            if entries is not None:
                self._reject(kind, "<block>", "not a list",
                             got=type(entries).__name__)
            return cleaned
        for entry in entries:
            if not isinstance(entry, dict):
                self._reject(kind, "<entry>", "not a mapping")
                continue
            name = str(entry.get("name") or "unnamed")
            severity = str(entry.get("severity") or "").strip().lower()
            if severity not in _VALID_SEVERITIES:
                self._reject(kind, name,
                             "severity %r is not one of %s"
                             % (severity, sorted(_VALID_SEVERITIES)))
                continue
            rule_ids = set()
            bad_ids = []
            for rid in entry.get("rule_ids") or []:
                try:
                    rule_ids.add(int(rid))
                except (TypeError, ValueError):
                    bad_ids.append(rid)
            if bad_ids:
                self._reject(kind, name,
                             "rule_ids contains non-numeric entries: %r"
                             % (bad_ids[:5],))
                continue
            groups = {str(g).strip().lower()
                      for g in (entry.get("rule_groups") or []) if str(g).strip()}
            if not rule_ids and not groups:
                self._reject(kind, name,
                             "no rule_ids and no rule_groups — can never fire")
                continue
            classes = {str(c).strip().lower()
                       for c in (entry.get("http_status_class") or [])
                       if str(c).strip()}
            codes = {str(c).strip()
                     for c in (entry.get("http_status") or []) if str(c).strip()}
            exclude_paths = [str(g).strip()
                             for g in (entry.get("exclude_paths") or [])
                             if str(g).strip()]
            level_cap = entry.get("max_rule_level")
            if level_cap is not None:
                try:
                    level_cap = int(level_cap)
                except (TypeError, ValueError):
                    self._reject(kind, name,
                                 "max_rule_level %r is not a number"
                                 % (level_cap,))
                    continue
            # A FLOOR at `high` or above is a PAGE, so a broad group selector
            # is as dangerous there as on a ceiling — the "floors only raise, so
            # they are the safe direction" argument stops holding the moment
            # raising IS paging. It is how the detection_integrity floor came to
            # page several hundred times a day on DHRUVA's own file writes. A
            # loud floor must name its rule ids, or bound the group with
            # exclusions or a level cap.
            # NOTE the test is on the GROUP being unbounded, not on the entry
            # having no rule ids. Adding a rule id ADDS coverage; it does not
            # bound the group, and requiring `not rule_ids` meant a single
            # unrelated id disarmed the whole guard (WO-H97 re-audit F4a). Only
            # exclude_paths and max_rule_level actually narrow a group.
            if (kind == "floor"
                    and severity_rank(severity) >= severity_rank("high")
                    and groups
                    and not exclude_paths and level_cap is None):
                self._reject(kind, name,
                             "a floor at %r that selects on rule_groups must "
                             "bound them with exclude_paths or max_rule_level "
                             "— a floor at high or above PAGES, so an "
                             "unbounded group is not the safe direction. "
                             "Adding rule_ids does not bound a group."
                             % severity)
                continue
            # A ceiling that selects by GROUP with no level cap is how 15 rules
            # (including three level-10 frequency rules) got silenced by an
            # entry written for a crawler. Refuse it rather than let it ship.
            # A cap with nothing to bound is config that looks meaningful and
            # does nothing — the exact shape this work order exists to stop.
            # Caps bound GROUP selectors; with no group there is nothing for it
            # to act on, and it does NOT reach the named ids.
            if level_cap is not None and not groups:
                self._reject(kind, name,
                             "max_rule_level %d bounds the rule_groups "
                             "selector and this entry has none, so the cap "
                             "can never act. It does NOT apply to the named "
                             "rule_ids %s — remove the cap, or add the "
                             "rule_groups it is meant to bound."
                             % (level_cap, sorted(rule_ids) or []))
                continue
            if kind == "ceiling" and groups:
                if level_cap is None:
                    self._reject(kind, name,
                                 "a ceiling with rule_groups must also set "
                                 "max_rule_level — see WO-H97 D1: rule_groups: "
                                 "['web'] silenced rules 31151/31153/31154 "
                                 "(level 10, 'from same source ip')")
                    continue
                # ...and the cap has to BE a cap. ``max_rule_level: 999`` loads
                # clean and is indistinguishable from no cap at all, which is
                # the same defect wearing a hat. Wazuh's level 10+ is the
                # "multiple / frequency / high-impact" tier — exactly the rules
                # a group-selected ceiling must never reach — so a group
                # selector may not cap above 9. Name the rule ids instead if
                # you really mean to silence a level-10 rule.
                if level_cap > _GROUP_CEILING_MAX_LEVEL:
                    self._reject(kind, name,
                                 "a ceiling with rule_groups may not set "
                                 "max_rule_level above %d (got %d) — Wazuh "
                                 "level 10+ is the frequency/high-impact tier; "
                                 "name the rule ids explicitly instead"
                                 % (_GROUP_CEILING_MAX_LEVEL, level_cap))
                    continue
            # WO-H111: optional `guidance_signal` condition. It NARROWS an
            # entry (like exclude_paths); it can never select on its own,
            # because the rule_ids/rule_groups requirement above still applies.
            gsig = entry.get("guidance_signal")
            if gsig is not None:
                gsig = str(gsig).strip().lower()
                if gsig not in ("note", "expected", "escalate"):
                    self._reject(kind, name,
                                 "guidance_signal %r is not one of "
                                 "note/expected/escalate" % (gsig,))
                    continue
            cleaned.append({
                "name": name,
                "severity": severity,
                "guidance_signal": gsig,
                "rule_ids": rule_ids,
                "rule_groups": groups,
                "http_status_class": classes,
                "http_status": codes,
                "exclude_paths": exclude_paths,
                "max_rule_level": level_cap,
                "reason": str(entry.get("reason") or ""),
            })
        return cleaned

    def _matches(self, entry: dict, alert: dict) -> bool:
        try:
            rule_id = int(alert.get("rule_id") or 0)
        except (TypeError, ValueError):
            rule_id = 0
        groups = {str(g).strip().lower()
                  for g in (alert.get("rule_groups") or [])}
        by_id = rule_id in entry["rule_ids"]
        by_group = bool(groups & entry["rule_groups"])
        if not (by_id or by_group):
            return False

        # EXCLUSIONS run before every other condition: an entry that has been
        # scoped away from this file does not apply, whatever else matches.
        if entry["exclude_paths"] and SeverityPolicy._excluded(entry, alert):
            return False

        # WO-H111: per-rule guidance signal.
        #
        # An entry asking for `escalate` fires ONLY when the guidance actually
        # loaded and actually matched. A FAILED load does not satisfy it — we
        # will not manufacture an escalation out of "we could not read the
        # file". That does mean a parse error silently costs this floor, which
        # is why RuleGuidance.load logs the failure at error level and
        # format_for_prompt renders an explicit UNAVAILABLE block rather than
        # falling silent. "We could not read it" is loud somewhere else, not
        # here.
        want_signal = entry.get("guidance_signal")
        if want_signal is not None:
            rg = alert.get("rule_guidance")
            if not isinstance(rg, dict):
                return False
            if rg.get("state") != "loaded":
                return False
            if rg.get("signal") != want_signal:
                return False

        # ``max_rule_level`` BOUNDS THE GROUP SELECTOR, AND ONLY THAT.
        #
        # A ``rule_groups`` entry is a promise about rules nobody has
        # enumerated and nobody can read in the diff — that is what needs a
        # ceiling on how far it can reach. A named ``rule_ids`` entry is the
        # opposite: someone typed that number and a reviewer can see it.
        #
        # Applying the cap to a named id would recreate this work order's own
        # defect in config clothes: ``rule_ids: [110128]`` with
        # ``max_rule_level: 9`` against a level-12 rule looks correct, loads
        # clean, and silently protects nothing. So a named id ALWAYS matches;
        # an entry whose cap can never act is refused at load (``_clean``);
        # and a cap that a named id walks past says so once in the log.
        cap = entry["max_rule_level"]
        if cap is not None and by_id:
            self._note_cap_bypassed(entry, rule_id, alert.get("rule_level"),
                                    cap)
        elif cap is not None and by_group:
            raw_level = alert.get("rule_level")
            # A MISSING level is not a level of 0. ``normalize_alert`` writes 0
            # when the alert carries no ``rule.level`` at all, and 0 passes
            # every cap — so an alert whose loudness we do not know would slip
            # UNDER a ceiling written for quiet rules. "We do not know" is not
            # "it is quiet", the same rule as the missing HTTP status.
            try:
                level = int(raw_level)
            except (TypeError, ValueError):
                # Includes None and "" — an unreadable level is not evidence
                # the rule is quiet.
                return False
            # ...and 0 is what ``normalize_alert`` writes when the alert
            # carried no ``rule.level`` AT ALL, so it means "unknown", not
            # "quiet". Parsed AFTER int() so the string "0" and the integer 0
            # are treated identically — they used to disagree.
            if level == 0:
                return False
            if level > cap:
                return False

        # Both response conditions are ANDed when both are present. A missing
        # status never satisfies either: "we do not know" is not "it failed".
        codes = entry["http_status"]
        classes = entry["http_status_class"]
        if codes or classes:
            observed = http_status(alert)
            if observed is None:
                return False
            if codes and observed not in codes:
                return False
            if classes and f"{observed[0]}xx" not in classes:
                return False
        return True

    def _note_cap_bypassed(self, entry: dict, rule_id: int, raw_level,
                           cap: int) -> None:
        """Say ONCE, per entry+rule, that a cap did not apply to a named id.

        The semantics are deliberate (see ``_matches``), but an operator who
        believed the cap bounded their named rule should learn that from the
        log rather than from a missed page. Deduplicated, because a rule firing
        several hundred times a day must not fill the log with it.
        """
        try:
            level = int(raw_level)
        except (TypeError, ValueError):
            return
        if level <= cap:
            return
        key = (entry["name"], rule_id)
        if key in self._cap_notices:
            return
        self._cap_notices.add(key)
        logger.info("severity_policy_cap_not_applied_to_named_rule",
                    entry=entry["name"], rule_id=rule_id, rule_level=level,
                    max_rule_level=cap,
                    detail="max_rule_level bounds the rule_groups selector "
                           "only; a rule named in rule_ids always matches. "
                           "Remove the id, or remove the cap.")

    @staticmethod
    def _excluded(entry: dict, alert: dict) -> bool:
        """Is this alert about a file the entry has been scoped away from?

        WO-H97 re-audit (B1). A floor could previously only be REMOVED, never
        narrowed — and the one case that needed narrowing was the worst kind:
        ``detection_integrity`` fires on any write to the manager's rules
        directory, and DHRUVA VALIDATES EVERY PROPOSED RULE by writing a probe
        file into exactly that directory. 152 of 176 live alerts on rule 110128
        (86%) are the platform tripping its own alarm. Flooring that to `high`
        is a page plus a 60-minute SLA clock, several hundred times a day once
        detection is re-enabled.

        FAIL-SAFE, in the direction that keeps the alert loud: an alert that
        names NO path is never excluded. "We cannot prove this was us" resolves
        to paging, the same rule as the missing HTTP status and the missing rule
        level. Matching is ``fnmatch`` on the structured path only.
        """
        observed = file_path(alert)
        if not observed:
            return False
        return any(_path_matches(observed, pattern)
                   for pattern in entry["exclude_paths"])

    def apply(self, band: str, alert: dict, enrichment: dict = None) -> tuple:
        """Return ``(severity, matched)`` for a risk band and an enriched alert.

        ``matched`` lists EVERY entry that matched this alert, as
        ``{"kind", "name", "severity", "reason", "moved"}``. ``moved`` says
        whether it actually changed the number.

        WO-H97 re-audit (F2). This used to append only on a strict rank
        increase, so ``matched`` was empty whenever the risk band ALREADY met
        the floor — and ``_process_single`` reads it to decide whether a
        deterministic floor outranks a benign verdict. The protection was
        therefore inverted: it held for the lowest-scoring alerts and vanished
        for the highest. A SIEM-tampering alert marked ``false_positive`` at
        0.99 was kept at risk 48 and DROPPED at 75 and 90 — and 75.00 is the
        cold-start prior, 9.1% of every decision on the live estate.
        "A floor applies to this alert" and "a floor changed this number" are
        different facts, and the guard needs the first one.
        """
        severity = band if band in _VALID_SEVERITIES else "low"
        matched = []
        if not isinstance(alert, dict):
            return severity, matched
        enrichment = enrichment if isinstance(enrichment, dict) else {}

        # 1. Confirmed malicious intelligence disables every ceiling.
        ti_hits = enrichment.get("threat_intel_hits") or 0
        try:
            ti_hits = int(ti_hits)
        except (TypeError, ValueError):
            ti_hits = 0
        confirmed_malicious = bool(
            enrichment.get("is_known_malicious")) or ti_hits > 0

        # 2. Ceilings — the lowest matching one wins.
        if not confirmed_malicious:
            for entry in self.ceilings:
                if not self._matches(entry, alert):
                    continue
                moved = severity_rank(entry["severity"]) < severity_rank(severity)
                if moved:
                    severity = entry["severity"]
                matched.append({"kind": "ceiling", "name": entry["name"],
                                "severity": entry["severity"],
                                "reason": entry["reason"], "moved": moved})

        # 3. Floors — the highest matching one wins, and beats any ceiling.
        for entry in self.floors:
            if not self._matches(entry, alert):
                continue
            moved = severity_rank(entry["severity"]) > severity_rank(severity)
            if moved:
                severity = entry["severity"]
            matched.append({"kind": "floor", "name": entry["name"],
                            "severity": entry["severity"],
                            "reason": entry["reason"], "moved": moved})

        return severity, matched
