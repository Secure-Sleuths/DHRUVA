"""Per-rule triage guidance — WO-H111.

WHY THIS MODULE EXISTS
----------------------
Rule 61138 fired on a live estate for a kernel driver whose service name was
eight random lowercase letters, registered as a SYSTEM START service 31 seconds
after Microsoft Defender quarantined ``Trojan:Win32/Kepavll!rfn`` (Severe) on
the same host. DHRUVA scored it **20.83**.

Every WinRing0 alert on that host also scores **20.83** — 80 of them since
April, all CPUID HWMonitor's own driver, all benign. The composite score could
not separate the one real intrusion of the month from the routine noise.

The discriminator was in the alert the whole time. Across 100 service
installations on that host, that driver and one other random-named driver eight
days earlier were the ONLY two kernel drivers set to ``system start``. Nothing
in the pipeline read that field.

This module reads it. It is deterministic matching over fields we already
carry — no model involved, so it cannot drift the way the verdict does
(see WO-H104: 5/5 alerts changed verdict on byte-identical prompts).

LOAD STATE IS PART OF THE ANSWER
--------------------------------
``GuidanceLoader._load_yaml`` returns ``{}`` for both "file is not there" and
"file failed to parse". For per-rule guidance those cannot share a value: an
``expected`` signal that fails to load must never read as "nothing to say here,
carry on". So this module tracks ``state`` explicitly — ``loaded`` / ``absent``
/ ``failed`` — and every consumer is handed it alongside the result.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import structlog
import yaml

logger = structlog.get_logger(__name__)

#: Load outcomes. ``absent`` and ``failed`` are deliberately distinct — see the
#: module docstring. A consumer that treats them the same reintroduces the
#: defect class of WO-H128..H134.
STATE_LOADED = "loaded"
STATE_ABSENT = "absent"
STATE_FAILED = "failed"

#: Signal kinds, weakest to strongest. ``escalate`` beats ``expected`` when both
#: match: safety wins ties, because a wrong escalation costs an analyst a few
#: minutes and a wrong "expected" costs what that missed rootkit cost.
SIGNAL_NOTE = "note"
SIGNAL_EXPECTED = "expected"
SIGNAL_ESCALATE = "escalate"
_SIGNAL_RANK = {SIGNAL_NOTE: 0, SIGNAL_EXPECTED: 1, SIGNAL_ESCALATE: 2}

#: Bounds. Guidance is operator-editable, so a typo must not become a hang or a
#: prompt-budget blowout.
_MAX_SIGNALS_PER_RULE = 40
_MAX_CONDITIONS_PER_SIGNAL = 12
_MAX_REGEX_LEN = 300
_MAX_VALUE_LEN = 4096
_MAX_PROMPT_CHARS = 2400

_OPERATORS = ("equals", "equals_ignore_case", "not_equals",
              "contains", "matches", "in", "not_in", "exists")


@dataclass
class Condition:
    field_path: str
    operator: str
    expected: Any
    regex: Optional[re.Pattern] = None


@dataclass
class Signal:
    id: str
    kind: str
    because: str
    mode: str                      # "all" | "any"
    conditions: list = field(default_factory=list)


@dataclass
class RuleEntry:
    rule_id: str
    name: str
    summary: str
    analyst_note: str
    signals: list = field(default_factory=list)


@dataclass
class GuidanceMatch:
    """What the guidance had to say about one alert.

    ``state`` is always present and always meaningful. ``signal`` is ``None``
    when nothing matched **and** when guidance could not be read — which is why
    callers must look at ``state`` before drawing any conclusion from ``signal``.
    """
    state: str
    rule_id: Optional[str] = None
    entry_found: bool = False
    signal: Optional[str] = None
    matched: list = field(default_factory=list)

    @property
    def escalates(self) -> bool:
        return self.signal == SIGNAL_ESCALATE

    @property
    def usable(self) -> bool:
        """True only when guidance was actually read. ``failed`` is not usable."""
        return self.state == STATE_LOADED

    def as_record(self) -> dict:
        """Compact form stored on the alert and surfaced to severity/scoring."""
        return {
            "state": self.state,
            "rule_id": self.rule_id,
            "entry_found": self.entry_found,
            "signal": self.signal,
            "matched": [m["id"] for m in self.matched],
        }


def _resolve(alert: dict, path: str) -> Any:
    """Walk a dotted path into the normalised alert. Missing → ``None``."""
    cur: Any = alert
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
        if cur is None:
            return None
    return cur


def _as_text(value: Any) -> Optional[str]:
    if value is None or isinstance(value, (dict, list)):
        return None
    return str(value)[:_MAX_VALUE_LEN]


def _test(cond: Condition, alert: dict) -> bool:
    value = _resolve(alert, cond.field_path)
    if cond.operator == "exists":
        return value is not None
    text = _as_text(value)
    if text is None:
        return False
    if cond.operator == "equals":
        return text == str(cond.expected)
    if cond.operator == "equals_ignore_case":
        return text.casefold() == str(cond.expected).casefold()
    if cond.operator == "not_equals":
        return text != str(cond.expected)
    if cond.operator == "contains":
        return str(cond.expected).casefold() in text.casefold()
    if cond.operator == "matches":
        return cond.regex is not None and bool(cond.regex.search(text))
    if cond.operator == "in":
        wanted = cond.expected if isinstance(cond.expected, list) else [cond.expected]
        return any(text == str(w) for w in wanted)
    if cond.operator == "not_in":
        # WO-H111 QA (B1). Added because "eight lowercase letters" turned out to
        # describe a large slice of the stock Windows driver set, not malware —
        # 24 of 24 driver names taken from the affected host's own directory
        # listing matched. A name-shape heuristic needs a way to say "except
        # these", or it is a pattern that fires on the operating system.
        # Case-insensitive: service names are not case-sensitive in Windows.
        unwanted = cond.expected if isinstance(cond.expected, list) else [cond.expected]
        return all(text.casefold() != str(w).casefold() for w in unwanted)
    return False


class RuleGuidance:
    """Deterministic, per-rule triage guidance.

    Construct with the path to ``rule_guidance.yaml``. Absent file is a normal,
    supported state — the platform ran without this for its whole life and must
    keep running identically when the file is not there.
    """

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.state: str = STATE_ABSENT
        self.error: Optional[str] = None
        self.rules: dict = {}
        self.rejected: list = []
        self.load()

    # -- loading ---------------------------------------------------------

    def load(self) -> str:
        """Read the guidance. Encrypted (.enc) first, then plaintext YAML.

        THE .enc PATH IS NOT OPTIONAL. ``scripts/build-client-package.sh``
        encrypts every guidance YAML and then DELETES the .yaml
        (``find ... -name "*.yaml" -delete``). A loader that only understood
        plaintext would therefore report ``absent`` on every production client
        package — the file is right there as ``rule_guidance.enc`` and the
        shipped escalate signals would silently never load. That is this
        module's own headline failure mode pointed at itself.
        """
        self.rules, self.rejected, self.error = {}, [], None
        enc_path = self.path.with_suffix(".enc")

        raw = None
        if enc_path.exists():
            try:
                # Imported late: loader.py imports THIS module, so a top-level
                # import here would be circular.
                from src.guidance.loader import _decrypt_guidance
                raw = _decrypt_guidance(enc_path) or {}
            except Exception as e:                              # noqa: BLE001
                # A file that exists but cannot be decrypted is FAILED, never
                # absent. Absent means "nobody wrote guidance"; this means
                # "guidance was written and we cannot read it".
                self.state = STATE_FAILED
                self.error = str(e)[:300]
                logger.error("rule_guidance_decrypt_failed",
                             path=str(enc_path), error=self.error)
                return self.state
        elif not self.path.exists():
            self.state = STATE_ABSENT
            logger.info("rule_guidance_absent", path=str(self.path))
            return self.state
        else:
            try:
                with open(self.path) as f:
                    raw = yaml.safe_load(f) or {}
            except Exception as e:                              # noqa: BLE001
                # LOUD. A parse failure silently removes every `escalate` signal
                # in the file; that must never look like "nothing to report".
                self.state = STATE_FAILED
                self.error = str(e)[:300]
                logger.error("rule_guidance_load_failed",
                             path=str(self.path), error=self.error)
                return self.state

        if not isinstance(raw, dict) or not isinstance(raw.get("rules"), dict):
            self.state = STATE_FAILED
            self.error = "top-level 'rules' mapping missing"
            logger.error("rule_guidance_load_failed",
                         path=str(self.path), error=self.error)
            return self.state

        for rid, entry in raw["rules"].items():
            parsed = self._parse_entry(str(rid).strip(), entry)
            if parsed is not None:
                self.rules[str(rid).strip()] = parsed

        self.state = STATE_LOADED
        logger.info("rule_guidance_loaded",
                    path=str(self.path), rules=len(self.rules),
                    signals=sum(len(r.signals) for r in self.rules.values()),
                    rejected=len(self.rejected))
        return self.state

    reload = load

    def _reject(self, what: str, why: str, **kv) -> None:
        self.rejected.append({"what": what, "why": why, **kv})
        logger.warning("rule_guidance_entry_rejected", what=what, why=why, **kv)

    def _parse_entry(self, rule_id: str, entry: Any) -> Optional[RuleEntry]:
        if not isinstance(entry, dict):
            self._reject(rule_id, "entry is not a mapping")
            return None
        raw_signals = entry.get("signals") or []
        if not isinstance(raw_signals, list):
            self._reject(rule_id, "signals is not a list")
            return None
        if len(raw_signals) > _MAX_SIGNALS_PER_RULE:
            self._reject(rule_id, "too many signals", count=len(raw_signals))
            return None

        signals = []
        for raw in raw_signals:
            sig = self._parse_signal(rule_id, raw)
            if sig is not None:
                signals.append(sig)

        return RuleEntry(
            rule_id=rule_id,
            name=str(entry.get("name") or "")[:200],
            summary=str(entry.get("summary") or "")[:1200],
            analyst_note=str(entry.get("analyst_note") or "")[:1200],
            signals=signals,
        )

    def _parse_signal(self, rule_id: str, raw: Any) -> Optional[Signal]:
        if not isinstance(raw, dict):
            self._reject(rule_id, "signal is not a mapping")
            return None
        sid = str(raw.get("id") or "")[:100]
        kind = str(raw.get("signal") or "").strip().lower()
        if not sid:
            self._reject(rule_id, "signal has no id")
            return None
        if kind not in _SIGNAL_RANK:
            self._reject(rule_id, "unknown signal kind", signal=sid, kind=kind)
            return None

        when = raw.get("when")
        if not isinstance(when, dict):
            self._reject(rule_id, "signal has no 'when'", signal=sid)
            return None
        mode = "all" if "all" in when else ("any" if "any" in when else "")
        if not mode:
            self._reject(rule_id, "'when' needs 'all' or 'any'", signal=sid)
            return None
        raw_conds = when.get(mode) or []
        if not isinstance(raw_conds, list) or not raw_conds:
            self._reject(rule_id, "'when' has no conditions", signal=sid)
            return None
        if len(raw_conds) > _MAX_CONDITIONS_PER_SIGNAL:
            self._reject(rule_id, "too many conditions", signal=sid)
            return None

        conditions = []
        for rc in raw_conds:
            cond = self._parse_condition(rule_id, sid, rc)
            if cond is None:
                # One bad condition invalidates the whole signal. A signal that
                # silently drops a condition is a WEAKER test than written, and
                # for an `escalate` that means a miss.
                return None
            conditions.append(cond)

        return Signal(id=sid, kind=kind,
                      because=str(raw.get("because") or "")[:900],
                      mode=mode, conditions=conditions)

    def _parse_condition(self, rule_id: str, sid: str, rc: Any) -> Optional[Condition]:
        if not isinstance(rc, dict):
            self._reject(rule_id, "condition is not a mapping", signal=sid)
            return None
        path = str(rc.get("field") or "").strip()
        if not path or not re.fullmatch(r"[A-Za-z0-9_.\-]{1,200}", path):
            self._reject(rule_id, "bad or missing field path", signal=sid, path=path)
            return None
        ops = [o for o in _OPERATORS if o in rc]
        if len(ops) != 1:
            self._reject(rule_id, "condition needs exactly one operator",
                         signal=sid, found=ops)
            return None
        op = ops[0]
        expected = rc[op]
        regex = None
        if op == "matches":
            pattern = str(expected)
            if len(pattern) > _MAX_REGEX_LEN:
                self._reject(rule_id, "regex too long", signal=sid)
                return None
            try:
                regex = re.compile(pattern)
            except re.error as e:
                self._reject(rule_id, "invalid regex", signal=sid, error=str(e)[:120])
                return None
        return Condition(field_path=path, operator=op, expected=expected, regex=regex)

    # -- evaluation ------------------------------------------------------

    def evaluate(self, alert: dict) -> GuidanceMatch:
        """Match one normalised alert. Never raises."""
        if self.state != STATE_LOADED:
            return GuidanceMatch(state=self.state)
        if not isinstance(alert, dict):
            return GuidanceMatch(state=STATE_LOADED)

        rule_id = alert.get("rule_id")
        rid = str(rule_id).strip() if rule_id is not None else ""
        entry = self.rules.get(rid)
        if entry is None:
            return GuidanceMatch(state=STATE_LOADED, rule_id=rid or None,
                                 entry_found=False)

        matched = []
        for sig in entry.signals:
            try:
                tests = [_test(c, alert) for c in sig.conditions]
            except Exception as e:                              # noqa: BLE001
                logger.warning("rule_guidance_signal_error",
                               rule_id=rid, signal=sig.id, error=str(e)[:160])
                continue
            hit = all(tests) if sig.mode == "all" else any(tests)
            if hit:
                matched.append({"id": sig.id, "signal": sig.kind,
                                "because": sig.because})

        strongest = None
        if matched:
            strongest = max(matched, key=lambda m: _SIGNAL_RANK[m["signal"]])["signal"]
            logger.info("rule_guidance_matched", rule_id=rid,
                        signal=strongest, signals=[m["id"] for m in matched])

        return GuidanceMatch(state=STATE_LOADED, rule_id=rid, entry_found=True,
                             signal=strongest, matched=matched)

    # -- prompt rendering ------------------------------------------------

    def format_for_prompt(self, alert: dict, match: GuidanceMatch = None) -> str:
        """Render guidance for the triage prompt. Bounded; never raises.

        Returns "" only when there is genuinely nothing to say — i.e. guidance
        loaded cleanly and this rule has no entry. A FAILED load renders an
        explicit warning instead of silence.
        """
        match = self.evaluate(alert) if match is None else match

        if match.state == STATE_FAILED:
            return ("## Per-Rule Guidance\n"
                    "**UNAVAILABLE — the per-rule guidance file failed to load.**\n"
                    "Do not read this as 'there is no guidance for this rule'. "
                    "Any rule-specific instruction that would normally appear "
                    "here is missing. Triage on the general methodology and say "
                    "in your reasoning that rule-specific guidance was "
                    "unavailable.")
        if match.state == STATE_ABSENT or not match.entry_found:
            return ""

        entry = self.rules.get(match.rule_id)
        if entry is None:
            return ""

        out = ["## Per-Rule Guidance — rule %s%s" % (
            entry.rule_id, (" (%s)" % entry.name) if entry.name else "")]
        if entry.summary:
            out.append("\n**What normally causes this here:** %s" % entry.summary.strip())

        if match.matched:
            out.append("\n**Deterministic signals that matched THIS alert:**")
            for m in sorted(match.matched,
                            key=lambda x: -_SIGNAL_RANK[x["signal"]]):
                out.append("- `%s` — **%s**: %s" % (
                    m["id"], m["signal"].upper(), (m["because"] or "").strip()))
            if match.signal == SIGNAL_ESCALATE:
                out.append("\nAn ESCALATE signal matched. These are field-exact "
                           "checks written by the SOC, not model inference. Do "
                           "not return a benign verdict without directly "
                           "addressing why the matched signal does not apply.")
        else:
            out.append("\n**No deterministic signal matched this alert.** That is "
                       "not evidence of benignity — it means none of the written "
                       "patterns fit. Triage on the rest of the context.")

        if entry.analyst_note:
            out.append("\n**Analyst note:** %s" % entry.analyst_note.strip())

        return "\n".join(out)[:_MAX_PROMPT_CHARS]
