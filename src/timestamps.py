"""Version-independent ISO-8601 timestamp parsing (WO-H116).

WHY THIS MODULE EXISTS
======================
``datetime.fromisoformat`` is **not** a stable ISO-8601 parser: what it accepts
changed in Python 3.11. Before 3.11 it only round-tripped what
``datetime.isoformat()`` emits; from 3.11 it accepts most of ISO-8601.

DHRUVA reads timestamps produced by other systems — Wazuh, OpenSearch, the
Wazuh Manager API, inbound webhooks, and Postgres' own ``::text`` cast — none of
which format the way ``datetime.isoformat()`` does. So the SAME line of code
works on the dev box and in CI and raises ``ValueError`` in production.

Measured, on real CPython builds (see ``tests/test_timestamps_h116.py``):

============================================  ======  =============
value                                          3.10    3.11 - 3.13
============================================  ======  =============
``2026-09-01T18:38:13.905+0000``  (Wazuh)      REJECT  accept
``2026-09-01T18:38:13.905Z``                   REJECT  accept
``2026-09-01 18:38:13.905497+00`` (PG ::text)  REJECT  accept
``2026-09-01T18:38:13.9051234+00:00``          REJECT  accept
``2026-09-01T18:38:13.9``                      REJECT  accept
``2026-09-01T18:38:13,905``                    REJECT  accept
============================================  ======  =============

That is not a hypothetical: ``triage_backlog_metric_failed`` fired 876 times in
one day on a live tenant (system Python 3.10.12) with
``Invalid isoformat string: '2026-09-01T18:38:13.905+0000'`` — the triage
backlog metric had been dead there for two weeks while every test stayed green.

THE FIX
=======
Normalise the string to the narrow subset that EVERY supported interpreter
accepts, THEN hand it to ``fromisoformat``. :func:`normalize_iso8601` is a pure
string function, so it can be asserted on directly — a test of the normalised
STRING fails on a permissive interpreter too, whereas a test that merely parses
``+0000`` would pass on 3.11+ with the fix reverted and prove nothing.

SUPPORTED PYTHON: **3.10 to 3.13 inclusive**. The floor is 3.10, Ubuntu 22.04's
system interpreter, which is what source-tarball deployments run. The ceiling is
3.13, because ``requirements.txt`` pins ``psycopg[binary]==3.2.4`` and
``pydantic-core==2.27.2`` and neither publishes a ``cp314`` wheel — on 3.14
``pip install -r requirements.txt`` fails outright, so every claim in this file
is measured across 3.10, 3.11, 3.12 and 3.13 only. See ``docs/TESTING.md``.

NAIVE INPUT MEANS UTC
=====================
A timestamp with no offset is read as **UTC**, never as the host's local time.
This matches ``TimeContextEnricher._assume_utc``
(``src/enrichment/enrichers/__init__.py``): Wazuh emits UTC, and production runs
in Asia/Kolkata while dev and CI run in UTC, so ``astimezone()`` on a naive value
is the same "right in test, wrong in production" defect class as this module.
Every function here returns a timezone-AWARE datetime or ``None``.

Stdlib only, no ``src`` imports: this is shared infrastructure that paid modules
(``src/pipeline/``, stripped from Community builds) and free modules both use,
and ``tools/`` scripts import it without pulling the platform in.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

__all__ = ["normalize_iso8601", "parse_iso8601", "parse_iso8601_or_none"]


# Python 3.10's ``fromisoformat`` accepts a fractional-second part of EXACTLY 3
# or 6 digits and nothing else, so ``.9`` and ``.9051234`` both raise there.
# Padding/truncating to 6 is lossless for anything we can represent (datetime
# resolution is microseconds) and valid on every version.
_FRACTIONAL_DIGITS = 6

# The ISO-8601 shapes we accept. Deliberately explicit rather than "whatever the
# interpreter tolerates" — an input this does not match is passed through
# untouched and left to ``fromisoformat`` to accept or reject, so this can only
# widen what parses, never narrow it.
#
# A FRACTION MAY ONLY FOLLOW SECONDS (qa-audit F2, second pass). ISO-8601 also
# allows a fractional HOUR or MINUTE — ``2026-09-01T18.5`` means 18:30 — and
# this pattern used to match those and pad the fraction to six digits, giving
# ``2026-09-01T18.500000``. Python 3.11+ rejects that outright, but 3.10 reads
# it as HOUR 18 plus 500000 MICROSECONDS: ``18:00:00.500000``, thirty minutes
# adrift, with no exception anywhere.
#
# That is categorically worse than the other residual divergences, which are
# all reject-vs-accept. It is a plausible wrong VALUE, on the interpreter
# production runs, in silence — the exact failure mode this module exists to
# kill. And it is reachable from outside: ``get_sla_at_risk`` and
# ``get_incident_sla`` parse SLA due dates that arrive over the API.
#
# Splitting the time alternation so a fraction can only attach to ``HH:MM:SS``
# means both interpreters now REJECT ``T18.5`` and ``T18:38.5`` identically.
# Refusing to guess beats guessing wrong.
_ISO_SHAPE = re.compile(
    r"""^
    (?P<date>\d{4}-\d{2}-\d{2})
    (?:
        [Tt ]                                       # date/time separator
        (?:
            (?P<time_sec>\d{2}:\d{2}:\d{2})         # HH:MM:SS ...
            (?:[.,](?P<frac>\d+))?                  # ... and ONLY here, a fraction
          |
            (?P<time_min>\d{2}(?::\d{2})?)          # HH | HH:MM, never fractional
        )
        (?P<tz>[Zz]|[+-]\d{2}(?::?\d{2}(?::?\d{2})?)?)?
    )?
    $""",
    re.VERBOSE,
)


# A fractional HOUR or MINUTE in extended format: ``2026-09-01T18.5``,
# ``2026-09-01T18:38.5``. Anchored, and it cannot match ``HH:MM:SS.ffffff``
# because a fraction there is preceded by a THIRD colon-delimited field.
#
# THIS IS THE ONE SHAPE :func:`parse_iso8601` REFUSES OUTRIGHT, and the only
# place this module narrows rather than widens what parses.
#
# Measured on real CPython builds across the WHOLE supported window (3.10-3.13;
# 3.14 cannot install the pinned deps, so it does not get a vote):
#
#     input                  3.10              3.11 / 3.12 / 3.13
#     2026-09-01T18.5        ValueError        18:00:00.500000
#     2026-09-01T18.500000   18:00:00.500000   18:00:00.500000
#     2026-09-01T18:38.5     ValueError        18:38:00.500000
#
# Those are not merely divergent, they are WRONG. ISO-8601 defines ``18.5`` as
# a fractional HOUR, i.e. 18:30; every one of those answers reads the fraction
# as sub-second and lands thirty minutes adrift, with no exception raised
# anywhere. Note the middle row: ``T18.500000`` is silently misread on ALL FOUR
# supported interpreters. Not one of them refuses it — 3.14 does, and 3.14 is
# the one version nobody can actually run. So without the check below there is
# no supported configuration in which this input is safe.
#
# That is this module's founding defect with the polarity reversed: instead of
# raising where it runs and passing where it is tested, it answers wrongly
# everywhere and says nothing.
#
# So it is refused explicitly. A ``ValueError`` reaches the caller's existing
# handler; a plausible timestamp thirty minutes out reaches the client's SLA
# report. Refusing to guess beats guessing wrong.
#
# HOW IT WOULD BE REACHED (qa-audit L4 — the earlier note here overstated this).
# The SLA columns are not caller-supplied. Their only writers are
# ``set_incident_sla`` and ``record_tier_handoff``, both fed by
# ``SLAManager``-computed ``.isoformat()`` values; ``get_sla_at_risk`` and
# ``get_incident_sla`` SERVE those values over the API, they do not accept
# them. So this is not a live inbound-API risk today. It is a guard on a
# TEXT column with more than one potential writer and a shared parser used by
# 25 call sites, several of which do read genuinely external input.
#
# TWO KNOWN, ACCEPTED GAPS in the refusal, recorded so they are not
# rediscovered as findings (round-2 audit; judged not worth fixing, and I
# agree):
#
#   1. ``.match(value.strip())`` -> ``.match(value)`` survives the whole
#      ``no_db`` suite on 3.11. A LEADING-whitespace input would slip past the
#      refusal and then be misparsed. Not fixed because no producer emits a
#      padded timestamp, and the ``.strip()`` here would have to disagree with
#      the one in :func:`normalize_iso8601` for it to matter. If you ever
#      remove the strip from one, remove it from both.
#   2. ``.match`` -> ``.fullmatch`` survives on 3.10 but is killed on 3.11.
#      ``match`` is correct: the offset/suffix follows the fraction, so the
#      pattern is deliberately a prefix test. The asymmetry is only because
#      3.10 rejects more of the trailing forms anyway.
_FRACTIONAL_HOUR_OR_MINUTE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt ]\d{2}(?::\d{2})?[.,]\d+")


def normalize_iso8601(raw: str) -> str:
    """Rewrite the EXTENDED-format ISO-8601 shapes DHRUVA's sources emit into
    the subset every supported interpreter accepts.

    Pure and total: never raises, never touches the clock. An input that this
    does not recognise is returned unchanged, so THIS FUNCTION can only ever
    widen what parses. (:func:`parse_iso8601` has exactly one refusal on top —
    the fractional hour/minute described below — because passing that shape
    through is what lets the interpreter answer it wrongly.)

    Normalisations applied, each one a shape that Python 3.10 REJECTS:

    * ``Z`` / ``z`` suffix          -> ``+00:00``
    * ``+0000`` / ``-0530``         -> ``+00:00`` / ``-05:30``  (Wazuh)
    * ``+00``                       -> ``+00:00``  (Postgres ``::text``)
    * ``,905`` decimal comma        -> ``.905``
    * ``.9`` / ``.9051234``         -> ``.900000`` / ``.905123`` (exactly 6)
    * a space date/time separator   -> ``T``

    An offset that is already ``+HH:MM`` and a fractional part that is already 6
    digits are left alone, so anything produced by our own ``.isoformat()``
    round-trips byte-identically.

    WHAT THIS DOES *NOT* DO (qa-audit F2)
    -------------------------------------
    This is **not** full ISO-8601 parity between interpreters, and it is not
    trying to be. The pattern above matches only the EXTENDED calendar format
    (``YYYY-MM-DD``, hyphens and colons present). TWO shapes are passed through
    untouched and still behave differently across the supported window
    (measured on real 3.10.20 / 3.11.15 / 3.12.13 / 3.13.14):

    ==================================  ========  =============
    shape                                3.10      3.11 - 3.13
    ==================================  ========  =============
    ``20260901`` / ``20260901T183813``   reject    accept   (basic format)
    ``2026-W36-2``                       reject    accept   (week date)
    ==================================  ========  =============

    qa-audit L2: ``2026-09-01T24:00:00`` used to be a third row here, claimed
    as "3.10 reject / 3.11+ accept". That is wrong. It raises ``ValueError`` on
    3.10, 3.11, 3.12 AND 3.13 alike — it is not divergent anywhere in the
    supported window. Only 3.14 accepts it, and 3.14 cannot install the pinned
    dependencies at all. The row was inferred from 3.14's behaviour rather than
    measured on 3.11, which is the same over-generalisation about 3.11 that CI
    caught once already in this PR. Every claim in this file is now measured on
    a real build of each supported minor.

    Neither remaining shape is emitted by Wazuh, OpenSearch, the Wazuh Manager
    API, Postgres' ``::text`` cast, our own ``.isoformat()`` or any inbound
    webhook we have seen, so chasing them would add grammar — and risk — for no
    measured input. Both are a clean REJECT on 3.10: the caller gets a
    ``ValueError`` and the existing handler, not a wrong answer. If one ever
    does turn up, widen ``_ISO_SHAPE`` here rather than hand-fixing the call
    site.

    THE ONE THAT WAS DIFFERENT, AND IS NOW REFUSED
    ----------------------------------------------
    A fractional HOUR or MINUTE (``2026-09-01T18.5``, ``2026-09-01T18:38.5``)
    used to be in that table and did not belong there. The others are
    reject-versus-accept; that one is **silently wrong versus reject** — see
    ``_FRACTIONAL_HOUR_OR_MINUTE`` above for the matrix, measured across the
    whole supported window. 3.11, 3.12 and 3.13 all answer ``18:00:00.500000``
    for ``18.5``, which ISO-8601 defines as 18:30, and 3.10 answers the same
    for ``18.500000``. No supported interpreter refuses that second form.

    Two changes close it. This function no longer matches a fraction unless it
    follows ``HH:MM:SS``, so it can no longer MANUFACTURE the shape by padding
    ``.5`` to ``.500000``; and :func:`parse_iso8601` refuses the shape outright,
    because not manufacturing it is not enough when the interpreter misreads
    what the caller wrote. That refusal is the single point where this module
    narrows what parses, and it is deliberate: a ``ValueError`` reaches the
    caller's existing handler, a timestamp thirty minutes out reaches the
    client's SLA report.

    See ``tests/test_timestamps_h116.py``.
    """
    if not isinstance(raw, str):
        return raw
    s = raw.strip()
    m = _ISO_SHAPE.match(s)
    if not m:
        return s

    out = m.group("date")
    time_part = m.group("time_sec") or m.group("time_min")
    if time_part is None:
        return out
    out += "T" + time_part

    frac = m.group("frac")
    if frac:
        # Truncate (never round) then right-pad: ``.9`` is 900000us, and
        # sub-microsecond precision is dropped exactly as 3.11+ drops it.
        out += "." + frac[:_FRACTIONAL_DIGITS].ljust(_FRACTIONAL_DIGITS, "0")

    tz = m.group("tz")
    if tz:
        if tz in ("Z", "z"):
            out += "+00:00"
        else:
            sign, digits = tz[0], tz[1:].replace(":", "")
            # digits is 2 (HH), 4 (HHMM) or 6 (HHMMSS) long.
            digits = digits.ljust(4, "0")
            parts = [digits[i:i + 2] for i in range(0, len(digits), 2)]
            out += sign + ":".join(parts)
    return out


def parse_iso8601(value: str) -> datetime:
    """Parse an externally-sourced ISO-8601 string to an aware UTC datetime.

    Raises ``TypeError`` for a non-string and ``ValueError`` for a string that
    is not a timestamp — the same exceptions ``fromisoformat`` raises, so
    callers' existing ``except (ValueError, TypeError)`` handlers keep working.

    One deliberate NARROWING, and the only one in this module: a fractional
    hour or minute (``2026-09-01T18.5``) raises ``ValueError`` here even though
    3.10 and 3.11 would happily parse it — because what they parse it INTO is
    wrong by thirty minutes, silently. See ``_FRACTIONAL_HOUR_OR_MINUTE``.

    A value with no offset is read as UTC (see the module docstring). A value
    that CARRIES an offset keeps it — the instant is what matters and every
    caller compares against an aware datetime, so re-projecting ``-05:30`` onto
    UTC would only throw away information the source gave us. Either way the
    result is aware, so it is always directly comparable with
    ``datetime.now(timezone.utc)``.
    """
    if not isinstance(value, str):
        raise TypeError(
            f"expected an ISO-8601 string, got {type(value).__name__}")
    if _FRACTIONAL_HOUR_OR_MINUTE.match(value.strip()):
        # See _FRACTIONAL_HOUR_OR_MINUTE. Every supported interpreter
        # (3.10-3.13) misreads at least one of these shapes as sub-second
        # precision — "18.5" becomes 18:00:00.5, thirty minutes adrift — and
        # none of them raises. Refused so the answer is the same everywhere,
        # and so that the answer is not silently wrong.
        raise ValueError(
            f"fractional hour/minute is not supported: {value.strip()!r} "
            f"(Python 3.10-3.13 misread it as sub-second precision rather "
            f"than as a fraction of an hour; use HH:MM:SS with a fractional "
            f"second)")
    dt = datetime.fromisoformat(normalize_iso8601(value))
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def parse_iso8601_or_none(value) -> Optional[datetime]:
    """:func:`parse_iso8601`, but ``None`` instead of an exception.

    For the many call sites whose documented contract is already "``None``
    means we could not tell" — a malformed timestamp on one row must not take
    down the query behind it.
    """
    try:
        return parse_iso8601(value)
    except (ValueError, TypeError):
        return None
