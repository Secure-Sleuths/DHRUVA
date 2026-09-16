"""WO-H129 — the minimum PostgreSQL server version DHRUVA supports, enforced.

WHY THIS MODULE EXISTS
======================

Migration ``0018_decision_rule_level_and_host`` backfills ``agent_decisions.host``
behind a ``pg_input_is_valid`` guard. That function is **PostgreSQL 16+**. On an
older server 0018 prints

    [0018] agent_name backfill SKIPPED — PostgreSQL 16+ required

and moves on. That is honest at the migration, and completely silent everywhere
else: the install boots, the dashboard renders, and ~50 000 decision rows simply
have no host, so nothing in that tenant's history can be correlated by host. A
tenant running 14.24 is exactly what happened; it went unnoticed for months and
cost a follow-up migration, two audit rounds and a maintenance window. (Which
tenant, and the dates, are in docs/PROGRESS.md — WO-H124b and WO-H127. That file
is not shipped; this one is, to every client, so it does not name anybody.)

Nothing in the codebase checked the server version — not ``main.py``, not
``_verify_schema()``, not alembic's ``env.py`` — and ``deploy.sh`` installed the
UNVERSIONED ``postgresql`` apt meta-package, which on Ubuntu 22.04 resolves to
PostgreSQL 14. So the next client installed on 22.04 would have got the identical
failure.

WHY THE FLOOR IS 16 AND NOT SOMETHING ELSE
==========================================

16 is the honest minimum, both directions:

  * **Not lower.** ``pg_input_is_valid`` (0018) is 16+. Anything below the floor
    cannot run that backfill, which is the concrete defect above.
  * **Not higher.** 16 is what CI actually runs (``tests/conftest.py`` and
    ``docker-compose.yml`` both pin ``postgres:16-alpine``). Claiming 17 or 18
    would be claiming support for versions no test ever exercises.

PostgreSQL 14 additionally reaches end of life in **November 2026**, so a client
installed on it today is handed a component that stops receiving security fixes
within months.

TWO BEHAVIOURS, DELIBERATELY DIFFERENT
======================================

``decide()`` below returns one of three actions, and the split is the whole point:

  * ``ACTION_OK``      — at or above the floor. Boot normally.
  * ``ACTION_REFUSE``  — below the floor **and the database holds no operational
    history**. Refuse to start. Nothing is lost by refusing, and letting it
    proceed is precisely how the incident above happened: a fresh install on 14
    that looked healthy for months.
  * ``ACTION_WARN``    — below the floor **but the database is already populated**.
    Start, and complain at ERROR level in the log plus in ``/api/health``.
    A hard refusal here would brick a running client the moment they restart on
    an old server — a worse outcome than continuing to run on it, and it would
    turn "your Postgres is old" into "your SOC is down".

WHY THE LOG NAG IS THROTTLED AND THE HEALTH FIELD IS NOT
========================================================

The alert loop polls every ~10 s, so an ERROR on every cycle is ~8 640 lines a
day about a condition that changes at most once — and an ERROR that repeats
8 640 times a day teaches the operator to filter it, which defeats the point of
nagging at all. This repo has already paid to fix that exact defect twice:
WO-H105 (the heartbeat check paging about healthy servers twelve times an hour)
and WO-H107 (the EPS check announcing every cycle). So the log line is
**attention**, and it is rate-limited — first detection, every state change,
and at most once an hour after that (``LOG_REPEAT_SECONDS``).

``/api/health`` is **state**, and it is NOT throttled at any level:
``health_state()`` reads the recorded verdict on every request, for as long as
the condition lasts. Machine readers poll it and need the answer to be true
right now. A quiet log must never become a quiet health field.

There is deliberately **no environment-variable bypass**. A silent way to run
unsupported is how this class of problem hides in the first place.

USED BY
=======
  * ``src/database/store.py`` — ``_verify_schema()``, at boot.
  * ``main.py`` — ``--migrate`` pre-flight, and the throttled nag in the alert
    loop.
  * ``src/api/routes/health.py`` — the ``db_server_version`` condition.
  * ``deploy.sh`` — via the ``__main__`` CLI below, so the shell installer and
    the runtime read the SAME number and cannot drift.

This module is deliberately **stdlib-only** at import time (psycopg is imported
lazily, inside the one function that needs its error classes) so ``deploy.sh``
can run it as a plain script before the venv exists.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass
from typing import Optional

#: The minimum PostgreSQL MAJOR version DHRUVA supports. Single source of truth
#: — imported by the store, main.py, the health route and the test suite, and
#: read by deploy.sh through this module's CLI. Do not repeat the literal.
MIN_PG_MAJOR = 16

#: Why 16 (short form, for operator-facing messages). The long form is the
#: module docstring above.
FLOOR_RATIONALE = (
    "migration 0018 needs pg_input_is_valid (PostgreSQL 16+) to backfill "
    "agent_decisions.host, and 16 is the version CI actually tests"
)

#: Where an operator goes when they hit the floor. WO-H127's dump/restore
#: runbook is the rehearsed procedure.
UPGRADE_RUNBOOK = "docs/POSTGRES-VERSION.md"

#: Health-endpoint field name. Named here so the route and the tests agree.
HEALTH_FIELD = "db_server_version"

#: How long the unsupported-server ERROR line stays quiet between repeats while
#: the condition is UNCHANGED. First detection and every state change ignore it.
#: One hour: often enough that the line is still in front of whoever is looking
#: at today's log, rare enough (24 lines/day, against 8 640 at a 10 s poll) that
#: nobody builds a filter for it. See the module docstring for why this is
#: throttled and ``/api/health`` is not.
LOG_REPEAT_SECONDS = 3600.0

ACTION_OK = "ok"
ACTION_REFUSE = "refuse"
ACTION_WARN = "warn"

#: Tables whose contents mean "this install has operational history worth not
#: bricking". Both are RLS-scoped, so the probe sets the cross-tenant GUC first
#: — see ``probe_has_history``. ``agent_decisions`` is the table 0018's backfill
#: targets, which makes it the honest signal for "there is data 0018 was
#: supposed to have filled in".
HISTORY_TABLES = ("agent_decisions", "incidents")

#: The GUC value that satisfies the 0006 RLS policies for an admin/maintenance
#: read. Mirrors ``store._CROSS_TENANT`` — kept as a literal here rather than
#: imported so this module stays importable without psycopg.
_CROSS_TENANT_GUC = "__CROSS_TENANT__"


# ─── Version parsing ────────────────────────────────────────────────────────

def major_from_version_num(version_num: int) -> int:
    """Major version from the ``server_version_num`` GUC.

    PostgreSQL 10+ uses MMmmmm (160014 -> 16). Pre-10 used MMmmpp (90624 ->
    9.6); integer-dividing those by 10000 collapses them to ``9``, which is far
    below any floor we will ever set and therefore fails the check — the right
    answer, reached by the same arithmetic.
    """
    return int(version_num) // 10000


def parse_major(version_text: str) -> Optional[int]:
    """Major version from a human version string, or ``None`` if unparseable.

    Handles everything Postgres and apt actually emit:
    ``"16.14 (Ubuntu 16.14-1.pgdg26.04+1)"``, ``"14.24"``, ``"18beta1"``,
    ``"16"``. Used for the ``deploy.sh`` path, where all we have is the output
    of ``psql --version`` / ``pg_lsclusters``.
    """
    if version_text is None:
        return None
    digits = ""
    for ch in str(version_text).strip():
        if ch.isdigit():
            digits += ch
        else:
            break
    if not digits:
        return None
    return int(digits)


def meets_floor(major: Optional[int]) -> bool:
    """True if ``major`` is at or above the supported floor."""
    return major is not None and major >= MIN_PG_MAJOR


# ─── Server interrogation ───────────────────────────────────────────────────

def read_server_version(conn) -> tuple[Optional[str], Optional[int]]:
    """Return ``(server_version_text, server_version_num)`` for a live conn.

    Uses ``current_setting`` rather than ``SHOW`` for one reason worth writing
    down: ``current_setting`` is an ordinary function, so a test can shadow it
    through ``search_path`` and make a REAL server report a below-floor version.
    That is what lets the refusal path be exercised on any server, including CI,
    which only ever has 16. It is the same technique
    ``tests/test_pg14_host_backfill_h124b.py`` uses on ``pg_input_is_valid``.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT current_setting('server_version') AS v, "
                    "current_setting('server_version_num') AS n")
        row = cur.fetchone()
    if row is None:
        return None, None
    # The store's pool uses dict_row; alembic/raw callers may not.
    if isinstance(row, dict):
        text, num = row.get("v"), row.get("n")
    else:
        text, num = row[0], row[1]
    try:
        num_i = int(num)
    except (TypeError, ValueError):
        num_i = None
    return text, num_i


def _log_probe_warning(event: str, exc: BaseException) -> None:
    """WARNING from inside the history probe, without breaking the probe.

    ``structlog`` is imported HERE and not at module scope on purpose: this
    module is run as a plain script by ``deploy.sh`` before the venv exists
    (see the module docstring), so its import-time dependency set has to stay
    stdlib-only. The import is cheap and cached after the first call, and the
    whole thing is wrapped because a logging failure must never be the reason a
    version check turns into a boot failure.

    Returns nothing and raises nothing. Deliberately not routed through the
    caller's logger: the probe is called from ``check_connection``, which has no
    logger argument, and threading one through every call site to reach a line
    that fires approximately never is worse than a module-local logger.
    """
    try:
        import structlog
        structlog.get_logger(__name__).warning(
            event, error=str(exc)[:200], error_type=type(exc).__name__)
    except Exception:                                    # pragma: no cover
        pass


def probe_has_history(conn) -> bool:
    """Does this database already hold operational history?

    ``True`` means "populated — warn, do not refuse". Getting this wrong in the
    ``False`` direction is the dangerous one (it would refuse to start a running
    client), so every ambiguous outcome resolves to ``True``.

    RLS IS THE TRAP HERE. Every table in ``HISTORY_TABLES`` carries FORCE ROW
    LEVEL SECURITY (migration 0006). The app role is NOSUPERUSER/NOBYPASSRLS on
    a correct install, and this probe runs on a raw pool connection that has no
    ``app.tenant_id`` set — so an unguarded ``SELECT`` here would return zero
    rows on a fully populated multi-tenant database and we would refuse to boot
    a live SOC. The cross-tenant sentinel (the same one ``store`` uses for admin
    and migration paths) is therefore set on the session first, and the
    session's PREVIOUS scope is restored after (``''`` when there was none).

    Outcomes:
      * a table has at least one row      -> True  (populated)
      * every table exists and is empty   -> False (fresh — safe to refuse)
      * every table is MISSING            -> False (pre-migration empty DB)
      * anything else fails               -> True  (unknown: never brick)
    """
    try:
        from psycopg import errors as pg_errors
        undefined = (pg_errors.UndefinedTable,)
    except Exception:                                    # pragma: no cover
        undefined = ()

    try:
        with conn.cursor() as cur:
            # Save whatever tenant scope this session already carried, so the
            # probe RESTORES it instead of clobbering it to ''. Today there is
            # exactly one call site (a raw pool connection at boot, with nothing
            # set) so this reads NULL and the restore is identical to the old
            # unconditional reset — but a probe that silently drops the caller's
            # tenant context is a landmine for the second call site, and RLS
            # bugs of that shape are the expensive kind. ``true`` is the
            # missing_ok argument: before any set_config the custom GUC is
            # undefined and a one-argument current_setting would RAISE.
            previous_tenant = None
            try:
                cur.execute("SELECT current_setting('app.tenant_id', true) AS t")
                _row = cur.fetchone()
                previous_tenant = (_row.get("t") if isinstance(_row, dict)
                                   else (_row[0] if _row else None))
            except Exception as exc:
                # Cannot read it -> restore the historical '' (fail-closed, the
                # same value store.py uses for "no tenant context").
                _log_probe_warning("pg_version_tenant_guc_read_failed", exc)
                conn.rollback()
            try:
                for table in HISTORY_TABLES:
                    try:
                        # set_config is re-issued per table ON PURPOSE. SET is
                        # transactional: on a non-autocommit connection the
                        # rollback below (after a missing table) would also
                        # discard the GUC, and the next probe would then run
                        # WITHOUT cross-tenant scope and read zero rows on a
                        # populated database.
                        cur.execute(
                            "SELECT set_config('app.tenant_id', %s, false)",
                            (_CROSS_TENANT_GUC,))
                        # EXISTS + LIMIT 1: O(1)-ish, never a full count on a
                        # multi-million-row table at boot.
                        cur.execute(
                            "SELECT EXISTS (SELECT 1 FROM %s LIMIT 1) AS present"
                            % table)
                        row = cur.fetchone()
                        present = (row.get("present") if isinstance(row, dict)
                                   else row[0])
                        if present:
                            return True
                    except undefined:
                        # Table not created yet (pre-migration, i.e. a genuinely
                        # empty database). Postgres aborts the transaction on
                        # error, so clear it before the next probe.
                        conn.rollback()
                        continue
            finally:
                # Restore the caller's scope. '' when there was none — the
                # fail-closed value, matching store.py's "no tenant context".
                try:
                    cur.execute("SELECT set_config('app.tenant_id', %s, false)",
                                (previous_tenant or "",))
                except Exception as exc:
                    # Defence-in-depth: the auditor could not make this fail.
                    # But if it ever does, the session is left holding
                    # __CROSS_TENANT__ — an RLS-bypassing scope on a pooled
                    # connection — and swallowing that silently is precisely
                    # the "nothing downstream saying so" failure this whole
                    # work order exists to end. SAY IT.
                    _log_probe_warning("pg_version_tenant_guc_reset_failed", exc)
    except Exception:
        # Permissions, a dropped connection, anything at all: assume populated.
        # "I could not tell" must never become "refuse to boot".
        return True
    # Every table either existed and was empty, or did not exist at all. Both
    # mean "nothing to lose".
    return False


# ─── The decision ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class VersionVerdict:
    """The outcome of the floor check. ``action`` is one of ACTION_*."""
    action: str
    version_text: Optional[str]
    major: Optional[int]
    required_major: int
    has_history: bool
    message: str

    @property
    def ok(self) -> bool:
        return self.action == ACTION_OK


def _refuse_message(version_text, major) -> str:
    return (
        "PostgreSQL {found} is below the supported floor of {floor}. This "
        "database holds no DHRUVA history, so DHRUVA is refusing to start "
        "rather than silently running degraded: on a server below {floor}, "
        "migration 0018 cannot backfill agent_decisions.host ({why}), and the "
        "result is a decision history that cannot be correlated by host with "
        "nothing anywhere saying so. Install PostgreSQL {floor} or newer and "
        "point DATABASE_URL at it. See {runbook}."
    ).format(found=version_text or "an unknown version",
             floor=MIN_PG_MAJOR, why=FLOOR_RATIONALE, runbook=UPGRADE_RUNBOOK)


def _warn_message(version_text, major) -> str:
    return (
        "PostgreSQL {found} is below the supported floor of {floor}, and this "
        "database ALREADY HOLDS DHRUVA history. DHRUVA is starting anyway — "
        "refusing would take a working SOC offline — but this install is "
        "UNSUPPORTED: migration 0018 cannot backfill agent_decisions.host on "
        "this server ({why}), so host correlation over existing decisions is "
        "incomplete. Upgrade the server to {floor} or newer, then re-run "
        "`python main.py --migrate`. Runbook: {runbook}."
    ).format(found=version_text or "an unknown version",
             floor=MIN_PG_MAJOR, why=FLOOR_RATIONALE, runbook=UPGRADE_RUNBOOK)


def decide(version_text: Optional[str], major: Optional[int],
           has_history: bool) -> VersionVerdict:
    """Pure decision function — no I/O, so the branch table is directly testable.

    An UNPARSEABLE version (``major is None``) is treated as below the floor.
    We cannot confirm support, and quietly assuming support is the exact habit
    this work order exists to end.
    """
    if meets_floor(major):
        return VersionVerdict(
            action=ACTION_OK, version_text=version_text, major=major,
            required_major=MIN_PG_MAJOR, has_history=has_history,
            message="PostgreSQL %s meets the supported floor of %d"
                    % (version_text, MIN_PG_MAJOR))
    if has_history:
        return VersionVerdict(
            action=ACTION_WARN, version_text=version_text, major=major,
            required_major=MIN_PG_MAJOR, has_history=True,
            message=_warn_message(version_text, major))
    return VersionVerdict(
        action=ACTION_REFUSE, version_text=version_text, major=major,
        required_major=MIN_PG_MAJOR, has_history=False,
        message=_refuse_message(version_text, major))


def check_connection(conn) -> VersionVerdict:
    """Interrogate a live connection and decide. The one call sites use."""
    version_text, version_num = read_server_version(conn)
    major = (major_from_version_num(version_num) if version_num is not None
             else parse_major(version_text))
    if meets_floor(major):
        # Skip the history probe entirely on the happy path — no reason to
        # query two tables at every boot on a supported server.
        return decide(version_text, major, has_history=False)
    return decide(version_text, major, has_history=probe_has_history(conn))


# ─── Runtime state (mirrors store.set_rls_backstop_degraded) ────────────────

_unsupported_verdict: Optional[VersionVerdict] = None


def set_unsupported(verdict: Optional[VersionVerdict]) -> None:
    """Record (or clear) the "running on an unsupported server" condition.

    Called once from ``_verify_schema`` at boot. ``None`` clears it, so a
    process that reconnects to an upgraded server stops complaining.
    """
    global _unsupported_verdict
    _unsupported_verdict = verdict


def get_unsupported() -> Optional[VersionVerdict]:
    """The recorded unsupported-server verdict, or ``None`` when supported."""
    return _unsupported_verdict


def is_unsupported() -> bool:
    """True if this process is running against a below-floor server."""
    return _unsupported_verdict is not None


def health_state() -> str:
    """Value for the ``db_server_version`` field of ``/api/health``.

    ``"unsupported"`` when below the floor, ``"ok"`` otherwise. There is no
    ``"unknown"`` produced here — the route supplies that if this call itself
    raises, the same posture as ``rls_backstop``.
    """
    return "unsupported" if _unsupported_verdict is not None else "ok"


#: Throttle state for ``log_if_unsupported``. ``_last_log_key`` is the condition
#: as last ANNOUNCED (``None`` = "supported / nothing announced"); comparing it
#: to the current condition is what makes a state change speak immediately.
#: ``_last_log_at`` is the monotonic reading of the last line emitted.
_last_log_key: Optional[tuple] = None
_last_log_at: Optional[float] = None


def _log_state_key(verdict: Optional[VersionVerdict]):
    """What counts as "the same condition" for throttling purposes.

    The version TEXT is in the key on purpose: a server that went 14 -> 15 is
    still unsupported, but it is a different fact and the operator should hear
    it at once rather than up to an hour later.
    """
    if verdict is None:
        return None
    return (verdict.action, verdict.version_text, verdict.major,
            verdict.required_major)


def reset_log_throttle() -> None:
    """Forget when the nag last fired, so the next detection speaks at once.

    Exists so tests (and any future caller that restarts the loop) can start
    from a known state. It is NOT called from ``set_unsupported``: the state-key
    comparison in ``log_if_unsupported`` is the single mechanism that decides
    when to speak, and a second path into the same behaviour would be a rule
    that cannot be tested by breaking it.
    """
    global _last_log_key, _last_log_at
    _last_log_key = None
    _last_log_at = None


def log_if_unsupported(logger, *, now: Optional[float] = None) -> bool:
    """Emit the ERROR line when running below the floor, RATE-LIMITED.

    Called from the alert loop next to the liveness heartbeat, so the complaint
    keeps coming rather than being a single boot line that scrolls away — which
    is how the 0018 skip stayed invisible for months. But the loop polls every
    ~10 s, and 8 640 identical ERRORs a day is how a line gets filtered, so it
    speaks on:

      * the FIRST detection,
      * any STATE CHANGE (supported -> unsupported, or the version changing),
      * and at most once per ``LOG_REPEAT_SECONDS`` while it is unchanged.

    ``now`` is an injected monotonic clock reading, in seconds — the seam the
    tests drive so the interval can be proven without sleeping through it.
    Production passes nothing and gets ``time.monotonic()``.

    Returns True only when a line was actually emitted, so a caller (and the
    tests) can count them. ``/api/health`` does not go through here and is
    unaffected by any of this.

    ONE ASSUMPTION, WRITTEN DOWN: the caller invokes this EVERY cycle
    regardless of state (``main.py`` does). That is how a supported window is
    observed at all — the state key is recorded here, at the moment the
    condition is looked at, and a flip that happens and reverts entirely
    between two calls was never observed by anything.
    """
    global _last_log_key, _last_log_at

    verdict = _unsupported_verdict
    key = _log_state_key(verdict)
    changed = key != _last_log_key
    _last_log_key = key

    if verdict is None:
        # Supported. Nothing to say — and the key is now None, so if the
        # condition ever comes back it reads as a change and speaks at once.
        return False

    at = time.monotonic() if now is None else float(now)
    if not changed and _last_log_at is not None and \
            at - _last_log_at < LOG_REPEAT_SECONDS:
        return False

    _last_log_at = at
    logger.error("postgres_version_unsupported",
                 server_version=verdict.version_text,
                 server_major=verdict.major,
                 required_major=verdict.required_major,
                 runbook=UPGRADE_RUNBOOK,
                 detail=verdict.message)
    return True


# ─── CLI, for deploy.sh ─────────────────────────────────────────────────────

_USAGE = """usage: pg_version.py --floor
       pg_version.py --check <version-string>
       pg_version.py --meets <version-string>

  --floor            print the minimum supported PostgreSQL major version
  --check VERSION    exit 0 if VERSION meets the floor, 1 if it does not
                     (accepts "16", "16.14", "16.14 (Ubuntu ...)")
  --meets VERSION    print "meets" or "below" on stdout and exit 0 EITHER WAY
"""

# WHY --meets EXISTS ALONGSIDE --check
# ===================================
# --check answers with an EXIT CODE, and an exit code cannot distinguish
#
#     1 = "this version is below the floor"          (the real answer)
#     1 = "this interpreter could not run me at all" (a .pyc with the wrong
#          magic number, a .so invoked as a script, a missing file)
#
# deploy.sh collapsed those two with `--check ... >/dev/null 2>&1`, so on a
# build lane that ships no .py a perfectly supported PostgreSQL 16.14 was
# reported as BELOW major 16 — while the floor lookup right next to it had
# already resolved 16 through its own fallback chain. The installer
# contradicted itself, and on the same-server path that was a hard exit 1.
#
# --meets puts the answer in a WORD ON STDOUT and always exits 0, so "below"
# and "I could not ask" are different observations. A crashed interpreter
# prints nothing; it cannot forge "meets" or "below". deploy.sh's
# pg_version_verdict() reads that word and has an explicit third branch for
# the empty case. --check is kept: it is the ergonomic form for a human at a
# shell, and it is still tested.


def _cli(argv) -> int:
    if len(argv) == 2 and argv[1] == "--floor":
        sys.stdout.write("%d\n" % MIN_PG_MAJOR)
        return 0
    if len(argv) == 3 and argv[1] == "--meets":
        # Machine-readable. Exit 0 in BOTH directions -- see the note above
        # _USAGE for why the answer must not ride on the exit code. An
        # UNPARSEABLE version answers "below", matching decide(): we could not
        # confirm support, and quietly assuming support is the habit this
        # module exists to end.
        sys.stdout.write(
            "meets\n" if meets_floor(parse_major(argv[2])) else "below\n")
        return 0
    if len(argv) == 3 and argv[1] == "--check":
        major = parse_major(argv[2])
        if meets_floor(major):
            sys.stdout.write("PostgreSQL %s meets the floor of %d\n"
                             % (argv[2], MIN_PG_MAJOR))
            return 0
        sys.stderr.write(
            "PostgreSQL %s is below the supported floor of %d (%s)\n"
            % (argv[2], MIN_PG_MAJOR, FLOOR_RATIONALE))
        return 1
    sys.stderr.write(_USAGE)
    return 2


if __name__ == "__main__":          # pragma: no cover - exercised via subprocess
    sys.exit(_cli(sys.argv))
