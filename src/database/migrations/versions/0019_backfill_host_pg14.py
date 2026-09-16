"""WO-H124 follow-up — back-fill the host on PostgreSQL 14, which 0018 could not

Migration 0018 added `agent_name` and back-filled it out of `enrichment_summary`.
The backfill is guarded by `pg_input_is_valid`, because `enrichment_summary` is
a TEXT column that "may be null, empty, or malformed" and an unguarded `::jsonb`
cast would abort the whole upgrade on a single bad row.

`pg_input_is_valid` is **PostgreSQL 16+**. The live tenant runs **14.24**. So
0018 announced the skip and did the honest thing:

    [0018] agent_name backfill SKIPPED — PostgreSQL 16+ required

and left ~50,000 historical rows with `agent_name = NULL`. New decisions carry
the host; the history does not, so correlation over past data cannot work.

WHY THIS WAS NOT CAUGHT BEFORE DEPLOY. The 0018 rehearsal restored a copy of the
tenant's data onto the *local* PostgreSQL 18 and passed. Copying the DATA is not
reproducing the ENVIRONMENT — the version floor was never checked, and the
CHANGELOG confidently stated a PG16 requirement that production does not meet.
This migration was written and rehearsed against a real 14.24 instance.

HOW IT WORKS WITHOUT pg_input_is_valid. A small PL/pgSQL helper attempts the
cast and returns NULL on any error, so one malformed blob costs that row and
nothing else. That is slower than a planner-level guard — each call opens a
subtransaction — so the candidate set is narrowed first with a cheap prefix
test. On 50k rows the cost is irrelevant.

THIS MIGRATION MAKES TWO PASSES, AND THE SECOND ONE IS NOT ABOUT PG14.

  1. BACKFILL — rows where `agent_name IS NULL`, exactly what 0018 skipped.

  2. RE-NORMALISE — rows 0018 already populated, on an install that WAS on
     PG16+ and therefore ran 0018's backfill successfully. 0018 trimmed with
     one-argument `btrim()`, which strips **spaces only**, while `_coerce_host`
     in src/database/store.py trims with Python's `str.strip()`. So on those
     installs a blob carrying `"\r\nweb-77\r\n"` was stored verbatim while
     `save_decision` stores the same machine as `"web-77"` — one host, two
     correlation keys, split by row age. Worse, a blob carrying
     `"\tunknown\n"` passed 0018's sentinel filter (because one-arg `btrim`
     did not remove the tab or the newline), so a PLACEHOLDER could land in
     the correlation key. Pass 2 rewrites those to their properly-trimmed form
     and puts sentinels back to NULL. It cannot run in 0018 — 0018 has already
     been applied on real installs — and pass 1's `WHERE agent_name IS NULL`
     would never revisit them. It is idempotent and leaves an
     already-clean value untouched, including one an operator fixed by hand.

ONE DEFINITION OF "TRIM". `_TRIM_CHARS` below is the single source of truth for
what counts as surrounding whitespace, and every trim in this file uses it.
Its character set is deliberately NOT the full set Python's `str.strip()`
removes. Two separate residuals, and they have different reasons:

  * The 22 Unicode space characters (U+2000-U+200A, U+3000, ...) are omitted
    because `chr(8192)` RAISES "requested character too large for encoding" on
    a LATIN1 or SQL_ASCII database — measured, not assumed. Widening to full
    `str.strip()` parity would trade this hardening for a migration that aborts
    on a non-UTF8 install.
  * U+001C-U+001F (the C0 separators) and U+0085 (NEL) are Latin-1 representable
    and could have been included at no cost. They are left out because no Wazuh
    `agent_name` has ever been observed carrying one. That is a judgement about
    the data, NOT an encoding constraint — do not cite the LATIN1 reason for it.

The seven characters here (space, TAB, LF, VT, FF, CR, NBSP) are valid in every
server encoding. One caveat: under SQL_ASCII `chr(160)` is a BYTE, not the NBSP
character, so trimming a UTF-8 NBSP (0xC2 0xA0) there would strip 0xA0 and leave
a dangling 0xC2. Not reachable on a UTF-8 database, which is what every DHRUVA
install uses; recorded so the next reader does not have to re-derive it.

Version-agnostic on purpose: this runs correctly on 14, 16 and 18. An install
that already got 0018's backfill simply finds nothing left to do in pass 1
(`WHERE agent_name IS NULL`) and gets its 0018 skew corrected by pass 2.

Reversible: downgrade does nothing. It cannot un-extract a value that was
already present in `enrichment_summary`, and dropping the column is 0018's job.

Revision ID: 0019
Revises: 0018
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0019"
down_revision: Union[str, None] = "0018"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

#: Kept in lockstep with `_HOST_SENTINELS` in src/database/store.py and with
#: 0018. A placeholder host persisted into the column becomes a CORRELATION KEY
#: shared by every agentless alert.
_HOST_SENTINELS = ("", "unknown", "none", "null", "n/a", "-")

#: THE ONLY DEFINITION OF "SURROUNDING WHITESPACE" IN THIS FILE — see the module
#: docstring for why the set stops at NBSP. Written as `chr()` calls so the
#: migration source stays pure ASCII; the one-argument `btrim(text)` that 0018
#: used strips U+0020 AND NOTHING ELSE, which is the defect this replaces.
_TRIM_CHARS = "' ' || chr(9) || chr(10) || chr(11) || chr(12) || chr(13) || chr(160)"

_FN = "_h124_safe_json_host"
_FN_OK = "_h124_json_parses"


def upgrade() -> None:
    # NOT OPTIONAL — see 0015 and 0018. agent_decisions carries FORCE ROW LEVEL
    # SECURITY, the migration role has rolbypassrls = false, and alembic sets no
    # tenant context, so an unguarded UPDATE matches ZERO rows and commits
    # happily.
    op.execute("SET LOCAL app.tenant_id = '__CROSS_TENANT__'")

    bind = op.get_bind()
    sentinels = list(_HOST_SENTINELS)

    # The cast, made safe without pg_input_is_valid. One bad blob costs its own
    # row instead of the whole migration.
    #
    # THE TRIM LIVES IN HERE, not at the call sites. The previous cut trimmed in
    # three separate places with three separate expressions; keeping one
    # definition is what stops them drifting apart again. Returns NULL — not the
    # empty string — for a blob whose host is nothing but whitespace, so "no
    # usable host" has exactly one spelling everywhere downstream.
    op.execute(f"""
        CREATE OR REPLACE FUNCTION {_FN}(txt text)
        RETURNS text AS $$
        BEGIN
            RETURN nullif(btrim((txt::jsonb ->> 'agent_name'), {_TRIM_CHARS}), '');
        EXCEPTION WHEN OTHERS THEN
            RETURN NULL;
        END $$ LANGUAGE plpgsql;
    """)

    # Only used for the deploy-time breakdown below: separates "the blob is not
    # parseable JSON" from "the blob parsed but carries no usable host", which
    # the helper above deliberately spells the same way (NULL).
    op.execute(f"""
        CREATE OR REPLACE FUNCTION {_FN_OK}(txt text)
        RETURNS boolean AS $$
        BEGIN
            PERFORM txt::jsonb;
            RETURN true;
        EXCEPTION WHEN OTHERS THEN
            RETURN false;
        END $$ LANGUAGE plpgsql;
    """)

    # ── PASS 1: the backfill 0018 could not run ──────────────────────────────
    backfilled = bind.execute(sa.text(f"""
        UPDATE agent_decisions
           SET agent_name = {_FN}(enrichment_summary)
         WHERE agent_name IS NULL
           AND enrichment_summary IS NOT NULL
           -- cheap narrowing first: the helper opens a subtransaction per
           -- call, so do not call it on rows that cannot possibly match.
           -- btrim WITH THE FULL CHARACTER SET — a blob that begins with a
           -- newline is still an object, and the one-argument form skipped it.
           AND left(btrim(enrichment_summary, {_TRIM_CHARS}), 1) = '{{'
           AND {_FN}(enrichment_summary) IS NOT NULL
           AND lower({_FN}(enrichment_summary)) <> ALL (:sentinels)
    """), {"sentinels": sentinels}).rowcount
    # Says WHY the rows were NULL, not which server this is. `alembic_version`
    # survives a dump/restore, so a tenant upgraded 14 -> 18 after 0018 skipped
    # arrives here with the backfill still outstanding and runs it ON 18 --
    # naming a version in this line would contradict the server it prints on.
    print("[0019] backfilled %s host name(s) that 0018 left NULL" % backfilled)

    # A bare rowcount cannot tell "correctly skipped" from "silently swallowed
    # by WHEN OTHERS". Two numbers can: a parse regression moves the first one,
    # a healthy estate full of agentless alerts moves the second.
    left_null = bind.execute(sa.text(f"""
        SELECT count(*) FILTER (
                   WHERE left(btrim(enrichment_summary, {_TRIM_CHARS}), 1) = '{{'
                     AND NOT {_FN_OK}(enrichment_summary)) AS unparseable,
               count(*) FILTER (
                   WHERE lower({_FN}(enrichment_summary)) = ANY (:sentinels)
               ) AS sentinel
          FROM agent_decisions
         WHERE agent_name IS NULL
           AND enrichment_summary IS NOT NULL
    """), {"sentinels": sentinels}).one()
    print("[0019] still NULL: %s row(s) whose blob is unparseable JSON, "
          "%s row(s) whose blob names a placeholder host" % tuple(left_null))

    # ── PASS 2: correct 0018's one-argument-btrim skew ───────────────────────
    #
    # Only reaches rows 0018 populated on a PG16+ install. On the PG14 tenant
    # 0018 wrote nothing, so this reports 0. Idempotent by construction: after
    # it runs, every value equals its own trim and none is a sentinel, so the
    # WHERE matches nothing on a second pass.
    renormalised = bind.execute(sa.text(f"""
        UPDATE agent_decisions
           SET agent_name = CASE
                 WHEN lower(btrim(agent_name, {_TRIM_CHARS})) <> ALL (:sentinels)
                 -- nullif is belt-and-braces: '' is already a sentinel, but a
                 -- correlation key is not the place to depend on that.
                 THEN nullif(btrim(agent_name, {_TRIM_CHARS}), '')
                 -- A placeholder goes back to NULL rather than being stored
                 -- tidily. "Unknown host" must not be a joinable value.
                 ELSE NULL
               END
         WHERE agent_name IS NOT NULL
           AND (agent_name <> btrim(agent_name, {_TRIM_CHARS})
                OR lower(agent_name) = ANY (:sentinels))
    """), {"sentinels": sentinels}).rowcount
    print("[0019] re-normalised %s host name(s) left skewed by 0018's "
          "space-only btrim" % renormalised)

    # Dropped on the SUCCESS path only, deliberately — there is no `finally`.
    #
    # env.py wraps the whole run in ONE transaction and PostgreSQL DDL is
    # transactional, so a failed run rolls the CREATE back on its own: measured
    # after a forced failure, pg_proc holds no row for either helper and
    # alembic_version is still 0018. A `finally` here cannot prevent a leak that
    # cannot happen, and it DOES cost the error message — the DROP raises
    # InFailedSqlTransaction inside the aborted transaction, and that becomes
    # the last line upgrade.sh, CI and a tailing operator read, burying the
    # real cause a hundred lines up.
    op.execute(f"DROP FUNCTION IF EXISTS {_FN}(text)")
    op.execute(f"DROP FUNCTION IF EXISTS {_FN_OK}(text)")

    # Back to fail-closed for the rest of the run. env.py wraps every revision
    # in ONE transaction, so a SET LOCAL left in place is inherited by 0020+.
    op.execute("SET LOCAL app.tenant_id = ''")


def downgrade() -> None:
    """Deliberately a no-op.

    This migration only COPIES a value that already exists inside
    `enrichment_summary` into a column, and re-trims values 0018 wrote. There is
    nothing to undo that would not also destroy information 0018's downgrade
    already handles by dropping the column outright. Setting `agent_name` back
    to NULL here would be worse than doing nothing: it would discard hosts
    recorded by `save_decision` since the upgrade, which were never part of this
    backfill. Re-introducing the whitespace pass 2 removed is not a
    restoration — it is putting a second correlation key back.
    """
    pass
