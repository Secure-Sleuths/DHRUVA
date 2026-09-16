"""WO-H124 — persist the Wazuh rule level and the host on a decision

WHY THIS EXISTS. `agent_decisions` carries `rule_id`, `rule_description`,
`risk_score` and `verdict` — and **not the Wazuh rule level**. The one number
the vendor assigns to every rule is dropped at ingestion.

That omission has already cost a whole build. WO-H123 wanted to ask "did another
**level-10+** alert fire on this host in the last ten minutes?" — the natural way
to express corroboration — and could not. It substituted `escalated`, which is
DHRUVA's own judgement, and the measurement killed it: the founding case came
back "corroborated" by four failed logins and the Windows licensing service, at a
base rate of 0.94. A gate that opens 94% of the time is not a gate. The
substitution was forced by this missing column.

The host is the second half of the same problem. `agent_name` lives inside the
`enrichment_summary` JSON blob, so any correlation by host is a `::jsonb ->>`
extraction with no index behind it — and that extraction throws on a single
malformed row, which is how one bad blob could have disabled an entire code path
estate-wide.

TWO COLUMNS, TWO DIFFERENT BACKFILL ANSWERS — THE DISTINCTION MATTERS.

  rule_level   NOT backfilled. The value was never stored; there is nothing to
               recover and inventing one would fabricate vendor severity.
               Historical rows are NULL, and NULL means "recorded before we
               listened" — it NEVER means level 0. A consumer that coalesces
               this to 0 turns every historical alert into the quietest possible
               rule, which is the opposite of the truth for the loud ones.

  agent_name   BACKFILLED, and that is not a contradiction. The value IS already
               stored, inside enrichment_summary. Copying it into a column is
               EXTRACTION, not invention — the same fact, made queryable and
               indexable. Rows whose blob is absent or unparseable are left NULL
               rather than guessed at.

DEPLOY NOTE — NOT OPTIONAL from this release onward: `save_decision` writes both
columns, so a Python-only hand deploy that skips `alembic upgrade head` makes
every decision write fail with UndefinedColumn. `scripts/upgrade.sh` runs alembic
and aborts on failure.

Reversible: downgrade drops the index and both columns. Nothing else is touched.

Revision ID: 0018
Revises: 0017
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0018"
down_revision: Union[str, None] = "0017"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_HOST_INDEX = "idx_decisions_agent_name_created"

#: Kept in lockstep with `_HOST_SENTINELS` in src/database/store.py, which
#: guards the write path. Duplicated rather than imported: a migration that
#: imports application code breaks the moment that code is refactored, and this
#: file must still run against a database whose app version has moved on. A test
#: asserts the two lists agree.
_HOST_SENTINELS = ("", "unknown", "none", "null", "n/a", "-")


def upgrade() -> None:
    # Statements issued SEPARATELY, not as one blob — see 0010, where a
    # multi-statement op.execute() applied the DDL, skipped the trailing DML,
    # and reported success on a live install.
    #
    # Both are NULLABLE with no default, so each is a catalog-only change in
    # PostgreSQL: no table rewrite on a 47k-row table.
    op.execute("ALTER TABLE agent_decisions ADD COLUMN IF NOT EXISTS rule_level INTEGER")
    op.execute("ALTER TABLE agent_decisions ADD COLUMN IF NOT EXISTS agent_name TEXT")

    # EXTRACTION, not invention — see the module docstring.
    #
    # ⚠ SET LOCAL IS NOT OPTIONAL, AND THIS REPO HAS ALREADY BEEN BITTEN.
    #
    # `agent_decisions` carries FORCE ROW LEVEL SECURITY (0006), the migration
    # role has rolbypassrls = false, and alembic connects with no tenant
    # context — so an unguarded UPDATE here matches ZERO rows and COMMITS
    # HAPPILY. Migration 0015 says this in its own comment, citing WO-H87
    # hitting exactly that on a live tenant. The first cut of 0018 did it
    # again anyway: it would have added both columns, built the index,
    # back-filled NOTHING across 47,460 live rows, and reported success.
    #
    # '__CROSS_TENANT__' is the sentinel the policies already accept and the
    # one SOCDatabase.cross_tenant() sets. SET LOCAL, so it lasts only for
    # alembic's migration transaction.
    op.execute("SET LOCAL app.tenant_id = '__CROSS_TENANT__'")

    # AND THE ROWCOUNT IS PRINTED, which is the part that would have caught it.
    # The house convention is `[0010] backfilled 0 ...` / `[0015] recorded ...`
    # — a number an operator reads on every deploy. The first cut buried this
    # in an anonymous DO block, whose rowcount is always -1, so a silent no-op
    # was unobservable by construction.
    #
    # `pg_input_is_valid` is PG16+; on an older server the guard cannot be
    # expressed, so the backfill is SKIPPED AND SAYS SO rather than risking a
    # cast error that aborts the upgrade.
    bind = op.get_bind()
    has_validator = bind.execute(sa.text(
        "SELECT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'pg_input_is_valid')"
    )).scalar()

    if not has_validator:
        print("[0018] agent_name backfill SKIPPED — PostgreSQL 16+ required "
              "for pg_input_is_valid; existing rows keep agent_name = NULL")
    else:
        # N-1: THE SENTINEL FILTER BELONGS HERE TOO.
        #
        # `_coerce_host` guards the Python write path, so decisions written from
        # this release onward store NULL rather than the placeholder. The
        # backfill did not honour it — so every historical row whose blob says
        # "agent_name": "unknown" (which `normalize_alert` writes for any
        # agentless alert) would have been copied verbatim into the column, and
        # all of them would share one bucket in the correlation index. The
        # column would then mean different things depending on row age, on
        # exactly the 47,460 rows the correlation query runs against.
        #
        # N-3: CASE, not chained ANDs. PostgreSQL does not guarantee AND
        # evaluation order — the planner sorts by cost — so
        # `pg_input_is_valid(...) AND jsonb_typeof(x::jsonb)` can be reordered
        # and the cast then aborts the upgrade on a malformed blob. Verified: a
        # forced cost bump on the validator reorders it and it throws. CASE is
        # the construct PostgreSQL documents as order-guaranteed.
        result = bind.execute(sa.text("""
            UPDATE agent_decisions
               -- Q-3: btrim in the SET too. The filter below already
               -- computes it, and `_coerce_host` strips on the write
               -- path — so without this the same host stores as two
               -- different correlation keys split by row age.
               SET agent_name = btrim(enrichment_summary::jsonb ->> 'agent_name')
             WHERE agent_name IS NULL
               AND enrichment_summary IS NOT NULL
               AND CASE
                     WHEN pg_input_is_valid(enrichment_summary, 'jsonb')
                     THEN jsonb_typeof(enrichment_summary::jsonb) = 'object'
                       AND lower(btrim(coalesce(
                             enrichment_summary::jsonb ->> 'agent_name', '')))
                           <> ALL (:sentinels)
                     ELSE false
                   END
        """), {"sentinels": list(_HOST_SENTINELS)})
        print("[0018] backfilled %s host name(s) from enrichment_summary"
              % result.rowcount)

    # N-2: BACK TO FAIL-CLOSED, exactly as 0015 does.
    #
    # env.py wraps the WHOLE run in one transaction (`transaction_per_migration`
    # is not set), so a SET LOCAL left in place survives into every later
    # revision. An operator going 0017 -> 0020 in one `alembic upgrade head`
    # would run 0019 and 0020 with RLS effectively disabled — migrations
    # inheriting a cross-tenant session they never asked for.
    op.execute("SET LOCAL app.tenant_id = ''")

    # Correlation asks "what else happened on this host, around this time?", so
    # the index leads with the host and carries the time.
    op.execute(
        f"CREATE INDEX IF NOT EXISTS {_HOST_INDEX} "
        "ON agent_decisions (agent_name, created_at) "
        "WHERE agent_name IS NOT NULL"
    )


def downgrade() -> None:
    """Reversible. NOTE: dropping `rule_level` permanently discards every level
    recorded since this migration ran — it cannot be re-derived, because that is
    the whole reason the column exists. `agent_name` can be re-extracted from
    `enrichment_summary` on a later upgrade."""
    op.execute(f"DROP INDEX IF EXISTS {_HOST_INDEX}")
    op.execute("ALTER TABLE agent_decisions DROP COLUMN IF EXISTS agent_name")
    op.execute("ALTER TABLE agent_decisions DROP COLUMN IF EXISTS rule_level")
