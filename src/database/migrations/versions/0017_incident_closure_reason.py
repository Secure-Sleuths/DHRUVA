"""WO-H112 — a closure reason we can actually learn from

WHY THIS EXISTS. An analyst investigated a random-named kernel driver on a
workstation, correctly identified it as BYOVD / rootkit persistence
(T1543.003), assigned it to admin with a four-step plan — and closed it 41
minutes later with the reason **"normal action"**.

That string cannot be compared to an AI verdict, cannot be counted, and cannot
train anything. `incidents.status_reason` has always been free text, so the
platform has thousands of closures and no way to ask "how often was the AI
right?" at the case level.

WHAT THIS ADDS

  closure_reason        constrained: true_positive / benign_positive /
                        false_positive / duplicate / insufficient_data
  ai_was_wrong          0/1/NULL — the closer's explicit judgement on the AI
  ai_wrong_detail       free text: WHY the AI was wrong
  ai_verdict_at_close   the AI's majority verdict on the case at the moment it
                        was closed, or NULL if the case had none
  closure_recorded_at   when the structured closure was captured

ai_verdict_at_close IS THE HONEST ONE AND IT IS THE POINT.

The metric everyone quotes for this ("AI verdict vs analyst close reason")
measures AGREEMENT, not accuracy, because the analyst reads the AI verdict
before choosing. Without recording whether an AI verdict was even available at
close time, there is no way to tell a correct AI from a deferential analyst.
NULL marks the unanchored cases — the only ones where agreement means anything
— and if that set turns out to be empty, the dashboard must say so rather than
report a number it cannot support.

NO BACKFILL, deliberately. Every historical row is NULL because the answers
were never asked for. NULL means "closed before we asked", never "no reason
given" and never "the AI was right". Inventing a value here would manufacture
the exact ground truth this work order exists to establish.

NOT TOUCHED: `_NON_HUMAN_REVIEWERS` in src/database/store.py, which the operator
emptied deliberately on 2026-08-13. Restoring it is their call and is not part
of this migration.

DEPLOY NOTE — NOT OPTIONAL from this release onward: `update_incident_status`
writes these columns, so a hand deploy that skips `alembic upgrade head` makes
every incident status change fail with UndefinedColumn. `scripts/upgrade.sh`
runs alembic and aborts on failure.

Reversible: downgrade drops the index, the constraint and all five columns.
Nothing else is touched.

Revision ID: 0017
Revises: 0016
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0017"
down_revision: Union[str, None] = "0016"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_CLOSURE_INDEX = "idx_incidents_closure_reason"
_CLOSURE_CHECK = "ck_incidents_closure_reason"

#: Kept in lockstep with ``ALLOWED_CLOSURE_REASONS`` in src/api/models.py.
#: Duplicated on purpose — the database is the last line of defence for the
#: column that a quality metric is computed from, and a typo'd reason that
#: loads clean is exactly how WO-H97's `meduim` silently deleted a floor.
_REASONS = ("true_positive", "benign_positive", "false_positive",
            "duplicate", "insufficient_data")


def upgrade() -> None:
    # Issued SEPARATELY, not as one blob — see 0010, where a multi-statement
    # op.execute() applied the DDL, skipped the trailing DML, and reported
    # success on a live install.
    #
    # All five are NULLABLE with no default, so each is a catalog-only change
    # in PostgreSQL: no table rewrite, and the ACCESS EXCLUSIVE lock is held
    # only momentarily.
    for column, ctype in (("closure_reason", "TEXT"),
                          ("ai_was_wrong", "INTEGER"),
                          ("ai_wrong_detail", "TEXT"),
                          ("ai_verdict_at_close", "TEXT"),
                          ("closure_recorded_at", "TEXT")):
        op.execute(
            f"ALTER TABLE incidents ADD COLUMN IF NOT EXISTS {column} {ctype}"
        )

    # NULL is allowed so every historical row stays valid without a rewrite.
    # The constraint only bites on values written from here on.
    values = ", ".join("'%s'" % r for r in _REASONS)
    op.execute(f"ALTER TABLE incidents DROP CONSTRAINT IF EXISTS {_CLOSURE_CHECK}")
    op.execute(
        f"ALTER TABLE incidents ADD CONSTRAINT {_CLOSURE_CHECK} "
        f"CHECK (closure_reason IS NULL OR closure_reason IN ({values}))"
    )
    # QA L8: drop-then-add, like the constraint above, so a re-run is safe.
    op.execute("ALTER TABLE incidents DROP CONSTRAINT IF EXISTS "
               "ck_incidents_ai_was_wrong")
    op.execute(
        "ALTER TABLE incidents ADD CONSTRAINT ck_incidents_ai_was_wrong "
        "CHECK (ai_was_wrong IS NULL OR ai_was_wrong IN (0, 1))"
    )

    # Partial index: for the first weeks the answered rows are a small
    # minority, and every query that matters groups over exactly those.
    op.execute(
        f"CREATE INDEX IF NOT EXISTS {_CLOSURE_INDEX} "
        "ON incidents (closure_reason) WHERE closure_reason IS NOT NULL"
    )


def downgrade() -> None:
    op.execute(f"DROP INDEX IF EXISTS {_CLOSURE_INDEX}")
    op.execute("ALTER TABLE incidents DROP CONSTRAINT IF EXISTS ck_incidents_ai_was_wrong")
    op.execute(f"ALTER TABLE incidents DROP CONSTRAINT IF EXISTS {_CLOSURE_CHECK}")
    for column in ("closure_recorded_at", "ai_verdict_at_close",
                   "ai_wrong_detail", "ai_was_wrong", "closure_reason"):
        op.execute(f"ALTER TABLE incidents DROP COLUMN IF EXISTS {column}")
