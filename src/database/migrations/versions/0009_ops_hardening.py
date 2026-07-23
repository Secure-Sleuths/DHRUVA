"""WO-H28 — ops hardening: budget-reservation table + sargable metrics index

Two independent pieces:

1. ``llm_budget_reservations`` (transactional DDL in the sibling
   0009_ops_hardening.sql, same convention as 0001..0008): the DB half of the
   atomic budget debit. ``BudgetGuard.reserve()`` holds a per-tenant advisory
   lock while it counts month-to-date spend PLUS active reservations against
   the cap and inserts its own reservation — closing the WO-H5 check-then-act
   race where N parallel triage workers all read the same cached spend and
   collectively overshoot the monthly cap. RLS (0006-style tenant_isolation
   policy, ENABLE + FORCE) is applied to the new table.

2. A composite index ``(metric_name, recorded_at)`` on ``operational_metrics``
   so the hot-path daily COUNT in ``get_metric_count`` (feature-gate quota
   checks run per triage call) is index-served. The query itself was made
   sargable in store.py (half-open recorded_at range instead of
   ``DATE(recorded_at) =``).

NON-BLOCKING DDL STANDARD (WO-H28, see docs/DB-MAINTENANCE.md):
``operational_metrics`` is one of the largest tables in a busy install, and a
plain CREATE INDEX takes a SHARE lock that blocks writes for the whole build.
The index is therefore created with CREATE INDEX CONCURRENTLY — which cannot
run inside a transaction, so it executes in an Alembic ``autocommit_block()``
AFTER the transactional part. If the CONCURRENTLY build is interrupted it can
leave an INVALID index behind; the upgrade defensively drops any invalid
leftover first, so re-running the migration self-heals.

Reversible: downgrade drops the index (plain DROP INDEX inside the migration
transaction — dropping is a short metadata operation) and the reservations
table + its policy.

Revision ID: 0009
Revises: 0008
Create Date: 2026-07-11
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence, Union

from alembic import op

revision: str = "0009"
down_revision: Union[str, None] = "0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_METRICS_INDEX = "idx_metrics_name_recorded"


def _sql() -> str:
    sql_path = Path(__file__).with_suffix(".sql")
    return sql_path.read_text(encoding="utf-8")


def upgrade() -> None:
    # Transactional half: reservations table + RLS (idempotent).
    op.execute(_sql())

    # Non-transactional half: CONCURRENTLY index build (cannot run inside a
    # transaction — Alembic commits the migration transaction, runs this
    # block in autocommit, then resumes).
    with op.get_context().autocommit_block():
        # Self-heal: an interrupted CONCURRENTLY build leaves an INVALID
        # index that would make the IF NOT EXISTS below a silent no-op.
        op.execute(f"""
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM pg_index i
                    JOIN pg_class c ON c.oid = i.indexrelid
                    WHERE c.relname = '{_METRICS_INDEX}' AND NOT i.indisvalid
                ) THEN
                    EXECUTE 'DROP INDEX ' || quote_ident('{_METRICS_INDEX}');
                END IF;
            END $$;
        """)
        op.execute(
            f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {_METRICS_INDEX} "
            f"ON operational_metrics (metric_name, recorded_at)"
        )


def downgrade() -> None:
    op.execute(f"DROP INDEX IF EXISTS {_METRICS_INDEX}")
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON llm_budget_reservations")
    op.execute("DROP TABLE IF EXISTS llm_budget_reservations")
