"""v4.9.0 baseline schema (Postgres)

Consolidates the v4.8.x SQLite initial schema + migrations 1-29 into a
single Postgres-native baseline. The actual DDL lives in the sibling
0001_baseline.sql file — keeping it as raw SQL keeps reviews and diffs
straightforward, and Alembic re-runs the whole file inside a single
transaction so partial application can't leave the schema half-built.

Revision ID: 0001
Revises:
Create Date: 2026-05-27
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence, Union

from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _baseline_sql() -> str:
    sql_path = Path(__file__).with_suffix(".sql")
    return sql_path.read_text(encoding="utf-8")


def upgrade() -> None:
    op.execute(_baseline_sql())


def downgrade() -> None:
    # The baseline IS the floor. There is nothing earlier to roll back to —
    # v4.8.x was SQLite. Operators needing a clean slate should drop and
    # recreate the database rather than relying on Alembic downgrade.
    raise NotImplementedError(
        "Downgrade past the v4.9.0 baseline is not supported. "
        "Drop and recreate the database, or restore from backup."
    )
