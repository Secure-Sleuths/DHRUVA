"""active_response_audit table (M3 — Active Response Safety Posture)

Adds a durable, tenant-scoped audit table for every auto AND manual
active-response action. Also the source-of-truth for the auto-block rolling
rate cap (replaces in-memory counting on the auto path).

The DDL lives in the sibling 0002_active_response_audit.sql file — same
convention as the 0001 baseline (raw SQL, applied in one transaction).

Revision ID: 0002
Revises: 0001
Create Date: 2026-06-13
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence, Union

from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _sql() -> str:
    sql_path = Path(__file__).with_suffix(".sql")
    return sql_path.read_text(encoding="utf-8")


def upgrade() -> None:
    op.execute(_sql())


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS active_response_audit")
