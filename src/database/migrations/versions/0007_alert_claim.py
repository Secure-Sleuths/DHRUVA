"""alert-level claim — claimed_by / claimed_at on agent_decisions (WO-H25)

Adds two backward-compatible, nullable columns so an analyst can claim an
individual triage alert/decision (WO-H24 gave incidents self-claim; this
extends ownership down to the decision, per "L1 is an operator"):

  * agent_decisions.claimed_by  TEXT  (NULL for historical/unclaimed rows)
  * agent_decisions.claimed_at  TEXT  (NULL until claimed)

The DDL lives in the sibling 0007_alert_claim.sql file — same convention as
0001 baseline through 0006 (raw SQL, applied in one transaction).

ADDITIVE-ONLY: nullable, no default, no backfill, no data mutation. No RLS /
tenant-policy change — agent_decisions already carries client_id and is
filtered by _tenant_filter().

Revision ID: 0007
Revises: 0006
Create Date: 2026-07-10
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence, Union

from alembic import op

revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _sql() -> str:
    sql_path = Path(__file__).with_suffix(".sql")
    return sql_path.read_text(encoding="utf-8")


def upgrade() -> None:
    op.execute(_sql())


def downgrade() -> None:
    op.execute("ALTER TABLE agent_decisions DROP COLUMN IF EXISTS claimed_by")
    op.execute("ALTER TABLE agent_decisions DROP COLUMN IF EXISTS claimed_at")
