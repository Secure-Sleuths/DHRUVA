"""attack-chain columns on incidents (M5 — Correlation / Attack-Chain Grouping)

Adds two backward-compatible columns to ``incidents`` so multi-stage
MITRE-tactic progressions on the same host/user can be grouped into a
single, explainable attack-chain incident:

  * attack_chain_id      TEXT  (NULL until an incident is recognized as a chain)
  * attack_chain_tactics TEXT  (ordered JSON list of kill-chain tactics, default '[]')

The DDL lives in the sibling 0003_attack_chain.sql file — same convention
as the 0001 baseline and 0002 (raw SQL, applied in one transaction).

Revision ID: 0003
Revises: 0002
Create Date: 2026-06-15
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence, Union

from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _sql() -> str:
    sql_path = Path(__file__).with_suffix(".sql")
    return sql_path.read_text(encoding="utf-8")


def upgrade() -> None:
    op.execute(_sql())


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_incidents_attack_chain")
    op.execute("ALTER TABLE incidents DROP COLUMN IF EXISTS attack_chain_tactics")
    op.execute("ALTER TABLE incidents DROP COLUMN IF EXISTS attack_chain_id")
