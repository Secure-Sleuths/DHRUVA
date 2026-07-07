"""grounding column for AI output faithfulness (AIS2)

Adds one backward-compatible, nullable column so the evidence-derived grounding
assessment for a triage verdict is persisted next to the decision it judges:

  * agent_decisions.grounding  TEXT  (NULL for historical rows)

Holds a JSON blob produced by src/agents/grounding.assess_triage_grounding
(grounding band, score, fabricated evidence_refs, reasons). This is an
INDEPENDENT signal from the model's self-reported confidence — a low-grounding
verdict is flagged for analyst attention rather than rendered as confident.

The DDL lives in the sibling 0005_grounding.sql file — same convention as 0001
baseline, 0002, 0003 and 0004 (raw SQL, applied in one transaction).

ADDITIVE-ONLY: nullable, no default, no backfill, no data mutation.

Revision ID: 0005
Revises: 0004
Create Date: 2026-07-05
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence, Union

from alembic import op

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _sql() -> str:
    sql_path = Path(__file__).with_suffix(".sql")
    return sql_path.read_text(encoding="utf-8")


def upgrade() -> None:
    op.execute(_sql())


def downgrade() -> None:
    op.execute("ALTER TABLE agent_decisions DROP COLUMN IF EXISTS grounding")
