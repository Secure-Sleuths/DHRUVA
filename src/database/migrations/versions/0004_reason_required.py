"""reason columns for human verdict/status overrides (WO-B2 + WO-B3)

Adds two backward-compatible, nullable columns so that a human-supplied
reason is persisted next to the row whose state a human changed:

  * agent_decisions.review_reason  TEXT  (NULL for historical rows)
  * incidents.status_reason        TEXT  (NULL for historical rows)

These hold the *most recent* reason; the full history of reasons is written
to the audit_log (verdict reviews) and the incident_timeline (status
changes). The mandatory-reason invariant itself is enforced at the API layer
(required Pydantic field) — deliberately NOT as a NOT NULL DB constraint, so
that pre-existing rows and any non-API writers are unaffected.

The DDL lives in the sibling 0004_reason_required.sql file — same convention
as 0001 baseline, 0002 and 0003 (raw SQL, applied in one transaction).

Revision ID: 0004
Revises: 0003
Create Date: 2026-07-02
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence, Union

from alembic import op

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _sql() -> str:
    sql_path = Path(__file__).with_suffix(".sql")
    return sql_path.read_text(encoding="utf-8")


def upgrade() -> None:
    op.execute(_sql())


def downgrade() -> None:
    op.execute("ALTER TABLE incidents DROP COLUMN IF EXISTS status_reason")
    op.execute("ALTER TABLE agent_decisions DROP COLUMN IF EXISTS review_reason")
