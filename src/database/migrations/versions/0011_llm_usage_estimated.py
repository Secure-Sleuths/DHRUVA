"""WO-H50 — flag estimated vs real token usage on llm_usage_metrics

Until now every row in llm_usage_metrics carried a token count computed as
`characters // 4` — an estimate, never a real measurement — with no way to tell
an estimate from a true count. WO-H50 makes the provider report real usage (API
SDK `usage`, or CLI `--output-format json`); this column records which rows are
real and which are the fallback estimate, so reporting never conflates them.

`estimated BOOLEAN NOT NULL DEFAULT TRUE`: the DEFAULT is TRUE on purpose — the
93 pre-existing rows were ALL character-estimates, so defaulting them to TRUE is
correct, not lossy. New rows written with real usage set it FALSE explicitly.

Catalog-only ALTER (constant DEFAULT, PG11+) — no table rewrite.
Reversible: downgrade drops the column.
"""

from __future__ import annotations

from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE llm_usage_metrics "
        "ADD COLUMN IF NOT EXISTS estimated BOOLEAN NOT NULL DEFAULT TRUE"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE llm_usage_metrics DROP COLUMN IF EXISTS estimated")
