"""WO-H46-b — distinguish a triage FAILURE from a real verdict

When the LLM backend is unreachable, ``triage_agent.py`` fails CLOSED: it
writes ``verdict='needs_investigation'``, ``escalated=True``,
``confidence=0.0`` and a reasoning string prefixed ``'Triage agent error: '``.

That fail-closed behaviour is CORRECT and is deliberately left byte-identical
by this change — the agent must never guess "benign" while its brain is
offline. What was wrong is that the failure was **invisible in the `verdict`
column**: on a dashboard, N dead LLM calls were indistinguishable from N
considered escalations.

Measured on wazuh-server (2026-07-20), a clean split at the service restart
that fixed the backend: 17:04-17:10 produced 4-5 failures/min and 0 real
verdicts; 17:12-17:16 produced 0 failures and 3-7 real verdicts/min. ~37 rows
(rules 5402 sudo-to-root, 5501 PAM session) were logged as
``needs_investigation`` without ever being analyzed.

This migration adds an explicit ``llm_failed`` boolean, a partial index over
just the failure rows, and backfills the historical rows by their reasoning
prefix.

Beyond dashboards, this also protects the closed loop: ``agent_decisions``
feeds ``get_fp_rate_for_rule()`` (``historical_fp_rate``, injected into the
triage prompt) and the feedback loop's FP mining. Counting un-analyzed rows as
real triage history inflates ``total`` and depresses ``fp_rate``, which feeds
back into future verdicts and Detection Agent tuning proposals. ``store.py``
excludes ``llm_failed`` rows from that computation as part of the same change.

Reversible: downgrade drops the index and the column. The backfill is not
separately reversible because the column carrying it is dropped — the
underlying reasoning-prefix marker is untouched, so re-upgrading reproduces it
exactly.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: Union[str, None] = "0009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_FAILED_INDEX = "idx_decisions_llm_failed"


def _sql() -> str:
    sql_path = Path(__file__).with_suffix(".sql")
    return sql_path.read_text(encoding="utf-8")


def upgrade() -> None:
    # Column + partial index + backfill, all idempotent. The ALTER TABLE takes
    # a brief ACCESS EXCLUSIVE lock, but adding a NOT NULL column WITH a
    # constant DEFAULT is a catalog-only operation in PostgreSQL 11+ (no table
    # rewrite), so it does not block writes for any meaningful duration.
    #
    # Each statement is issued SEPARATELY rather than as one multi-statement
    # string. Shipping them as a single op.execute() blob silently applied only
    # the DDL on a live install (2026-07-20, wazuh-server): the column and index
    # appeared, the trailing UPDATE did not run, and the backfill flagged 0 of
    # 1398 matching rows — with no error raised anywhere. A migration that
    # half-applies without failing is worse than one that fails, so the DML now
    # gets its own execute and its rowcount is logged.
    op.execute(
        "ALTER TABLE agent_decisions "
        "ADD COLUMN IF NOT EXISTS llm_failed BOOLEAN NOT NULL DEFAULT FALSE"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_decisions_llm_failed "
        "ON agent_decisions (created_at) WHERE llm_failed"
    )
    # Backfill rows written before the flag existed. They are identifiable only
    # by the reasoning prefix, which is a stable literal emitted at one site
    # (triage_agent.py). The prefix is ANCHORED, so a genuine verdict that
    # merely mentions the phrase mid-sentence is not caught (verified against
    # real data: 0 such rows).
    #
    # The pattern is BOUND, not inlined. A literal '%' inside the SQL string is
    # parsed by psycopg as a parameter placeholder — inlining it raises
    # "only '%s', '%b', '%t' are allowed as placeholders, got '%''". That is
    # what silently defeated the first version of this migration on a live
    # install: shipped as one multi-statement blob, the DDL applied, the
    # trailing UPDATE did not, alembic reported success, and the backfill
    # flagged 0 of 1398 matching rows.
    result = op.get_bind().execute(
        sa.text(
            "UPDATE agent_decisions SET llm_failed = TRUE "
            "WHERE llm_failed = FALSE AND reasoning LIKE :prefix"
        ),
        {"prefix": "Triage agent error: %"},
    )
    print(f"[0010] backfilled {result.rowcount} un-analyzed triage rows")


def downgrade() -> None:
    op.execute(f"DROP INDEX IF EXISTS {_FAILED_INDEX}")
    op.execute("ALTER TABLE agent_decisions DROP COLUMN IF EXISTS llm_failed")
