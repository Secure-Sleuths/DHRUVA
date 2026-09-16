"""WO-H97 Phase 1 — shadow-store response_urgency and kill_chain_stage

The triage prompt has asked the model for both fields since it was written
(``src/agents/prompts/__init__.py``), and ``claude_backend.py`` returns whatever
JSON the model produced, so the answers already reach ``triage_agent.py`` on
every alert. Nothing has ever read them and no column has ever existed.

Reading them costs one ``.get()`` and zero tokens. TRUSTING them costs more than
anyone can currently justify: a shadow replay of 24 stored decisions through the
real prompt and the tenant's configured model answered ``24h`` 21 times, gave
``immediate`` for a stored FALSE POSITIVE, and once answered ``none`` — a value
that is not in the schema. So the fields get a column and not a behaviour.

Both columns are NULLABLE and WIRED TO NOTHING. Severity is computed by
``src/incidents/severity.py`` from the risk score plus structured alert facts
and does not read either column.

NO BACKFILL, deliberately. Historical rows are NULL because the answers were
never stored; NULL means "asked before we listened", never "low urgency". There
is nothing to recover and inventing a value would fabricate a model output.

DEPLOY NOTE — THIS MIGRATION IS NOT OPTIONAL. ``save_decision`` writes both
columns from this release onward, so a Python-only hand deploy that skips
``alembic upgrade head`` (or ``python main.py --migrate``) makes EVERY decision
write fail with ``UndefinedColumn``. The supported path is safe:
``scripts/upgrade.sh`` runs alembic and aborts on failure. Copying ``.py`` files
onto a running box by hand is not.

Reversible: downgrade drops the index and both columns. Nothing else is touched.
A downgrade on a running service has the same requirement in reverse — stop the
service, or ``save_decision`` will write to columns that no longer exist.

Revision ID: 0016
Revises: 0015
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0016"
down_revision: Union[str, None] = "0015"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_URGENCY_INDEX = "idx_decisions_response_urgency"


def upgrade() -> None:
    # Statements are issued SEPARATELY, not as one blob — see 0010, where a
    # multi-statement op.execute() applied the DDL, skipped the trailing DML,
    # and reported success on a live install.
    #
    # Adding a NULLABLE column with no default is a catalog-only operation in
    # PostgreSQL: no table rewrite, so the brief ACCESS EXCLUSIVE lock does not
    # block writes for any meaningful duration even on 35k+ rows.
    op.execute(
        "ALTER TABLE agent_decisions "
        "ADD COLUMN IF NOT EXISTS response_urgency TEXT"
    )
    op.execute(
        "ALTER TABLE agent_decisions "
        "ADD COLUMN IF NOT EXISTS kill_chain_stage TEXT"
    )
    # Partial index: for the first weeks of shadow collection the answered rows
    # are a small minority, and the only query that matters groups over them.
    op.execute(
        f"CREATE INDEX IF NOT EXISTS {_URGENCY_INDEX} "
        "ON agent_decisions (response_urgency) "
        "WHERE response_urgency IS NOT NULL"
    )


def downgrade() -> None:
    op.execute(f"DROP INDEX IF EXISTS {_URGENCY_INDEX}")
    op.execute("ALTER TABLE agent_decisions DROP COLUMN IF EXISTS kill_chain_stage")
    op.execute("ALTER TABLE agent_decisions DROP COLUMN IF EXISTS response_urgency")
