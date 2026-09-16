"""WO-H94 — record which file a pre-deploy backup is a snapshot of.

A rule deploy writes exactly one file: ``ai-soc-tuned.xml``. The rollback chain
keyed on ``detection_proposals.rule_file`` — the rule's ORIGINATING file,
usually a stock Wazuh ruleset like ``0095-sshd_rules.xml``. So the "backup" was
a copy of a file the deploy never touched, and pressing rollback left the
deployed rule live *and* wrote that stale copy over the stock ruleset.

``backup_xml`` on its own cannot say which file it came from, so after the fix
there is no way to tell a trustworthy snapshot from a poisoned one. This column
says it explicitly, and ``rollback_proposal`` refuses to restore a snapshot
into any file other than the one it names.

BACKFILL IS A FACT, NOT A REINTERPRETATION. Before this change the backup was
read from ``proposal['rule_file']`` at one call site, on both the single and
the bulk deploy path, so for every existing row ``rule_file`` IS the file
``backup_xml`` was read from. Copying it across records what happened; it does
not re-decide what the row meant. Measured on a live install 2026-08-22: of 28
deployed proposals, the 4 whose ``rule_file`` is already ``ai-soc-tuned.xml``
stay rollback-able (their snapshot really is of the deployed file); the other
24 are refused instead of being written over the tuned ruleset.

DELIBERATELY NOT TOUCHED: ``rule_deployment_history``. Its 13 rows on the
install that was measured all name stock rulesets, and none of them are
rewritten, re-keyed or deleted. ``rule_file`` there has always truthfully
named the file ``xml_before`` was read from — that half was never the bug —
so keying the rollback lookup on the file the deploy WROTE excludes them
structurally, with no data edit and nothing to undo if the judgement is
revisited.

Reversible: downgrade drops the column. The backfill is not separately
reversible because the column carrying it is dropped; the underlying fact
(``rule_file``) is untouched, so re-upgrading reproduces it exactly.

Revision ID: 0015
Revises: 0014
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: Union[str, None] = "0014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Statements are issued SEPARATELY, not as one blob — see 0010, where a
    # multi-statement op.execute() applied the DDL, skipped the trailing
    # UPDATE, and reported success on a live install.
    op.execute(
        "ALTER TABLE detection_proposals "
        "ADD COLUMN IF NOT EXISTS backup_file TEXT"
    )

    # Cross-tenant for the backfill. NOT optional: the migration role
    # (`dhruva`) has rolbypassrls = false and detection_proposals carries FORCE
    # ROW LEVEL SECURITY, so alembic runs with no tenant context and the UPDATE
    # would match ZERO rows while committing happily (WO-H87 hit exactly that
    # on a live tenant). '__CROSS_TENANT__' is the sentinel the policies
    # already accept (0006/0009) and the one SOCDatabase.cross_tenant() sets.
    #
    # SET LOCAL, so it lasts only for alembic's migration transaction.
    op.execute("SET LOCAL app.tenant_id = '__CROSS_TENANT__'")

    result = op.get_bind().execute(
        sa.text(
            "UPDATE detection_proposals SET backup_file = rule_file "
            " WHERE backup_file IS NULL "
            "   AND backup_xml IS NOT NULL "
            "   AND rule_file IS NOT NULL"
        )
    )
    print(f"[0015] recorded the source file of {result.rowcount} "
          f"pre-deploy backups")

    # Back to fail-closed for the remainder of the transaction — no later
    # migration should inherit a cross-tenant session it did not ask for.
    op.execute("SET LOCAL app.tenant_id = ''")


def downgrade() -> None:
    op.execute(
        "ALTER TABLE detection_proposals DROP COLUMN IF EXISTS backup_file"
    )
