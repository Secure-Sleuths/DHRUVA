"""WO-H85 — append-only review history for alert verdicts (`decision_reviews`)

`apply_human_override` overwrites `human_verdict` / `review_reason` in place, so
a second analyst overriding a colleague's verdict ERASES the first reviewer and
their reason. Incidents survive this by accident (`incident_timeline` keeps every
status change + reason); alerts had no equivalent. This adds one.

`decision_reviews` is append-only in use — the DAO only INSERTs
(`SOCDatabase._record_decision_review`), never UPDATEs or DELETEs — and records
who / when / verdict / free-text reason / the verdict it replaced, so a reviewer
can read what the previous person said BEFORE overriding them.

FK-scoped for multi-tenancy exactly like `incident_alerts` / `incident_timeline`
(no `client_id`; scoped transitively through `decision_id` → `agent_decisions`),
with the same SUBQUERY RLS policy shape 0008 installs. Added to
`SOCDatabase.FK_SCOPED_TABLES`.

The DDL lives in the sibling `0013_decision_review_history.sql` — same
convention as 0001..0011. ADDITIVE-ONLY, no backfill (historical rows have no
recoverable history; inventing one would attribute reviews to people who never
made them).

⚠ THE DOWNGRADE IS DESTRUCTIVE AND UNRECOVERABLE. `downgrade()` DROPs the table,
which erases EVERY recorded review — every reviewer, every reason, and every
disagreement one analyst recorded with another. There is nowhere else those rows
live: `agent_decisions` keeps only the CURRENT verdict and its reason, which is
the exact overwrite this migration exists to stop. Upgrading again returns an
EMPTY table, not the history. A downgrade/upgrade round trip is therefore
schema-idempotent but DATA-LOSSY. Dump `decision_reviews` first if the history
matters, which on any live install it does.

Also note the retention coupling (`SOCDatabase.RETENTION_PRUNABLE`): the
`decision_id` FK has NO `ON DELETE`, so a review row pins its parent decision
against the retention prune until the review itself ages out. Both halves are
wired in `prune_expired_rows`; removing either one silently stops
`agent_decisions` from ever being pruned.

Revision ID: 0013
Revises: 0012
Create Date: 2026-08-14
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence, Union

from alembic import op

revision: str = "0013"
down_revision: Union[str, None] = "0012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _sql() -> str:
    sql_path = Path(__file__).with_suffix(".sql")
    return sql_path.read_text(encoding="utf-8")


def upgrade() -> None:
    op.execute(_sql())


def downgrade() -> None:
    # DESTRUCTIVE: this DROP erases every recorded review — reviewer, reason and
    # every disagreement. Nothing else stores them. See the module docstring.
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON decision_reviews")
    op.execute("ALTER TABLE IF EXISTS decision_reviews NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE IF EXISTS decision_reviews DISABLE ROW LEVEL SECURITY")
    op.execute("DROP INDEX IF EXISTS idx_decision_reviews_decision")
    op.execute("DROP INDEX IF EXISTS idx_decision_reviews_created")
    op.execute("DROP TABLE IF EXISTS decision_reviews")
