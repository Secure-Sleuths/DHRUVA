"""WO-H87: collapse duplicate SLA breaches and stop them recurring.

`save_sla_breach` carries `ON CONFLICT DO NOTHING`, which reads as dedup
protection but is not: the caller mints a fresh uuid4() for `id` on every run
and `id` is the primary key, so there is never a conflict. Every SLA check
re-recorded every still-open breach as a new row.

A live tenant, 2026-08-18: 3,577,852 rows / 1,052 MB, the largest table in the
database, against 8,284 incidents — and not in RETENTION_PRUNABLE, so nothing
would ever have reclaimed it.

Upgrade collapses to the EARLIEST row per (client_id, incident_id, sla_type) —
first detection is when the SLA actually breached — and adds the unique index
that makes the existing ON CONFLICT clause do its job.

DOWNGRADE IS NOT DATA-LOSSLESS IN REVERSE: dropping the index restores the
ability to insert duplicates, but the duplicates already collapsed are gone.
That is deliberate — they carried no information the surviving row does not.

Revision ID: 0014
Revises: 0013
"""
from pathlib import Path

from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    sql = Path(__file__).with_suffix(".sql").read_text()
    op.execute(sql)


def downgrade() -> None:
    # Only the constraint is reversible. The collapsed duplicates are not, and
    # are not worth reconstructing — see the module docstring.
    op.execute("DROP INDEX IF EXISTS uq_sla_breach_incident_type;")
