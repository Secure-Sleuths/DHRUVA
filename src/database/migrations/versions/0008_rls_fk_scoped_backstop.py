"""RLS backstop for FK-scoped incident child tables (WO-H29 — finding N2)

Extends the WO-H12 / 0006 Row-Level Security backstop to the two FK-scoped
tables ``incident_alerts`` and ``incident_timeline``, which 0006 deliberately
skipped because they carry no direct ``client_id`` (they are scoped transitively
through their ``incident_id`` FK to the already-RLS-scoped ``incidents`` parent).

No live leak exists today — the DAO only reaches these rows via a join to
``incidents`` — but a future forgotten-filter raw query on either table could
return cross-tenant rows. This installs a SUBQUERY RLS policy that confines each
child row to the session tenant's incidents:

    USING (incident_id IN (SELECT id FROM incidents))

The inner ``SELECT id FROM incidents`` is itself RLS-scoped by the 0006
``tenant_isolation`` policy, so it composes automatically with the existing
``app.tenant_id`` session GUC / ``__CROSS_TENANT__`` sentinel (see the sibling
0008_rls_fk_scoped_backstop.sql header for the full composition table). No new
column, no backfill, and RLS on NO OTHER table is touched.

Same NON-SUPERUSER / NON-BYPASSRLS role requirement as 0006 (a superuser skips
this policy exactly as it skips the parent ones — see docs/MULTI-TENANT.md §RLS).

The upgrade DDL lives in the sibling 0008_rls_fk_scoped_backstop.sql file (same
convention as 0001..0007). Reversible: ``downgrade()`` drops the policy and
disables RLS/FORCE on JUST these two tables — it does not touch 0006's tables or
mechanics. Idempotent both ways.

Revision ID: 0008
Revises: 0007
Create Date: 2026-07-11
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence, Union

from alembic import op

revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# The two FK-scoped tables this migration protects. Kept in lock-step with
# SOCDatabase.FK_SCOPED_TABLES. RLS on NO OTHER table is altered here.
_FK_SCOPED_TABLES = ("incident_alerts", "incident_timeline")


def _sql() -> str:
    sql_path = Path(__file__).with_suffix(".sql")
    return sql_path.read_text(encoding="utf-8")


def upgrade() -> None:
    op.execute(_sql())


def downgrade() -> None:
    # Drop the policy + disable RLS/FORCE on ONLY these two tables. DROP POLICY
    # IF EXISTS and DISABLE are no-ops if already reverted, so this is
    # idempotent. 0006's tables and its mechanics are left untouched.
    for t in _FK_SCOPED_TABLES:
        op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{t}"')
        op.execute(f'ALTER TABLE "{t}" NO FORCE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{t}" DISABLE ROW LEVEL SECURITY')
