"""RLS tenant backstop (WO-H12 — Row-Level Security defense-in-depth)

Enables Postgres Row-Level Security + FORCE on every table in
``SOCDatabase.TENANT_SCOPED_TABLES`` and installs a ``tenant_isolation`` policy
that confines every read/write to the row-owning tenant unless the session's
``app.tenant_id`` GUC is the ``__CROSS_TENANT__`` sentinel. This is the DB-layer
safety net UNDER the WO-H8 app-level query guard — both stay active.

The upgrade DDL lives in the sibling 0006_rls_tenant_backstop.sql file (same
convention as 0001 baseline / 0002 / 0005). The GUC is set per connection
checkout in src/database/store.py (``_apply_tenant_guc``).

CRITICAL runtime requirement — DOCUMENTED in the .sql header and
docs/MULTI-TENANT.md: DHRUVA must connect as a NON-superuser, NON-BYPASSRLS
role or RLS is silently skipped (superusers/BYPASSRLS bypass RLS even with
FORCE). deploy.sh already provisions such a role; the docker-compose bundled-db
POSTGRES_USER=dhruva is a SUPERUSER and needs a separate app role.

Reversible: ``downgrade()`` drops the policy, disables RLS/FORCE on every table,
and drops the six client_id indexes this migration added. Idempotent both ways
(DROP ... IF EXISTS / ENABLE-FORCE are no-ops when already in the target state),
so it is safe to rehearse on a copy — see docs/MULTI-TENANT.md §RLS rehearsal.

Revision ID: 0006
Revises: 0005
Create Date: 2026-07-10
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence, Union

from alembic import op

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Single-sourced here for the downgrade; the upgrade path reads the .sql file.
# Kept in lock-step with SOCDatabase.TENANT_SCOPED_TABLES (all have client_id).
_TENANT_TABLES = (
    "agent_decisions", "incidents", "detection_proposals",
    "feedback_patterns", "behavioral_baselines", "rule_tuning_overrides",
    "hunt_findings", "operational_metrics", "soar_executions",
    "mitre_coverage", "audit_log", "anon_mappings", "decision_audit_trail",
    "sla_breaches", "alert_enrichment_cache", "processed_alerts",
    "tickets", "ticket_sync_log", "kb_documents", "post_incident_reviews",
    "hunt_hypothesis_library", "shift_handoffs", "compliance_mappings",
    "llm_usage_metrics", "buffered_alerts", "assets", "identities",
    "local_iocs",
)

# Only the six indexes this migration introduces (the rest pre-date it in the
# baseline and must NOT be dropped on downgrade).
_ADDED_INDEXES = (
    "idx_sla_breaches_client_id",
    "idx_alert_enrichment_cache_client_id",
    "idx_post_incident_reviews_client_id",
    "idx_hunt_hypothesis_library_client_id",
    "idx_shift_handoffs_client_id",
    "idx_buffered_alerts_client_id",
)


def _sql() -> str:
    sql_path = Path(__file__).with_suffix(".sql")
    return sql_path.read_text(encoding="utf-8")


def upgrade() -> None:
    op.execute(_sql())


def downgrade() -> None:
    # Drop policy + disable RLS/FORCE on every protected table. DROP POLICY IF
    # EXISTS and DISABLE are no-ops if already reverted, so this is idempotent.
    for t in _TENANT_TABLES:
        op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{t}"')
        op.execute(f'ALTER TABLE "{t}" NO FORCE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{t}" DISABLE ROW LEVEL SECURITY')
    for idx in _ADDED_INDEXES:
        op.execute(f'DROP INDEX IF EXISTS "{idx}"')
