"""WO-H57 — persistent, admin-governed decision cache

`AlertDeduplicator` (src/agents/cost_controls.py) already reuses a triage verdict
for a structurally-identical alert WITHOUT an LLM call — but only in-memory, for
`window_seconds` (default 300s). This table PERSISTS that reuse across the window
and across restarts: a recurring alert reuses its stored verdict for $0 instead
of re-paying the LLM. It is the durable, per-tenant backing store behind the
in-memory dedup.

Safety is enforced in the triage path (WO-H57), NOT here: a cache hit is only
consulted AFTER the always-escalate + positive-signal disqualifiers have already
run against THE INCOMING alert, so a cached benign verdict can never suppress a
freshly-signalled threat. This table just stores the snapshot + admin governance
columns (`enabled`, `source`, expiry, hit accounting).

Tenant isolation: `client_id` + the same RLS `tenant_isolation` policy every
other `TENANT_SCOPED_TABLES` entry carries (WO-H12). Added to
`SOCDatabase.TENANT_SCOPED_TABLES` so the WO-H8 app-layer guard also covers it.

Reversible: downgrade drops the policy then the table. Idempotent both ways.

Revision ID: 0012
Revises: 0011
"""

from __future__ import annotations

from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS decision_cache (
            id                TEXT PRIMARY KEY,
            client_id         TEXT,
            fingerprint       TEXT NOT NULL,
            rule_id           INTEGER,
            rule_description  TEXT,
            entity_summary    TEXT,
            verdict           TEXT NOT NULL,
            confidence        DOUBLE PRECISION NOT NULL DEFAULT 0,
            risk_score        DOUBLE PRECISION NOT NULL DEFAULT 0,
            reasoning         TEXT,
            grounding         TEXT,
            escalated         BOOLEAN NOT NULL DEFAULT FALSE,
            actions_taken     TEXT DEFAULT '[]',
            origin_alert_id   TEXT,
            source            TEXT NOT NULL DEFAULT 'llm_cached',
            enabled           BOOLEAN NOT NULL DEFAULT TRUE,
            hit_count         INTEGER NOT NULL DEFAULT 0,
            tokens_saved_est  BIGINT NOT NULL DEFAULT 0,
            created_at        TEXT,
            created_by        TEXT,
            last_hit_at       TEXT,
            expires_at        TEXT
        )
        """
    )
    # One live entry per (tenant, fingerprint) — the ON CONFLICT write target.
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_decision_cache_tenant_fp "
        "ON decision_cache (client_id, fingerprint)"
    )
    # RLS backstop (WO-H12) — mirror the tenant_isolation policy every
    # TENANT_SCOPED_TABLES entry carries. FORCE so it applies even to the owner.
    op.execute("ALTER TABLE decision_cache ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE decision_cache FORCE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON decision_cache")
    op.execute(
        "CREATE POLICY tenant_isolation ON decision_cache "
        "USING ("
        "    client_id = current_setting('app.tenant_id', true) "
        "    OR current_setting('app.tenant_id', true) = '__CROSS_TENANT__'"
        ") "
        "WITH CHECK ("
        "    client_id = current_setting('app.tenant_id', true) "
        "    OR current_setting('app.tenant_id', true) = '__CROSS_TENANT__'"
        ")"
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON decision_cache")
    op.execute("ALTER TABLE decision_cache NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE decision_cache DISABLE ROW LEVEL SECURITY")
    op.execute("DROP INDEX IF EXISTS ux_decision_cache_tenant_fp")
    op.execute("DROP TABLE IF EXISTS decision_cache")
