-- M3 — Active Response Safety Posture
-- Durable audit + rate-cap source-of-truth for every auto AND manual
-- active-response action. Tenant-scoped via client_id.

CREATE TABLE IF NOT EXISTS active_response_audit (
    id TEXT PRIMARY KEY,
    client_id TEXT,
    mode TEXT NOT NULL,            -- 'auto' | 'manual'
    action TEXT NOT NULL,
    status TEXT NOT NULL,          -- executed|pending_approval|denied|reversed|expired
    actor TEXT NOT NULL DEFAULT '',-- username, or 'system:auto-block-policy' for auto
    target_ip TEXT,
    agent_id TEXT,
    alert_id TEXT,
    decision_id TEXT,
    incident_id TEXT,
    ti_evidence TEXT DEFAULT '{}', -- JSON: matched sources + confidences
    gate_snapshot TEXT DEFAULT '{}',-- JSON: triage_conf, ti_conf, floors-at-time
    reason TEXT DEFAULT '',
    ttl_seconds INTEGER,
    expires_at TEXT,
    reversed_at TEXT,
    reversed_by TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ar_audit_client       ON active_response_audit(client_id);
CREATE INDEX IF NOT EXISTS idx_ar_audit_client_created
    ON active_response_audit(client_id, created_at);
CREATE INDEX IF NOT EXISTS idx_ar_audit_status       ON active_response_audit(status);
CREATE INDEX IF NOT EXISTS idx_ar_audit_mode_action  ON active_response_audit(mode, action);
-- Used by the durable auto-block rate cap (count executed auto-blocks per
-- tenant in a rolling window).
CREATE INDEX IF NOT EXISTS idx_ar_audit_ratecap
    ON active_response_audit(client_id, mode, action, status, created_at);
