-- ============================================================================
-- DHRUVA v4.9.0 baseline schema (Postgres)
-- ----------------------------------------------------------------------------
-- Consolidates the SQLite initial schema + migrations 1-29 from the v4.8.x
-- line. Fresh installs only. See docs/MIGRATION-FROM-SQLITE.md if you
-- intend to carry data forward from an existing SQLite install.
--
-- Conventions preserved from SQLite for 1:1 port:
--   * TEXT primary keys (UUIDs) everywhere
--   * Timestamps stored as ISO-8601 TEXT (JSONB / TIMESTAMPTZ are v4.9.x work)
--   * JSON payloads stored as TEXT
--   * Booleans stored as INTEGER 0/1 (except llm_usage_metrics.success which
--     was already BOOLEAN in the source schema)
--
-- Intentional deviations:
--   * Unix epoch timestamps that lived in SQLite INTEGER cells move to BIGINT
--     (PG INTEGER is 32-bit and would overflow in 2038)
--   * SQLite FTS5 virtual table kb_documents_fts is replaced by a tsvector
--     column on kb_documents + GIN index + BEFORE INSERT/UPDATE trigger
-- ============================================================================

-- ── Tenancy & identity ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    config_encrypted TEXT NOT NULL DEFAULT '',
    active INTEGER DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tenants_active ON tenants(active);
CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug);

CREATE TABLE IF NOT EXISTS platform_users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'analyst',
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    client_id TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON platform_users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON platform_users(role);

CREATE TABLE IF NOT EXISTS revoked_tokens (
    token_hash TEXT PRIMARY KEY,
    expires_at BIGINT NOT NULL,
    revoked_at BIGINT NOT NULL,
    client_id TEXT
);

-- ── Threat intel (shared across tenants by design) ──────────────────────────

CREATE TABLE IF NOT EXISTS threat_intel_iocs (
    id TEXT PRIMARY KEY,
    ioc_type TEXT NOT NULL,
    ioc_value TEXT NOT NULL,
    source TEXT NOT NULL,
    severity TEXT DEFAULT 'medium',
    confidence INTEGER DEFAULT 50,
    category TEXT,
    malware_family TEXT,
    description TEXT,
    reference_url TEXT,
    tags TEXT DEFAULT '[]',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    expires_at TEXT,
    is_active INTEGER DEFAULT 1,
    raw_data TEXT DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ti_ioc_dedup
    ON threat_intel_iocs(ioc_type, ioc_value, source);
CREATE INDEX IF NOT EXISTS idx_ti_value    ON threat_intel_iocs(ioc_value);
CREATE INDEX IF NOT EXISTS idx_ti_type     ON threat_intel_iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_ti_source   ON threat_intel_iocs(source);
CREATE INDEX IF NOT EXISTS idx_ti_severity ON threat_intel_iocs(severity);
CREATE INDEX IF NOT EXISTS idx_ti_active   ON threat_intel_iocs(is_active);
CREATE INDEX IF NOT EXISTS idx_ti_expires  ON threat_intel_iocs(expires_at);

CREATE TABLE IF NOT EXISTS threat_intel_feeds (
    id TEXT PRIMARY KEY,
    feed_name TEXT UNIQUE NOT NULL,
    feed_url TEXT,
    feed_type TEXT DEFAULT 'bulk_json',
    tier INTEGER DEFAULT 1,
    enabled INTEGER DEFAULT 1,
    requires_api_key INTEGER DEFAULT 0,
    last_fetch_at TEXT,
    last_success_at TEXT,
    last_ioc_count INTEGER DEFAULT 0,
    total_ioc_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    last_error TEXT,
    collection_interval_minutes INTEGER DEFAULT 360,
    status TEXT DEFAULT 'pending',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_intel_cve (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    severity TEXT,
    cvss_score REAL,
    epss_score REAL,
    epss_percentile REAL,
    in_cisa_kev INTEGER DEFAULT 0,
    kev_date_added TEXT,
    kev_due_date TEXT,
    kev_ransomware INTEGER DEFAULT 0,
    vendor TEXT,
    product TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ti_cve_kev  ON threat_intel_cve(in_cisa_kev);
CREATE INDEX IF NOT EXISTS idx_ti_cve_epss ON threat_intel_cve(epss_score);

-- ── Core decision / incident ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS agent_decisions (
    id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL,
    rule_id INTEGER NOT NULL,
    rule_description TEXT,
    agent_type TEXT NOT NULL,
    verdict TEXT NOT NULL,
    confidence REAL NOT NULL,
    risk_score REAL DEFAULT 0,
    reasoning TEXT,
    enrichment_summary TEXT,
    playbook_used TEXT,
    actions_taken TEXT DEFAULT '[]',
    escalated INTEGER DEFAULT 0,
    human_override TEXT,
    human_verdict TEXT,
    feedback_applied INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    resolved_at TEXT,
    client_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_decisions_alert          ON agent_decisions(alert_id);
CREATE INDEX IF NOT EXISTS idx_decisions_rule           ON agent_decisions(rule_id);
CREATE INDEX IF NOT EXISTS idx_decisions_verdict        ON agent_decisions(verdict);
CREATE INDEX IF NOT EXISTS idx_decisions_created        ON agent_decisions(created_at);
CREATE INDEX IF NOT EXISTS idx_decisions_client         ON agent_decisions(client_id);
CREATE INDEX IF NOT EXISTS idx_decisions_rule_created   ON agent_decisions(rule_id, created_at);
CREATE INDEX IF NOT EXISTS idx_decisions_client_created ON agent_decisions(client_id, created_at);
CREATE INDEX IF NOT EXISTS idx_decisions_rule_override
    ON agent_decisions(rule_id, human_verdict, created_at)
    WHERE human_verdict IS NOT NULL;

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'open',
    grouping_key TEXT NOT NULL,
    alert_count INTEGER DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    assigned_to TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolved_at TEXT,
    summary TEXT,
    mitre_tactics TEXT DEFAULT '[]',
    mitre_techniques TEXT DEFAULT '[]',
    affected_hosts TEXT DEFAULT '[]',
    affected_users TEXT DEFAULT '[]',
    affected_ips TEXT DEFAULT '[]',
    client_id TEXT,
    tier TEXT NOT NULL DEFAULT 'L1',
    sla_response_due TEXT,
    sla_resolution_due TEXT,
    sla_response_met INTEGER,
    sla_resolution_met INTEGER,
    first_response_at TEXT,
    escalation_count INTEGER DEFAULT 0,
    handoff_notes TEXT,
    evidence_chain TEXT DEFAULT '[]',
    flagged_interesting INTEGER DEFAULT 0,
    interesting_notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_status            ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity          ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_grouping_key      ON incidents(grouping_key);
CREATE INDEX IF NOT EXISTS idx_incidents_created           ON incidents(created_at);
CREATE INDEX IF NOT EXISTS idx_incidents_assigned          ON incidents(assigned_to);
CREATE INDEX IF NOT EXISTS idx_incidents_status_severity   ON incidents(status, severity);
CREATE INDEX IF NOT EXISTS idx_incidents_grouping_status   ON incidents(grouping_key, status);
CREATE INDEX IF NOT EXISTS idx_incidents_client_created    ON incidents(client_id, created_at);

CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id TEXT NOT NULL,
    decision_id TEXT NOT NULL,
    added_at TEXT NOT NULL,
    PRIMARY KEY (incident_id, decision_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(id),
    FOREIGN KEY (decision_id) REFERENCES agent_decisions(id)
);
CREATE INDEX IF NOT EXISTS idx_incident_alerts_incident ON incident_alerts(incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_alerts_decision ON incident_alerts(decision_id);

CREATE TABLE IF NOT EXISTS incident_timeline (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    description TEXT,
    actor TEXT DEFAULT 'system',
    created_at TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);
CREATE INDEX IF NOT EXISTS idx_timeline_incident ON incident_timeline(incident_id);
CREATE INDEX IF NOT EXISTS idx_timeline_created  ON incident_timeline(created_at);

-- ── Detection lifecycle ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS detection_proposals (
    id TEXT PRIMARY KEY,
    rule_id INTEGER NOT NULL,
    rule_file TEXT,
    change_type TEXT NOT NULL,
    original_xml TEXT,
    proposed_xml TEXT,
    reasoning TEXT,
    fp_count_trigger INTEGER DEFAULT 0,
    fp_window_days INTEGER DEFAULT 7,
    status TEXT DEFAULT 'proposed',
    proposed_at TEXT NOT NULL,
    reviewed_by TEXT,
    reviewed_at TEXT,
    deployed_at TEXT,
    rejection_notes TEXT,
    backup_xml TEXT,
    client_id TEXT,
    assigned_reviewer TEXT,
    review_requested_at TEXT,
    peer_review_notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_proposals_rule   ON detection_proposals(rule_id);
CREATE INDEX IF NOT EXISTS idx_proposals_status ON detection_proposals(status);
CREATE INDEX IF NOT EXISTS idx_detection_proposals_client ON detection_proposals(client_id);

CREATE TABLE IF NOT EXISTS feedback_patterns (
    id TEXT PRIMARY KEY,
    pattern_type TEXT NOT NULL,
    rule_id INTEGER NOT NULL,
    description TEXT,
    occurrence_count INTEGER DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    auto_action_taken TEXT,
    status TEXT DEFAULT 'active',
    client_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_patterns_rule    ON feedback_patterns(rule_id);
CREATE INDEX IF NOT EXISTS idx_patterns_type    ON feedback_patterns(pattern_type);
CREATE INDEX IF NOT EXISTS idx_feedback_patterns_client ON feedback_patterns(client_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_patterns_active_rule
    ON feedback_patterns(pattern_type, rule_id, client_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS rule_tuning_overrides (
    id TEXT PRIMARY KEY,
    rule_id INTEGER NOT NULL,
    action_type TEXT NOT NULL,
    confidence_override REAL,
    fp_pattern_signature TEXT,
    reason TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    client_id TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tuning_rule
    ON rule_tuning_overrides(rule_id, client_id);
CREATE INDEX IF NOT EXISTS idx_tuning_action ON rule_tuning_overrides(action_type);
CREATE INDEX IF NOT EXISTS idx_rule_tuning_overrides_client
    ON rule_tuning_overrides(client_id);

CREATE TABLE IF NOT EXISTS rule_deployment_history (
    id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL,
    rule_id INTEGER NOT NULL,
    rule_file TEXT NOT NULL,
    version INTEGER NOT NULL,
    xml_before TEXT,
    xml_after TEXT NOT NULL,
    deployed_by TEXT,
    deployed_at TEXT NOT NULL,
    rolled_back_at TEXT,
    client_id TEXT,
    FOREIGN KEY (proposal_id) REFERENCES detection_proposals(id)
);
CREATE INDEX IF NOT EXISTS idx_rdh_rule      ON rule_deployment_history(rule_id, version);
CREATE INDEX IF NOT EXISTS idx_rdh_proposal  ON rule_deployment_history(proposal_id);
CREATE INDEX IF NOT EXISTS idx_rdh_client    ON rule_deployment_history(client_id);
CREATE INDEX IF NOT EXISTS idx_rdh_rule_file ON rule_deployment_history(rule_file, deployed_at);

-- ── Metrics, baselines, hunts ───────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS operational_metrics (
    id TEXT PRIMARY KEY,
    metric_name TEXT NOT NULL,
    metric_value REAL NOT NULL,
    dimensions TEXT DEFAULT '{}',
    recorded_at TEXT NOT NULL,
    client_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_metrics_name ON operational_metrics(metric_name);
CREATE INDEX IF NOT EXISTS idx_metrics_time ON operational_metrics(recorded_at);
CREATE INDEX IF NOT EXISTS idx_operational_metrics_client ON operational_metrics(client_id);

CREATE TABLE IF NOT EXISTS behavioral_baselines (
    id TEXT PRIMARY KEY,
    dimension TEXT NOT NULL,
    dimension_value TEXT NOT NULL,
    metric TEXT NOT NULL,
    mean REAL NOT NULL,
    std_dev REAL NOT NULL,
    sample_count INTEGER NOT NULL,
    window_days INTEGER NOT NULL,
    computed_at TEXT NOT NULL,
    client_id TEXT
);
-- Widened idx (migration 29): all 4 columns from the save_baseline() upsert
-- conflict target are covered, so ON CONFLICT (...) DO UPDATE matches.
CREATE UNIQUE INDEX IF NOT EXISTS idx_baselines_lookup
    ON behavioral_baselines(dimension, dimension_value, metric, client_id);
CREATE INDEX IF NOT EXISTS idx_behavioral_baselines_client ON behavioral_baselines(client_id);

CREATE TABLE IF NOT EXISTS hunt_findings (
    id TEXT PRIMARY KEY,
    hunt_cycle_id TEXT NOT NULL,
    hypothesis TEXT NOT NULL,
    mitre_technique TEXT,
    priority TEXT DEFAULT 'medium',
    query_index TEXT,
    query_body TEXT,
    result_count INTEGER DEFAULT 0,
    results_summary TEXT,
    status TEXT DEFAULT 'open',
    confirmed INTEGER DEFAULT 0,
    analyst_notes TEXT,
    created_at TEXT NOT NULL,
    reviewed_at TEXT,
    client_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_hunt_cycle             ON hunt_findings(hunt_cycle_id);
CREATE INDEX IF NOT EXISTS idx_hunt_status            ON hunt_findings(status);
CREATE INDEX IF NOT EXISTS idx_hunt_created           ON hunt_findings(created_at);
CREATE INDEX IF NOT EXISTS idx_hunt_findings_client   ON hunt_findings(client_id);
CREATE INDEX IF NOT EXISTS idx_hunt_client            ON hunt_findings(client_id);

CREATE TABLE IF NOT EXISTS hunt_hypothesis_library (
    id TEXT PRIMARY KEY,
    hypothesis TEXT NOT NULL,
    mitre_technique TEXT,
    query_index TEXT,
    query_body TEXT NOT NULL,
    success_count INTEGER DEFAULT 0,
    last_success_at TEXT,
    tags TEXT DEFAULT '[]',
    created_from_finding_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    client_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_hypothesis_lib_technique
    ON hunt_hypothesis_library(mitre_technique);
CREATE INDEX IF NOT EXISTS idx_hypothesis_lib_success
    ON hunt_hypothesis_library(success_count DESC);

-- ── Alert ingest / dedupe / buffer ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS alert_enrichment_cache (
    alert_id TEXT PRIMARY KEY,
    enriched_data TEXT NOT NULL,
    cached_at TEXT NOT NULL,
    ttl_seconds INTEGER DEFAULT 3600,
    client_id TEXT
);

-- Compound PK from migration 24 (tenant-qualified uniqueness)
CREATE TABLE IF NOT EXISTS processed_alerts (
    alert_id TEXT NOT NULL,
    rule_id INTEGER,
    rule_description TEXT,
    processed_at TEXT NOT NULL,
    verdict TEXT,
    client_id TEXT NOT NULL DEFAULT 'default',
    PRIMARY KEY (client_id, alert_id)
);
CREATE INDEX IF NOT EXISTS idx_processed_at     ON processed_alerts(processed_at);
CREATE INDEX IF NOT EXISTS idx_processed_client ON processed_alerts(client_id);

CREATE TABLE IF NOT EXISTS buffered_alerts (
    id TEXT PRIMARY KEY,
    alert_json TEXT NOT NULL,
    buffered_at TEXT NOT NULL,
    client_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_buffered_at ON buffered_alerts(buffered_at);

CREATE TABLE IF NOT EXISTS buffered_alerts_dead_letter (
    id TEXT PRIMARY KEY,
    alert_json TEXT NOT NULL,
    buffered_at TEXT NOT NULL,
    quarantined_at TEXT NOT NULL,
    last_error TEXT,
    client_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_dead_letter_quarantined
    ON buffered_alerts_dead_letter(quarantined_at);
CREATE INDEX IF NOT EXISTS idx_dead_letter_client
    ON buffered_alerts_dead_letter(client_id);

-- ── Anonymization & audit ───────────────────────────────────────────────────

-- Compound PK from migration 20 (tenant-qualified)
CREATE TABLE IF NOT EXISTS anon_mappings (
    token TEXT NOT NULL,
    original_value TEXT NOT NULL,
    field_type TEXT NOT NULL,    -- HOST, INT-IP, USER, OWNER
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    hit_count INTEGER DEFAULT 1,
    client_id TEXT NOT NULL DEFAULT '__legacy__',
    PRIMARY KEY (token, client_id)
);
CREATE INDEX IF NOT EXISTS idx_anon_original ON anon_mappings(original_value);
CREATE INDEX IF NOT EXISTS idx_anon_type     ON anon_mappings(field_type);
CREATE INDEX IF NOT EXISTS idx_anon_client   ON anon_mappings(client_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    target_id TEXT NOT NULL DEFAULT '',
    details TEXT DEFAULT '{}',
    ip_address TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    client_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_actor          ON audit_log(actor);
CREATE INDEX IF NOT EXISTS idx_audit_action         ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_created        ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_client     ON audit_log(client_id);
CREATE INDEX IF NOT EXISTS idx_audit_client_created ON audit_log(client_id, created_at);

CREATE TABLE IF NOT EXISTS decision_audit_trail (
    id TEXT PRIMARY KEY,
    decision_id TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    guidance_version TEXT NOT NULL DEFAULT '{}',
    playbook_name TEXT,
    risk_breakdown TEXT NOT NULL DEFAULT '{}',
    enrichment_inputs TEXT NOT NULL DEFAULT '{}',
    model_backend TEXT,
    latency_ms INTEGER,
    created_at TEXT NOT NULL,
    client_id TEXT,
    FOREIGN KEY (decision_id) REFERENCES agent_decisions(id)
);
CREATE INDEX IF NOT EXISTS idx_audit_trail_decision        ON decision_audit_trail(decision_id);
CREATE INDEX IF NOT EXISTS idx_audit_trail_created         ON decision_audit_trail(created_at);
CREATE INDEX IF NOT EXISTS idx_decision_audit_trail_client ON decision_audit_trail(client_id);

-- ── SLA, SOAR, MITRE ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS sla_breaches (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    sla_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    tier TEXT NOT NULL DEFAULT 'L1',
    due_at TEXT NOT NULL,
    breached_at TEXT NOT NULL,
    notified INTEGER DEFAULT 0,
    client_id TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);
CREATE INDEX IF NOT EXISTS idx_sla_breach_incident ON sla_breaches(incident_id);

CREATE TABLE IF NOT EXISTS soar_playbooks (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    description TEXT,
    enabled INTEGER DEFAULT 1,
    trigger_verdicts TEXT DEFAULT '["true_positive"]',
    trigger_min_confidence REAL DEFAULT 0.90,
    trigger_min_risk_score REAL DEFAULT 75,
    trigger_mitre_techniques TEXT DEFAULT '[]',
    trigger_rule_groups TEXT DEFAULT '[]',
    trigger_ti_required INTEGER DEFAULT 0,
    actions TEXT DEFAULT '[]',
    rollback_actions TEXT DEFAULT '[]',
    require_approval INTEGER DEFAULT 1,
    cooldown_minutes INTEGER DEFAULT 30,
    max_executions_per_hour INTEGER DEFAULT 5,
    priority INTEGER DEFAULT 50,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    client_id TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_soar_pb_name ON soar_playbooks(name);

CREATE TABLE IF NOT EXISTS soar_executions (
    id TEXT PRIMARY KEY,
    playbook_id TEXT NOT NULL,
    playbook_name TEXT NOT NULL,
    incident_id TEXT,
    decision_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending_approval',
    trigger_data TEXT DEFAULT '{}',
    actions_planned TEXT DEFAULT '[]',
    actions_completed TEXT DEFAULT '[]',
    current_step INTEGER DEFAULT 0,
    total_steps INTEGER DEFAULT 0,
    approved_by TEXT,
    approved_at TEXT,
    started_at TEXT,
    completed_at TEXT,
    error_message TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    client_id TEXT,
    FOREIGN KEY (playbook_id) REFERENCES soar_playbooks(id),
    FOREIGN KEY (decision_id) REFERENCES agent_decisions(id)
);
CREATE INDEX IF NOT EXISTS idx_soar_exec_status   ON soar_executions(status);
CREATE INDEX IF NOT EXISTS idx_soar_exec_incident ON soar_executions(incident_id);
CREATE INDEX IF NOT EXISTS idx_soar_exec_created  ON soar_executions(created_at);
CREATE INDEX IF NOT EXISTS idx_soar_executions_client ON soar_executions(client_id);

CREATE TABLE IF NOT EXISTS mitre_coverage (
    technique_id TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    tactic TEXT NOT NULL,
    detection_count INTEGER DEFAULT 0,
    tp_count INTEGER DEFAULT 0,
    fp_count INTEGER DEFAULT 0,
    last_seen TEXT,
    rule_ids TEXT DEFAULT '[]',
    coverage_status TEXT DEFAULT 'not_detected',
    updated_at TEXT NOT NULL,
    client_id TEXT,
    PRIMARY KEY (technique_id, tactic)
);
CREATE INDEX IF NOT EXISTS idx_mitre_cov_tactic     ON mitre_coverage(tactic);
CREATE INDEX IF NOT EXISTS idx_mitre_cov_status     ON mitre_coverage(coverage_status);
CREATE INDEX IF NOT EXISTS idx_mitre_coverage_client ON mitre_coverage(client_id);

-- ── Ticketing ───────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tickets (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    external_id TEXT,
    external_url TEXT,
    external_status TEXT,
    platform_status TEXT NOT NULL DEFAULT 'pending',
    summary TEXT NOT NULL,
    description TEXT,
    priority TEXT DEFAULT 'medium',
    assigned_to_external TEXT,
    metadata TEXT DEFAULT '{}',
    sync_direction TEXT DEFAULT 'outbound',
    last_synced_at TEXT,
    sync_error TEXT,
    retry_count INTEGER DEFAULT 0,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    client_id TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);
CREATE INDEX IF NOT EXISTS idx_tickets_incident    ON tickets(incident_id);
CREATE INDEX IF NOT EXISTS idx_tickets_provider    ON tickets(provider);
CREATE INDEX IF NOT EXISTS idx_tickets_external_id ON tickets(external_id);
CREATE INDEX IF NOT EXISTS idx_tickets_status      ON tickets(platform_status);
CREATE INDEX IF NOT EXISTS idx_tickets_client      ON tickets(client_id);
CREATE INDEX IF NOT EXISTS idx_tickets_created     ON tickets(created_at);

CREATE TABLE IF NOT EXISTS ticket_sync_log (
    id TEXT PRIMARY KEY,
    ticket_id TEXT NOT NULL,
    direction TEXT NOT NULL,
    event_type TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    details TEXT DEFAULT '{}',
    created_at TEXT NOT NULL,
    client_id TEXT,
    FOREIGN KEY (ticket_id) REFERENCES tickets(id)
);
CREATE INDEX IF NOT EXISTS idx_sync_log_ticket  ON ticket_sync_log(ticket_id);
CREATE INDEX IF NOT EXISTS idx_sync_log_created ON ticket_sync_log(created_at);
CREATE INDEX IF NOT EXISTS idx_sync_log_client  ON ticket_sync_log(client_id);

-- ── Knowledge base (FTS5 replaced by tsvector + GIN + trigger) ──────────────

CREATE TABLE IF NOT EXISTS kb_documents (
    id TEXT PRIMARY KEY,
    doc_type TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    tags TEXT DEFAULT '[]',
    mitre_techniques TEXT DEFAULT '[]',
    source_id TEXT,
    source_type TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    client_id TEXT,
    -- PG full-text search vector; replaces the SQLite kb_documents_fts virtual table
    search_tsv tsvector
);
CREATE INDEX IF NOT EXISTS idx_kb_doc_type    ON kb_documents(doc_type);
CREATE INDEX IF NOT EXISTS idx_kb_source      ON kb_documents(source_type, source_id);
CREATE INDEX IF NOT EXISTS idx_kb_client      ON kb_documents(client_id);
CREATE INDEX IF NOT EXISTS idx_kb_created     ON kb_documents(created_at);
CREATE INDEX IF NOT EXISTS idx_kb_search_tsv  ON kb_documents USING GIN (search_tsv);

CREATE OR REPLACE FUNCTION kb_documents_tsv_update() RETURNS trigger AS $$
BEGIN
    NEW.search_tsv := to_tsvector(
        'english',
        COALESCE(NEW.title, '')   || ' ' ||
        COALESCE(NEW.content, '') || ' ' ||
        COALESCE(NEW.tags, '')
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS kb_documents_tsv_trigger ON kb_documents;
CREATE TRIGGER kb_documents_tsv_trigger
    BEFORE INSERT OR UPDATE OF title, content, tags ON kb_documents
    FOR EACH ROW
    EXECUTE FUNCTION kb_documents_tsv_update();

-- ── Post-incident review, shift, compliance ─────────────────────────────────

CREATE TABLE IF NOT EXISTS post_incident_reviews (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL UNIQUE,
    review_date TEXT NOT NULL,
    participants TEXT DEFAULT '[]',
    timeline_accuracy TEXT,
    detection_gap TEXT,
    response_effectiveness TEXT,
    lessons_learned TEXT,
    action_items TEXT DEFAULT '[]',
    detection_backlog_items TEXT DEFAULT '[]',
    status TEXT DEFAULT 'draft',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    client_id TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);
CREATE INDEX IF NOT EXISTS idx_pir_incident ON post_incident_reviews(incident_id);
CREATE INDEX IF NOT EXISTS idx_pir_status   ON post_incident_reviews(status);

CREATE TABLE IF NOT EXISTS shift_handoffs (
    id TEXT PRIMARY KEY,
    shift_from TEXT NOT NULL,
    shift_to TEXT NOT NULL,
    report_json TEXT NOT NULL,
    created_by TEXT,
    created_at TEXT NOT NULL,
    client_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_handoff_created ON shift_handoffs(created_at);

CREATE TABLE IF NOT EXISTS compliance_mappings (
    id TEXT PRIMARY KEY,
    framework TEXT NOT NULL,
    control_id TEXT NOT NULL,
    control_name TEXT,
    rule_groups TEXT DEFAULT '[]',
    mitre_techniques TEXT DEFAULT '[]',
    detection_count INTEGER DEFAULT 0,
    last_detected TEXT,
    updated_at TEXT NOT NULL,
    client_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_compliance_framework ON compliance_mappings(framework);
CREATE INDEX IF NOT EXISTS idx_compliance_client    ON compliance_mappings(client_id);

-- ── LLM usage metrics ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS llm_usage_metrics (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    request_type TEXT NOT NULL,
    tokens_input INTEGER NOT NULL,
    tokens_output INTEGER NOT NULL,
    cost_usd REAL,
    latency_ms INTEGER,
    success BOOLEAN NOT NULL,
    error_type TEXT,
    created_at TEXT NOT NULL,
    client_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_llm_usage_tenant_date  ON llm_usage_metrics(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_llm_usage_provider     ON llm_usage_metrics(provider);
CREATE INDEX IF NOT EXISTS idx_llm_usage_client       ON llm_usage_metrics(client_id);
CREATE INDEX IF NOT EXISTS idx_llm_usage_request_type ON llm_usage_metrics(request_type);
CREATE INDEX IF NOT EXISTS idx_llm_usage_cost         ON llm_usage_metrics(cost_usd DESC);

-- ── Webhooks ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS webhook_requests (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    source_ip TEXT,
    processed_at TEXT NOT NULL,
    alert_id TEXT,
    risk_score INTEGER,
    processing_status TEXT DEFAULT 'success',
    error_message TEXT,
    created_at TEXT NOT NULL,
    client_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_webhook_tenant  ON webhook_requests(tenant_id);
CREATE INDEX IF NOT EXISTS idx_webhook_hash    ON webhook_requests(payload_hash);
CREATE INDEX IF NOT EXISTS idx_webhook_created ON webhook_requests(created_at);
CREATE INDEX IF NOT EXISTS idx_webhook_client  ON webhook_requests(client_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_webhook_dedup
    ON webhook_requests(tenant_id, payload_hash);

CREATE TABLE IF NOT EXISTS webhook_rate_limits (
    tenant_id TEXT PRIMARY KEY,
    requests_count INTEGER DEFAULT 0,
    window_start TEXT NOT NULL,
    client_id TEXT,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_webhook_rate_limit_window
    ON webhook_rate_limits(window_start);

-- ── Tenant-to-agent mapping ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tenant_agents (
    client_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    added_at TEXT NOT NULL,
    PRIMARY KEY (client_id, agent_id),
    FOREIGN KEY (client_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_tenant_agents_client ON tenant_agents(client_id);
-- Migration 25: enforce one tenant per agent globally
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_agents_unique_agent
    ON tenant_agents(agent_id);

-- ── Settings panel: assets / identities / local_iocs ────────────────────────

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    tier TEXT DEFAULT 'unknown',
    owner TEXT DEFAULT 'unknown',
    environment TEXT DEFAULT 'unknown',
    criticality_multiplier REAL DEFAULT 1.0,
    tags TEXT DEFAULT '[]',
    services TEXT DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    client_id TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_hostname_client
    ON assets(hostname, client_id);
CREATE INDEX IF NOT EXISTS idx_assets_client ON assets(client_id);

CREATE TABLE IF NOT EXISTS identities (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    risk_level TEXT DEFAULT 'standard',
    risk_multiplier REAL DEFAULT 1.0,
    is_admin INTEGER DEFAULT 0,
    is_service_account INTEGER DEFAULT 0,
    roles TEXT DEFAULT '[]',
    department TEXT DEFAULT 'unknown',
    known_ips TEXT DEFAULT '[]',
    onboarded_date TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    client_id TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_identities_username_client
    ON identities(username, client_id);
CREATE INDEX IF NOT EXISTS idx_identities_client ON identities(client_id);

CREATE TABLE IF NOT EXISTS local_iocs (
    id TEXT PRIMARY KEY,
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    severity TEXT DEFAULT 'medium',
    description TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    client_id TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_local_iocs_value_type_client
    ON local_iocs(value, ioc_type, client_id);
CREATE INDEX IF NOT EXISTS idx_local_iocs_client ON local_iocs(client_id);
CREATE INDEX IF NOT EXISTS idx_local_iocs_type   ON local_iocs(ioc_type);
