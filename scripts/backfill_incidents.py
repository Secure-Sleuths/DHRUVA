#!/usr/bin/env python3
"""
Backfill incidents from existing triage decisions.

Reads all agent_decisions from SQLite, fetches the original alert
from OpenSearch for each, and runs them through the incident engine
in chronological order.

Usage:
    python scripts/backfill_incidents.py config/config.yaml [--dry-run]
"""

import sys
import json
import yaml
import structlog
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime, timezone

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.database.store import SOCDatabase
from src.incidents.engine import IncidentEngine

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.dev.ConsoleRenderer()
    ],
    wrapper_class=structlog.BoundLogger,
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
)
logger = structlog.get_logger("backfill")


@dataclass
class DecisionProxy:
    """Minimal decision object matching what IncidentEngine expects."""
    id: str
    alert_id: str
    verdict: str
    confidence: float
    risk_score: float
    reasoning: str
    client_id: str = None


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def reconstruct_alert_from_decision(decision: dict) -> dict:
    """
    Reconstruct a minimal enriched alert dict from a stored decision.
    Uses enrichment_summary JSON + decision fields.

    When OpenSearch is unavailable, we use rule_id as a synthetic
    rule_group for grouping. This creates incidents per-rule, which
    is still useful for identifying noisy rule clusters.
    """
    enrichment = {}
    try:
        enrichment = json.loads(decision.get("enrichment_summary") or "{}")
    except (json.JSONDecodeError, TypeError):
        pass

    asset = enrichment.get("asset_info", {})
    rule_id = decision.get("rule_id", 0)

    # Use rule_id as a synthetic rule_group when real groups aren't available
    rule_groups = enrichment.get("matched_rule_groups", [])
    if not rule_groups:
        rule_groups = [f"rule_{rule_id}"]

    return {
        "alert_id": decision["alert_id"],
        "rule_id": rule_id,
        "rule_description": decision.get("rule_description", ""),
        "rule_groups": rule_groups,
        "rule_mitre_tactics": enrichment.get("mitre_tactics", []),
        "rule_mitre_techniques": enrichment.get("mitre_techniques", []),
        "agent_id": enrichment.get("agent_id") or asset.get("agent_id", ""),
        "agent_name": enrichment.get("agent_name") or asset.get("hostname", ""),
        "src_ip": enrichment.get("src_ip") or enrichment.get("source_ip", ""),
        "dst_ip": enrichment.get("dst_ip", ""),
        "src_user": enrichment.get("src_user") or enrichment.get("username", ""),
        "dst_user": enrichment.get("dst_user", ""),
        "timestamp": decision["created_at"],
    }


_os_failures = 0

def reconstruct_alert_from_opensearch(decision: dict, os_client) -> dict:
    """
    Fetch the original alert from OpenSearch and normalize it.
    Falls back to decision-based reconstruction if not found.
    After 3 consecutive failures, stops trying OpenSearch entirely.
    """
    global _os_failures
    if _os_failures >= 3:
        return reconstruct_alert_from_decision(decision)

    alert_id = decision["alert_id"]
    try:
        raw_index = os_client.indices.get("raw_alerts", "wazuh-alerts-*")
        query = {
            "query": {"term": {"id": alert_id}},
            "size": 1
        }
        results = os_client.search_alerts(query, index=raw_index, size=1)
        if results:
            raw = results[0]
            rule = raw.get("rule", {})
            agent = raw.get("agent", {})
            data = raw.get("data", {})
            mitre = rule.get("mitre", {})
            mitre_tactics = mitre.get("tactic", [])
            mitre_techniques = mitre.get("id", [])

            return {
                "alert_id": alert_id,
                "rule_id": rule.get("id", decision["rule_id"]),
                "rule_description": rule.get("description", decision.get("rule_description", "")),
                "rule_groups": rule.get("groups", []),
                "rule_mitre_tactics": mitre_tactics if isinstance(mitre_tactics, list) else [mitre_tactics],
                "rule_mitre_techniques": mitre_techniques if isinstance(mitre_techniques, list) else [mitre_techniques],
                "agent_id": agent.get("id", "000"),
                "agent_name": agent.get("name", "unknown"),
                "src_ip": (data.get("srcip") or data.get("src_ip") or
                           data.get("srcaddr") or None),
                "dst_ip": (data.get("dstip") or data.get("dst_ip") or None),
                "src_user": (data.get("srcuser") or data.get("src_user") or
                             data.get("dstuser") or data.get("user") or None),
                "dst_user": data.get("dstuser") or data.get("dst_user") or None,
                "timestamp": raw.get("timestamp", decision["created_at"]),
            }
    except Exception as e:
        _os_failures += 1
        if _os_failures >= 3:
            logger.warning("opensearch_unreachable_falling_back",
                           failures=_os_failures,
                           fallback="rule_id_based_grouping")
        else:
            logger.warning("opensearch_lookup_failed", alert_id=alert_id, error=str(e))

    return reconstruct_alert_from_decision(decision)


def _backfill_tenant(db, config, os_client, tenant_id, tenant_name, dry_run):
    """Backfill incidents for a single tenant."""
    db.set_tenant(tenant_id)
    tf, tp = db._tenant_filter()

    # Check existing incidents for this tenant
    existing = db.get_incidents(limit=1)
    if existing:
        logger.warning("existing_incidents_found",
                       tenant=tenant_name,
                       count=len(db.get_incidents(limit=10000)),
                       message="Backfill will create NEW incidents alongside existing ones. "
                               "Consider clearing incidents table first if re-running.")

    # Load triage decisions chronologically for this tenant
    conn = db._get_conn()
    rows = conn.execute(f"""
        SELECT * FROM agent_decisions
        WHERE agent_type = 'triage' {tf}
        ORDER BY created_at ASC
    """, tp).fetchall()
    conn.close()

    decisions_raw = [dict(r) for r in rows]
    total = len(decisions_raw)
    logger.info("decisions_loaded", tenant=tenant_name, total=total)

    if total == 0:
        logger.info("no_decisions_found", tenant=tenant_name,
                     message="Nothing to backfill")
        return 0, 0

    if dry_run:
        logger.info("dry_run_mode", tenant=tenant_name,
                     message="Showing grouping preview without writing")
        engine = IncidentEngine(config, db)
        engine.enabled = False

        from collections import Counter
        key_counts = Counter()
        skipped = 0
        for d in decisions_raw:
            if d["verdict"] in ("auto_close", "false_positive"):
                try:
                    conf = float(d["confidence"])
                except (TypeError, ValueError):
                    conf = 0.0
                if conf >= 0.85:
                    skipped += 1
                    continue
            alert = (reconstruct_alert_from_opensearch(d, os_client)
                     if os_client else reconstruct_alert_from_decision(d))
            keys = engine._compute_grouping_keys(alert)
            if keys:
                key_counts[keys[0]] += 1

        print(f"\n--- Dry Run Summary [{tenant_name}] ---")
        print(f"Total decisions: {total}")
        print(f"Would skip (high-conf FP): {skipped}")
        print(f"Would process: {total - skipped}")
        print(f"Unique grouping keys: {len(key_counts)}")
        print(f"\nTop 20 grouping keys (potential incidents):")
        for key, count in key_counts.most_common(20):
            print(f"  {count:4d} alerts  {key}")
        return total, 0

    # Run the engine
    engine = IncidentEngine(config, db)
    batch_size = 50
    processed = 0

    for i in range(0, total, batch_size):
        batch_decisions_raw = decisions_raw[i:i + batch_size]
        batch_decisions = []
        batch_alerts = []

        for d in batch_decisions_raw:
            alert = (reconstruct_alert_from_opensearch(d, os_client)
                     if os_client else reconstruct_alert_from_decision(d))

            proxy = DecisionProxy(
                id=d["id"],
                alert_id=d["alert_id"],
                verdict=d["verdict"],
                confidence=float(d.get("confidence") or 0),
                risk_score=float(d.get("risk_score") or 0),
                reasoning=d.get("reasoning") or "",
                client_id=d.get("client_id"),
            )
            batch_decisions.append(proxy)
            batch_alerts.append(alert)

        engine.process_decisions(batch_decisions, batch_alerts)
        processed += len(batch_decisions_raw)

        if processed % 100 == 0 or processed == total:
            incidents_so_far = db.get_incidents(limit=10000)
            logger.info("backfill_progress",
                        tenant=tenant_name,
                        processed=processed, total=total,
                        incidents_created=len(incidents_so_far))

    all_incidents = db.get_incidents(limit=10000)
    return processed, len(all_incidents)


def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/backfill_incidents.py config/config.yaml [--dry-run] [--tenant-id ID]")
        sys.exit(1)

    config_path = sys.argv[1]
    dry_run = "--dry-run" in sys.argv
    skip_opensearch = "--no-opensearch" in sys.argv

    # Optional: scope to a single tenant
    tenant_id_arg = None
    for i, arg in enumerate(sys.argv):
        if arg == "--tenant-id" and i + 1 < len(sys.argv):
            tenant_id_arg = sys.argv[i + 1]

    config = load_config(config_path)
    db_path = config.get("database", {}).get("path", "/var/lib/ai-soc/ai-soc.db")
    db = SOCDatabase(db_path)

    # Try to connect to OpenSearch for full alert data
    os_client = None
    if not skip_opensearch:
        try:
            from dotenv import load_dotenv
            import os as _os
            load_dotenv()
            from src.enrichment.opensearch_client import OpenSearchClient
            os_cfg = config.get("opensearch", {})
            os_client = OpenSearchClient(
                hosts=os_cfg.get("hosts", []),
                username=_os.environ.get("OPENSEARCH_USER", os_cfg.get("username", "admin")),
                password=_os.environ.get("OPENSEARCH_PASSWORD", os_cfg.get("password", "admin")),
                verify_ssl=os_cfg.get("verify_ssl", False),
                indices=os_cfg.get("indices", {}),
            )
            logger.info("opensearch_connected", mode="full_alert_lookup")
        except Exception as e:
            logger.warning("opensearch_unavailable", error=str(e),
                           fallback="decision_enrichment_summary")
    else:
        logger.info("opensearch_skipped", mode="rule_id_based_grouping")

    # Determine which tenants to backfill
    if tenant_id_arg:
        # Single-tenant mode
        tenants = [{"id": tenant_id_arg, "name": tenant_id_arg}]
    else:
        # All tenants — use cross_tenant to read the tenants table
        with db.cross_tenant():
            tenants = db.get_all_tenants()
        if not tenants:
            logger.error("no_tenants_found",
                         message="No tenants in database. Cannot backfill without tenant context.")
            sys.exit(1)

    logger.info("backfill_start", tenant_count=len(tenants), dry_run=dry_run)

    grand_processed = 0
    grand_incidents = 0

    for tenant in tenants:
        tid = tenant["id"]
        tname = tenant.get("name", tid)
        logger.info("backfill_tenant_start", tenant=tname, tenant_id=tid)

        processed, incidents = _backfill_tenant(
            db, config, os_client, tid, tname, dry_run)
        grand_processed += processed
        grand_incidents += incidents

    # Final summary
    print(f"\n--- Backfill Complete ---")
    print(f"Tenants processed: {len(tenants)}")
    print(f"Decisions processed: {grand_processed}")
    if not dry_run:
        print(f"Incidents created: {grand_incidents}")

        # Show top incidents across all tenants
        with db.cross_tenant():
            all_incidents = db.get_incidents(limit=10000)
            stats = db.get_dashboard_stats()
        print(f"Open: {stats['open_incidents']} | Critical: {stats['critical_incidents']}")
        by_count = sorted(all_incidents, key=lambda x: x["alert_count"], reverse=True)
        print(f"\nTop 10 incidents by alert count:")
        for inc in by_count[:10]:
            print(f"  [{inc['severity']:8s}] {inc['alert_count']:3d} alerts  {inc['title'][:70]}")


if __name__ == "__main__":
    main()
