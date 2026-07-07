"""
Enrichment Service - The context layer of DHRUVA.
Pulls alerts from Wazuh, enriches them with multiple context sources,
and stores the enriched data for agent consumption.
"""

import uuid
import json
import time
import math
import structlog
import requests as _requests
from datetime import datetime, timezone
from typing import Optional

from src.enrichment.wazuh_client import WazuhClient
from src.enrichment.opensearch_client import OpenSearchClient
from src.enrichment.enrichers import (
    AssetEnricher, IdentityEnricher,
    HistoricalEnricher, TimeContextEnricher,
    VulnerabilityContextEnricher, HostIntegrityContextEnricher
)
from src.enrichment.threat_intel.enricher import ThreatIntelEnricher
from src.database.store import SOCDatabase, _tenant_ctx, is_multi_tenant

logger = structlog.get_logger(__name__)


class EnrichmentService:
    """
    Core enrichment pipeline:
    1. Poll Wazuh for new alerts
    2. Normalize alert fields
    3. Run through all enrichers
    4. Compute composite risk score
    5. Store enriched alert in OpenSearch + local DB cache
    """

    def __init__(self, config: dict, db: SOCDatabase, tenant_registry=None):
        self.config = config
        self.db = db
        self.processed_ids: set = db.get_processed_ids(hours=48)
        self._max_processed_cache = 10000

        logger.info("processed_ids_loaded_from_db", count=len(self.processed_ids))

        # Initialize Wazuh client
        import os as _os
        _dev_mode = _os.environ.get("DEV_MODE", "").lower() in ("1", "true", "yes")
        wazuh_cfg = config["wazuh"]
        # verify_ssl: True/False, or a path to CA cert for self-signed.
        # Outside DEV_MODE, default to True if config says False.
        _wazuh_ssl_cfg = wazuh_cfg["api"]["verify_ssl"]
        if not _wazuh_ssl_cfg and not _dev_mode:
            logger.warning("wazuh_verify_ssl_forced_true",
                           msg="Wazuh verify_ssl=false outside DEV_MODE — "
                               "defaulting to true. Set DEV_MODE=true to disable.")
            _wazuh_ssl_cfg = True
        wazuh_verify = wazuh_cfg["api"].get("ca_cert") or _wazuh_ssl_cfg
        self.wazuh = WazuhClient(
            host=wazuh_cfg["api"]["host"],
            port=wazuh_cfg["api"]["port"],
            username=wazuh_cfg["api"]["username"],
            password=wazuh_cfg["api"]["password"],
            verify_ssl=wazuh_verify,
            tls_insecure_hostname=wazuh_cfg["api"].get("tls_insecure_hostname", False),
            ssh_user=wazuh_cfg.get("ssh_user", ""),
            ssh_password=wazuh_cfg.get("ssh_password", ""),
            ssh_key_path=wazuh_cfg.get("ssh_key_path", ""),
            ssh_key_passphrase=wazuh_cfg.get("ssh_key_passphrase", ""),
            ssh_sudo_nopasswd=wazuh_cfg.get("ssh_sudo_nopasswd", False),
        )

        # Initialize OpenSearch client
        os_cfg = config["opensearch"]
        _os_ssl_cfg = os_cfg["verify_ssl"]
        if not _os_ssl_cfg and not _dev_mode:
            logger.warning("opensearch_verify_ssl_forced_true",
                           msg="OpenSearch verify_ssl=false outside DEV_MODE — "
                               "defaulting to true. Set DEV_MODE=true to disable.")
            _os_ssl_cfg = True
        # Pass verify_ssl (bool) and ca_certs (path) as separate kwargs.
        # Collapsing them into a single value silently drops the CA bundle.
        os_ca_cert = os_cfg.get("ca_cert") or None
        self.opensearch = OpenSearchClient(
            hosts=os_cfg["hosts"],
            username=os_cfg["username"],
            password=os_cfg["password"],
            verify_ssl=bool(_os_ssl_cfg),
            ca_certs=os_ca_cert,
            indices=os_cfg["indices"]
        )

        # Initialize enrichers
        enrich_cfg = config.get("enrichment", {})
        risk_criteria = self._load_risk_criteria(config)

        self.asset_enricher = AssetEnricher({
            **enrich_cfg.get("asset_inventory", {}),
            "risk_criteria": risk_criteria
        })
        self.identity_enricher = IdentityEnricher({
            **enrich_cfg.get("identity", {}),
            "risk_criteria": risk_criteria
        })
        self.threat_intel_enricher = ThreatIntelEnricher(
            enrich_cfg.get("threat_intel", {}),
            db=self.db,
        )
        self.historical_enricher = HistoricalEnricher(
            enrich_cfg.get("historical", {}),
            opensearch_client=self.opensearch,
            db=self.db
        )
        self.time_enricher = TimeContextEnricher(enrich_cfg)

        # Per-tenant override registry. May be passed here OR set externally
        # (main.py sets self._tenant_registry after construction). The vuln
        # enricher reads it late via providers so either path works.
        self._tenant_registry = tenant_registry

        # Vulnerability/SCA host-context enricher (M4). It resolves the tenant
        # from _tenant_ctx and uses the tenant-scoped Wazuh client only; in
        # single-tenant mode it falls back to the global self.wazuh client.
        self.vuln_context_enricher = VulnerabilityContextEnricher(
            enrich_cfg.get("vulnerability_context", {}),
            registry_provider=lambda: self._tenant_registry,
            wazuh_provider=lambda: self.wazuh,
        )

        # Host-integrity (FIM/rootcheck) context enricher (M6b). Same tenant-
        # scoped, fail-safe pattern as M4: resolves the tenant from _tenant_ctx
        # and uses the tenant-scoped Wazuh client only; in single-tenant mode
        # it falls back to the global self.wazuh client. Rootcheck is the
        # primary driver; only RECENT FIM changes above a threshold engage.
        self.host_integrity_enricher = HostIntegrityContextEnricher(
            enrich_cfg.get("host_integrity_context", {}),
            registry_provider=lambda: self._tenant_registry,
            wazuh_provider=lambda: self.wazuh,
        )

        self.risk_criteria = risk_criteria
        logger.info("enrichment_service_initialized")
        self.alert_buffer = None

        # Try loading enrichment data from DB (settings panel)
        self._try_db_load(db)

    def _try_db_load(self, db):
        """Load enrichment data from DB, overriding YAML if DB has data."""
        try:
            self.asset_enricher.reload_from_db(db)
            self.identity_enricher.reload_from_db(db)
        except Exception as e:
            logger.warning("db_enrichment_load_failed", error=str(e))

    def reload_enrichers(self, db):
        """Reload all enricher data from DB. Called by admin settings API."""
        self._try_db_load(db)
        local_iocs_count = 0
        try:
            local_iocs_count = len(db.get_local_iocs(limit=10000))
        except Exception:
            pass
        return {
            "assets": len(self.asset_enricher.assets),
            "identities": len(self.identity_enricher.identities),
            "local_iocs": local_iocs_count,
        }

    def _load_risk_criteria(self, config: dict) -> dict:
        """Load risk criteria from guidance directory."""
        try:
            import yaml
            guidance_cfg = config.get("guidance", {})
            base_path = guidance_cfg.get("base_path", "./config/guidance")
            criteria_file = guidance_cfg.get("risk_criteria", "risk_criteria.yaml")
            with open(f"{base_path}/{criteria_file}") as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error("risk_criteria_load_failed", error=str(e))
            return {}

    def normalize_alert(self, raw_alert: dict) -> dict:
        """Normalize Wazuh alert into a consistent schema."""
        rule = raw_alert.get("rule", {})
        agent = raw_alert.get("agent", {})
        data = raw_alert.get("data", {})

        # Extract MITRE info
        mitre = rule.get("mitre", {})
        mitre_tactics = mitre.get("tactic", [])
        mitre_techniques = mitre.get("id", [])

        # Extract source/destination from different alert types
        src_ip = (data.get("srcip") or data.get("src_ip") or
                  data.get("srcaddr") or raw_alert.get("data", {}).get("aws", {}).get("sourceIPAddress"))
        dst_ip = (data.get("dstip") or data.get("dst_ip") or data.get("dstaddr"))
        src_user = (data.get("srcuser") or data.get("src_user") or
                    data.get("dstuser") or data.get("user"))
        dst_user = data.get("dstuser") or data.get("dst_user")

        normalized = {
            "alert_id": raw_alert.get("id", str(uuid.uuid4())),
            "timestamp": raw_alert.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "rule_id": int(rule.get("id", 0)),
            "rule_level": int(rule.get("level", 0)),
            "rule_description": rule.get("description", ""),
            "rule_groups": rule.get("groups", []),
            "rule_mitre_tactics": mitre_tactics if isinstance(mitre_tactics, list) else [mitre_tactics],
            "rule_mitre_techniques": mitre_techniques if isinstance(mitre_techniques, list) else [mitre_techniques],
            "rule_pci_dss": rule.get("pci_dss", []),
            "rule_gdpr": rule.get("gdpr", []),
            "agent_id": agent.get("id", "000"),
            "agent_name": agent.get("name", "unknown"),
            "agent_ip": agent.get("ip", "") or None,
            "src_ip": src_ip or None,
            "dst_ip": dst_ip or None,
            "src_user": src_user,
            "dst_user": dst_user,
            "data": data,
            "full_log": raw_alert.get("full_log", ""),
            "decoder": raw_alert.get("decoder", {}),
            "location": raw_alert.get("location", ""),
        }
        # Stamp tenant identity — required for multi-tenant indexing
        tenant_id = _tenant_ctx.get()
        if tenant_id and tenant_id != "__CROSS_TENANT__":
            normalized["client_id"] = tenant_id
        return normalized

    def enrich_alert(self, normalized_alert: dict) -> dict:
        """Run all enrichers on a normalized alert and compute risk score."""
        enrichment = {}
        enricher_timings = {}

        # Asset context
        t0 = time.monotonic()
        try:
            asset_ctx = self.asset_enricher.enrich(normalized_alert)
            enrichment.update(asset_ctx)
        except Exception as e:
            logger.warning("asset_enrichment_failed", error=str(e))
        enricher_timings["asset"] = round((time.monotonic() - t0) * 1000, 2)

        # Identity context
        t0 = time.monotonic()
        try:
            identity_ctx = self.identity_enricher.enrich(normalized_alert)
            enrichment.update(identity_ctx)
        except Exception as e:
            logger.warning("identity_enrichment_failed", error=str(e))
        enricher_timings["identity"] = round((time.monotonic() - t0) * 1000, 2)

        # Vulnerability / SCA host context (M4). Tenant-scoped, fail-safe:
        # any failure (incl. M2 fail-closed TenantConfigUnavailable) degrades
        # to multiplier 1.0 internally and never raises out of enrich().
        t0 = time.monotonic()
        try:
            vuln_ctx = self.vuln_context_enricher.enrich(normalized_alert)
            enrichment.update(vuln_ctx)
        except Exception as e:
            logger.warning("vuln_context_enrichment_failed", error=str(e))
        enricher_timings["vuln_context"] = round((time.monotonic() - t0) * 1000, 2)

        # Host-integrity (FIM/rootcheck) host context (M6b). Tenant-scoped,
        # fail-safe: any failure (incl. M2 fail-closed TenantConfigUnavailable)
        # degrades to multiplier 1.0 internally and never raises out of
        # enrich(); it never blocks the enrichment cycle.
        t0 = time.monotonic()
        try:
            host_integrity_ctx = self.host_integrity_enricher.enrich(normalized_alert)
            enrichment.update(host_integrity_ctx)
        except Exception as e:
            logger.warning("host_integrity_enrichment_failed", error=str(e))
        enricher_timings["host_integrity"] = round((time.monotonic() - t0) * 1000, 2)

        # Threat intelligence
        t0 = time.monotonic()
        try:
            ti_ctx = self.threat_intel_enricher.enrich(normalized_alert)
            enrichment.update(ti_ctx)
        except Exception as e:
            logger.warning("threat_intel_enrichment_failed", error=str(e))
        enricher_timings["threat_intel"] = round((time.monotonic() - t0) * 1000, 2)

        # Historical context
        t0 = time.monotonic()
        try:
            hist_ctx = self.historical_enricher.enrich(normalized_alert)
            enrichment.update(hist_ctx)
        except Exception as e:
            logger.warning("historical_enrichment_failed", error=str(e))
        enricher_timings["historical"] = round((time.monotonic() - t0) * 1000, 2)

        # Time context
        t0 = time.monotonic()
        try:
            time_ctx = self.time_enricher.enrich(normalized_alert)
            enrichment.update(time_ctx)
        except Exception as e:
            logger.warning("time_enrichment_failed", error=str(e))
        enricher_timings["time"] = round((time.monotonic() - t0) * 1000, 2)

        # Record enrichment latency metrics
        total_ms = sum(enricher_timings.values())
        self.db.record_metric("enrichment_latency_ms", total_ms, enricher_timings)
        enrichment["enricher_timings_ms"] = enricher_timings

        # Compute composite risk score with breakdown for audit trail
        risk_result = self._compute_risk_score(normalized_alert, enrichment)
        enrichment["risk_score"] = risk_result["score"]
        enrichment["risk_breakdown"] = risk_result["breakdown"]

        # Attach enrichment to alert
        normalized_alert["enrichment"] = enrichment
        return normalized_alert

    async def enrich_single_alert(self, alert: dict, tenant_id: str) -> dict:
        """Enrich a single alert (used by webhook ingestion).

        Sets tenant context, normalizes the alert into the canonical schema
        (including ``alert_id`` and ``client_id``), runs the full enrichment
        pipeline, and returns a schema-compatible enriched alert ready for
        indexing.
        """
        from src.database.store import _tenant_ctx
        token = _tenant_ctx.set(tenant_id)
        try:
            # Normalize — handles both raw Wazuh and webhook formats
            normalized = self.normalize_alert(alert)

            # Ensure canonical alert_id is present (webhook may use "id")
            if not normalized.get("alert_id") and alert.get("id"):
                normalized["alert_id"] = str(alert["id"])

            # Stamp tenant identity
            normalized["client_id"] = tenant_id

            # Run full enrichment (asset, identity, TI, historical, time, risk)
            enriched = self.enrich_alert(normalized)
            return enriched
        finally:
            _tenant_ctx.reset(token)

    def _compute_risk_score(self, alert: dict, enrichment: dict) -> dict:
        """Compute composite risk score with full breakdown for audit trail.

        Returns {"score": float, "breakdown": dict} so callers can store
        the individual multipliers for compliance explainability.
        """
        # Base severity from Wazuh rule level (1-15) mapped to 0-100
        base = (alert.get("rule_level", 0) / 15.0) * 100

        # Multipliers
        asset_mult = enrichment.get("asset_criticality_multiplier", 1.0)
        user_mult = enrichment.get("user_risk_multiplier", 1.0)
        time_mult = enrichment.get("time_risk_multiplier", 1.0)

        # Host vuln/SCA context (M4). Bounded by the enricher; default 1.0.
        # AMPLIFIES an existing signal — a low base stays low (multiplicative).
        vuln_context_mult = enrichment.get("vuln_context_multiplier", 1.0)

        # Host-integrity (FIM/rootcheck) context (M6b). Bounded by the enricher
        # (capped, default 1.0). Rootcheck-primary, thresholded-recent-FIM
        # secondary — sharpens an existing signal, never manufactures one.
        host_integrity_mult = enrichment.get("host_integrity_multiplier", 1.0)

        # MITRE priority boost
        mitre_boost = 1.0
        critical_techniques = []
        if self.risk_criteria:
            critical_techniques = (
                self.risk_criteria
                .get("mitre_attack_priority", {})
                .get("critical_techniques", [])
            )
        alert_techniques = alert.get("rule_mitre_techniques", [])
        if any(t in critical_techniques for t in alert_techniques):
            mitre_boost = 1.5

        # TI boost
        ti_boost = 1.0
        if enrichment.get("is_known_malicious"):
            ti_boost = 2.0
        elif enrichment.get("threat_intel_hits", 0) > 0:
            ti_boost = 1.3

        # Historical FP discount
        fp_discount = 1.0
        fp_rate = enrichment.get("historical_fp_rate", 0)
        if fp_rate > 0.8:
            fp_discount = 0.4
        elif fp_rate > 0.5:
            fp_discount = 0.6

        # Anomaly boost — elevate alerts deviating ABOVE behavioral baselines
        anomaly_boost = 1.0
        if enrichment.get("baseline_anomaly"):
            deviation = enrichment.get("baseline_deviation", 0)
            if deviation >= 4.0:
                anomaly_boost = 1.5
            elif deviation >= 3.0:
                anomaly_boost = 1.3
            elif deviation > 0:
                anomaly_boost = 1.15

        raw_score = (base * asset_mult * user_mult * time_mult
                     * mitre_boost * ti_boost * fp_discount * anomaly_boost
                     * vuln_context_mult * host_integrity_mult)
        clamped = min(100.0, max(0.0, round(raw_score, 2)))

        return {
            "score": clamped,
            "breakdown": {
                "base_severity": round(base, 2),
                "asset_multiplier": asset_mult,
                "user_multiplier": user_mult,
                "time_multiplier": time_mult,
                "mitre_boost": mitre_boost,
                "ti_boost": ti_boost,
                "fp_discount": fp_discount,
                "anomaly_boost": anomaly_boost,
                "vuln_context_multiplier": vuln_context_mult,
                "vuln_context_reason": enrichment.get("vuln_context_reason", ""),
                "host_integrity_multiplier": host_integrity_mult,
                "host_integrity_reason": enrichment.get("host_integrity_reason", ""),
                "host_rootcheck_findings": enrichment.get("host_rootcheck_findings", 0),
                "host_fim_recent_changes": enrichment.get("host_fim_recent_changes", 0),
                "raw_score": round(raw_score, 2),
                "clamped_score": clamped,
            },
        }

    def _fetch_alerts_dashboard_proxy(self, proxy_cfg: dict, query: dict,
                                       batch_size: int) -> list[dict]:
        """Fetch alerts via Wazuh Dashboard proxy when direct OpenSearch is unavailable.

        The Wazuh Dashboard (OSD) exposes a console proxy at:
          POST /api/console/proxy?path=<index>/_search&method=POST
        which forwards requests to the underlying OpenSearch indexer.
        """
        import urllib.parse
        from src.enrichment.proxy_ssl import resolve_proxy_verify_ssl
        base_url = proxy_cfg["url"].rstrip("/")
        username = proxy_cfg["username"]
        password = proxy_cfg["password"]

        # verify_ssl: True/False, or a path to CA cert for self-signed.
        # Shared policy (default True; explicit false honored only under
        # DEV_MODE; forced True + warned outside DEV_MODE; per-call warning
        # when genuinely off) lives in proxy_ssl.resolve_proxy_verify_ssl so
        # this path and tenant_registry.query_dashboard_proxy can't diverge.
        verify_ssl = resolve_proxy_verify_ssl(proxy_cfg)

        path = urllib.parse.quote("wazuh-alerts-4.x-*/_search", safe="")
        url = f"{base_url}/api/console/proxy?path={path}&method=POST"

        body = {**query, "size": batch_size}
        try:
            resp = _requests.post(
                url,
                json=body,
                auth=(username, password),
                headers={"osd-xsrf": "true", "Content-Type": "application/json"},
                verify=verify_ssl,
                timeout=30,
            )
            resp.raise_for_status()
            result = resp.json()
            raw_alerts = [hit["_source"] for hit in result.get("hits", {}).get("hits", [])]
            if raw_alerts:
                logger.info("alerts_fetched_via_dashboard_proxy",
                            count=len(raw_alerts), url=base_url)
            return raw_alerts
        except Exception as e:
            logger.error("dashboard_proxy_fetch_failed",
                         error=str(e)[:200], url=base_url)
            return []

    def process_batch(self) -> list[dict]:
        """
        Main processing loop iteration:
        1. Fetch new alerts from OpenSearch (wazuh-alerts-* index)
           — or via Dashboard proxy if tenant config specifies it
        2. Normalize and enrich each alert
        3. Store in enriched alerts index
        4. Return enriched alerts for agent processing
        """
        # Fail closed: in multi-tenant mode, tenant context MUST be set
        if is_multi_tenant():
            current = _tenant_ctx.get()
            if not current or current == "__CROSS_TENANT__":
                logger.error("process_batch_no_tenant_context",
                             msg="process_batch() called in MT mode without tenant context")
                return []

        wazuh_cfg = self.config["wazuh"]["alerts"]
        min_level = wazuh_cfg.get("min_severity", 3)
        batch_size = wazuh_cfg.get("batch_size", 50)

        # Determine fetch window: new tenants start from "now" (no backfill),
        # existing tenants use a rolling lookback window.
        # NOTE: _tenant_ctx is imported at module level — do NOT re-import here
        current_tenant = _tenant_ctx.get()
        if not hasattr(self, '_tenant_first_fetch'):
            self._tenant_first_fetch = {}
        if not hasattr(self, '_tenant_fetch_anchor'):
            self._tenant_fetch_anchor = {}  # tenant_id -> ISO timestamp of first poll

        if current_tenant and current_tenant not in self._tenant_first_fetch:
            # First poll for this tenant — check if they have any processed alerts
            has_history = bool(self.db.is_alert_processed("__probe__") is not None
                               and len(self.processed_ids) > 0)
            if has_history:
                fetch_window = "now-24h"
            else:
                # New tenant with no history — only fetch from now onwards
                fetch_window = "now-1m"
                self._tenant_fetch_anchor[current_tenant] = datetime.now(
                    timezone.utc).isoformat()
                logger.info("new_tenant_first_fetch",
                            tenant=current_tenant,
                            message="First connection — fetching only new alerts, no backfill")
            self._tenant_first_fetch[current_tenant] = True
        elif current_tenant in self._tenant_fetch_anchor:
            # Subsequent polls for a newly-enrolled tenant — use the anchor
            # timestamp so we never backfill before enrollment time
            fetch_window = self._tenant_fetch_anchor[current_tenant]
        else:
            fetch_window = "now-24h"

        # Fetch raw alerts from Wazuh's alert index in OpenSearch
        # In multi-tenant mode, scope by the current tenant's allowed agent IDs
        try:
            must_clauses = [
                {"range": {"rule.level": {"gte": min_level}}},
                {"range": {"timestamp": {"gte": fetch_window}}}
            ]
            if is_multi_tenant() and current_tenant:
                allowed_agents = self.db.get_tenant_agent_ids(current_tenant)
                if allowed_agents is not None:
                    must_clauses.append({"terms": {"agent.id": allowed_agents}})
                elif allowed_agents is None:
                    # No agent mapping in MT mode — fetch nothing
                    must_clauses.append({"terms": {"agent.id": []}})

            query = {
                "query": {"bool": {"must": must_clauses}},
                "sort": [{"timestamp": {"order": "desc"}}]
            }

            # Check if this tenant uses the dashboard proxy instead of direct OpenSearch
            proxy_cfg = None
            if self._tenant_registry and current_tenant:
                tenant_cfg = self._tenant_registry.get_tenant_config(current_tenant)
                proxy_cfg = tenant_cfg.get("dashboard_proxy")

            if proxy_cfg:
                raw_alerts = self._fetch_alerts_dashboard_proxy(
                    proxy_cfg, query, batch_size)
            else:
                result = self.opensearch.client.search(
                    index="wazuh-alerts-4.x-*",
                    body=query,
                    size=batch_size
                )
                raw_alerts = [hit["_source"] for hit in result["hits"]["hits"]]
                if raw_alerts:
                    logger.info("wazuh_alerts_fetched_from_opensearch", count=len(raw_alerts))
        except Exception as e:
            logger.error("wazuh_alerts_fetch_failed", error=str(e)[:200])
            raw_alerts = []

        enriched_batch = []
        for raw in raw_alerts:
            alert_id = raw.get("id", raw.get("_id", ""))
            if not alert_id:
                continue

            # Tenant-qualified cache key to prevent cross-tenant dedup collisions
            cache_key = f"{current_tenant}:{alert_id}" if current_tenant else alert_id

            # Check in-memory cache first, then Postgres
            if cache_key in self.processed_ids:
                continue
            if self.db.is_alert_processed(alert_id):
                self.processed_ids.add(cache_key)
                continue

            # Normalize
            normalized = self.normalize_alert(raw)

            # Enrich
            enriched = self.enrich_alert(normalized)

            # Store in enriched index (buffer on transient failure;
            # poison pills get buffered too and the buffer flush quarantines
            # them to the dead-letter table on next tick).
            from src.enrichment.opensearch_client import INDEX_OK
            stored = None
            try:
                stored = self.opensearch.index_enriched_alert(enriched)
            except Exception as idx_err:
                logger.warning("alert_index_exception",
                               error=str(idx_err)[:200])

            if stored != INDEX_OK:
                if self.alert_buffer:
                    buffered = self.alert_buffer.buffer_alert(enriched)
                    if buffered:
                        logger.warning("alert_buffered_opensearch_unavailable",
                                       alert_id=alert_id,
                                       index_result=stored,
                                       buffer_count=self.alert_buffer.get_buffer_count())
                    else:
                        logger.error("alert_buffer_failed",
                                     alert_id=alert_id)
                        continue  # Neither indexed nor buffered — retry
                else:
                    logger.error("alert_index_failed_no_buffer",
                                 alert_id=alert_id, index_result=stored)
                    continue  # Do NOT mark processed — alert should be retried

            # Track processed — both in memory AND Postgres (survives restarts)
            self.processed_ids.add(cache_key)
            self.db.mark_alert_processed(
                alert_id=alert_id,
                rule_id=normalized.get("rule_id"),
                rule_description=normalized.get("rule_description")
            )

            # Trim in-memory cache (Postgres is source of truth)
            if len(self.processed_ids) > self._max_processed_cache:
                self.processed_ids = self.db.get_processed_ids(hours=48)

            enriched_batch.append(enriched)

        if enriched_batch:
            logger.info("enrichment_batch_processed", count=len(enriched_batch))
            self.db.record_metric("alerts_enriched", len(enriched_batch))

        return enriched_batch

    def compute_baselines(self) -> dict:
        """
        Compute 30-day behavioral baselines per agent, user, and source IP.
        Queries OpenSearch for daily alert counts, computes mean/stddev,
        and stores results in Postgres for fast per-alert lookups.
        """
        hist_cfg = self.config.get("enrichment", {}).get("historical", {})
        window_days = hist_cfg.get("baseline_window_days", 30)

        dimensions = [
            ("agent", "agent_name"),
            ("src_ip", "src_ip"),
            ("src_user", "src_user"),
        ]

        stats = {"dimensions_processed": 0, "baselines_saved": 0, "errors": 0}

        for dim_name, os_field in dimensions:
            try:
                values = self.opensearch.get_unique_dimension_values(
                    os_field, days=window_days, max_values=500
                )
                logger.info("baseline_dimension_discovered",
                            dimension=dim_name, unique_values=len(values))

                for value in values:
                    if not value:
                        continue
                    try:
                        daily = self.opensearch.get_daily_alert_counts(
                            os_field, value, days=window_days
                        )
                        if len(daily) < 3:
                            continue  # Not enough data points

                        counts = [d["count"] for d in daily]
                        risks = [d["avg_risk"] for d in daily if d["avg_risk"]]

                        # Daily alert count baseline
                        count_mean = sum(counts) / len(counts)
                        count_var = sum((c - count_mean) ** 2 for c in counts) / len(counts)
                        count_std = math.sqrt(count_var)

                        self.db.save_baseline(
                            dimension=dim_name,
                            dimension_value=str(value),
                            metric="daily_alert_count",
                            mean=count_mean,
                            std_dev=count_std,
                            sample_count=len(counts),
                            window_days=window_days
                        )
                        stats["baselines_saved"] += 1

                        # Average risk score baseline
                        if risks:
                            risk_mean = sum(risks) / len(risks)
                            risk_var = sum((r - risk_mean) ** 2 for r in risks) / len(risks)
                            risk_std = math.sqrt(risk_var)

                            self.db.save_baseline(
                                dimension=dim_name,
                                dimension_value=str(value),
                                metric="daily_avg_risk",
                                mean=risk_mean,
                                std_dev=risk_std,
                                sample_count=len(risks),
                                window_days=window_days
                            )
                            stats["baselines_saved"] += 1

                    except Exception as e:
                        logger.warning("baseline_value_failed",
                                       dimension=dim_name, value=value, error=str(e))
                        stats["errors"] += 1

                stats["dimensions_processed"] += 1

            except Exception as e:
                logger.error("baseline_dimension_failed",
                             dimension=dim_name, error=str(e))
                stats["errors"] += 1

        self.db.record_metric("baselines_computed", stats["baselines_saved"], stats)
        logger.info("baseline_computation_completed", **stats)
        return stats

    def get_alert_context_for_agent(self, alert: dict,
                                     max_correlated: int = 20) -> dict:
        """
        Build the full context package an agent needs for triage.
        Includes the alert, its enrichment, and correlated events.
        """
        context = {
            "alert": alert,
            "enrichment": alert.get("enrichment", {}),
            "correlated_events": [],
            "rule_history": [],
            "source_history": [],
            "user_history": []
        }

        # Get correlated events
        try:
            correlated = self.opensearch.get_correlated_events(
                alert, window_minutes=60, size=max_correlated
            )
            context["correlated_events"] = correlated
        except Exception as e:
            logger.warning("correlation_failed", error=str(e))

        # Rule-specific history
        rule_id = alert.get("rule_id")
        if rule_id:
            context["rule_history"] = self.opensearch.get_alert_history_for_rule(
                rule_id, days=7, size=10
            )

        # Source IP history
        if alert.get("src_ip"):
            context["source_history"] = self.opensearch.get_alert_history_for_source(
                alert["src_ip"], days=7, size=10
            )

        return context
