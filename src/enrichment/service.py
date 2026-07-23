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

# WO-H13: bounded look-back overlap for late / out-of-order alerts.
# The WO-H9 forward-only ``search_after`` cursor on (timestamp, _id) never
# re-fetches an alert whose event ``timestamp`` lands BEHIND the current
# high-water mark (clock skew, delayed agent ingest, bulk backfill). Each poll
# therefore ALSO re-queries a small window immediately behind the high-water
# mark so an out-of-order arrival within that window is picked up; the durable
# processed-id dedup guarantees an already-handled alert is never re-triaged.
# The window is bounded so it can never degenerate into the old full re-scan.
# DOCUMENTED LIMIT: an alert arriving MORE than ``look_back_seconds`` behind the
# high-water mark (i.e. its event timestamp is older than high_water -
# look_back_seconds by the time we next poll) is NOT caught — that is the
# accepted bound, not a silent guarantee.
_DEFAULT_LOOK_BACK_SECONDS = 300      # 5 min — sensible default
_MAX_LOOK_BACK_SECONDS = 3600         # 1 h hard ceiling — keeps it a small
                                      # overlap, never the old sliding window


def _sort_value_to_millis(val) -> Optional[int]:
    """Convert a high-water cursor timestamp to epoch milliseconds.

    The direct OpenSearch path stores the ``search_after`` sort tuple whose
    first element is the date field's sort value — epoch millis (a number) by
    default. The proxy path stores an ISO-8601 timestamp string. Accept either
    and return epoch millis, or ``None`` if it can't be parsed.
    """
    if val is None:
        return None
    if isinstance(val, bool):
        return None
    if isinstance(val, (int, float)):
        return int(val)
    try:
        parsed = datetime.fromisoformat(str(val).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return int(parsed.timestamp() * 1000)
    except Exception:
        return None


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

        # Vulnerability/SCA host-context enricher (M4 + WO-H11). Vulns are read
        # from the Wazuh vuln STATE index in OpenSearch (the Manager API vuln
        # endpoint was removed in Wazuh 4.8+); SCA still uses the tenant-scoped
        # Wazuh client. It resolves the tenant from _tenant_ctx and, in
        # multi-tenant mode, scopes the vuln query to the tenant's mapped agents
        # (same fail-closed agent-id scoping as the alert-read path). In
        # single-tenant mode it falls back to the global self.wazuh client and
        # the shared self.opensearch handle with no agent restriction.
        self.vuln_context_enricher = VulnerabilityContextEnricher(
            enrich_cfg.get("vulnerability_context", {}),
            registry_provider=lambda: self._tenant_registry,
            wazuh_provider=lambda: self.wazuh,
            opensearch_provider=lambda: self.opensearch,
            # WO-H23: per-CVE EPSS/KEV lookups against the local (global) CVE TI
            # table. Display-only detail; never fed to an LLM prompt.
            db=self.db,
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
        # WO-H13: bounded look-back overlap window (seconds). Clamped to
        # [0, _MAX_LOOK_BACK_SECONDS]; 0 disables the look-back entirely. The
        # ceiling keeps it a small overlap and forbids regressing to the old
        # full sliding-window re-scan.
        _cfg_look_back = wazuh_cfg.get("look_back_seconds",
                                       _DEFAULT_LOOK_BACK_SECONDS)
        try:
            look_back_seconds = int(_cfg_look_back)
        except (TypeError, ValueError):
            look_back_seconds = _DEFAULT_LOOK_BACK_SECONDS
        look_back_seconds = max(0, min(look_back_seconds,
                                       _MAX_LOOK_BACK_SECONDS))

        # Determine fetch window: new tenants start from "now" (no backfill),
        # existing tenants use a rolling lookback window.
        # NOTE: _tenant_ctx is imported at module level — do NOT re-import here
        current_tenant = _tenant_ctx.get()
        if not hasattr(self, '_tenant_first_fetch'):
            self._tenant_first_fetch = {}
        if not hasattr(self, '_tenant_fetch_anchor'):
            self._tenant_fetch_anchor = {}  # tenant_id -> ISO timestamp of first poll
        if not hasattr(self, '_tenant_cursor'):
            # WO-H9: monotonic ASCENDING cursor per tenant. For the direct
            # OpenSearch path this holds the ``search_after`` sort tuple
            # ``[timestamp, _id]`` of the LAST alert fetched, so each poll pages
            # strictly FORWARD past that exact (timestamp, _id) position. A plain
            # gte-timestamp cursor would stall if >batch_size alerts shared one
            # exact timestamp (the same top-N would return forever and the cursor
            # never advances); pairing the timestamp with the tiebreaking ``_id``
            # via search_after makes progress strictly monotonic. In-memory: on
            # restart we re-seed from the fetch window and rely on the durable
            # processed-id dedup to skip already-HANDLED alerts.
            self._tenant_cursor = {}  # tenant_id -> [timestamp, _id] sort tuple
        if not hasattr(self, '_tenant_ts_floor'):
            # Proxy path only: a timestamp-string floor cursor (the dashboard
            # proxy does not return per-hit sort values, so search_after can't be
            # threaded through it). Advanced from the newest fetched timestamp.
            self._tenant_ts_floor = {}  # tenant_id -> ISO timestamp

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

        # WO-H9: prefer the monotonic ascending cursor once we have one for this
        # tenant, so each poll continues FORWARD from the last alert seen rather
        # than re-scanning a sliding desc window (which starved older alerts).

        # Resolve the fetch route first — proxy vs direct — because the cursor
        # strategy differs (search_after needs per-hit sort values the proxy
        # doesn't return).
        proxy_cfg = None
        if self._tenant_registry and current_tenant:
            tenant_cfg = self._tenant_registry.get_tenant_config(current_tenant)
            proxy_cfg = tenant_cfg.get("dashboard_proxy")

        # Precise ascending pagination cursor (direct path) vs timestamp floor.
        search_after = None
        if not proxy_cfg and current_tenant:
            search_after = self._tenant_cursor.get(current_tenant)
        # Timestamp floor: the proxy path's advancing cursor, or the first-poll
        # window before we have a precise cursor.
        lower_bound = fetch_window
        if proxy_cfg and current_tenant and current_tenant in self._tenant_ts_floor:
            lower_bound = self._tenant_ts_floor[current_tenant]

        # WO-H13: capture the high-water mark this poll STARTS from (the cursor
        # the forward scan pages past) BEFORE it is advanced below — the
        # look-back window is measured behind exactly this point. Direct path:
        # the timestamp element of the search_after tuple. Proxy path: the
        # pre-poll ISO timestamp floor. None on the first poll (no cursor yet),
        # where the wide initial fetch_window already covers late arrivals.
        high_water_val = None
        if search_after:
            high_water_val = search_after[0]
        elif proxy_cfg and current_tenant:
            high_water_val = self._tenant_ts_floor.get(current_tenant)

        # Fetch raw alerts from Wazuh's alert index in OpenSearch
        # In multi-tenant mode, scope by the current tenant's allowed agent IDs
        last_sort = None
        # Shared query scoping — min rule level + fail-closed per-tenant agent
        # scoping — built ONCE so the WO-H13 look-back query reuses the exact
        # same restrictions and can never widen a tenant's visibility.
        base_must = None
        try:
            base_must = [
                {"range": {"rule.level": {"gte": min_level}}},
            ]
            if is_multi_tenant() and current_tenant:
                allowed_agents = self.db.get_tenant_agent_ids(current_tenant)
                if allowed_agents is not None:
                    base_must.append({"terms": {"agent.id": allowed_agents}})
                else:
                    # No agent mapping in MT mode — fetch nothing (fail closed)
                    base_must.append({"terms": {"agent.id": []}})

            must_clauses = list(base_must)
            # Only apply the timestamp floor when we have NO precise
            # search_after cursor (first poll, or proxy path). Once search_after
            # is set it supersedes the floor and paginates strictly forward.
            if not search_after:
                must_clauses.append(
                    {"range": {"timestamp": {"gte": lower_bound}}})

            query = {
                "query": {"bool": {"must": must_clauses}},
                # ASCENDING (oldest-first) with a stable ``_id`` tiebreaker so the
                # search_after cursor advances monotonically and >batch_size
                # same-timestamp alerts can't stall the pipeline.
                "sort": [
                    {"timestamp": {"order": "asc"}},
                    {"_id": {"order": "asc"}},
                ],
            }
            if search_after:
                query["search_after"] = search_after

            if proxy_cfg:
                raw_alerts = self._fetch_alerts_dashboard_proxy(
                    proxy_cfg, query, batch_size)
            else:
                result = self.opensearch.client.search(
                    index="wazuh-alerts-4.x-*",
                    body=query,
                    size=batch_size
                )
                hits = result["hits"]["hits"]
                raw_alerts = [hit["_source"] for hit in hits]
                # Capture the LAST hit's sort values as the next search_after
                # cursor (ascending => last hit is the furthest-forward).
                if hits and "sort" in hits[-1]:
                    last_sort = hits[-1]["sort"]
                if raw_alerts:
                    logger.info("wazuh_alerts_fetched_from_opensearch", count=len(raw_alerts))
        except Exception as e:
            logger.error("wazuh_alerts_fetch_failed", error=str(e)[:200])
            raw_alerts = []

        # WO-H9: advance the cursor and emit the backlog-lag metric (how far
        # behind real time we are). We advance from the RAW batch — even alerts
        # that dedup out still count as "seen", so the cursor keeps moving
        # forward and never re-scans them.
        if current_tenant and raw_alerts:
            newest_ts = None
            for raw in raw_alerts:
                ts = raw.get("timestamp") or raw.get("@timestamp")
                if ts and (newest_ts is None or str(ts) > str(newest_ts)):
                    newest_ts = ts
            # Direct path: precise search_after cursor. Proxy path: timestamp
            # floor (advance only forward).
            if last_sort is not None:
                self._tenant_cursor[current_tenant] = last_sort
            elif proxy_cfg and newest_ts:
                prev = self._tenant_ts_floor.get(current_tenant)
                if prev is None or str(newest_ts) >= str(prev):
                    self._tenant_ts_floor[current_tenant] = newest_ts
            if newest_ts:
                try:
                    from datetime import datetime as _dt, timezone as _tz
                    parsed = _dt.fromisoformat(
                        str(newest_ts).replace("Z", "+00:00"))
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=_tz.utc)
                    lag = (_dt.now(_tz.utc) - parsed).total_seconds()
                    self.db.record_metric(
                        "triage_backlog_seconds", max(0.0, lag),
                        {"tenant": current_tenant,
                         "cursor": str(newest_ts),
                         "batch": len(raw_alerts)})
                except Exception:
                    pass

        # WO-H13: bounded look-back overlap. In ADDITION to the forward scan,
        # re-query the small window immediately BEHIND the high-water mark so an
        # alert that arrived out-of-order within it (clock skew, delayed ingest,
        # backfill) is picked up. This does NOT touch the forward cursor or the
        # backlog metric — both stay driven solely by the forward scan above, so
        # the cursor still advances strictly monotonically and can't stall. The
        # look-back re-surfaces already-handled alerts too, but the processed-id
        # dedup in the loop below skips them, so only GENUINELY-new late arrivals
        # are triaged — never a re-triage. The same per-tenant agent scoping
        # (base_must) is reused, so tenant isolation is unchanged. Applies to
        # BOTH the direct-OpenSearch path and the dashboard-proxy path (a plain
        # bounded range query needs no per-hit sort values, unlike search_after).
        # DOCUMENTED BOUND: an alert whose event timestamp is older than
        # (high_water - look_back_seconds) by the time of this poll is NOT caught.
        if (look_back_seconds > 0 and base_must is not None
                and current_tenant and high_water_val is not None):
            hw_ms = _sort_value_to_millis(high_water_val)
            if hw_ms is not None:
                gte_ms = hw_ms - look_back_seconds * 1000
                lookback_must = list(base_must)
                lookback_must.append({
                    "range": {"timestamp": {
                        "gte": gte_ms, "lte": hw_ms,
                        "format": "epoch_millis"}}})
                lookback_query = {
                    "query": {"bool": {"must": lookback_must}},
                    # Ascending + stable _id tiebreaker, mirroring the forward
                    # query; bounded by batch_size so it can't become a re-scan.
                    "sort": [
                        {"timestamp": {"order": "asc"}},
                        {"_id": {"order": "asc"}},
                    ],
                }
                try:
                    if proxy_cfg:
                        lookback_raw = self._fetch_alerts_dashboard_proxy(
                            proxy_cfg, lookback_query, batch_size)
                    else:
                        lb_result = self.opensearch.client.search(
                            index="wazuh-alerts-4.x-*",
                            body=lookback_query,
                            size=batch_size,
                        )
                        lookback_raw = [h["_source"]
                                        for h in lb_result["hits"]["hits"]]
                    if lookback_raw:
                        raw_alerts = raw_alerts + lookback_raw
                        logger.info("triage_lookback_window_scanned",
                                    tenant=current_tenant,
                                    look_back_seconds=look_back_seconds,
                                    candidates=len(lookback_raw))
                except Exception as e:
                    logger.warning("triage_lookback_fetch_failed",
                                   error=str(e)[:200])

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

            # WO-H9 crash-safe checkpoint: do NOT durably mark processed here.
            # The DURABLE ``processed_alerts`` checkpoint is written only once an
            # alert is fully HANDLED — atomically with the triage decision save
            # (store.save_decision) for triaged alerts, or at the below-threshold
            # skip point in the fetch loop. Marking at enrichment (pre-triage)
            # meant a shutdown/crash that dropped the not-yet-triaged queue item
            # left the alert durably "processed" → never re-fetched → SILENT
            # detection loss. The IN-MEMORY add still de-dups boundary re-reads
            # within this process; it is cleared on restart, so a dropped alert
            # is safely re-fetched + re-enriched (idempotent by alert_id) +
            # re-triaged.
            self.processed_ids.add(cache_key)

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
