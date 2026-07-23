"""
Enrichment modules - Add context to raw Wazuh alerts.
Each enricher adds a specific type of intelligence.
"""

import re
import json
import hashlib
import structlog
import requests
from typing import Optional
from datetime import datetime, timezone, timedelta
from fnmatch import fnmatch
from cachetools import TTLCache

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Asset Enricher
# ---------------------------------------------------------------------------

class AssetEnricher:
    """Enriches alerts with asset criticality, ownership, and classification."""

    def __init__(self, config: dict):
        self.assets: dict = {}
        self.risk_criteria: dict = config.get("risk_criteria", {})
        self.source = config.get("source", "file")
        self.file_path = config.get("file_path", "")
        self._load_assets()

    def _load_assets(self):
        """Load asset inventory from configured source."""
        if self.source == "file" and self.file_path:
            try:
                import yaml
                with open(self.file_path) as f:
                    data = yaml.safe_load(f) or {}
                    self.assets = {a["hostname"]: a for a in (data.get("assets") or [])}
                logger.info("assets_loaded", count=len(self.assets))
            except FileNotFoundError:
                logger.warning("asset_file_not_found", path=self.file_path)
            except Exception as e:
                logger.error("asset_load_failed", error=str(e))

    def reload_from_db(self, db):
        """Reload asset data from the database (settings panel)."""
        try:
            db_assets = db.get_assets_as_dict()
            if db_assets:
                self.assets = db_assets
                logger.info("assets_reloaded_from_db", count=len(self.assets))
            else:
                logger.info("assets_db_empty_keeping_current",
                            count=len(self.assets))
        except Exception as e:
            logger.error("asset_db_reload_failed", error=str(e))

    def enrich(self, alert: dict) -> dict:
        """Add asset context to an alert."""
        agent_name = alert.get("agent_name", "")
        enrichment = {
            "asset_tier": "unknown",
            "asset_owner": "unknown",
            "asset_environment": "unknown",
            "asset_criticality_multiplier": 1.0
        }

        # Try exact match first
        if agent_name in self.assets:
            asset = self.assets[agent_name]
            enrichment.update({
                "asset_tier": asset.get("tier", "unknown"),
                "asset_owner": asset.get("owner", "unknown"),
                "asset_environment": asset.get("environment", "unknown"),
                "asset_criticality_multiplier": asset.get("criticality_multiplier", 1.0),
                "asset_tags": asset.get("tags", []),
                "asset_services": asset.get("services", [])
            })
        else:
            # Pattern-based matching from risk criteria
            for tier_name, tier_config in self.risk_criteria.get("asset_criticality", {}).items():
                patterns = tier_config.get("patterns", [])
                for pattern in patterns:
                    if fnmatch(agent_name.lower(), pattern.lower()):
                        enrichment["asset_tier"] = tier_name
                        enrichment["asset_criticality_multiplier"] = tier_config.get("risk_multiplier", 1.0)
                        break

        return enrichment


# ---------------------------------------------------------------------------
# Identity Enricher
# ---------------------------------------------------------------------------

class IdentityEnricher:
    """Enriches alerts with user context: roles, privileges, behavior patterns."""

    def __init__(self, config: dict):
        self.identities: dict = {}
        self.risk_criteria: dict = config.get("risk_criteria", {})
        self.source = config.get("source", "file")
        self.file_path = config.get("file_path", "")
        self._load_identities()

    def _load_identities(self):
        if self.source == "file" and self.file_path:
            try:
                import yaml
                with open(self.file_path) as f:
                    data = yaml.safe_load(f) or {}
                    self.identities = {u["username"]: u for u in (data.get("users") or [])}
                logger.info("identities_loaded", count=len(self.identities))
            except FileNotFoundError:
                logger.warning("identity_file_not_found", path=self.file_path)
            except Exception as e:
                logger.error("identity_load_failed", error=str(e))

    def reload_from_db(self, db):
        """Reload identity data from the database (settings panel)."""
        try:
            db_identities = db.get_identities_as_dict()
            if db_identities:
                self.identities = db_identities
                logger.info("identities_reloaded_from_db",
                            count=len(self.identities))
            else:
                logger.info("identities_db_empty_keeping_current",
                            count=len(self.identities))
        except Exception as e:
            logger.error("identity_db_reload_failed", error=str(e))

    def enrich(self, alert: dict) -> dict:
        """Add identity context to an alert."""
        users = set()
        for field in ["src_user", "dst_user"]:
            if alert.get(field):
                users.add(alert[field])

        enrichment = {
            "user_risk_level": "standard",
            "user_risk_multiplier": 1.0,
            "user_roles": [],
            "user_has_admin": False,
            "user_is_service_account": False,
            "user_department": "unknown"
        }

        max_risk = 1.0
        for username in users:
            if username in self.identities:
                identity = self.identities[username]
                risk = identity.get("risk_multiplier", 1.0)
                if risk > max_risk:
                    max_risk = risk
                    enrichment.update({
                        "user_risk_level": identity.get("risk_level", "standard"),
                        "user_risk_multiplier": risk,
                        "user_roles": identity.get("roles", []),
                        "user_has_admin": identity.get("is_admin", False),
                        "user_is_service_account": identity.get("is_service_account", False),
                        "user_department": identity.get("department", "unknown"),
                        "user_normal_hours": identity.get("normal_hours", {}),
                        "user_normal_ips": identity.get("known_ips", []),
                        "user_onboarded_date": identity.get("onboarded_date", "")
                    })
            else:
                # Unknown user = elevated risk
                if username not in ("root", "SYSTEM", "LOCAL SERVICE"):
                    enrichment["user_risk_level"] = "elevated"
                    enrichment["user_risk_multiplier"] = max(max_risk, 1.5)

        return enrichment


# ---------------------------------------------------------------------------
# Threat Intelligence Enricher
# ---------------------------------------------------------------------------

class ThreatIntelEnricher:
    """Enriches alerts with threat intelligence from multiple feeds."""

    def __init__(self, config: dict):
        self.feeds = config.get("feeds", [])
        self.local_iocs: dict = {}
        self._ioc_cache = TTLCache(maxsize=10000, ttl=3600 * 24)
        self._load_local_iocs(config.get("local_iocs_file", ""))

    def _load_local_iocs(self, file_path: str):
        if file_path:
            try:
                import yaml
                with open(file_path) as f:
                    data = yaml.safe_load(f) or {}
                    for ioc_type in ["ips", "domains", "hashes"]:
                        for ioc in (data.get(ioc_type) or []):
                            self.local_iocs[ioc["value"]] = {
                                "source": "local",
                                "type": ioc_type,
                                "severity": ioc.get("severity", "medium"),
                                "description": ioc.get("description", "")
                            }
                logger.info("local_iocs_loaded", count=len(self.local_iocs))
            except Exception as e:
                logger.warning("local_iocs_load_failed", error=str(e))

    def _check_abuseipdb(self, ip: str, api_key: str) -> Optional[dict]:
        """Query AbuseIPDB for IP reputation."""
        cache_key = f"abuseipdb:{ip}"
        if cache_key in self._ioc_cache:
            return self._ioc_cache[cache_key]
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                result = {
                    "source": "abuseipdb",
                    "abuse_confidence": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                    "is_tor": data.get("isTor", False)
                }
                self._ioc_cache[cache_key] = result
                return result
        except Exception as e:
            logger.warning("abuseipdb_check_failed", ip=ip, error=str(e))
        return None

    def _check_otx(self, indicator_type: str, value: str, api_key: str) -> Optional[dict]:
        """Query AlienVault OTX for indicator reputation."""
        cache_key = f"otx:{indicator_type}:{value}"
        if cache_key in self._ioc_cache:
            return self._ioc_cache[cache_key]

        type_map = {"ip": "IPv4", "hash": "file", "domain": "domain"}
        otx_type = type_map.get(indicator_type)
        if not otx_type:
            return None

        try:
            resp = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{value}/general",
                headers={"X-OTX-API-KEY": api_key, "Accept": "application/json"},
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                pulse_info = data.get("pulse_info", {})
                pulse_count = pulse_info.get("count", 0)
                pulses = pulse_info.get("pulses", [])
                pulse_names = [p.get("name", "") for p in pulses[:5]]
                tags = set()
                for p in pulses[:10]:
                    tags.update(p.get("tags", []))

                result = {
                    "source": "alienvault_otx",
                    "pulse_count": pulse_count,
                    "pulse_names": pulse_names,
                    "tags": list(tags)[:20],
                    "country": data.get("country_name", ""),
                    "reputation": data.get("reputation", 0)
                }
                self._ioc_cache[cache_key] = result
                logger.info("otx_lookup_hit", indicator=value, pulse_count=pulse_count)
                return result
            elif resp.status_code == 404:
                self._ioc_cache[cache_key] = None
                return None
            else:
                logger.warning("otx_check_non_200", indicator=value, status=resp.status_code)
        except Exception as e:
            logger.warning("otx_check_failed", indicator=value, error=str(e))
        return None

    def enrich(self, alert: dict) -> dict:
        """Check alert indicators against threat intelligence."""
        enrichment = {
            "threat_intel_hits": 0,
            "threat_intel_sources": [],
            "threat_intel_details": [],
            "is_known_malicious": False,
            "highest_ti_severity": "none"
        }

        indicators = set()
        for field in ["src_ip", "dst_ip"]:
            if alert.get(field) and not self._is_private_ip(alert[field]):
                indicators.add(("ip", alert[field]))

        for field in ["data.md5", "data.sha256"]:
            val = self._nested_get(alert, field)
            if val:
                indicators.add(("hash", val))

        severity_rank = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        max_severity = "none"

        for ioc_type, value in indicators:
            # Check local IOCs
            if value in self.local_iocs:
                hit = self.local_iocs[value]
                enrichment["threat_intel_hits"] += 1
                enrichment["threat_intel_sources"].append("local")
                enrichment["threat_intel_details"].append({
                    "indicator": value, "type": ioc_type, **hit
                })
                if severity_rank.get(hit.get("severity", ""), 0) > severity_rank.get(max_severity, 0):
                    max_severity = hit["severity"]

            # Check AbuseIPDB for IPs
            if ioc_type == "ip":
                for feed in self.feeds:
                    if feed["name"] == "abuse_ipdb" and feed.get("api_key"):
                        result = self._check_abuseipdb(value, feed["api_key"])
                        if result and result.get("abuse_confidence", 0) > 25:
                            enrichment["threat_intel_hits"] += 1
                            enrichment["threat_intel_sources"].append("abuseipdb")
                            enrichment["threat_intel_details"].append({
                                "indicator": value, "type": "ip", **result
                            })
                            if result["abuse_confidence"] > 75:
                                max_severity = "high"
                            elif result["abuse_confidence"] > 50:
                                max_severity = max(max_severity, "medium",
                                                   key=lambda x: severity_rank.get(x, 0))

            # Check AlienVault OTX for all indicator types
            for feed in self.feeds:
                if feed["name"] == "alienvault_otx" and feed.get("api_key"):
                    result = self._check_otx(ioc_type, value, feed["api_key"])
                    if result and result.get("pulse_count", 0) > 0:
                        enrichment["threat_intel_hits"] += 1
                        enrichment["threat_intel_sources"].append("alienvault_otx")
                        enrichment["threat_intel_details"].append({
                            "indicator": value, "type": ioc_type, **result
                        })
                        pulse_count = result["pulse_count"]
                        if pulse_count >= 20:
                            max_severity = "high"
                        elif pulse_count >= 5:
                            max_severity = max(max_severity, "medium",
                                               key=lambda x: severity_rank.get(x, 0))
                        elif pulse_count >= 1:
                            max_severity = max(max_severity, "low",
                                               key=lambda x: severity_rank.get(x, 0))

        enrichment["highest_ti_severity"] = max_severity
        enrichment["is_known_malicious"] = max_severity in ("high", "critical")
        return enrichment

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if IP is private/reserved (IPv4 and IPv6)."""
        import ipaddress as _ipaddress
        try:
            return _ipaddress.ip_address(ip).is_private
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _nested_get(d: dict, key: str):
        """Get nested dict value with dot notation."""
        keys = key.split(".")
        for k in keys:
            if isinstance(d, dict):
                d = d.get(k)
            else:
                return None
        return d


# ---------------------------------------------------------------------------
# Historical Enricher
# ---------------------------------------------------------------------------

class HistoricalEnricher:
    """Enriches alerts with historical context: baselines, patterns, FP rates.

    Anomaly detection compares current 24-hour activity against 30-day
    behavioral baselines per agent, user, and source IP.  Alerts that
    deviate beyond the configured standard-deviation threshold are
    flagged for elevated scrutiny.
    """

    def __init__(self, config: dict, opensearch_client=None, db=None):
        self.opensearch = opensearch_client
        self.db = db
        self.baseline_window = config.get("baseline_window_days", 30)
        self.anomaly_threshold = config.get("anomaly_std_deviations", 2.5)
        # Short-lived cache: (dimension_field, value) → 24h count
        self._count_cache = TTLCache(maxsize=5000, ttl=300)

    def _get_24h_count(self, dimension_field: str, value: str) -> int:
        """Get alert count for a dimension in the last 24h (cached 5 min)."""
        cache_key = (dimension_field, value)
        if cache_key in self._count_cache:
            return self._count_cache[cache_key]
        if not self.opensearch:
            return 0
        count = self.opensearch.get_alert_count_since(dimension_field, value, hours=24)
        self._count_cache[cache_key] = count
        return count

    def _check_anomaly(self, dimension: str, dimension_field: str,
                       value: str) -> tuple[bool, float, dict]:
        """
        Check if current 24h activity deviates from the stored baseline.
        Returns (is_anomaly, z_score, details).
        """
        if not self.db or not value:
            return False, 0.0, {}

        baseline = self.db.get_baseline(dimension, str(value), "daily_alert_count")
        if not baseline or baseline["sample_count"] < 3:
            return False, 0.0, {}

        current_count = self._get_24h_count(dimension_field, value)
        mean = baseline["mean"]
        std_dev = baseline["std_dev"]

        # Avoid division by zero — if stddev is 0 the entity has perfectly
        # consistent behavior; any count above mean is noteworthy
        if std_dev < 0.5:
            std_dev = 0.5

        z_score = (current_count - mean) / std_dev

        details = {
            "dimension": dimension,
            "value": str(value),
            "current_24h": current_count,
            "baseline_mean": round(mean, 2),
            "baseline_std": round(std_dev, 2),
            "z_score": round(z_score, 2),
            "sample_days": baseline["sample_count"]
        }

        return z_score > self.anomaly_threshold, z_score, details

    def enrich(self, alert: dict) -> dict:
        """Add historical context and anomaly detection to an alert."""
        enrichment = {
            "historical_fp_rate": 0.0,
            "historical_occurrence_count": 0,
            "same_rule_last_7d": 0,
            "same_source_last_7d": 0,
            "same_user_last_7d": 0,
            "baseline_anomaly": False,
            "baseline_deviation": 0.0,
            "baseline_anomaly_details": [],
            "previously_seen_pattern": False
        }

        rule_id = alert.get("rule_id")

        # Get FP rate from local database
        if self.db and rule_id:
            fp_stats = self.db.get_fp_rate_for_rule(rule_id, days=7)
            enrichment["historical_fp_rate"] = fp_stats.get("fp_rate", 0)
            enrichment["historical_occurrence_count"] = fp_stats.get("total", 0)
            enrichment["same_rule_last_7d"] = fp_stats.get("total", 0)

        # Get correlated history from OpenSearch
        if self.opensearch:
            try:
                # Same source IP history
                if alert.get("src_ip"):
                    src_history = self.opensearch.get_alert_history_for_source(
                        alert["src_ip"], days=7
                    )
                    enrichment["same_source_last_7d"] = len(src_history)

                # Same user history
                for user_field in ["src_user", "dst_user"]:
                    if alert.get(user_field):
                        user_history = self.opensearch.get_alert_history_for_user(
                            alert[user_field], days=7
                        )
                        enrichment["same_user_last_7d"] = max(
                            enrichment["same_user_last_7d"], len(user_history)
                        )

                # Check if this exact pattern was seen before
                if alert.get("agent_id") and rule_id:
                    host_rule_history = self.opensearch.search_alerts({
                        "query": {
                            "bool": {
                                "must": [
                                    {"term": {"agent_id": alert["agent_id"]}},
                                    {"term": {"rule_id": rule_id}},
                                    {"range": {"timestamp": {"gte": "now-30d"}}}
                                ]
                            }
                        }
                    }, size=10)
                    if len(host_rule_history) > 0:
                        enrichment["previously_seen_pattern"] = True

            except Exception as e:
                logger.warning("historical_enrichment_partial_failure", error=str(e))

        # --- Behavioral baseline anomaly detection ---
        max_z = 0.0
        anomaly_details = []

        checks = [
            ("agent", "agent_name", alert.get("agent_name")),
            ("src_ip", "src_ip", alert.get("src_ip")),
            ("src_user", "src_user", alert.get("src_user")),
        ]

        for dim_name, os_field, value in checks:
            if not value:
                continue
            try:
                is_anomaly, z_score, details = self._check_anomaly(
                    dim_name, os_field, value
                )
                if is_anomaly:
                    anomaly_details.append(details)
                if z_score > max_z:
                    max_z = z_score
            except Exception as e:
                logger.warning("baseline_check_failed",
                               dimension=dim_name, error=str(e))

        if anomaly_details:
            enrichment["baseline_anomaly"] = True
            enrichment["baseline_deviation"] = round(max_z, 2)
            enrichment["baseline_anomaly_details"] = anomaly_details
            logger.info("baseline_anomaly_detected",
                         alert_id=alert.get("alert_id"),
                         deviation=round(max_z, 2),
                         dimensions=[d["dimension"] for d in anomaly_details])

        return enrichment


# ---------------------------------------------------------------------------
# Time Context Enricher
# ---------------------------------------------------------------------------

class TimeContextEnricher:
    """Adds time-based context: business hours, maintenance windows, etc."""

    def __init__(self, config: dict):
        self.time_config = config.get("time_context", {})

    def enrich(self, alert: dict) -> dict:
        """Determine time context for the alert."""
        timestamp_str = alert.get("timestamp", "")
        try:
            if isinstance(timestamp_str, str):
                # Handle common Wazuh timestamp formats
                for fmt in ["%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                             "%Y-%m-%d %H:%M:%S"]:
                    try:
                        ts = datetime.strptime(timestamp_str, fmt)
                        break
                    except ValueError:
                        continue
                else:
                    ts = datetime.now(timezone.utc)
            else:
                ts = datetime.now(timezone.utc)
        except Exception:
            ts = datetime.now(timezone.utc)

        bh = self.time_config.get("business_hours", {})
        is_business_hours = self._is_business_hours(ts, bh)
        is_maintenance = self._is_maintenance_window(ts)
        is_weekend = ts.strftime("%A").lower() in ("saturday", "sunday")

        # Calculate time multiplier
        multiplier = 1.0
        adj = self.time_config.get("risk_adjustments", {})
        if is_maintenance:
            multiplier *= adj.get("maintenance_window_multiplier", 0.3)
        elif not is_business_hours:
            multiplier *= adj.get("outside_business_hours_multiplier", 1.5)
        if is_weekend:
            multiplier *= adj.get("weekend_multiplier", 1.3)

        return {
            "time_context": self._get_context_label(is_business_hours, is_maintenance, is_weekend),
            "is_business_hours": is_business_hours,
            "is_maintenance_window": is_maintenance,
            "is_weekend": is_weekend,
            "time_risk_multiplier": multiplier
        }

    def _is_business_hours(self, ts: datetime, bh: dict) -> bool:
        try:
            start = datetime.strptime(bh.get("start", "09:00"), "%H:%M").time()
            end = datetime.strptime(bh.get("end", "18:00"), "%H:%M").time()
            day_name = ts.strftime("%A").lower()
            bh_days = [d.lower() for d in bh.get("days", [])]
            return day_name in bh_days and start <= ts.time() <= end
        except Exception:
            return True  # Default to business hours

    def _is_maintenance_window(self, ts: datetime) -> bool:
        windows = self.time_config.get("maintenance_windows", [])
        day_name = ts.strftime("%A").lower()
        for window in windows:
            w_days = window.get("days", [window.get("day", "")])
            w_days = [d.lower() for d in w_days if d]
            if day_name in w_days:
                try:
                    start = datetime.strptime(window["start"], "%H:%M").time()
                    end = datetime.strptime(window["end"], "%H:%M").time()
                    if start <= end:
                        in_window = start <= ts.time() <= end
                    else:  # Crosses midnight (e.g., 22:00-06:00)
                        in_window = ts.time() >= start or ts.time() <= end
                    if in_window:
                        return True
                except Exception:
                    pass
        return False

    @staticmethod
    def _get_context_label(bh: bool, maint: bool, weekend: bool) -> str:
        if maint:
            return "maintenance_window"
        if weekend:
            return "weekend"
        if bh:
            return "business_hours"
        return "outside_business_hours"


# ---------------------------------------------------------------------------
# Vulnerability Context Enricher (M4 — Context-into-Triage)
# ---------------------------------------------------------------------------

class VulnerabilityContextEnricher:
    """Amplify the risk score with the affected host's vuln + SCA posture.

    For the alert's ``agent_id`` this fetches the host's vulnerabilities from
    the Wazuh vulnerability STATE index in OpenSearch
    (``wazuh-states-vulnerabilities-*``) and the host's SCA (CIS) check results
    from the tenant-scoped Wazuh Manager client, and emits a bounded
    ``vuln_context_multiplier`` plus a human-readable ``vuln_context_reason``.

    WHY OPENSEARCH FOR VULNS (WO-H11): the Wazuh Manager API endpoint
    ``GET /vulnerability/{agent}`` was REMOVED in Wazuh 4.8+ — it 404s, so the
    old ``client.get_agent_vulnerabilities()`` fetch silently returned nothing
    and the entire vuln-context signal was dead on modern Wazuh. Vuln data now
    lives one-doc-per-package-CVE in ``wazuh-states-vulnerabilities-<cluster>``
    with an ECS-nested ``_source`` (``agent.id``, ``vulnerability.id`` = CVE,
    ``vulnerability.severity`` capitalized, ``package.*``). The parsing helpers
    ``_severity``/``_cve_id`` already read that nested shape, so only the FETCH
    SOURCE moved — the scoring/multiplier logic is unchanged. SCA still uses the
    Manager client (its ``/sca/{agent}`` endpoint is unaffected).

    SHARPEN, NEVER MANUFACTURE: because the score is multiplicative the
    multiplier only amplifies an already-present signal — a low-base benign
    alert stays low.  Magnitudes are deliberately modest and the combined
    product is capped so even the most-vulnerable host cannot push a benign
    alert across the escalation/HIGH band on vuln context alone.

    TENANT ISOLATION (security-critical): the Wazuh vuln state index carries no
    ``client_id``, so — exactly like the alert-read path in
    ``EnrichmentService.process_batch`` — tenant isolation is enforced by
    restricting the query's ``agent.id`` to the SET of agents mapped to the
    caller's tenant (``db.get_tenant_agent_ids``), in addition to the alert's
    own ``agent_id``. No tenant context / multi-tenant-with-no-registry / a
    tenant with no agent mapping all fail CLOSED (fetch nothing → multiplier
    1.0); a wrong tenant's vulns can never reach another tenant's triage.

    DEFENSE-IN-DEPTH: vuln context is an additive scoring enhancement, not a
    security control.  Every failure path (no client, missing agent_id, fetch
    error, absent index, and crucially the M2 fail-closed
    ``TenantConfigUnavailable``) degrades to multiplier 1.0 and is logged —
    ``enrich`` never raises, so it can never block the triage/enrichment cycle.
    """

    # Bounded magnitudes. Kept modest so they sharpen rather than manufacture.
    DEFAULT_CRITICAL_MULT = 1.5
    DEFAULT_HIGH_MULT = 1.2
    DEFAULT_SCA_FAILED_MULT = 1.3
    # Hard ceiling on the combined product — prevents runaway stacking.
    DEFAULT_MAX_MULT = 1.8
    # Min number of failed SCA checks before the SCA factor engages.
    DEFAULT_SCA_FAILED_THRESHOLD = 1
    # Wazuh 4.x vulnerability STATE index (one doc per package-CVE). Wildcard
    # spans the per-cluster suffix (``wazuh-states-vulnerabilities-<cluster>``).
    VULN_INDEX = "wazuh-states-vulnerabilities-*"
    # Size cap on the per-host vuln fetch. A host with more open CVEs than this
    # is already maximally "critical" for scoring purposes, so the cap is safe.
    DEFAULT_VULN_FETCH_SIZE = 500

    # WO-H23: cap on the per-host CVE detail list (CVSS/EPSS/KEV). Aligned with
    # the existing ``top_critical_cves`` cap so the two stay 1:1.
    TOP_CVE_DETAIL_MAX = 3

    def __init__(self, config: dict, tenant_registry=None, wazuh_client=None,
                 registry_provider=None, wazuh_provider=None,
                 opensearch_client=None, opensearch_provider=None,
                 db=None, db_provider=None):
        cfg = config or {}
        self.enabled = cfg.get("enabled", True)
        self.critical_mult = float(cfg.get("critical_multiplier",
                                           self.DEFAULT_CRITICAL_MULT))
        self.high_mult = float(cfg.get("high_multiplier",
                                       self.DEFAULT_HIGH_MULT))
        self.sca_failed_mult = float(cfg.get("sca_failed_multiplier",
                                             self.DEFAULT_SCA_FAILED_MULT))
        self.max_mult = float(cfg.get("max_multiplier",
                                      self.DEFAULT_MAX_MULT))
        self.sca_failed_threshold = int(cfg.get("sca_failed_threshold",
                                                self.DEFAULT_SCA_FAILED_THRESHOLD))
        self.vuln_fetch_size = int(cfg.get("vuln_fetch_size",
                                           self.DEFAULT_VULN_FETCH_SIZE))
        self.cache_ttl = int(cfg.get("cache_ttl", 300))
        # Direct references (used in tests / single-tenant) ...
        self._tenant_registry = tenant_registry
        self._wazuh = wazuh_client
        # OpenSearch handle for the vuln STATE-index fetch (WO-H11). This is the
        # SAME shared indexer client the alert-read path uses; tenant isolation
        # is by agent.id scoping, not a per-tenant OpenSearch connection.
        self._opensearch = opensearch_client
        # ... plus optional late-binding providers so the owning service can
        # expose a registry/client that is wired AFTER this enricher is built
        # (main.py sets service._tenant_registry post-construction).
        self._registry_provider = registry_provider
        self._wazuh_provider = wazuh_provider
        self._opensearch_provider = opensearch_provider
        # WO-H23: optional platform DB handle for per-CVE EPSS/KEV lookups
        # against the local ``threat_intel_cve`` table (populated by the CISA
        # KEV + EPSS collectors). CVE metadata is GLOBAL public reference data
        # (no tenant column), so this lookup is not tenant-scoped and cannot
        # leak another tenant's data. Best-effort: absent db → CVSS-only detail.
        self._db = db
        self._db_provider = db_provider
        # Short-lived per-agent cache: (tenant_id, agent_id) -> enrichment dict
        self._cache = TTLCache(maxsize=2000, ttl=max(1, self.cache_ttl))

    def _empty(self) -> dict:
        """No-op / no-signal enrichment: multiplier 1.0, empty reason."""
        return {
            "host_vulnerabilities_critical": 0,
            "host_vulnerabilities_high": 0,
            "host_sca_failed_checks": 0,
            "host_top_critical_cves": [],
            "vuln_context_multiplier": 1.0,
            "vuln_context_reason": "",
            # WO-H23 finding-level detail (display-only): per-CVE CVSS/EPSS/KEV.
            "host_top_cve_details": [],
        }

    def _resolve_client(self):
        """Resolve the Wazuh client for the active tenant.

        Tenant is read from the SAME contextvar the pipeline already sets
        (``_tenant_ctx``); the read path uses the tenant-scoped client only.
        Falls back to the global client (single-tenant) when no registry is
        wired.  Propagates ``TenantConfigUnavailable`` to the caller, which
        handles the M2 fail-closed case explicitly.
        """
        registry = self._tenant_registry
        if registry is None and self._registry_provider is not None:
            registry = self._registry_provider()
        if registry is not None:
            # Import here to avoid a hard dependency / import cycle in shared
            # code; the contextvar lives next to the DB store.
            from src.database.store import _tenant_ctx
            tenant_id = _tenant_ctx.get()
            if tenant_id and tenant_id != "__CROSS_TENANT__":
                # May raise TenantConfigUnavailable (M2 fail-closed). We let it
                # propagate; enrich() catches it and degrades to 1.0.
                return registry.get_wazuh_client(tenant_id), tenant_id
            # No usable tenant context — do not fetch under another tenant.
            return None, tenant_id
        # No registry resolvable. In MULTI-TENANT mode we must NEVER touch the
        # global client: doing so would fetch one tenant's host vulns through a
        # cross-tenant client. The safety property "no tenant context → no vuln
        # multiplier" must hold by construction, not by init timing (the
        # registry is wired into EnrichmentService AFTER construction). Degrade
        # to the no-client path (multiplier 1.0) instead.
        from src.database.store import is_multi_tenant
        if is_multi_tenant():
            logger.warning("vuln_context_no_tenant_registry")
            return None, None
        # Genuine single-tenant deployment: use the global client if provided.
        wazuh = self._wazuh
        if wazuh is None and self._wazuh_provider is not None:
            wazuh = self._wazuh_provider()
        return wazuh, None

    def _resolve_vuln_scope(self, tenant_id):
        """Resolve ``(opensearch_client, allowed_agent_ids)`` for the vuln fetch.

        The OpenSearch handle is the shared indexer client — the SAME one the
        alert-read path (``EnrichmentService.process_batch``) uses. The Wazuh
        vuln STATE index carries no ``client_id``, so tenant isolation is by
        restricting ``agent.id`` to the tenant's mapped agents:

          * ``tenant_id is None`` (genuine single-tenant, per ``_resolve_client``)
            → no agent restriction (``allowed_agent_ids=None``).
          * multi-tenant tenant → restrict to ``db.get_tenant_agent_ids(tenant)``.
            A ``None`` mapping (no agents configured) or an unresolvable
            registry/db degrades to an EMPTY allow-set — the fetch then matches
            nothing (fail closed), never the whole index. This mirrors
            ``process_batch``'s ``allowed_agents is None → terms: []`` rule.

        Only reached once ``_resolve_client`` has already established a usable,
        tenant-appropriate context (its ``None`` client short-circuits ``enrich``
        before this runs), so the tenant gate itself is enforced upstream.
        """
        os_client = self._opensearch
        if os_client is None and self._opensearch_provider is not None:
            os_client = self._opensearch_provider()

        if tenant_id is None:
            # Single-tenant: shared OpenSearch, no per-agent restriction.
            return os_client, None

        registry = self._tenant_registry
        if registry is None and self._registry_provider is not None:
            registry = self._registry_provider()

        allowed = None
        db = getattr(registry, "db", None) if registry is not None else None
        if db is not None:
            try:
                allowed = db.get_tenant_agent_ids(tenant_id)
            except Exception as e:
                logger.warning("vuln_context_agent_scope_failed",
                               tenant_id=tenant_id, error=str(e)[:200])
                allowed = None
        # Fail CLOSED: no mapping / unresolvable db → empty scope → fetch
        # nothing, rather than the whole (cross-tenant) index.
        if allowed is None:
            allowed = []
        return os_client, allowed

    @staticmethod
    def _is_index_absent(exc: Exception) -> bool:
        """True if ``exc`` indicates the vuln STATE index does not exist.

        Distinguishes a genuinely-absent index (fresh cluster / vuln detector
        disabled) — which is a benign "no data" condition — from a real
        OpenSearch fault. Defensive across opensearch-py versions: checks the
        HTTP ``status_code`` (404) and the exception text for the OpenSearch
        ``index_not_found_exception`` marker.
        """
        if getattr(exc, "status_code", None) == 404:
            return True
        text = str(exc).lower()
        return "index_not_found" in text or "no such index" in text

    def _fetch_vulns(self, os_client, agent_id, allowed_agent_ids) -> list:
        """Fetch the host's vuln STATE docs (raw ``_source``) from OpenSearch.

        Query: ``term agent.id == <agent_id>`` (the alert's host), AND — when a
        tenant scope is supplied — ``terms agent.id in <allowed_agent_ids>`` so
        a spoofed/foreign ``agent_id`` cannot pull another tenant's vulns. Size
        bounded by ``vuln_fetch_size``. Returns the raw ``_source`` dicts so the
        existing ``_severity``/``_cve_id`` parsing consumes them unchanged.

        Fail-safe & self-observable: an absent index logs ``vuln_context_index_absent``
        and returns ``[]`` (so SCA can still run); any other OpenSearch fault
        propagates to ``enrich``'s handler (→ multiplier 1.0). "No vulns found"
        is logged distinctly from "index absent" so the signal can't silently die.
        """
        if os_client is None:
            logger.debug("vuln_context_no_opensearch", agent_id=str(agent_id))
            return []
        must = [{"term": {"agent.id": str(agent_id)}}]
        if allowed_agent_ids is not None:
            must.append(
                {"terms": {"agent.id": [str(a) for a in allowed_agent_ids]}})
        body = {"query": {"bool": {"must": must}}}
        try:
            result = os_client.client.search(
                index=self.VULN_INDEX, body=body, size=self.vuln_fetch_size)
        except Exception as e:
            if self._is_index_absent(e):
                logger.info("vuln_context_index_absent",
                            index=self.VULN_INDEX, agent_id=str(agent_id))
                return []
            raise
        hits = (result or {}).get("hits", {}).get("hits", [])
        if not hits:
            logger.debug("vuln_context_no_vulns_for_host",
                         agent_id=str(agent_id))
        return [h.get("_source", {}) for h in hits]

    @staticmethod
    def _severity(vuln: dict) -> str:
        """Extract a normalized lowercase severity from a Wazuh vuln item."""
        sev = (vuln.get("vulnerability", {}) or {}).get("severity")
        if sev is None:
            sev = vuln.get("severity")
        return str(sev or "").strip().lower()

    @staticmethod
    def _cve_id(vuln: dict) -> str:
        cid = (vuln.get("vulnerability", {}) or {}).get("id")
        if not cid:
            cid = vuln.get("cve") or vuln.get("id")
        return str(cid or "")

    @staticmethod
    def _cvss(vuln: dict) -> tuple:
        """Extract ``(cvss_base, cvss_version)`` from a Wazuh vuln STATE doc.

        Wazuh 4.x nests this under ``vulnerability.score`` (``base`` +
        ``version``); flatter shapes are tolerated as a fallback. Returns
        ``(None, None)`` when nothing parseable is present — the case view then
        shows an honest absent state rather than a fabricated 0.0. WO-H23."""
        score = (vuln.get("vulnerability", {}) or {}).get("score")
        base = None
        version = None
        if isinstance(score, dict):
            base = score.get("base")
            version = score.get("version")
        if base is None:
            base = vuln.get("cvss") or vuln.get("cvss_score")
        try:
            base = float(base) if base is not None else None
        except (TypeError, ValueError):
            base = None
        return base, (str(version) if version else None)

    def _resolve_db(self):
        """Resolve the platform DB handle for per-CVE EPSS/KEV lookups (or
        None). Never raises."""
        db = self._db
        if db is None and self._db_provider is not None:
            try:
                db = self._db_provider()
            except Exception:
                db = None
        return db

    @staticmethod
    def _kev_catalog_populated(db) -> bool:
        """Has the CISA-KEV feed EVER populated the local catalog? (WO-H23)

        On a fresh install / Community box the KEV feed may not have cycled yet,
        so a CVE's ``in_cisa_kev = 0`` is NOT trustworthy as "not in KEV" — it's
        UNKNOWN. This distinguishes the two: only when the catalog has at least
        one KEV entry is a ``0`` flag a genuine known-negative. Fail-safe: no db
        / query error → ``False`` (treat KEV status as unknown, never a false
        negative)."""
        if db is None:
            return False
        try:
            return bool(db.get_kev_cves(limit=1))
        except Exception as e:
            logger.debug("vuln_context_kev_catalog_check_failed",
                         error=str(e)[:200])
            return False

    def _cve_intel(self, db, cve_id: str, kev_available: bool) -> dict:
        """EPSS/KEV for a CVE from the local ``threat_intel_cve`` table (WO-H23).

        Fail-safe & NEVER-FABRICATE: no db handle / CVE not in the table / any
        query error → ``{}`` (the case view shows an honest absent/unknown state,
        never a guessed score). ``epss`` is included only when the row carries a
        real value. CVE metadata is global public reference data (no tenant
        column) — not a tenant leak.

        KEV is TRI-STATE and honest about "unknown":
          * ``kev = True``  → the CVE is genuinely in CISA KEV.
          * ``kev = False`` → the KEV catalog IS populated but this CVE is not in
            it (a real known-negative).
          * ``kev`` KEY OMITTED → we cannot tell (no CVE row, or the KEV catalog
            is empty/unpopulated). The UI renders this as "KEV data unavailable",
            NOT "not in KEV".
        """
        if not cve_id or db is None:
            return {}
        try:
            row = db.lookup_cve(cve_id)
        except Exception as e:
            logger.debug("vuln_context_cve_intel_failed",
                         cve=cve_id, error=str(e)[:200])
            return {}
        if not isinstance(row, dict):
            return {}
        out: dict = {}
        epss = row.get("epss_score")
        if epss is not None:
            try:
                out["epss"] = float(epss)
            except (TypeError, ValueError):
                pass
        pct = row.get("epss_percentile")
        if pct is not None:
            try:
                out["epss_percentile"] = float(pct)
            except (TypeError, ValueError):
                pass
        if row.get("in_cisa_kev"):
            out["kev"] = True
        elif kev_available:
            # Row exists + the KEV catalog is populated → a genuine not-in-KEV.
            out["kev"] = False
        # else: KEV status unknown → omit the key (UI shows "unavailable").
        return out

    def enrich(self, alert: dict) -> dict:
        """Add host vuln/SCA context. Never raises."""
        if not self.enabled:
            return self._empty()

        agent_id = alert.get("agent_id")
        if not agent_id or agent_id == "000":
            # No host to scope to (000 = Wazuh manager itself).
            return self._empty()

        # Resolve the tenant-scoped client; M2 fail-closed is handled here.
        try:
            client, tenant_id = self._resolve_client()
        except Exception as e:
            # Includes TenantConfigUnavailable (M2 fail-closed). Vuln context
            # is an enhancement, not a security control — degrade, never block.
            tenant_id = None
            try:
                from src.database.store import _tenant_ctx
                tenant_id = _tenant_ctx.get()
            except Exception:
                pass
            logger.warning("vuln_context_unavailable",
                           tenant_id=tenant_id,
                           agent_id=agent_id,
                           error=str(e)[:200])
            return self._empty()

        if client is None:
            logger.debug("vuln_context_no_client", agent_id=agent_id)
            return self._empty()

        cache_key = (tenant_id, str(agent_id))
        if cache_key in self._cache:
            return dict(self._cache[cache_key])

        # Resolve the OpenSearch handle + tenant agent-scope for the vuln fetch
        # (WO-H11). ``client`` (the tenant-scoped Wazuh Manager client) is still
        # used for the SCA path below. ``tenant_id`` was established by
        # ``_resolve_client`` above and drives the agent-id isolation scope.
        os_client, allowed_agent_ids = self._resolve_vuln_scope(tenant_id)

        try:
            result = self._compute(os_client, client, agent_id,
                                   allowed_agent_ids)
        except Exception as e:
            logger.warning("vuln_context_fetch_failed",
                           tenant_id=tenant_id,
                           agent_id=agent_id,
                           error=str(e)[:200])
            return self._empty()

        self._cache[cache_key] = dict(result)
        return result

    def _compute(self, os_client, sca_client, agent_id,
                 allowed_agent_ids=None) -> dict:
        """Fetch vulns (OpenSearch) + SCA (Wazuh) and build the multiplier.

        Vulnerabilities come from the Wazuh vuln STATE index in OpenSearch
        (WO-H11), scoped to ``agent_id`` and the tenant's ``allowed_agent_ids``.
        SCA still comes from the Wazuh Manager client (``sca_client``) whose
        ``/sca/{agent}`` endpoint is unaffected by the 4.8 vuln-endpoint removal.
        """
        enrichment = self._empty()

        # WO-H23: resolve the CVE-intel db + whether the KEV catalog is populated
        # ONCE per host (not per CVE), so the KEV tri-state is honest and cheap.
        cve_db = self._resolve_db()
        kev_available = self._kev_catalog_populated(cve_db)

        vulns = self._fetch_vulns(os_client, agent_id, allowed_agent_ids) or []
        critical = 0
        high = 0
        top_critical_cves: list[str] = []
        top_cve_details: list[dict] = []
        for v in vulns:
            sev = self._severity(v)
            if sev == "critical":
                critical += 1
                cid = self._cve_id(v)
                if (cid and cid not in top_critical_cves
                        and len(top_critical_cves) < self.TOP_CVE_DETAIL_MAX):
                    top_critical_cves.append(cid)
                    # WO-H23: attach per-CVE CVSS (from the Wazuh doc) + EPSS/KEV
                    # (from the local CVE TI table). Missing fields are simply
                    # absent — never fabricated; KEV is tri-state (see
                    # _cve_intel: true / false / unknown-omitted).
                    cvss_base, cvss_version = self._cvss(v)
                    detail: dict = {"cve": cid, "severity": "critical"}
                    if cvss_base is not None:
                        detail["cvss"] = cvss_base
                    if cvss_version:
                        detail["cvss_version"] = cvss_version
                    detail.update(self._cve_intel(cve_db, cid, kev_available))
                    top_cve_details.append(detail)
            elif sev == "high":
                high += 1

        # SCA failed checks across all policies on the host. Still served by the
        # Wazuh Manager client (``/sca/{agent}`` is unaffected by the 4.8 vuln-
        # endpoint removal); best-effort — the vuln signal alone still counts.
        failed_sca = 0
        try:
            if sca_client is not None:
                policies = sca_client.get_sca_list(agent_id) or []
                for pol in policies:
                    pol_id = pol.get("policy_id") or pol.get("id")
                    if not pol_id:
                        continue
                    failed = sca_client.get_sca_checks(
                        agent_id, pol_id, result_filter="failed") or []
                    failed_sca += len(failed)
        except Exception as e:
            # SCA is best-effort; vuln signal alone still counts.
            logger.debug("vuln_context_sca_partial", agent_id=agent_id,
                         error=str(e)[:200])

        # Build the bounded multiplier — multiply each engaged factor, then cap.
        mult = 1.0
        reasons: list[str] = []
        if critical > 0:
            mult *= self.critical_mult
            lead = top_critical_cves[0] if top_critical_cves else f"{critical} critical CVE(s)"
            if top_critical_cves:
                reasons.append(f"host has critical {lead} (unpatched)")
            else:
                reasons.append(f"host has {critical} critical CVE(s)")
        if high > 0:
            mult *= self.high_mult
            reasons.append(f"{high} high-severity CVE(s)")
        if failed_sca >= self.sca_failed_threshold:
            mult *= self.sca_failed_mult
            reasons.append(f"{failed_sca} failed SCA check(s)")

        # Cap the combined product so vuln context sharpens, never manufactures.
        mult = round(min(mult, self.max_mult), 4)

        enrichment.update({
            "host_vulnerabilities_critical": critical,
            "host_vulnerabilities_high": high,
            "host_sca_failed_checks": failed_sca,
            "host_top_critical_cves": top_critical_cves,
            "vuln_context_multiplier": mult,
            "vuln_context_reason": " + ".join(reasons) if reasons else "",
            # WO-H23 finding-level detail (display-only): per-CVE CVSS/EPSS/KEV.
            # Excluded from the triage/hunt prompts; on the detection-prompt path
            # it egresses only through anonymize_fp_text (CVE ids/scores carry no
            # client identifier). See _ti_match_summary in triage_agent for the
            # full boundary note.
            "host_top_cve_details": top_cve_details,
        })
        return enrichment


# ---------------------------------------------------------------------------
# Host Integrity Context Enricher (M6b — FIM/rootcheck-into-Triage)
# ---------------------------------------------------------------------------

class HostIntegrityContextEnricher:
    """Sharpen the risk score with the affected host's FIM + rootcheck posture.

    For the alert's ``agent_id`` this fetches the host's rootcheck (policy-
    monitoring) findings and syscheck (FIM) changes via the tenant-scoped
    Wazuh client and emits a bounded ``host_integrity_multiplier`` plus a
    human-readable ``host_integrity_reason``.

    CONSERVATIVE TUNING (operator-approved):
      * Rootcheck is the PRIMARY driver — an open rootcheck finding (rootkit /
        policy violation) is a strong integrity signal, so it engages the
        ``rootcheck_finding_multiplier``.
      * FIM is a SECONDARY, thresholded, smaller driver — file-integrity
        monitoring is inherently noisy, so raw FIM volume must NOT amplify.
        Only the count of RECENT changes (within ``fim_recency_hours``) is
        considered, and only when it crosses ``fim_recent_threshold`` does the
        smaller ``fim_recent_changes_multiplier`` engage.
      * The combined product is capped at ``max_multiplier`` (default 1.5,
        tighter than M4's 1.8) so host-integrity context alone can never push
        a benign alert across the escalation/HIGH band.

    SHARPEN, NEVER MANUFACTURE: because the score is multiplicative the
    multiplier only amplifies an already-present signal — a low-base benign
    alert stays low.

    DEFENSE-IN-DEPTH: host-integrity context is an additive scoring
    enhancement, not a security control. Every failure path (no client,
    missing agent_id, fetch error, and crucially the M2 fail-closed
    ``TenantConfigUnavailable``) degrades to multiplier 1.0 and is logged —
    ``enrich`` never raises, so it can never block the triage/enrichment cycle.
    """

    # Bounded magnitudes. Kept modest so they sharpen rather than manufacture.
    DEFAULT_ROOTCHECK_MULT = 1.3
    DEFAULT_FIM_RECENT_MULT = 1.15
    # Min number of RECENT FIM changes before the FIM factor engages.
    DEFAULT_FIM_RECENT_THRESHOLD = 10
    # Only FIM changes within this many hours count as "recent".
    DEFAULT_FIM_RECENCY_HOURS = 24
    # Hard ceiling on the combined product — prevents runaway stacking. Tighter
    # than M4 (1.8) so host-integrity alone cannot cross a benign alert to HIGH.
    DEFAULT_MAX_MULT = 1.5
    DEFAULT_CACHE_TTL = 300

    # WO-H23 finding-level detail (DISPLAY-ONLY): the specific rootcheck
    # signatures + recently-changed FIM paths behind the counts. Capped +
    # truncated so the persisted blob stays bounded. Primary purpose is the
    # analyst case view (deanonymized-to-the-viewer, like WO-H21's raw event).
    #
    # LLM boundary (honest): these keys are NOT in build_triage_prompt's fixed
    # enrichment allowlist and NOT in build_hunt_prompt's projection, so they
    # never reach the triage/hunt LLM. They DO, however, land in the persisted
    # ``enrichment_summary`` blob, which build_detection_prompt serializes whole
    # (json.dumps → truncated to 300 chars) and passes through
    # ``anonymize_fp_text`` — so a FIM path / rootcheck signature CAN egress to
    # the DETECTION LLM, but only after anonymization tokenizes registered
    # client identifiers. Per _DETECTION_EXCLUDE_KEYS this is the documented
    # detection posture (file-path/command free-text is verbatim-by-design;
    # only REGISTERED identifiers are tokenized), unchanged by WO-H23.
    SIGNATURE_MAX = 8
    SIGNATURE_TRUNC = 200
    FIM_PATH_MAX = 12

    def __init__(self, config: dict, tenant_registry=None, wazuh_client=None,
                 registry_provider=None, wazuh_provider=None):
        cfg = config or {}
        self.enabled = cfg.get("enabled", True)
        self.rootcheck_mult = float(cfg.get("rootcheck_finding_multiplier",
                                            self.DEFAULT_ROOTCHECK_MULT))
        self.fim_recent_mult = float(cfg.get("fim_recent_changes_multiplier",
                                             self.DEFAULT_FIM_RECENT_MULT))
        self.fim_recent_threshold = int(cfg.get("fim_recent_threshold",
                                                self.DEFAULT_FIM_RECENT_THRESHOLD))
        self.fim_recency_hours = float(cfg.get("fim_recency_hours",
                                               self.DEFAULT_FIM_RECENCY_HOURS))
        self.max_mult = float(cfg.get("max_multiplier",
                                      self.DEFAULT_MAX_MULT))
        self.cache_ttl = int(cfg.get("cache_ttl", self.DEFAULT_CACHE_TTL))
        # Direct references (used in tests / single-tenant) ...
        self._tenant_registry = tenant_registry
        self._wazuh = wazuh_client
        # ... plus optional late-binding providers so the owning service can
        # expose a registry/client that is wired AFTER this enricher is built
        # (main.py sets service._tenant_registry post-construction).
        self._registry_provider = registry_provider
        self._wazuh_provider = wazuh_provider
        # Short-lived per-agent cache: (tenant_id, agent_id) -> enrichment dict
        self._cache = TTLCache(maxsize=2000, ttl=max(1, self.cache_ttl))

    def _empty(self) -> dict:
        """No-op / no-signal enrichment: multiplier 1.0, empty reason."""
        return {
            "host_rootcheck_findings": 0,
            "host_fim_recent_changes": 0,
            "host_integrity_multiplier": 1.0,
            "host_integrity_reason": "",
            # WO-H23 finding-level detail (display-only, empty when no signal).
            "host_rootcheck_signatures": [],
            "host_fim_changed_paths": [],
        }

    def _resolve_client(self):
        """Resolve the Wazuh client for the active tenant.

        Tenant is read from the SAME contextvar the pipeline already sets
        (``_tenant_ctx``); the read path uses the tenant-scoped client only.
        Falls back to the global client (single-tenant) when no registry is
        wired.  Propagates ``TenantConfigUnavailable`` to the caller, which
        handles the M2 fail-closed case explicitly.

        NOTE: this method is a verbatim clone of
        ``VulnerabilityContextEnricher._resolve_client`` (M4) — the fail-closed
        tenant-isolation property is enforced by construction, not paraphrase.
        """
        registry = self._tenant_registry
        if registry is None and self._registry_provider is not None:
            registry = self._registry_provider()
        if registry is not None:
            # Import here to avoid a hard dependency / import cycle in shared
            # code; the contextvar lives next to the DB store.
            from src.database.store import _tenant_ctx
            tenant_id = _tenant_ctx.get()
            if tenant_id and tenant_id != "__CROSS_TENANT__":
                # May raise TenantConfigUnavailable (M2 fail-closed). We let it
                # propagate; enrich() catches it and degrades to 1.0.
                return registry.get_wazuh_client(tenant_id), tenant_id
            # No usable tenant context — do not fetch under another tenant.
            return None, tenant_id
        # No registry resolvable. In MULTI-TENANT mode we must NEVER touch the
        # global client: doing so would fetch one tenant's host integrity data
        # through a cross-tenant client. The safety property "no tenant context
        # → no host-integrity multiplier" must hold by construction, not by
        # init timing (the registry is wired into EnrichmentService AFTER
        # construction). Degrade to the no-client path (multiplier 1.0) instead.
        from src.database.store import is_multi_tenant
        if is_multi_tenant():
            logger.warning("host_integrity_no_tenant_registry")
            return None, None
        # Genuine single-tenant deployment: use the global client if provided.
        wazuh = self._wazuh
        if wazuh is None and self._wazuh_provider is not None:
            wazuh = self._wazuh_provider()
        return wazuh, None

    # Rootcheck/syscheck scan-control & informational markers. Wazuh emits
    # these lifecycle messages through /rootcheck/{agent} with a non-solved
    # status; they are NOT integrity findings and must not engage the primary
    # multiplier (else it fires on nearly every host that simply runs a scan).
    _SCAN_CONTROL_MARKERS = (
        "starting rootcheck scan",
        "ending rootcheck scan",
        "starting syscheck scan",
        "ending syscheck scan",
    )

    @classmethod
    def _is_scan_control(cls, item: dict) -> bool:
        """True if the item is a rootcheck/syscheck scan-control / info message.

        Defensive across Wazuh field-name variants: checks the descriptive text
        fields the item may carry (``title``/``log``/``event``/``description``),
        substring-matched case-insensitively against known scan-control markers.
        Fail-safe: if the item has no recognizable text field, returns False so
        the caller falls back to its normal open/solved status handling."""
        for field in ("title", "log", "event", "description"):
            val = item.get(field)
            if not isinstance(val, str):
                continue
            text = val.strip().lower()
            if any(marker in text for marker in cls._SCAN_CONTROL_MARKERS):
                return True
        return False

    @staticmethod
    def _finding_signature(item: dict) -> str:
        """The human-readable signature text of a rootcheck finding (WO-H23).

        Prefers the concise descriptive fields (``title``/``event``/
        ``description``) over the verbose ``log`` line. Fail-safe to "" when the
        item carries no recognizable text field. DISPLAY-ONLY — never fed to an
        LLM."""
        for field in ("title", "event", "description", "log"):
            val = item.get(field)
            if isinstance(val, str) and val.strip():
                return val.strip()
        return ""

    @classmethod
    def _is_open_finding(cls, item: dict) -> bool:
        """A rootcheck finding is OPEN unless explicitly marked solved.

        Wazuh rootcheck items carry a ``status`` of ``outstanding`` (still
        present) or ``solved`` (remediated). Anything not explicitly solved is
        treated as an open integrity concern (defensive default) — EXCEPT
        scan-control / informational lifecycle messages, which are filtered out
        first so the primary driver keeps its discriminating power."""
        if cls._is_scan_control(item):
            return False
        status = str(item.get("status", "") or "").strip().lower()
        return status != "solved"

    @staticmethod
    def _parse_ts(val) -> Optional[datetime]:
        """Parse a Wazuh timestamp string into an aware UTC datetime.

        Fail-safe: returns None for anything unparseable so the caller treats
        the item as "not recent" rather than crashing."""
        if not isinstance(val, str):
            return None
        s = val.strip()
        if not s:
            return None
        dt = None
        # ISO-8601 (Wazuh 4.x commonly emits this; normalize trailing Z).
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            dt = None
        if dt is None:
            for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                        "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
                try:
                    dt = datetime.strptime(s, fmt)
                    break
                except ValueError:
                    continue
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    def _change_time(self, item: dict) -> Optional[datetime]:
        """Best-effort per-item ACTUAL file-change time.

        Field names vary by Wazuh version. Prefer real modification-time fields
        (``mtime``/``modification_time``) FIRST; use ``date`` only as a weak
        last-resort fallback. In Wazuh 4.x syscheck items, ``date`` is the FIM
        DB sync/report timestamp (when the manager recorded the item), NOT when
        the file changed — so a routine full scan would stamp a recent ``date``
        on many unchanged files and could spuriously engage the FIM factor.
        Preferring change-time keeps "raw FIM volume must not amplify" intact.
        Fail-safe to None (not recent) when nothing is parseable."""
        for field in ("mtime", "modification_time", "date"):
            ts = self._parse_ts(item.get(field))
            if ts is not None:
                return ts
        return None

    def enrich(self, alert: dict) -> dict:
        """Add host FIM/rootcheck integrity context. Never raises."""
        if not self.enabled:
            return self._empty()

        agent_id = alert.get("agent_id")
        if not agent_id or agent_id == "000":
            # No host to scope to (000 = Wazuh manager itself).
            return self._empty()

        # Resolve the tenant-scoped client; M2 fail-closed is handled here.
        try:
            client, tenant_id = self._resolve_client()
        except Exception as e:
            # Includes TenantConfigUnavailable (M2 fail-closed). Host-integrity
            # context is an enhancement, not a security control — degrade,
            # never block.
            tenant_id = None
            try:
                from src.database.store import _tenant_ctx
                tenant_id = _tenant_ctx.get()
            except Exception:
                pass
            logger.warning("host_integrity_unavailable",
                           tenant_id=tenant_id,
                           agent_id=agent_id,
                           error=str(e)[:200])
            return self._empty()

        if client is None:
            logger.debug("host_integrity_no_client", agent_id=agent_id)
            return self._empty()

        cache_key = (tenant_id, str(agent_id))
        if cache_key in self._cache:
            return dict(self._cache[cache_key])

        try:
            result = self._compute(client, agent_id)
        except Exception as e:
            logger.warning("host_integrity_fetch_failed",
                           tenant_id=tenant_id,
                           agent_id=agent_id,
                           error=str(e)[:200])
            return self._empty()

        self._cache[cache_key] = dict(result)
        return result

    def _compute(self, client, agent_id) -> dict:
        """Fetch rootcheck + FIM and build the bounded multiplier + reason."""
        enrichment = self._empty()

        # --- Rootcheck (PRIMARY driver) ---
        rootcheck = client.get_agent_rootcheck(agent_id) or []
        open_findings = 0
        rootcheck_signatures: list[str] = []
        for item in rootcheck:
            if not isinstance(item, dict) or not self._is_open_finding(item):
                continue
            open_findings += 1
            # WO-H23: capture the specific finding signature (display-only).
            if len(rootcheck_signatures) < self.SIGNATURE_MAX:
                sig = self._finding_signature(item)
                if sig:
                    rootcheck_signatures.append(sig[:self.SIGNATURE_TRUNC])

        # --- FIM/syscheck (SECONDARY, thresholded, recency-gated) ---
        # Raw FIM volume must NOT amplify — FIM is noisy. Count only RECENT
        # changes; this is the core sharpen-not-manufacture guard.
        syscheck = client.get_agent_syscheck(agent_id) or []
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.fim_recency_hours)
        recent_changes = 0
        fim_changed_paths: list[str] = []
        for item in syscheck:
            if not isinstance(item, dict):
                continue
            ts = self._change_time(item)
            if ts is not None and ts >= cutoff:
                recent_changes += 1
                # WO-H23: capture the specific changed file path (display-only).
                path = item.get("file") or item.get("path")
                if path and len(fim_changed_paths) < self.FIM_PATH_MAX:
                    fim_changed_paths.append(str(path))

        # --- Build the bounded multiplier — multiply engaged factors, then cap ---
        mult = 1.0
        reasons: list[str] = []
        if open_findings > 0:
            # Rootcheck is primary: flat, modest multiplier (the count is
            # surfaced in the reason for explainability but does not stack).
            mult *= self.rootcheck_mult
            reasons.append(
                f"host has {open_findings} open rootcheck finding(s)")
        if recent_changes >= self.fim_recent_threshold:
            # FIM is secondary: engages only when recent-change count crosses
            # the threshold, never on raw volume.
            mult *= self.fim_recent_mult
            reasons.append(
                f"{recent_changes} FIM changes in last "
                f"{int(self.fim_recency_hours)}h")

        # Cap the combined product so host integrity sharpens, never manufactures.
        mult = round(min(mult, self.max_mult), 4)

        enrichment.update({
            "host_rootcheck_findings": open_findings,
            "host_fim_recent_changes": recent_changes,
            "host_integrity_multiplier": mult,
            "host_integrity_reason": "; ".join(reasons) if reasons else "",
            # WO-H23 finding-level detail (display-only; excluded from the
            # triage/hunt prompts, anonymized on the detection-prompt path —
            # see the SIGNATURE_MAX comment above).
            "host_rootcheck_signatures": rootcheck_signatures,
            "host_fim_changed_paths": fim_changed_paths,
        })
        return enrichment
