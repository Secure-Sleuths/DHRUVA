"""
Enrichment modules - Add context to raw Wazuh alerts.
Each enricher adds a specific type of intelligence.
"""

import json
import hashlib
import structlog
import requests
from typing import Optional
from datetime import datetime, timezone, timedelta
from fnmatch import fnmatch
from cachetools import TTLCache

from src.timestamps import parse_iso8601_or_none

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# WO-S11 — per-tenant enrichment inventories
# ---------------------------------------------------------------------------
#
# AssetEnricher.assets and IdentityEnricher.identities used to be ONE
# process-wide dict on the single shared EnrichmentService. They are loaded from
# the tenant-scoped `assets` / `identities` tables (db.get_assets() applies
# _tenant_filter()), but the result was stored globally — so whichever tenant's
# inventory was loaded most recently enriched EVERY tenant's alerts.
#
# Two consequences, both real:
#   * Confidentiality — tenant A's asset owner name/email, tier, tags and
#     identity roles/is_admin/known_ips were written into tenant B's
#     enriched-alert documents, shown in B's case view, and sent to B's LLM
#     provider inside the triage prompt.
#   * Integrity — any tenant `admin` could register a hostname or username that
#     another tenant also uses (DC01, administrator) with a
#     criticality/risk multiplier of 0.1, call the tenant-scoped
#     /api/admin/settings/reload-enrichers, and push the OTHER tenant's alerts
#     below the min_risk triage threshold, where they are dropped without triage
#     entirely.
#
# Fix (operator-approved 2026-08-03, "option 1"): keep the in-memory cache, but
# key it by the tenant contextvar. DB-loaded inventory lands in the calling
# tenant's slice and is only ever read back for that tenant.
#
# The file/YAML inventory is kept in a SEPARATE shared slot and used as a
# fallback. That is deployment-level configuration written by the operator, not
# tenant-submitted data, and sharing it is the existing intended behaviour — but
# it is now explicit rather than an accident of a global dict.

_DEFAULT_TENANT_SLICE = "__default__"


def _tenant_slice_key() -> str:
    """Cache key for the tenant currently in context.

    Single-tenant deployments (and any code path with no tenant bound) share
    ``__default__``, which is correct there — there is only one customer. The
    cross-tenant sentinel also maps to ``__default__`` rather than leaking one
    arbitrary tenant's inventory into an unscoped operation.
    """
    try:
        from src.database.store import _tenant_ctx
        tenant_id = _tenant_ctx.get()
    except Exception as e:                               # noqa: BLE001
        # WO-H90: was a bare `except: return`. This is the TENANT CACHE KEY. If
        # resolving it ever fails we fall back to the shared `__default__` slice,
        # which means alerts get enriched from the wrong customer's asset and
        # identity inventory. `error` — not `warning` — because there is no
        # benign version of this, and it must not stay quiet just because it is
        # on a per-alert path. In practice `_tenant_ctx` has a default and cannot
        # raise, so firing at all means the store module failed to import.
        logger.error("tenant_slice_key_resolution_failed", error=str(e)[:200])
        return _DEFAULT_TENANT_SLICE
    if not tenant_id or tenant_id == "__CROSS_TENANT__":
        return _DEFAULT_TENANT_SLICE
    return str(tenant_id)


# ---------------------------------------------------------------------------
# Asset Enricher
# ---------------------------------------------------------------------------

class AssetEnricher:
    """Enriches alerts with asset criticality, ownership, and classification."""

    def __init__(self, config: dict):
        # WO-S11: DB-loaded inventory, keyed by tenant. Never read across
        # tenants.
        self._assets_by_tenant: dict[str, dict] = {}
        # Operator-provided YAML inventory — deployment config, shared by
        # design, used only as a fallback when the tenant has no own record.
        self._shared_assets: dict = {}
        # Tenants whose last DB reload RAISED. Keyed like _assets_by_tenant,
        # because the inventory it describes is per-tenant: a process-global
        # health flag let one tenant's outage mask another's (and vice versa),
        # which is the defect class WO-S11 fixed for `assets` itself.
        self._reload_failed_tenants: set = set()
        self.risk_criteria: dict = config.get("risk_criteria", {})
        self.source = config.get("source", "file")
        self.file_path = config.get("file_path", "")
        self._load_assets()

    @property
    def assets(self) -> dict:
        """Effective inventory for the CURRENT tenant (shared + own).

        Kept as a property so existing readers — including the counts returned
        by ``EnrichmentService.reload_enrichers`` — keep working unchanged.
        The hot path uses ``_lookup`` instead, which avoids building this dict
        per alert.
        """
        return {**self._shared_assets,
                **self._assets_by_tenant.get(_tenant_slice_key(), {})}

    @assets.setter
    def assets(self, value: dict):
        """Assign the CURRENT tenant's inventory.

        WO-S11 made ``assets`` a property; without this setter every existing
        caller doing ``enricher.assets = {...}`` raises
        ``AttributeError: property 'assets' has no setter``. That includes
        ``tests/test_enrichers.py``, whose failures were masked because the
        module is skipped when no Docker daemon is present — so the regression
        would only have surfaced on a machine that could run the DB lane.
        """
        self._assets_by_tenant[_tenant_slice_key()] = dict(value or {})

    def _lookup(self, hostname: str):
        """Resolve a hostname for the current tenant. Own record wins."""
        own = self._assets_by_tenant.get(_tenant_slice_key())
        if own and hostname in own:
            return own[hostname]
        return self._shared_assets.get(hostname)

    def _load_assets(self):
        """Load asset inventory from configured source."""
        if self.source == "file" and self.file_path:
            try:
                import yaml
                with open(self.file_path) as f:
                    data = yaml.safe_load(f) or {}
                    self._shared_assets = {
                        a["hostname"]: a for a in (data.get("assets") or [])}
                logger.info("assets_loaded", count=len(self._shared_assets))
            except FileNotFoundError:
                logger.warning("asset_file_not_found", path=self.file_path)
            except Exception as e:
                logger.error("asset_load_failed", error=str(e))

    def reload_from_db(self, db):
        """Reload asset data from the database for the CURRENT tenant only.

        WO-S11: writes into this tenant's slice. Previously this replaced the
        one process-global dict, so a tenant admin hitting
        /api/admin/settings/reload-enrichers repointed every other tenant's
        enrichment at their own inventory.
        """
        key = _tenant_slice_key()
        try:
            db_assets = db.get_assets_as_dict()
            if db_assets:
                self._assets_by_tenant[key] = db_assets
                logger.info("assets_reloaded_from_db",
                            tenant_slice=key, count=len(db_assets))
                self._reload_failed_tenants.discard(key)
            else:
                logger.info("assets_db_empty_keeping_current",
                            tenant_slice=key,
                            count=len(self._assets_by_tenant.get(key, {})))
        except Exception as e:
            logger.error("asset_db_reload_failed",
                         tenant_slice=key, error=str(e))
            # The inventory is now stale or empty, so hosts resolve to
            # asset_tier "unknown". Downstream that is indistinguishable from
            # "not a critical asset", which would silently switch off the
            # verdict guard's tier_1_critical condition. Say so explicitly —
            # and only for THIS tenant.
            self._reload_failed_tenants.add(key)

    def enrich(self, alert: dict) -> dict:
        """Add asset context to an alert."""
        agent_name = alert.get("agent_name", "")
        enrichment = {
            "asset_tier": "unknown",
            "asset_owner": "unknown",
            "asset_environment": "unknown",
            "asset_criticality_multiplier": 1.0
        }

        # Try exact match first — WO-S11: scoped to the current tenant.
        asset = self._lookup(agent_name)
        matched_pattern = False
        if asset is not None:
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
                        matched_pattern = True
                        break
                if matched_pattern:
                    break

        # Whether the tier in this record can be TRUSTED.
        #
        # Derived from whether the lookup could actually be PERFORMED, not from
        # "the last call didn't throw". An earlier version tracked a boolean set
        # on exception, which the shipped default reset to healthy: the asset
        # YAML is absent, the DB reload returns empty and takes the
        # "keeping current" branch, and every host reads asset_tier "unknown"
        # while the flag says fine. That is the exact bypass the flag exists to
        # catch, so the flag has to follow the data rather than the control flow.
        #
        # Trusted when EITHER:
        #   * this alert was authoritatively classified (inventory record hit,
        #     or a risk_criteria hostname pattern matched), or
        #   * this tenant has a usable inventory and its last reload didn't
        #     fail — a host simply not being listed is a real answer, not a
        #     degradation, and must not trip the guard.
        key = _tenant_slice_key()
        inventory_usable = bool(self._assets_by_tenant.get(key)
                                or self._shared_assets)
        reload_failed = key in self._reload_failed_tenants
        # A failed reload leaves the previous slice in place. Reading a STALE
        # record must not count as an authoritative answer: a host promoted to
        # tier_1_critical in the DB while the cached copy still says tier_3
        # would otherwise report trusted, the tier-1 condition would not fire,
        # and the alert would stay auto-close eligible on a now-critical asset.
        # Only a pattern match — which is computed fresh from risk_criteria and
        # cannot be stale — survives a failed reload.
        enrichment["asset_lookup_ok"] = bool(
            matched_pattern
            or (not reload_failed and (asset is not None or inventory_usable))
        )
        return enrichment


# ---------------------------------------------------------------------------
# Identity Enricher
# ---------------------------------------------------------------------------

class IdentityEnricher:
    """Enriches alerts with user context: roles, privileges, behavior patterns."""

    def __init__(self, config: dict):
        # WO-S11: see the AssetEnricher note — same defect, same fix.
        self._identities_by_tenant: dict[str, dict] = {}
        self._shared_identities: dict = {}
        self.risk_criteria: dict = config.get("risk_criteria", {})
        self.source = config.get("source", "file")
        self.file_path = config.get("file_path", "")
        self._load_identities()

    @property
    def identities(self) -> dict:
        """Effective directory for the CURRENT tenant (shared + own)."""
        return {**self._shared_identities,
                **self._identities_by_tenant.get(_tenant_slice_key(), {})}

    @identities.setter
    def identities(self, value: dict):
        """Assign the CURRENT tenant's directory — see AssetEnricher.assets."""
        self._identities_by_tenant[_tenant_slice_key()] = dict(value or {})

    def _lookup(self, username: str):
        """Resolve a username for the current tenant. Own record wins."""
        own = self._identities_by_tenant.get(_tenant_slice_key())
        if own and username in own:
            return own[username]
        return self._shared_identities.get(username)

    def _load_identities(self):
        if self.source == "file" and self.file_path:
            try:
                import yaml
                with open(self.file_path) as f:
                    data = yaml.safe_load(f) or {}
                    self._shared_identities = {
                        u["username"]: u for u in (data.get("users") or [])}
                logger.info("identities_loaded",
                            count=len(self._shared_identities))
            except FileNotFoundError:
                logger.warning("identity_file_not_found", path=self.file_path)
            except Exception as e:
                logger.error("identity_load_failed", error=str(e))

    def reload_from_db(self, db):
        """Reload identity data from the DB for the CURRENT tenant only (WO-S11)."""
        key = _tenant_slice_key()
        try:
            db_identities = db.get_identities_as_dict()
            if db_identities:
                self._identities_by_tenant[key] = db_identities
                logger.info("identities_reloaded_from_db",
                            tenant_slice=key, count=len(db_identities))
            else:
                logger.info("identities_db_empty_keeping_current",
                            tenant_slice=key,
                            count=len(self._identities_by_tenant.get(key, {})))
        except Exception as e:
            logger.error("identity_db_reload_failed",
                         tenant_slice=key, error=str(e))

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
            # WO-S11: scoped to the current tenant.
            identity = self._lookup(username)
            if identity is not None:
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
        # WO-H60 step 3: the window over which `historical_fp_rate` is computed
        # and shown to the triage agent.
        #
        # This was hard-coded to 7 days. For a product whose thesis is
        # COMPOUNDING intelligence, institutional memory that expires in a week
        # barely compounds — and it measurably did not: on the live install the
        # newest analyst label was 12 days old, so a 7-day window contained ZERO
        # labelled decisions and the agent was shown 0.0% for rules analysts had
        # dispositioned false-positive 100% of the time (rule 40101: 0.0% at 7d,
        # 100.0% at 30d across 774 decisions).
        #
        # 30 days matches `baseline_window_days` above, so the two historical
        # signals now describe the same period.
        self.fp_window_days = config.get("fp_rate_window_days", 30)
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
            fp_stats = self.db.get_fp_rate_for_rule(
                rule_id, days=self.fp_window_days)
            enrichment["historical_fp_rate"] = fp_stats.get("fp_rate", 0)
            enrichment["historical_occurrence_count"] = fp_stats.get("total", 0)
            # Carried so the prompt can state the ACTUAL window instead of a
            # hard-coded "7d" that would now be a lie.
            enrichment["historical_window_days"] = self.fp_window_days

            # `same_rule_last_7d` is consumed by the dashboard
            # (web/src/lib/incident.ts -> sameRule7d) and must stay a genuine
            # SEVEN-day count. When the FP window is no longer 7 it needs its
            # own query — one extra indexed aggregate per alert, paid only when
            # the windows differ.
            if self.fp_window_days == 7:
                enrichment["same_rule_last_7d"] = fp_stats.get("total", 0)
            else:
                try:
                    enrichment["same_rule_last_7d"] = self.db.get_fp_rate_for_rule(
                        rule_id, days=7).get("total", 0)
                except Exception as e:
                    logger.warning("same_rule_7d_lookup_failed",
                                   rule_id=rule_id, error=str(e))

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
    """Adds time-based context: business hours, maintenance windows, etc.

    WO-H76 — three defects fixed here, all of which made every alert ever
    scored look like it arrived outside business hours (verified on two live
    deployments: ``time_multiplier`` was 1.0 in 0 of 14,259 and 0 of 10,878
    alerts; only 1.5 and 1.95 were ever produced):

    1. The ``time_context`` block lives in
       ``config/guidance/risk_criteria.yaml``, not in the ``enrichment:``
       section of config.yaml, so this enricher was constructed with an empty
       config. See ``resolve_time_context_config`` in
       ``src/enrichment/service.py`` for the wiring.
    2. The configured ``timezone`` was loaded but never applied. Wazuh emits
       UTC timestamps, so a 09:00-18:00 Asia/Kolkata window was being compared
       against UTC wall-clock time — a 5.5 hour shift. Business hours,
       maintenance windows AND the weekend check now all run against the
       timestamp converted into the configured timezone, so all three agree on
       what day it is.
    3. The "default to business hours when config is missing" fallback was
       dead: an empty ``days`` list raises nothing, so the guarded expression
       returned False (= outside business hours) instead of hitting the
       ``except``. A genuinely missing/empty config now defaults to business
       hours (multiplier 1.0) AND says so in the log — silence is how this
       survived in production.

    WO-H76 follow-up (QA round): ``config/guidance/risk_criteria.yaml`` is the
    OPERATOR-editable file, and it is now reloadable live, so a typo in it must
    never crash enrichment and — worse — must never be accepted silently. The
    whole block is therefore VALIDATED once at construction into normalized
    fields (``_business_hours`` / ``_maintenance_windows`` /
    ``_risk_adjustments``); every rejection is logged with the offending value
    and falls back to a documented default. The shapes that motivated it, all
    of which YAML makes easy to write by accident:

    * ``days: monday`` (unquoted scalar) — iterating a str yields characters,
      so ``bh_days`` became a truthy 6-element list of letters and EVERY
      weekday alert silently scored 1.5 again: the original defect, restored.
    * ``days: [0, 1, 2]`` — same silent outcome.
    * ``start: 9:00`` unquoted — YAML 1.1 sexagesimal, parses to the int 540.
      ``start: 9`` / ``start: "9am"`` / ``"25:00"`` are unparsable too, and the
      old behaviour was "everything is business hours, 24/7" — i.e. ALL
      out-of-hours risk silently gone.
    * ``risk_adjustments:`` with an empty body — ``None``, so ``.get`` on it
      raised ``AttributeError`` and killed time context, but only on
      out-of-hours/weekend/maintenance alerts (it looks healthy during the
      day).
    * a ``maintenance_windows`` entry written as a bare string rather than a
      mapping — ``.get`` raised and killed time context for 100% of alerts.
    """

    #: Fallback working week, used when ``business_hours`` declares no usable
    #: ``days``. A COMPLETELY absent business_hours block defaults to business
    #: hours (1.0) instead — see ``_is_business_hours``.
    _DEFAULT_BUSINESS_DAYS = ("monday", "tuesday", "wednesday",
                              "thursday", "friday")
    _WEEKDAY_NAMES = ("monday", "tuesday", "wednesday", "thursday",
                      "friday", "saturday", "sunday")
    _DEFAULT_START = "09:00"
    _DEFAULT_END = "18:00"

    def __init__(self, config: dict):
        raw = (config or {}).get("time_context", {})
        if raw and not isinstance(raw, dict):
            logger.warning(
                "time_context_config_not_a_mapping",
                got=type(raw).__name__,
                msg="time_context must be a mapping — ignoring it and "
                    "defaulting every alert to business hours (1.0).")
            raw = {}
        self.time_config = raw or {}
        self._tz = self._resolve_timezone(self.time_config)
        # Warn-once latches — these run per alert, so an unconditional warning
        # would be a log flood.
        self._warned_missing_config = False
        self._warned_unparsed_timestamp = False
        if not self.time_config:
            logger.warning(
                "time_context_config_missing",
                msg="No time_context block supplied to TimeContextEnricher — "
                    "defaulting every alert to business hours (multiplier 1.0). "
                    "Expected it under time_context in "
                    "config/guidance/risk_criteria.yaml.")

        # Validate ONCE, here, so a bad edit is reported at load/reload time
        # rather than being silently absorbed on every alert forever. Wrapped
        # because this now runs during EnrichmentService.__init__ AND during a
        # live reload: an operator typo must not be able to stop the platform
        # booting.
        try:
            self._business_hours = self._validate_business_hours(
                self.time_config.get("business_hours"))
            self._maintenance_windows = self._validate_maintenance_windows(
                self.time_config.get("maintenance_windows"))
            self._risk_adjustments = self._validate_risk_adjustments(
                self.time_config.get("risk_adjustments"))
        except Exception as e:      # pragma: no cover — belt and braces
            logger.error("time_context_config_validation_failed", error=str(e),
                         msg="Falling back to business hours for every alert "
                             "(multiplier 1.0).")
            self._business_hours = None
            self._maintenance_windows = []
            self._risk_adjustments = {}

    # ── config validation ──────────────────────────────────────────────────

    @classmethod
    def _parse_hhmm(cls, value, field: str, where: str):
        """Parse an ``"HH:MM"`` string, or return None having said why.

        Deliberately strict about the type. ``start: 9:00`` without quotes is
        YAML 1.1 sexagesimal and arrives here as the int 540; guessing at what
        an int means (minutes past midnight? an hour?) would be inventing
        intent, so it is rejected loudly with the fix in the message.
        """
        if isinstance(value, str):
            try:
                return datetime.strptime(value.strip(), "%H:%M").time()
            except ValueError:
                pass
        logger.warning("time_context_time_unparsable",
                       where=where, field=field, value=repr(value),
                       msg='Expected a quoted "HH:MM" string, e.g. '
                           'start: "09:00". Note an unquoted 9:00 is read by '
                           'YAML as the number 540.')
        return None

    @classmethod
    def _normalize_days(cls, value, where: str):
        """Normalize a ``days`` value to a list of real weekday names.

        Returns ``[]`` when nothing usable is present; the caller decides what
        that means (business hours default to Mon-Fri, a maintenance window is
        dropped). Never raises.
        """
        if value is None:
            return []
        if isinstance(value, str):
            # Iterating a str yields CHARACTERS — the silent-failure shape.
            logger.warning("time_context_days_not_a_list",
                           where=where, value=repr(value),
                           msg="`days` should be a list, e.g. "
                               'days: ["monday"]. Reading it as one day.')
            candidates = [value]
        elif isinstance(value, (list, tuple, set)):
            candidates = list(value)
        else:
            logger.warning("time_context_days_invalid_type",
                           where=where, got=type(value).__name__,
                           msg="`days` must be a list of weekday names — "
                               "ignoring it.")
            return []

        days, rejected = [], []
        for item in candidates:
            name = str(item).strip().lower()
            if name in cls._WEEKDAY_NAMES:
                if name not in days:
                    days.append(name)
            elif name:
                rejected.append(item)
        if rejected:
            logger.warning("time_context_invalid_weekday",
                           where=where, rejected=[repr(r) for r in rejected],
                           accepted=days,
                           msg="Entries must be full weekday names "
                               "(monday..sunday) — the rest were dropped.")
        return days

    @classmethod
    def _validate_business_hours(cls, raw):
        """Normalize ``business_hours`` or return None (= always in-hours)."""
        if not raw:
            return None
        if not isinstance(raw, dict):
            logger.warning("time_context_business_hours_invalid_type",
                           got=type(raw).__name__,
                           msg="business_hours must be a mapping — treating "
                               "all alerts as business hours (1.0).")
            return None

        start = cls._parse_hhmm(raw.get("start", cls._DEFAULT_START),
                                "start", "business_hours")
        end = cls._parse_hhmm(raw.get("end", cls._DEFAULT_END),
                              "end", "business_hours")
        if start is None or end is None:
            # A sane, documented default beats "everything is business hours,
            # 24/7", which is what the old code silently did here.
            logger.warning(
                "time_context_business_hours_defaulted",
                start=cls._DEFAULT_START, end=cls._DEFAULT_END,
                msg="Falling back to the default business-hours window.")
            start = start or datetime.strptime(cls._DEFAULT_START,
                                               "%H:%M").time()
            end = end or datetime.strptime(cls._DEFAULT_END, "%H:%M").time()

        days = cls._normalize_days(raw.get("days"), "business_hours")
        if not days:
            logger.warning(
                "time_context_business_days_undefined",
                default=list(cls._DEFAULT_BUSINESS_DAYS),
                msg="business_hours has no usable `days` — assuming "
                    "Monday-Friday.")
            days = list(cls._DEFAULT_BUSINESS_DAYS)
        return {"start": start, "end": end, "days": days}

    @classmethod
    def _validate_maintenance_windows(cls, raw):
        """Normalize maintenance windows, dropping (loudly) any unusable one."""
        if not raw:
            return []
        if not isinstance(raw, (list, tuple)):
            logger.warning("time_context_maintenance_windows_invalid_type",
                           got=type(raw).__name__,
                           msg="maintenance_windows must be a list of "
                               "mappings — ignoring all of them.")
            return []

        windows = []
        for idx, window in enumerate(raw):
            where = "maintenance_windows[%d]" % idx
            if not isinstance(window, dict):
                logger.warning("time_context_maintenance_window_not_a_mapping",
                               where=where, got=type(window).__name__,
                               value=repr(window),
                               msg="Each maintenance window must be a mapping "
                                   "with day(s)/start/end — dropping it.")
                continue
            name = window.get("name", where)
            # Both spellings ship in risk_criteria.yaml. Singular `day:` is a
            # scalar BY DESIGN, so wrap it rather than warning about it.
            raw_days = window.get("days")
            if raw_days is None and window.get("day") is not None:
                raw_days = [window.get("day")]
            days = cls._normalize_days(raw_days, where)
            if not days:
                logger.warning("time_context_maintenance_window_no_days",
                               where=where, window=str(name),
                               msg="No usable day(s) — dropping this window "
                                   "(it could never match).")
                continue
            start = cls._parse_hhmm(window.get("start"), "start", where)
            end = cls._parse_hhmm(window.get("end"), "end", where)
            if start is None or end is None:
                logger.warning("time_context_maintenance_window_dropped",
                               where=where, window=str(name),
                               msg="Unusable start/end — dropping this window.")
                continue
            windows.append({"name": str(name), "days": days,
                            "start": start, "end": end})
        return windows

    @classmethod
    def _validate_risk_adjustments(cls, raw):
        """Keep only numeric multipliers; anything else falls back to default.

        ``risk_adjustments:`` with an empty body is ``None`` in YAML, which is
        why this must not assume a mapping.
        """
        if raw is None:
            return {}
        if not isinstance(raw, dict):
            logger.warning("time_context_risk_adjustments_invalid_type",
                           got=type(raw).__name__,
                           msg="risk_adjustments must be a mapping — using "
                               "the built-in default multipliers.")
            return {}
        clean = {}
        for key, value in raw.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                logger.warning("time_context_risk_adjustment_not_numeric",
                               field=str(key), value=repr(value),
                               msg="Multiplier must be a number — using the "
                                   "built-in default for this one.")
                continue
            clean[str(key)] = float(value)
        return clean

    @staticmethod
    def _resolve_timezone(time_config: dict):
        """Resolve the configured business timezone, falling back to UTC.

        An unknown/invalid zone name must not take enrichment down: log it and
        carry on in UTC (which is what the old code effectively did anyway).
        """
        name = ((time_config.get("business_hours") or {}).get("timezone")
                or time_config.get("timezone"))
        if not name:
            return timezone.utc
        try:
            from zoneinfo import ZoneInfo
            return ZoneInfo(str(name))
        except Exception as e:
            logger.warning("time_context_timezone_invalid",
                           timezone=str(name), error=str(e),
                           msg="Falling back to UTC for business-hours, "
                               "maintenance-window and weekend evaluation.")
            return timezone.utc

    def _to_local(self, ts: datetime) -> datetime:
        """Convert an alert timestamp into the configured business timezone.

        Wazuh emits UTC. A naive timestamp (the ``%Y-%m-%d %H:%M:%S`` format)
        is therefore assumed to be UTC rather than local-to-the-process —
        though ``_parse_timestamp`` now guarantees an aware value, so the
        ``tzinfo is None`` branch below is belt-and-braces for a caller that
        hands us a datetime from somewhere else.
        """
        try:
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return ts.astimezone(self._tz)
        except Exception as e:
            logger.warning("time_context_tz_conversion_failed", error=str(e))
            return ts

    @staticmethod
    def _assume_utc(ts: datetime) -> datetime:
        """Stamp UTC on a naive datetime. Wazuh emits UTC.

        PORTABILITY (WO-H76 QA round 2): this must happen HERE, at the parse
        boundary, not only later in ``_to_local``. A naive datetime crossing a
        function boundary carries no timezone contract, so anything that does
        not route through ``_to_local`` — a future caller, or a test asserting
        on the parsed value — gets SYSTEM-LOCAL semantics from ``astimezone()``.
        That is correct on a UTC dev box or CI runner and silently wrong on the
        Asia/Kolkata production host: the exact "right in test, wrong in
        production because of where it runs" defect class this work order
        exists to kill. Three tests failed only on an IST machine.
        """
        return ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts

    def _parse_timestamp(self, timestamp_str) -> datetime:
        """Parse an alert timestamp, or fall back to NOW — and say so.

        ALWAYS returns a timezone-AWARE datetime; a naive input is read as UTC
        (see :meth:`_assume_utc`), never as the host's local time.

        The fallback scores the alert against PROCESSING time rather than
        EVENT time, which is silently wrong for a backfill or a replay. It used
        to happen with no log at all for perfectly ordinary shapes: bare
        ISO-8601 with no offset (``2026-08-12T12:00:00``), fractional seconds
        with no offset, sub-microsecond precision, and epoch numbers.
        """
        try:
            if isinstance(timestamp_str, str) and timestamp_str.strip():
                raw = timestamp_str.strip()
                # WO-H116: one version-independent parse covers every shape the
                # hand-rolled ladder below used to cover — ``+0000``, ``Z``,
                # offset-less, and sub-microsecond — on 3.10 as well as 3.14.
                # ``parse_iso8601`` applies the same naive-means-UTC rule as
                # :meth:`_assume_utc`.
                parsed = parse_iso8601_or_none(raw)
                if parsed is not None:
                    return parsed
                # Compatibility net for non-ISO shapes ``strptime`` tolerates
                # but ISO-8601 does not (e.g. unpadded ``2026-9-1 8:05:00``).
                for fmt in ["%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                            "%Y-%m-%d %H:%M:%S"]:
                    try:
                        return self._assume_utc(datetime.strptime(raw, fmt))
                    except ValueError:
                        continue
            elif isinstance(timestamp_str, (int, float)) and \
                    not isinstance(timestamp_str, bool):
                # Epoch seconds or milliseconds (Wazuh integrations emit both).
                value = float(timestamp_str)
                if abs(value) >= 1e11:
                    value /= 1000.0
                return datetime.fromtimestamp(value, tz=timezone.utc)
        except Exception:
            pass

        if not self._warned_unparsed_timestamp:
            self._warned_unparsed_timestamp = True
            logger.warning(
                "time_context_timestamp_unparsed",
                timestamp=repr(timestamp_str),
                msg="Could not parse the alert timestamp — scoring time "
                    "context against PROCESSING time, not event time. "
                    "Warned once per enricher instance.")
        else:
            logger.debug("time_context_timestamp_unparsed",
                         timestamp=repr(timestamp_str))
        return datetime.now(timezone.utc)

    def enrich(self, alert: dict) -> dict:
        """Determine time context for the alert."""
        ts = self._parse_timestamp(alert.get("timestamp", ""))

        # Everything below is evaluated in the CONFIGURED timezone, not UTC,
        # so business hours, maintenance windows and the weekend check all
        # agree on what local day/hour it is (WO-H76).
        ts = self._to_local(ts)

        is_business_hours = self._is_business_hours(ts)
        is_maintenance = self._is_maintenance_window(ts)
        is_weekend = ts.strftime("%A").lower() in ("saturday", "sunday")

        # Calculate time multiplier
        multiplier = 1.0
        adj = self._risk_adjustments
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

    def _is_business_hours(self, ts: datetime) -> bool:
        """Is ``ts`` (already converted to the business timezone) in-hours?

        A missing business_hours block defaults to True (= business hours,
        multiplier 1.0), which is the conservative direction: it does not
        inflate risk on every alert. The old code intended this but never
        reached it. Note the difference from an UNPARSABLE window, which now
        falls back to the default 09:00-18:00 Mon-Fri instead of switching
        out-of-hours risk off entirely — see ``_validate_business_hours``.
        """
        bh = self._business_hours
        if not bh:
            if not self._warned_missing_config:
                self._warned_missing_config = True
                logger.warning(
                    "time_context_business_hours_undefined",
                    msg="No business_hours configured — treating all alerts as "
                        "business hours (time_risk_multiplier 1.0).")
            return True
        return (ts.strftime("%A").lower() in bh["days"]
                and bh["start"] <= ts.time() <= bh["end"])

    def _is_maintenance_window(self, ts: datetime) -> bool:
        """Is ``ts`` inside a configured maintenance window?

        ``ts`` must already be in the configured business timezone (``enrich``
        converts it) — a window written as "sunday 02:00-06:00" means 02:00
        local, not 02:00 UTC. Windows are validated at construction, so
        everything reaching here has real weekday names and parsed times.
        """
        day_name = ts.strftime("%A").lower()
        now = ts.time()
        for window in self._maintenance_windows:
            if day_name not in window["days"]:
                continue
            start, end = window["start"], window["end"]
            if start <= end:
                in_window = start <= now <= end
            else:  # Crosses midnight (e.g., 22:00-06:00)
                in_window = now >= start or now <= end
            if in_window:
                return True
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
        the item as "not recent" rather than crashing.

        WO-H116: this used to be a second hand-rolled copy of the ISO ladder.
        It now delegates to ``src.timestamps`` so the ``+0000`` form Wazuh
        actually emits parses on Python 3.10 too, where bare ``fromisoformat``
        raises."""
        return parse_iso8601_or_none(val)

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
