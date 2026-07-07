"""Enhanced Threat Intelligence Enricher.

Local-DB-first enrichment: checks the local Postgres IOC database before
making any live API calls.  Replaces the original ThreatIntelEnricher
in src/enrichment/enrichers/__init__.py.
"""

import ipaddress
import re
import time
import structlog
from typing import Optional

logger = structlog.get_logger(__name__)

SEVERITY_RANK = {"none": 0, "info": 0, "low": 1, "medium": 2,
                 "high": 3, "critical": 4}


class _RateLimiter:
    """Simple per-API sliding window rate limiter for live TI lookups."""

    _LIMITS = {
        "abuseipdb": 0.7,       # 1000/day ~ 0.7/min
        "alienvault_otx": 10,   # generous
        "virustotal": 4,        # free tier: 4/min
    }

    def __init__(self):
        self._timestamps: dict = {}

    def allow(self, feed_name: str) -> bool:
        """Return True if a request to this feed is within rate limits."""
        limit = self._LIMITS.get(feed_name)
        if limit is None:
            return True

        now = time.monotonic()
        times = self._timestamps.setdefault(feed_name, [])
        times[:] = [t for t in times if now - t < 60.0]

        if len(times) >= limit:
            return False

        times.append(now)
        return True

# Private/reserved networks for IP filtering (IPv4 + IPv6)
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),       # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),      # IPv6 link-local
    ipaddress.ip_network("::1/128"),        # IPv6 loopback
]


class ThreatIntelEnricher:
    """Enriches alerts with threat intelligence.

    Lookup order:
    1. Local Postgres IOC database (zero latency — bulk-collected feeds)
    2. On-demand live lookups (AbuseIPDB, OTX, VirusTotal) for indicators
       not found locally
    3. CVE enrichment (CISA KEV + EPSS) for vulnerability alerts
    """

    def __init__(self, config: dict, db=None, ti_collector=None):
        self.config = config
        self.db = db
        self.ti_collector = ti_collector
        self._live_lookups_enabled = config.get("live_lookups_enabled", True)
        self._rate_limiter = _RateLimiter()

    def enrich(self, alert: dict) -> dict:
        """Check alert indicators against threat intelligence.

        Returns dict with the same keys as the original enricher for
        backward compatibility, plus additional structured data.
        """
        enrichment = {
            "threat_intel_hits": 0,
            "threat_intel_sources": [],
            "threat_intel_details": [],
            "is_known_malicious": False,
            "highest_ti_severity": "none",
            "ti_matches": [],
        }

        if not self.db:
            return enrichment

        # Extract indicators from alert
        indicators = self._extract_indicators(alert)
        cve_ids = self._extract_cve_ids(alert)

        if not indicators and not cve_ids:
            return enrichment

        max_severity = "none"

        # ------ Step 1: Batch lookup against local Postgres DB ------
        values = [v for _, v in indicators]
        local_hits = self.db.lookup_iocs_batch(values)
        matched_values = set()

        for ioc_type, value in indicators:
            matches = local_hits.get(value, [])
            if matches:
                matched_values.add(value)
                # Take the highest-severity match for this indicator
                best = max(matches,
                           key=lambda m: SEVERITY_RANK.get(m.get("severity", ""), 0))
                sev = best.get("severity", "medium")

                enrichment["threat_intel_hits"] += 1
                source = best.get("source", "local_db")
                if source not in enrichment["threat_intel_sources"]:
                    enrichment["threat_intel_sources"].append(source)

                detail = {
                    "indicator": value,
                    "type": ioc_type,
                    "source": source,
                    "severity": sev,
                    "confidence": best.get("confidence", 50),
                    "category": best.get("category"),
                    "malware_family": best.get("malware_family"),
                    "description": best.get("description"),
                }
                enrichment["threat_intel_details"].append(detail)
                enrichment["ti_matches"].append({
                    **detail,
                    "all_sources": [m.get("source") for m in matches],
                    "match_count": len(matches),
                })

                if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(max_severity, 0):
                    max_severity = sev

        # ------ Step 2: Live lookups for unmatched indicators ------
        if self._live_lookups_enabled and self.ti_collector:
            for ioc_type, value in indicators:
                if value in matched_values:
                    continue
                live_result = self._try_live_lookups(ioc_type, value)
                if live_result:
                    matched_values.add(value)
                    enrichment["threat_intel_hits"] += 1
                    source = live_result.get("source", "live")
                    if source not in enrichment["threat_intel_sources"]:
                        enrichment["threat_intel_sources"].append(source)
                    enrichment["threat_intel_details"].append({
                        "indicator": value,
                        "type": ioc_type,
                        **live_result,
                    })

                    # Determine severity from live result
                    sev = self._severity_from_live(live_result)
                    if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(max_severity, 0):
                        max_severity = sev

        # ------ Step 3: CVE enrichment ------
        if cve_ids:
            cve_enrichment = self._enrich_cves(cve_ids)
            enrichment.update(cve_enrichment)
            if cve_enrichment.get("cve_in_kev"):
                if SEVERITY_RANK.get(max_severity, 0) < SEVERITY_RANK["critical"]:
                    max_severity = "critical"

        enrichment["highest_ti_severity"] = max_severity
        enrichment["is_known_malicious"] = max_severity in ("high", "critical")

        # Confidence-based IOC routing recommendation
        if enrichment.get("is_known_malicious") and enrichment.get("highest_ti_severity") == "critical":
            enrichment["auto_block_recommended"] = True
        else:
            enrichment["auto_block_recommended"] = False

        return enrichment

    # ------------------------------------------------------------------
    # Indicator extraction
    # ------------------------------------------------------------------

    def _extract_indicators(self, alert: dict) -> list:
        """Extract IOC indicators from an alert. Returns [(type, value)]."""
        indicators = []

        # Public IPs
        for field in ["src_ip", "dst_ip"]:
            ip = alert.get(field)
            if ip and not self._is_private_ip(ip):
                indicators.append(("ip", ip))

        # File hashes
        data = alert.get("data", {})
        if isinstance(data, dict):
            for hash_field, hash_type in [
                ("md5", "hash_md5"), ("sha256", "hash_sha256"),
                ("sha1", "hash_sha1"),
            ]:
                val = data.get(hash_field)
                if val and isinstance(val, str) and len(val) > 8:
                    indicators.append((hash_type, val))

            # Syscheck (FIM) hashes
            syscheck = data.get("syscheck", {})
            if isinstance(syscheck, dict):
                for hash_field, hash_type in [
                    ("md5_after", "hash_md5"), ("sha256_after", "hash_sha256"),
                    ("sha1_after", "hash_sha1"),
                ]:
                    val = syscheck.get(hash_field)
                    if val and isinstance(val, str) and len(val) > 8:
                        indicators.append((hash_type, val))

        # Email addresses
        for field in ("src_user", "dst_user"):
            val = alert.get(field, "")
            if val and isinstance(val, str) and "@" in val:
                parts = val.split("@")
                if len(parts) == 2 and "." in parts[1]:
                    indicators.append(("email", val.lower()))
        if isinstance(data, dict):
            for _k, v in data.items():
                if isinstance(v, str) and "@" in v:
                    parts = v.split("@")
                    if len(parts) == 2 and "." in parts[1]:
                        indicators.append(("email", v.lower()))

        # Domains from URL fields
        url_val = data.get("url") if isinstance(data, dict) else None
        if url_val and isinstance(url_val, str):
            domain = self._extract_domain(url_val)
            if domain:
                indicators.append(("domain", domain))

        return indicators

    def _extract_cve_ids(self, alert: dict) -> list:
        """Extract CVE IDs from vulnerability alerts."""
        cves = []
        data = alert.get("data", {})
        if isinstance(data, dict):
            # Wazuh vulnerability detector format
            vuln = data.get("vulnerability", {})
            if isinstance(vuln, dict):
                cve = vuln.get("cve")
                if cve:
                    cves.append(cve)

            # Also check rule description for CVE references
            rule_desc = alert.get("rule_description", "")
            cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}')
            cves.extend(cve_pattern.findall(rule_desc))

        return list(set(cves))

    # ------------------------------------------------------------------
    # Live lookups
    # ------------------------------------------------------------------

    def _try_live_lookups(self, ioc_type: str, value: str) -> Optional[dict]:
        """Try on-demand feeds for an indicator not in local DB."""
        # AbuseIPDB for IPs
        if ioc_type == "ip" and self._rate_limiter.allow("abuseipdb"):
            feed = self.ti_collector.get_on_demand_feed("abuseipdb")
            if feed:
                result = feed.lookup("ip", value)
                if result:
                    return result

        # OTX for all types
        if self._rate_limiter.allow("alienvault_otx"):
            feed = self.ti_collector.get_on_demand_feed("alienvault_otx")
            if feed:
                result = feed.lookup(ioc_type, value)
                if result:
                    return result

        # VirusTotal as fallback
        if self._rate_limiter.allow("virustotal"):
            feed = self.ti_collector.get_on_demand_feed("virustotal")
            if feed:
                result = feed.lookup(ioc_type, value)
                if result:
                    return result

        return None

    def _severity_from_live(self, result: dict) -> str:
        """Derive severity from a live lookup result."""
        source = result.get("source", "")

        if source == "abuseipdb":
            score = result.get("abuse_confidence", 0)
            if score > 75:
                return "high"
            elif score > 50:
                return "medium"
            return "low"

        if source == "alienvault_otx":
            pulses = result.get("pulse_count", 0)
            if pulses >= 20:
                return "high"
            elif pulses >= 5:
                return "medium"
            return "low"

        if source == "virustotal":
            ratio = result.get("detection_ratio", 0)
            if ratio > 0.3:
                return "critical"
            elif ratio > 0.15:
                return "high"
            elif ratio > 0.05:
                return "medium"
            return "low"

        return "medium"

    # ------------------------------------------------------------------
    # CVE enrichment
    # ------------------------------------------------------------------

    def _enrich_cves(self, cve_ids: list) -> dict:
        """Look up CVE data (KEV + EPSS) from local cache."""
        result = {
            "cve_in_kev": False,
            "cve_epss_score": None,
            "cve_ransomware_use": False,
            "cve_details": [],
        }

        for cve_id in cve_ids:
            cve = self.db.lookup_cve(cve_id)
            if not cve:
                # Try EPSS on-demand lookup
                if self.ti_collector:
                    epss_feed = None
                    for f in self.ti_collector.feeds:
                        if f.FEED_NAME == "epss":
                            epss_feed = f
                            break
                    if epss_feed and hasattr(epss_feed, "lookup_cve"):
                        cve = epss_feed.lookup_cve(cve_id)

            if cve:
                result["cve_details"].append(cve)
                if cve.get("in_cisa_kev"):
                    result["cve_in_kev"] = True
                if cve.get("kev_ransomware"):
                    result["cve_ransomware_use"] = True
                epss = cve.get("epss_score")
                if epss is not None:
                    if result["cve_epss_score"] is None or epss > result["cve_epss_score"]:
                        result["cve_epss_score"] = epss

        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if IP is private/reserved (IPv4 and IPv6)."""
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in _PRIVATE_NETWORKS)
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _extract_domain(url: str) -> Optional[str]:
        """Extract domain from a URL string."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.hostname
            if host and not all(c.isdigit() or c == '.' for c in host):
                return host
        except Exception:
            pass
        return None
