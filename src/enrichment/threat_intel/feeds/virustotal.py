"""VirusTotal — multi-engine file/IP/domain reputation (on-demand, Tier 2)."""

import structlog
from cachetools import TTLCache
from src.enrichment.threat_intel.feeds.base import BaseFeedCollector

logger = structlog.get_logger(__name__)

VT_TYPE_MAP = {
    "ip": "ip_addresses",
    "domain": "domains",
    "hash_sha256": "files",
    "hash_md5": "files",
    "hash_sha1": "files",
}


class VirusTotalCollector(BaseFeedCollector):
    FEED_NAME = "virustotal"
    FEED_URL = "https://www.virustotal.com/api/v3"
    FEED_TYPE = "api_rest"
    TIER = 2
    DEFAULT_INTERVAL = 1440
    REQUIRES_API_KEY = True

    def __init__(self, config: dict, db):
        super().__init__(config, db)
        self._cache = TTLCache(maxsize=5000, ttl=3600 * 24)

    def collect(self) -> int:
        """VirusTotal is on-demand only — no bulk collection."""
        self.db.update_feed_status(
            self.FEED_NAME, status="active", ioc_count=0,
            feed_url=self.FEED_URL, feed_type=self.FEED_TYPE,
            tier=self.TIER, requires_api_key=True,
            interval_minutes=self.interval,
        )
        return 0

    def lookup(self, indicator_type: str, value: str):
        """Look up an indicator on VirusTotal. Returns enrichment dict or None."""
        vt_type = VT_TYPE_MAP.get(indicator_type)
        if not vt_type:
            return None

        cache_key = f"vt:{indicator_type}:{value}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            url = f"{self.FEED_URL}/{vt_type}/{value}"
            resp = self._http_get(
                url,
                headers={"x-apikey": self.api_key},
                timeout=15,
            )
            if resp.status_code == 404:
                self._cache[cache_key] = None
                return None
            if resp.status_code != 200:
                return None

            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total_engines = sum(stats.values()) if stats else 1

            if malicious == 0 and suspicious == 0:
                self._cache[cache_key] = None
                return None

            detection_ratio = (malicious + suspicious) / max(total_engines, 1)

            if detection_ratio > 0.3:
                severity = "critical"
            elif detection_ratio > 0.15:
                severity = "high"
            elif detection_ratio > 0.05:
                severity = "medium"
            else:
                severity = "low"

            result = {
                "source": "virustotal",
                "malicious_detections": malicious,
                "suspicious_detections": suspicious,
                "total_engines": total_engines,
                "detection_ratio": round(detection_ratio, 3),
                "reputation": attrs.get("reputation", 0),
            }

            # Cache in DB
            confidence = min(100, int(detection_ratio * 100) + 20)
            self.db.upsert_ioc(self._make_ioc(
                ioc_type=indicator_type,
                ioc_value=value,
                severity=severity,
                confidence=confidence,
                category="malware" if indicator_type.startswith("hash") else "malicious_ip",
                description=f"VirusTotal: {malicious}/{total_engines} engines detected",
                tags=[],
                expires_at=self._default_expiry(7),
                raw_data=stats,
            ))

            self._cache[cache_key] = result
            return result

        except Exception as e:
            logger.warning("virustotal_lookup_failed", indicator=value,
                            error=str(e))
            return None
