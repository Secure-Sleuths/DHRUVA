"""AbuseIPDB — IP reputation scoring (on-demand, Tier 2)."""

import structlog
from cachetools import TTLCache
from src.enrichment.threat_intel.feeds.base import BaseFeedCollector

logger = structlog.get_logger(__name__)


class AbuseIPDBCollector(BaseFeedCollector):
    FEED_NAME = "abuseipdb"
    FEED_URL = "https://api.abuseipdb.com/api/v2/check"
    FEED_TYPE = "api_rest"
    TIER = 2
    DEFAULT_INTERVAL = 1440
    REQUIRES_API_KEY = True

    def __init__(self, config: dict, db):
        super().__init__(config, db)
        self._cache = TTLCache(maxsize=10000, ttl=3600 * 24)

    def collect(self) -> int:
        """AbuseIPDB is on-demand only — no bulk collection."""
        self.db.update_feed_status(
            self.FEED_NAME, status="active", ioc_count=0,
            feed_url=self.FEED_URL, feed_type=self.FEED_TYPE,
            tier=self.TIER, requires_api_key=True,
            interval_minutes=self.interval,
        )
        return 0

    def lookup(self, indicator_type: str, value: str):
        """Check an IP against AbuseIPDB. Returns enrichment dict or None."""
        if indicator_type != "ip":
            return None

        cache_key = f"abuseipdb:{value}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            resp = self._http_get(
                self.FEED_URL,
                headers={"Key": self.api_key},
                params={"ipAddress": value, "maxAgeInDays": 90},
                timeout=10,
            )
            if resp.status_code != 200:
                return None

            data = resp.json().get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0)

            result = {
                "source": "abuseipdb",
                "abuse_confidence": abuse_score,
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode", ""),
                "isp": data.get("isp", ""),
                "is_tor": data.get("isTor", False),
                "usage_type": data.get("usageType", ""),
            }

            # Determine severity
            if abuse_score > 75:
                severity = "high"
            elif abuse_score > 50:
                severity = "medium"
            elif abuse_score > 25:
                severity = "low"
            else:
                self._cache[cache_key] = None
                return None  # Below threshold, not a hit

            # Cache the IOC in the database for future local lookups
            self.db.upsert_ioc(self._make_ioc(
                ioc_type="ip",
                ioc_value=value,
                severity=severity,
                confidence=abuse_score,
                category="malicious_ip",
                description=f"AbuseIPDB: score {abuse_score}/100, "
                            f"{data.get('totalReports', 0)} reports, "
                            f"ISP: {data.get('isp', 'unknown')}",
                tags=["tor"] if data.get("isTor") else [],
                expires_at=self._default_expiry(7),
                raw_data=data,
            ))

            self._cache[cache_key] = result
            return result

        except Exception as e:
            logger.warning("abuseipdb_lookup_failed", ip=value, error=str(e))
            return None
