"""AlienVault OTX — Open Threat Exchange (on-demand lookups, Tier 2)."""

import structlog
from cachetools import TTLCache
from src.enrichment.threat_intel.feeds.base import BaseFeedCollector

logger = structlog.get_logger(__name__)

OTX_TYPE_MAP = {
    "ip": "IPv4",
    "domain": "domain",
    "hash_sha256": "file",
    "hash_md5": "file",
    "hash_sha1": "file",
    "hash": "file",
}


class OTXCollector(BaseFeedCollector):
    FEED_NAME = "alienvault_otx"
    FEED_URL = "https://otx.alienvault.com/api/v1/indicators"
    FEED_TYPE = "api_rest"
    TIER = 2
    DEFAULT_INTERVAL = 1440
    REQUIRES_API_KEY = True

    def __init__(self, config: dict, db):
        super().__init__(config, db)
        self._cache = TTLCache(maxsize=10000, ttl=3600 * 24)

    def collect(self) -> int:
        """OTX is on-demand only in this implementation."""
        self.db.update_feed_status(
            self.FEED_NAME, status="active", ioc_count=0,
            feed_url=self.FEED_URL, feed_type=self.FEED_TYPE,
            tier=self.TIER, requires_api_key=True,
            interval_minutes=self.interval,
        )
        return 0

    def lookup(self, indicator_type: str, value: str):
        """Look up an indicator on OTX. Returns enrichment dict or None."""
        otx_type = OTX_TYPE_MAP.get(indicator_type)
        if not otx_type:
            return None

        cache_key = f"otx:{indicator_type}:{value}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            url = f"{self.FEED_URL}/{otx_type}/{value}/general"
            resp = self._http_get(
                url,
                headers={"X-OTX-API-KEY": self.api_key},
                timeout=10,
            )
            if resp.status_code == 404:
                self._cache[cache_key] = None
                return None
            if resp.status_code != 200:
                return None

            data = resp.json()
            pulse_info = data.get("pulse_info", {})
            pulse_count = pulse_info.get("count", 0)

            if pulse_count == 0:
                self._cache[cache_key] = None
                return None

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
                "reputation": data.get("reputation", 0),
            }

            # Severity by pulse count
            if pulse_count >= 20:
                severity = "high"
            elif pulse_count >= 5:
                severity = "medium"
            else:
                severity = "low"

            # Cache in DB
            self.db.upsert_ioc(self._make_ioc(
                ioc_type=indicator_type if indicator_type != "hash" else "hash_sha256",
                ioc_value=value,
                severity=severity,
                confidence=min(95, 40 + pulse_count * 3),
                category="c2" if pulse_count >= 10 else "malicious_ip",
                description=f"OTX: {pulse_count} pulses — "
                            + ", ".join(pulse_names[:3]),
                tags=list(tags)[:10],
                expires_at=self._default_expiry(7),
            ))

            self._cache[cache_key] = result
            logger.info("otx_lookup_hit", indicator=value,
                         pulse_count=pulse_count)
            return result

        except Exception as e:
            logger.warning("otx_lookup_failed", indicator=value,
                            error=str(e))
            return None
