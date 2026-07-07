"""FIRST.org EPSS — Exploit Prediction Scoring System.

On-demand only: looks up EPSS scores for specific CVEs during enrichment,
not bulk-collected.
"""

import structlog
from src.enrichment.threat_intel.feeds.base import BaseFeedCollector

logger = structlog.get_logger(__name__)


class EPSSCollector(BaseFeedCollector):
    FEED_NAME = "epss"
    FEED_URL = "https://api.first.org/data/v1/epss"
    FEED_TYPE = "api_rest"
    TIER = 1
    DEFAULT_INTERVAL = 1440  # daily — but primarily on-demand
    REQUIRES_API_KEY = False

    def collect(self) -> int:
        """EPSS is on-demand only. No bulk collection needed."""
        self.db.update_feed_status(
            self.FEED_NAME, status="active", ioc_count=0,
            feed_url=self.FEED_URL, feed_type=self.FEED_TYPE,
            tier=self.TIER, interval_minutes=self.interval,
        )
        return 0

    def lookup_cve(self, cve_id: str) -> dict:
        """Fetch EPSS score for a specific CVE and cache in DB."""
        # Check cache first
        existing = self.db.lookup_cve(cve_id)
        if existing and existing.get("epss_score") is not None:
            return existing

        try:
            resp = self._http_get(
                self.FEED_URL,
                params={"cve": cve_id},
                timeout=10,
            )
            if resp.status_code != 200:
                return existing or {}

            data = resp.json()
            items = data.get("data", [])
            if not items:
                return existing or {}

            item = items[0]
            epss_score = float(item.get("epss", 0))
            epss_percentile = float(item.get("percentile", 0))

            self.db.upsert_cve({
                "cve_id": cve_id,
                "epss_score": epss_score,
                "epss_percentile": epss_percentile,
            })

            logger.info("epss_lookup_hit", cve=cve_id,
                         score=epss_score, percentile=epss_percentile)

            result = self.db.lookup_cve(cve_id)
            return result or {}

        except Exception as e:
            logger.warning("epss_lookup_failed", cve=cve_id, error=str(e))
            return existing or {}
