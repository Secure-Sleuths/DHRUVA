"""CISA Known Exploited Vulnerabilities (KEV) catalog."""

import structlog
from src.enrichment.threat_intel.feeds.base import BaseFeedCollector

logger = structlog.get_logger(__name__)


class CISAKEVCollector(BaseFeedCollector):
    FEED_NAME = "cisa_kev"
    FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    FEED_TYPE = "bulk_json"
    TIER = 1
    DEFAULT_INTERVAL = 1440  # daily
    REQUIRES_API_KEY = False
    # CISA (Akamai) 403s this host's native IPv6; its IPv4 edge is reachable
    # via NAT64. See BaseFeedCollector._nat64_get.
    NAT64_FALLBACK = True

    def collect(self) -> int:
        resp = self._http_get(self.FEED_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        vulns = data.get("vulnerabilities", [])
        count = 0
        for v in vulns:
            cve_id = v.get("cveID", "").strip()
            if not cve_id:
                continue

            ransomware = v.get("knownRansomwareCampaignUse", "").lower() == "known"

            self.db.upsert_cve({
                "cve_id": cve_id,
                "description": v.get("shortDescription"),
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "in_cisa_kev": True,
                "kev_date_added": v.get("dateAdded"),
                "kev_due_date": v.get("dueDate"),
                "kev_ransomware": ransomware,
            })
            count += 1

        # Update feed status
        self.db.update_feed_status(
            self.FEED_NAME, status="active", ioc_count=count,
            feed_url=self.FEED_URL, feed_type=self.FEED_TYPE,
            tier=self.TIER, interval_minutes=self.interval,
        )
        logger.info("cisa_kev_collected", cves=count,
                     catalog_version=data.get("catalogVersion"))
        return count
