"""Threat Intelligence Collector — orchestrates all feed collectors."""

import structlog
from datetime import datetime, timezone, timedelta

from src.enrichment.threat_intel.feeds.threatfox import ThreatFoxCollector
from src.enrichment.threat_intel.feeds.urlhaus import URLhausCollector
from src.enrichment.threat_intel.feeds.feodo import FeodoCollector
from src.enrichment.threat_intel.feeds.malwarebazaar import MalwareBazaarCollector
from src.enrichment.threat_intel.feeds.cisa_kev import CISAKEVCollector
from src.enrichment.threat_intel.feeds.epss import EPSSCollector
from src.enrichment.threat_intel.feeds.openphish import OpenPhishCollector
from src.enrichment.threat_intel.feeds.abuseipdb import AbuseIPDBCollector
from src.enrichment.threat_intel.feeds.virustotal import VirusTotalCollector
from src.enrichment.threat_intel.feeds.otx import OTXCollector

logger = structlog.get_logger(__name__)

# Registry: feed_name → collector class
FEED_REGISTRY = [
    ("threatfox", ThreatFoxCollector),
    ("urlhaus", URLhausCollector),
    ("feodo", FeodoCollector),
    ("malwarebazaar", MalwareBazaarCollector),
    ("cisa_kev", CISAKEVCollector),
    ("epss", EPSSCollector),
    ("openphish", OpenPhishCollector),
    ("abuseipdb", AbuseIPDBCollector),
    ("virustotal", VirusTotalCollector),
    ("alienvault_otx", OTXCollector),
]


class ThreatIntelCollector:
    """Orchestrates TI feed collection on a schedule."""

    def __init__(self, config: dict, db):
        self.config = config
        self.db = db
        self.feeds = []
        self._on_demand = {}  # feed_name → collector (for enricher)
        self._init_feeds()

    def _init_feeds(self):
        feeds_cfg = self.config.get("feeds", {})
        for name, cls in FEED_REGISTRY:
            feed_cfg = feeds_cfg.get(name, {})
            if not feed_cfg.get("enabled", True):
                continue
            try:
                collector = cls(feed_cfg, self.db)
                if collector.enabled:
                    self.feeds.append(collector)
                    if collector.REQUIRES_API_KEY:
                        self._on_demand[name] = collector
            except Exception as e:
                logger.warning("feed_init_failed", feed=name, error=str(e))

        logger.info("threat_intel_feeds_initialized",
                     total=len(self.feeds),
                     names=[f.FEED_NAME for f in self.feeds])

    def collect_all(self) -> dict:
        """Run collection for all feeds that are due.

        Each feed tracks its own last_fetch_at; we only collect if enough
        time has elapsed based on its configured interval.
        """
        results = {"feeds_checked": 0, "feeds_collected": 0,
                    "total_iocs": 0, "errors": []}

        for feed in self.feeds:
            # Skip on-demand-only feeds (mode = "on_demand")
            if feed.config.get("mode") == "on_demand":
                continue

            results["feeds_checked"] += 1

            # Check if this feed is due for collection
            if not self._is_due(feed):
                continue

            try:
                count = feed.collect()
                results["feeds_collected"] += 1
                results["total_iocs"] += count
            except Exception as e:
                error_msg = f"{feed.FEED_NAME}: {e}"
                results["errors"].append(error_msg)
                feed._record_error(str(e))

        logger.info("ti_collection_cycle_complete",
                     feeds_collected=results["feeds_collected"],
                     total_iocs=results["total_iocs"],
                     errors=len(results["errors"]))
        return results

    def _is_due(self, feed) -> bool:
        """Check if a feed should be collected now."""
        statuses = self.db.get_feed_statuses()
        for s in statuses:
            if s["feed_name"] == feed.FEED_NAME and s.get("last_success_at"):
                last = datetime.fromisoformat(s["last_success_at"])
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                next_due = last + timedelta(minutes=feed.interval)
                if datetime.now(timezone.utc) < next_due:
                    return False
        return True

    def get_on_demand_feed(self, name: str):
        """Get a specific on-demand feed collector for live lookups."""
        return self._on_demand.get(name)

    def cleanup_expired(self) -> int:
        """Remove IOCs past their expiry date."""
        count = self.db.cleanup_expired_iocs()
        if count > 0:
            logger.info("ti_expired_iocs_cleaned", count=count)
        return count

    def get_feed_status(self) -> list:
        """Get health status of all feeds."""
        return self.db.get_feed_statuses()
