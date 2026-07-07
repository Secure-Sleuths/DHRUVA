"""
MISP Feed Collector — pulls IOCs from a MISP instance.
Requires pymisp library and MISP API key.
"""

import structlog
from datetime import datetime, timezone, timedelta

logger = structlog.get_logger(__name__)


class MISPCollector:
    """Collects threat intelligence indicators from a MISP instance."""

    FEED_NAME = "misp"
    FEED_URL = ""
    FEED_TYPE = "api_rest"
    TIER = 1
    REQUIRES_API_KEY = True

    def __init__(self, config: dict, db=None):
        self.db = db
        self.config = config
        self.enabled = config.get("enabled", False)
        self.url = config.get("url", "")
        self.api_key = config.get("api_key", "")
        self.verify_ssl = config.get("verify_ssl", True)
        self.interval = config.get("collection_interval_minutes", 360)
        self.FEED_URL = self.url

        if self.enabled and not self.url:
            logger.warning("misp_disabled_no_url")
            self.enabled = False

    def collect(self) -> int:
        """Pull events/attributes from MISP and store as IOCs."""
        if not self.enabled:
            return 0

        try:
            from pymisp import PyMISP
        except ImportError:
            logger.warning("misp_pymisp_not_installed",
                           message="Install pymisp: pip install pymisp")
            self._record_error("pymisp library not installed")
            return 0

        try:
            misp = PyMISP(self.url, self.api_key, self.verify_ssl)

            # Pull recent events (last 7 days)
            since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
            events = misp.search(
                controller="events",
                published=True,
                date_from=since,
                limit=100,
                pythonify=False,
            )

            ioc_count = 0
            if isinstance(events, dict):
                events = events.get("response", [])
            for event_wrapper in events:
                event = event_wrapper.get("Event", event_wrapper) if isinstance(event_wrapper, dict) else {}
                for attr in event.get("Attribute", []):
                    ioc_type = self._map_type(attr.get("type", ""))
                    if not ioc_type:
                        continue

                    self.db.upsert_ioc(
                        ioc_type=ioc_type,
                        ioc_value=attr.get("value", ""),
                        source="misp",
                        severity=self._map_threat_level(
                            str(event.get("threat_level_id", "3"))),
                        description=f"MISP Event: {event.get('info', '')[:200]}",
                        tags=",".join(
                            t.get("name", "") for t in event.get("Tag", [])[:5]),
                    )
                    ioc_count += 1

            self._store_success(ioc_count)
            logger.info("misp_collection_complete", ioc_count=ioc_count)
            return ioc_count

        except Exception as e:
            logger.error("misp_collection_failed", error=str(e))
            self._record_error(str(e))
            return 0

    def _map_type(self, misp_type: str) -> str:
        """Map MISP attribute type to our IOC type."""
        type_map = {
            "ip-src": "ip", "ip-dst": "ip", "ip": "ip",
            "domain": "domain", "hostname": "domain",
            "md5": "hash", "sha256": "hash", "sha1": "hash",
            "url": "url",
            "email-src": "email", "email-dst": "email",
        }
        return type_map.get(misp_type, "")

    def _map_threat_level(self, level_id: str) -> str:
        """Map MISP threat level to our severity."""
        level_map = {"1": "high", "2": "medium", "3": "low", "4": "low"}
        return level_map.get(str(level_id), "low")

    def _store_success(self, ioc_count: int):
        """Record successful collection."""
        if self.db:
            self.db.update_feed_status(
                self.FEED_NAME, status="active",
                ioc_count=ioc_count,
                feed_url=self.FEED_URL, feed_type=self.FEED_TYPE,
                tier=self.TIER, requires_api_key=self.REQUIRES_API_KEY,
                interval_minutes=self.interval,
            )

    def _record_error(self, error: str):
        """Record collection failure."""
        if self.db:
            self.db.update_feed_status(
                self.FEED_NAME, status="error", error=error,
                feed_url=self.FEED_URL, feed_type=self.FEED_TYPE,
                tier=self.TIER, requires_api_key=self.REQUIRES_API_KEY,
                interval_minutes=self.interval,
            )
