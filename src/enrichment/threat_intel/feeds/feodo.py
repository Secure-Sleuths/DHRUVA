"""abuse.ch Feodo Tracker — banking trojan / botnet C2 servers."""

import structlog
from src.enrichment.threat_intel.feeds.base import BaseFeedCollector

logger = structlog.get_logger(__name__)


class FeodoCollector(BaseFeedCollector):
    FEED_NAME = "feodo"
    FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
    FEED_TYPE = "bulk_json"
    TIER = 1
    DEFAULT_INTERVAL = 720
    REQUIRES_API_KEY = False

    def collect(self) -> int:
        resp = self._http_get(self.FEED_URL, timeout=30)
        resp.raise_for_status()
        entries = resp.json()

        if not isinstance(entries, list):
            raise ValueError("Feodo: expected JSON array")

        iocs = []
        for item in entries:
            ip = item.get("ip_address", "").strip()
            if not ip:
                continue

            malware = item.get("malware", "unknown")
            iocs.append(self._make_ioc(
                ioc_type="ip",
                ioc_value=ip,
                severity="critical",
                confidence=90,
                category="botnet",
                malware_family=malware,
                description=f"Feodo: {malware} C2 server "
                            f"(AS{item.get('as_number', '?')} {item.get('as_name', '')})",
                reference_url="https://feodotracker.abuse.ch/",
                tags=[malware.lower(), "c2", "banking_trojan"],
                first_seen=item.get("first_seen"),
                last_seen=item.get("last_online"),
                expires_at=self._default_expiry(90),
                raw_data=item,
            ))

        return self._store(iocs)
