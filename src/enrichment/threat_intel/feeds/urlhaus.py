"""abuse.ch URLhaus — malicious URLs serving malware payloads."""

import structlog
from urllib.parse import urlparse
from src.enrichment.threat_intel.feeds.base import BaseFeedCollector

logger = structlog.get_logger(__name__)

# Download endpoint (no auth required, unlike the API)
EXPORT_URL = "https://urlhaus.abuse.ch/downloads/json_recent/"


class URLhausCollector(BaseFeedCollector):
    FEED_NAME = "urlhaus"
    FEED_URL = EXPORT_URL
    FEED_TYPE = "bulk_json"
    TIER = 1
    DEFAULT_INTERVAL = 360
    REQUIRES_API_KEY = False

    def collect(self) -> int:
        resp = self._http_get(self.FEED_URL, timeout=60)
        resp.raise_for_status()
        data = resp.json()

        # Download format: {id: [item], id: [item], ...}
        iocs = []
        for _id, items in data.items():
            if not isinstance(items, list):
                continue
            for item in items:
                url = item.get("url", "").strip()
                if not url:
                    continue

                status = item.get("url_status", "")
                severity = "high" if status == "online" else "medium"

                # Store the full URL
                iocs.append(self._make_ioc(
                    ioc_type="url",
                    ioc_value=url,
                    severity=severity,
                    confidence=70,
                    category="malware",
                    description=f"URLhaus: {item.get('threat', 'malware_download')}",
                    reference_url=item.get("urlhaus_link", ""),
                    tags=item.get("tags") or [],
                    first_seen=item.get("dateadded"),
                    last_seen=item.get("last_online") or item.get("dateadded"),
                    expires_at=self._default_expiry(90),
                    raw_data=item,
                ))

                # Also extract and store the domain/IP host
                try:
                    parsed = urlparse(url)
                    host = parsed.hostname
                    if host:
                        host_type = "ip" if self._looks_like_ip(host) else "domain"
                        iocs.append(self._make_ioc(
                            ioc_type=host_type,
                            ioc_value=host,
                            severity=severity,
                            confidence=60,
                            category="malware",
                            description="URLhaus host: serves malware payload",
                            tags=item.get("tags") or [],
                            first_seen=item.get("dateadded"),
                            last_seen=item.get("last_online") or item.get("dateadded"),
                            expires_at=self._default_expiry(90),
                        ))
                except Exception:
                    pass

        return self._store(iocs)

    @staticmethod
    def _looks_like_ip(host: str) -> bool:
        import ipaddress
        try:
            ipaddress.ip_address(host)
            return True
        except (ValueError, TypeError):
            return False
