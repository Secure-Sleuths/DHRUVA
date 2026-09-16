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
        # WO-H90: per-indicator host-extraction failures are counted, not
        # logged, and reported once at the end of the cycle. See below.
        _host_extract_failures = 0
        _last_host_error = ""
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
                except Exception as e:                   # noqa: BLE001
                    # WO-H90: was a bare `except: pass`. A failure here means the
                    # HOST half of each malware-distribution indicator is
                    # dropped, so DHRUVA knows the exact payload URL but not the
                    # domain/IP serving it — and an alert touching that host
                    # reads clean. HOT LOOP — counted per indicator, reported
                    # ONCE below.
                    _host_extract_failures += 1
                    _last_host_error = str(e)[:200]

        if _host_extract_failures:
            logger.warning("urlhaus_host_extraction_failed",
                           feed=self.FEED_NAME,
                           failed=_host_extract_failures,
                           error=_last_host_error)

        return self._store(iocs)

    @staticmethod
    def _looks_like_ip(host: str) -> bool:
        import ipaddress
        try:
            ipaddress.ip_address(host)
            return True
        except (ValueError, TypeError):
            return False
