"""OpenPhish — community phishing URL feed."""

import structlog
from urllib.parse import urlparse
from src.enrichment.threat_intel.feeds.base import BaseFeedCollector

logger = structlog.get_logger(__name__)


class OpenPhishCollector(BaseFeedCollector):
    FEED_NAME = "openphish"
    FEED_URL = "https://openphish.com/feed.txt"
    FEED_TYPE = "bulk_text"
    TIER = 1
    DEFAULT_INTERVAL = 720  # every 12 hours
    REQUIRES_API_KEY = False

    def collect(self) -> int:
        resp = self._http_get(
            self.FEED_URL,
            headers={"Accept": "text/plain"},
            timeout=30,
        )
        resp.raise_for_status()

        iocs = []
        # WO-H90: per-indicator host-extraction failures are counted, not
        # logged, and reported once at the end of the cycle. See below.
        _host_extract_failures = 0
        _last_host_error = ""
        for line in resp.text.strip().splitlines():
            url = line.strip()
            if not url or not url.startswith("http"):
                continue

            # Store the full URL
            iocs.append(self._make_ioc(
                ioc_type="url",
                ioc_value=url,
                severity="medium",
                confidence=65,
                category="phishing",
                description="OpenPhish: active phishing URL",
                reference_url="https://openphish.com/",
                tags=["phishing"],
                expires_at=self._default_expiry(30),
            ))

            # Extract and store domain
            try:
                parsed = urlparse(url)
                host = parsed.hostname
                if host and not self._looks_like_ip(host):
                    iocs.append(self._make_ioc(
                        ioc_type="domain",
                        ioc_value=host,
                        severity="medium",
                        confidence=60,
                        category="phishing",
                        description="OpenPhish: phishing domain",
                        tags=["phishing"],
                        expires_at=self._default_expiry(30),
                    ))
            except Exception as e:                       # noqa: BLE001
                # WO-H90: was a bare `except: pass`. A failure here means the
                # DOMAIN half of each phishing indicator is dropped, so a hit on
                # the domain alone (a different URL path on the same host) never
                # matches and the alert reads clean. HOT LOOP — this runs per
                # URL in a feed of thousands, so it is counted here and reported
                # ONCE below rather than logged per indicator.
                _host_extract_failures += 1
                _last_host_error = str(e)[:200]

        if _host_extract_failures:
            logger.warning("openphish_host_extraction_failed",
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
