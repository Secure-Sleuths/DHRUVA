"""MISP — self-hosted threat-intel platform (scheduled bulk pull, Tier 2).

MISP is an on-prem/self-hosted feed: it needs a base URL *and* an API key, so
it is gated exactly like the other Tier-2 feeds (AbuseIPDB / OTX / VirusTotal) —
``TIER = 2`` + ``REQUIRES_API_KEY = True``. The ``pymisp`` client is an optional
dependency that is physically absent from Community builds, so it is imported
lazily inside ``collect()`` and a missing library degrades the feed to a no-op
rather than crashing the collector or the scheduler.
"""

import structlog
from datetime import datetime, timezone, timedelta

from src.enrichment.threat_intel.feeds.base import BaseFeedCollector

logger = structlog.get_logger(__name__)

# MISP attribute type -> our normalised IOC type
MISP_TYPE_MAP = {
    "ip-src": "ip", "ip-dst": "ip", "ip": "ip",
    "domain": "domain", "hostname": "domain",
    "md5": "hash", "sha256": "hash", "sha1": "hash",
    "url": "url",
    "email-src": "email", "email-dst": "email",
}

# MISP threat_level_id -> our severity
MISP_THREAT_LEVEL_MAP = {"1": "high", "2": "medium", "3": "low", "4": "low"}


def _unresolved(value) -> bool:
    """True if a config value is an unresolved ``${ENV_VAR}`` placeholder.

    The config loader leaves ``${MISP_URL}`` literal when the env var is unset,
    so we treat such placeholders as empty and let the feed auto-disable.
    """
    return isinstance(value, str) and value.startswith("${") and value.endswith("}")


class MISPCollector(BaseFeedCollector):
    """Collects threat-intel indicators from a MISP instance on a schedule."""

    FEED_NAME = "misp"
    FEED_URL = ""
    FEED_TYPE = "api_rest"
    TIER = 2
    DEFAULT_INTERVAL = 360          # 6 hours
    REQUIRES_API_KEY = True

    def __init__(self, config: dict, db):
        super().__init__(config, db)

        # MISP needs a base URL in addition to the API key handled by the base
        # class. Treat unresolved ${ENV} placeholders as unset so a missing
        # MISP_URL / MISP_KEY degrades gracefully to disabled.
        self.url = config.get("url", "")
        if _unresolved(self.url):
            self.url = ""
        if _unresolved(self.api_key):
            self.api_key = ""
        self.FEED_URL = self.url
        self.verify_ssl = self._coerce_bool(config.get("verify_ssl", True))

        if self.enabled and not self.url:
            self.enabled = False
            logger.info("feed_disabled_no_url", feed=self.FEED_NAME)
        if self.enabled and not self.api_key:
            # Base class already disables on a missing key, but re-check after
            # the ${ENV} scrub above so an unresolved placeholder also disables.
            self.enabled = False
            logger.info("feed_disabled_no_api_key", feed=self.FEED_NAME)

    @staticmethod
    def _coerce_bool(value) -> bool:
        """Coerce a config/env value to bool. Defaults secure (verify=True)."""
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            if _unresolved(value):
                return True  # unset MISP_VERIFY_TLS -> verify (secure default)
            # Blank / whitespace (e.g. `MISP_VERIFY_TLS=`) must NOT silently
            # disable TLS verification — fall through to the secure default.
            stripped = value.strip().lower()
            if stripped == "":
                return True
            return stripped not in ("false", "0", "no", "off")
        return bool(value)

    def collect(self) -> int:
        """Pull recent published events from MISP and store their IOCs."""
        if not self.enabled:
            return 0

        try:
            from pymisp import PyMISP
        except ImportError:
            logger.warning(
                "misp_pymisp_not_installed",
                feed=self.FEED_NAME,
                message="pymisp not available (Community build) — install pymisp to enable",
            )
            self._record_error("pymisp library not installed")
            return 0

        try:
            misp = PyMISP(self.url, self.api_key, self.verify_ssl)

            # Pull recent published events (last 7 days).
            since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
            events = misp.search(
                controller="events",
                published=True,
                date_from=since,
                limit=100,
                pythonify=False,
            )
            if isinstance(events, dict):
                events = events.get("response", [])

            iocs = []
            for event_wrapper in events or []:
                event = (event_wrapper.get("Event", event_wrapper)
                         if isinstance(event_wrapper, dict) else {})
                severity = MISP_THREAT_LEVEL_MAP.get(
                    str(event.get("threat_level_id", "3")), "low")
                info = (event.get("info", "") or "")[:200]
                tags = [t.get("name", "") for t in (event.get("Tag", []) or [])[:5]
                        if t.get("name")]
                event_id = event.get("id", "")
                ref = f"{self.url.rstrip('/')}/events/view/{event_id}" if event_id else None

                for attr in event.get("Attribute", []) or []:
                    ioc_type = MISP_TYPE_MAP.get(attr.get("type", ""))
                    ioc_value = attr.get("value", "")
                    if not ioc_type or not ioc_value:
                        continue
                    iocs.append(self._make_ioc(
                        ioc_type=ioc_type,
                        ioc_value=ioc_value,
                        severity=severity,
                        confidence=70,
                        category="misp_event",
                        description=f"MISP Event: {info}" if info else "MISP indicator",
                        reference_url=ref,
                        tags=tags,
                        expires_at=self._default_expiry(30),
                    ))

            count = self._store(iocs)
            logger.info("misp_collection_complete", iocs=count)
            return count

        except Exception as e:
            logger.error("misp_collection_failed", error=str(e))
            self._record_error(str(e))
            return 0
