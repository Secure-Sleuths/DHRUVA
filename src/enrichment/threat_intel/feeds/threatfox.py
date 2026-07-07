"""abuse.ch ThreatFox — malware C2 IOCs (IPs, domains, URLs, hashes)."""

import structlog
from src.enrichment.threat_intel.feeds.base import BaseFeedCollector

logger = structlog.get_logger(__name__)

# Download endpoint (no auth required, unlike the API)
EXPORT_URL = "https://threatfox.abuse.ch/export/json/recent/"


class ThreatFoxCollector(BaseFeedCollector):
    FEED_NAME = "threatfox"
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
                ioc = self._normalize(item)
                if ioc:
                    iocs.append(ioc)

        return self._store(iocs)

    def _normalize(self, raw: dict) -> dict:
        ioc_value = raw.get("ioc_value", raw.get("ioc", "")).strip()
        ioc_type_raw = raw.get("ioc_type", "")

        # Map ThreatFox types to our schema
        if "ip" in ioc_type_raw:
            ioc_type = "ip"
            # Strip port — handle IPv4 (1.2.3.4:443) and IPv6 ([::1]:443)
            if ioc_value.startswith("["):
                bracket_end = ioc_value.find("]")
                if bracket_end != -1:
                    ioc_value = ioc_value[1:bracket_end]
            elif ioc_value.count(":") == 1:
                ioc_value = ioc_value.split(":")[0]
        elif ioc_type_raw == "domain":
            ioc_type = "domain"
        elif ioc_type_raw == "url":
            ioc_type = "url"
        elif "md5" in ioc_type_raw:
            ioc_type = "hash_md5"
        elif "sha256" in ioc_type_raw:
            ioc_type = "hash_sha256"
        else:
            return None

        if not ioc_value:
            return None

        # Severity from confidence_level
        conf = raw.get("confidence_level", 50)
        if conf > 75:
            severity = "high"
        elif conf > 50:
            severity = "medium"
        else:
            severity = "low"

        # Category from threat_type
        threat_type = raw.get("threat_type", "")
        category_map = {
            "botnet_cc": "c2",
            "payload_delivery": "malware",
            "payload": "malware",
            "c2": "c2",
        }
        category = category_map.get(threat_type, "malware")

        return self._make_ioc(
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            severity=severity,
            confidence=conf,
            category=category,
            malware_family=raw.get("malware_printable"),
            description=f"ThreatFox: {raw.get('malware_printable', '')} {threat_type}".strip(),
            reference_url=raw.get("reference"),
            tags=[raw["tags"]] if isinstance(raw.get("tags"), str) else (raw.get("tags") or []),
            first_seen=raw.get("first_seen_utc"),
            last_seen=raw.get("last_seen_utc") or raw.get("first_seen_utc"),
            expires_at=self._default_expiry(180),
            raw_data=raw,
        )
