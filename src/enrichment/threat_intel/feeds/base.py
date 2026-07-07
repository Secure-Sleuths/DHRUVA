"""Base class for all threat intelligence feed collectors."""

import uuid
import os
import socket
import ipaddress
import structlog
import requests
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

logger = structlog.get_logger(__name__)

USER_AGENT = "SecureSleuths-AI-SOC/1.0 (Threat Intel Collector)"

# ---------------------------------------------------------------------------
# NAT64 fallback (RFC 6052 / 7050)
#
# Some CDNs (e.g. CISA behind Akamai) return 403 to this host's *native IPv6*
# source but serve normally to their IPv4 edge. On an IPv6-only host reached
# via NAT64, hitting the IPv4 edge requires mapping the target's A record into
# the local NAT64 /96 prefix. Feeds opt in via ``NAT64_FALLBACK = True``.
# ---------------------------------------------------------------------------

_nat64_prefixes_cache = None


def _discover_nat64_prefixes() -> list:
    """Discover local NAT64 /96 prefixes as 96-bit ints (IPv4 in low 32 bits).

    Uses RFC 7050 well-known name ``ipv4only.arpa`` (which embeds 192.0.0.170/
    .171 in every NAT64 address). Overridable via env ``NAT64_PREFIXES`` (a
    comma-separated list of prefix addresses, ``/96`` suffix optional). Cached
    for the process; empty list when no NAT64 is configured.
    """
    global _nat64_prefixes_cache
    if _nat64_prefixes_cache is not None:
        return _nat64_prefixes_cache

    prefixes = []
    env = os.getenv("NAT64_PREFIXES", "").strip()
    if env:
        for item in env.split(","):
            item = item.split("/")[0].strip()
            if not item:
                continue
            try:
                prefixes.append(int(ipaddress.IPv6Address(item)) & ~0xFFFFFFFF)
            except ValueError:
                logger.warning("nat64_bad_prefix_env", value=item)
    else:
        try:
            infos = socket.getaddrinfo("ipv4only.arpa", None, socket.AF_INET6)
        except socket.gaierror:
            infos = []
        seen = set()
        for info in infos:
            try:
                v6 = int(ipaddress.IPv6Address(info[4][0]))
            except ValueError:
                continue
            prefix = v6 & ~0xFFFFFFFF  # strip embedded IPv4 -> /96 network
            if prefix not in seen:
                seen.add(prefix)
                prefixes.append(prefix)

    _nat64_prefixes_cache = prefixes
    if prefixes:
        logger.info("nat64_prefixes_discovered",
                    prefixes=[str(ipaddress.IPv6Address(p)) for p in prefixes])
    return prefixes


def _nat64_map(prefix96: int, ipv4: str) -> str:
    """Embed an IPv4 dotted string into a NAT64 /96 prefix -> IPv6 string."""
    return str(ipaddress.IPv6Address(prefix96 | int(ipaddress.IPv4Address(ipv4))))


class _PinnedIPHTTPSAdapter(requests.adapters.HTTPAdapter):
    """Route this adapter's HTTPS connections for *host* to *pinned_ip* while
    keeping SNI and certificate verification bound to the original hostname.

    Thread-safe by construction: the pinning is confined to this adapter
    instance (mounted on a short-lived Session), so no process-global state
    (e.g. ``socket.getaddrinfo``) is ever mutated — safe under the scheduler +
    uvicorn + worker threads that share the process. Only requests to *host*
    are pinned; a redirect to any other host resolves normally (no SSRF via
    redirect). Certificate verification is unchanged: urllib3 still presents
    ``server_hostname`` (the real host) for SNI and validates the cert against
    it, even though the socket connects to the NAT64-mapped IP.
    """

    def __init__(self, host: str, pinned_ip: str, **kwargs):
        self._host = host
        self._pinned_ip = pinned_ip
        super().__init__(**kwargs)

    def send(self, request, **kwargs):
        # Force the Host header to the real hostname. get_connection_with_tls_context
        # pins pool.host to the NAT64 IP, so without this urllib3 would derive the
        # Host header from that IP and the CDN would route to the wrong vhost.
        if urlparse(request.url).hostname == self._host:
            request.headers["Host"] = self._host
        return super().send(request, **kwargs)

    def get_connection_with_tls_context(self, request, verify,
                                        proxies=None, cert=None):
        pool = super().get_connection_with_tls_context(
            request, verify, proxies=proxies, cert=cert)
        if urlparse(request.url).hostname == self._host:
            pool.host = self._pinned_ip        # connect to NAT64 IPv4 edge
            pool.assert_hostname = self._host  # verify cert against real host
            # SNI must go through conn_kw — urllib3 2.x forwards conn_kw to the
            # connection but does NOT propagate pool.server_hostname.
            pool.conn_kw["server_hostname"] = self._host
        return pool


class BaseFeedCollector:
    """Abstract base for TI feed collectors.

    Subclasses must set the class-level constants and implement ``collect()``.
    On-demand feeds should also implement ``lookup()``.
    """

    FEED_NAME: str = ""
    FEED_URL: str = ""
    FEED_TYPE: str = "bulk_json"        # bulk_json, bulk_csv, bulk_text, api_rest
    TIER: int = 1                       # 1=no key, 2=free key, 3=optional
    DEFAULT_INTERVAL: int = 360         # minutes
    REQUIRES_API_KEY: bool = False
    # Opt in when the feed's CDN 403s this host's native IPv6 but serves its
    # IPv4 edge (reachable here via NAT64). Off by default so genuine 403s
    # (bad API key, etc.) on other feeds are not masked or retried.
    NAT64_FALLBACK: bool = False

    def __init__(self, config: dict, db):
        self.config = config
        self.db = db
        self.enabled = config.get("enabled", True)
        self.api_key = config.get("api_key", "")
        self.interval = config.get("interval_minutes", self.DEFAULT_INTERVAL)

        if self.REQUIRES_API_KEY and not self.api_key:
            self.enabled = False
            logger.info("feed_disabled_no_api_key", feed=self.FEED_NAME)

    # ------------------------------------------------------------------
    # Subclass interface
    # ------------------------------------------------------------------

    def collect(self) -> int:
        """Fetch IOCs from feed, store in DB. Returns count ingested."""
        raise NotImplementedError

    def lookup(self, indicator_type: str, value: str):
        """On-demand lookup (Tier 2/3 feeds). Returns dict or None."""
        return None

    # ------------------------------------------------------------------
    # Helpers available to all collectors
    # ------------------------------------------------------------------

    def _http_get(self, url: str, *, headers: dict = None,
                  params: dict = None, timeout: int = 30) -> requests.Response:
        """GET with standard headers, timeout, and single 429 retry."""
        hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if headers:
            hdrs.update(headers)
        resp = requests.get(url, headers=hdrs, params=params, timeout=timeout)

        if resp.status_code == 429:
            import time
            retry_after = min(int(resp.headers.get("Retry-After", 5)), 30)
            logger.warning("http_429_rate_limited", url=url,
                           retry_after=retry_after)
            time.sleep(retry_after)
            resp = requests.get(url, headers=hdrs, params=params,
                                timeout=timeout)

        # Native-IPv6 CDN block: retry via NAT64 to the IPv4 edge.
        if resp.status_code == 403 and self.NAT64_FALLBACK:
            alt = self._nat64_get(url, hdrs, params, timeout)
            if alt is not None:
                return alt

        return resp

    def _nat64_get(self, url: str, hdrs: dict, params, timeout: int):
        """Retry a GET forcing the connection through NAT64 to the host's
        IPv4 edge. Returns the response on success, or None to fall back to the
        original (still-403) response."""
        host = urlparse(url).hostname
        if not host:
            return None
        prefixes = _discover_nat64_prefixes()
        if not prefixes:
            return None
        try:
            ipv4s = sorted({i[4][0]
                            for i in socket.getaddrinfo(host, 443, socket.AF_INET)})
        except socket.gaierror:
            return None

        for prefix in prefixes:
            for ipv4 in ipv4s:
                mapped = _nat64_map(prefix, ipv4)
                try:
                    with requests.Session() as sess:
                        sess.mount("https://",
                                   _PinnedIPHTTPSAdapter(host, mapped))
                        resp = sess.get(url, headers=hdrs, params=params,
                                        timeout=timeout)
                except requests.RequestException:
                    continue
                if resp.status_code < 400:
                    logger.info("nat64_fallback_used", feed=self.FEED_NAME,
                                host=host, ipv4=ipv4, mapped=mapped,
                                status=resp.status_code)
                    return resp

        logger.warning("nat64_fallback_exhausted", feed=self.FEED_NAME,
                       host=host, tried=len(prefixes) * len(ipv4s))
        return None

    def _http_post(self, url: str, *, headers: dict = None,
                   json_body: dict = None, data=None,
                   timeout: int = 30) -> requests.Response:
        """POST with standard headers and timeout."""
        hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if headers:
            hdrs.update(headers)
        return requests.post(url, headers=hdrs, json=json_body, data=data,
                             timeout=timeout)

    def _make_ioc(self, *, ioc_type: str, ioc_value: str,
                  severity: str = "medium", confidence: int = 50,
                  category: str = None, malware_family: str = None,
                  description: str = None, reference_url: str = None,
                  tags: list = None, first_seen: str = None,
                  last_seen: str = None, expires_at: str = None,
                  raw_data: dict = None) -> dict:
        """Build a normalised IOC dict ready for ``db.upsert_ioc``."""
        now = datetime.now(timezone.utc).isoformat()
        return {
            "id": str(uuid.uuid4()),
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "source": self.FEED_NAME,
            "severity": severity,
            "confidence": confidence,
            "category": category,
            "malware_family": malware_family,
            "description": description,
            "reference_url": reference_url,
            "tags": tags or [],
            "first_seen": first_seen or now,
            "last_seen": last_seen or now,
            "expires_at": expires_at,
            "raw_data": raw_data or {},
        }

    def _default_expiry(self, days: int = 90) -> str:
        """Return an ISO expiry timestamp *days* from now."""
        return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()

    def _store(self, iocs: list) -> int:
        """Persist IOCs and update feed status."""
        count = self.db.upsert_iocs_batch(iocs)
        self.db.update_feed_status(
            self.FEED_NAME, status="active", ioc_count=count,
            feed_url=self.FEED_URL, feed_type=self.FEED_TYPE,
            tier=self.TIER, requires_api_key=self.REQUIRES_API_KEY,
            interval_minutes=self.interval,
        )
        logger.info("feed_collected", feed=self.FEED_NAME, iocs=count)
        return count

    def _record_error(self, error: str):
        """Record a collection failure."""
        self.db.update_feed_status(
            self.FEED_NAME, status="error", error=error,
            feed_url=self.FEED_URL, feed_type=self.FEED_TYPE,
            tier=self.TIER, requires_api_key=self.REQUIRES_API_KEY,
            interval_minutes=self.interval,
        )
        logger.warning("feed_collection_failed", feed=self.FEED_NAME,
                        error=error)
