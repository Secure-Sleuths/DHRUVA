"""Centralized IP classification for active-response blocking decisions.

Single source of truth for "is this IP safe to block?" — used by BOTH the
auto-block gate (``src/soar/auto_block_gate.py``) and the manual block path
(``src/api/routes/response.py``). Do NOT add a third copy of this logic.

An IP is *blockable* only when it is a real, public/external address that we
are willing to firewall-drop: never an internal/private/reserved address, and
never an address (or CIDR) on the tenant's ``never_block_allowlist``.

Fail-closed: any missing/null/malformed input returns ``False`` (NOT blockable)
rather than raising — the caller treats "not blockable" as DENY.
"""

from __future__ import annotations

import ipaddress
import structlog

logger = structlog.get_logger(__name__)

# Private/reserved networks (IPv4 + IPv6). Mirrors the set used by the TI
# enricher (_PRIVATE_NETWORKS) — kept here as the canonical block-safety list.
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT / shared address space
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("::/128"),           # IPv6 unspecified
]


def is_private_or_reserved_ip(ip: str) -> bool:
    """True if ``ip`` is private/reserved/loopback/etc. (IPv4 + IPv6).

    Fail-closed: a missing/null/malformed value is treated as "private"
    (i.e. NOT a public address) so it can never be auto-blocked.
    """
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except (ValueError, TypeError):
        return True  # malformed -> treat as non-public, never blockable
    if addr.is_private or addr.is_loopback or addr.is_link_local \
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return True
    return any(addr in net for net in _PRIVATE_NETWORKS)


def _ip_in_allowlist(addr, allowlist) -> bool:
    """True if ``addr`` matches any entry (IP or CIDR) in ``allowlist``."""
    if not allowlist:
        return False
    if not isinstance(allowlist, (list, tuple, set)):
        # Malformed allowlist -> fail closed: behave as if everything matched
        # so the caller refuses to block.
        return True
    for entry in allowlist:
        if entry is None:
            continue
        try:
            net = ipaddress.ip_network(str(entry).strip(), strict=False)
        except (ValueError, TypeError):
            # A malformed allowlist entry must not silently weaken protection.
            # Treat an unparseable entry as a match -> refuse to block.
            logger.warning("never_block_allowlist_entry_malformed", entry=entry)
            return True
        try:
            if addr.version == net.version and addr in net:
                return True
        except (ValueError, TypeError):
            continue
    return False


def is_blockable_external_ip(ip: str, allowlist=None) -> bool:
    """True only if ``ip`` is a public/external IP that is safe to block.

    An IP is blockable when ALL hold:
      * it parses as a valid IP address (IPv4 or IPv6),
      * it is NOT private/reserved/loopback/link-local/etc.,
      * it is NOT covered by any entry in ``allowlist`` (IP or CIDR, version-aware).

    Fail-closed: any missing/null/malformed IP, or a malformed allowlist /
    allowlist entry, returns ``False`` (NOT blockable). Never raises.
    """
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except (ValueError, TypeError):
        return False
    if is_private_or_reserved_ip(ip):
        return False
    if _ip_in_allowlist(addr, allowlist):
        return False
    return True
