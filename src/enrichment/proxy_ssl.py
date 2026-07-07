"""Shared dashboard-proxy TLS-verification policy.

Both alert-fetch paths that talk to a Wazuh Dashboard (OSD) console proxy must
apply the SAME verify_ssl policy so they can never diverge:

  * default True (verification ON);
  * an explicit ``verify_ssl: false`` is honored ONLY under DEV_MODE;
  * outside DEV_MODE, an explicit false is forced back to True with a loud
    ``dashboard_proxy_verify_ssl_forced_true`` warning;
  * when verification is genuinely off (DEV_MODE opt-out in effect), emit a
    per-call ``dashboard_proxy_verify_ssl_disabled`` warning — every call, not
    once at construction.

The return value is what ``requests``' ``verify=`` expects: ``True``,
``False``, or a path to a CA bundle (string) for self-signed certs.
"""

import os as _os

import structlog

logger = structlog.get_logger()


def resolve_proxy_verify_ssl(proxy_cfg: dict):
    """Resolve the effective ``verify=`` value for a dashboard-proxy request.

    Args:
        proxy_cfg: the tenant's ``dashboard_proxy`` config block.

    Returns:
        ``True``, ``False``, or a CA-bundle path string.
    """
    base_url = (proxy_cfg.get("url") or "").rstrip("/")
    _dev_mode = _os.environ.get("DEV_MODE", "").lower() in ("1", "true", "yes")
    verify_ssl = proxy_cfg.get("verify_ssl", True)

    # Outside DEV_MODE an explicit false is forced back to True.
    if not verify_ssl and not _dev_mode:
        logger.warning("dashboard_proxy_verify_ssl_forced_true",
                       msg="Dashboard proxy verify_ssl=false outside DEV_MODE — "
                           "defaulting to true. Set DEV_MODE=true to disable.",
                       url=base_url)
        verify_ssl = True

    # Loud per-call opt-out: warn on EVERY call when verification is genuinely
    # off (DEV_MODE opt-out in effect), not once at construction.
    if not verify_ssl:
        logger.warning("dashboard_proxy_verify_ssl_disabled",
                       msg="Dashboard proxy TLS verification is DISABLED "
                           "(DEV_MODE opt-out). Traffic is not verified.",
                       url=base_url)

    return verify_ssl
