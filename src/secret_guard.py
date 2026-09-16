"""Shared guards for secrets that must never be used in a weak or unresolved form.

WO-S1. Two unauthenticated HTTP routes exist on the platform — the Wazuh alert
ingest webhook (``/api/v1/webhooks/wazuh/alerts``) and the inbound ticket
webhook (``/api/webhooks/tickets/{provider}``). Both are excluded from JWT auth
and from ``TenantContextMiddleware``, so an HMAC signature over the request body
is their ONLY authentication control.

Both read their HMAC key straight from config and guard it with nothing but
``if not secret``. That guard is insufficient because the key is frequently a
non-empty string that is not a secret at all:

  * ``main.py::_resolve_env_vars`` does ``os.environ.get(env_key, obj)`` — when
    the referenced variable is unset it leaves the LITERAL ``"${JIRA_WEBHOOK_SECRET}"``
    in the config. That string is published in this repository's own
    ``config/config.yaml``.
  * ``src/setup/deployment_wizard.py`` persists the literal
    ``"${TENANT_<ID>_WEBHOOK_SECRET}"`` into the tenant record, and no code path
    ever ``${VAR}``-resolves a DB-loaded tenant config.

In both cases the HMAC key is a publicly-known constant, so any remote party can
compute a valid signature. These helpers make that fail closed at the point of
use, independently of fixing the code that produces the bad value (WO-S8).

The ``${VAR}`` test matches the existing guards at
``src/enrichment/threat_intel/feeds/misp.py::_unresolved`` and
``src/agents/llm_providers/anthropic_provider.py``.
"""

import structlog

logger = structlog.get_logger(__name__)

# An HMAC key shorter than this cannot carry meaningful entropy. The wizard and
# deploy.sh both generate `secrets.token_urlsafe(32)` (43 chars), so this floor
# rejects only values that were never real secrets.
MIN_SECRET_LENGTH = 16


def is_unresolved_placeholder(value) -> bool:
    """True if ``value`` is a literal, unsubstituted ``${ENV_VAR}`` placeholder."""
    return (isinstance(value, str)
            and value.startswith("${")
            and value.endswith("}"))


def secret_rejection_reason(value) -> str | None:
    """Return why ``value`` is unusable as an HMAC key, or None if it is usable.

    Never returns the secret itself, and never returns a reason that would let a
    caller distinguish "wrong secret" from "no secret" — callers should map every
    rejection onto one identical response.
    """
    if not value or not isinstance(value, str):
        return "missing"
    if is_unresolved_placeholder(value):
        return "unresolved_placeholder"
    if len(value) < MIN_SECRET_LENGTH:
        return "too_short"
    return None


def assert_usable_secret(value, *, context: str, **log_fields) -> str | None:
    """Validate an HMAC key, logging a CRITICAL misconfiguration on rejection.

    Returns the rejection reason (truthy) when the secret must NOT be used, or
    ``None`` when it is usable. Logs at CRITICAL because a rejected secret means
    an unauthenticated route is currently misconfigured — the operator needs to
    see it, and the request that triggered it is being refused.

    The placeholder VALUE is logged (it is a config key name, not a secret) so
    the operator can see exactly which environment variable to set. A short or
    missing secret is never logged.
    """
    reason = secret_rejection_reason(value)
    if reason is None:
        return None

    logger.critical(
        "webhook_secret_unusable",
        context=context,
        reason=reason,
        placeholder=value if reason == "unresolved_placeholder" else None,
        detail=(
            "The HMAC secret for an UNAUTHENTICATED webhook route is not a "
            "usable secret. Requests are being refused. An unresolved ${VAR} "
            "placeholder is a publicly-known constant — any remote party could "
            "otherwise forge a valid signature."
        ),
        remediation=(
            "Set the referenced environment variable (and restart), or store a "
            "real generated secret in the tenant/provider config. Generate one "
            "with: python3 -c 'import secrets; print(secrets.token_urlsafe(32))'"
        ),
        **log_fields,
    )
    return reason
