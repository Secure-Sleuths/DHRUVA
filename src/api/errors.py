"""Shared API error helpers.

Centralizes the "log full detail server-side, return a generic body to the
client" pattern so internal exception text, stack traces, and internal paths
never leak in 5xx responses (M2 item 4).
"""

import structlog
from fastapi import HTTPException

logger = structlog.get_logger(__name__)

_GENERIC_5XX_DETAIL = "Internal server error"


def internal_error(exc: Exception, *, context: str,
                   status_code: int = 500, **log_fields) -> HTTPException:
    """Log a full exception server-side and return a generic HTTPException.

    Usage::

        except Exception as e:
            raise internal_error(e, context="generate_usage_report",
                                 tenant_id=tenant_id)

    The full exception is logged via structlog under the ``api_internal_error``
    event (with ``context`` and any extra bound fields). The returned
    HTTPException carries only a generic body — no exception text reaches the
    client.
    """
    logger.error("api_internal_error", context=context,
                 error=str(exc), error_type=type(exc).__name__, **log_fields)
    return HTTPException(status_code=status_code, detail=_GENERIC_5XX_DETAIL)
