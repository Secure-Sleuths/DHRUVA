"""OpenAI LLM provider (GPT-4o, GPT-4-turbo, etc.)

Also works with Azure OpenAI via custom base_url.
"""

import structlog

from .base import BaseLLMProvider

logger = structlog.get_logger(__name__)


class OpenAIProvider(BaseLLMProvider):
    """OpenAI ChatCompletion API provider.

    Uses ``response_format={"type": "json_object"}`` when available
    for reliable structured output.
    """

    PROVIDER_NAME = "openai"

    def __init__(self, config: dict):
        super().__init__(config)
        if not self.model:
            self.model = config.get("model", "gpt-4o")

        api_key = config.get("api_key", "")
        base_url = config.get("base_url", "") or None

        try:
            import openai
            kwargs = {"api_key": api_key}
            if base_url:
                kwargs["base_url"] = base_url
            # Retries and timeout are set EXPLICITLY rather than left to the
            # SDK defaults (2 retries, a 10-minute timeout).
            #
            # A self-hosted or proxied OpenAI-compatible endpoint throttles
            # differently from api.openai.com: upstream capacity pressure
            # surfaces as 5xx rather than 429. Observed against a client's
            # endpoint on 2026-08-12 — 11 "Internal Server Error" and 8
            # "Upstream temporarily unavailable — circuit breaker open" across
            # 192 calls (6% failure), all of them transient.
            #
            # The 10-minute default is the dangerous half. With
            # `llm.rate_limit.max_concurrent_calls` at 2, two calls parked on a
            # throttled upstream stall triage entirely for ten minutes while
            # the platform reports itself healthy.
            kwargs["max_retries"] = int(config.get("max_retries", 5))
            kwargs["timeout"] = float(config.get("timeout_seconds", 120))
            self.client = openai.OpenAI(**kwargs)
            logger.info("openai_provider_ready",
                        model=self.model,
                        base_url=base_url or "default",
                        max_retries=kwargs["max_retries"],
                        timeout_s=kwargs["timeout"])
        except ImportError:
            logger.error("openai_sdk_not_installed",
                         hint="pip install openai")
            raise

    # Upstream states that are worth waiting out rather than failing on. The
    # SDK already retries these by status code; this second layer exists
    # because a proxy in front of the model can surface a transient upstream
    # as a body string on an otherwise-successful-looking error, and because
    # the SDK's retry budget is exhausted quickly under sustained throttling.
    _TRANSIENT_MARKERS = (
        "circuit breaker",          # proxy shed load; upstream is fine
        "temporarily unavailable",
        "internal server error",
        "bad gateway",
        "service unavailable",
        "gateway timeout",
        "overloaded",
        "timed out",
        "timeout",
    )
    _TRANSIENT_STATUSES = {500, 502, 503, 504, 408, 429}

    @classmethod
    def _is_transient(cls, exc: Exception) -> bool:
        status = getattr(exc, "status_code", None)
        if isinstance(status, int) and status in cls._TRANSIENT_STATUSES:
            return True
        text = str(exc).lower()
        return any(m in text for m in cls._TRANSIENT_MARKERS)

    def call_text(self, system_prompt: str, user_message: str) -> str:
        # Retry with exponential backoff and jitter ON TOP of the SDK's own
        # retries. Throttling on a shared endpoint is bursty: the SDK's budget
        # can be spent inside a single congestion window, and returning a hard
        # failure then turns a recoverable pause into a lost alert — the triage
        # agent fails closed, writes needs_investigation, and escalates.
        #
        # Jitter matters because the platform runs several workers against ONE
        # endpoint. Without it they retry in lockstep and re-create the burst
        # they are backing off from.
        import random
        import time

        attempts = int((self.config or {}).get("retry_attempts", 4))
        base_delay = 2.0
        last_exc = None

        for attempt in range(1, attempts + 1):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    temperature=self.temperature,
                    response_format={"type": "json_object"},
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message},
                    ],
                )
                if attempt > 1:
                    logger.info("openai_call_recovered_after_retry",
                                attempt=attempt)
                break
            except Exception as e:
                last_exc = e
                transient = self._is_transient(e)
                if not transient or attempt == attempts:
                    logger.error("openai_api_call_failed",
                                 error=str(e)[:300], attempt=attempt,
                                 transient=transient)
                    raise RuntimeError(f"OpenAI API call failed: {e}") from e
                delay = base_delay * (2 ** (attempt - 1))
                delay = min(delay, 30.0) * (0.5 + random.random())
                logger.warning("openai_call_retrying",
                               attempt=attempt, of=attempts,
                               sleep_s=round(delay, 1),
                               error=str(e)[:200],
                               detail="transient upstream state — retrying "
                                      "rather than failing the alert closed")
                time.sleep(delay)
        else:                                    # pragma: no cover - defensive
            raise RuntimeError(f"OpenAI API call failed: {last_exc}")

        if not response.choices:
            raise RuntimeError("OpenAI returned empty choices array")

        raw_text = response.choices[0].message.content or ""
        usage = response.usage
        if usage:
            logger.debug("openai_tokens",
                         input=usage.prompt_tokens,
                         output=usage.completion_tokens)
        return raw_text
