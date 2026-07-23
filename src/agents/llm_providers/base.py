"""Abstract base class for LLM providers."""

import structlog

logger = structlog.get_logger(__name__)


class BaseLLMProvider:
    """Abstract LLM provider interface.

    Each provider implements ``call_text()`` which takes a system prompt
    and user message and returns raw text.  JSON parsing, retry logic,
    and rate limiting are handled by the shared ``LLMBackend`` wrapper.
    """

    PROVIDER_NAME: str = ""

    def __init__(self, config: dict):
        self.config = config
        self.model = config.get("model", "")
        # Default raised from 4096 to 8192 in v4.8.5 — the 4096 cap was
        # truncating responses on detection-rule synthesis and large-incident
        # summarization paths, producing unparseable JSON
        # (json_parse_all_attempts_failed). Override per-call by setting
        # llm.max_tokens in config.yaml or per-tenant LLM config.
        self.max_tokens = config.get("max_tokens", 8192)
        self.temperature = config.get("temperature", 0.1)
        # WO-H50: real usage from the most recent call_text(), when the provider
        # can obtain it. Shape: {"input_tokens": int, "output_tokens": int,
        # "cost_usd": float|None, "estimated": bool}. None until the first call,
        # or when a provider cannot report usage (LLMBackend then falls back to
        # a character-length estimate and flags the row estimated). Non-breaking:
        # call_text() still returns a plain str; this is read out-of-band.
        self.last_usage: dict | None = None

    def call_text(self, system_prompt: str, user_message: str) -> str:
        """Send a prompt to the LLM and return raw text response.

        This is the ONLY method providers must implement.
        """
        raise NotImplementedError

    def get_info(self) -> dict:
        """Return provider info for health checks and admin display."""
        return {
            "provider": self.PROVIDER_NAME,
            "model": self.model,
            "max_tokens": self.max_tokens,
        }
