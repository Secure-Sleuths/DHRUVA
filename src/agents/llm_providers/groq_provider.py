"""Groq LLM provider — fast cloud inference.

Uses the OpenAI-compatible API with Groq's base URL.
Requires ``openai`` SDK (same as OpenAI provider).
"""

import structlog

from .base import BaseLLMProvider

logger = structlog.get_logger(__name__)

GROQ_BASE_URL = "https://api.groq.com/openai/v1"


class GroqProvider(BaseLLMProvider):
    """Groq cloud inference provider.

    OpenAI-compatible API — uses the ``openai`` SDK pointed at
    Groq's endpoint. Supports Llama, Mixtral, Gemma models.
    """

    PROVIDER_NAME = "groq"

    def __init__(self, config: dict):
        super().__init__(config)
        if not self.model:
            self.model = config.get("model", "llama-3.1-70b-versatile")

        api_key = config.get("api_key", "")
        base_url = config.get("base_url", GROQ_BASE_URL)

        try:
            import openai
            self.client = openai.OpenAI(
                api_key=api_key, base_url=base_url)
            logger.info("groq_provider_ready", model=self.model)
        except ImportError:
            logger.error("openai_sdk_not_installed",
                         hint="pip install openai (required for Groq)")
            raise

    def call_text(self, system_prompt: str, user_message: str) -> str:
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
        except Exception as e:
            logger.error("groq_api_call_failed", error=str(e))
            raise RuntimeError(f"Groq API call failed: {e}") from e

        if not response.choices:
            raise RuntimeError("Groq returned empty choices array")

        raw_text = response.choices[0].message.content or ""
        usage = response.usage
        if usage:
            logger.debug("groq_tokens",
                         input=usage.prompt_tokens,
                         output=usage.completion_tokens)
        return raw_text
