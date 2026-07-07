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
            self.client = openai.OpenAI(**kwargs)
            logger.info("openai_provider_ready",
                        model=self.model,
                        base_url=base_url or "default")
        except ImportError:
            logger.error("openai_sdk_not_installed",
                         hint="pip install openai")
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
            logger.error("openai_api_call_failed", error=str(e))
            raise RuntimeError(f"OpenAI API call failed: {e}") from e

        if not response.choices:
            raise RuntimeError("OpenAI returned empty choices array")

        raw_text = response.choices[0].message.content or ""
        usage = response.usage
        if usage:
            logger.debug("openai_tokens",
                         input=usage.prompt_tokens,
                         output=usage.completion_tokens)
        return raw_text
