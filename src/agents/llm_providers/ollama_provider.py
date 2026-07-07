"""Ollama LLM provider — local models via REST API.

Zero SDK dependencies — uses ``requests`` (already a project dependency).
"""

import requests
import structlog

from .base import BaseLLMProvider

logger = structlog.get_logger(__name__)


class OllamaProvider(BaseLLMProvider):
    """Ollama REST API provider for local LLMs.

    Talks to Ollama at ``base_url`` (default ``http://localhost:11434``).
    Supports any model available in the local Ollama instance
    (Llama 3.1, Mistral, Mixtral, Phi, Gemma, etc.).
    """

    PROVIDER_NAME = "ollama"

    def __init__(self, config: dict):
        super().__init__(config)
        self.base_url = config.get(
            "base_url", "http://localhost:11434").rstrip("/")
        if not self.model:
            self.model = config.get("model", "llama3.1:70b")

        # Verify Ollama is reachable
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if resp.status_code == 200:
                models = [m["name"] for m in resp.json().get("models", [])]
                logger.info("ollama_provider_ready",
                            model=self.model,
                            available_models=models[:10])
            else:
                logger.warning("ollama_api_check_failed",
                               status=resp.status_code)
        except requests.ConnectionError:
            logger.warning("ollama_not_reachable",
                           url=self.base_url,
                           hint="Start Ollama: ollama serve")
        except Exception as e:
            logger.warning("ollama_check_error", error=str(e))

    def call_text(self, system_prompt: str, user_message: str) -> str:
        url = f"{self.base_url}/api/chat"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens,
            },
        }

        resp = requests.post(url, json=payload, timeout=300)
        resp.raise_for_status()
        data = resp.json()

        raw_text = data.get("message", {}).get("content", "")
        if not raw_text:
            raise RuntimeError("Ollama returned empty response")

        # Log token usage if available
        eval_count = data.get("eval_count", 0)
        prompt_count = data.get("prompt_eval_count", 0)
        if eval_count:
            logger.debug("ollama_tokens",
                         input=prompt_count, output=eval_count)

        return raw_text

    def get_info(self) -> dict:
        info = super().get_info()
        info["base_url"] = self.base_url
        return info
