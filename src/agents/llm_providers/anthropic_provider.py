"""Anthropic (Claude) LLM provider — API and CLI modes."""

import os
import subprocess
import structlog

from .base import BaseLLMProvider

logger = structlog.get_logger(__name__)


class AnthropicProvider(BaseLLMProvider):
    """Claude via Anthropic API or Claude CLI.

    Sub-modes:
      - ``api``  — uses the ``anthropic`` Python SDK (needs API key)
      - ``cli``  — uses the ``claude`` CLI binary (Max subscription)
      - ``auto`` — detects: API key present → api, otherwise → cli
    """

    PROVIDER_NAME = "anthropic"

    def __init__(self, config: dict):
        super().__init__(config)
        self.sub_mode = config.get("mode", "auto")

        if not self.model:
            self.model = config.get("model", "claude-sonnet-4-20250514")

        # Auto-detect sub-mode
        if self.sub_mode == "auto":
            api_key = config.get("api_key", "")
            if api_key and not api_key.startswith("${"):
                self.sub_mode = "api"
            else:
                self.sub_mode = "cli"
            logger.info("anthropic_mode_detected", mode=self.sub_mode)

        if self.sub_mode == "api":
            self._init_api(config)
        else:
            self._init_cli(config)

    def _init_api(self, cfg: dict):
        try:
            import anthropic
            self.client = anthropic.Anthropic(
                api_key=cfg.get("api_key", ""))
            logger.info("anthropic_api_ready", model=self.model)
        except ImportError:
            logger.error("anthropic_sdk_not_installed",
                         hint="pip install anthropic")
            raise

    def _init_cli(self, cfg: dict):
        self.cli_path = cfg.get("cli_path", "claude")
        try:
            result = subprocess.run(
                [self.cli_path, "--version"],
                capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.info("anthropic_cli_ready",
                            version=result.stdout.strip(),
                            path=self.cli_path)
            else:
                logger.warning("anthropic_cli_version_check_failed",
                               stderr=result.stderr[:200])
        except FileNotFoundError:
            logger.error("anthropic_cli_not_found", path=self.cli_path,
                         hint="Install: npm install -g @anthropic-ai/claude-code")
            raise
        except Exception as e:
            logger.warning("anthropic_cli_check_error", error=str(e))

    def call_text(self, system_prompt: str, user_message: str) -> str:
        if self.sub_mode == "api":
            return self._call_api(system_prompt, user_message)
        return self._call_cli(system_prompt, user_message)

    def _call_api(self, system_prompt: str, user_message: str) -> str:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        raw_text = response.content[0].text
        usage = response.usage
        logger.debug("anthropic_api_tokens",
                     input=usage.input_tokens,
                     output=usage.output_tokens)
        return raw_text

    def _call_cli(self, system_prompt: str, user_message: str) -> str:
        combined_prompt = f"""<system>
{system_prompt}
</system>

<user_message>
{user_message}
</user_message>

Respond ONLY with the JSON object as specified in the system prompt. No other text."""

        result = subprocess.run(
            [self.cli_path, "-p", combined_prompt,
             "--output-format", "text"],
            capture_output=True, text=True, timeout=120,
            env={**os.environ},
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip()[:500]
            logger.error("anthropic_cli_failed",
                         returncode=result.returncode, stderr=error_msg)
            raise RuntimeError(f"Claude CLI failed: {error_msg}")

        raw_text = result.stdout.strip()
        if not raw_text:
            raise RuntimeError("Claude CLI returned empty response")

        logger.debug("anthropic_cli_completed",
                     response_length=len(raw_text))
        return raw_text

    def get_info(self) -> dict:
        info = super().get_info()
        info["sub_mode"] = self.sub_mode
        return info
