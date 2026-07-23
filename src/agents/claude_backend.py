"""
LLM Backend - Unified interface for calling language models.

Supports multiple providers:
  - Anthropic (Claude) — API and CLI modes
  - OpenAI (GPT-4o, etc.) — standard and Azure endpoints
  - Ollama — local models via REST API
  - Groq — fast cloud inference

The rest of the platform doesn't care which provider is active.
It just calls: backend.call(system_prompt, user_message) → dict

Backward compatible: ``ClaudeBackend`` is an alias for ``LLMBackend``.
"""

import json
import threading
import time
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

from src.agents.llm_providers.base import BaseLLMProvider

logger = structlog.get_logger(__name__)

# Provider registry — maps config name to class
PROVIDER_REGISTRY = {}


def _load_providers():
    """Lazily load provider classes to avoid import errors for missing SDKs."""
    global PROVIDER_REGISTRY
    if PROVIDER_REGISTRY:
        return
    from src.agents.llm_providers.anthropic_provider import AnthropicProvider
    from src.agents.llm_providers.openai_provider import OpenAIProvider
    from src.agents.llm_providers.ollama_provider import OllamaProvider
    from src.agents.llm_providers.groq_provider import GroqProvider
    PROVIDER_REGISTRY.update({
        "anthropic": AnthropicProvider,
        "openai": OpenAIProvider,
        "ollama": OllamaProvider,
        "groq": GroqProvider,
    })


class LLMBackend:
    """
    Unified LLM interface with provider abstraction.

    Config structure (new):
      llm:
        provider: "anthropic"    # "anthropic", "openai", "ollama", "groq"
        model: "..."
        max_tokens: 4096
        temperature: 0.1
        rate_limit:
          cooldown_seconds: 5
        anthropic:
          mode: "auto"
          api_key: "..."
        openai:
          api_key: "..."
          model: "gpt-4o"
        ollama:
          base_url: "http://localhost:11434"
          model: "llama3.1:70b"
        groq:
          api_key: "..."
          model: "llama-3.1-70b-versatile"

    Backward-compatible with old ``claude:`` config section.
    """

    def __init__(self, config: dict, db=None):
        _load_providers()
        self._usage_db = db

        # Support both new 'llm:' and old 'claude:' config
        llm_cfg = config.get("llm") or config.get("claude", {})
        provider_name = llm_cfg.get("provider", "")

        # Backward compat: if using old 'claude:' section, default to anthropic
        if not provider_name:
            if "claude" in config and "llm" not in config:
                provider_name = "anthropic"
            else:
                provider_name = "anthropic"

        # Global settings (can be overridden per-provider)
        self.model = llm_cfg.get("model", "")
        self.max_tokens = llm_cfg.get("max_tokens", 4096)
        self.temperature = llm_cfg.get("temperature", 0.1)

        # Rate limiting. WO-H32: the dispatcher runs N triage workers against
        # this ONE backend instance, so the cooldown must be thread-safe (the
        # old unlocked read-modify-write let every worker pass at once) and
        # in-flight calls are capped by a semaphore. ``max_concurrent_calls``
        # bounds concurrent provider calls (API-mode HTTP requests, or CLI-mode
        # subprocesses — the anthropic SDK client is thread-safe; the CLI path
        # spawns one process per call). One provider per client is unchanged —
        # this only shapes HOW MANY calls hit the SAME provider at once.
        rate_cfg = llm_cfg.get("rate_limit", {})
        self.cooldown_seconds = rate_cfg.get("cooldown_seconds", 5)
        self._last_call_time = 0
        self._rate_lock = threading.Lock()
        self.max_concurrent_calls = max(
            1, int(rate_cfg.get("max_concurrent_calls", 4)))
        self._call_sem = threading.BoundedSemaphore(self.max_concurrent_calls)

        # Build provider config: merge global settings + provider-specific
        provider_cfg = llm_cfg.get(provider_name, {})
        merged_cfg = {
            "model": provider_cfg.get("model") or self.model,
            "max_tokens": provider_cfg.get("max_tokens") or self.max_tokens,
            "temperature": provider_cfg.get("temperature", self.temperature),
            **provider_cfg,
        }

        # Backward compat: old claude config has api_key at top level
        if provider_name == "anthropic" and "api_key" not in merged_cfg:
            merged_cfg["api_key"] = llm_cfg.get("api_key", "")
        if provider_name == "anthropic" and "mode" not in merged_cfg:
            merged_cfg["mode"] = llm_cfg.get("mode", "auto")
        if provider_name == "anthropic" and "cli_path" not in merged_cfg:
            merged_cfg["cli_path"] = llm_cfg.get("cli_path", "claude")

        # Instantiate provider
        cls = PROVIDER_REGISTRY.get(provider_name)
        if not cls:
            raise ValueError(
                f"Unknown LLM provider: '{provider_name}'. "
                f"Available: {list(PROVIDER_REGISTRY.keys())}")

        self.provider: BaseLLMProvider = cls(merged_cfg)
        self.mode = provider_name  # For backward compat with code checking .mode

        logger.info("llm_backend_ready",
                    provider=provider_name,
                    model=self.provider.model)

    def _rate_limit(self):
        """Enforce cooldown between calls — thread-safe (WO-H32).

        Each caller RESERVES the next start slot under the lock (slots are
        spaced ``cooldown_seconds`` apart), then sleeps outside the lock until
        its slot arrives. N concurrent workers therefore serialize call STARTS
        at the configured pace instead of all racing through the old unlocked
        check at once. ``cooldown_seconds: 0`` disables pacing entirely (full
        parallelism up to the semaphore cap)."""
        if self.cooldown_seconds <= 0:
            return
        with self._rate_lock:
            now = time.time()
            slot = max(now, self._last_call_time + self.cooldown_seconds)
            self._last_call_time = slot
        wait = slot - now
        if wait > 0:
            time.sleep(wait)

    def _track(self, request_type, input_len, output_len, latency,
               success, error_type=None):
        """Record usage metrics if DB is available.

        WO-H50: prefer the provider's REAL token counts (``last_usage``, set by
        the API/CLI path) over the character-length estimate. When real usage is
        present the row is recorded exactly and flagged ``estimated=False``;
        otherwise it falls back to the ``chars//4`` estimate flagged
        ``estimated=True`` so real and guessed usage are never conflated.
        """
        if not self._usage_db:
            return
        try:
            from src.agents.llm_providers.multi_provider import ProviderUsageTracker
            from src.database.store import _tenant_ctx
            tid = _tenant_ctx.get() or "default"
            usage = getattr(self.provider, "last_usage", None) if success else None
            tracker = ProviderUsageTracker(tid, self._usage_db)
            tracker.track_usage(
                provider=self.mode, model=self.provider.model,
                request_type=request_type,
                input_length=input_len, output_length=output_len,
                latency=latency, success=success, error_type=error_type,
                real_usage=usage)
        except Exception as e:
            logger.debug("usage_track_failed", error=str(e))

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=30),
           before_sleep=lambda rs: logger.warning(
               "llm_call_retry",
               attempt=rs.attempt_number,
               error=str(rs.outcome.exception()) if rs.outcome else "unknown"))
    def call(self, system_prompt: str, user_message: str,
             request_type: str = "triage") -> dict:
        """
        Call the LLM and return parsed JSON response.
        Works identically regardless of which provider is active.
        request_type accepted for compatibility with MultiProviderLLMBackend.
        """
        self._rate_limit()
        input_len = len(system_prompt) + len(user_message)
        t0 = time.time()
        try:
            # WO-H32: cap concurrent in-flight provider calls (the prompt was
            # already built + anonymized by the caller — this gates transport
            # only, never touches content).
            with self._call_sem:
                raw_text = self.provider.call_text(system_prompt, user_message)
            self._track(request_type, input_len, len(raw_text),
                        time.time() - t0, True)
            return self._parse_json_response(raw_text)
        except Exception as e:
            self._track(request_type, input_len, 0,
                        time.time() - t0, False, type(e).__name__)
            raise

    def call_raw(self, system_prompt: str, user_message: str,
                 request_type: str = "raw") -> str:
        """Call the LLM and return raw text (no JSON parsing)."""
        self._rate_limit()
        input_len = len(system_prompt) + len(user_message)
        t0 = time.time()
        try:
            with self._call_sem:  # WO-H32: transport-level concurrency cap
                raw_text = self.provider.call_text(system_prompt, user_message)
            self._track(request_type, input_len, len(raw_text),
                        time.time() - t0, True)
            return raw_text
        except Exception as e:
            self._track(request_type, input_len, 0,
                        time.time() - t0, False, type(e).__name__)
            raise

    def get_info(self) -> dict:
        """Return backend info for admin/health display."""
        return self.provider.get_info()

    def describe_model(self) -> str:
        """Resolved concrete ``provider/model`` id of the backend that runs a
        call (WO-H29 finding NEW-3).

        Persisted per-decision on ``decision_audit_trail.model_backend`` so a
        silent provider/model swap is attributable to the verdicts it produced —
        the same ``(provider, model)`` pair recorded in ``llm_usage_metrics``.
        Falls back to the provider name alone if the model string is empty.
        """
        provider = getattr(self, "mode", "") or "unknown"
        model = getattr(getattr(self, "provider", None), "model", "") or ""
        return f"{provider}/{model}" if model else provider

    # ─── Response Parsing (shared across all providers) ──────────────

    def _parse_json_response(self, raw_text: str) -> dict:
        """Parse JSON from LLM response, handling markdown fences."""
        json_text = raw_text.strip()

        # Strip markdown code fences
        if json_text.startswith("```"):
            json_text = json_text.split("\n", 1)[1] if "\n" in json_text else json_text[3:]
        if json_text.endswith("```"):
            json_text = json_text[:-3]
        json_text = json_text.strip()

        try:
            return json.loads(json_text)
        except json.JSONDecodeError as e:
            logger.warning("json_parse_first_attempt_failed", error=str(e))

            extracted = self._extract_json_object(raw_text)
            if extracted is not None:
                return extracted

            extracted = self._extract_json_array(raw_text)
            if extracted is not None:
                return extracted

            stripped = raw_text.rstrip()
            looks_truncated = (
                len(stripped) > 0
                and stripped[-1] not in ('}', ']', '"')
            )
            logger.error("json_parse_all_attempts_failed",
                         raw_length=len(raw_text),
                         raw_preview=raw_text[:500],
                         raw_tail=raw_text[-200:] if raw_text else "",
                         looks_truncated=looks_truncated,
                         hint=("response likely hit max_tokens — increase "
                               "llm.max_tokens in config")
                              if looks_truncated else "")
            raise ValueError(
                f"Could not parse JSON from LLM response (len={len(raw_text)}, "
                f"truncated={looks_truncated}): {raw_text[:200]}")

    @staticmethod
    def _extract_json_object(text: str):
        """Extract the first complete JSON object using balanced brace counting."""
        start = text.find('{')
        if start == -1:
            return None
        depth = 0
        in_string = False
        escape = False
        for i in range(start, len(text)):
            c = text[i]
            if escape:
                escape = False
                continue
            if c == '\\' and in_string:
                escape = True
                continue
            if c == '"' and not escape:
                in_string = not in_string
                continue
            if in_string:
                continue
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        return None
        return None

    @staticmethod
    def _extract_json_array(text: str):
        """Extract the first complete JSON array using balanced bracket counting."""
        start = text.find('[')
        if start == -1:
            return None
        depth = 0
        in_string = False
        escape = False
        for i in range(start, len(text)):
            c = text[i]
            if escape:
                escape = False
                continue
            if c == '\\' and in_string:
                escape = True
                continue
            if c == '"' and not escape:
                in_string = not in_string
                continue
            if in_string:
                continue
            if c == '[':
                depth += 1
            elif c == ']':
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        return None
        return None


# Backward-compatible alias
ClaudeBackend = LLMBackend
