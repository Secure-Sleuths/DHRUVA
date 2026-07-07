"""
Multi-Provider LLM Backend with Failover Support

Provides tenant-aware LLM provider routing with automatic failover, circuit breaker
patterns, usage tracking, and cost calculation.
"""

import json
import time
import structlog
from datetime import datetime, timezone
from typing import Optional, Dict, List
from tenacity import retry, stop_after_attempt, wait_exponential

from .base import BaseLLMProvider
from src.agents.claude_backend import PROVIDER_REGISTRY, _load_providers

logger = structlog.get_logger(__name__)


class CircuitBreaker:
    """Circuit breaker for provider failures."""

    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 300):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = 0
        self.state = "closed"  # closed, open, half_open

    def can_call(self) -> bool:
        """Check if provider can be called."""
        if self.state == "closed":
            return True
        elif self.state == "open":
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = "half_open"
                return True
            return False
        else:  # half_open
            return True

    def record_success(self):
        """Record successful call."""
        self.failure_count = 0
        self.state = "closed"

    def record_failure(self):
        """Record failed call."""
        self.failure_count += 1
        self.last_failure_time = time.time()

        if self.failure_count >= self.failure_threshold:
            self.state = "open"
            logger.warning("circuit_breaker_opened",
                          failures=self.failure_count)


class ProviderUsageTracker:
    """Track usage metrics per tenant and provider."""

    def __init__(self, tenant_id: str, db):
        self.tenant_id = tenant_id
        self.db = db

    def track_usage(self, provider: str, model: str, request_type: str,
                   input_length: int, output_length: int, latency: float,
                   success: bool, error_type: Optional[str] = None,
                   cost_usd: Optional[float] = None):
        """Record usage metrics to dedicated llm_usage_metrics table."""
        try:
            import uuid
            from datetime import datetime, timezone

            usage_record = {
                "id": str(uuid.uuid4()),
                "tenant_id": self.tenant_id,
                "provider": provider,
                "model": model,
                "request_type": request_type,
                "tokens_input": self._estimate_tokens(input_length),
                "tokens_output": self._estimate_tokens(output_length),
                "cost_usd": cost_usd or self._estimate_cost(provider, model, input_length, output_length),
                "latency_ms": int(latency * 1000),
                "success": success,
                "error_type": error_type,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "client_id": self.tenant_id  # For backward compatibility
            }

            # Store in dedicated llm_usage_metrics table
            conn = self.db._get_conn()
            conn.execute("""
                INSERT INTO llm_usage_metrics (
                    id, tenant_id, provider, model, request_type,
                    tokens_input, tokens_output, cost_usd, latency_ms,
                    success, error_type, created_at, client_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                usage_record["id"],
                usage_record["tenant_id"],
                usage_record["provider"],
                usage_record["model"],
                usage_record["request_type"],
                usage_record["tokens_input"],
                usage_record["tokens_output"],
                usage_record["cost_usd"],
                usage_record["latency_ms"],
                usage_record["success"],
                usage_record["error_type"],
                usage_record["created_at"],
                usage_record["client_id"]
            ))
            conn.commit()

            logger.debug("llm_usage_tracked",
                        tenant=self.tenant_id,
                        provider=provider,
                        tokens_total=usage_record["tokens_input"] + usage_record["tokens_output"],
                        cost=usage_record["cost_usd"],
                        success=success)
        except Exception as e:
            logger.error("usage_tracking_failed", error=str(e))

    def _estimate_tokens(self, text_length: int) -> int:
        """Rough token estimation (4 chars per token average)."""
        return max(1, text_length // 4)

    def _estimate_cost(self, provider: str, model: str, input_length: int, output_length: int) -> float:
        """Rough cost estimation based on provider pricing."""
        input_tokens = self._estimate_tokens(input_length)
        output_tokens = self._estimate_tokens(output_length)

        # Rough pricing per 1K tokens (as of 2024)
        pricing = {
            "anthropic": {
                "claude-sonnet-4": {"input": 0.003, "output": 0.015},
                "claude-haiku-4": {"input": 0.00025, "output": 0.00125}
            },
            "openai": {
                "gpt-4o": {"input": 0.005, "output": 0.015},
                "gpt-4o-mini": {"input": 0.00015, "output": 0.0006}
            },
            "groq": {
                "llama-3.1-70b-versatile": {"input": 0.00059, "output": 0.00079}
            }
        }

        provider_pricing = pricing.get(provider, {})
        model_pricing = provider_pricing.get(model, {"input": 0.001, "output": 0.001})

        input_cost = (input_tokens / 1000) * model_pricing["input"]
        output_cost = (output_tokens / 1000) * model_pricing["output"]

        return round(input_cost + output_cost, 6)


class MultiProviderLLMBackend:
    """Multi-provider LLM backend with failover and usage tracking."""

    def __init__(self, tenant_id: str, llm_config: dict, db):
        _load_providers()

        self.tenant_id = tenant_id
        self.db = db
        self.usage_tracker = ProviderUsageTracker(tenant_id, db)

        # Parse configuration
        self.primary_provider = llm_config.get("primary_provider") or llm_config.get("provider", "anthropic")
        self.fallback_providers = llm_config.get("fallback_providers", [])
        self.provider_configs = llm_config.get("providers", {})

        # Backward compatibility with old config format
        if not self.provider_configs and llm_config.get("api_key"):
            self.provider_configs = {
                self.primary_provider: llm_config
            }

        # Initialize providers and circuit breakers
        self.providers: Dict[str, BaseLLMProvider] = {}
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}

        # Global rate limiting
        rate_cfg = llm_config.get("rate_limit", {})
        self.cooldown_seconds = rate_cfg.get("cooldown_seconds", 1)
        self._last_call_time = 0

        logger.info("multi_provider_backend_initialized",
                   tenant_id=tenant_id,
                   primary=self.primary_provider,
                   fallbacks=self.fallback_providers)

    def _get_or_create_provider(self, provider_name: str) -> Optional[BaseLLMProvider]:
        """Get or create a provider instance with circuit breaker."""
        if provider_name in self.providers:
            return self.providers[provider_name]

        provider_config = self.provider_configs.get(provider_name, {})
        if not provider_config:
            logger.warning("no_config_for_provider",
                          provider=provider_name, tenant=self.tenant_id)
            return None

        try:
            cls = PROVIDER_REGISTRY.get(provider_name)
            if not cls:
                logger.error("unknown_provider", provider=provider_name)
                return None

            provider = cls(provider_config)
            self.providers[provider_name] = provider
            self.circuit_breakers[provider_name] = CircuitBreaker()

            logger.info("provider_initialized",
                       provider=provider_name,
                       tenant=self.tenant_id,
                       model=provider.model)
            return provider
        except Exception as e:
            logger.error("provider_initialization_failed",
                        provider=provider_name,
                        tenant=self.tenant_id,
                        error=str(e))
            return None

    def _rate_limit(self):
        """Enforce cooldown between calls."""
        elapsed = time.time() - self._last_call_time
        if elapsed < self.cooldown_seconds:
            time.sleep(self.cooldown_seconds - elapsed)
        self._last_call_time = time.time()

    def get_primary_provider(self) -> str:
        """Get the primary provider name."""
        return self.primary_provider

    def call(self, system_prompt: str, user_message: str, request_type: str = "triage") -> dict:
        """
        Call LLM with failover support and usage tracking.

        Args:
            system_prompt: System prompt for the LLM
            user_message: User message
            request_type: Type of request for usage tracking (triage, detection, hunt, query)

        Returns:
            Parsed JSON response from the LLM
        """
        self._rate_limit()

        # Try primary provider first
        providers_to_try = [self.primary_provider] + self.fallback_providers

        for provider_name in providers_to_try:
            circuit_breaker = self.circuit_breakers.get(provider_name)
            if circuit_breaker and not circuit_breaker.can_call():
                logger.debug("provider_circuit_breaker_open",
                           provider=provider_name, tenant=self.tenant_id)
                continue

            provider = self._get_or_create_provider(provider_name)
            if not provider:
                continue

            start_time = time.time()
            try:
                raw_text = provider.call_text(system_prompt, user_message)
                response = self._parse_json_response(raw_text)
                latency = time.time() - start_time

                # Record successful call
                if circuit_breaker:
                    circuit_breaker.record_success()

                # Track usage
                self.usage_tracker.track_usage(
                    provider=provider_name,
                    model=provider.model,
                    request_type=request_type,
                    input_length=len(system_prompt + user_message),
                    output_length=len(raw_text),
                    latency=latency,
                    success=True
                )

                logger.debug("llm_call_success",
                           provider=provider_name,
                           tenant=self.tenant_id,
                           latency=f"{latency:.2f}s")
                return response

            except Exception as e:
                latency = time.time() - start_time

                # Record failure
                if circuit_breaker:
                    circuit_breaker.record_failure()

                # Track failed usage
                self.usage_tracker.track_usage(
                    provider=provider_name,
                    model=provider.model if provider else "unknown",
                    request_type=request_type,
                    input_length=len(system_prompt + user_message),
                    output_length=0,
                    latency=latency,
                    success=False,
                    error_type=type(e).__name__
                )

                logger.warning("llm_call_failed_trying_fallback",
                              provider=provider_name,
                              tenant=self.tenant_id,
                              error=str(e)[:200],
                              remaining_providers=len(providers_to_try) - providers_to_try.index(provider_name) - 1)
                continue

        # All providers failed
        error_msg = f"All LLM providers failed for tenant {self.tenant_id}"
        logger.error("all_llm_providers_failed", tenant=self.tenant_id,
                    providers_tried=providers_to_try)
        raise RuntimeError(error_msg)

    def call_raw(self, system_prompt: str, user_message: str, request_type: str = "raw") -> str:
        """Call LLM and return raw text (no JSON parsing)."""
        # For raw calls, we'll use the same failover but return the raw text
        # We can reuse the logic by calling the main call method and extracting raw response
        # For simplicity, let's implement a direct version

        self._rate_limit()
        providers_to_try = [self.primary_provider] + self.fallback_providers

        for provider_name in providers_to_try:
            circuit_breaker = self.circuit_breakers.get(provider_name)
            if circuit_breaker and not circuit_breaker.can_call():
                continue

            provider = self._get_or_create_provider(provider_name)
            if not provider:
                continue

            start_time = time.time()
            try:
                raw_text = provider.call_text(system_prompt, user_message)
                latency = time.time() - start_time

                if circuit_breaker:
                    circuit_breaker.record_success()

                self.usage_tracker.track_usage(
                    provider=provider_name,
                    model=provider.model,
                    request_type=request_type,
                    input_length=len(system_prompt + user_message),
                    output_length=len(raw_text),
                    latency=latency,
                    success=True
                )

                return raw_text

            except Exception as e:
                latency = time.time() - start_time

                if circuit_breaker:
                    circuit_breaker.record_failure()

                self.usage_tracker.track_usage(
                    provider=provider_name,
                    model=provider.model if provider else "unknown",
                    request_type=request_type,
                    input_length=len(system_prompt + user_message),
                    output_length=0,
                    latency=latency,
                    success=False,
                    error_type=type(e).__name__
                )
                continue

        error_msg = f"All LLM providers failed for tenant {self.tenant_id}"
        logger.error("all_llm_providers_failed_raw", tenant=self.tenant_id)
        raise RuntimeError(error_msg)

    def get_info(self) -> dict:
        """Return backend info for admin/health display."""
        provider_status = {}
        for name in [self.primary_provider] + self.fallback_providers:
            provider = self.providers.get(name)
            breaker = self.circuit_breakers.get(name)
            provider_status[name] = {
                "initialized": provider is not None,
                "model": provider.model if provider else None,
                "circuit_breaker_state": breaker.state if breaker else "unknown",
                "failure_count": breaker.failure_count if breaker else 0
            }

        return {
            "tenant_id": self.tenant_id,
            "primary_provider": self.primary_provider,
            "fallback_providers": self.fallback_providers,
            "provider_status": provider_status
        }

    # ─── Response Parsing (shared with claude_backend.py) ──────────────

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
            logger.warning("json_parse_first_attempt_failed",
                          tenant=self.tenant_id, error=str(e))

            extracted = self._extract_json_object(raw_text)
            if extracted is not None:
                return extracted

            extracted = self._extract_json_array(raw_text)
            if extracted is not None:
                return extracted

            # Truncation heuristic — surfaced for operators triaging the
            # cheersin "raw_preview=<empty>" symptom. If the response ends
            # with no closing brace/bracket and the last char isn't a quote,
            # it almost certainly hit max_tokens. Log explicitly so the
            # operator knows to bump max_tokens rather than chase a parser
            # bug.
            stripped = raw_text.rstrip()
            looks_truncated = (
                len(stripped) > 0
                and stripped[-1] not in ('}', ']', '"')
            )

            logger.error("json_parse_all_attempts_failed",
                        tenant=self.tenant_id,
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