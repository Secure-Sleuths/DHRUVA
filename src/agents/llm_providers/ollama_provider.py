"""Ollama LLM provider — local models via REST API.

Zero SDK dependencies — uses ``requests`` (already a project dependency).
"""

import requests
import structlog

from .base import BaseLLMProvider

logger = structlog.get_logger(__name__)

# Fraction of the context window at which a prompt is reported as dangerously
# close to eviction. Ollama drops the OLDEST tokens when the window overflows —
# that is the SYSTEM message, which carries the <untrusted_data> prompt-injection
# guard. Losing it silently is the worst failure this provider can have, so the
# alarm fires with headroom rather than at the exact boundary.
_CTX_ALARM_FRACTION = 0.95


class OllamaProvider(BaseLLMProvider):
    """Ollama REST API provider for local LLMs.

    Talks to Ollama at ``base_url`` (default ``http://localhost:11434``).
    Supports any model available in the local Ollama instance
    (Llama 3.1, Mistral, Mixtral, Phi, Gemma, Granite, etc.).

    Config keys (all optional beyond ``model``)::

        llm:
          ollama:
            base_url: http://127.0.0.1:11434
            model: dhruva-granite
            num_ctx: 16384      # explicit context window; discovered from the
                                # model if omitted
    """

    PROVIDER_NAME = "ollama"

    def __init__(self, config: dict):
        super().__init__(config)
        self.base_url = config.get(
            "base_url", "http://localhost:11434").rstrip("/")
        if not self.model:
            self.model = config.get("model", "llama3.1:70b")

        # Explicit context window. Ollama otherwise silently inherits whatever
        # the Modelfile declares, which makes prompt-eviction risk invisible to
        # the platform. Sent on every request AND used as the alarm threshold.
        self.num_ctx = config.get("num_ctx")

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

        # If num_ctx wasn't configured, discover the model's own value so the
        # truncation alarm has a real threshold instead of being disabled.
        if not self.num_ctx:
            self.num_ctx = self._discover_num_ctx()

        logger.info("ollama_context_config",
                    model=self.model, num_ctx=self.num_ctx,
                    num_predict=self.max_tokens,
                    headroom=(int(self.num_ctx) - self.max_tokens
                              if self.num_ctx else None),
                    detail="num_predict larger than the window's spare room "
                           "means generation is capped by context, not by "
                           "max_tokens")

    def _discover_num_ctx(self):
        """Read num_ctx from the model's own parameters (best effort)."""
        try:
            resp = requests.post(f"{self.base_url}/api/show",
                                 json={"model": self.model}, timeout=10)
            if resp.status_code != 200:
                return None
            for line in (resp.json().get("parameters") or "").splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[0] == "num_ctx":
                    return int(parts[1])
        except Exception as e:
            logger.debug("ollama_num_ctx_discovery_failed", error=str(e)[:120])
        return None

    def call_text(self, system_prompt: str, user_message: str) -> str:
        """Free-form completion. Used by ``LLMBackend.call_raw`` for prose
        (e.g. plain-language incident summaries) — must NOT be JSON-constrained."""
        return self._chat(system_prompt, user_message, json_mode=False)

    def call_text_json(self, system_prompt: str, user_message: str) -> str:
        """JSON-constrained completion, preferred by ``LLMBackend.call``.

        Ollama's ``format: "json"`` makes the server constrain decoding to a
        syntactically valid JSON value. Without it the model wraps the verdict in
        a ```json fence; ``LLMBackend._parse_json_response`` does strip fences,
        but relying on that is relying on a cleanup path rather than on the
        response being right in the first place.

        Deliberately a SEPARATE method rather than a flag on the provider: the
        dispatcher runs N triage workers against ONE provider instance (WO-H32),
        so a mutable ``json_mode`` attribute would race between threads and could
        JSON-constrain a prose call or vice versa.
        """
        return self._chat(system_prompt, user_message, json_mode=True)

    def _chat(self, system_prompt: str, user_message: str,
              json_mode: bool) -> str:
        url = f"{self.base_url}/api/chat"
        options = {
            "temperature": self.temperature,
            "num_predict": self.max_tokens,
        }
        if self.num_ctx:
            options["num_ctx"] = int(self.num_ctx)

        payload = {
            "model": self.model,
            # The system prompt MUST stay at index 0 and keep role "system":
            # chat templates (Granite among them) only honour a system message
            # in that position, and it carries the <untrusted_data> injection
            # guard. Never merge it into the user turn.
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "stream": False,
            "options": options,
        }
        if json_mode:
            payload["format"] = "json"

        resp = requests.post(url, json=payload, timeout=300)
        resp.raise_for_status()
        data = resp.json()

        raw_text = data.get("message", {}).get("content", "")

        eval_count = data.get("eval_count", 0)
        prompt_count = data.get("prompt_eval_count", 0)
        if eval_count:
            logger.debug("ollama_tokens",
                         input=prompt_count, output=eval_count)

        # WO-H50 parity with the Anthropic provider: expose the REAL token
        # counts so LLMBackend._track() records them exactly and flags the row
        # estimated=False, instead of falling back to a chars//4 guess.
        # Set before the empty-response check so a failed call still meters.
        if prompt_count or eval_count:
            self.last_usage = {
                "input_tokens": int(prompt_count),
                "output_tokens": int(eval_count),
                "cost_usd": 0.0,   # local inference — no marginal cost
                "estimated": False,
            }
        else:
            self.last_usage = None

        self._check_context_pressure(prompt_count, eval_count,
                                     data.get("done_reason"))

        if not raw_text:
            raise RuntimeError("Ollama returned empty response")

        return raw_text

    def _check_context_pressure(self, prompt_count, eval_count, done_reason):
        """Alarm when the prompt is at risk of being evicted.

        Ollama fills num_ctx with prompt + completion and, on overflow, discards
        the OLDEST tokens first. The oldest tokens are the system prompt — which
        is where the <untrusted_data> prompt-injection guard lives. So a context
        overflow does not merely truncate output: it can silently remove the
        instruction telling the model not to obey attacker-controlled alert
        fields, while triage carries on returning confident-looking verdicts.

        CRITICAL rather than warning because this is the same class of failure as
        an unavailable backend: the platform keeps producing verdicts that look
        fine and are no longer trustworthy.
        """
        if not self.num_ctx or not prompt_count:
            return
        ctx = int(self.num_ctx)
        alarm_at = int(ctx * _CTX_ALARM_FRACTION)

        if prompt_count >= alarm_at:
            logger.critical(
                "ollama_prompt_near_context_limit",
                prompt_tokens=prompt_count, num_ctx=ctx,
                alarm_threshold=alarm_at,
                utilization=round(prompt_count / ctx, 3),
                detail="Prompt is at or near the context window. Ollama evicts "
                       "OLDEST tokens on overflow — that is the system prompt, "
                       "which carries the <untrusted_data> prompt-injection "
                       "guard. Verdicts produced in this state may have been "
                       "generated WITHOUT that instruction.",
                remediation="Raise llm.ollama.num_ctx (and the Modelfile "
                            "num_ctx), or reduce prompt size.")
            return

        # Not truncated, but the requested generation cannot fit in what's left,
        # so output will be cut short by the window rather than by max_tokens.
        spare = ctx - prompt_count
        if self.max_tokens > spare:
            logger.warning(
                "ollama_generation_capped_by_context",
                prompt_tokens=prompt_count, num_ctx=ctx, spare_tokens=spare,
                num_predict=self.max_tokens, output_tokens=eval_count,
                done_reason=done_reason,
                detail="num_predict exceeds the context window's remaining "
                       "room; generation is capped by context. A truncated "
                       "response fails JSON parsing downstream.")

    def get_info(self) -> dict:
        info = super().get_info()
        info["base_url"] = self.base_url
        info["num_ctx"] = self.num_ctx
        info["json_mode_supported"] = True
        return info
