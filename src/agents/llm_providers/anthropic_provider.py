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

        # Auto-detect sub-mode.
        #
        # WO-H46-a: an empty api_key is AMBIGUOUS at this layer and cannot be
        # treated as a hard error. claude_backend._build_provider_config()
        # unconditionally injects ``api_key: ""`` when the key is absent, so
        # "operator never configured a key, wants subscription/CLI mode" and
        # "operator set ANTHROPIC_API_KEY= but it resolved to nothing" arrive
        # here as the identical value. Failing startup on empty would break
        # every legitimate CLI/subscription install.
        #
        # So the fallback stays, but it is no longer SILENT: the reason is
        # logged explicitly, and — the part that actually matters — _init_cli()
        # now verifies the CLI can AUTHENTICATE rather than merely exist. That
        # is the gap that caused the incident: `claude --version` returns 0 on
        # an unauthenticated CLI, so the platform logged `anthropic_cli_ready`,
        # reported healthy, and then failed every single call.
        if self.sub_mode == "auto":
            api_key = config.get("api_key", "")
            if api_key and not api_key.startswith("${"):
                self.sub_mode = "api"
                logger.info("anthropic_mode_detected", mode="api",
                            reason="api_key present")
            else:
                self.sub_mode = "cli"
                if api_key.startswith("${"):
                    # A literal ${VAR} means env substitution did not happen —
                    # unambiguously a misconfiguration, not a mode choice.
                    logger.critical(
                        "anthropic_api_key_unresolved",
                        placeholder=api_key,
                        detail="api_key is an unsubstituted ${VAR} placeholder; "
                               "the environment variable is not set. Falling "
                               "back to CLI/subscription mode, which is almost "
                               "certainly not what was intended.",
                        remediation="Set the env var referenced by the "
                                    "placeholder, or remove api_key from "
                                    "config to use CLI mode deliberately.")
                else:
                    logger.warning(
                        "anthropic_mode_fallback_to_cli",
                        detail="No API key configured — using CLI/subscription "
                               "mode. If you intended API mode, ANTHROPIC_API_KEY "
                               "is unset or empty. Note subscription mode is not "
                               "appropriate for client-facing use.")
                logger.info("anthropic_mode_detected", mode="cli")

        if self.sub_mode == "api":
            self._init_api(config)
        else:
            self._init_cli(config)

    def _init_api(self, cfg: dict):
        # WO-H46-a: unlike the auto path, an empty key here is UNAMBIGUOUS —
        # the operator explicitly selected mode="api", so a missing key is a
        # misconfiguration, not a mode preference. Fail loudly at startup
        # rather than constructing a client that will fail on every call.
        api_key = cfg.get("api_key", "")
        if not api_key or api_key.startswith("${"):
            logger.critical(
                "llm_backend_unavailable", backend="anthropic_api",
                reason="api_key_missing_in_explicit_api_mode",
                placeholder=api_key if api_key.startswith("${") else None,
                detail="mode is explicitly 'api' but api_key is empty or an "
                       "unsubstituted ${VAR} placeholder.",
                remediation="Set ANTHROPIC_API_KEY, or set mode to 'auto'/'cli' "
                            "to use the Claude CLI deliberately.")
            raise ValueError(
                "Anthropic provider is in explicit 'api' mode but no api_key is "
                "configured (empty or unresolved ${VAR} placeholder). Set "
                "ANTHROPIC_API_KEY, or choose mode 'auto'/'cli'.")
        try:
            import anthropic
            self.client = anthropic.Anthropic(api_key=api_key)
            logger.info("anthropic_api_ready", model=self.model)
        except ImportError:
            logger.error("anthropic_sdk_not_installed",
                         hint="pip install anthropic")
            raise

    def _init_cli(self, cfg: dict):
        self.cli_path = cfg.get("cli_path", "claude")
        # WO-H46-a: set True only after the CLI proves it can authenticate.
        # Exposed so callers/health endpoints can report backend readiness.
        self.cli_authenticated: bool | None = None
        try:
            result = subprocess.run(
                [self.cli_path, "--version"],
                capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.info("anthropic_cli_present",
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

        # `--version` returns 0 on an UNAUTHENTICATED CLI, so presence proves
        # nothing about usability. Verify auth with a real (tiny) call unless
        # explicitly disabled.
        if cfg.get("verify_cli_auth", True):
            self._verify_cli_auth(timeout=int(cfg.get("cli_auth_timeout", 45)))

    def _verify_cli_auth(self, timeout: int = 45) -> bool:
        """WO-H46-a: prove the CLI can actually authenticate, at startup.

        The incident this prevents: the CLI's OAuth session expired while the
        service was stopped. On restart `claude --version` returned 0, the
        platform logged "ready", reported healthy — and then every triage call
        failed. Because triage fails CLOSED, each failure was written as a
        needs_investigation escalation, so the platform looked BUSY rather than
        BROKEN. It ran that way long enough to accumulate 1398 un-analyzed rows
        (20% of the decision history on that install).

        This is deliberately NOT fatal. The platform still does useful work
        without an LLM (ingestion, enrichment, correlation, deterministic
        always-escalate rules), and a transient CLI hiccup should not prevent
        boot. It logs CRITICAL so the failure is visible at startup instead of
        being discovered later via poisoned data.
        """
        try:
            result = subprocess.run(
                [self.cli_path, "-p", "Reply with exactly: OK",
                 "--output-format", "text"],
                capture_output=True, text=True, timeout=timeout,
                env={**os.environ},
            )
        except subprocess.TimeoutExpired:
            self.cli_authenticated = False
            logger.critical(
                "llm_backend_unavailable", backend="anthropic_cli",
                reason="auth_check_timeout", timeout_seconds=timeout,
                detail="Claude CLI did not respond to a minimal prompt. Triage "
                       "will fail closed and escalate every alert un-analyzed.")
            return False
        except Exception as e:
            self.cli_authenticated = False
            logger.critical(
                "llm_backend_unavailable", backend="anthropic_cli",
                reason="auth_check_error", error=str(e)[:200])
            return False

        if result.returncode != 0:
            stderr = (result.stderr or "").strip()[:300]
            expired = "oauth" in stderr.lower() or "authenticate" in stderr.lower()
            self.cli_authenticated = False
            logger.critical(
                "llm_backend_unavailable", backend="anthropic_cli",
                reason="oauth_expired" if expired else "auth_check_failed",
                returncode=result.returncode, stderr=stderr,
                detail="Claude CLI cannot authenticate. Triage will fail closed "
                       "and escalate every alert WITHOUT analyzing it — the "
                       "platform will look busy, not broken.",
                remediation="Run `claude login` as the service user, or set a "
                            "real ANTHROPIC_API_KEY to use API mode (required "
                            "for client-facing use).")
            return False

        self.cli_authenticated = True
        logger.info("anthropic_cli_ready", path=self.cli_path,
                    auth_verified=True)
        return True

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
        # WO-H50: capture the SDK's REAL token counts instead of logging them
        # at debug and discarding them. LLMBackend reads last_usage after the
        # call and records these exact numbers rather than a chars//4 estimate.
        self.last_usage = {
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
            "cost_usd": None,   # SDK doesn't return cost; priced from tokens
            "estimated": False,
        }
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

        # WO-H50: request JSON so the CLI returns its real usage block
        # ({"result": "...", "usage": {"input_tokens", "output_tokens"},
        # "total_cost_usd": ...}) instead of bare text that discards it. The
        # model's answer is the `result` field. Falls back to treating stdout
        # as text (estimated usage) if the envelope can't be parsed, so a CLI
        # version that doesn't speak this format still works.
        self.last_usage = None
        result = subprocess.run(
            [self.cli_path, "-p", combined_prompt,
             "--output-format", "json"],
            capture_output=True, text=True, timeout=120,
            env={**os.environ},
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip()[:500]
            logger.error("anthropic_cli_failed",
                         returncode=result.returncode, stderr=error_msg)
            raise RuntimeError(f"Claude CLI failed: {error_msg}")

        stdout = result.stdout.strip()
        if not stdout:
            raise RuntimeError("Claude CLI returned empty response")

        raw_text = stdout
        try:
            import json as _json
            env = _json.loads(stdout)
            if isinstance(env, dict) and "result" in env:
                raw_text = str(env["result"]).strip()
                u = env.get("usage") or {}
                in_tok = u.get("input_tokens")
                out_tok = u.get("output_tokens")
                if in_tok is not None and out_tok is not None:
                    self.last_usage = {
                        "input_tokens": int(in_tok),
                        "output_tokens": int(out_tok),
                        "cost_usd": env.get("total_cost_usd"),
                        "estimated": False,
                    }
        except (ValueError, TypeError) as e:
            # Not JSON (older CLI / plain text) — use stdout as the answer and
            # let LLMBackend fall back to a flagged estimate. Never fatal.
            logger.debug("anthropic_cli_json_parse_fallback", error=str(e)[:120])

        if not raw_text:
            raise RuntimeError("Claude CLI returned empty response")

        logger.debug("anthropic_cli_completed",
                     response_length=len(raw_text),
                     usage_captured=self.last_usage is not None)
        return raw_text

    def get_info(self) -> dict:
        info = super().get_info()
        info["sub_mode"] = self.sub_mode
        return info
