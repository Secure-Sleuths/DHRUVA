"""
Triage Agent - Processes enriched alerts through Claude for classification.
Implements the action layer of DHRUVA.
"""

import json
import time
import uuid
import structlog
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path

from src.agents.claude_backend import LLMBackend
from src.agents.cost_controls import (
    AlertDeduplicator,
    BudgetGuard,
    NoisePreFilter,
    PersistentDecisionCache,
)
from src.agents.grounding import assess_triage_grounding, output_safety_metrics
from src.agents.prompts import build_triage_prompt, PROMPT_VERSION
from src.agents.verdict_guard import (
    blocking_evidence,
    degraded_evidence_sources,
    evaluate_verdict_guard,
    evidence_unavailable,
)
from src.anonymization import AlertAnonymizer
from src.database.store import SOCDatabase, AgentDecision, FeedbackPattern
from src.enrichment.service import EnrichmentService
from src.guidance.loader import GuidanceLoader

logger = structlog.get_logger(__name__)

# Auto-close bar applied to a rule the feedback loop has BASELINED (a rule whose
# recent history is all false positives with zero true positives). Historically
# this LOWERED the bar to make a known-noisy rule auto-close more readily.
_BASELINED_AUTO_CLOSE_THRESHOLD = 0.80

# WO-H97 shadow fields. The model already answers both on every alert; the
# answers are stored and READ BY NOTHING (see AgentDecision.response_urgency).
# Only these literals are ever persisted — anything else, including a value the
# model invented such as "none", becomes NULL. Same shape as the VALID_VERDICTS
# clamp in triage_alert: the alert body is attacker-controlled text that reaches
# the prompt, so an unvalidated free-text decision field would be an injection
# sink the moment anything started reading it.
VALID_RESPONSE_URGENCY = ("immediate", "1h", "4h", "24h")
VALID_KILL_CHAIN_STAGES = (
    "recon", "initial_access", "execution", "persistence",
    "privilege_escalation", "defense_evasion", "credential_access",
    "discovery", "lateral_movement", "collection", "c2", "exfiltration",
    "impact",
)

# Decision fields that de-anonymization must never be able to rewrite (WO-S7).
# response_urgency/kill_chain_stage joined the list with WO-H97, before anything
# consumes them, so the guard is never retrofitted after a consumer exists.
_PROTECTED_DECISION_FIELDS = (
    "verdict", "confidence", "escalation_required",
    "response_urgency", "kill_chain_stage",
)


def _clamp_shadow_field(raw, allowed: tuple, field: str, alert_id: str = None):
    """Return ``raw`` when it is exactly one of ``allowed``, else ``None``.

    ``None`` is stored as SQL NULL and means "the model did not give us a usable
    answer" — never a default bucket.

    An out-of-schema answer is logged at INFO, not debug. Once it is NULLed it
    is indistinguishable in the column from "the model omitted the key", and the
    difference is exactly what the shadow phase is trying to learn: the replay
    that motivated this work saw the model answer ``none``, a value that is not
    in the scale at all. Debug is off in production, so that evidence would be
    lost at the one moment it matters.
    """
    if raw is None:
        return None
    value = str(raw).strip().lower()
    if value in allowed:
        return value
    logger.info("triage_shadow_field_out_of_schema",
                field=field, raw=str(raw)[:40], alert_id=alert_id,
                detail="model answered outside the documented scale; stored "
                       "as NULL")
    return None


def resolve_auto_close_threshold(configured: float, rule_override, verdict):
    """Resolve the effective auto-close threshold for a single alert.

    **INVARIANT: the returned threshold is NEVER below ``configured``.**

    A per-rule tuning override may only ever RAISE the auto-close bar. This is
    enforced here, at the single assignment point, rather than in each branch —
    so a future ``action_type`` cannot reopen the hole by forgetting to clamp.

    Why this matters. ``agents.triage.auto_close_confidence_threshold`` is the
    operator's stated ceiling on automated dismissal. Both override branches
    used to be able to defeat it:

    * ``baselined`` did ``min(effective, 0.80)`` — floor 0.80 regardless of config
    * ``threshold_raised`` did a PLAIN ASSIGNMENT of ``confidence_override``, so
      any stored value at or below the configured bar silently lowered it,
      despite the name

    Both are written AUTOMATICALLY by ``src/feedback/loop.py`` (``auto_tune_enabled``)
    with ``expires_at=None``, on a 4-hour cycle. So the bypass did not need a
    human to open it — a rule accumulating false positives would reopen
    auto-close by itself, with no config change and nothing in the config to show
    it had happened.

    RELATIONSHIP TO ``auto_close_enabled`` (WO-H60). That flag is the blunt
    switch: when false, every dismissal escalates and this threshold is never
    consulted. It does NOT make this clamp redundant, because it defaults to
    TRUE — on a default install the override path below is live, and this
    function is the only thing holding the operator's configured bar.

    NOTE ON THE NAME ``threshold_raised``: it is a persisted ``action_type``
    value written by the feedback loop and stored in ``rule_tuning_overrides``
    rows, so renaming it would orphan existing rows and require a coordinated
    change in ``src/feedback/loop.py``. The name is kept and the invariant is
    documented instead — the label alone must NOT be trusted to mean the bar went
    up; only this function's clamp guarantees that.

    Returns ``(threshold, action, floored)``:
      * ``threshold`` — the effective bar, guaranteed ``>= configured``
      * ``action``    — the ``action_type`` that was considered, else ``None``
      * ``floored``   — True when the override REQUESTED a lower bar and was
                        clamped away (an event worth logging: it means the
                        feedback loop is trying to re-enable auto-close)
    """
    try:
        configured = float(configured)
    except (TypeError, ValueError):
        configured = 0.0

    if not rule_override:
        return configured, None, False

    action = rule_override.get("action_type") if hasattr(
        rule_override, "get") else None

    requested = None
    if action == "threshold_raised" and (
            rule_override.get("confidence_override") is not None):
        # ``is not None``, NOT truthiness: a stored confidence_override of 0.0
        # means "auto-close everything on this rule" — the most aggressive
        # bypass request there is. The original truthiness check dropped it
        # silently. It is still clamped either way, but it must be VISIBLE.
        requested = rule_override["confidence_override"]
    elif action == "baselined" and verdict in ("false_positive", "auto_close"):
        requested = _BASELINED_AUTO_CLOSE_THRESHOLD

    if requested is None:
        return configured, action, False

    try:
        requested = float(requested)
    except (TypeError, ValueError):
        # Unusable override value — keep the operator's configured bar.
        return configured, action, False

    # NaN must be rejected explicitly, not left to max(). Every NaN comparison
    # is False, so max(configured, nan) happens to return configured only
    # because of ARGUMENT ORDER — max(nan, configured) would return nan, and a
    # NaN threshold makes `confidence < threshold` always False, i.e. auto-close
    # everything. Too sharp an edge to leave resting on argument order.
    if requested != requested:
        logger.warning("tuning_override_nan_rejected", action=action)
        return configured, action, False

    # The floor. Every return path above yields ``configured`` unchanged; this is
    # the ONLY path that can move the bar, and it can only move it upward.
    return max(configured, requested), action, requested < configured


class TriageAgent:
    """
    AI-powered alert triage agent.
    
    Flow:
    1. Receives enriched alert from EnrichmentService
    2. Builds context package (alert + enrichment + correlated events)
    3. Selects appropriate investigation playbook
    4. Sends to Claude with full context + guidance
    5. Parses structured verdict
    6. Records decision in database + OpenSearch
    7. Handles escalation/auto-close based on confidence thresholds
    """

    def __init__(self, config: dict, db: SOCDatabase,
                 enrichment_service: EnrichmentService,
                 guidance_loader: GuidanceLoader,
                 knowledge_base=None, tenant_registry=None):
        self.config = config
        self.db = db
        self.enrichment = enrichment_service
        self.guidance = guidance_loader
        self.knowledge_base = knowledge_base
        self.tenant_registry = tenant_registry

        agent_cfg = config.get("agents", {}).get("triage", {})
        self.auto_close_threshold = agent_cfg.get("auto_close_confidence_threshold", 0.92)
        self.escalation_threshold = agent_cfg.get("escalation_confidence_threshold", 0.5)
        self.max_context_alerts = agent_cfg.get("max_context_alerts", 20)
        # WO-H60: explicit kill switch for the alert-SUPPRESSING path. When
        # false, every AI dismissal (auto_close / false_positive) is escalated
        # for human confirmation regardless of confidence. Defaults to TRUE so
        # this release changes nothing for existing installs; set it false
        # while rolling out a change to the evidence the agent reasons from.
        # Preferred over setting auto_close_confidence_threshold above 1.0,
        # which achieves the same thing opaquely and looks like a typo.
        self.auto_close_enabled = agent_cfg.get("auto_close_enabled", True)
        # WO-H104: `auto_close` is the only verdict that DISCARDS an alert, and
        # the verdict is not reproducible — five real alerts replayed five times
        # each through the real prompt and the real model, at temperature 0,
        # changed verdict 5/5. So the irreversible direction gets a second
        # opinion and the reversible ones do not.
        # DEFAULT OFF, deliberately. The mechanism is the point; switching it
        # on for every existing install without asking is not. It costs one
        # extra LLM call per close — 29.4% of verdicts on the measured estate,
        # ~458 calls/day — and it will move alerts a client currently never
        # sees into their queue. That is the operator's decision to make with
        # the number in front of them.
        #
        # RECOMMENDED ON. Set `agents.triage.confirm_auto_close: true`. After
        # WO-H118 the repeat call re-reads a cached prefix, so the marginal
        # cost is the per-alert tail, not a second full prompt.
        self.confirm_auto_close = agent_cfg.get("confirm_auto_close", False)
        if not self.auto_close_enabled:
            logger.warning(
                "auto_close_disabled",
                detail="Auto-close is held shut: every AI dismissal will be "
                       "escalated for human confirmation regardless of "
                       "confidence. Alert suppression is OFF.")

        # Multi-tenant LLM backend support with backward compatibility
        if self.tenant_registry:
            # New multi-tenant mode: get LLM backend per tenant
            self.claude = None  # Will be resolved per request
            logger.info("triage_agent_multi_tenant_mode")
        else:
            # Legacy single-tenant mode: global LLM backend
            from src.agents.claude_backend import LLMBackend
            self.claude = LLMBackend(config, db=db)
            logger.info("triage_agent_legacy_mode", mode=self.claude.mode)

        # Anonymization layer — strips client identifiers before LLM calls
        self.anonymizer = AlertAnonymizer(config, db=db)

        # Load always-escalate rules for pre-AI bypass
        self._always_escalate_rules = (
            self.guidance._escalation_logic.get("always_escalate", [])
        )

        # ── WO-H5: LLM cost controls (all opt-in / graceful-degrade) ──
        # Hard per-tenant spend cap that blocks the LLM call, structural dedup,
        # and a cheap deterministic noise pre-filter. Each reads its config from
        # agents.triage.cost_controls and is a no-op when disabled/unconfigured.
        self.budget_guard = BudgetGuard(db, config, tenant_registry=tenant_registry)
        self.deduplicator = AlertDeduplicator(config)
        self.prefilter = NoisePreFilter(config)
        # WO-H57: durable verdict cache BELOW the in-memory dedup window.
        self.decision_cache = PersistentDecisionCache(config)

        logger.info("triage_agent_initialized",
                     auto_close_threshold=self.auto_close_threshold,
                     always_escalate_rules=len(self._always_escalate_rules),
                     multi_tenant=self.tenant_registry is not None,
                     budget_cap_enabled=self.budget_guard.enabled,
                     dedup_enabled=self.deduplicator.enabled,
                     prefilter_enabled=self.prefilter.enabled,
                     decision_cache_enabled=self.decision_cache.enabled)

    def _get_alert_field(self, alert: dict, enrichment: dict, field: str):
        """Resolve a field name from the alert or its enrichment data."""
        # Check enrichment first (asset_tier, mitre_tactic, etc.)
        if field == "asset_tier":
            return enrichment.get("asset_tier", "")
        if field == "mitre_tactic":
            return alert.get("rule_mitre_tactics", [])
        if field == "mitre_technique":
            return alert.get("rule_mitre_techniques", [])
        if field == "rule_level":
            return alert.get("rule_level", 0)
        if field == "rule_group":
            return alert.get("rule_groups", [])
        if field == "time_context":
            ctx = enrichment.get("time_context", "")
            # WO-H76: a maintenance window MUST survive this normalization.
            # Every configured window is by definition outside business hours,
            # so `is_bh` is always False for one — and the collapse below
            # rewrote every maintenance-window alert to "outside_business_hours".
            # That made "maintenance_window" a value no rule could ever see,
            # including the "Maintenance window activity" auto-close condition
            # in escalation_logic.yaml, which is gated behind a CI/CD agent
            # allowlist and a 0.90 confidence floor.
            # SIDE EFFECT: any always-escalate rule written as a bare
            # `match: "outside_business_hours"` stops firing inside a
            # maintenance window. The operator accepted the OTHER narrowing
            # (business-hours alerts no longer always-escalating), NOT this
            # one. The shipped "New admin account creation" rule was therefore
            # widened to `in: ["outside_business_hours", "maintenance_window"]`
            # in config/guidance/escalation_logic.yaml — a maintenance window
            # is outside business hours, and suppressing a security control
            # during one is exactly the cover an attacker would want. Any NEW
            # rule keyed on outside-hours must make the same choice explicitly.
            if ctx == "maintenance_window" or \
                    enrichment.get("is_maintenance_window"):
                return "maintenance_window"
            is_bh = enrichment.get("is_business_hours", True)
            if ctx == "outside_business_hours" or not is_bh:
                return "outside_business_hours"
            return ctx
        if field == "data_volume_anomaly":
            return enrichment.get("baseline_anomaly", False)
        if field == "action":
            return alert.get("data", {}).get("action", "")
        if field == "followed_by_success":
            return enrichment.get("followed_by_success", False)
        if field == "unique_source_count":
            return enrichment.get("unique_source_count", 0)
        # Fallback: check alert then enrichment
        return alert.get(field, enrichment.get(field))

    def _eval_condition(self, field_value, condition: dict) -> bool:
        """Evaluate a single always-escalate condition against a field value."""
        if "in" in condition:
            expected = condition["in"]
            if isinstance(field_value, list):
                return bool(set(field_value) & set(expected))
            return field_value in expected
        if "match" in condition:
            return field_value == condition["match"]
        # M2 fix: a "value" key means pure equality ONLY when there is no
        # operator. Previously this branch ran first and short-circuited the
        # operator branch, so {operator: ">=", value: N} silently behaved as
        # "== N". Guarding on the absence of "operator" lets such conditions
        # reach the operator branch below.
        if "value" in condition and "operator" not in condition:
            return field_value == condition["value"]
        if "operator" in condition:
            op = condition["operator"]
            val = condition.get("value", 0)
            try:
                field_value = float(field_value)
                val = float(val)
            except (TypeError, ValueError):
                return False
            if op == ">=":
                return field_value >= val
            if op == "<=":
                return field_value <= val
            if op == ">":
                return field_value > val
            if op == "<":
                return field_value < val
            if op == "==":
                return field_value == val
        return False

    def _check_always_escalate(self, alert: dict, enrichment: dict) -> Optional[str]:
        """
        Pre-AI check: evaluate always-escalate rules from escalation_logic.yaml.
        Returns the matched rule name if any rule triggers, None otherwise.
        ALL conditions within a rule must match for it to trigger.
        """
        for rule in self._always_escalate_rules:
            rule_name = rule.get("name", "unnamed")
            conditions = rule.get("conditions", [])
            if not conditions:
                continue

            all_match = True
            for cond in conditions:
                field = cond.get("field", "")
                field_value = self._get_alert_field(alert, enrichment, field)
                if field_value is None:
                    all_match = False
                    break
                if not self._eval_condition(field_value, cond):
                    all_match = False
                    break

            if all_match:
                logger.warning("always_escalate_triggered",
                               rule=rule_name,
                               alert_id=alert.get("alert_id"))
                return rule_name

        return None

    def select_playbook(self, alert: dict) -> str:
        """Select the most relevant investigation playbook based on alert type."""
        rule_groups = set(alert.get("rule_groups", []))
        rule_id = alert.get("rule_id", 0)

        playbooks = self.guidance.get_all_playbooks()
        
        for pb_name, pb_data in playbooks.items():
            # Check rule group match
            trigger_groups = set(pb_data.get("trigger_rule_groups", []))
            if rule_groups & trigger_groups:
                return self.guidance.format_playbook(pb_name)

            # Check rule ID match
            trigger_ids = pb_data.get("trigger_rule_ids", [])
            if rule_id in trigger_ids:
                return self.guidance.format_playbook(pb_name)

        # Return generic guidance if no specific playbook matches
        return "No specific playbook matched. Apply general investigation methodology: understand the alert, assess context, check threat intelligence, correlate events, and reach a verdict."

    #: WO-H104. What an unconfirmed close becomes. NOT `false_positive`: that
    #: is still a dismissal, and the whole point is that we do not know.
    _UNCONFIRMED_VERDICT = "needs_investigation"

    def _confirm_auto_close(self, result: dict, system_prompt: str,
                            user_message: str, tenant_id: str = None) -> dict:
        """Re-ask before discarding an alert. Costs one call, only on closes.

        WO-H104. The measured problem: five real alerts, five replays each,
        byte-identical prompts, temperature 0 on the tenant path — and the
        verdict changed on 5 of 5. In production, 12 of 12 same-rule/same-host
        /same-day groups carried conflicting verdicts, one of them all four.

        THE ASYMMETRY IS THE WHOLE DESIGN. `needs_investigation` costs an
        analyst a look; a wrong one is corrected by the person reading it.
        `auto_close` throws the alert away and no rerun ever happens. So only
        that direction is confirmed — on this estate 29.4% of verdicts, about
        458 calls a day, and after WO-H118 the repeat call re-reads a cached
        prefix rather than paying for it again.

        Disagreement does NOT mean "the second answer is right". It means the
        model does not have a stable opinion, so a human gets it.
        """
        # getattr, not attribute access. An agent built by __new__ (the eval
        # harness, several test suites) has no such attribute, and a bare
        # `self.confirm_auto_close` raises AttributeError straight into
        # triage_alert. That is the FOURTH time in this branch that a new
        # attribute or method assumed on `self` broke a caller that predates
        # it — the pattern, not the line, is the lesson.
        if not getattr(self, "confirm_auto_close", False):
            return result
        if (result or {}).get("verdict") != "auto_close":
            return result   # reversible outcomes are not re-asked

        try:
            second = self._call_claude(system_prompt, user_message, tenant_id)
        except Exception as e:                                  # noqa: BLE001
            # Could not get a second opinion. Fail toward the human: an
            # unconfirmable close is exactly the case this exists for.
            logger.warning("auto_close_confirmation_failed",
                           error=str(e)[:200])
            out = dict(result)
            out["verdict"] = self._UNCONFIRMED_VERDICT
            out["auto_close_confirmation"] = {"agreed": False,
                                              "second_verdict": None,
                                              "reason": "confirmation_failed"}
            return out

        second_verdict = (second or {}).get("verdict")
        agreed = second_verdict == "auto_close"
        logger.info("auto_close_confirmation",
                    agreed=agreed, second_verdict=second_verdict)
        out = dict(result)
        out["auto_close_confirmation"] = {"agreed": agreed,
                                          "second_verdict": second_verdict,
                                          "reason": "agreed" if agreed
                                          else "verdict_unstable"}
        if not agreed:
            out["verdict"] = self._UNCONFIRMED_VERDICT
            existing = out.get("reasoning") or ""
            out["reasoning"] = (
                "[WO-H104] Auto-close was NOT confirmed: a second pass over the "
                "identical prompt returned %r. The model does not hold a stable "
                "opinion on this alert, so it is being shown to a person rather "
                "than discarded. Original reasoning follows. %s"
                % (second_verdict, existing))
        return out

    def _call_claude(self, system_prompt: str, user_message: str,
                     tenant_id: str = None) -> dict:
        """Call LLM via tenant-specific backend with failover support."""
        if self.tenant_registry and tenant_id:
            # Multi-tenant mode: get LLM backend for specific tenant
            llm_backend = self.tenant_registry.get_llm_backend(tenant_id)
            if llm_backend:
                return llm_backend.call(system_prompt, user_message, "triage")
            # Per-tenant backend unavailable — fall through to global
            logger.warning("tenant_llm_fallback_to_global", tenant_id=tenant_id)

        # Global / legacy single-tenant mode
        if not self.claude:
            raise RuntimeError("No LLM backend configured")
        return self.claude.call(system_prompt, user_message)

    def _resolve_model_id(self, tenant_id: str = None) -> str:
        """Resolved concrete provider/model id of the backend that ran a triage
        call, for per-decision attribution (WO-H29 finding NEW-3).

        Mirrors ``_call_claude``'s backend selection (per-tenant backend first,
        then the global/legacy backend) so the recorded id matches the backend
        that actually produced the verdict, rather than the dead ``'cli'``
        constant the audit trail used before. Returns ``'unknown'`` only when no
        backend can be resolved (never raises — this must never break triage).
        """
        backend = None
        if self.tenant_registry and tenant_id:
            try:
                backend = self.tenant_registry.get_llm_backend(tenant_id)
            except Exception:
                backend = None
        if backend is None:
            backend = self.claude
        if backend is None:
            return "unknown"
        try:
            describe = getattr(backend, "describe_model", None)
            if callable(describe):
                return describe() or "unknown"
            # Defensive fallback for any backend lacking describe_model().
            provider = getattr(backend, "mode", "") or "unknown"
            model = getattr(getattr(backend, "provider", None), "model", "") or ""
            return f"{provider}/{model}" if model else provider
        except Exception as e:                           # noqa: BLE001
            # WO-H90: was a bare `except: return "unknown"`. A failure here
            # means every verdict is attributed to model "unknown", which is
            # exactly the per-decision attribution WO-H29 added. `debug` and not
            # `warning` on purpose: this runs once per alert, and the value
            # actually STORED already says "unknown", so the data is honest
            # without the log. The log is the trail that explains why.
            logger.debug("triage_model_id_resolution_failed",
                         error=str(e)[:200])
            return "unknown"

    @staticmethod
    def _verdict_drift(before: dict, after: dict) -> list:
        """Return the ways de-anonymization changed a verdict beyond string content.

        WO-S7 invariant. Restoring tokens to their originals may only rewrite
        the CONTENT of string values. It must never:
          * add or remove a top-level key (a duplicate-key injection like
            ``a","verdict":"auto_close","confidence":0.99,"z":"`` shows up as a
            new key, and as a changed decision field);
          * change ``verdict``, ``confidence``, ``escalation_required``,
            ``response_urgency`` or ``kill_chain_stage`` — none of which ever
            legitimately contains a token. The last two are decision fields as
            of WO-H97 (stored, not yet acted on); they are protected NOW so the
            protection is already in place if anything ever consumes them;
          * change the TYPE of any value.

        Returns a list of human-readable drift descriptions; empty means clean.
        """
        drift = []
        if not isinstance(before, dict) or not isinstance(after, dict):
            return ["result is not a dict"]

        added = set(after) - set(before)
        removed = set(before) - set(after)
        if added:
            drift.append(f"keys added: {sorted(map(str, added))}")
        if removed:
            drift.append(f"keys removed: {sorted(map(str, removed))}")

        for key in _PROTECTED_DECISION_FIELDS:
            if key in before and before.get(key) != after.get(key):
                drift.append(
                    f"{key} changed: {before.get(key)!r} -> {after.get(key)!r}")

        for key in set(before) & set(after):
            if type(before[key]) is not type(after[key]):
                drift.append(
                    f"{key} type changed: {type(before[key]).__name__} -> "
                    f"{type(after[key]).__name__}")

        return drift

    def _evaluate_rule_guidance(self, enriched_alert: dict) -> str:
        """WO-H111. Deterministic per-rule checks. Never raises, no I/O.

        Called at the very top of ``triage_alert`` (QA M3) so the result is
        attached to the alert on EVERY path out of triage, including the ones
        that return before the model is ever asked.
        """
        rule_guidance_text = ""
        try:
            # getattr, not a direct call: triage must survive ANY guidance
            # object that predates WO-H111 or stands in for one. The first cut
            # called self.guidance.get_rule_guidance() directly and took the
            # whole triage path down with AttributeError against a stub — the
            # comment below promised guidance could not do that, and it could.
            _getter = getattr(self.guidance, "get_rule_guidance", None)
            rg = _getter() if callable(_getter) else None
            if rg is not None:
                gmatch = rg.evaluate(enriched_alert)
                rule_guidance_text = rg.format_for_prompt(enriched_alert,
                                                          gmatch)
                # Attached whatever the outcome, INCLUDING the failed-load case:
                # severity and the case view must be able to tell "no signal
                # matched" from "guidance could not be read".
                enriched_alert["rule_guidance"] = gmatch.as_record()
        except Exception as e:                                  # noqa: BLE001
            logger.warning("rule_guidance_eval_failed",
                           rule_id=enriched_alert.get("rule_id"),
                           error=str(e)[:200])
            enriched_alert["rule_guidance"] = {
                "state": "failed", "signal": None,
                "entry_found": False, "matched": [],
                "rule_id": str(enriched_alert.get("rule_id") or ""),
            }

        return rule_guidance_text

    def triage_alert(self, enriched_alert: dict,
                     tenant_id: str = None) -> AgentDecision:
        """
        Main triage flow for a single enriched alert.
        Returns an AgentDecision with the verdict and reasoning.

        ``tenant_id`` overrides the global config client_id for decision
        attribution in multi-tenant deployments.
        """
        _decision_tenant = (tenant_id
                            or enriched_alert.get("client_id")
                            or self.config.get("client_id"))
        alert_id = enriched_alert.get("alert_id", str(uuid.uuid4()))
        rule_id = enriched_alert.get("rule_id", 0)
        
        logger.info("triage_started", alert_id=alert_id, rule_id=rule_id)

        # WO-H111 + QA M3: THE DETERMINISTIC CHECK RUNS FIRST.
        #
        # It used to be evaluated just before the LLM call, which is AFTER the
        # always-escalate gate, after the noise prefilter's early return, and
        # after `_fanout_duplicate` — so on any of those paths `severity.py`
        # saw no `rule_guidance` at all and a guidance floor could not fire.
        # A field-exact check we trust more than the model has no business
        # sitting downstream of the heuristics that suppress the model.
        #
        # It is cheap (no I/O, no LLM) and it never raises, so running it for
        # every alert costs nothing and means the record is attached whatever
        # path the alert takes out of here.
        rule_guidance_text = self._evaluate_rule_guidance(enriched_alert)

        enrichment = enriched_alert.get("enrichment", {})

        # ── Pre-AI always-escalate check ──
        # Bypasses Claude entirely for critical patterns defined in
        # escalation_logic.yaml. These alerts go straight to human review.
        escalate_rule = self._check_always_escalate(enriched_alert, enrichment)
        if escalate_rule:
            risk_score = enrichment.get("risk_score", 0)
            reasoning = (
                f"AUTOMATIC ESCALATION — bypassed AI triage.\n"
                f"Matched always-escalate rule: \"{escalate_rule}\".\n"
                f"This alert matched a critical pattern that requires immediate "
                f"human investigation regardless of AI assessment.\n\n"
                f"Enrichment snapshot:\n"
                f"- Asset tier: {enrichment.get('asset_tier', 'unknown')}\n"
                f"- User risk: {enrichment.get('user_risk_level', 'unknown')} "
                f"(multiplier: {enrichment.get('user_risk_multiplier', 'N/A')})\n"
                f"- MITRE tactics: {enriched_alert.get('rule_mitre_tactics', [])}\n"
                f"- MITRE techniques: {enriched_alert.get('rule_mitre_techniques', [])}\n"
                f"- Threat intel hits: {enrichment.get('threat_intel_hits', 0)}\n"
                f"- Known malicious: {enrichment.get('is_known_malicious', False)}\n"
                f"- Baseline anomaly: {enrichment.get('baseline_anomaly', False)}\n"
                f"- Risk score: {risk_score}"
            )

            decision = AgentDecision(
                id=str(uuid.uuid4()),
                alert_id=alert_id,
                rule_id=rule_id,
                # WO-H124: the Wazuh level and the host, as COLUMNS. Both were
                # already known here and neither was persisted — which is what
                # forced WO-H123 onto a proxy that measured 0.94 and failed.
                rule_level=enriched_alert.get("rule_level"),
                agent_name=enriched_alert.get("agent_name"),
                rule_description=enriched_alert.get("rule_description", ""),
                agent_type="triage",
                verdict="true_positive",
                confidence=1.0,
                risk_score=max(risk_score, 90.0),
                reasoning=reasoning,
                # Built by the ONE helper, not a copy of it. This blob used to
                # be hand-duplicated with a comment asking the reader to "keep
                # it consistent with the main triage path" — and it drifted
                # anyway: src_user/dst_user were added in one place only.
                enrichment_summary=self._enrichment_blob(enriched_alert),
                playbook_used=f"always_escalate:{escalate_rule}",
                actions_taken=json.dumps(["Immediate human investigation required"]),
                escalated=True,
                human_override=None,
                human_verdict=None,
                feedback_applied=False,
                created_at=datetime.now(timezone.utc).isoformat(),
                resolved_at=None,
                client_id=_decision_tenant,
                # AIS2: this verdict is a deterministic rule match (not an LLM
                # inference), so it is grounded by definition — the matched
                # always-escalate rule IS the supporting evidence.
                grounding=json.dumps({
                    "grounding": "high",
                    "score": 1.0,
                    "unsupported": [],
                    "reasons": [f"always_escalate rule matched: {escalate_rule}"],
                }),
            )

            self.db.save_decision(decision)
            self.db.record_metric("triage_completed", 1, {
                "verdict": "true_positive",
                "confidence": 1.0,
                "escalated": True,
                "rule_id": rule_id,
                "bypass_reason": escalate_rule
            })

            logger.info("triage_completed_bypass",
                         alert_id=alert_id,
                         verdict="true_positive",
                         bypass_rule=escalate_rule)

            return decision

        # ── WO-H5: cheap deterministic noise pre-filter ──
        # Runs ONLY after the always-escalate gate above has already returned
        # for critical patterns — so the pre-filter is physically unreachable
        # for an always-escalate alert and can never suppress one. It also
        # refuses to dismiss anything with a positive signal (see NoisePreFilter).
        prefilter = getattr(self, "prefilter", None)
        if prefilter is not None and prefilter.is_noise(enriched_alert, enrichment):
            return self._prefilter_dismiss(enriched_alert, _decision_tenant)

        # ── Standard AI triage path ──

        # Build full context
        context = self.enrichment.get_alert_context_for_agent(
            enriched_alert, max_correlated=self.max_context_alerts
        )

        # Select playbook
        playbook = self.select_playbook(enriched_alert)

        # Load guidance documents
        risk_criteria = self.guidance.get_risk_criteria_text()
        escalation_logic = self.guidance.get_escalation_logic_text()

        # WO-H111: per-rule guidance.
        #
        # Evaluated BEFORE the LLM call and attached to the enriched alert, so
        # the deterministic result survives regardless of what the model says.
        # That ordering is the point: the verdict is unstable (WO-H104 measured
        # 5/5 alerts changing verdict on byte-identical prompts at temperature
        # 0), and the one real intrusion of the month measured scored the
        # same 20.83 as 80 benign WinRing0 installs on the same host. A field
        # check does not drift.
        # WO-H113: precedent for this rule — a plain query, not an agent.
        #
        # Fail-soft in the same shape as the guidance block above: a lookup
        # failure returns state="unavailable", which the prompt renders as an
        # explicit warning. It must never arrive as an empty history, because
        # "no analyst has ever labelled this" and "we could not ask" argue in
        # opposite directions.
        precedent = None
        try:
            # QA L1: config lives under `agents.triage`, not top-level
            # `triage`, so the old lookup could never find the key.
            _agents = (self.config.get("agents") or {})
            _days = int((_agents.get("triage") or {}).get(
                "precedent_window_days", 30))
            # QA L6: getattr like the other three new lookups. A store
            # predating WO-H113 would otherwise stamp "UNAVAILABLE" onto every
            # prompt forever — safe direction, wrong answer.
            _lookup = getattr(self.db, "get_rule_precedent", None)
            precedent = (_lookup(enriched_alert.get("rule_id"), days=_days)
                         if callable(_lookup) else None)
        except Exception as e:                                  # noqa: BLE001
            logger.warning("rule_precedent_failed",
                           rule_id=enriched_alert.get("rule_id"),
                           error=str(e)[:200])
            precedent = {"state": "unavailable",
                         "rule_id": enriched_alert.get("rule_id"),
                         "window_days": locals().get("_days", 30),
                         "human_tp": 0, "human_fp": 0,
                         "disagreements": [], "closures": {}}

        # Knowledge Base context injection
        kb_context = ""
        if self.knowledge_base:
            try:
                mitre_techs = enriched_alert.get("rule_mitre_techniques", [])
                rule_desc = enriched_alert.get("rule_description", "")
                kb_context = self.knowledge_base.search_for_agent(
                    rule_description=rule_desc,
                    mitre_techniques=mitre_techs,
                )
            except Exception as e:
                logger.warning("kb_search_failed", error=str(e))

        # Build prompt (anonymizer strips hostnames/internal IPs/usernames)
        system_prompt, user_message = build_triage_prompt(
            alert_context=context,
            risk_criteria=risk_criteria,
            escalation_logic=escalation_logic,
            playbook=playbook,
            auto_close_threshold=self.auto_close_threshold,
            escalation_threshold=self.escalation_threshold,
            anonymizer=self.anonymizer,
            kb_context=kb_context,
            rule_guidance=rule_guidance_text,
            precedent=precedent,
        )

        # Call Claude (timed for audit trail)
        _t0 = time.monotonic()

        # Extract tenant ID for multi-tenant LLM routing
        tenant_id = (enriched_alert.get("tenant_id") or
                    enriched_alert.get("client_id") or
                    self.config.get("client_id") or
                    "default")

        # ── WO-H5: hard per-tenant spend cap (blocks the LLM call) ──
        # Checked against the SAME tenant the LLM call would bill under. When
        # the cap is reached the alert is NOT sent to the LLM; instead it takes
        # the budget fail-safe path, which ESCALATES (never auto-closes).
        # Headroom warnings log before the hard stop.
        budget_guard = getattr(self, "budget_guard", None)
        _budget_reservation_id = None
        if budget_guard is not None:
            # WO-H28: reserve() is the atomic check-AND-debit — it serializes
            # per tenant on a DB advisory lock and counts in-flight
            # reservations, so N parallel workers can no longer all pass the
            # same pre-call spend check and overshoot the cap. Falls back to
            # check() for stub guards without reserve (older tests/plugins).
            _reserve = getattr(budget_guard, "reserve", None) or budget_guard.check
            budget_status = _reserve(tenant_id)
            _budget_reservation_id = budget_status.get("reservation_id")
            if budget_status.get("warn"):
                logger.warning("triage_budget_headroom_warning",
                               tenant_id=tenant_id,
                               spend=round(budget_status["spend"], 4),
                               cap=budget_status["cap"],
                               utilization=round(budget_status["utilization"], 4),
                               warn_threshold=budget_status["warn_threshold"])
            if not budget_status.get("allowed", True):
                logger.warning("triage_budget_exhausted_blocking_llm",
                               tenant_id=tenant_id,
                               spend=round(budget_status["spend"], 4),
                               cap=budget_status["cap"],
                               alert_id=alert_id)
                return self._budget_exhausted_decision(
                    enriched_alert, _decision_tenant, budget_status)

        try:
            try:
                result = self._call_claude(system_prompt, user_message, tenant_id)
                # WO-H104 + QA M5. Confirming is a SECOND REAL LLM CALL, so it
                # belongs inside the reservation: outside it, a tenant sitting
                # at its spend cap could be pushed over by a call the budget
                # guard never saw. It runs on the ANONYMIZED result, before
                # de-anonymization, so the second call sends exactly the bytes
                # the first one did.
                result = self._confirm_auto_close(result, system_prompt,
                                                  user_message, tenant_id)
            finally:
                # WO-H28: settle the budget reservation as soon as the call
                # returns (success OR failure) — by now the usage tracker has
                # recorded the real cost row, so the estimate must stop
                # counting against the cap.
                if _budget_reservation_id and budget_guard is not None:
                    budget_guard.release(tenant_id, _budget_reservation_id)
                    _budget_reservation_id = None
            _latency_ms = int((time.monotonic() - _t0) * 1000)
            # Deanonymize structured fields (verdict, actions) but keep
            # reasoning anonymized for secure storage
            result_for_audit = result.copy()  # Anonymized version for audit trail
            result = self.anonymizer.deanonymize_dict(result)
            # WO-S7: de-anonymization restores attacker-influenced text into the
            # verdict. It must only ever change the CONTENT of string leaves —
            # never the document's shape, and never a decision field. The walk
            # in deanonymize_dict guarantees this by construction; this asserts
            # it at the boundary that acts on the result, so a future regression
            # in the anonymizer surfaces as a loud, fail-closed escalation
            # rather than as a silently rewritten verdict.
            _drift = self._verdict_drift(result_for_audit, result)
            if _drift:
                logger.error("deanonymization_altered_verdict",
                             rule_id=enriched_alert.get("rule_id"),
                             drift=_drift,
                             detail="de-anonymization changed decision fields "
                                    "or document shape — possible injection via "
                                    "a tokenized identity value. Using the "
                                    "pre-restoration decision fields.")
                for _k in _PROTECTED_DECISION_FIELDS:
                    if _k in result_for_audit:
                        result[_k] = result_for_audit[_k]
            # Preserve anonymized reasoning in audit — don't store real identifiers
            if result_for_audit.get("reasoning"):
                result["_anonymized_reasoning"] = result_for_audit["reasoning"]
        except Exception as e:
            _latency_ms = int((time.monotonic() - _t0) * 1000)
            # Sanitize error message to prevent API key leakage in stored records
            import re as _re
            _raw_err = str(e)
            # M2 fix: the old pattern stopped at the first '-', leaking the
            # suffix of modern hyphenated keys (sk-ant-..., sk-proj-...). The
            # 'sk-' alternative now allows an optional ant-/proj- segment and
            # internal hyphens/underscores.
            #
            # M2 remediation: the 'sk-'/'key-' anchors had NO left boundary, so
            # ordinary prose ending in 'sk'/'key' followed by a hyphen got eaten
            # (e.g. "disk-space-...", "turnkey-..."). The (?<![\w-]) negative
            # lookbehind requires those anchors to start at a token boundary,
            # leaving hyphenated prose untouched while still fully redacting
            # real keys. The long-hex alternative is unbounded by design.
            _safe_err = _re.sub(
                r'((?<![\w-])sk-(?:ant-|proj-)?[a-zA-Z0-9_-]{10,}'
                r'|(?<![\w-])key-[a-zA-Z0-9]{10,}'
                r'|[a-f0-9]{40,})',
                '[REDACTED]', _raw_err)
            logger.error("triage_call_failed", alert_id=alert_id, error=_raw_err)
            # Fail safe: escalate on error.
            # WO-H46-b: `_llm_failed` marks this row as a FAILURE rather than a
            # verdict. The verdict/confidence/escalation fields below are
            # deliberately unchanged — failing closed is the correct safety
            # behaviour and must stay byte-identical. The flag exists so the
            # failure is queryable and alertable (it is otherwise
            # indistinguishable from a considered escalation in the `verdict`
            # column) and so un-analyzed rows can be excluded from FP
            # statistics that feed the prompt and the tuning loop.
            result = {
                "verdict": "needs_investigation",
                "confidence": 0.0,
                "reasoning": f"Triage agent error: {_safe_err}. Escalating for manual review.",
                "key_findings": ["Agent error - manual review required"],
                "recommended_actions": ["Manual investigation required"],
                "escalation_required": True,
                "escalation_reason": f"Agent error: {_safe_err}",
                "detection_feedback": {"rule_quality": "unknown"},
                "_llm_failed": True,
            }

        # Validate and clamp LLM output to prevent malicious overrides
        VALID_VERDICTS = {"true_positive", "false_positive", "needs_investigation", "auto_close"}
        verdict = result.get("verdict", "needs_investigation")
        if verdict not in VALID_VERDICTS:
            logger.warning("invalid_llm_verdict", raw_verdict=verdict, alert_id=alert_id)
            verdict = "needs_investigation"
        confidence = result.get("confidence", 0.0)
        try:
            confidence = max(0.0, min(1.0, float(confidence)))
        except (TypeError, ValueError):
            confidence = 0.0
        risk_override = result.get("risk_score_override")
        if risk_override is not None:
            try:
                risk_override = max(0, min(100, int(risk_override)))
            except (TypeError, ValueError):
                risk_override = None
            result["risk_score_override"] = risk_override
        escalated = result.get("escalation_required", False)

        # ── Deterministic verdict guard — runs BEFORE the verdict is accepted ──
        # Reads ONLY structured enrichment, never the model's output, so nothing
        # a threat actor can write into an alert field reaches this decision. A
        # dismissal laid over a TI hit / known-malicious IOC / tier-1 asset is
        # overridden to needs_investigation and forced to a human. The model's
        # original verdict is retained for audit and for FP analytics.
        #
        # This exists because the <untrusted_data> instructional boundary is not
        # reliably honoured by small local models (see src/agents/verdict_guard.py),
        # and because production logs show the cloud provider also emitting
        # ungrounded dismissals. Placed before the threshold logic below, which
        # can only ever set escalated=True — so nothing downstream un-escalates.
        verdict_guard = evaluate_verdict_guard(verdict, enrichment)
        if verdict_guard["triggered"]:
            result["ai_verdict"] = verdict_guard["original_verdict"]
            result["verdict_guard"] = verdict_guard
            verdict = verdict_guard["verdict"]
            escalated = True
            result["escalation_required"] = True
            result["escalation_reason"] = verdict_guard["reason"]
            logger.warning("verdict_guard_override",
                           alert_id=alert_id,
                           rule_id=rule_id,
                           ai_verdict=verdict_guard["original_verdict"],
                           forced_verdict=verdict,
                           ai_confidence=f"{confidence:.2f}",
                           triggers=verdict_guard["triggers"],
                           evidence=verdict_guard["evidence"],
                           model_backend=self._resolve_model_id(tenant_id))
            self.db.record_metric("verdict_guard_override", 1, {
                "agent": "triage",
                "ai_verdict": verdict_guard["original_verdict"],
                "forced_verdict": verdict,
                "triggers": ",".join(verdict_guard["triggers"]),
                "rule_id": rule_id,
            })

        # Check for per-rule tuning overrides. The resolver enforces a hard
        # floor: an override can only RAISE the auto-close bar, never lower it,
        # so the operator's configured ceiling on automated dismissal always
        # holds. See resolve_auto_close_threshold() for why both branches used to
        # be able to defeat it, automatically and invisibly.
        rule_override = self.db.get_tuning_override(rule_id)
        effective_auto_close_threshold, _tuning_action, _tuning_floored = (
            resolve_auto_close_threshold(
                self.auto_close_threshold, rule_override, verdict))

        if _tuning_floored:
            # The feedback loop asked for a LOWER bar and was refused. Worth a
            # warning, not an info: it means auto-tune is actively trying to
            # re-enable auto-close for this rule against operator config.
            logger.warning("tuning_override_floored",
                           rule_id=rule_id, action=_tuning_action,
                           requested=rule_override.get("confidence_override")
                           if rule_override else None,
                           configured_floor=self.auto_close_threshold,
                           effective=effective_auto_close_threshold,
                           detail="Per-rule tuning override requested an "
                                  "auto-close threshold below the configured "
                                  "floor; clamped to the configured value.")
            self.db.record_metric("tuning_override_floored", 1, {
                "agent": "triage",
                "action": str(_tuning_action),
                "rule_id": rule_id,
            })
        elif _tuning_action:
            logger.info("tuning_override_applied",
                        rule_id=rule_id, action=_tuning_action,
                        threshold=effective_auto_close_threshold)

        # Per-alert confidence adjustment from human override history
        feedback_applied = False
        override_learning = None
        try:
            override_stats = self.db.get_override_stats_for_rule(rule_id)
            if override_stats and override_stats["direction"] != "mixed":
                original_confidence = confidence
                delta = override_stats["confidence_delta"]
                if override_stats["direction"] == "upgrade":
                    confidence = min(1.0, confidence + delta)
                else:  # downgrade
                    confidence = max(0.0, confidence - delta)
                feedback_applied = True
                override_learning = {
                    "original_confidence": round(original_confidence, 4),
                    "adjusted_confidence": round(confidence, 4),
                    "delta": delta,
                    "direction": override_stats["direction"],
                    "override_count": override_stats["total_overrides"],
                    "override_window_days": override_stats["window_days"],
                }
                logger.info("confidence_adjusted_from_overrides",
                            rule_id=rule_id,
                            original=f"{original_confidence:.2f}",
                            adjusted=f"{confidence:.2f}",
                            delta=delta,
                            direction=override_stats["direction"],
                            override_count=override_stats["total_overrides"])
        except Exception as e:
            logger.warning("override_learning_failed", rule_id=rule_id,
                           error=str(e))

        # WO-H60 SAFETY GATE — when auto-close is held shut, EVERY AI dismissal
        # still goes to a human, whatever its confidence.
        #
        # Why this exists: WO-H60 fixed `historical_fp_rate` to count the
        # ANALYST's disposition instead of the agent's own past guesses. On the
        # noisiest rules that moves the number the agent sees from ~0% to
        # 90-100% — which is the truth, and is exactly the signal the system was
        # designed to use, but it is a large step change in what the agent
        # believes. An agent that suddenly has strong evidence a rule is benign
        # may start auto-closing it, and auto-close SUPPRESSES the alert without
        # a human ever seeing it.
        #
        # So the corrected signal is rolled out with the suppression path held
        # shut: the agent may still SAY "false positive" (and that verdict is
        # recorded, and feeds the loop), but a human confirms every dismissal.
        # Open it deliberately, as its own decision, once the new verdicts have
        # been observed to match what analysts would have said.
        #
        # Defaults to True so existing installs are unchanged by this release.
        # getattr default: several tests (and any partially-constructed
        # agent) bypass __init__, and a missing attribute must not crash
        # triage — it falls back to the shipped default of enabled.
        _auto_close_on = getattr(self, "auto_close_enabled", True)
        if not _auto_close_on and verdict in ("auto_close", "false_positive"):
            result["ai_verdict"] = verdict
            escalated = True
            result["escalation_reason"] = (
                f"Auto-close is disabled (auto_close_enabled=false) — AI verdict "
                f"'{verdict}' at confidence {confidence:.2f} held for human review"
            )
            logger.info("auto_close_held_shut",
                        alert_id=alert_id, rule_id=rule_id,
                        ai_verdict=verdict, confidence=f"{confidence:.2f}")
        # Escalate low-confidence auto-dismissals for human review,
        # but preserve the AI's original verdict for analytics/feedback.
        elif verdict in ("auto_close", "false_positive") and confidence < effective_auto_close_threshold:
            result["ai_verdict"] = verdict
            escalated = True
            result["escalation_reason"] = (
                f"Auto-dismiss confidence {confidence:.2f} below threshold "
                f"{effective_auto_close_threshold}"
            )

        if confidence < self.escalation_threshold and not escalated:
            escalated = True
            result["escalation_reason"] = (
                f"Confidence {confidence:.2f} below escalation threshold "
                f"{self.escalation_threshold}"
            )

        # ── AIS2: independent, evidence-derived grounding check ──
        # Deterministic faithfulness tripwire — verifies the verdict is
        # consistent with the STRUCTURED enrichment evidence and that any
        # evidence_refs the model cited actually exist. This is independent of
        # the model's self-reported confidence: it FLAGS a confident-but-
        # unsupported verdict for analyst attention; it never auto-closes or
        # auto-escalates on its own.
        grounding_assessment = assess_triage_grounding(
            verdict=verdict,
            confidence=confidence,
            evidence_refs=result.get("evidence_refs"),
            enrichment=enrichment,
        )
        grounding_json = json.dumps(grounding_assessment, default=str)
        _safety = output_safety_metrics(
            result.get("reasoning", ""), anonymizer=self.anonymizer)
        if grounding_assessment["grounding"] == "low":
            logger.warning("triage_low_grounding",
                           alert_id=alert_id,
                           verdict=verdict,
                           confidence=f"{confidence:.2f}",
                           score=grounding_assessment["score"],
                           reasons=grounding_assessment["reasons"],
                           unsupported=grounding_assessment["unsupported"])
        else:
            logger.info("triage_grounding_assessed",
                        alert_id=alert_id,
                        grounding=grounding_assessment["grounding"],
                        score=grounding_assessment["score"])
        self.db.record_metric("output_grounding", 1, {
            "agent": "triage",
            "verdict": verdict,
            "grounding": grounding_assessment["grounding"],
            "score": grounding_assessment["score"],
            "token_leaks": _safety["token_leaks"],
            "injection_echoes": _safety["injection_echoes"],
            "breakout_markers": _safety["breakout_markers"],
        })

        # Build decision record
        decision = AgentDecision(
            id=str(uuid.uuid4()),
            alert_id=alert_id,
            rule_id=rule_id,
            # WO-H124: the Wazuh level and the host, as COLUMNS. Both were
            # already known here and neither was persisted — which is what
            # forced WO-H123 onto a proxy that measured 0.94 and failed.
            rule_level=enriched_alert.get("rule_level"),
            agent_name=enriched_alert.get("agent_name"),
            rule_description=enriched_alert.get("rule_description", ""),
            agent_type="triage",
            verdict=verdict,
            confidence=confidence,
            risk_score=result.get("risk_score_override") or enriched_alert.get("enrichment", {}).get("risk_score", 0),
            reasoning=result.get("reasoning", ""),
            # THE MAIN TRIAGE PATH — this writes the great majority of
            # decisions. It shares the one blob builder with the always-escalate
            # and cost-control paths; only the extras below differ.
            #
            # Verdict provenance. ``ai_verdict`` is the model's ORIGINAL verdict
            # whenever anything overrode it — the deterministic verdict guard,
            # the auto_close_enabled hold (WO-H60), or the low-confidence
            # auto-dismiss escalation. It was previously set on ``result`` and
            # then dropped on the floor, never persisted anywhere, so an
            # overridden verdict was unauditable and invisible to the feedback
            # loop. That silently broke WO-H60's stated guarantee that the loop
            # keeps learning while auto-close is held shut. Additive JSON keys —
            # no schema migration, and no consumer of enrichment_summary breaks.
            enrichment_summary=self._enrichment_blob(enriched_alert, {
                **({"override_learning": override_learning}
                   if override_learning else {}),
                **({"ai_verdict": result["ai_verdict"]}
                   if result.get("ai_verdict") else {}),
                **({"verdict_guard": verdict_guard}
                   if verdict_guard["triggered"] else {}),
            }),
            playbook_used=playbook[:100] if playbook else None,
            actions_taken=json.dumps(result.get("recommended_actions", [])),
            escalated=escalated,
            human_override=None,
            human_verdict=None,
            feedback_applied=feedback_applied,
            created_at=datetime.now(timezone.utc).isoformat(),
            resolved_at=None if escalated else datetime.now(timezone.utc).isoformat(),
            client_id=_decision_tenant,
            grounding=grounding_json,
            # WO-H46-b: True only on the fail-closed LLM-error path above.
            llm_failed=bool(result.get("_llm_failed", False)),
            # WO-H97 SHADOW FIELDS — stored, read by nothing. The model has
            # answered both on every alert since the prompt was written; the
            # values were already sitting in `result` and were dropped on the
            # floor. Nothing downstream branches on them: severity comes from
            # src/incidents/severity.py, which takes the risk score and
            # structured alert facts only. This starts the clock on measuring
            # whether the answers are worth anything, on real traffic.
            response_urgency=_clamp_shadow_field(
                result.get("response_urgency"), VALID_RESPONSE_URGENCY,
                "response_urgency", alert_id),
            kill_chain_stage=_clamp_shadow_field(
                result.get("kill_chain_stage"), VALID_KILL_CHAIN_STAGES,
                "kill_chain_stage", alert_id),
        )

        # Save decision
        self.db.save_decision(decision)

        # Save audit trail for compliance explainability
        try:
            version_info = self.guidance.get_version_info()
            enrichment = enriched_alert.get("enrichment", {})
            self.db.save_decision_audit_trail({
                "decision_id": decision.id,
                "prompt_version": version_info.get("prompt_version", PROMPT_VERSION),
                "guidance_version": json.dumps(version_info.get("guidance_hashes", {})),
                "playbook_name": playbook[:100] if playbook else None,
                "risk_breakdown": json.dumps(enrichment.get("risk_breakdown", {})),
                "enrichment_inputs": json.dumps({
                    "asset_tier": enrichment.get("asset_tier"),
                    "user_risk_level": enrichment.get("user_risk_level"),
                    "threat_intel_hits": enrichment.get("threat_intel_hits", 0),
                    "is_known_malicious": enrichment.get("is_known_malicious", False),
                    "baseline_anomaly": enrichment.get("baseline_anomaly", False),
                    "baseline_deviation": enrichment.get("baseline_deviation", 0),
                    "historical_fp_rate": enrichment.get("historical_fp_rate", 0),
                    "override_learning_applied": feedback_applied,
                    "override_learning_delta": override_learning["delta"] if override_learning else 0,
                    # Deterministic verdict guard: what the model said, what it
                    # was forced to, and which hard-evidence condition forced it.
                    "verdict_guard_triggered": verdict_guard["triggered"],
                    "verdict_guard_triggers": verdict_guard["triggers"],
                    "verdict_guard_ai_verdict": (
                        verdict_guard["original_verdict"]
                        if verdict_guard["triggered"] else None),
                }),
                # WO-H29 (NEW-3): resolved concrete provider/model id of the
                # backend that ACTUALLY produced this verdict (was the dead
                # constant 'cli' — _claude_backend_type was never set), so a
                # silent provider/model swap is attributable per-decision. Routed
                # by the same tenant_id used for the LLM call above.
                "model_backend": self._resolve_model_id(tenant_id),
                "latency_ms": _latency_ms,
                "created_at": decision.created_at,
            })
        except Exception as e:
            logger.warning("audit_trail_save_failed", error=str(e))

        # Record detection feedback as a feedback pattern
        feedback = result.get("detection_feedback", {})
        if feedback.get("false_positive_pattern"):
            pattern = FeedbackPattern(
                id=str(uuid.uuid4()),
                pattern_type="recurring_fp",
                rule_id=rule_id,
                description=feedback["false_positive_pattern"],
                occurrence_count=1,
                first_seen=datetime.now(timezone.utc).isoformat(),
                last_seen=datetime.now(timezone.utc).isoformat(),
                auto_action_taken=None,
                status="active"
            )
            self.db.upsert_feedback_pattern(pattern)

        # Record metrics
        self.db.record_metric("triage_completed", 1, {
            "verdict": verdict,
            "confidence": confidence,
            "escalated": escalated,
            "rule_id": rule_id,
            "feedback_applied": feedback_applied,
        })

        logger.info("triage_completed",
                     alert_id=alert_id,
                     verdict=verdict,
                     confidence=f"{confidence:.2f}",
                     escalated=escalated)

        return decision

    # WO-H23: whitelisted display-safe fields copied from a
    # ``threat_intel_details`` entry into the trimmed, persisted match record.
    # External indicators + feed metadata only — never a client identity field.
    _TI_MATCH_FIELDS = ("indicator", "type", "source", "severity",
                        "category", "last_seen", "description")
    _TI_MATCH_MAX = 10

    @staticmethod
    def _ti_match_summary(enrichment: dict) -> list:
        """Trim ``threat_intel_details`` to a display-safe subset (WO-H23).

        ``threat_intel_details`` is deliberately EXCLUDED from the persisted
        ``enrichment_summary`` blob (it can be large and feed-shape-specific).
        This re-adds a TRIMMED, DISPLAY-ONLY projection so the analyst can see
        the EXACT matched indicator behind ``is_known_malicious`` inline in the
        case view. Only whitelisted feed/indicator fields are copied — never a
        raw feed object — and the list is capped.

        LLM BOUNDARY (honest, and the canonical note for ALL of WO-H23's new
        display-only keys — ``threat_intel_match``, ``host_top_cve_details``,
        ``host_rootcheck_signatures``, ``host_fim_changed_paths``):

          * ``build_triage_prompt`` reads a FIXED allowlist of enrichment keys
            that does NOT include any of these, so they never reach the triage
            LLM. ``build_hunt_prompt`` takes aggregate patterns, not the blob —
            also walled off.
          * ``build_detection_prompt`` is DIFFERENT: it serializes the WHOLE
            persisted ``enrichment_summary`` blob for each FP example
            (``json.dumps(...)[:300]``) and passes it through
            ``anonymizer.anonymize_fp_text``. So these fields DO egress to the
            DETECTION LLM — but only AFTER anonymization tokenizes registered
            client identifiers (and truncated to 300 chars). This is the
            documented detection posture (per ``_DETECTION_EXCLUDE_KEYS``,
            file-path / command free-text is verbatim-by-design; only REGISTERED
            identifiers are tokenized), and WO-H23 does not change it — it just
            adds more free-text (FIM paths, rootcheck signatures) into that same
            already-anonymized detection channel. The matched INDICATOR here is
            an external threat indicator (un-anonymized by design), not a client
            identity field.

        This method itself runs at PERSIST time only. Defensive: any non-list /
        bad entry degrades to []."""
        details = enrichment.get("threat_intel_details") \
            if isinstance(enrichment, dict) else None
        if not isinstance(details, list):
            return []
        matches: list = []
        for entry in details:
            if not isinstance(entry, dict):
                continue
            trimmed: dict = {}
            for k in TriageAgent._TI_MATCH_FIELDS:
                v = entry.get(k)
                if v is None or v == "" or v == []:
                    continue
                trimmed[k] = v
            # Derive a human-readable category from feed-specific fields when no
            # explicit one is present (OTX pulse names / tags).
            if "category" not in trimmed:
                cat = entry.get("pulse_names") or entry.get("tags")
                if isinstance(cat, list) and cat:
                    trimmed["category"] = ", ".join(str(c) for c in cat[:3])
            if trimmed.get("indicator"):
                matches.append(trimmed)
            if len(matches) >= TriageAgent._TI_MATCH_MAX:
                break
        return matches

    def _enrichment_blob(self, enriched_alert: dict, extra: dict = None) -> str:
        """Build the persisted enrichment_summary blob consistent with the main
        and always-escalate paths (host/network fields + MITRE lists), with an
        optional ``extra`` merged in (e.g. a cost_control marker)."""
        enrichment = enriched_alert.get("enrichment", {})
        blob = {
            **{k: v for k, v in enrichment.items()
               if k not in ("threat_intel_details",)},
            "agent_name": enriched_alert.get("agent_name"),
            "agent_ip": enriched_alert.get("agent_ip"),
            "src_ip": enriched_alert.get("src_ip"),
            "dst_ip": enriched_alert.get("dst_ip"),
            # WHO. normalize_alert() resolves these from data.srcuser /
            # data.dstuser and the prompt has always shown them, but they were
            # never persisted — so every consumer of enrichment_summary (the
            # case view, the feedback loop's FP-example selector, any later
            # analysis) could see the host and the source IP but never the
            # account. On rule 5501/5402 the account is the ONLY identity the
            # alert carries: PAM and sudo logs contain no source IP at all.
            "src_user": enriched_alert.get("src_user"),
            "dst_user": enriched_alert.get("dst_user"),
            "rule_mitre_techniques": enriched_alert.get("rule_mitre_techniques", []),
            "rule_mitre_tactics": enriched_alert.get("rule_mitre_tactics", []),
            # WO-H23: trimmed, display-only TI match (see _ti_match_summary).
            "threat_intel_match": self._ti_match_summary(enrichment),
        }
        if extra:
            blob.update(extra)
        return json.dumps(blob, default=str)

    def _budget_exhausted_decision(self, enriched_alert: dict,
                                   tenant: str, status: dict) -> AgentDecision:
        """WO-H5 fail-safe: the tenant's LLM spend cap is reached, so NO LLM
        call is made. SAFETY INVARIANT — this path ESCALATES and is *never*
        auto-closed: the verdict is hard-coded to ``needs_investigation`` and
        ``escalated=True`` here so a budget-exhausted alert can never become a
        ``false_positive``/``auto_close``."""
        alert_id = enriched_alert.get("alert_id", str(uuid.uuid4()))
        rule_id = enriched_alert.get("rule_id", 0)
        enrichment = enriched_alert.get("enrichment", {})
        reasoning = (
            "BUDGET-EXHAUSTED FAIL-SAFE — AI triage was NOT performed because "
            f"this tenant's LLM spend cap for the period was reached "
            f"(${status.get('spend', 0):.2f} / ${status.get('cap', 0):.2f}). "
            "Per the cost-control safety invariant this alert is ESCALATED for "
            "human review; it is never auto-closed on budget grounds."
        )
        now = datetime.now(timezone.utc).isoformat()
        decision = AgentDecision(
            id=str(uuid.uuid4()),
            alert_id=alert_id,
            rule_id=rule_id,
            # WO-H124: the Wazuh level and the host, as COLUMNS. Both were
            # already known here and neither was persisted — which is what
            # forced WO-H123 onto a proxy that measured 0.94 and failed.
            rule_level=enriched_alert.get("rule_level"),
            agent_name=enriched_alert.get("agent_name"),
            rule_description=enriched_alert.get("rule_description", ""),
            agent_type="triage",
            verdict="needs_investigation",   # SAFETY: never auto_close/false_positive
            confidence=0.0,
            risk_score=enrichment.get("risk_score", 0),
            reasoning=reasoning,
            enrichment_summary=self._enrichment_blob(enriched_alert, {
                "cost_control": {
                    "budget_exhausted": True,
                    "spend_usd": round(status.get("spend", 0), 4),
                    "cap_usd": round(status.get("cap", 0), 4),
                },
            }),
            playbook_used="cost_control:budget_exhausted",
            actions_taken=json.dumps(
                ["Manual investigation required (LLM budget cap reached)"]),
            escalated=True,                  # SAFETY: always escalate
            human_override=None,
            human_verdict=None,
            feedback_applied=False,
            created_at=now,
            resolved_at=None,                # escalated => unresolved
            client_id=tenant,
            grounding=json.dumps({
                "grounding": "not_assessed",
                "score": 0.0,
                "unsupported": [],
                "reasons": ["budget_exhausted fail-safe — no LLM inference performed"],
            }),
        )
        self.db.save_decision(decision)
        self.db.record_metric("triage_budget_exhausted", 1, {
            "verdict": "needs_investigation",
            "escalated": True,
            "rule_id": rule_id,
            "spend": round(status.get("spend", 0), 4),
            "cap": round(status.get("cap", 0), 4),
        })
        logger.warning("triage_completed_budget_exhausted",
                       alert_id=alert_id,
                       verdict="needs_investigation",
                       escalated=True)
        return decision

    def _prefilter_dismiss(self, enriched_alert: dict,
                           tenant: str) -> AgentDecision:
        """WO-H5: dismiss an obviously-benign noise alert WITHOUT an LLM call.
        Only reachable for non-critical alerts (the always-escalate gate returns
        before the pre-filter is consulted)."""
        pf = self.prefilter
        alert_id = enriched_alert.get("alert_id", str(uuid.uuid4()))
        rule_id = enriched_alert.get("rule_id", 0)
        enrichment = enriched_alert.get("enrichment", {})
        verdict = pf.verdict if pf.verdict in (
            "auto_close", "false_positive") else "auto_close"
        now = datetime.now(timezone.utc).isoformat()
        reasoning = (
            "PRE-FILTER DISMISSAL — matched a deterministic known-noise rule "
            f"(rule_id={rule_id}, rule_level={enriched_alert.get('rule_level', 0)}, "
            f"risk_score={enrichment.get('risk_score', 0)}) with no threat-intel "
            "hit, not known-malicious, and no baseline anomaly. Dismissed before "
            "the LLM call to save cost. Not applicable to always-escalate "
            "critical patterns (those bypass the pre-filter entirely)."
        )
        decision = AgentDecision(
            id=str(uuid.uuid4()),
            alert_id=alert_id,
            rule_id=rule_id,
            # WO-H124: the Wazuh level and the host, as COLUMNS. Both were
            # already known here and neither was persisted — which is what
            # forced WO-H123 onto a proxy that measured 0.94 and failed.
            rule_level=enriched_alert.get("rule_level"),
            agent_name=enriched_alert.get("agent_name"),
            rule_description=enriched_alert.get("rule_description", ""),
            agent_type="triage",
            verdict=verdict,
            confidence=pf.confidence,
            risk_score=enrichment.get("risk_score", 0),
            reasoning=reasoning,
            enrichment_summary=self._enrichment_blob(enriched_alert, {
                "cost_control": {"prefilter_dismissed": True},
            }),
            playbook_used="cost_control:prefilter",
            actions_taken=json.dumps(["Dismissed as known noise (pre-filter)"]),
            escalated=False,
            human_override=None,
            human_verdict=None,
            feedback_applied=False,
            created_at=now,
            resolved_at=now,                 # dismissed => resolved
            client_id=tenant,
            grounding=json.dumps({
                "grounding": "not_assessed",
                "score": 0.0,
                "unsupported": [],
                "reasons": ["deterministic noise pre-filter — no LLM inference"],
            }),
        )
        self.db.save_decision(decision)
        self.db.record_metric("triage_prefilter_dismissed", 1, {
            "verdict": verdict,
            "rule_id": rule_id,
        })
        logger.info("triage_completed_prefilter",
                    alert_id=alert_id, verdict=verdict)
        return decision

    def _fanout_duplicate(self, enriched_alert: dict, rep: dict,
                          tenant: str, *, origin: str = "dedup") -> AgentDecision:
        """Clone a representative verdict onto a structurally-identical alert
        WITHOUT a new LLM call. Each reuse still gets its own persisted
        AgentDecision referencing the origin, so the audit trail stays intact.

        ``origin="dedup"`` — WO-H5 in-memory dedup (within the ~300s window).
        ``origin="cache"`` — WO-H57 durable decision cache (across the window /
        restarts); records a cache hit + the token-saving estimate.
        """
        alert_id = enriched_alert.get("alert_id", str(uuid.uuid4()))
        rule_id = enriched_alert.get("rule_id", 0)
        enrichment = enriched_alert.get("enrichment", {})
        now = datetime.now(timezone.utc).isoformat()
        origin_alert_id = rep.get("alert_id")
        if origin == "cache":
            origin_ref = (f"cached decision {origin_alert_id}"
                          if origin_alert_id else "a cached decision")
            reasoning = (
                f"[CACHE] Verdict restored from the persistent decision cache "
                f"(same fingerprint as {origin_ref}); the alert carries no new "
                "threat signal, so no LLM call was made. This reuse is visible "
                "and revocable in Admin → Decision Cache.\n\n"
                f"{rep.get('reasoning', '')}"
            )
            playbook_used = f"cost_control:decision_cache:{rep.get('cache_id')}"
            metric_name = "triage_decision_cache_hit"
        else:
            reasoning = (
                f"[DEDUP] Structurally identical to alert {origin_alert_id} (same "
                "fingerprint) triaged within the dedup window. Verdict fanned out "
                "from that decision — no additional LLM call was made.\n\n"
                f"{rep.get('reasoning', '')}"
            )
            playbook_used = f"cost_control:dedup:{origin_alert_id}"
            metric_name = "triage_dedup_fanout"
        decision = AgentDecision(
            id=str(uuid.uuid4()),
            alert_id=alert_id,
            rule_id=rule_id,
            # WO-H124: the Wazuh level and the host, as COLUMNS. Both were
            # already known here and neither was persisted — which is what
            # forced WO-H123 onto a proxy that measured 0.94 and failed.
            rule_level=enriched_alert.get("rule_level"),
            agent_name=enriched_alert.get("agent_name"),
            rule_description=enriched_alert.get("rule_description", ""),
            agent_type="triage",
            verdict=rep["verdict"],
            confidence=rep["confidence"],
            risk_score=enrichment.get("risk_score", rep.get("risk_score", 0)),
            reasoning=reasoning,
            enrichment_summary=self._enrichment_blob(enriched_alert, {
                "cost_control": {
                    f"{origin}_of": origin_alert_id,
                    "fingerprint": rep.get("fingerprint"),
                },
            }),
            playbook_used=playbook_used[:100],
            actions_taken=rep.get("actions_taken", "[]"),
            escalated=rep["escalated"],
            human_override=None,
            human_verdict=None,
            feedback_applied=False,
            created_at=now,
            resolved_at=None if rep["escalated"] else now,
            client_id=tenant,
            grounding=rep.get("grounding"),
        )
        self.db.save_decision(decision)
        self.db.record_metric(metric_name, 1, {
            "verdict": rep["verdict"],
            "rule_id": rule_id,
            "origin_alert_id": origin_alert_id,
        })
        if origin == "cache":
            cache = getattr(self, "decision_cache", None)
            if cache is not None:
                cache.record_hit(self.db, rep.get("cache_id"))
        logger.info(f"triage_{origin}_fanout",
                    alert_id=alert_id,
                    origin_alert_id=origin_alert_id,
                    verdict=rep["verdict"])
        return decision

    def _process_one(self, enriched_alert: dict,
                     tenant_id: str = None) -> AgentDecision:
        """Process a single alert with WO-H5 structural dedup applied.

        Dedup never applies to an always-escalate critical alert (those cost no
        LLM call and must remain distinct escalations) and never collapses
        across tenants (the fingerprint map is keyed by tenant)."""
        _tenant = (tenant_id
                   or enriched_alert.get("client_id")
                   or self.config.get("client_id")
                   or "default")
        dedup = getattr(self, "deduplicator", None)
        cache = getattr(self, "decision_cache", None)
        enrichment = enriched_alert.get("enrichment", {})
        # QA dedup-signal-drift hardening: a duplicate must NOT inherit a benign
        # representative's verdict if THIS alert's own enrichment carries a
        # threat signal the representative may not have had. Reuse the same
        # positive-signal keys NoisePreFilter treats as disqualifiers so the two
        # controls stay consistent (cheap, no extra DB call).
        # Evidence conditions come from the deterministic verdict guard so this
        # reuse path and the LLM path enforce ONE policy. They were previously
        # duplicated here by hand and had drifted: the guard forbids dismissing
        # a tier_1_critical asset, this gate did not check asset tier, and so a
        # cached benign verdict could be fanned onto a tier-1 alert without the
        # guard ever running. It also now covers degraded enrichment — an alert
        # whose TI/asset lookup failed must not inherit a benign verdict, since
        # "no signal" and "we could not look" are indistinguishable here.
        # A True here makes reuse unsafe, so the alert goes to real triage.
        has_positive_signal = bool(
            blocking_evidence(enrichment)
            or enrichment.get("baseline_anomaly")
        )
        # THE SHARED SAFETY GATE for BOTH reuse mechanisms (in-memory dedup and
        # the WO-H57 durable cache): re-evaluated on THIS alert, so a stored
        # benign verdict is never reused for an alert that itself carries a
        # threat signal or must always escalate. Neither reuse path is reachable
        # unless this holds — that is the no-suppression invariant.
        reuse_safe = (
            not has_positive_signal
            and not self._check_always_escalate(enriched_alert, enrichment)
        )
        # Degraded enrichment is deliberately NOT part of reuse_safe above, and
        # the difference between the two reuse mechanisms is the whole point:
        #
        #   * The DURABLE CACHE replays a verdict decided earlier, under
        #     enrichment conditions that may have been healthy. Reusing it now
        #     would apply a benign conclusion to an alert we cannot currently
        #     evaluate — so degradation blocks it.
        #   * IN-MEMORY DEDUP collapses alerts that are structurally identical
        #     and arriving in the same window. Under degradation they are all
        #     equally unknown, so collapsing them adds no risk — they share one
        #     verdict either way.
        #
        # Treating both alike (the first cut of this fix) meant a threat-intel
        # outage disabled duplicate collapsing fleet-wide, multiplying LLM spend
        # by the duplicate factor at precisely the moment the platform was
        # already degraded — and handing anyone who can disrupt TI lookups a
        # cheap way to flood the analyst queue.
        _unknown_evidence = evidence_unavailable(enrichment)
        cache_reuse_safe = reuse_safe and not _unknown_evidence
        if _unknown_evidence and reuse_safe:
            logger.warning("decision_cache_blocked_by_degraded_enrichment",
                           rule_id=enriched_alert.get("rule_id"),
                           sources=degraded_evidence_sources(enrichment),
                           detail="Durable verdict reuse suspended while "
                                  "evidence enrichers are degraded; in-memory "
                                  "dedup still collapses duplicates.")

        dedup_enabled = dedup is not None and dedup.enabled
        cache_enabled = cache is not None and cache.enabled
        fingerprint = None
        if reuse_safe and (dedup_enabled or cache_enabled):
            # Same structural fingerprint for both reuse paths.
            fingerprint = AlertDeduplicator.fingerprint(enriched_alert)
            # 1) In-memory dedup window (WO-H5) — fastest, collapses bursts.
            if dedup_enabled:
                rep = dedup.lookup(_tenant, fingerprint)
                if rep is not None and _unknown_evidence and not rep.get(
                        "evidence_degraded"):
                    # The representative was judged while evidence WAS
                    # available; this duplicate arrives while it is not. The
                    # indicator may have appeared on a feed since and we cannot
                    # check, so the "equally unknown" argument that keeps dedup
                    # enabled under degradation does not hold here.
                    logger.warning("dedup_blocked_stale_evidence_state",
                                   rule_id=enriched_alert.get("rule_id"),
                                   sources=degraded_evidence_sources(enrichment),
                                   detail="Representative was decided with "
                                          "evidence available; this duplicate "
                                          "is not. Routing to full triage.")
                    rep = None
                if rep is not None:
                    return self._fanout_duplicate(enriched_alert, rep, _tenant)
            # 2) Durable decision cache (WO-H57) — BELOW the in-memory window,
            #    so a recurring alert reuses its verdict for $0 after the window
            #    expired / the process restarted. Independent of dedup being on.
            if cache_enabled and cache_reuse_safe:
                cached = cache.lookup(self.db, fingerprint)
                if cached is not None:
                    return self._fanout_duplicate(
                        enriched_alert, cached, _tenant, origin="cache")

        decision = self.triage_alert(enriched_alert, tenant_id=tenant_id)

        if reuse_safe and fingerprint is not None:
            # Register as the in-memory representative for later duplicates.
            if dedup_enabled:
                dedup.register(_tenant, fingerprint, decision,
                               evidence_degraded=bool(_unknown_evidence))
            # WO-H57: write-through to the durable cache when the verdict is
            # confident + benign (see PersistentDecisionCache.should_cache). A
            # human-confirmed override later upgrades the entry via the feedback
            # loop; this first-pass write is only the LLM's own benign call.
            # Gated on cache_reuse_safe, not just should_cache: a verdict
            # reached while the evidence enrichers were degraded must not be
            # memoized for max_age_hours (168h default) and replayed later. The
            # READ side three lines up already refuses such entries; leaving the
            # WRITE ungated made safety depend on a transitive chain (VALID_VERDICTS
            # rejecting the risky verdicts, plus the guard force-escalating
            # dismissals) rather than on the flag that already exists here.
            if cache_enabled and cache_reuse_safe and cache.should_cache(decision):
                cache.store(
                    self.db, fingerprint, decision,
                    rule_description=enriched_alert.get("rule_description", ""),
                    entity_summary=self._cache_entity_summary(enriched_alert))
        return decision

    @staticmethod
    def _cache_entity_summary(alert: dict) -> str:
        """A short human-readable entity line for the Decision Cache tab, so an
        admin can see WHAT a cached entry matches without reversing a hash. Uses
        only the structural entities already in the fingerprint (no raw PII)."""
        parts = []
        for label, key in (("host", "agent_name"), ("agent", "agent_id"),
                           ("src", "src_ip"), ("dst", "dst_ip"),
                           ("user", "src_user")):
            val = alert.get(key)
            if val:
                parts.append(f"{label}={val}")
        return ", ".join(parts)

    def process_batch(self, enriched_alerts: list[dict],
                      tenant_id: str = None) -> list[AgentDecision]:
        """Process a batch of enriched alerts.

        When ``tenant_id`` is provided, it overrides the global config
        client_id for decision attribution — critical for multi-tenant
        deployments where different alerts belong to different tenants.
        """
        decisions = []
        for alert in enriched_alerts:
            try:
                decision = self._process_one(alert, tenant_id=tenant_id)
                decisions.append(decision)
            except Exception as e:
                logger.error("triage_batch_item_failed",
                             alert_id=alert.get("alert_id"),
                             error=str(e))
        
        # Log batch metrics
        if decisions:
            verdicts = {}
            for d in decisions:
                verdicts[d.verdict] = verdicts.get(d.verdict, 0) + 1
            logger.info("triage_batch_completed",
                         total=len(decisions),
                         verdicts=verdicts)
        
        return decisions
