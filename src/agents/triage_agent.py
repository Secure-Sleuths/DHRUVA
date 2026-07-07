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
from src.agents.grounding import assess_triage_grounding, output_safety_metrics
from src.agents.prompts import build_triage_prompt, PROMPT_VERSION
from src.anonymization import AlertAnonymizer
from src.database.store import SOCDatabase, AgentDecision, FeedbackPattern
from src.enrichment.service import EnrichmentService
from src.guidance.loader import GuidanceLoader

logger = structlog.get_logger(__name__)


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

        logger.info("triage_agent_initialized",
                     auto_close_threshold=self.auto_close_threshold,
                     always_escalate_rules=len(self._always_escalate_rules),
                     multi_tenant=self.tenant_registry is not None)

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
                rule_description=enriched_alert.get("rule_description", ""),
                agent_type="triage",
                verdict="true_positive",
                confidence=1.0,
                risk_score=max(risk_score, 90.0),
                reasoning=reasoning,
                enrichment_summary=json.dumps({
                    **{k: v for k, v in enrichment.items()
                       if k not in ("threat_intel_details",)},
                    # Keep the escalated-row blob consistent with the main
                    # triage path so worst-first queue rows flatten to non-null
                    # host + techniques (WO-B1).
                    "agent_name": enriched_alert.get("agent_name"),
                    "agent_ip": enriched_alert.get("agent_ip"),
                    "src_ip": enriched_alert.get("src_ip"),
                    "rule_mitre_techniques": enriched_alert.get("rule_mitre_techniques", []),
                    "rule_mitre_tactics": enriched_alert.get("rule_mitre_tactics", []),
                }, default=str),
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
        )

        # Call Claude (timed for audit trail)
        _t0 = time.monotonic()

        # Extract tenant ID for multi-tenant LLM routing
        tenant_id = (enriched_alert.get("tenant_id") or
                    enriched_alert.get("client_id") or
                    self.config.get("client_id") or
                    "default")

        try:
            result = self._call_claude(system_prompt, user_message, tenant_id)
            _latency_ms = int((time.monotonic() - _t0) * 1000)
            # Deanonymize structured fields (verdict, actions) but keep
            # reasoning anonymized for secure storage
            result_for_audit = result.copy()  # Anonymized version for audit trail
            result = self.anonymizer.deanonymize_dict(result)
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
            # Fail safe: escalate on error
            result = {
                "verdict": "needs_investigation",
                "confidence": 0.0,
                "reasoning": f"Triage agent error: {_safe_err}. Escalating for manual review.",
                "key_findings": ["Agent error - manual review required"],
                "recommended_actions": ["Manual investigation required"],
                "escalation_required": True,
                "escalation_reason": f"Agent error: {_safe_err}",
                "detection_feedback": {"rule_quality": "unknown"}
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

        # Check for per-rule tuning overrides
        rule_override = self.db.get_tuning_override(rule_id)
        effective_auto_close_threshold = self.auto_close_threshold

        if rule_override:
            action = rule_override['action_type']
            if action == "threshold_raised" and rule_override.get('confidence_override'):
                # Raise the auto-close bar for this noisy-but-real rule
                effective_auto_close_threshold = rule_override['confidence_override']
                logger.info("tuning_override_applied",
                            rule_id=rule_id, action="threshold_raised",
                            threshold=effective_auto_close_threshold)
            elif action == "baselined" and verdict in ("false_positive", "auto_close"):
                # Rule is baselined with 0 TPs — lower the auto-close threshold
                # so this known-FP rule auto-closes more easily
                effective_auto_close_threshold = min(
                    effective_auto_close_threshold, 0.80)
                logger.info("tuning_override_applied",
                            rule_id=rule_id, action="baselined",
                            lowered_threshold=effective_auto_close_threshold)

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

        # Escalate low-confidence auto-dismissals for human review,
        # but preserve the AI's original verdict for analytics/feedback.
        if verdict in ("auto_close", "false_positive") and confidence < effective_auto_close_threshold:
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
        })

        # Build decision record
        decision = AgentDecision(
            id=str(uuid.uuid4()),
            alert_id=alert_id,
            rule_id=rule_id,
            rule_description=enriched_alert.get("rule_description", ""),
            agent_type="triage",
            verdict=verdict,
            confidence=confidence,
            risk_score=result.get("risk_score_override") or enriched_alert.get("enrichment", {}).get("risk_score", 0),
            reasoning=result.get("reasoning", ""),
            enrichment_summary=json.dumps({
                **{k: v for k, v in enriched_alert.get("enrichment", {}).items()
                   if k not in ("threat_intel_details",)},
                # First-class host/network fields (surfaced by the triage queue
                # via the route's enrichment flattening — WO-B1).
                "agent_name": enriched_alert.get("agent_name"),
                "agent_ip": enriched_alert.get("agent_ip"),
                "src_ip": enriched_alert.get("src_ip"),
                "rule_mitre_techniques": enriched_alert.get("rule_mitre_techniques", []),
                "rule_mitre_tactics": enriched_alert.get("rule_mitre_tactics", []),
                **({"override_learning": override_learning} if override_learning else {}),
            }, default=str),
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
                }),
                "model_backend": getattr(self, '_claude_backend_type', 'cli'),
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
                decision = self.triage_alert(alert, tenant_id=tenant_id)
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
