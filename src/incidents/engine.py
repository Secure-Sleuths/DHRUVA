"""
Incident Grouping Engine.
Groups triage decisions into incidents using deterministic rules.
Called after each triage batch in the main alert loop.
"""

import html
import json
import re
import uuid
import structlog
from datetime import datetime, timezone
from typing import Optional

from src.database.store import SOCDatabase, Incident
from src.incidents.sla import SLAManager
from src.mitre.matrix import tactic_index, order_tactics

logger = structlog.get_logger(__name__)


class IncidentEngine:
    """
    Deterministic incident grouping.

    Grouping Rules (evaluated in priority order):
    1. Same src_ip + same rule_group within window -> same incident
    2. Same src_user + same MITRE tactic within window -> same incident
    3. Same agent_id + activity within window -> same incident

    If a new alert matches an open incident's grouping_key -> add to existing.
    If no match -> create new incident.
    """

    def __init__(self, config: dict, db: SOCDatabase,
                 notifications=None,
                 sla_manager: SLAManager = None,
                 soar_engine=None, ticketing_service=None):
        self.config = config
        self.db = db
        self.notifications = notifications
        self.sla_manager = sla_manager
        self.soar_engine = soar_engine
        self.ticketing_service = ticketing_service
        inc_cfg = config.get("incidents", {})
        self.grouping_window_minutes = inc_cfg.get("grouping_window_minutes", 30)
        self.enabled = inc_cfg.get("enabled", True)
        # M5 — attack-chain grouping (deterministic, explainable; no ML).
        chain_cfg = inc_cfg.get("attack_chain", {}) or {}
        self.attack_chain_enabled = chain_cfg.get("enabled", True)
        self.attack_chain_window_minutes = chain_cfg.get("window_minutes", 120)
        self.attack_chain_min_tactics = chain_cfg.get("min_distinct_tactics", 2)
        logger.info("incident_engine_initialized",
                     window_minutes=self.grouping_window_minutes,
                     attack_chain_enabled=self.attack_chain_enabled,
                     attack_chain_window_minutes=self.attack_chain_window_minutes,
                     attack_chain_min_tactics=self.attack_chain_min_tactics)

    def _compute_grouping_keys(self, enriched_alert: dict) -> list[str]:
        """
        Compute all applicable grouping keys for an alert.
        Returns a list ordered by priority (most specific first).
        """
        keys = []
        src_ip = enriched_alert.get("src_ip")
        src_user = enriched_alert.get("src_user")
        agent_id = enriched_alert.get("agent_id")
        rule_groups = enriched_alert.get("rule_groups", [])
        mitre_tactics = enriched_alert.get("rule_mitre_tactics", [])

        # Rule 1: src_ip + rule_group (tightest correlation)
        if src_ip:
            for grp in rule_groups:
                if grp:
                    keys.append(f"ip:{src_ip}|grp:{grp}")

        # Rule 2: src_user + MITRE tactic
        if src_user:
            for tactic in mitre_tactics:
                if tactic:
                    keys.append(f"user:{src_user}|tactic:{tactic}")

        # Rule 3: agent_id (broadest)
        if agent_id and agent_id != "000":
            keys.append(f"agent:{agent_id}|activity")

        # Rule 4: Fallback — group by rule_id when no network/identity context
        if not keys:
            rule_id = enriched_alert.get("rule_id", 0)
            if rule_id:
                keys.append(f"rule:{rule_id}")

        return keys

    def _compute_severity(self, risk_score: float, verdict: str) -> str:
        if verdict == "true_positive" or risk_score >= 75:
            return "critical"
        elif risk_score >= 50:
            return "high"
        elif risk_score >= 25:
            return "medium"
        return "low"

    @staticmethod
    def _sanitize_text(text: str) -> str:
        """Strip HTML tags and escape residual entities from external data."""
        cleaned = re.sub(r"<[^>]*>", "", text)
        return html.escape(cleaned)

    def _generate_title(self, grouping_key: str,
                        enriched_alert: dict) -> str:
        rule_desc = self._sanitize_text(
            enriched_alert.get("rule_description", "Unknown activity"))
        parts = grouping_key.split("|")
        descriptors = []
        for part in parts:
            k, _, v = part.partition(":")
            v = self._sanitize_text(v)
            if k == "ip":
                descriptors.append(f"from {v}")
            elif k == "user":
                descriptors.append(f"by {v}")
            elif k == "grp":
                descriptors.append(f"[{v}]")
            elif k == "tactic":
                descriptors.append(f"({v})")
            elif k == "agent":
                descriptors.append(f"on agent {v}")
        return f"{rule_desc} {' '.join(descriptors)}".strip()[:200]

    @staticmethod
    def _parse_ts(value: str) -> datetime:
        """Parse an ISO8601 timestamp into an offset-aware datetime (UTC)."""
        dt = datetime.fromisoformat(
            (value or datetime.now(timezone.utc).isoformat()).replace("Z", "+00:00")
        )
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    def _within_window(self, last_seen: str, alert_ts: str,
                       window_minutes: int) -> bool:
        """True if alert_ts is within ``window_minutes`` of last_seen.

        Mirrors the offset-aware window check in the keyed match loop.
        """
        return abs((self._parse_ts(alert_ts) - self._parse_ts(last_seen))
                   .total_seconds()) <= window_minutes * 60

    def _known_tactics(self, tactics: list) -> list:
        """Filter a tactic list down to the MITRE-known ones (order preserved)."""
        return [t for t in (tactics or []) if tactic_index(t) is not None]

    def _merge_json_list(self, existing_json: str, new_items: list) -> str:
        existing = json.loads(existing_json or "[]")
        merged = list(set(existing + [i for i in new_items if i]))
        return json.dumps(merged)

    def process_decisions(self, decisions: list,
                          enriched_alerts: list[dict]):
        """
        Main entry point. Called after triage_agent.process_batch().
        Groups decisions into new or existing incidents.
        """
        if not self.enabled:
            return

        alert_map = {a.get("alert_id"): a for a in enriched_alerts}

        for decision in decisions:
            try:
                alert = alert_map.get(decision.alert_id)
                if not alert:
                    continue
                self._process_single(decision, alert)
            except Exception as e:
                logger.error("incident_engine_error",
                             decision_id=decision.id, error=str(e))

    def _process_single(self, decision, enriched_alert: dict):
        """Process a single decision into an incident."""
        # Skip incident creation entirely for auto-closed and high-confidence
        # FP verdicts — these have no operational value and would just clutter
        # the incident database over time. Pattern visibility is already
        # provided by the agent_decisions table and feedback loop.
        if (decision.verdict in ("auto_close", "false_positive")
                and decision.confidence >= 0.85):
            logger.debug("incident_skipped_low_value",
                         decision_id=decision.id,
                         verdict=decision.verdict,
                         confidence=decision.confidence)
            return

        skip_notification = decision.verdict in ("auto_close", "false_positive")

        grouping_keys = self._compute_grouping_keys(enriched_alert)
        if not grouping_keys:
            grouping_keys = [f"standalone:{decision.id}"]

        alert_ts_str = enriched_alert.get(
            "timestamp", datetime.now(timezone.utc).isoformat())

        # Try to match against existing open incidents (exact-keyed bucketing)
        matched_incident = None
        matched_key = grouping_keys[0]
        chain_link = False
        for key in grouping_keys:
            existing = self.db.find_open_incident_by_grouping_key(key)
            if existing and self._within_window(
                    existing["last_seen"], alert_ts_str,
                    self.grouping_window_minutes):
                matched_incident = existing
                matched_key = key
                break

        # M5 — attack-chain linking. If keyed bucketing found nothing, try to
        # extend an open incident on the same host/user whose MITRE tactics
        # form a multi-stage progression with this alert. Deterministic and
        # explainable; defensive — a failure here must never crash incident
        # processing (we fall through to create-new).
        if matched_incident is None and self.attack_chain_enabled:
            try:
                new_tactics = self._known_tactics(
                    enriched_alert.get("rule_mitre_tactics", []))
                if new_tactics:
                    host = enriched_alert.get("agent_name")
                    user = enriched_alert.get("src_user")
                    candidate = self.db.find_open_attack_chain_candidate(
                        host=host, user=user)
                    if candidate and self._within_window(
                            candidate["last_seen"], alert_ts_str,
                            self.attack_chain_window_minutes):
                        existing_tactics = self._known_tactics(
                            json.loads(candidate.get("mitre_tactics") or "[]"))
                        union = set(existing_tactics) | set(new_tactics)
                        if len(union) >= self.attack_chain_min_tactics:
                            matched_incident = candidate
                            matched_key = candidate["grouping_key"]
                            chain_link = True
                            logger.info("attack_chain_link",
                                        incident_id=candidate["id"],
                                        host=host,
                                        new_tactics=new_tactics)
            except Exception as e:
                logger.warning("attack_chain_link_failed", error=str(e))

        now = datetime.now(timezone.utc).isoformat()
        sev_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}

        if matched_incident:
            # Add alert to existing incident (updates alert_count in DB)
            self.db.add_alert_to_incident(matched_incident["id"], decision.id)

            # Re-read to get updated alert_count
            matched_incident = self.db.get_incident(matched_incident["id"])

            # Escalate severity if needed
            new_severity = self._compute_severity(
                decision.risk_score, decision.verdict)
            best_severity = max(
                [matched_incident["severity"], new_severity],
                key=lambda s: sev_order.get(s, 0)
            )

            # Update aggregate metadata
            mitre_tactics = self._merge_json_list(
                matched_incident.get("mitre_tactics", "[]"),
                enriched_alert.get("rule_mitre_tactics", []))
            mitre_techniques = self._merge_json_list(
                matched_incident.get("mitre_techniques", "[]"),
                enriched_alert.get("rule_mitre_techniques", []))
            affected_hosts = self._merge_json_list(
                matched_incident.get("affected_hosts", "[]"),
                [enriched_alert.get("agent_name")])
            affected_users = self._merge_json_list(
                matched_incident.get("affected_users", "[]"),
                [enriched_alert.get("src_user"),
                 enriched_alert.get("dst_user")])
            affected_ips = self._merge_json_list(
                matched_incident.get("affected_ips", "[]"),
                [enriched_alert.get("src_ip"),
                 enriched_alert.get("dst_ip")])

            # M5 — attack-chain annotation (explainability). Any incident that
            # accrues >= min_distinct_tactics distinct KNOWN tactics gets the
            # kill-chain-ordered sequence recorded, regardless of how the alert
            # joined (keyed match or chain link).
            attack_chain_id = matched_incident.get("attack_chain_id")
            attack_chain_tactics = (
                matched_incident.get("attack_chain_tactics") or "[]")
            title = matched_incident["title"]
            ordered = order_tactics(json.loads(mitre_tactics))
            if len(ordered) >= self.attack_chain_min_tactics:
                attack_chain_tactics = json.dumps(ordered)
                attack_chain_id = (matched_incident.get("attack_chain_id")
                                   or str(uuid.uuid4()))
                host = self._sanitize_text(
                    enriched_alert.get("agent_name") or "host")
                title = (f"Attack chain on {host}: "
                         + " → ".join(
                             self._sanitize_text(t) for t in ordered))[:200]
                logger.info("attack_chain_extended",
                            incident_id=matched_incident["id"],
                            attack_chain_id=attack_chain_id,
                            tactics=ordered)
                try:
                    self.db.add_timeline_entry(
                        matched_incident["id"], "attack_chain_extended",
                        "Attack chain: " + " -> ".join(ordered))
                except Exception as e:
                    logger.warning("attack_chain_timeline_failed",
                                   incident_id=matched_incident["id"],
                                   error=str(e))

            updated = Incident(
                id=matched_incident["id"],
                title=title,
                severity=best_severity,
                status=matched_incident["status"],
                grouping_key=matched_incident["grouping_key"],
                alert_count=matched_incident["alert_count"],
                first_seen=matched_incident["first_seen"],
                last_seen=now,
                assigned_to=matched_incident["assigned_to"],
                created_at=matched_incident["created_at"],
                updated_at=now,
                resolved_at=matched_incident["resolved_at"],
                summary=matched_incident["summary"],
                mitre_tactics=mitre_tactics,
                mitre_techniques=mitre_techniques,
                affected_hosts=affected_hosts,
                affected_users=affected_users,
                affected_ips=affected_ips,
                client_id=matched_incident["client_id"],
                attack_chain_id=attack_chain_id,
                attack_chain_tactics=attack_chain_tactics,
            )
            self.db.save_incident(updated)

            logger.info("alert_added_to_incident",
                        incident_id=matched_incident["id"],
                        decision_id=decision.id,
                        chain_link=chain_link)

            # Evaluate SOAR playbooks for new true_positive alerts
            if self.soar_engine and decision.verdict in ("true_positive", "needs_investigation"):
                try:
                    self.soar_engine.evaluate(
                        decision, enriched_alert, matched_incident["id"])
                except Exception as e:
                    logger.error("soar_evaluation_failed",
                                 incident_id=matched_incident["id"],
                                 error=str(e))

            # Notify on true_positive added to existing incident
            if (not skip_notification and self.notifications
                    and decision.verdict == "true_positive"):
                try:
                    self.notifications.notify_incident_escalated(
                        self.db.get_incident(matched_incident["id"]),
                        f"New true_positive alert (risk {decision.risk_score:.0f}) "
                        f"added — rule {decision.rule_id}: "
                        f"{decision.rule_description[:80]}")
                except Exception as e:
                    logger.warning("notification_failed",
                                   event="tp_added", error=str(e))

            # Notify if severity escalated (but not for auto-closed FPs)
            old_sev = matched_incident["severity"]
            if (not skip_notification and self.notifications
                    and best_severity != old_sev
                    and sev_order.get(best_severity, 0) > sev_order.get(old_sev, 0)):
                try:
                    self.notifications.notify_incident_escalated(
                        self.db.get_incident(matched_incident["id"]),
                        f"Severity escalated from {old_sev} to {best_severity}")
                except Exception as e:
                    logger.warning("notification_failed", event="escalated", error=str(e))
        else:
            # Create new incident
            severity = self._compute_severity(
                decision.risk_score, decision.verdict)
            alert_ts = enriched_alert.get("timestamp", now)

            incident = Incident(
                id=str(uuid.uuid4()),
                title=self._generate_title(matched_key, enriched_alert),
                severity=severity,
                status="open",
                grouping_key=matched_key,
                alert_count=1,
                first_seen=alert_ts,
                last_seen=alert_ts,
                assigned_to=None,
                created_at=now,
                updated_at=now,
                resolved_at=None,
                summary=(decision.reasoning[:500]
                         if decision.reasoning else ""),
                mitre_tactics=json.dumps(
                    enriched_alert.get("rule_mitre_tactics", [])),
                mitre_techniques=json.dumps(
                    enriched_alert.get("rule_mitre_techniques", [])),
                affected_hosts=json.dumps(
                    [h for h in [enriched_alert.get("agent_name")] if h]),
                affected_users=json.dumps(
                    [u for u in [enriched_alert.get("src_user"),
                                 enriched_alert.get("dst_user")] if u]),
                affected_ips=json.dumps(
                    [ip for ip in [enriched_alert.get("src_ip"),
                                   enriched_alert.get("dst_ip")] if ip]),
                client_id=decision.client_id,
                attack_chain_id=None,
                attack_chain_tactics="[]",
            )

            self.db.save_incident(incident)
            self.db.add_alert_to_incident(incident.id, decision.id)

            # Set SLA deadlines based on severity
            if self.sla_manager:
                try:
                    self.sla_manager.set_initial_sla(incident.id, severity)
                except Exception as e:
                    logger.warning("sla_set_failed",
                                   incident_id=incident.id, error=str(e))

            # Evaluate SOAR playbooks for automated response
            if self.soar_engine:
                try:
                    self.soar_engine.evaluate(
                        decision, enriched_alert, incident.id)
                except Exception as e:
                    logger.error("soar_evaluation_failed",
                                 incident_id=incident.id, error=str(e))

            # Auto-create ticket in external ticketing system
            if self.ticketing_service:
                try:
                    self.ticketing_service.auto_create_ticket(
                        self.db.get_incident(incident.id))
                except Exception as e:
                    logger.error("ticket_auto_create_failed",
                                 incident_id=incident.id, error=str(e))

            logger.info("incident_created",
                        incident_id=incident.id,
                        grouping_key=matched_key,
                        severity=severity)

            # Notify on critical/high incidents (but not for auto-closed FPs)
            if (not skip_notification and self.notifications
                    and severity in ("critical", "high")):
                try:
                    self.notifications.notify_incident_created(
                        self.db.get_incident(incident.id))
                except Exception as e:
                    logger.warning("notification_failed", event="created", error=str(e))
