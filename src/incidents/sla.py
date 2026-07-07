"""
SLA Manager — Computes deadlines, checks breaches, manages escalation tiers.

Uses SLA targets defined in config/guidance/escalation_logic.yaml:
  critical: 15min response, 4hr resolution
  high: 60min response, 24hr resolution
  medium: 240min response, 72hr resolution
  low: 1440min response, 168hr resolution
"""

import uuid
import structlog
from datetime import datetime, timezone, timedelta

logger = structlog.get_logger(__name__)

# Default SLA targets (minutes for response, hours for resolution)
DEFAULT_SLA = {
    "critical": {"response_min": 15, "resolution_hr": 4},
    "high":     {"response_min": 60, "resolution_hr": 24},
    "medium":   {"response_min": 240, "resolution_hr": 72},
    "low":      {"response_min": 1440, "resolution_hr": 168},
}

TIER_ORDER = ["L1", "L2", "L3"]


class SLAManager:
    """Manages SLA deadlines, breach detection, and tier escalation."""

    def __init__(self, config: dict, db, notifications=None):
        self.db = db
        self.notifications = notifications

        # Load SLA targets from escalation logic guidance
        guidance_cfg = config.get("guidance", {})
        self._sla_targets = DEFAULT_SLA.copy()

        # Try to load from escalation_logic.yaml
        try:
            from src.guidance.loader import GuidanceLoader
            loader = GuidanceLoader(config)
            el = loader._escalation_logic
            sla = el.get("sla_targets", {})
            for sev in ("critical", "high", "medium", "low"):
                if sev in sla:
                    self._sla_targets[sev] = {
                        "response_min": sla[sev].get(
                            "initial_response_minutes",
                            DEFAULT_SLA[sev]["response_min"]),
                        "resolution_hr": sla[sev].get(
                            "resolution_hours",
                            DEFAULT_SLA[sev]["resolution_hr"]),
                    }
        except Exception as e:
            logger.warning("sla_config_load_failed", error=str(e))

        logger.info("sla_manager_initialized", targets=self._sla_targets)

    def set_initial_sla(self, incident_id: str, severity: str):
        """Set SLA deadlines on a newly created incident."""
        targets = self._sla_targets.get(severity, self._sla_targets["medium"])
        now = datetime.now(timezone.utc)

        response_due = (now + timedelta(
            minutes=targets["response_min"])).isoformat()
        resolution_due = (now + timedelta(
            hours=targets["resolution_hr"])).isoformat()

        self.db.set_incident_sla(incident_id, "L1", response_due,
                                 resolution_due)

    def record_first_response(self, incident_id: str):
        """Record first analyst response (assign, note, status change)."""
        self.db.record_first_response(incident_id)

    def escalate_tier(self, incident_id: str, new_tier: str,
                      actor: str, handoff_notes: str = ""):
        """Escalate incident to a higher tier and reset SLA clock."""
        incident = self.db.get_incident(incident_id)
        if not incident:
            return False

        current_tier = incident.get("tier", "L1")
        if TIER_ORDER.index(new_tier) <= TIER_ORDER.index(current_tier):
            return False  # Can't de-escalate

        # Recompute SLA for new tier (same severity, fresh clock)
        severity = incident.get("severity", "medium")
        targets = self._sla_targets.get(severity, self._sla_targets["medium"])
        now = datetime.now(timezone.utc)
        response_due = (now + timedelta(
            minutes=targets["response_min"])).isoformat()
        resolution_due = (now + timedelta(
            hours=targets["resolution_hr"])).isoformat()

        self.db.escalate_incident_tier(
            incident_id, new_tier, handoff_notes, actor,
            response_due, resolution_due)

        if self.notifications:
            updated = self.db.get_incident(incident_id)
            if updated:
                self.notifications.notify_tier_escalation(
                    updated, current_tier, new_tier, actor)

        logger.info("incident_tier_escalated",
                     incident_id=incident_id,
                     from_tier=current_tier,
                     to_tier=new_tier,
                     actor=actor)
        return True

    def check_sla_breaches(self):
        """Scan all open incidents for SLA breaches. Run on schedule."""
        incidents = self.db.get_open_incidents_with_sla()
        now = datetime.now(timezone.utc)
        breaches = 0

        for inc in incidents:
            inc_id = inc["id"]

            # Check response SLA
            response_due = inc.get("sla_response_due")
            first_response = inc.get("first_response_at")
            if response_due and not first_response:
                try:
                    due = datetime.fromisoformat(
                        response_due.replace("Z", "+00:00"))
                    if due.tzinfo is None:
                        due = due.replace(tzinfo=timezone.utc)
                    if now > due:
                        self.db.save_sla_breach({
                            "id": str(uuid.uuid4()),
                            "incident_id": inc_id,
                            "sla_type": "response",
                            "severity": inc.get("severity", "medium"),
                            "tier": inc.get("tier", "L1"),
                            "due_at": response_due,
                            "breached_at": now.isoformat(),
                        })
                        breaches += 1
                        if self.notifications:
                            self.notifications.notify_sla_breach(
                                inc, "response")
                except (ValueError, TypeError):
                    pass

            # Check resolution SLA
            resolution_due = inc.get("sla_resolution_due")
            if resolution_due and inc.get("status") != "resolved":
                try:
                    due = datetime.fromisoformat(
                        resolution_due.replace("Z", "+00:00"))
                    if due.tzinfo is None:
                        due = due.replace(tzinfo=timezone.utc)
                    if now > due:
                        self.db.save_sla_breach({
                            "id": str(uuid.uuid4()),
                            "incident_id": inc_id,
                            "sla_type": "resolution",
                            "severity": inc.get("severity", "medium"),
                            "tier": inc.get("tier", "L1"),
                            "due_at": resolution_due,
                            "breached_at": now.isoformat(),
                        })
                        breaches += 1
                        if self.notifications:
                            self.notifications.notify_sla_breach(
                                inc, "resolution")
                except (ValueError, TypeError):
                    pass

        if breaches:
            logger.warning("sla_breaches_detected", count=breaches)
        return breaches
