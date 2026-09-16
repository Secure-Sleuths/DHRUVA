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

from src.timestamps import parse_iso8601

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

    # WO-H101: how many times ONE process re-attempts an undelivered breach
    # notification before giving up on it.
    #
    # Not unbounded, because a permanently broken channel would otherwise
    # re-attempt every open breach every 5 minutes forever, and 2,880 identical
    # ERROR lines a day is its own kind of silence. Not 1 either — that was the
    # regression: a single network blip or a Slack 5xx permanently lost the
    # page. Five attempts spans ~25 minutes of 5-minute cycles.
    #
    # Giving up is not losing the record: the row keeps ``notified = 0``, so a
    # restart — which is what follows any credential or channel fix — re-arms
    # every one of them, and `SELECT * FROM sla_breaches WHERE notified = 0`
    # answers "who was never told" at any time.
    NOTIFY_MAX_ATTEMPTS = 5

    # WO-H101: ceiling on breach announcements per cycle. The FIRST cycle after
    # this ships finds every already-recorded, never-announced breach (all
    # 13,980 rows on the tenant that was measured carried notified = 0) and
    # announces the ones whose incidents are still open — which is the entire
    # point, but it must not arrive as one unbounded burst. The remainder
    # drains on later cycles.
    # Ceiling on announcements per PASS — and a pass is one tenant, because
    # main.py calls set_tenant(tid) then check_sla_breaches() once per tenant.
    NOTIFY_PER_CYCLE_LIMIT = 20

    # How many consecutive passes a ledger entry may go untouched before it is
    # discarded.
    #
    # This replaced a membership test against the current pass's incident list,
    # which was wrong in a way that disabled NOTIFY_MAX_ATTEMPTS entirely:
    # SLAManager is ONE object shared by every tenant, so tenant B's pass
    # deleted every one of tenant A's counters. No counter ever reached the cap,
    # nothing was ever abandoned, and the retry ceiling that exists to prevent a
    # log flood silently did not apply on any multi-tenant install.
    #
    # An entry for a still-open breach is touched on every one of its own
    # tenant's passes, so this only needs to comfortably exceed the tenant
    # count. 200 passes is ~8 hours at two tenants on a 5-minute cycle.
    LEDGER_STALE_PASSES = 200

    def __init__(self, config: dict, db, notifications=None):
        self.db = db
        self.notifications = notifications
        # (incident_id, sla_type) -> {"attempts", "pass", "delivered"} for THIS
        # process. Entries age out by pass (see LEDGER_STALE_PASSES), never by
        # "is this incident in the list I am looking at right now".
        self._notify_attempts: dict = {}
        self._pass_counter = 0

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

    def _delivered_breach_keys(self, incident_ids: list) -> set:
        """``(incident_id, sla_type)`` pairs whose notification WAS DELIVERED.

        Batched: ONE query for the whole pass. The per-incident version this
        replaces was an N+1 — 2,000 open breached incidents cost 4,001 execute
        calls and 1.69s, every 5 minutes, for every tenant.

        This is the distinction the whole work order turns on. A ROW means the
        breach was **detected**. ``notified = 1`` means a channel **accepted the
        message**. They are not the same fact, and the first cut of this change
        conflated them — gating re-announcement on row-existence — which caused
        two regressions:

          * one failed send (a blip, a Slack 5xx, a ``ratelimited`` that our own
            error table describes as "DROPPED, not queued") lost the page
            permanently, because the row was written before the attempt; and
          * the entire pre-existing backlog went silent on the first run after
            deploy — every existing row carries ``notified = 0``, so every one of
            them looked "already announced", including the eight-day-old
            critical attack chain this work order was written about.

        Gating on DELIVERY fixes both at once: an undelivered breach is retried
        (bounded by NOTIFY_MAX_ATTEMPTS), and the backlog announces itself on
        the first cycle because none of it was ever delivered.

        On a read failure this returns the empty set, so we announce. Announcing
        a breach twice is recoverable; never announcing one is the bug. That
        fail-open is only safe because the retry ledger bounds re-announcement
        independently of whatever this read says — see _notify_breach, where
        not popping the entry on success is what makes that true.
        """
        try:
            return self.db.get_notified_breach_keys(incident_ids) or set()
        except Exception as e:                       # noqa: BLE001
            logger.warning("sla_breach_history_read_failed",
                           incidents=len(incident_ids), error=str(e)[:200])
            return set()

    def _ledger(self, incident_id: str, sla_type: str) -> dict:
        """The retry record for one breach, created on first touch."""
        key = (incident_id, sla_type)
        entry = self._notify_attempts.get(key)
        if entry is None:
            entry = {"attempts": 0, "pass": self._pass_counter,
                     "delivered": False}
            self._notify_attempts[key] = entry
        return entry

    def _attempts_so_far(self, incident_id: str, sla_type: str) -> int:
        """Attempts already spent, without creating a ledger entry."""
        entry = self._notify_attempts.get((incident_id, sla_type))
        return entry["attempts"] if entry else 0

    def _is_abandoned(self, incident_id: str, sla_type: str) -> bool:
        """Has this breach already exhausted its retry budget?

        Checked BEFORE the per-pass announcement budget is spent. Consuming a
        slot for a breach that will be refused anyway is how the first
        NOTIFY_PER_CYCLE_LIMIT entries, once abandoned, went on eating the whole
        budget every pass forever — so anything past position 20 was never
        attempted even once, and was never named in any log.

        Touches the entry's pass marker so an abandoned-but-still-open breach
        stays in the ledger rather than ageing out and being silently re-armed.
        """
        entry = self._notify_attempts.get((incident_id, sla_type))
        if entry is None:
            return False
        entry["pass"] = self._pass_counter
        return entry["attempts"] >= self.NOTIFY_MAX_ATTEMPTS

    def _log_abandoned(self, incident_id, sla_type, attempts, *, delivered):
        """Say, once, that this breach will not be attempted again.

        Both ways of exhausting the retry budget end here — the send failing
        every time, and the send succeeding while the ``notified`` write fails
        — because an alarm that fires on only one of them leaves the other
        stopping silently. The two cases say very different things and must not
        share wording: one means nobody was told, the other means somebody was
        told and we could not write it down.
        """
        if delivered:
            logger.error(
                "sla_breach_notification_abandoned",
                incident_id=incident_id, sla_type=sla_type, attempts=attempts,
                delivered=True,
                msg="Stopping re-announcement of this SLA breach after "
                    f"{self.NOTIFY_MAX_ATTEMPTS} attempts. It WAS delivered at "
                    "least once; the notified=1 write is what failed, so the "
                    "row still reads as untold. Check the store for "
                    "mark_sla_breach_notified_failed.")
        else:
            logger.error(
                "sla_breach_notification_abandoned",
                incident_id=incident_id, sla_type=sla_type, attempts=attempts,
                delivered=False,
                msg="Gave up announcing this SLA breach after "
                    f"{self.NOTIFY_MAX_ATTEMPTS} failed attempts — NOBODY HAS "
                    "BEEN TOLD. The row keeps notified=0, so restarting the "
                    "platform retries it. Check GET /api/health -> "
                    "notifications for why sends are failing.")

    def _notify_breach(self, incident: dict, sla_type: str) -> bool:
        """Announce a breach, and record delivery only if it actually happened.

        ``notified = 1`` is written from HERE and nowhere else, and only after
        ``notify_sla_breach()`` has returned True.

        **The ledger entry is never popped, including on full success.** It
        ages out via LEDGER_STALE_PASSES instead. Popping it made
        NOTIFY_MAX_ATTEMPTS unreachable whenever the ``sla_breaches`` READ
        failed: ``get_sla_breaches`` swallows its exceptions and returns ``[]``,
        which reads as "nothing delivered", so the breach was announced again —
        and because the previous success had popped the entry, the attempt
        count restarted from zero every pass. 500 open breached incidents with
        that read failing produced 2,000 pages over 100 passes and a ledger of
        size 0, unbounded in time. A statement timeout on a table that reached
        3.5M rows, or a lock during a migration, is enough to trigger it. With
        the entry retained, re-announcement is bounded by the attempt cap no
        matter what the read says.
        """
        if not self.notifications:
            return False
        if not getattr(self.notifications, "enabled", True):
            # Switched off deliberately. Not a failure, and it must not burn a
            # retry attempt.
            return False

        inc_id = incident.get("id")
        entry = self._ledger(inc_id, sla_type)
        if entry["attempts"] >= self.NOTIFY_MAX_ATTEMPTS:
            return False
        entry["attempts"] += 1
        entry["pass"] = self._pass_counter
        attempts = entry["attempts"]

        try:
            sent = bool(
                self.notifications.notify_sla_breach(incident, sla_type))
        except Exception as e:                       # noqa: BLE001
            # A RAISE is a failed send, not an escape hatch. Letting it
            # propagate burned an attempt with no log line of any kind — no
            # "not notified", no abandon alarm — and aborted the rest of this
            # tenant's pass, so every breach behind this one went unexamined.
            # notify_sla_breach catches HTTPError/URLError/OSError, but
            # http.client.IncompleteRead from resp.read() is none of those.
            logger.error(
                "sla_breach_notification_raised",
                incident_id=inc_id, sla_type=sla_type, attempt=attempts,
                error=str(e)[:200], error_type=type(e).__name__,
                msg="The notification path raised instead of reporting "
                    "failure. Treated as a failed send; it will be retried "
                    "like any other.")
            sent = False

        recorded = False
        if sent:
            entry["delivered"] = True
            recorded = bool(self.db.mark_sla_breach_notified(inc_id, sla_type))
            if recorded:
                logger.info("sla_breach_notified",
                            incident_id=inc_id, sla_type=sla_type,
                            attempts=attempts)
            else:
                logger.error(
                    "sla_breach_notified_but_not_recorded",
                    incident_id=inc_id, sla_type=sla_type, attempts=attempts,
                    msg="The breach notification was DELIVERED but writing "
                        "notified=1 failed, so the next pass will see it as "
                        "undelivered and announce it again. Capped at "
                        f"{self.NOTIFY_MAX_ATTEMPTS} repeats. Check the store "
                        "for mark_sla_breach_notified_failed.")
        elif attempts < self.NOTIFY_MAX_ATTEMPTS:
            logger.error(
                "sla_breach_not_notified",
                incident_id=inc_id, sla_type=sla_type, attempt=attempts,
                max_attempts=self.NOTIFY_MAX_ATTEMPTS,
                msg="An SLA breach was recorded but no notification channel "
                    "accepted it — nobody has been told yet. Will retry on the "
                    "next pass. Check GET /api/health -> notifications.")

        # ONE exhaustion tail for every route out of this method. Each route
        # that had its own copy of this check was a route that could stop
        # silently — and ``delivered`` is read from the ledger rather than
        # hardcoded per-route, because a breach delivered on attempt 1 whose
        # channel then dies for attempts 2-5 was being reported as "NOBODY HAS
        # BEEN TOLD" when somebody had.
        #
        # Gated on the OUTCOME, not on the attempt count alone. Consolidating
        # the tail made it fire on a route that is not an exhaustion at all: a
        # breach that fails four times and then SUCCEEDS and is RECORDED on
        # attempt 5 reaches this line having gone perfectly right. It then
        # logged an abandon ERROR telling the operator the notified=1 write had
        # failed and to go looking for a mark_sla_breach_notified_failed line
        # that does not exist. Nothing is abandoned when the last attempt
        # delivered AND was written down — there is nothing left to retry.
        if attempts >= self.NOTIFY_MAX_ATTEMPTS and not (sent and recorded):
            self._log_abandoned(inc_id, sla_type, attempts,
                                delivered=entry["delivered"])
        return sent

    def _announce(self, pending: list):
        """Spend this pass's announcement budget on the breaches that need it.

        Two rules, both of them fixes for ways the tail of the list went
        permanently unheard:

          * **Least-tried first.** THIS is what prevents starvation. Ordering
            by attempts means a breach never tried outranks one that has, so
            the tail is reached on the very next pass. Without it, and with a
            broken channel, the first NOTIFY_PER_CYCLE_LIMIT entries ate every
            slot on every pass forever — a 31-breach backlog on a 20-slot
            budget left 11 breaches never attempted once, never named in a log,
            and still silent after the operator fixed the channel.

          * **Abandoned breaches are skipped without spending a slot.** BELT
            AND BRACES ONLY, and honestly labelled as such: the sort above
            already places exhausted entries last, so removing this check
            changes no observed behaviour and no test fails. It is kept because
            it makes the intent explicit and because it stops depending on the
            sort for correctness — but do not describe it as tested, because
            it is not.
        """
        if not pending:
            return

        pending.sort(key=lambda p: self._attempts_so_far(p[0]["id"], p[1]))

        attempted = 0
        deferred = 0
        for incident, sla_type in pending:
            if self._is_abandoned(incident["id"], sla_type):
                continue
            if attempted >= self.NOTIFY_PER_CYCLE_LIMIT:
                deferred += 1
                continue
            attempted += 1
            self._notify_breach(incident, sla_type)

        if deferred:
            # Expected while a never-announced backlog drains. Not an error —
            # just say it, so a partial burst is never mistaken for the whole
            # story.
            logger.warning(
                "sla_breach_notifications_deferred",
                deferred=deferred, per_cycle_limit=self.NOTIFY_PER_CYCLE_LIMIT,
                msg="More undelivered SLA breaches than one pass announces; "
                    "the rest follow on subsequent passes, least-tried first.")

    def _prune_ledger(self):
        """Drop retry counters that no pass has touched for a long time.

        Ages entries out by PASS, never by membership of the current pass's
        incident list — see LEDGER_STALE_PASSES for why that distinction is
        what makes NOTIFY_MAX_ATTEMPTS work on a multi-tenant install.
        """
        if not self._notify_attempts:
            return
        cutoff = self._pass_counter - self.LEDGER_STALE_PASSES
        stale = [k for k, v in self._notify_attempts.items()
                 if v["pass"] < cutoff]
        for k in stale:
            del self._notify_attempts[k]

    def check_sla_breaches(self):
        """Scan all open incidents for SLA breaches. Run on schedule."""
        incidents = self.db.get_open_incidents_with_sla()
        now = datetime.now(timezone.utc)
        breaches = 0
        self._pass_counter += 1

        # Detection and announcement are two phases on purpose. Announcing
        # inline meant the per-pass budget was spent in incident order, so a
        # permanently failing head of the list starved the tail out of ever
        # being attempted. Collect first, then dispatch least-tried-first.
        pending = []
        # (incident_id, sla_type) pairs already delivered, for the WHOLE pass.
        # Resolved lazily on the first breach detected, so a pass with nothing
        # breached still costs no extra query.
        delivered = None

        for inc in incidents:
            inc_id = inc["id"]

            # Check response SLA
            response_due = inc.get("sla_response_due")
            first_response = inc.get("first_response_at")
            if response_due and not first_response:
                try:
                    # WO-H116: version-independent parse (stored TEXT column).
                    due = parse_iso8601(response_due)
                    if now > due:
                        if delivered is None:
                            delivered = self._delivered_breach_keys(
                                [i["id"] for i in incidents])
                        needs_announcing = (inc_id, "response") not in delivered
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
                        # WO-H101: announce until DELIVERED, not once on
                        # detection. See _delivered_breach_types.
                        if needs_announcing:
                            pending.append((inc, "response"))
                except (ValueError, TypeError):
                    pass

            # Check resolution SLA
            resolution_due = inc.get("sla_resolution_due")
            if resolution_due and inc.get("status") != "resolved":
                try:
                    # WO-H116: version-independent parse (stored TEXT column).
                    due = parse_iso8601(resolution_due)
                    if now > due:
                        if delivered is None:
                            delivered = self._delivered_breach_keys(
                                [i["id"] for i in incidents])
                        needs_announcing = (inc_id, "resolution") not in delivered
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
                        # WO-H101: announce until DELIVERED, not once on
                        # detection.
                        if needs_announcing:
                            pending.append((inc, "resolution"))
                except (ValueError, TypeError):
                    pass

        self._announce(pending)
        self._prune_ledger()

        if breaches:
            logger.warning("sla_breaches_detected", count=breaches)
        return breaches
