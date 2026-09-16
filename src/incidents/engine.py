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
from src.timestamps import normalize_iso8601, parse_iso8601
from src.incidents.severity import SeverityPolicy, risk_band, severity_rank
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
        # WO-H73: how many MEMBER ALERTS must have been genuinely triaged before
        # this incident may be called an attack chain. A row whose triage errored
        # (llm_failed, no human verdict) is an escalation-by-default, not a
        # judgement — see count_triaged_incident_alerts. Observed on the live
        # estate 2026-08-10: three CRITICAL five-stage chains
        # (Initial Access → … → Lateral Movement) built entirely from routine
        # administrative SSH, several members carrying
        # "Triage agent error: RetryError[ReadTimeout]. Escalating for manual
        # review." Set to 0 to restore the previous behaviour.
        self.attack_chain_min_triaged = chain_cfg.get("min_triaged_alerts", 1)
        # WO-H97 — deterministic severity floors/ceilings, owned by
        # config/guidance/escalation_logic.yaml. Loaded the same way SLAManager
        # loads sla_targets from the same file, and reloadable in place via
        # POST /api/guidance/reload (see reload_severity_policy).
        self._guidance = None
        self.severity_policy = SeverityPolicy()
        _policy_load = self.reload_severity_policy()
        if _policy_load.get("status") != "ok":
            # Startup must not swallow what the reload endpoint would report.
            logger.error("severity_policy_startup_degraded",
                         detail=_policy_load.get("message",
                                                 _policy_load.get("status")))
        logger.info("incident_engine_initialized",
                     window_minutes=self.grouping_window_minutes,
                     attack_chain_enabled=self.attack_chain_enabled,
                     attack_chain_window_minutes=self.attack_chain_window_minutes,
                     attack_chain_min_tactics=self.attack_chain_min_tactics,
                     attack_chain_min_triaged=self.attack_chain_min_triaged)

    @staticmethod
    def _rejection_summary(rejected: list) -> str:
        return "; ".join("%s (%s): %s" % (r["kind"], r["entry"], r["reason"])
                         for r in rejected[:5])

    def reload_severity_policy(self) -> dict:
        """(Re)load the severity floors/ceilings from the guidance YAML.

        **THE SWAP IS ATOMIC ON A RELOAD.** If any entry is unusable, the whole
        new policy is discarded and the one already running stays running. This
        matches the enrichment reload's own contract ("a failure must not leave
        the service permanently half-reloaded") and it is the safe direction: a
        typo in the ceiling must not delete a floor that was protecting you.

        WO-H97 QA (D2 then D3-round-3). The first fix reported a rejection as a
        failure but had ALREADY assigned the partial policy, so the endpoint
        said "NOT applied" while the previously working loss-of-visibility floor
        had in fact been deleted from the running service — an operator reading
        that message would believe they were still protected. Now the message
        and the reality agree on both paths:

          * reload with rejections  -> nothing changes, "NOT applied", and the
            counts returned are the counts STILL IN FORCE.
          * FIRST load with rejections -> there is no previous policy to keep,
            so the usable entries are applied and the response says exactly
            which entries are not active. Discarding everything here would mean
            one typo in the ceiling silently costs you the floor at startup.

        Guidance that cannot be loaded at all is fail-open in the same way: the
        engine keeps the policy it has (an empty one at startup, i.e. pure risk
        bands) and reports the failure rather than swallowing it.
        """
        try:
            from src.guidance.loader import GuidanceLoader
            first_load = self._guidance is None
            if first_load:
                self._guidance = GuidanceLoader(self.config)
            else:
                self._guidance.reload()
            policy = SeverityPolicy.from_guidance(
                self._guidance._escalation_logic)

            if policy.rejected and not first_load:
                # Keep what is running. Report the counts that are ACTUALLY in
                # force, not the counts of the policy we just threw away.
                live = self.severity_policy
                logger.error("severity_policy_reload_rejected",
                             rejected=policy.rejected,
                             kept_floors=len(live.floors),
                             kept_ceilings=len(live.ceilings))
                return {
                    "status": "error",
                    "floors": len(live.floors),
                    "ceilings": len(live.ceilings),
                    "rejected": list(policy.rejected),
                    "message": (
                        "%d severity_policy entr%s unusable, so NOTHING was "
                        "applied — the policy already loaded is still in force "
                        "(%d floor(s), %d ceiling(s)). Fix and reload: %s"
                        % (len(policy.rejected),
                           "y is" if len(policy.rejected) == 1 else "ies are",
                           len(live.floors), len(live.ceilings),
                           self._rejection_summary(policy.rejected))),
                }

            self.severity_policy = policy
            result = {"status": "ok",
                      "floors": len(policy.floors),
                      "ceilings": len(policy.ceilings),
                      "rejected": list(policy.rejected)}
            if policy.rejected:
                # First load only — see the docstring.
                result["status"] = "error"
                result["message"] = (
                    "severity_policy applied WITHOUT %d unusable entr%s, which "
                    "%s NOT active (%d floor(s), %d ceiling(s) are): %s"
                    % (len(policy.rejected),
                       "y" if len(policy.rejected) == 1 else "ies",
                       "is" if len(policy.rejected) == 1 else "are",
                       len(policy.floors), len(policy.ceilings),
                       self._rejection_summary(policy.rejected)))
                logger.error("severity_policy_loaded_with_rejections",
                             floors=len(policy.floors),
                             ceilings=len(policy.ceilings),
                             rejected=policy.rejected)
            else:
                logger.info("severity_policy_loaded",
                            floors=len(policy.floors),
                            ceilings=len(policy.ceilings))
            return result
        # SystemExit is caught DELIBERATELY: GuidanceLoader raises it when a
        # required guidance file is missing or will not decrypt. Refusing to
        # START on that is correct, and the triage agent still enforces it at
        # construction. Refusing to keep RUNNING is a different decision: this
        # method is called from the /api/guidance/reload handler, where an
        # admin's bad edit must produce a reported failure, not a dead process.
        #
        # WO-H97 QA (D3): the first version of this comment claimed the engine
        # was the only place that could kill the process from that handler. It
        # was not — health.py called triage_agent.guidance.reload() unguarded,
        # first. That call is now guarded too, so the claim is true; if either
        # guard is ever removed, fix this comment as well.
        except (Exception, SystemExit) as e:        # noqa: BLE001
            logger.warning("severity_policy_load_failed", error=str(e)[:200])
            return {"status": "error", "message": str(e)[:200]}

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

    def _compute_severity(self, risk_score: float, verdict: str,
                          enriched_alert: dict = None) -> str:
        """Severity for one alert: the risk band, then the guidance policy.

        WO-H97. Two things changed here and both are deliberate.

        **``verdict == "true_positive"`` no longer forces critical.** It used to
        be the first clause of this function, so a confirmed "a port is exposed"
        and a confirmed intrusion were the same severity. On a live tenant
        1,444 decisions were critical solely via that clause. ``verdict``
        is still a parameter and is still logged — it is part of the audit line
        for how this severity was reached — but it does not decide.

        **The band comes from ``src/incidents/severity.py``**, which is the one
        ladder shared with the SPA (80 / 55 / 30), and the floors/ceilings come
        from ``config/guidance/escalation_logic.yaml``. See that module for why
        the boundary moved off the cold-start prior's 75.00.

        ``enriched_alert`` is optional so that callers with only a decision (and
        the existing tests) still work; without it no floor or ceiling can fire
        and the result is the pure risk band.
        """
        return self._evaluate_severity(risk_score, verdict, enriched_alert)[0]

    def _evaluate_severity(self, risk_score: float, verdict: str,
                           enriched_alert: dict = None) -> tuple:
        """``(severity, applied)`` — the severity plus the policy entries that
        moved it.

        Callers that only want the string use ``_compute_severity``.
        ``process_decision`` needs ``applied`` because a FLOOR has to survive
        the verdict: see the ``_floored`` guard there.
        """
        band = risk_band(risk_score)
        if not isinstance(enriched_alert, dict):
            return band, []

        enrichment = enriched_alert.get("enrichment")
        enrichment = enrichment if isinstance(enrichment, dict) else {}
        try:
            severity, applied = self.severity_policy.apply(
                band, enriched_alert, enrichment)
        except Exception as e:                      # noqa: BLE001
            # A severity computation must never take the incident pipeline
            # down. Fall back to the pure band and say so.
            logger.warning("severity_policy_failed",
                           rule_id=enriched_alert.get("rule_id"),
                           band=band, error=str(e)[:200])
            return band, []

        # An unlearned rule is not silently invisible: it lands in `high` (the
        # cold-start prior scores 75.00), and it says so in the ops log as well
        # as in the case view. NOTE ``applied`` lists every entry that MATCHED,
        # each carrying ``moved`` — a floor that matched without changing the
        # number still counts, because it still outranks the verdict.
        breakdown = enrichment.get("risk_breakdown")
        unlearned = (isinstance(breakdown, dict)
                     and breakdown.get("confident") is False)

        if applied or unlearned:
            logger.info("incident_severity_computed",
                        rule_id=enriched_alert.get("rule_id"),
                        risk_score=risk_score,
                        verdict=verdict,
                        band=band,
                        severity=severity,
                        unlearned_rule=unlearned,
                        policy_matched=[a["name"] for a in applied],
                        policy_moved=[a["name"] for a in applied
                                      if a.get("moved")])
        return severity, applied

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
    def _normalize_iso_offset(s: str) -> str:
        """Rewrite a compact ``±HHMM`` UTC offset to the ``±HH:MM`` form.

        Wazuh emits alert timestamps as ``2026-07-28T17:58:36.933+0000`` — a
        valid ISO 8601 offset, but one that ``datetime.fromisoformat`` REJECTS
        on Python < 3.11. Support for the colon-less form was added in 3.11.

        This matters because the platform's own CI and Docker image both accept
        it, while a source-tarball install running the distro's system Python
        (3.10 on Ubuntu 22.04) does not. So this failure is invisible to every
        test and every container, and appears only on the deployments that use
        system Python — which is where it was found:
        ``incident_engine_error ... Invalid isoformat string`` firing on every
        decision, silently preventing incidents from being grouped.

        WO-H116: the implementation now lives in ``src.timestamps`` and is
        shared with every other externally-sourced timestamp in the platform —
        this one-off fix did not propagate, and the same bug killed the triage
        backlog metric.

        qa-audit F8 — THIS IS A TEST SEAM, NOT PRODUCTION CODE. Nothing in
        ``src/`` calls it any more; ``_parse_ts`` goes straight to
        ``src.timestamps.parse_iso8601``. It is kept deliberately, under its
        original name, because it is the subject of the regression test for the
        FIRST time this bug shipped (``tests/test_incident_engine.py``, the
        incident-grouping outage) and that test's value is that it still names
        the thing that broke. Deleting the method would delete the anchor.
        Do not call it from ``src/``; call ``parse_iso8601`` instead.
        """
        return normalize_iso8601(s)

    @classmethod
    def _parse_ts(cls, value: str) -> datetime:
        """Parse an ISO8601 timestamp into an offset-aware datetime (UTC).

        Never raises: an unparseable timestamp falls back to "now". A malformed
        timestamp on ONE alert must not take down incident grouping for every
        alert behind it — which is exactly what the unguarded call did.
        """
        raw = (value or datetime.now(timezone.utc).isoformat())
        try:
            return parse_iso8601(raw)
        except (ValueError, TypeError):
            logger.warning("incident_ts_unparseable", value=str(value)[:64],
                           detail="Falling back to now(); incident grouping "
                                  "continues rather than failing the alert.")
            return datetime.now(timezone.utc)

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
        #
        # A cost-control dismissal counts as benign REGARDLESS of the nominal
        # confidence, because that number does not mean the same thing here as
        # it does on an LLM verdict:
        #
        #   * prefilter — ``confidence`` is the operator's configured floor for
        #     when the filter is ALLOWED to act (``prefilter.confidence``,
        #     shipped at 0.60), not a belief about this alert. The filter has
        #     already refused to dismiss anything carrying blocking evidence, a
        #     baseline anomaly, degraded enrichment, or a critical asset tier.
        #   * dedup / cache — the verdict is copied from an origin decision
        #     that already has its own incident. Re-creating one per copy
        #     duplicates the same finding N times.
        #
        # Reading 0.60 as "not confident enough to skip" defeated the entire
        # point of the pre-filter: it exists to dismiss known noise WITHOUT an
        # LLM call, and every alert it dismissed then opened an incident that
        # nothing would ever close. On a live tenant this was 2,116 of
        # 4,178 open incidents — 51% of the backlog, 1,518 of them stamped
        # critical — produced by two components reading one number in opposite
        # directions.
        _benign = decision.verdict in ("auto_close", "false_positive")
        _cost_control = str(getattr(decision, "playbook_used", "") or "") \
            .startswith("cost_control:")

        # WO-H97 re-audit (2). A DETERMINISTIC FLOOR OUTRANKS THE VERDICT.
        #
        # Both guards below key on the verdict and BOTH run ahead of severity,
        # so a floored `high` used to send nothing whenever the model said
        # false_positive — the early return drops the incident entirely, and
        # `skip_notification` vetoes the notify call even when it survives.
        #
        # That is precisely backwards for a floor. A floor exists because the
        # label cannot be trusted to price the alert: nobody will ever mark a
        # dark host "dangerous", and on SIEM tampering an analyst who has been
        # seeing the platform's own probe files all week will quite reasonably
        # start marking them false positive — which would then silence the real
        # one. Deterministic evidence is not overridable by an opinion about it.
        #
        # Severity is therefore computed FIRST, once, and reused by both
        # branches below.
        severity, _policy_matched = self._evaluate_severity(
            decision.risk_score, decision.verdict, enriched_alert)
        # MATCHED, not moved. A floor whose severity the score already meets is
        # still a floor — it is the statement "this matters regardless of the
        # verdict", and it does not stop being true because the number happened
        # to arrive there on its own. Keying on "moved" inverted the protection:
        # it held at risk 48 and vanished at 75 and 90 (WO-H97 re-audit F2).
        _floored = any(a.get("kind") == "floor" for a in _policy_matched)

        if _benign and (_cost_control or decision.confidence >= 0.85):
            if not _floored:
                logger.debug("incident_skipped_low_value",
                             decision_id=decision.id,
                             verdict=decision.verdict,
                             confidence=decision.confidence,
                             cost_control=_cost_control)
                return
            logger.info("incident_kept_by_severity_floor",
                        decision_id=decision.id,
                        rule_id=decision.rule_id,
                        verdict=decision.verdict,
                        confidence=decision.confidence,
                        severity=severity,
                        floors=[a["name"] for a in _policy_matched
                                if a.get("kind") == "floor"],
                        detail="a benign verdict would normally drop this "
                               "alert, but a deterministic severity floor "
                               "applies — the floor outranks the verdict")

        skip_notification = _benign and not _floored

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
                # WO-H73 note — the triage guard is deliberately NOT here.
                #
                # An earlier version blocked chain LINKING for alerts whose
                # triage had failed. That was the wrong layer: it prevented the
                # incidents merging at all, so a chain could not form even when
                # other members HAD been triaged, and it ignored the config
                # knob. Three tests caught it.
                #
                # The distinction that matters: the alert really happened, so
                # GROUPING it with related alerts is legitimate — grouping is a
                # statement about co-occurrence. What a failed triage cannot
                # support is the ASSERTION that this is a kill chain, which is a
                # statement about intent. That guard lives on the annotation
                # below, where the whole incident's triage history is visible.
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
        # One rank function, shared with the ladder in src/incidents/severity.py.
        sev_order = {s: severity_rank(s)
                     for s in ("low", "medium", "high", "critical")}

        if matched_incident:
            # Add alert to existing incident (updates alert_count in DB)
            self.db.add_alert_to_incident(matched_incident["id"], decision.id)

            # Re-read to get updated alert_count
            matched_incident = self.db.get_incident(matched_incident["id"])

            # Escalate severity if needed (computed once, above).
            new_severity = severity
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
            # WO-H73: tactic count alone is not evidence of an attack. Require
            # that at least one member alert was actually triaged before this
            # incident is titled as a kill chain. Defensive: a failure to count
            # must not block incident processing, so it falls back to allowing
            # the annotation rather than crashing the pipeline.
            triaged_ok = True
            if self.attack_chain_min_triaged > 0:
                try:
                    n_triaged = self.db.count_triaged_incident_alerts(
                        matched_incident["id"])
                    triaged_ok = n_triaged >= self.attack_chain_min_triaged
                    if not triaged_ok:
                        logger.info(
                            "attack_chain_suppressed_untriaged",
                            incident_id=matched_incident["id"],
                            triaged_alerts=n_triaged,
                            required=self.attack_chain_min_triaged,
                            distinct_tactics=len(ordered),
                            reason="tactics present but no successfully triaged "
                                   "member alert — not asserting a kill chain")
                except Exception as e:
                    logger.warning("attack_chain_triage_check_failed",
                                   incident_id=matched_incident["id"],
                                   error=str(e))
            if triaged_ok and len(ordered) >= self.attack_chain_min_tactics:
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
            # Create new incident (severity computed once, above).
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
