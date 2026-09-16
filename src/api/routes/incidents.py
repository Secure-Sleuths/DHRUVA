"""Incident management routes."""

import json
import threading
import structlog
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from src.api.auth import verify_jwt, require_role
from src.api.dependencies import (
    get_db, get_triage_agent, get_notifications, get_sla_manager,
    get_knowledge_base, get_config, limiter,
)
from src.api.feature_gates import require_license_feature
from src.database.store import anonymized_fields_for
from src.timestamps import parse_iso8601
from src.api.models import (
    IncidentAssignRequest, IncidentStatusRequest, IncidentNoteRequest,
    IncidentMergeRequest, BatchSummaryRequest, PLAIN_SUMMARY_PROMPT,
    EvidenceRequest, IncidentReviewRequest, FlagInterestingRequest,
    IncidentVerdictPropagationRequest,
)

router = APIRouter(prefix="/api/incidents")
logger = structlog.get_logger(__name__)

# Module-level lock for batch summary generation (thread-safe initialization)
_batch_summary_lock = threading.Lock()


def _build_plain_summary_message(anon, incident: dict, alerts: list) -> str:
    """Build the plain-summary LLM message — anonymized AND injection-guarded.

    WO-S14. Both plain-summary paths previously computed an anonymized copy of
    the incident, used it ONLY for affected_hosts/users/ips, and then
    interpolated the RAW ``incident['title']`` and the raw
    ``agent_decisions.reasoning`` straight into the prompt. Titles are built as
    "Attack chain on <host> by <user> from <ip>", and the reasoning is
    explicitly DE-anonymized before storage in triage_agent — so real client
    hostnames, usernames and IPs egressed to the third-party LLM provider on
    every generation, while the product docs and the operator's contract state
    that identifiers are tokenized before leaving the platform.

    Every attacker-influenced field is now (a) anonymized and (b) wrapped in
    ``<untrusted_data>`` via ``sanitize_for_prompt``, which the injection guard
    now prepended to PLAIN_SUMMARY_PROMPT governs.

    One helper, used by BOTH the interactive and the batch path, so the two
    cannot drift apart again — the scan found the identical defect in both.
    """
    from src.agents.prompts import sanitize_for_prompt

    def _clean(value) -> str:
        return sanitize_for_prompt(anon.anonymize_free_text(str(value or "")))

    anon_incident = anon.anonymize_incident(incident)

    alert_details = []
    for a in alerts[:5]:
        reasoning = (a.get("reasoning") or "N/A")[:300]
        alert_details.append(
            f"Rule {a.get('rule_id')}: {_clean(a.get('rule_description', ''))}\n"
            f"  Verdict: {a.get('verdict')} "
            f"(confidence {a.get('confidence', 0):.0%})\n"
            f"  Risk score: {a.get('risk_score', 0)}/100\n"
            f"  Summary: {_clean(reasoning)}\n"
        )

    return (
        f"Incident: {_clean(anon_incident.get('title'))}\n"
        f"Severity: {incident.get('severity')}\n"
        f"Status: {incident.get('status')}\n"
        f"Affected machines: {anon_incident.get('affected_hosts', '[]')}\n"
        f"Affected users: {anon_incident.get('affected_users', '[]')}\n"
        f"Affected IPs: {anon_incident.get('affected_ips', '[]')}\n"
        f"Total alerts: {incident.get('alert_count', 0)}\n"
        f"First seen: {incident.get('first_seen', '')}\n"
        f"Last seen: {incident.get('last_seen', '')}\n\n"
        f"Technical alert details:\n" + "\n".join(alert_details)
    )


def _check_incident_access(user: dict, incident: dict, incident_id: str):
    """Enforce ownership: analysts can only act on incidents assigned to them.

    Admin and senior_analyst bypass this check (can act on any incident).
    Raises 403 if analyst tries to act on an unassigned or others' incident.
    """
    role = user.get("role", "")
    if role in ("mssp_admin", "admin", "senior_analyst"):
        return
    assigned_to = incident.get("assigned_to") or ""
    actor = user.get("sub", "")
    if not assigned_to or assigned_to != actor:
        raise HTTPException(
            status_code=403,
            detail="Incident is not assigned to you",
        )


@router.get("")
@limiter.limit("200/minute")
async def get_incidents(
    request: Request,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    assigned_to: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    sort: str = Query("newest",
                      description="newest (when DHRUVA created the incident, "
                                  "the default), event_time (the alert's own "
                                  "timestamp — the previous behaviour), or "
                                  "oldest"),
    user: dict = Depends(verify_jwt),
):
    """List incidents with optional filters.

    Defaults to ``newest`` — DHRUVA's own clock. Ordering by the alert's
    timestamp is correct for "when did this happen" and wrong for a work queue:
    when triage falls behind, freshly-created incidents carry old alert times
    and sort below stale ones. On 2026-08-12 that hid 666 incidents created in
    five hours and the team reported no new alerts were arriving.
    """
    _db = get_db()
    incidents = _db.get_incidents(
        status=status, severity=severity,
        assigned_to=assigned_to, limit=limit, offset=offset, sort=sort,
    )
    return {"incidents": incidents, "total": len(incidents),
            "offset": offset, "sort": sort}


@router.get("/sla-at-risk")
async def get_sla_at_risk(
    user: dict = Depends(verify_jwt),
    _gate: None = Depends(require_license_feature("sla")),
):
    """Get incidents approaching SLA breach (< 30% time remaining)."""
    _db = get_db()
    incidents = _db.get_open_incidents_with_sla()
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)

    at_risk = []
    for inc in incidents:
        for sla_field in ("sla_response_due", "sla_resolution_due"):
            due_str = inc.get(sla_field)
            if not due_str:
                continue
            try:
                # WO-H116: version-independent parse (stored TEXT column).
                due = parse_iso8601(due_str)
                remaining = (due - now).total_seconds()
                if remaining < 0 or remaining < 900:  # breached or < 15 min
                    at_risk.append({
                        "incident_id": inc["id"],
                        "title": inc.get("title", ""),
                        "severity": inc.get("severity", ""),
                        "tier": inc.get("tier", "L1"),
                        "sla_type": "response" if "response" in sla_field else "resolution",
                        "remaining_sec": max(0, int(remaining)),
                    })
            except (ValueError, TypeError):
                continue

    return {"at_risk": at_risk, "count": len(at_risk)}


@router.get("/interesting")
async def get_interesting_incidents(
    limit: int = Query(20, ge=1, le=100),
    user: dict = Depends(verify_jwt),
):
    """List incidents flagged as interesting (case of the week)."""
    _db = get_db()
    conn = _db._get_conn()
    tf, tp = _db._tenant_filter()
    # tf is generated by _tenant_filter() — always " AND client_id = %s" or ""
    # This is NOT user-controlled input (safe pattern used project-wide)
    rows = conn.execute(f"""
        SELECT id, title, severity, status, assigned_to, interesting_notes,
               created_at, alert_count
        FROM incidents
        WHERE flagged_interesting = 1 {tf}
        ORDER BY created_at DESC
        LIMIT %s
    """, tp + [limit]).fetchall()

    return {"incidents": [
        {"id": r["id"], "title": r["title"], "severity": r["severity"],
         "status": r["status"], "assigned_to": r["assigned_to"],
         "notes": r["interesting_notes"], "created_at": r["created_at"],
         "alert_count": r["alert_count"]}
        for r in rows
    ]}


@router.get("/{incident_id}")
@limiter.limit("200/minute")
async def get_incident_detail(
    request: Request,
    incident_id: str,
    user: dict = Depends(verify_jwt),
):
    """Get a single incident with its alerts and timeline."""
    _db = get_db()
    incident = _db.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    alerts = _db.get_incident_alerts(incident_id)
    # WO-H85: every member alert's APPEND-ONLY review history, in ONE batched,
    # tenant-scoped read (not N+1) — so a reviewer can see who judged an alert
    # before them, and read what that person said, BEFORE they override it.
    review_history = _db.get_incident_alert_reviews(incident_id)
    # WO-B4: attach the parsed glass_box (risk_breakdown + provenance) to each
    # member alert so the case view can show each step's risk-score math without
    # a second round-trip. Reuses the tenant-scoped audit-trail read — one extra
    # lookup per member alert (small N per incident); each returns the stable
    # default shape when a decision has no audit trail.
    for alert in alerts:
        decision_id = alert.get("id")
        if decision_id:
            alert["glass_box"] = _db.get_decision_glass_box(decision_id)
            alert["review_history"] = review_history.get(decision_id, [])
        # WO-B9: field-level "what the AI saw vs what you see" — which identity
        # CATEGORIES were anonymized before the LLM call (host / internal_ip /
        # user). Labels only, NEVER token strings or raw client values. Derived
        # at read time from the member alert; nothing new is stored.
        alert["anonymized_fields"] = anonymized_fields_for(alert)
    incident["alerts"] = alerts
    incident["timeline"] = _db.get_incident_timeline(incident_id)
    # WO-H85: what an opt-in verdict propagation WOULD do — the alert count it
    # would touch, how many are protected by an existing human verdict, and
    # whether the members already agree with each other. Read-only; the control
    # itself stays default-OFF and server-confirmed.
    incident["verdict_propagation"] = (
        _db.get_incident_verdict_propagation_preview(incident_id))
    # WO-H17: expose the CURRENT effective-verdict mix of the member decisions
    # (human_verdict when set, else AI verdict) so the case view can render
    # "N alerts: X FP, Y TP, Z open" reflecting human overrides, not a stale
    # snapshot. Additive to the response; tenant-scoped inside the store.
    incident["verdict_mix"] = _db.get_incident_verdict_mix(incident_id)
    logger.info("incident_detail_served", incident_id=incident_id,
                alert_count=len(alerts))
    return incident


@router.post("/{incident_id}/assign")
@limiter.limit("30/minute")
async def assign_incident(
    request: Request, incident_id: str, body: IncidentAssignRequest,
    user: dict = Depends(require_role("admin", "senior_analyst", "analyst")),
):
    """Assign an incident to an analyst.

    WO-H24: opened to `analyst` for SELF-CLAIM of UNOWNED work ONLY. A plain
    `analyst` may assign an incident to THEMSELVES (`assigned_to == own
    username`) AND only when the incident is currently unowned (or already
    theirs — a harmless re-claim). Assigning to ANY OTHER user, or self-claiming
    a case already owned by a colleague, stays senior_analyst+ (403 otherwise).
    admin / senior_analyst / mssp_admin keep full assign/reassign-anyone
    behavior. Everything else (target-user existence/active checks, SLA
    first-response, notifications, audit log) is unchanged.
    """
    _db = get_db()
    role = user.get("role", "")
    actor = user.get("sub", "unknown")
    is_privileged = role in ("mssp_admin", "admin", "senior_analyst")
    if not is_privileged:
        # Self-only: a plain `analyst` may only name themselves as the assignee.
        if body.assigned_to != actor:
            raise HTTPException(
                status_code=403,
                detail="Analysts can only self-claim an incident "
                       "(assign it to themselves); assigning to another user "
                       "requires a senior analyst.",
            )
        # Unowned-only: an analyst may claim work that is unassigned, or re-claim
        # one already theirs, but NOT pull a colleague's owned case. Checked
        # BEFORE any write so a denied claim never partially assigns.
        incident = _db.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        current_owner = incident.get("assigned_to") or ""
        if current_owner and current_owner != actor:
            raise HTTPException(
                status_code=403,
                detail="Analysts can only claim unowned incidents",
            )
    # Verify the target user exists and is active.
    # allow_unscoped=True so MSSP admins / env-seeded admins without a
    # tenant in their JWT can still resolve users (username is globally
    # UNIQUE in platform_users, so no ambiguity).
    target_user = _db.get_user_by_username(body.assigned_to, allow_unscoped=True)
    if not target_user:
        raise HTTPException(status_code=400, detail=f"User '{body.assigned_to}' not found")
    if not target_user.get("is_active"):
        raise HTTPException(status_code=400, detail=f"User '{body.assigned_to}' is inactive")
    _notifications = get_notifications()
    _db.assign_incident(incident_id, body.assigned_to, actor=actor)
    # Record first response for SLA tracking
    _sla = get_sla_manager()
    if _sla:
        _sla.record_first_response(incident_id)
    logger.info("incident_assigned", incident_id=incident_id,
                assigned_to=body.assigned_to, actor=actor)
    if _notifications:
        inc = _db.get_incident(incident_id)
        if inc:
            _notifications.notify_incident_assigned(inc, body.assigned_to, actor)
    return {"status": "ok", "incident_id": incident_id}


@router.post("/{incident_id}/status")
@limiter.limit("30/minute")
async def change_incident_status(
    request: Request, incident_id: str, body: IncidentStatusRequest,
    user: dict = Depends(require_role("admin", "senior_analyst", "analyst")),
):
    """Change the status of an incident.

    WO-H85: moving an incident to ``resolved``/``closed`` now also marks its
    member alerts resolved AS WORK ITEMS (``agent_decisions.resolved_at``), so
    finishing an investigation no longer leaves every alert it grouped sitting
    unreviewed forever. It does NOT record a verdict on them — ``human_verdict``
    is untouched. Putting a verdict on an incident's alerts is a separate,
    opt-in, explicitly-confirmed action (``/propagate-verdict`` below).
    """
    _VALID_STATUSES = {"open", "investigating", "resolved", "closed"}
    if body.status not in _VALID_STATUSES:
        raise HTTPException(status_code=400,
                            detail=f"Invalid status. Must be one of: {_VALID_STATUSES}")
    _db = get_db()
    incident = _db.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    _check_incident_access(user, incident, incident_id)
    # Prevent invalid state transitions
    current = incident.get("status", "open")
    if current == "closed" and body.status != "closed":
        raise HTTPException(status_code=400,
                            detail="Cannot reopen a closed incident")
    _notifications = get_notifications()
    actor = user.get("sub", "unknown")
    # WO-H112: the structured closure travels with the status change, in the
    # same transaction. `reason` is prose for a human; `closure_reason` is the
    # only field the AI-correctness metric can be computed from.
    _db.update_incident_status(incident_id, body.status, actor=actor,
                               reason=body.reason,
                               closure_reason=body.closure_reason,
                               ai_was_wrong=body.ai_was_wrong,
                               ai_wrong_detail=body.ai_wrong_detail)
    # Record first response for SLA tracking
    _sla = get_sla_manager()
    if _sla:
        _sla.record_first_response(incident_id)
    logger.info("incident_status_changed", incident_id=incident_id,
                status=body.status, actor=actor)
    _db.log_audit(actor, "status_change", "incident", incident_id,
                  details={"status": body.status, "reason": body.reason},
                  ip_address=request.client.host if request.client else "")
    if _notifications and body.status == "resolved":
        inc = _db.get_incident(incident_id)
        if inc:
            _notifications.notify_incident_resolved(inc, actor)
    # Auto-index resolved incidents with notes to KB
    if body.status == "resolved":
        _kb = get_knowledge_base()
        if _kb:
            try:
                inc = _db.get_incident(incident_id)
                timeline = _db.get_incident_timeline(incident_id)
                notes = [e["description"] for e in (timeline or [])
                         if e.get("event_type") == "note_added"]
                if notes and inc:
                    _kb.index_incident_learning(inc, notes)
            except Exception as e:                       # noqa: BLE001
                # WO-H90: was a bare `except: pass`. A failure here means the
                # analyst notes on a resolved incident never reach the knowledge
                # base, so the lesson from this incident is lost and the next
                # identical one gets no help. Incident id only — never the note
                # text, which is free-form analyst writing.
                logger.warning("incident_learning_kb_index_failed",
                               incident_id=incident_id, error=str(e)[:200])
    return {"status": "ok", "incident_id": incident_id, "new_status": body.status}


@router.post("/{incident_id}/propagate-verdict")
@limiter.limit("30/minute")
async def propagate_incident_verdict(
    request: Request, incident_id: str,
    body: IncidentVerdictPropagationRequest,
    user: dict = Depends(require_role("admin", "senior_analyst", "analyst")),
):
    """Apply ONE human verdict to this incident's member alerts — OPT-IN (WO-H85).

    Explicitly NOT part of closing an incident. Closing cascades work-item state
    only; an incident groups alerts nobody individually judged (one observed
    chain carried 24 distinct source addresses — operational access, staff
    ranges and genuine attackers), so a blanket verdict would mislabel most of
    them. This endpoint exists so an analyst who HAS looked and does mean it can
    say so once, deliberately.

    Two safeguards, both server-side:

    * ``confirm`` DEFAULTS TO FALSE and a request without it is refused (400).
      The control is therefore off unless the caller explicitly turned it on.
    * An alert that ALREADY carries a human verdict is REFUSED, not overwritten.
      The store's UPDATE carries ``AND human_verdict IS NULL`` so even a verdict
      recorded between the read and the write survives; those members come back
      in ``skipped``.

    RBAC is deliberately UNCHANGED — it is exactly the analyst+ / ownership gate
    every other incident write uses, and it can only ever set a FIRST verdict, so
    it does not widen who may override an existing one (that stays admin-only on
    ``/api/triage/review``, per WO-B10).
    """
    _db = get_db()
    incident = _db.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    _check_incident_access(user, incident, incident_id)
    if not body.confirm:
        raise HTTPException(
            status_code=400,
            detail="Verdict propagation is opt-in: set confirm=true to apply "
                   "this verdict to the incident's unreviewed member alerts. "
                   "Alerts that already carry a human verdict are never "
                   "overwritten.",
        )
    actor = user.get("sub", "unknown")
    result = _db.propagate_incident_verdict(
        incident_id, human_verdict=body.human_verdict, reviewer=actor,
        reason=body.reason)
    # WO-H85 follow-up: run the SAME WO-H17 roll-up the alert-by-alert path runs
    # from /api/triage/review. Without it the bulk path left an incident open
    # that the one-at-a-time path would have auto-resolved — the two ways of
    # recording the same verdicts disagreed about the incident's state.
    # FAIL-SAFE, exactly as in the triage route: the verdicts are already
    # committed, so a roll-up error is logged and swallowed.
    if result.get("applied"):
        try:
            _cfg = get_config() or {}
            _auto_resolve = (_cfg.get("incidents", {}) or {}).get(
                "auto_resolve_on_all_fp", True)
            _db.rollup_incident_for_decision(
                result["applied_ids"][0], actor=actor,
                auto_resolve=_auto_resolve)
        except Exception as exc:  # noqa: BLE001 — roll-up is best-effort
            logger.warning("incident_rollup_after_propagation_failed",
                           incident_id=incident_id, error=str(exc))
    logger.info("incident_verdict_propagated", incident_id=incident_id,
                verdict=body.human_verdict, actor=actor,
                applied=result["applied"], skipped=result["skipped"],
                total=result["total"])
    _db.log_audit(actor, "propagate_verdict", "incident", incident_id,
                  details={"verdict": body.human_verdict,
                           "reason": body.reason,
                           "applied": result["applied"],
                           "skipped": result["skipped"],
                           "total": result["total"]},
                  ip_address=request.client.host if request.client else "")
    return {"status": "ok", "incident_id": incident_id, **result}


@router.post("/{incident_id}/note")
@limiter.limit("30/minute")
async def add_incident_note(
    request: Request, incident_id: str, body: IncidentNoteRequest,
    user: dict = Depends(require_role("admin", "senior_analyst", "analyst")),
):
    """Add an analyst note to an incident."""
    _db = get_db()
    incident = _db.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    _check_incident_access(user, incident, incident_id)
    actor = user.get("sub", "unknown")
    note_id = _db.add_incident_note(incident_id, body.note, actor=actor)
    logger.info("incident_note_added", incident_id=incident_id, actor=actor)
    return {"status": "ok", "incident_id": incident_id, "note_id": note_id}


@router.post("/{incident_id}/plain-summary")
@limiter.limit("10/minute")
async def get_plain_summary(
    request: Request,
    incident_id: str,
    user: dict = Depends(require_role("admin", "senior_analyst", "analyst")),
):
    """Generate a plain-language incident summary for non-technical users."""
    _db = get_db()
    _triage_agent = get_triage_agent()
    incident = _db.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    _check_incident_access(user, incident, incident_id)

    # Check cache: look for existing plain_summary in timeline
    timeline = _db.get_incident_timeline(incident_id)
    for entry in timeline:
        if entry.get("event_type") == "plain_summary":
            return {"summary": entry["description"], "cached": True}

    # Gather context for Claude — keep concise to avoid CLI timeout
    alerts = _db.get_incident_alerts(incident_id)

    # WO-S14: one helper builds the message, fully anonymized and wrapped in
    # <untrusted_data>. Shared with the batch path below.
    anon = _triage_agent.anonymizer
    user_message = _build_plain_summary_message(anon, incident, alerts)

    # Resolve LLM backend (multi-tenant or legacy)
    def _call_llm():
        if _triage_agent.tenant_registry:
            tenant_id = incident.get("client_id") or _db.get_tenant_id()
            llm = _triage_agent.tenant_registry.get_llm_backend(tenant_id)
            if llm:
                return llm.call_raw(PLAIN_SUMMARY_PROMPT, user_message)
            # Per-tenant backend unavailable — fall through to global
        return _triage_agent.claude.call_raw(PLAIN_SUMMARY_PROMPT, user_message)

    # Call Claude for plain-language translation
    import asyncio
    loop = asyncio.get_running_loop()
    try:
        summary = await loop.run_in_executor(None, _call_llm)
        summary = anon.deanonymize_text(summary)
    except Exception as e:
        logger.error("plain_summary_failed", incident_id=incident_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to generate summary")

    summary = summary.strip()

    # Cache in timeline
    _db.add_timeline_entry(incident_id, "plain_summary", summary, actor="ai_summary")
    logger.info("plain_summary_generated", incident_id=incident_id,
                 length=len(summary))

    return {"summary": summary, "cached": False}


@router.post("/{incident_id}/help-request")
@limiter.limit("5/minute")
async def request_help(
    request: Request,
    incident_id: str,
    user: dict = Depends(require_role("admin", "senior_analyst", "analyst")),
):
    """Send a help request notification for an incident."""
    _db = get_db()
    _notifications = get_notifications()
    actor = user.get("sub", "unknown")
    incident = _db.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    _check_incident_access(user, incident, incident_id)

    _db.add_timeline_entry(incident_id, "help_requested",
                           f"Help requested by {actor}", actor)
    if _notifications:
        _notifications.notify_help_requested(incident, actor)

    logger.info("help_requested", incident_id=incident_id, actor=actor)
    return {"status": "ok", "incident_id": incident_id}


@router.post("/batch-plain-summary")
@limiter.limit("30/minute")
async def batch_plain_summary(
    request: Request, body: BatchSummaryRequest,
    user: dict = Depends(require_role("admin", "senior_analyst")),
):
    """Pre-generate plain-language summaries for multiple incidents.

    Skips incidents that already have a cached summary or are already
    being generated. Runs sequentially in a background thread.
    """
    _db = get_db()
    _triage_agent = get_triage_agent()

    # Dedup: skip if a generation thread is already running
    if not _batch_summary_lock.acquire(blocking=False):
        return {"status": "already_running", "count": 0}

    # Capture effective tenant context before spawning thread
    _effective_tenant = _db.get_tenant_id()

    def _generate(ids):
        # Restore tenant context in the worker thread
        if _effective_tenant:
            _db.set_tenant(_effective_tenant)
        anon = _triage_agent.anonymizer
        try:
            for inc_id in ids:
                try:
                    incident = _db.get_incident(inc_id)
                    if not incident:
                        continue
                    timeline = _db.get_incident_timeline(inc_id)
                    if any(e.get("event_type") == "plain_summary" for e in timeline):
                        continue
                    alerts = _db.get_incident_alerts(inc_id)
                    # WO-S14: identical treatment to the interactive path —
                    # the scan found the same leak duplicated in both.
                    user_msg = _build_plain_summary_message(
                        anon, incident, alerts)
                    llm = None
                    if _triage_agent.tenant_registry:
                        tenant_id = incident.get("client_id")
                        llm = _triage_agent.tenant_registry.get_llm_backend(tenant_id)
                    if llm:
                        raw = llm.call_raw(PLAIN_SUMMARY_PROMPT, user_msg)
                    else:
                        raw = _triage_agent.claude.call_raw(PLAIN_SUMMARY_PROMPT, user_msg)
                    summary = anon.deanonymize_text(raw.strip())
                    _db.add_timeline_entry(inc_id, "plain_summary", summary,
                                           actor="ai_summary")
                    logger.info("batch_plain_summary_generated",
                                incident_id=inc_id)
                except Exception as e:
                    logger.warning("batch_plain_summary_failed",
                                   incident_id=inc_id, error=str(e))
        finally:
            _batch_summary_lock.release()

    import threading as _threading
    _threading.Thread(target=_generate, args=(body.incident_ids,),
                      daemon=True).start()
    return {"status": "generating", "count": len(body.incident_ids)}


@router.post("/merge")
@limiter.limit("10/minute")
async def merge_incidents(
    request: Request, body: IncidentMergeRequest,
    user: dict = Depends(require_role("admin", "senior_analyst")),
    _gate: None = Depends(require_license_feature("incidents_merge")),
):
    """Merge source incidents into a target incident."""
    _db = get_db()
    target = _db.get_incident(body.target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target incident not found")
    for src_id in body.source_ids:
        if not _db.get_incident(src_id):
            raise HTTPException(status_code=404,
                                detail=f"Source incident {src_id} not found")
    if body.target_id in body.source_ids:
        raise HTTPException(status_code=400,
                            detail="Cannot merge an incident into itself")
    actor = user.get("sub", "unknown")
    _db.merge_incidents(body.target_id, body.source_ids, actor=actor)
    logger.info("incidents_merged", target=body.target_id,
                sources=body.source_ids, actor=actor)
    return {"status": "ok", "target_id": body.target_id}


@router.post("/{incident_id}/escalate")
@limiter.limit("10/minute")
async def escalate_incident_tier(
    request: Request, incident_id: str,
    user: dict = Depends(require_role("admin", "senior_analyst", "analyst")),
):
    """Escalate an incident to a higher tier (L1->L2, L2->L3).

    WO-H24: opened to `analyst` so an L1 is a real operator — an analyst who
    cannot resolve a case can hand it up-tier with context. The L2/L3 tier
    validation, the SLA escalation record, and the audit log are unchanged;
    only the role gate widened. Active response is NOT loosened by this.
    """
    _db = get_db()
    _sla = get_sla_manager()
    incident = _db.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    new_tier = body.get("tier", "")
    handoff_notes = body.get("handoff_notes", "")

    if new_tier not in ("L2", "L3"):
        raise HTTPException(status_code=400, detail="Tier must be L2 or L3")

    actor = user.get("sub", "unknown")
    if _sla:
        success = _sla.escalate_tier(incident_id, new_tier, actor, handoff_notes)
        if not success:
            raise HTTPException(status_code=400,
                                detail="Cannot escalate to same or lower tier")
    else:
        # WO-H88: this used to be fire-and-forget. The store swallowed any
        # failure, so the analyst was told "ok" for an escalation that never
        # happened — and escalation is precisely the action nobody re-checks.
        if not _db.escalate_incident_tier(
                incident_id, new_tier, handoff_notes, actor):
            raise HTTPException(
                status_code=500,
                detail="Escalation could not be saved. Nothing was changed — "
                       "please retry rather than assuming it went through.")

    _db.log_audit(actor, "escalate", "incident", incident_id,
                  details={"tier": new_tier}, ip_address=request.client.host if request.client else "")
    return {"status": "ok", "incident_id": incident_id, "tier": new_tier}


@router.post("/{incident_id}/evidence")
@limiter.limit("30/minute")
async def add_evidence(
    request: Request, incident_id: str,
    body: EvidenceRequest,
    user: dict = Depends(require_role("admin", "senior_analyst", "analyst")),
):
    """Add an evidence entry to the incident's evidence chain."""
    _db = get_db()
    incident = _db.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    _check_incident_access(user, incident, incident_id)

    actor = user.get("sub", "unknown")
    from datetime import datetime, timezone
    evidence = {
        "type": body.type,
        "description": body.description,
        "ref_id": body.ref_id,
        "added_by": actor,
        "added_at": datetime.now(timezone.utc).isoformat(),
    }
    # WO-H88: an analyst types evidence, hits save, and used to be told "ok"
    # whether or not it was written. Evidence lost this way is unrecoverable —
    # it only existed in the text box.
    if not _db.add_incident_evidence(incident_id, evidence):
        raise HTTPException(
            status_code=500,
            detail="Evidence could not be saved. Copy your text before "
                   "retrying — it has not been stored.")
    return {"status": "ok", "incident_id": incident_id}


@router.get("/{incident_id}/sla")
async def get_incident_sla(
    incident_id: str,
    user: dict = Depends(verify_jwt),
    _gate: None = Depends(require_license_feature("sla")),
):
    """Get SLA status for an incident."""
    _db = get_db()
    incident = _db.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    breaches = _db.get_sla_breaches(incident_id)
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)

    def _time_remaining(due_str):
        if not due_str:
            return None
        try:
            # WO-H116: version-independent parse (stored TEXT column).
            due = parse_iso8601(due_str)
            delta = due - now
            return max(0, int(delta.total_seconds()))
        except (ValueError, TypeError):
            return None

    return {
        "tier": incident.get("tier", "L1"),
        "sla_response_due": incident.get("sla_response_due"),
        "sla_resolution_due": incident.get("sla_resolution_due"),
        "first_response_at": incident.get("first_response_at"),
        "response_remaining_sec": _time_remaining(incident.get("sla_response_due")),
        "resolution_remaining_sec": _time_remaining(incident.get("sla_resolution_due")),
        "sla_response_met": incident.get("sla_response_met"),
        "sla_resolution_met": incident.get("sla_resolution_met"),
        "breaches": breaches,
        "escalation_count": incident.get("escalation_count", 0),
    }


@router.post("/{incident_id}/review")
@limiter.limit("10/minute")
def create_or_update_review(
    request: Request,
    incident_id: str,
    body: IncidentReviewRequest,
    user: dict = Depends(require_role("admin", "senior_analyst")),
):
    """Create or update a post-incident review.

    Deliberately a plain ``def``, not ``async def`` (WO-H98). The body opens a
    ``SOCDatabase._txn`` block, and the state that makes that safe —
    ``txn_depth``/``txn_conn`` and the per-thread cached connection — is
    ``threading.local``. On the event loop every coroutine shares one thread and
    therefore one connection and one depth counter, so a block opened in an
    ``async def`` route is safe only for as long as nobody adds an ``await``
    inside it; the day someone does, two requests silently join one transaction
    and one of them has its ``commit()`` dropped. As a plain ``def`` FastAPI
    runs this on the threadpool — one thread, one connection, no sharing — and
    the hazard cannot arise. This route also does no I/O other than the DB
    calls, which are synchronous anyway, so nothing is lost by moving it off
    the loop; it is a strict improvement (it no longer blocks the event loop).
    """
    _db = get_db()
    incident = _db.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    import uuid
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()

    conn = _db._get_conn()
    tf, tp = _db._tenant_filter()

    review_date = body.review_date or now
    participants_json = json.dumps(body.participants)
    action_items_json = json.dumps(body.action_items)
    backlog_json = json.dumps(body.detection_backlog_items)

    # WO-H98: the pool is autocommit now, so this read-then-upsert has to say
    # its transaction out loud — the existence check and the write it decides
    # between belong to the same unit of work.
    with _db._txn(conn):
        existing = conn.execute(
            f"SELECT id FROM post_incident_reviews WHERE incident_id = %s {tf}",
            [incident_id] + tp,
        ).fetchone()
        if existing:
            conn.execute(f"""
                UPDATE post_incident_reviews SET
                    review_date = %s, participants = %s, timeline_accuracy = %s,
                    detection_gap = %s, response_effectiveness = %s,
                    lessons_learned = %s, action_items = %s,
                    detection_backlog_items = %s, status = %s, updated_at = %s
                WHERE incident_id = %s {tf}
            """, (
                review_date, participants_json,
                body.timeline_accuracy, body.detection_gap,
                body.response_effectiveness, body.lessons_learned,
                action_items_json, backlog_json,
                body.status, now, incident_id,
            ) + tuple(tp))
            review_id = existing["id"]
        else:
            review_id = str(uuid.uuid4())
            conn.execute("""
                INSERT INTO post_incident_reviews
                (id, incident_id, review_date, participants, timeline_accuracy,
                 detection_gap, response_effectiveness, lessons_learned,
                 action_items, detection_backlog_items, status, created_by,
                 created_at, updated_at, client_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                review_id, incident_id, review_date, participants_json,
                body.timeline_accuracy, body.detection_gap,
                body.response_effectiveness, body.lessons_learned,
                action_items_json, backlog_json,
                body.status, user.get("sub", "unknown"),
                now, now, _db._tenant_value(),
            ))
    conn.commit()

    _db.log_audit(user.get("sub", "unknown"), "review_created",
                  "incident", incident_id, {},
                  request.client.host if request.client else "")

    return {"status": "ok", "review_id": review_id}


@router.get("/{incident_id}/review")
async def get_review(
    incident_id: str,
    user: dict = Depends(verify_jwt),
):
    """Get the post-incident review for an incident."""
    _db = get_db()
    conn = _db._get_conn()
    tf, tp = _db._tenant_filter()
    row = conn.execute(
        f"SELECT * FROM post_incident_reviews WHERE incident_id = %s {tf}",
        [incident_id] + tp,
    ).fetchone()

    if not row:
        return {"review": None}

    # psycopg dict_row already gives us a column-name dict.
    review = dict(row)

    for field in ("participants", "action_items", "detection_backlog_items"):
        try:
            review[field] = json.loads(review.get(field, "[]"))
        except (json.JSONDecodeError, TypeError):
            review[field] = []

    return {"review": review}


@router.post("/{incident_id}/flag-interesting")
@limiter.limit("10/minute")
async def flag_interesting(
    request: Request,
    incident_id: str,
    body: FlagInterestingRequest,
    user: dict = Depends(require_role("admin", "senior_analyst", "analyst")),
):
    """Flag an incident as interesting (case of the week candidate)."""
    _db = get_db()
    conn = _db._get_conn()
    incident = _db.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    tf, tp = _db._tenant_filter()
    conn.execute(f"""
        UPDATE incidents SET flagged_interesting = %s, interesting_notes = %s
        WHERE id = %s {tf}
    """, [1 if body.flagged else 0, body.notes, incident_id] + tp)
    conn.commit()

    _db.log_audit(user.get("sub", "unknown"),
                  "incident_flagged_interesting" if body.flagged else "incident_unflagged",
                  "incident", incident_id, {"notes": body.notes, "flagged": body.flagged},
                  request.client.host if request.client else "")
    return {"status": "ok", "incident_id": incident_id}
