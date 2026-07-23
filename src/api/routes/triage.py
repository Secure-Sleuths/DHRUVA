"""Triage review routes."""

import json
import structlog
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from src.api import auth
from src.api.auth import verify_jwt, require_role
from src.api.dependencies import (
    get_db, get_config, get_enrichment, get_triage_agent, limiter,
)
from src.api.models import HumanReviewRequest
from src.database.store import parse_glass_box, anonymized_fields_for

router = APIRouter(prefix="/api/triage")
logger = structlog.get_logger(__name__)

# Client-facing sort options → store order_by keys. Anything else falls back to
# "recent" so a bad query param can never break the endpoint or reach SQL.
_SORT_TO_ORDER = {"recent": "recent", "risk": "risk"}


def _flatten_enrichment(decision: dict) -> dict:
    """Expose host / src_ip / MITRE technique + tactic IDs and the
    baseline-anomaly flag as first-class top-level fields so clients don't have
    to parse the ``enrichment_summary`` JSON blob themselves.

    Defensive by design: ``enrichment_summary`` may be null, empty, or malformed
    JSON — in every failure case we fall back to null / [] / ``False`` and never
    raise. The original ``enrichment_summary`` is left untouched in the payload.
    """
    host = None
    src_ip = None
    technique_ids: list = []
    tactic_ids: list = []
    baseline_anomaly = False

    raw = decision.get("enrichment_summary")
    if raw:
        try:
            enr = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, TypeError, ValueError):
            enr = None
        if isinstance(enr, dict):
            host = enr.get("agent_name")
            src_ip = enr.get("src_ip")
            techs = enr.get("rule_mitre_techniques")
            tactics = enr.get("rule_mitre_tactics")
            technique_ids = techs if isinstance(techs, list) else (
                [techs] if techs else [])
            tactic_ids = tactics if isinstance(tactics, list) else (
                [tactics] if tactics else [])
            baseline_anomaly = bool(enr.get("baseline_anomaly"))

    decision["host"] = host
    decision["src_ip"] = src_ip
    decision["technique_ids"] = technique_ids
    decision["tactic_ids"] = tactic_ids
    decision["baseline_anomaly"] = baseline_anomaly
    return decision


@router.get("/decisions")
async def get_triage_decisions(
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    agent_type: Optional[str] = None,
    verdict: Optional[str] = None,
    escalated_only: bool = False,
    anomaly: bool = False,
    llm_failed: Optional[bool] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    sort: str = Query("recent"),
    user: dict = Depends(verify_jwt),
):
    """Get triage decisions, optionally filtered by time range.

    ``sort=risk`` presents the queue worst-first (highest ``risk_score`` at the
    top); ``sort=recent`` (default) preserves newest-first ordering. Each row is
    flattened to expose host / src_ip / technique_ids / tactic_ids at top level.
    ``anomaly=true`` filters to decisions flagged as baseline/behavioral
    anomalies (``enrichment_summary.baseline_anomaly`` truthy).

    WO-H33: ``offset`` pages beyond the first window so the FULL queue is
    reachable (the worst-first view used to silently end at ``limit`` rows).
    ``verdict``/``escalated_only`` now filter in SQL, so each page is a full
    page of matches. ``has_more`` in the response tells the client whether
    another page exists. ``anomaly`` remains a JSON-derived post-filter: it can
    shorten a page but never lies about ``has_more`` (which reflects the SQL
    window before that filter).

    WO-H46-c: ``llm_failed=true`` returns ONLY rows where triage failed closed
    because the LLM was unreachable — the alert was escalated WITHOUT being
    analyzed. ``llm_failed=false`` excludes them, giving a queue of genuine
    verdicts. Both populations otherwise look identical
    (``needs_investigation`` + ``escalated``), which is exactly how a backend
    outage used to masquerade as a busy escalation queue.
    """
    _db = get_db()
    order_by = _SORT_TO_ORDER.get(sort, "recent")
    # Fetch one extra row to learn whether another page exists — cheaper than
    # a COUNT(*) on every poll, and keeps the initial-load cost unchanged.
    rows = _db.get_recent_decisions(
        limit=limit + 1, offset=offset, agent_type=agent_type,
        verdict=verdict, escalated_only=escalated_only,
        llm_failed=llm_failed,
        since=since, until=until, order_by=order_by,
    )
    has_more = len(rows) > limit
    decisions = [_flatten_enrichment(d) for d in rows[:limit]]
    if anomaly:
        decisions = [d for d in decisions if d.get("baseline_anomaly")]
    # WO-B9: field-level "what the AI saw vs what you see" — which identity
    # categories were anonymized before the LLM call. Labels only, NEVER token
    # strings or raw values. Derived at read time; nothing new is stored.
    for d in decisions:
        d["anonymized_fields"] = anonymized_fields_for(d)
    logger.info("triage_decisions_served", sort=order_by,
                anomaly=anomaly, count=len(decisions),
                offset=offset, has_more=has_more)
    return {"decisions": decisions, "total": len(decisions),
            "offset": offset, "limit": limit, "has_more": has_more}


@router.get("/decisions/{decision_id}")
async def get_triage_decision(
    decision_id: str,
    user: dict = Depends(verify_jwt),
):
    """Single-decision read (WO-H33): lets a deep-link resolve a decision that
    sits beyond the currently-loaded queue window instead of failing with
    "not in the current slice". Tenant-scoped via ``store.get_decision`` (a
    foreign tenant's row is a no-match → 404, never a leak); the row is
    flattened + carries ``anonymized_fields`` exactly like the list read.
    """
    _db = get_db()
    decision = _db.get_decision(decision_id)
    if not decision:
        raise HTTPException(status_code=404, detail="Decision not found")
    decision = _flatten_enrichment(decision)
    decision["anonymized_fields"] = anonymized_fields_for(decision)
    return decision


@router.get("/pending-review")
async def get_pending_reviews(
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    sort: str = Query("recent"),
    user: dict = Depends(verify_jwt),
):
    """Get alerts awaiting human review (escalated, no human verdict yet).

    WO-H37: mirrors the WO-H33 pagination on ``/decisions``. The pending
    filter runs in SQL (it used to Python-filter the 200 most-recent rows,
    silently hiding every pending decision beyond that window), ``offset``
    pages the FULL pending set, and ``has_more`` (from a limit+1 probe row —
    no COUNT(*), initial-load cost unchanged) says whether a next page
    exists. Response stays backward-compatible: ``pending``/``count`` are
    unchanged; the pagination fields are additive.
    """
    _db = get_db()
    order_by = _SORT_TO_ORDER.get(sort, "recent")
    rows = _db.get_recent_decisions(
        limit=limit + 1, offset=offset, pending_only=True, order_by=order_by,
    )
    has_more = len(rows) > limit
    pending = rows[:limit]
    return {"pending": pending, "count": len(pending),
            "offset": offset, "limit": limit, "has_more": has_more}


@router.post("/review")
@limiter.limit("30/minute")
async def submit_human_review(
    request: Request, review: HumanReviewRequest,
    user: dict = Depends(require_role("admin", "senior_analyst", "analyst")),
):
    """Submit a human review/override for an agent decision.

    WO-B10: analysts may set the FIRST human verdict on a decision, but
    CHANGING a verdict a human has ALREADY recorded requires admin/mssp_admin
    (enforced SERVER-SIDE here). The base ``require_role`` gate still keeps
    read_only out entirely. ``mssp_admin`` is the platform superuser and passes
    the override gate like ``admin`` (mirrors auth.require_role/require_admin).
    """
    _db = get_db()
    reviewer = user.get("sub", "unknown")

    # Read the existing verdict TENANT-SCOPED before applying — get_decision()
    # is a no-match (→ 404) for another tenant's decision, never a leak.
    existing = _db.get_decision(review.decision_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Decision not found")

    # An override = a human verdict already exists on this decision.
    is_override = bool(existing.get("human_verdict"))
    role = user.get("role", "")
    # Overriding an EXISTING human verdict is admin-only. Skip this gate when
    # auth is disabled (lab/dev), consistent with require_role/require_admin —
    # otherwise the anonymous read_only dev user would be wrongly blocked.
    if (auth._auth_enabled and is_override
            and role not in ("admin", "mssp_admin")):
        logger.warning("human_verdict_override_denied",
                       decision_id=review.decision_id,
                       reviewer=reviewer, role=role,
                       existing_verdict=existing.get("human_verdict"))
        raise HTTPException(
            status_code=403,
            detail="Overriding an existing human verdict requires admin",
        )

    success = _db.apply_human_override(
        decision_id=review.decision_id,
        human_verdict=review.human_verdict,
        reviewer=reviewer,
        reason=review.reason,
    )
    if not success:
        raise HTTPException(status_code=404, detail="Decision not found")
    logger.info("human_review_submitted",
                 decision_id=review.decision_id,
                 verdict=review.human_verdict,
                 reviewer=reviewer,
                 is_override=is_override)
    # WO-H17 — couple the verdict override to incident roll-up state. Look up
    # the incident(s) that group this decision (tenant-scoped) and, when every
    # constituent alert is dispositioned FP/benign, auto-resolve the incident
    # so a fully-closed case no longer shows "Open". FAIL-SAFE: the roll-up must
    # NEVER break the override — the override is already committed above, so any
    # roll-up error is logged and swallowed and the endpoint still returns ok.
    try:
        _cfg = get_config() or {}
        _auto_resolve = (_cfg.get("incidents", {}) or {}).get(
            "auto_resolve_on_all_fp", True)
        _db.rollup_incident_for_decision(
            review.decision_id, actor=reviewer, auto_resolve=_auto_resolve)
    except Exception as exc:  # noqa: BLE001 — roll-up is best-effort
        logger.warning("incident_rollup_after_override_failed",
                       decision_id=review.decision_id, error=str(exc))
    _db.log_audit(reviewer, "review", "decision", review.decision_id,
                  details={"verdict": review.human_verdict,
                           "reason": review.reason,
                           "is_override": is_override},
                  ip_address=request.client.host if request.client else "")
    return {"status": "ok", "decision_id": review.decision_id}


@router.get("/decisions/{decision_id}/audit-trail")
async def get_decision_audit_trail(
    decision_id: str,
    user: dict = Depends(verify_jwt),
):
    """Get the AI decision audit trail (prompt version, risk breakdown, etc.).

    The response also carries a parsed ``glass_box`` object (WO-B4) so the
    Incident/decision case view can render the risk-score math and provenance
    without re-parsing the stored JSON blobs itself. The raw trail fields are
    left untouched alongside it for backwards compatibility.
    """
    _db = get_db()
    trail = _db.get_decision_audit_trail(decision_id)
    if not trail:
        raise HTTPException(status_code=404, detail="Audit trail not found")
    trail["glass_box"] = parse_glass_box(trail)
    return trail


# ---------------------------------------------------------------------------
# WO-H25 — alert-level claim. Ownership of the INDIVIDUAL triage decision so
# two analysts working the queue don't double-work the same item. Mirrors the
# WO-H24 incident assign semantics (L1 is an operator): `analyst`+ may claim,
# the claim is ALWAYS to the caller themselves (the authenticated `sub` — a
# client-supplied claimant is never accepted), and only an UNOWNED decision
# (or one already yours — idempotent re-claim) may be claimed. A decision
# owned by a colleague is a 409 with NO write, for every role — taking over
# someone's in-progress work is deliberately not a thing; the owner releases
# it via /unclaim. Tenant-scoped end to end: `get_decision()` no-matches a
# foreign tenant's row (→ 404), and the store UPDATEs carry `_tenant_filter`.
# ---------------------------------------------------------------------------

@router.post("/decisions/{decision_id}/claim")
@limiter.limit("30/minute")
async def claim_decision(
    request: Request, decision_id: str,
    user: dict = Depends(require_role("admin", "senior_analyst", "analyst")),
):
    """Claim a triage decision for YOURSELF (self-claim, unowned-only).

    200 on a fresh claim AND on an idempotent re-claim of a decision already
    yours; 409 (no write) when a different user owns it; 404 for an unknown
    or foreign-tenant decision id. Audit-logged.
    """
    _db = get_db()
    actor = user.get("sub", "unknown")

    decision = _db.get_decision(decision_id)
    if decision is None:
        raise HTTPException(status_code=404, detail="Decision not found")
    current_owner = decision.get("claimed_by") or ""
    if current_owner and current_owner != actor:
        raise HTTPException(
            status_code=409,
            detail="Decision is already claimed by another analyst",
        )

    # Atomic claim: the store UPDATE re-checks the unowned-or-mine
    # precondition (and the tenant filter) in its WHERE clause, so a race
    # with a colleague's concurrent claim loses cleanly with no write.
    if not _db.claim_decision(decision_id, actor):
        raise HTTPException(
            status_code=409,
            detail="Decision is already claimed by another analyst",
        )

    logger.info("decision_claimed", decision_id=decision_id, actor=actor,
                reclaim=bool(current_owner))
    _db.log_audit(actor, "claim", "decision", decision_id,
                  details={"reclaim": bool(current_owner)},
                  ip_address=request.client.host if request.client else "")
    return {"status": "ok", "decision_id": decision_id, "claimed_by": actor}


@router.post("/decisions/{decision_id}/unclaim")
@limiter.limit("30/minute")
async def unclaim_decision(
    request: Request, decision_id: str,
    user: dict = Depends(require_role("admin", "senior_analyst", "analyst")),
):
    """Release YOUR OWN claim on a triage decision.

    200 when your claim is released — and idempotently when the decision is
    already unclaimed (nothing to release); 409 (no write) when a different
    user owns the claim; 404 for an unknown/foreign decision id.
    """
    _db = get_db()
    actor = user.get("sub", "unknown")

    decision = _db.get_decision(decision_id)
    if decision is None:
        raise HTTPException(status_code=404, detail="Decision not found")
    current_owner = decision.get("claimed_by") or ""
    if current_owner and current_owner != actor:
        raise HTTPException(
            status_code=409,
            detail="Decision is claimed by another analyst — only the owner "
                   "can release it",
        )

    released = False
    if current_owner == actor:
        released = _db.unclaim_decision(decision_id, actor)

    logger.info("decision_unclaimed", decision_id=decision_id, actor=actor,
                released=released)
    _db.log_audit(actor, "unclaim", "decision", decision_id,
                  details={"released": released},
                  ip_address=request.client.host if request.client else "")
    return {"status": "ok", "decision_id": decision_id, "claimed_by": None}


@router.get("/rule-stats/{rule_id}")
async def get_rule_stats(
    rule_id: int, days: int = Query(7, ge=1, le=90),
    user: dict = Depends(verify_jwt),
):
    """Get triage statistics for a specific rule."""
    _db = get_db()
    return _db.get_fp_rate_for_rule(rule_id, days=days)


# ---------------------------------------------------------------------------
# WO-H21 — complete-context case view (READ-ONLY, human display path).
#
# Both endpoints below surface data the platform has ALREADY computed/stored to
# the analyst looking at a case. They are strictly display reads: nothing here
# feeds an LLM call or touches the anonymization boundary, and nothing is
# recomputed. Tenant scoping rides the SAME primitives as the rest of this
# module — `get_decision()` is a tenant-scoped no-match (→ 404) for another
# tenant's decision, and the OpenSearch read goes through `search_alerts`,
# which injects the tenant filter from the request's tenant context.
# ---------------------------------------------------------------------------

@router.get("/decisions/{decision_id}/raw-alert")
async def get_decision_raw_alert(
    decision_id: str,
    user: dict = Depends(verify_jwt),
):
    """The raw underlying Wazuh event behind a decision, for inline case view.

    Fetches the enriched-alert document (the normalized Wazuh event: rule,
    agent, ``data``, ``full_log``, decoder, location) by the decision's
    ``alert_id`` from the enriched-alert index. The ``enrichment`` sub-object
    is dropped — the case already renders it — so what remains is the event as
    ingested.

    Defensive by design: every degraded condition (no alert id on an old row,
    OpenSearch not configured on this deployment, the event rotated out of the
    index, a query fault) returns ``{"found": false, "reason": ...}`` — never
    a 5xx. Only an unknown/foreign decision id is a 404.
    """
    _db = get_db()
    decision = _db.get_decision(decision_id)
    if decision is None:
        raise HTTPException(status_code=404, detail="Decision not found")

    alert_id = decision.get("alert_id")
    if not alert_id:
        return {"found": False, "alert": None,
                "reason": "No alert id was recorded on this decision."}

    enrichment = get_enrichment()
    os_client = getattr(enrichment, "opensearch", None) if enrichment else None
    if os_client is None:
        return {"found": False, "alert": None,
                "reason": "The alert store (OpenSearch) is not available "
                          "on this deployment."}

    try:
        hits = os_client.search_alerts(
            {"query": {"term": {"alert_id": str(alert_id)}}}, size=1)
    except Exception as exc:  # noqa: BLE001 — display read must never 500
        logger.warning("raw_alert_fetch_failed", decision_id=decision_id,
                       alert_id=str(alert_id), error=str(exc)[:200])
        return {"found": False, "alert": None,
                "reason": "The alert store could not be queried."}

    if not hits or not isinstance(hits[0], dict):
        return {"found": False, "alert": None,
                "reason": "The underlying event was not found in the "
                          "enriched-alert index (it may have been rotated "
                          "out of retention)."}

    doc = dict(hits[0])
    # The enrichment blob is already surfaced on the case (risk factors /
    # context records) — the raw view is the EVENT, not the derived context.
    doc.pop("enrichment", None)
    logger.info("raw_alert_served", decision_id=decision_id,
                alert_id=str(alert_id))
    return {"found": True, "alert": doc, "reason": None}


# The first line `format_playbook()` emits — the persisted ``playbook_used`` /
# audit-trail ``playbook_name`` are 100-char prefixes of that formatted text,
# so the display name is recovered from this header.
_PLAYBOOK_HEADER = "## Investigation Playbook: "
# `select_playbook()`'s generic fallback starts with this marker.
_NO_PLAYBOOK_MARKER = "No specific playbook matched"


def _playbook_display_name(pb_data, key: str) -> str:
    """A playbook's human display name (its ``name`` field, else its key)."""
    if isinstance(pb_data, dict):
        name = pb_data.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
    return key


def _resolve_playbook_key(playbooks: dict, stored) -> Optional[str]:
    """Resolve a persisted ``playbook_used`` string to a loaded playbook key.

    The stored value is either a bare key (older rows / fixtures), a display
    name, or — the main triage path — the first 100 chars of the FORMATTED
    playbook text (``## Investigation Playbook: <display name>\\n...``). The
    100-char truncation can clip the display name itself, so when no newline
    survives after the header a prefix match is accepted. Pure + defensive:
    any non-string/unknown input resolves to ``None``, never raises.
    """
    if not isinstance(playbooks, dict) or not isinstance(stored, str):
        return None
    ref = stored.strip()
    if not ref:
        return None

    clipped = False
    if ref.startswith(_PLAYBOOK_HEADER):
        rest = ref[len(_PLAYBOOK_HEADER):]
        clipped = "\n" not in rest
        ref = rest.split("\n", 1)[0].strip()
        if not ref:
            return None

    for key, data in playbooks.items():
        display = _playbook_display_name(data, str(key))
        if ref == str(key) or ref == display:
            return str(key)
        if clipped and display.startswith(ref):
            return str(key)
    return None


def _as_str_list(value) -> list:
    """Coerce a YAML field to a clean list of non-empty strings."""
    if value is None:
        return []
    if not isinstance(value, list):
        value = [value]
    return [str(v) for v in value if v is not None and str(v).strip()]


def _shape_playbook(key: str, data) -> dict:
    """Shape a loaded playbook YAML into the read-only display contract.

    Defensive against malformed YAML: any wrong-typed section degrades to an
    empty list/dict so the case view renders an empty state, never crashes.
    ``escalation_criteria`` is the playbook's ``needs_investigation`` verdict
    criteria — the conditions under which the playbook says a human must take
    the case rather than close it.
    """
    if not isinstance(data, dict):
        data = {}

    steps = []
    raw_steps = data.get("investigation_steps")
    for s in raw_steps if isinstance(raw_steps, list) else []:
        if not isinstance(s, dict):
            continue
        steps.append({
            "step": s.get("step"),
            "name": str(s.get("name") or ""),
            "assess": str(s.get("assess") or ""),
            "query_template": str(s.get("query_template") or ""),
        })

    raw_verdicts = data.get("verdict_criteria")
    verdict_criteria = {
        str(k): _as_str_list(v)
        for k, v in (raw_verdicts.items()
                     if isinstance(raw_verdicts, dict) else [])
    }
    raw_actions = data.get("recommended_actions")
    recommended_actions = {
        str(k): _as_str_list(v)
        for k, v in (raw_actions.items()
                     if isinstance(raw_actions, dict) else [])
    }

    return {
        "key": key,
        "name": _playbook_display_name(data, key),
        "trigger_rule_groups": _as_str_list(data.get("trigger_rule_groups")),
        "trigger_rule_ids": [
            i for i in (data.get("trigger_rule_ids")
                        if isinstance(data.get("trigger_rule_ids"), list)
                        else [])
        ],
        "investigation_steps": steps,
        "verdict_criteria": verdict_criteria,
        "escalation_criteria": verdict_criteria.get("needs_investigation", []),
        "recommended_actions": recommended_actions,
    }


@router.get("/decisions/{decision_id}/playbook")
async def get_decision_playbook(
    decision_id: str,
    user: dict = Depends(verify_jwt),
):
    """The matched playbook's CONTENT (steps + verdict/escalation criteria)
    for a decision — so the case shows the playbook itself, not just its name.

    Resolves the decision's persisted ``playbook_used`` reference against the
    currently loaded guidance (hot-reload aware — same loader instance
    ``/api/guidance/reload`` refreshes). READ-ONLY; same visibility as the
    case itself (``verify_jwt``). Every degraded condition (no playbook
    recorded, the generic no-match guidance, guidance unavailable in this
    build, a renamed/removed playbook) is ``{"matched": false, "reason": ...}``
    — never a 5xx. Only an unknown/foreign decision id is a 404.
    """
    _db = get_db()
    decision = _db.get_decision(decision_id)
    if decision is None:
        raise HTTPException(status_code=404, detail="Decision not found")

    stored = decision.get("playbook_used")
    if not stored or not str(stored).strip():
        return {"matched": False, "playbook": None,
                "reason": "No playbook was recorded for this decision."}
    stored = str(stored)

    if stored.startswith(_NO_PLAYBOOK_MARKER):
        return {"matched": False, "playbook": None,
                "reason": "No specific playbook matched this alert — the AI "
                          "applied the general investigation methodology."}

    agent = get_triage_agent()
    guidance = getattr(agent, "guidance", None) if agent else None
    playbooks = None
    if guidance is not None:
        try:
            playbooks = guidance.get_all_playbooks()
        except Exception as exc:  # noqa: BLE001 — display read must never 500
            logger.warning("decision_playbook_guidance_failed",
                           decision_id=decision_id, error=str(exc)[:200])
            playbooks = None
    if not isinstance(playbooks, dict) or not playbooks:
        return {"matched": False, "playbook": None,
                "reason": "Guidance playbooks are not available on this "
                          "deployment."}

    key = _resolve_playbook_key(playbooks, stored)
    if key is None:
        logger.info("decision_playbook_unresolved", decision_id=decision_id)
        return {"matched": False, "playbook": None,
                "reason": "The recorded playbook is not in the currently "
                          "loaded guidance (it may have been renamed or "
                          "removed since this decision)."}

    logger.info("decision_playbook_served", decision_id=decision_id,
                playbook=key)
    return {"matched": True,
            "playbook": _shape_playbook(key, playbooks.get(key)),
            "reason": None}
