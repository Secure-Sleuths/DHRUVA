"""Triage review routes."""

import json
import structlog
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from src.api import auth
from src.api.auth import verify_jwt, require_role
from src.api.dependencies import get_db, limiter
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
    agent_type: Optional[str] = None,
    verdict: Optional[str] = None,
    escalated_only: bool = False,
    anomaly: bool = False,
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
    """
    _db = get_db()
    order_by = _SORT_TO_ORDER.get(sort, "recent")
    decisions = _db.get_recent_decisions(
        limit=limit, agent_type=agent_type, since=since, until=until,
        order_by=order_by,
    )
    if verdict:
        decisions = [d for d in decisions if d.get("verdict") == verdict]
    if escalated_only:
        decisions = [d for d in decisions if d.get("escalated")]
    decisions = [_flatten_enrichment(d) for d in decisions]
    if anomaly:
        decisions = [d for d in decisions if d.get("baseline_anomaly")]
    # WO-B9: field-level "what the AI saw vs what you see" — which identity
    # categories were anonymized before the LLM call. Labels only, NEVER token
    # strings or raw values. Derived at read time; nothing new is stored.
    for d in decisions:
        d["anonymized_fields"] = anonymized_fields_for(d)
    logger.info("triage_decisions_served", sort=order_by,
                anomaly=anomaly, count=len(decisions))
    return {"decisions": decisions, "total": len(decisions)}


@router.get("/pending-review")
async def get_pending_reviews(user: dict = Depends(verify_jwt)):
    """Get alerts awaiting human review."""
    _db = get_db()
    decisions = _db.get_recent_decisions(limit=200)
    pending = [d for d in decisions if d.get("escalated") and not d.get("human_verdict")]
    return {"pending": pending, "count": len(pending)}


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


@router.get("/rule-stats/{rule_id}")
async def get_rule_stats(
    rule_id: int, days: int = Query(7, ge=1, le=90),
    user: dict = Depends(verify_jwt),
):
    """Get triage statistics for a specific rule."""
    _db = get_db()
    return _db.get_fp_rate_for_rule(rule_id, days=days)
