"""MITRE ATT&CK coverage mapping routes."""

import structlog
from fastapi import APIRouter, Depends, HTTPException

from src.api.auth import verify_jwt
from src.api.dependencies import get_mitre_analyzer
from src.api.feature_gates import require_license_feature

router = APIRouter(prefix="/api/mitre")
logger = structlog.get_logger(__name__)

_mitre_gate = Depends(require_license_feature("mitre"))


@router.get("/coverage")
async def get_coverage(user: dict = Depends(verify_jwt), _gate: None = _mitre_gate):
    """Get full MITRE ATT&CK heatmap data (all tactics + techniques)."""
    analyzer = get_mitre_analyzer()
    if not analyzer:
        return {"tactics": []}
    return analyzer.get_heatmap_data()


@router.get("/gaps")
async def get_gaps(user: dict = Depends(verify_jwt), _gate: None = _mitre_gate):
    """Get uncovered techniques (gap analysis)."""
    analyzer = get_mitre_analyzer()
    if not analyzer:
        return {"gaps": {}, "total_gaps": 0, "total_techniques": 0, "coverage_pct": 0}
    return analyzer.get_gap_analysis()


@router.get("/summary")
async def get_summary(user: dict = Depends(verify_jwt), _gate: None = _mitre_gate):
    """Get per-tactic coverage percentages."""
    analyzer = get_mitre_analyzer()
    if not analyzer:
        return {"per_tactic": [], "overall": {}}
    return analyzer.get_coverage_summary()


@router.get("/incident/{incident_id}")
async def get_incident_coverage(
    incident_id: str, user: dict = Depends(verify_jwt), _gate: None = _mitre_gate,
):
    """Per-incident MITRE kill-chain detection coverage (WO-B6).

    Maps ONE incident's observed tactic sequence onto the canonical kill chain
    and overlays ORG-WIDE per-tactic detection %. Reuses ``get_incident`` (so
    the read is tenant-scoped) and ``MITRECoverageAnalyzer`` (org overlay — not
    recomputed). ``org_coverage_pct`` is ORG-WIDE, never incident-specific.
    """
    from src.api.dependencies import get_db, get_mitre_analyzer
    from src.database.store import _parse_json_obj
    from src.mitre.coverage import build_incident_chain_coverage

    _db = get_db()
    incident = _db.get_incident(incident_id)  # tenant-scoped — cross-tenant reads 404
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Prefer the ordered M5 kill-chain list; fall back to the (unordered)
    # per-incident tactic list. Both parsed defensively (null/malformed -> []).
    observed = _parse_json_obj(incident.get("attack_chain_tactics"), [])
    if not observed:
        observed = _parse_json_obj(incident.get("mitre_tactics"), [])
    if not isinstance(observed, list):
        observed = []

    # ORG-WIDE per-tactic detection % overlay — reuse the analyzer's existing
    # summary rather than recomputing. Absent analyzer / failure -> no overlay
    # (org_coverage_pct becomes None; gaps then reflect only unseen stages).
    org_by_tactic = {}
    analyzer = get_mitre_analyzer()
    if analyzer:
        try:
            summary = analyzer.get_coverage_summary()
            for row in summary.get("per_tactic", []):
                org_by_tactic[row.get("tactic")] = row.get("coverage_pct")
        except Exception as e:
            logger.warning("incident_coverage_org_overlay_failed",
                           incident_id=incident_id, error=str(e))

    result = build_incident_chain_coverage(observed, org_by_tactic)
    result["incident_id"] = incident_id
    # org_coverage_pct on each stage is ORG-WIDE, not this incident's detection.
    result["coverage_basis"] = "org_wide"
    logger.info("incident_coverage_served", incident_id=incident_id,
                chain_length=result["chain_length"],
                covered_count=result["covered_count"])
    return result


@router.get("/technique/{technique_id}")
async def get_technique(technique_id: str, user: dict = Depends(verify_jwt), _gate: None = _mitre_gate):
    """Get detail for a specific technique."""
    from src.mitre.matrix import TECHNIQUE_NAMES, TECHNIQUE_TACTICS
    if technique_id not in TECHNIQUE_NAMES:
        raise HTTPException(status_code=404, detail="Technique not found")

    from src.api.dependencies import get_db
    _db = get_db()
    records = _db.get_mitre_technique_detail(technique_id)
    return {
        "technique_id": technique_id,
        "technique_name": TECHNIQUE_NAMES.get(technique_id, ""),
        "tactics": TECHNIQUE_TACTICS.get(technique_id, []),
        "coverage": records,
    }
