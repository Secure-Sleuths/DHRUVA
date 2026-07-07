"""
MITRE ATT&CK Coverage Analyzer — Computes detection coverage from
triage decisions and generates heatmap data + gap analysis.
"""

import json
import structlog
from datetime import datetime, timezone
from collections import defaultdict

from src.mitre.matrix import (
    MITRE_MATRIX, MITRE_TACTICS, TACTIC_IDS,
    TECHNIQUE_NAMES, TECHNIQUE_TACTICS, ALL_TECHNIQUE_IDS, TOTAL_TECHNIQUES,
    order_tactics, tactic_index,
)

logger = structlog.get_logger(__name__)

# WO-B6: a chain stage is a "low-coverage" gap when its ORG-WIDE per-tactic
# detection coverage falls below this percentage. Named constant so the
# product threshold is explicit and adjustable (not a magic literal).
GAP_COVERAGE_THRESHOLD_PCT = 50.0


def build_incident_chain_coverage(
    observed_tactics: "list[str]",
    org_coverage_by_tactic: "dict | None" = None,
    threshold: float = GAP_COVERAGE_THRESHOLD_PCT,
) -> dict:
    """Map ONE incident's observed tactic sequence onto the canonical kill
    chain and mark each stage covered-vs-gap (WO-B6). Pure function — no DB.

    Args:
      observed_tactics: raw tactic names for this incident (any order, may
        contain unknowns / duplicates / None). Cleaned + canonically ordered
        via ``matrix.order_tactics`` (unknowns dropped, dupes collapsed) — the
        SAME ordering the M5 engine and campaign rollup use; no second copy.
      org_coverage_by_tactic: ``{tactic_name: coverage_pct}`` sourced from
        ``MITRECoverageAnalyzer.get_coverage_summary()['per_tactic']``. This is
        ORG-WIDE per-tactic detection %, NOT incident-specific. Missing/None
        for a tactic → ``org_coverage_pct = None`` and that stage cannot be a
        low-coverage gap (only an unseen-intermediate gap).
      threshold: org coverage % below which a present stage counts as a gap.

    Definitions (documented, honest):
      * "chain" = the contiguous canonical kill-chain SPAN from the incident's
        earliest observed tactic to its furthest (latest) observed tactic,
        inclusive. Intermediate canonical tactics the incident did NOT touch
        are filled in (they are candidate blind spots in the middle of an
        observed chain).
      * ``present_in_incident`` = the incident actually surfaced this tactic.
      * a stage ``is_gap`` when EITHER it is an unseen intermediate tactic
        (``present_in_incident`` False) OR its ORG-WIDE coverage % is below
        ``threshold`` (weak org detection even where the stage was observed).
      * ``covered_count`` = span stages that are NOT gaps.
      * ``weakest_tactic`` = the span stage with the lowest KNOWN org coverage
        % (the "Discovery gap"-style label); None if no org % is known.
      * ``furthest_tactic`` = the furthest (highest canonical index) tactic the
        incident actually reached.

    Never raises on malformed input — an empty/unknown-only tactic list yields
    an empty chain with zero counts.
    """
    org = org_coverage_by_tactic or {}
    observed = order_tactics(observed_tactics or [])
    if not observed:
        return {
            "chain": [],
            "covered_count": 0,
            "chain_length": 0,
            "weakest_tactic": None,
            "furthest_tactic": None,
        }

    observed_set = set(observed)
    first_idx = tactic_index(observed[0])
    last_idx = tactic_index(observed[-1])
    span = MITRE_TACTICS[first_idx:last_idx + 1]

    chain = []
    covered_count = 0
    weakest_tactic = None
    weakest_pct = None
    for tactic in span:
        present = tactic in observed_set
        pct = org.get(tactic)  # ORG-WIDE %, may be None if unknown
        low_coverage = pct is not None and pct < threshold
        is_gap = (not present) or low_coverage
        entry = {
            "tactic": tactic,
            "tactic_id": TACTIC_IDS.get(tactic, ""),
            "present_in_incident": present,
            "org_coverage_pct": pct,
        }
        if is_gap:
            entry["is_gap"] = True
        else:
            covered_count += 1
        chain.append(entry)
        if pct is not None and (weakest_pct is None or pct < weakest_pct):
            weakest_pct = pct
            weakest_tactic = tactic

    return {
        "chain": chain,
        "covered_count": covered_count,
        "chain_length": len(span),
        "weakest_tactic": weakest_tactic,
        "furthest_tactic": observed[-1],
    }


class MITRECoverageAnalyzer:
    """Analyzes MITRE ATT&CK coverage from triage data."""

    def __init__(self, db):
        self.db = db

    def compute_coverage(self, days: int = 90):
        """Compute technique detection coverage from agent decisions.

        Queries enrichment_summary JSON for MITRE techniques, counts
        detections and TP/FP splits, writes to mitre_coverage table.
        """
        counts = self.db.get_technique_counts_from_decisions(days=days)
        now = datetime.now(timezone.utc).isoformat()

        for tech_id in ALL_TECHNIQUE_IDS:
            data = counts.get(tech_id, {})
            detection_count = data.get("total", 0)
            tp_count = data.get("tp", 0)
            fp_count = data.get("fp", 0)
            last_seen = data.get("last_seen")
            rule_ids = json.dumps(list(data.get("rule_ids", set())))

            # Determine coverage status
            if detection_count == 0:
                status = "not_detected"
            elif last_seen and self._days_ago(last_seen) > 90:
                status = "stale"
            elif detection_count > 0 and fp_count / max(detection_count, 1) > 0.7:
                status = "noisy"
            else:
                status = "active"

            # Get tactics for this technique
            tactics = TECHNIQUE_TACTICS.get(tech_id, ["Unknown"])
            for tactic in tactics:
                self.db.save_mitre_coverage({
                    "technique_id": tech_id,
                    "technique_name": TECHNIQUE_NAMES.get(tech_id, tech_id),
                    "tactic": tactic,
                    "detection_count": detection_count,
                    "tp_count": tp_count,
                    "fp_count": fp_count,
                    "last_seen": last_seen,
                    "rule_ids": rule_ids,
                    "coverage_status": status,
                    "updated_at": now,
                })

        logger.info("mitre_coverage_computed",
                     techniques_in_matrix=TOTAL_TECHNIQUES,
                     techniques_detected=len(
                         [t for t in counts if counts[t].get("total", 0) > 0]))

    @staticmethod
    def _days_ago(iso_str: str) -> int:
        try:
            dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - dt).days
        except (ValueError, TypeError):
            return 999

    def get_heatmap_data(self) -> dict:
        """Return heatmap data organized by tactic for the dashboard."""
        coverage = self.db.get_mitre_coverage()
        coverage_map = {}
        for row in coverage:
            key = (row["technique_id"], row["tactic"])
            coverage_map[key] = row

        result = []
        for tactic in MITRE_TACTICS:
            techniques = MITRE_MATRIX.get(tactic, [])
            tactic_data = {
                "tactic": tactic,
                "tactic_id": TACTIC_IDS.get(tactic, ""),
                "techniques": [],
            }
            for tech in techniques:
                cov = coverage_map.get((tech["id"], tactic), {})
                tactic_data["techniques"].append({
                    "id": tech["id"],
                    "name": tech["name"],
                    "detection_count": cov.get("detection_count", 0),
                    "tp_count": cov.get("tp_count", 0),
                    "fp_count": cov.get("fp_count", 0),
                    "status": cov.get("coverage_status", "not_detected"),
                    "last_seen": cov.get("last_seen"),
                })
            result.append(tactic_data)

        return {"tactics": result}

    def get_gap_analysis(self) -> dict:
        """Return techniques with zero detections, grouped by tactic."""
        coverage = self.db.get_mitre_coverage()
        detected_ids = {r["technique_id"] for r in coverage
                        if r.get("detection_count", 0) > 0}

        gaps = defaultdict(list)
        for tactic in MITRE_TACTICS:
            for tech in MITRE_MATRIX.get(tactic, []):
                if tech["id"] not in detected_ids:
                    gaps[tactic].append({
                        "id": tech["id"],
                        "name": tech["name"],
                    })

        return {
            "gaps": dict(gaps),
            "total_gaps": sum(len(v) for v in gaps.values()),
            "total_techniques": TOTAL_TECHNIQUES,
            "coverage_pct": round(
                (1 - sum(len(v) for v in gaps.values()) / max(TOTAL_TECHNIQUES, 1)) * 100, 1),
        }

    def get_coverage_summary(self) -> dict:
        """Return per-tactic coverage percentages and overall stats."""
        coverage = self.db.get_mitre_coverage()
        detected_by_tactic = defaultdict(set)
        total_by_tactic = {}

        for row in coverage:
            if row.get("detection_count", 0) > 0:
                detected_by_tactic[row["tactic"]].add(row["technique_id"])

        for tactic in MITRE_TACTICS:
            total_by_tactic[tactic] = len(MITRE_MATRIX.get(tactic, []))

        all_detected = set()
        for row in coverage:
            if row.get("detection_count", 0) > 0:
                all_detected.add(row["technique_id"])

        per_tactic = []
        for tactic in MITRE_TACTICS:
            total = total_by_tactic.get(tactic, 0)
            detected = len(detected_by_tactic.get(tactic, set()))
            per_tactic.append({
                "tactic": tactic,
                "tactic_id": TACTIC_IDS.get(tactic, ""),
                "total": total,
                "detected": detected,
                "coverage_pct": round(
                    (detected / max(total, 1)) * 100, 1),
            })

        return {
            "per_tactic": per_tactic,
            "overall": {
                "total_techniques": TOTAL_TECHNIQUES,
                "detected": len(all_detected),
                "coverage_pct": round(
                    (len(all_detected) / max(TOTAL_TECHNIQUES, 1)) * 100, 1),
            },
        }
