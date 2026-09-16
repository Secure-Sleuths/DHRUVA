"""
SOC Metrics Calculator — Computes MTTD/MTTA/MTTR and operational metrics.

Uses incident timestamps to derive Mean Time to Detect, Acknowledge, and Resolve.
Stores daily rollups in operational_metrics for historical trending.
"""

import json
import structlog
from datetime import datetime, timezone, timedelta

from src.timestamps import parse_iso8601

logger = structlog.get_logger(__name__)


def _iso_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


class MetricsCalculator:
    """Computes and stores SOC operational metrics."""

    def __init__(self, db):
        self.db = db

    def get_current_metrics(self, days: int = 30) -> dict:
        """Get live MTT metrics computed from incident timestamps."""
        return self.db.compute_mtt_metrics(days=days)

    def get_metric_trends(self, days: int = 30) -> list[dict]:
        """Get daily MTTD/MTTA/MTTR averages for charting."""
        return self.db.get_mtt_daily_trend(days=days)

    def get_analyst_stats(self, days: int = 30) -> list[dict]:
        """Get per-analyst performance stats."""
        return self.db.get_analyst_performance(days=days)

    def compute_daily_rollup(self, date_str: str = None):
        """Compute and store daily MTT metrics rollup.

        Called by scheduler at 1 AM for yesterday's data.
        """
        if not date_str:
            yesterday = datetime.now(timezone.utc) - timedelta(days=1)
            date_str = yesterday.strftime("%Y-%m-%d")

        metrics = self.db.compute_mtt_metrics(days=1)

        for metric_name in ("mttd_min", "mtta_min", "mttr_min",
                            "sla_response_compliance",
                            "sla_resolution_compliance"):
            value = metrics.get(metric_name, 0)
            if value:
                self.db.record_metric(
                    f"daily_{metric_name}",
                    value,
                    {"date": date_str, "sample_count": metrics["sample_count"]},
                )

        logger.info("daily_mtt_rollup_complete",
                     date=date_str,
                     mttd=metrics.get("mttd_min"),
                     mtta=metrics.get("mtta_min"),
                     mttr=metrics.get("mttr_min"),
                     sample_count=metrics.get("sample_count"))

    def get_automation_health(self, days: int = 7) -> dict:
        """Get automation health metrics: enrichment latency and SOAR action stats."""
        import json
        conn = self.db._get_conn()
        tf, tp = self.db._tenant_filter()

        # Enrichment latency stats
        latency_rows = conn.execute(f"""
            SELECT metric_value FROM operational_metrics
            WHERE metric_name = 'enrichment_latency_ms'
            AND recorded_at >= %s {tf}
            ORDER BY metric_value
        """, [_iso_ago(days)] + tp).fetchall()

        latency_stats = {}
        if latency_rows:
            values = sorted([r["metric_value"] for r in latency_rows])
            n = len(values)
            latency_stats = {
                "sample_count": n,
                "p50_ms": round(values[n // 2], 1),
                "p95_ms": round(values[int(n * 0.95)], 1) if n >= 20 else None,
                "p99_ms": round(values[int(n * 0.99)], 1) if n >= 100 else None,
                "avg_ms": round(sum(values) / n, 1),
            }

        # SOAR action stats
        soar_rows = conn.execute(f"""
            SELECT metric_value, dimensions FROM operational_metrics
            WHERE metric_name = 'soar_action_latency_ms'
            AND recorded_at >= %s {tf}
        """, [_iso_ago(days)] + tp).fetchall()

        soar_stats = {"total_actions": 0, "success_count": 0, "failure_count": 0}
        if soar_rows:
            for row in soar_rows:
                soar_stats["total_actions"] += 1
                dims = json.loads(row["dimensions"] or "{}")
                if dims.get("success"):
                    soar_stats["success_count"] += 1
                else:
                    soar_stats["failure_count"] += 1
            if soar_stats["total_actions"] > 0:
                soar_stats["success_rate"] = round(
                    soar_stats["success_count"] / soar_stats["total_actions"] * 100, 1)

        return {
            "period_days": days,
            "enrichment_latency": latency_stats,
            "soar_actions": soar_stats,
        }

    def get_case_aging(self, stale_threshold_hours: int = 48) -> list[dict]:
        """Get open incidents sorted by age, flagging stale cases."""
        conn = self.db._get_conn()
        tf, tp = self.db._tenant_filter()
        rows = conn.execute(f"""
            SELECT id, title, severity, status, assigned_to,
                   created_at, first_response_at, alert_count
            FROM incidents
            WHERE status IN ('open', 'investigating') {tf}
            ORDER BY created_at ASC
        """, [] + tp).fetchall()

        cases = []
        now = datetime.now(timezone.utc)
        for r in rows:
            try:
                # WO-H116: ``incidents.created_at`` is TEXT written by several
                # producers, including ``CURRENT_TIMESTAMP::text``.
                created = parse_iso8601(r["created_at"])
                hours_open = (now - created).total_seconds() / 3600
            except Exception:
                hours_open = 0
            cases.append({
                "id": r["id"], "title": r["title"], "severity": r["severity"],
                "status": r["status"], "assigned_to": r["assigned_to"],
                "created_at": r["created_at"],
                "first_response_at": r["first_response_at"],
                "alert_count": r["alert_count"],
                "hours_open": round(hours_open, 1),
                "is_stale": hours_open > stale_threshold_hours,
            })
        return cases

    def get_automation_rates(self, days: int = 30) -> dict:
        """Get automation rate metrics."""
        conn = self.db._get_conn()
        tf, tp = self.db._tenant_filter()
        row = conn.execute(f"""
            SELECT COUNT(*) as total,
                   SUM(CASE WHEN verdict = 'auto_close' THEN 1 ELSE 0 END) as auto_closed,
                   SUM(CASE WHEN verdict = 'false_positive' THEN 1 ELSE 0 END) as fp,
                   SUM(CASE WHEN verdict = 'true_positive' THEN 1 ELSE 0 END) as tp_count
            FROM agent_decisions
            WHERE agent_type = 'triage'
            AND created_at >= %s {tf}
        """, [_iso_ago(days)] + tp).fetchone()

        total = row["total"] or 0
        auto_closed = row["auto_closed"] or 0
        return {
            "period_days": days,
            "total_decisions": total,
            "auto_closed": auto_closed,
            "auto_close_rate": round(auto_closed / total * 100, 1) if total > 0 else 0,
            "enrichment_automation_pct": 100.0,  # All alerts are auto-enriched
            "false_positives": row["fp"] or 0,
            "true_positives": row["tp_count"] or 0,
            # Deterministic verdict-guard overrides. Surfaced on the SAME panel
            # as auto_close_rate because the guard is what removes alerts from
            # the auto-dismissal path: reading one rate without the other gives
            # a misleading picture of how much triage is actually automated.
            "verdict_guard": self.get_verdict_guard_rates(days=days, total=total),
        }

    def get_verdict_guard_rates(self, days: int = 30, total: int = None) -> dict:
        """Override rate for the deterministic verdict guard.

        The guard blocks a dismissal verdict that contradicts hard enrichment
        evidence (TI hit / known-malicious IOC / tier-1 asset) and forces the
        alert to a human — see src/agents/verdict_guard.py. Every trip emits an
        ``verdict_guard_override`` counter with the firing conditions in its
        dimensions; this aggregates them into a dashboard-ready rate.

        A RISING rate means the model is increasingly trying to dismiss alerts
        that hard evidence says it should not. On a local/small model that is
        the signal to watch: it is the observable footprint of both model
        degradation and a successful prompt-injection attempt.

        ``total`` is the triage-decision count for the same window; passed in by
        get_automation_rates to avoid a second scan, recomputed if omitted.
        Never raises — a metrics panel must not 500 on a reporting query.
        """
        conn = self.db._get_conn()
        tf, tp = self.db._tenant_filter()

        if total is None:
            try:
                r = conn.execute(f"""
                    SELECT COUNT(*) as total FROM agent_decisions
                    WHERE agent_type = 'triage' AND created_at >= %s {tf}
                """, [_iso_ago(days)] + tp).fetchone()
                total = r["total"] or 0
            except Exception:
                total = 0

        empty = {"period_days": days, "overrides": 0, "override_rate": 0.0,
                 "by_trigger": {}, "by_ai_verdict": {}}
        try:
            rows = conn.execute(f"""
                SELECT dimensions FROM operational_metrics
                WHERE metric_name = 'verdict_guard_override'
                AND recorded_at >= %s {tf}
            """, [_iso_ago(days)] + tp).fetchall()
        except Exception as e:
            logger.warning("verdict_guard_rates_failed", error=str(e))
            return empty

        by_trigger, by_ai_verdict = {}, {}
        for r in rows:
            try:
                dims = r["dimensions"]
                dims = json.loads(dims) if isinstance(dims, str) else (dims or {})
            except (ValueError, TypeError):
                dims = {}
            # One override can fire on several conditions at once; count each so
            # operators can see WHICH evidence is doing the blocking.
            for trig in str(dims.get("triggers", "")).split(","):
                trig = trig.strip()
                if trig:
                    by_trigger[trig] = by_trigger.get(trig, 0) + 1
            av = str(dims.get("ai_verdict", "") or "unknown")
            by_ai_verdict[av] = by_ai_verdict.get(av, 0) + 1

        overrides = len(rows)
        return {
            "period_days": days,
            "overrides": overrides,
            "override_rate": round(overrides / total * 100, 1) if total else 0.0,
            "by_trigger": dict(sorted(by_trigger.items(),
                                      key=lambda kv: -kv[1])),
            "by_ai_verdict": dict(sorted(by_ai_verdict.items(),
                                         key=lambda kv: -kv[1])),
        }

    def get_hunt_cycle_trends(self, days: int = 90) -> list[dict]:
        """Get hunt findings per cycle with confirmation rate trend."""
        conn = self.db._get_conn()
        tf, tp = self.db._tenant_filter()
        rows = conn.execute(f"""
            SELECT hunt_cycle_id,
                   COUNT(*) as total_hypotheses,
                   SUM(CASE WHEN result_count > 0 THEN 1 ELSE 0 END) as hits,
                   SUM(CASE WHEN confirmed = 1 THEN 1 ELSE 0 END) as confirmed,
                   MIN(created_at) as cycle_date
            FROM hunt_findings
            WHERE created_at >= %s {tf}
            GROUP BY hunt_cycle_id
            ORDER BY cycle_date DESC
        """, [_iso_ago(days)] + tp).fetchall()

        cycles = []
        for r in rows:
            total = r["total_hypotheses"] or 1
            cycles.append({
                "cycle_id": r["hunt_cycle_id"],
                "total_hypotheses": r["total_hypotheses"],
                "hits": r["hits"],
                "confirmed": r["confirmed"],
                "hit_rate": round((r["hits"] or 0) / total * 100, 1),
                "confirmation_rate": round(
                    (r["confirmed"] or 0) / max(r["hits"] or 1, 1) * 100, 1),
                "cycle_date": r["cycle_date"],
            })
        return cycles

    def check_analyst_workload(self, max_per_analyst: int = 15) -> list[dict]:
        """Check analyst workload and flag overloaded analysts."""
        conn = self.db._get_conn()
        tf, tp = self.db._tenant_filter()
        rows = conn.execute(f"""
            SELECT assigned_to, COUNT(*) as open_count,
                   SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                   SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high
            FROM incidents
            WHERE status IN ('open', 'investigating')
            AND assigned_to IS NOT NULL AND assigned_to != '' {tf}
            GROUP BY assigned_to
            ORDER BY open_count DESC
        """, [] + tp).fetchall()

        analysts = []
        for r in rows:
            analysts.append({
                "analyst": r["assigned_to"],
                "open_incidents": r["open_count"],
                "critical": r["critical"],
                "high": r["high"],
                "is_overloaded": r["open_count"] > max_per_analyst,
            })
        return analysts
