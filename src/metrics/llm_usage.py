"""
LLM Usage Metrics and Cost Tracking

Provides detailed analytics on LLM usage per tenant, including token consumption,
costs, performance metrics, and budget monitoring.
"""

import structlog
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

logger = structlog.get_logger(__name__)


@dataclass
class UsageReport:
    """Container for usage report data."""
    tenant_id: str
    period_start: str
    period_end: str
    total_requests: int
    total_tokens_input: int
    total_tokens_output: int
    total_cost_usd: float
    avg_latency_ms: float
    success_rate: float
    provider_breakdown: Dict[str, dict]
    model_breakdown: Dict[str, dict]
    request_type_breakdown: Dict[str, dict]


class LLMUsageAnalyzer:
    """Analyze and report on LLM usage patterns."""

    def __init__(self, db):
        self.db = db

    def get_tenant_usage_report(self, tenant_id: str, days: int = 30) -> UsageReport:
        """Generate comprehensive usage report for a tenant."""
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)

        # Get usage metrics from database
        # Note: This queries the generic metrics table for now
        # TODO: Query dedicated llm_usage_metrics table when available
        usage_metrics = self._get_usage_metrics(tenant_id, start_date, end_date)

        if not usage_metrics:
            return self._empty_report(tenant_id, start_date, end_date)

        # Aggregate metrics
        total_requests = len(usage_metrics)
        total_tokens_input = sum(m.get("tokens_input", 0) for m in usage_metrics)
        total_tokens_output = sum(m.get("tokens_output", 0) for m in usage_metrics)
        total_cost = sum(m.get("cost_usd", 0) for m in usage_metrics)

        # Calculate averages
        avg_latency = sum(m.get("latency_ms", 0) for m in usage_metrics) / total_requests
        success_count = sum(1 for m in usage_metrics if m.get("success", True))
        success_rate = success_count / total_requests

        # Provider breakdown
        provider_breakdown = self._breakdown_by_field(usage_metrics, "provider")

        # Model breakdown
        model_breakdown = self._breakdown_by_field(usage_metrics, "model")

        # Request type breakdown
        request_type_breakdown = self._breakdown_by_field(usage_metrics, "request_type")

        return UsageReport(
            tenant_id=tenant_id,
            period_start=start_date.isoformat(),
            period_end=end_date.isoformat(),
            total_requests=total_requests,
            total_tokens_input=total_tokens_input,
            total_tokens_output=total_tokens_output,
            total_cost_usd=round(total_cost, 4),
            avg_latency_ms=round(avg_latency, 2),
            success_rate=round(success_rate, 4),
            provider_breakdown=provider_breakdown,
            model_breakdown=model_breakdown,
            request_type_breakdown=request_type_breakdown
        )

    def get_all_tenants_usage_summary(self, days: int = 30) -> List[Dict]:
        """Get usage summary for all active tenants."""
        from src.database.tenant_registry import TenantServiceRegistry

        # Get all active tenants
        registry = TenantServiceRegistry(self.db)
        active_tenants = registry.get_active_tenant_ids()

        summaries = []
        for tenant_id in active_tenants:
            report = self.get_tenant_usage_report(tenant_id, days)
            summaries.append({
                "tenant_id": tenant_id,
                "total_requests": report.total_requests,
                "total_cost_usd": report.total_cost_usd,
                "total_tokens": report.total_tokens_input + report.total_tokens_output,
                "success_rate": report.success_rate,
                "avg_latency_ms": report.avg_latency_ms,
                "primary_provider": self._get_primary_provider(report.provider_breakdown)
            })

        # Sort by total cost descending
        summaries.sort(key=lambda x: x["total_cost_usd"], reverse=True)
        return summaries

    def check_budget_alerts(self, tenant_id: str) -> List[Dict]:
        """Check for budget overruns and generate alerts."""
        from src.database.tenant_registry import TenantServiceRegistry

        registry = TenantServiceRegistry(self.db)
        llm_config = registry.get_llm_config(tenant_id)

        monthly_budget = llm_config.get("usage_tracking", {}).get("monthly_budget")
        if not monthly_budget:
            return []  # No budget configured

        # Get current month usage
        now = datetime.now(timezone.utc)
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        current_month_usage = self.get_tenant_usage_report(
            tenant_id, days=(now - month_start).days + 1)

        current_spend = current_month_usage.total_cost_usd
        budget_utilization = current_spend / monthly_budget

        alerts = []

        # Generate alerts based on utilization
        if budget_utilization >= 1.0:
            alerts.append({
                "type": "budget_exceeded",
                "severity": "critical",
                "message": f"Monthly budget exceeded: ${current_spend:.2f} / ${monthly_budget:.2f}",
                "budget_utilization": budget_utilization,
                "current_spend": current_spend,
                "monthly_budget": monthly_budget
            })
        elif budget_utilization >= 0.9:
            alerts.append({
                "type": "budget_warning",
                "severity": "warning",
                "message": f"90% of monthly budget used: ${current_spend:.2f} / ${monthly_budget:.2f}",
                "budget_utilization": budget_utilization,
                "current_spend": current_spend,
                "monthly_budget": monthly_budget
            })
        elif budget_utilization >= 0.75:
            alerts.append({
                "type": "budget_notice",
                "severity": "info",
                "message": f"75% of monthly budget used: ${current_spend:.2f} / ${monthly_budget:.2f}",
                "budget_utilization": budget_utilization,
                "current_spend": current_spend,
                "monthly_budget": monthly_budget
            })

        return alerts

    def get_cost_trends(self, tenant_id: str, days: int = 90) -> Dict:
        """Get cost trends over time for a tenant."""
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)

        usage_metrics = self._get_usage_metrics(tenant_id, start_date, end_date)

        # Group by day
        daily_costs = {}
        for metric in usage_metrics:
            day = metric.get("created_at", "")[:10]  # YYYY-MM-DD
            if day not in daily_costs:
                daily_costs[day] = {
                    "cost": 0,
                    "requests": 0,
                    "tokens": 0
                }
            daily_costs[day]["cost"] += metric.get("cost_usd", 0)
            daily_costs[day]["requests"] += 1
            daily_costs[day]["tokens"] += (
                metric.get("tokens_input", 0) + metric.get("tokens_output", 0)
            )

        # Convert to sorted list
        trend_data = []
        for day in sorted(daily_costs.keys()):
            trend_data.append({
                "date": day,
                **daily_costs[day]
            })

        return {
            "tenant_id": tenant_id,
            "period_days": days,
            "daily_trends": trend_data,
            "total_cost": sum(day["cost"] for day in trend_data),
            "avg_daily_cost": sum(day["cost"] for day in trend_data) / max(1, len(trend_data))
        }

    def _get_usage_metrics(self, tenant_id: str, start_date: datetime,
                          end_date: datetime) -> List[Dict]:
        """Retrieve usage metrics from dedicated llm_usage_metrics table."""
        try:
            conn = self.db._get_conn()

            # Query dedicated llm_usage_metrics table
            rows = conn.execute("""
                SELECT
                    id, tenant_id, provider, model, request_type,
                    tokens_input, tokens_output, cost_usd, latency_ms,
                    success, error_type, created_at
                FROM llm_usage_metrics
                WHERE tenant_id = %s
                AND created_at BETWEEN %s AND %s
                ORDER BY created_at DESC
            """, (
                tenant_id,
                start_date.isoformat(),
                end_date.isoformat()
            )).fetchall()

            metrics = []
            for row in rows:
                try:
                    metrics.append({
                        "id": row["id"],
                        "tenant_id": row["tenant_id"],
                        "provider": row["provider"],
                        "model": row["model"],
                        "request_type": row["request_type"],
                        "tokens_input": row["tokens_input"],
                        "tokens_output": row["tokens_output"],
                        "cost_usd": row["cost_usd"],
                        "latency_ms": row["latency_ms"],
                        "success": bool(row["success"]),
                        "error_type": row["error_type"],
                        "created_at": row["created_at"]
                    })
                except (KeyError, TypeError):
                    continue

            return metrics
        except Exception as e:
            logger.error("usage_metrics_query_failed",
                        tenant_id=tenant_id, error=str(e))
            return []

    def _empty_report(self, tenant_id: str, start_date: datetime,
                     end_date: datetime) -> UsageReport:
        """Generate empty report when no usage data found."""
        return UsageReport(
            tenant_id=tenant_id,
            period_start=start_date.isoformat(),
            period_end=end_date.isoformat(),
            total_requests=0,
            total_tokens_input=0,
            total_tokens_output=0,
            total_cost_usd=0.0,
            avg_latency_ms=0.0,
            success_rate=1.0,
            provider_breakdown={},
            model_breakdown={},
            request_type_breakdown={}
        )

    def _breakdown_by_field(self, metrics: List[Dict], field: str) -> Dict[str, dict]:
        """Break down metrics by a specific field."""
        breakdown = {}

        for metric in metrics:
            value = metric.get(field, "unknown")
            if value not in breakdown:
                breakdown[value] = {
                    "requests": 0,
                    "tokens_input": 0,
                    "tokens_output": 0,
                    "cost_usd": 0.0,
                    "avg_latency_ms": 0.0,
                    "success_rate": 0.0
                }

            breakdown[value]["requests"] += 1
            breakdown[value]["tokens_input"] += metric.get("tokens_input", 0)
            breakdown[value]["tokens_output"] += metric.get("tokens_output", 0)
            breakdown[value]["cost_usd"] += metric.get("cost_usd", 0)
            breakdown[value]["avg_latency_ms"] += metric.get("latency_ms", 0)
            if metric.get("success", True):
                breakdown[value]["success_rate"] += 1

        # Calculate averages
        for value_data in breakdown.values():
            if value_data["requests"] > 0:
                value_data["avg_latency_ms"] /= value_data["requests"]
                value_data["success_rate"] /= value_data["requests"]
                value_data["cost_usd"] = round(value_data["cost_usd"], 4)
                value_data["avg_latency_ms"] = round(value_data["avg_latency_ms"], 2)
                value_data["success_rate"] = round(value_data["success_rate"], 4)

        return breakdown

    def _get_primary_provider(self, provider_breakdown: Dict) -> str:
        """Get the provider with the most requests."""
        if not provider_breakdown:
            return "unknown"

        return max(provider_breakdown.items(),
                  key=lambda x: x[1]["requests"])[0]


class LLMCostOptimizer:
    """Suggest cost optimizations based on usage patterns."""

    def __init__(self, analyzer: LLMUsageAnalyzer):
        self.analyzer = analyzer

    def get_optimization_suggestions(self, tenant_id: str, days: int = 30) -> List[Dict]:
        """Generate cost optimization suggestions for a tenant."""
        report = self.analyzer.get_tenant_usage_report(tenant_id, days)
        suggestions = []

        # Analyze provider costs
        if len(report.provider_breakdown) > 1:
            providers_by_cost = sorted(
                report.provider_breakdown.items(),
                key=lambda x: x[1]["cost_usd"],
                reverse=True
            )

            most_expensive = providers_by_cost[0]
            least_expensive = providers_by_cost[-1]

            cost_diff = most_expensive[1]["cost_usd"] - least_expensive[1]["cost_usd"]
            if cost_diff > 10:  # $10+ difference
                suggestions.append({
                    "type": "provider_cost_optimization",
                    "priority": "high",
                    "description": f"Consider using {least_expensive[0]} more often. "
                                 f"Could save ${cost_diff:.2f} per month.",
                    "current_expensive_provider": most_expensive[0],
                    "suggested_provider": least_expensive[0],
                    "potential_savings": cost_diff
                })

        # Analyze model usage
        if "claude-sonnet-4" in report.model_breakdown and "claude-haiku-4" in report.model_breakdown:
            sonnet_cost = report.model_breakdown["claude-sonnet-4"]["cost_usd"]
            haiku_cost = report.model_breakdown["claude-haiku-4"]["cost_usd"]

            if sonnet_cost > haiku_cost * 3:
                suggestions.append({
                    "type": "model_optimization",
                    "priority": "medium",
                    "description": "Consider using Claude Haiku for simpler tasks. "
                                 f"Sonnet costs are ${sonnet_cost:.2f} vs Haiku ${haiku_cost:.2f}",
                    "expensive_model": "claude-sonnet-4",
                    "cheaper_alternative": "claude-haiku-4"
                })

        # Check for high-cost low-success patterns
        for provider, data in report.provider_breakdown.items():
            if data["success_rate"] < 0.8 and data["cost_usd"] > 50:
                suggestions.append({
                    "type": "reliability_cost_issue",
                    "priority": "high",
                    "description": f"Provider {provider} has low success rate ({data['success_rate']:.2%}) "
                                 f"but high cost (${data['cost_usd']:.2f}). Consider investigating.",
                    "provider": provider,
                    "success_rate": data["success_rate"],
                    "cost": data["cost_usd"]
                })

        return suggestions