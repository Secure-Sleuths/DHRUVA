/**
 * LLM Usage FIXTURE — screenshot / dev-preview only (parity-restore:
 * Reports → LLM Usage).
 *
 * Reached solely from `api.ts::getLlmUsageReport` / `getLlmBudgetAlerts` /
 * `getLlmCostTrends` / `getLlmOptimization` when `NEXT_PUBLIC_DHRUVA_FIXTURES`
 * is set, via dynamic import so it is dead-code-eliminated from a normal
 * production bundle. The real path calls the live
 * `GET /api/v1/llm-usage/tenant/{tenant_id}/...` (verify_jwt + own-tenant scope;
 * NO license gate).
 *
 * Mirrors the ROUTE-reshaped response EXACTLY (breakdowns.{providers,models,
 * request_types}, summary.total_tokens; success_rate is a 0-1 fraction).
 * Fabricates NO capability the backend lacks. There is no license gate here, so
 * there is no locked variant.
 */

import type {
  LlmBudgetAlertsResponse,
  LlmCostTrendsResponse,
  LlmOptimizationResponse,
  LlmUsageReportResponse,
} from "../types";

interface Opts {
  empty?: boolean;
  tenantId: string;
  days?: number;
}

export function llmUsageReportFixture(opts: Opts): LlmUsageReportResponse {
  const days = opts.days ?? 30;
  if (opts.empty) {
    return {
      success: true,
      report: {
        tenant_id: opts.tenantId,
        period: { start: "2026-06-03", end: "2026-07-03", days },
        summary: {
          total_requests: 0,
          total_tokens_input: 0,
          total_tokens_output: 0,
          total_tokens: 0,
          total_cost_usd: 0,
          avg_latency_ms: 0,
          success_rate: 0,
        },
        breakdowns: { providers: {}, models: {}, request_types: {} },
      },
    };
  }
  return {
    success: true,
    report: {
      tenant_id: opts.tenantId,
      period: { start: "2026-06-03", end: "2026-07-03", days },
      summary: {
        total_requests: 8420,
        total_tokens_input: 12_940_000,
        total_tokens_output: 3_110_000,
        total_tokens: 16_050_000,
        total_cost_usd: 214.83,
        avg_latency_ms: 1840.2,
        success_rate: 0.987,
      },
      breakdowns: {
        providers: {
          anthropic: {
            requests: 6100,
            tokens_input: 9_800_000,
            tokens_output: 2_300_000,
            cost_usd: 178.4,
            avg_latency_ms: 1910.0,
            success_rate: 0.991,
          },
          openai: {
            requests: 2320,
            tokens_input: 3_140_000,
            tokens_output: 810_000,
            cost_usd: 36.43,
            avg_latency_ms: 1660.0,
            success_rate: 0.977,
          },
        },
        models: {
          "claude-opus-4": {
            requests: 4100,
            tokens_input: 7_200_000,
            tokens_output: 1_700_000,
            cost_usd: 142.1,
            avg_latency_ms: 2010.0,
            success_rate: 0.992,
          },
          "gpt-4o-mini": {
            requests: 2320,
            tokens_input: 3_140_000,
            tokens_output: 810_000,
            cost_usd: 36.43,
            avg_latency_ms: 1660.0,
            success_rate: 0.977,
          },
        },
        request_types: {
          triage: {
            requests: 5200,
            tokens_input: 8_600_000,
            tokens_output: 1_900_000,
            cost_usd: 128.9,
            avg_latency_ms: 1880.0,
            success_rate: 0.99,
          },
          nl_query: {
            requests: 1900,
            tokens_input: 2_900_000,
            tokens_output: 820_000,
            cost_usd: 54.2,
            avg_latency_ms: 1780.0,
            success_rate: 0.985,
          },
          detection: {
            requests: 1320,
            tokens_input: 1_440_000,
            tokens_output: 390_000,
            cost_usd: 31.7,
            avg_latency_ms: 1720.0,
            success_rate: 0.981,
          },
        },
      },
    },
  };
}

export function llmBudgetAlertsFixture(opts: Opts): LlmBudgetAlertsResponse {
  if (opts.empty) {
    return {
      success: true,
      tenant_id: opts.tenantId,
      alerts: [],
      alert_count: 0,
      has_critical: false,
    };
  }
  return {
    success: true,
    tenant_id: opts.tenantId,
    alerts: [
      {
        type: "budget_warning",
        severity: "warning",
        message:
          "Spend is at 91% of the $250 monthly budget with 6 days remaining.",
        budget_utilization: 0.91,
        current_spend: 227.5,
        monthly_budget: 250.0,
      },
    ],
    alert_count: 1,
    has_critical: false,
  };
}

export function llmCostTrendsFixture(opts: Opts): LlmCostTrendsResponse {
  const days = opts.days ?? 30;
  if (opts.empty) {
    return {
      success: true,
      trends: {
        tenant_id: opts.tenantId,
        period_days: days,
        daily_trends: [],
        total_cost: 0,
        avg_daily_cost: 0,
      },
    };
  }
  const daily_trends = [
    { date: "2026-06-28", cost: 6.9, requests: 268, tokens: 512_000 },
    { date: "2026-06-29", cost: 7.4, requests: 291, tokens: 548_000 },
    { date: "2026-06-30", cost: 8.1, requests: 322, tokens: 601_000 },
    { date: "2026-07-01", cost: 7.8, requests: 305, tokens: 579_000 },
    { date: "2026-07-02", cost: 9.2, requests: 361, tokens: 664_000 },
  ];
  return {
    success: true,
    trends: {
      tenant_id: opts.tenantId,
      period_days: days,
      daily_trends,
      total_cost: 214.83,
      avg_daily_cost: 7.16,
    },
  };
}

export function llmOptimizationFixture(opts: Opts): LlmOptimizationResponse {
  const days = opts.days ?? 30;
  if (opts.empty) {
    return {
      success: true,
      tenant_id: opts.tenantId,
      suggestions: [],
      analysis_period_days: days,
      suggestion_count: 0,
      high_priority_count: 0,
    };
  }
  return {
    success: true,
    tenant_id: opts.tenantId,
    suggestions: [
      {
        type: "provider_cost_optimization",
        priority: "high",
        description:
          "openai handles 28% of requests at a higher blended token cost. Routing low-complexity triage to your primary provider could cut spend.",
        current_expensive_provider: "openai",
        suggested_provider: "anthropic",
        potential_savings: 22.4,
      },
      {
        type: "model_optimization",
        priority: "medium",
        description:
          "A cheaper model handles simple NL-query summaries at comparable quality for this workload.",
        expensive_model: "claude-opus-4",
        cheaper_alternative: "claude-haiku-4",
      },
    ],
    analysis_period_days: days,
    suggestion_count: 2,
    high_priority_count: 1,
  };
}
