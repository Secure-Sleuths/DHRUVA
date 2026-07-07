"""
OpenSearch Client - Stores enriched alerts, agent decisions, and baselines.
"""

import json
import structlog
from datetime import datetime, timezone
import time
from typing import Optional
from opensearchpy import OpenSearch, helpers
from opensearchpy.exceptions import (
    ConnectionError as OSConnectionError,
    RequestError,
    TransportError,
)
from src.database.store import _tenant_ctx, _CROSS_TENANT, is_multi_tenant, TenantContextRequired

# Index result codes — used by index_enriched_alert and consumed by the
# buffer-flush poison-pill quarantine path in src/pipeline/alert_buffer.py.
INDEX_OK = "ok"          # Document indexed successfully.
INDEX_REJECT = "reject"  # OpenSearch 400/422 (mapping/validation). Permanent
                         # failure — retrying will never succeed. Caller should
                         # quarantine the document, NOT keep retrying.
INDEX_DOWN = "down"      # Transport/connection/auth/429/5xx. Transient —
                         # caller should keep the document buffered and retry.

logger = structlog.get_logger(__name__)


class OpenSearchClient:
    """Client for the Wazuh OpenSearch indexer."""

    def __init__(self, hosts: list, username: str, password: str,
                 verify_ssl: bool = True, ca_certs: Optional[str] = None,
                 indices: dict = None):
        # Build the OpenSearch client kwargs explicitly. opensearch-py treats
        # `verify_certs` as a bool: passing a string path through it would
        # be truthy but ignored, falling back to system CAs (the cheersin
        # symptom: "[SSL: CERTIFICATE_VERIFY_FAILED] unable to get local
        # issuer certificate" despite a working bundle on disk). When a
        # ca_certs path is supplied we keep verify_certs=True and pass the
        # path through the dedicated ca_certs kwarg.
        client_kwargs = {
            "hosts": hosts,
            "http_auth": (username, password),
            "use_ssl": True,
            "ssl_show_warn": False,
            "timeout": 30,
        }
        if ca_certs:
            client_kwargs["verify_certs"] = True
            client_kwargs["ca_certs"] = ca_certs
        else:
            client_kwargs["verify_certs"] = bool(verify_ssl)
        self.client = OpenSearch(**client_kwargs)
        self.indices = indices or {}
        self._indices_ready = False
        try:
            self._ensure_indices()
            self._indices_ready = True
        except Exception as e:
            logger.warning("opensearch_unavailable_at_startup",
                           error=str(e),
                           message="Will retry index creation on first write")

    # Dynamic-mapping defaults shared by all custom indices.
    # date_detection=false: prevents OpenSearch from inferring `date` from
    #   ISO-ish strings (e.g. a single timestamp value buried in an array of
    #   mixed audit strings) and then atomically rejecting subsequent docs
    #   where other entries can't be coerced. The atomic rejection prevents
    #   the mapping from ever persisting, so the error is invisible to
    #   `_mapping` queries — exactly the cheersin 2026-05-13 freeze.
    # all_strings_keyword: any string field we haven't explicitly mapped
    #   defaults to keyword (aggregatable, sortable) rather than text. Wazuh
    #   relays raw cloud-audit payloads (M365/AWS/Azure) under `data.*` which
    #   would otherwise need full-text indexing we never use.
    _DYNAMIC_MAPPING_DEFAULTS = {
        "date_detection": False,
        "dynamic_templates": [
            {
                "audit_value_strings_to_keyword": {
                    "path_match": "data.event.AuditKeyValues.ValueString",
                    "mapping": {"type": "keyword"}
                }
            },
            {
                "all_strings_keyword": {
                    "match_mapping_type": "string",
                    "mapping": {"type": "keyword"}
                }
            }
        ]
    }

    def _ensure_indices(self):
        """Create custom indices if they don't exist."""
        index_mappings = {
            "ai-soc-enriched-alerts": {
                "mappings": {
                    **self._DYNAMIC_MAPPING_DEFAULTS,
                    "properties": {
                        "alert_id": {"type": "keyword"},
                        "client_id": {"type": "keyword"},
                        "timestamp": {"type": "date"},
                        "rule_id": {"type": "integer"},
                        "rule_level": {"type": "integer"},
                        "rule_description": {"type": "text"},
                        "rule_groups": {"type": "keyword"},
                        "rule_mitre": {"type": "keyword"},
                        "agent_id": {"type": "keyword"},
                        "agent_name": {"type": "keyword"},
                        "agent_ip": {"type": "ip"},
                        "src_ip": {"type": "ip"},
                        "dst_ip": {"type": "ip"},
                        "src_user": {"type": "keyword"},
                        "dst_user": {"type": "keyword"},
                        "data": {"type": "object", "enabled": True},
                        "enrichment": {
                            "type": "object",
                            "properties": {
                                "asset_tier": {"type": "keyword"},
                                "asset_owner": {"type": "keyword"},
                                "user_risk_level": {"type": "keyword"},
                                "threat_intel_hits": {"type": "integer"},
                                "threat_intel_sources": {"type": "keyword"},
                                "historical_fp_rate": {"type": "float"},
                                "historical_occurrence_count": {"type": "integer"},
                                "baseline_anomaly": {"type": "boolean"},
                                "baseline_deviation": {"type": "float"},
                                "baseline_anomaly_details": {"type": "object", "enabled": True},
                                "risk_score": {"type": "float"},
                                "time_context": {"type": "keyword"}
                            }
                        },
                        "triage": {
                            "type": "object",
                            "properties": {
                                "verdict": {"type": "keyword"},
                                "confidence": {"type": "float"},
                                "reasoning": {"type": "text"},
                                "playbook_used": {"type": "keyword"},
                                "escalated": {"type": "boolean"},
                                "actions": {"type": "keyword"}
                            }
                        }
                    }
                },
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0
                }
            },
            "ai-soc-agent-decisions": {
                "mappings": {
                    **self._DYNAMIC_MAPPING_DEFAULTS,
                    "properties": {
                        "decision_id": {"type": "keyword"},
                        "alert_id": {"type": "keyword"},
                        "agent_type": {"type": "keyword"},
                        "verdict": {"type": "keyword"},
                        "confidence": {"type": "float"},
                        "risk_score": {"type": "float"},
                        "reasoning": {"type": "text"},
                        "timestamp": {"type": "date"}
                    }
                }
            }
        }

        for idx_name, idx_body in index_mappings.items():
            if not self.client.indices.exists(index=idx_name):
                try:
                    self.client.indices.create(index=idx_name, body=idx_body)
                    logger.info("opensearch_index_created", index=idx_name)
                except Exception as e:
                    logger.warning("opensearch_index_create_failed",
                                   index=idx_name, error=str(e))
            else:
                # Existing index — patch dynamic-mapping defaults onto it so
                # operators on platforms predating v4.8.6 self-heal on next
                # startup without needing manual PUT /_mapping. The patch is
                # idempotent (date_detection / dynamic_templates are mutable
                # post-creation and only affect future field creation, never
                # existing mappings).
                try:
                    self.client.indices.put_mapping(
                        index=idx_name,
                        body=self._DYNAMIC_MAPPING_DEFAULTS,
                    )
                except Exception as e:
                    logger.debug("opensearch_dynamic_mapping_patch_failed",
                                 index=idx_name, error=str(e))

    def is_available(self) -> bool:
        """Check if OpenSearch is reachable. Cached for 30 seconds."""
        now = time.monotonic()
        if hasattr(self, '_avail_cache') and now - self._avail_cache_at < 30:
            return self._avail_cache
        try:
            self.client.info()
            self._avail_cache = True
        except Exception:
            self._avail_cache = False
        self._avail_cache_at = now
        return self._avail_cache

    @staticmethod
    def _add_query_filter(body: dict, clause: dict) -> dict:
        """Safely add a filter clause to any OpenSearch query DSL shape.

        Handles three cases:
        - No query → creates bool.filter
        - Existing bool query → appends to bool.filter
        - Non-bool query (range, match, term, match_all) → wraps as
          bool.must + bool.filter
        """
        original = body.get("query")
        if not original:
            body["query"] = {"bool": {"filter": [clause]}}
        elif isinstance(original, dict) and set(original.keys()) == {"bool"}:
            filt = original["bool"].setdefault("filter", [])
            if isinstance(filt, dict):
                original["bool"]["filter"] = [filt]
            original["bool"]["filter"].append(clause)
        else:
            body["query"] = {
                "bool": {"must": [original], "filter": [clause]}
            }
        return body

    def _inject_tenant_filter(self, query: dict, client_id: str = None) -> dict:
        """Inject client_id filter into a bool query for tenant isolation.

        Fail-closed in multi-tenant mode: raises TenantContextRequired when
        no tenant context is set and no explicit client_id is provided.
        In single-tenant mode, returns the unfiltered query for backward compat.
        """
        cid = client_id or _tenant_ctx.get()
        if cid == _CROSS_TENANT:
            return query  # explicit admin bypass
        if not cid:
            if is_multi_tenant():
                raise TenantContextRequired(
                    "OpenSearch query requires tenant context in multi-tenant mode. "
                    "Use db.set_tenant() or db.cross_tenant() first."
                )
            return query  # single-tenant backward compat

        return self._add_query_filter(query, {"term": {"client_id": cid}})

    # ----- Indexing -----

    def _lazy_ensure_indices(self):
        """Retry index creation if it failed at startup."""
        if not self._indices_ready:
            try:
                self._ensure_indices()
                self._indices_ready = True
                logger.info("opensearch_indices_ready_after_retry")
            except Exception as e:
                logger.debug("opensearch_still_unavailable", error=str(e))

    @staticmethod
    def _sanitize_ip_fields(doc: dict) -> dict:
        """Coerce empty-string IP fields to None before indexing.

        OpenSearch rejects "" for fields mapped as type "ip". The main
        normalize_alert path already handles this, but any code path that
        bypasses it (manual indexing, enrichment overrides) would cause
        mapping errors. This is the last-resort safety net at the index
        boundary.
        """
        for field in ("agent_ip", "src_ip", "dst_ip"):
            if field in doc and not doc[field]:
                doc[field] = None
        return doc

    def index_enriched_alert(self, alert: dict) -> str:
        """Index an enriched alert.

        Returns one of INDEX_OK / INDEX_REJECT / INDEX_DOWN so the caller
        can distinguish a permanent document-level failure (quarantine)
        from a transient cluster-level failure (retry). Prior versions
        returned a bare bool which conflated the two and let a single
        poison-pill document wedge the buffer indefinitely (cheersin,
        2026-05-13).
        """
        self._lazy_ensure_indices()
        alert = self._sanitize_ip_fields(alert)
        if not alert.get("client_id"):
            if is_multi_tenant():
                logger.error("refusing_index_without_client_id",
                             alert_id=alert.get("alert_id"),
                             reason="multi-tenant mode requires client_id")
                # Treat as a hard reject — the document will never index
                # without a client_id and must not be retried forever.
                return INDEX_REJECT
            logger.warning("indexing_alert_without_client_id", alert_id=alert.get("alert_id"))
        try:
            # In multi-tenant mode, use a composite document ID to prevent
            # cross-tenant overwrites when two tenants share the same alert_id.
            alert_id = alert.get("alert_id")
            client_id = alert.get("client_id")
            doc_id = (f"{client_id}:{alert_id}" if client_id and is_multi_tenant()
                      else alert_id)
            self.client.index(
                index=self.indices.get("enriched_alerts", "ai-soc-enriched-alerts"),
                id=doc_id,
                body=alert
            )
            return INDEX_OK
        except RequestError as e:
            # 4xx from OpenSearch. Split: 400/422 are document-level
            # (mapping conflict, validation, malformed) and will never
            # succeed on retry. 401/403/404/409/429 are cluster-level
            # (auth, missing index, conflict, rate limit) and should be
            # retried as DOWN. status_code lives on the exception in
            # opensearch-py >=2.0.
            status = getattr(e, "status_code", None)
            if status in (400, 422):
                logger.error("opensearch_index_rejected",
                             alert_id=alert.get("alert_id"),
                             status=status, error=str(e))
                return INDEX_REJECT
            logger.warning("opensearch_index_transient_4xx",
                           alert_id=alert.get("alert_id"),
                           status=status, error=str(e))
            return INDEX_DOWN
        except (OSConnectionError, TransportError) as e:
            logger.warning("opensearch_index_transport_failed",
                           alert_id=alert.get("alert_id"), error=str(e))
            return INDEX_DOWN
        except Exception as e:
            # Conservative: unknown errors are treated as transient so
            # we never quarantine on something we don't understand.
            logger.error("opensearch_index_failed", alert_id=alert.get("alert_id"),
                         error=str(e))
            return INDEX_DOWN

    _BULK_BATCH_SIZE = 500

    def bulk_index(self, index_name: str, documents: list[dict]) -> int:
        """Bulk index documents in batches to avoid overwhelming the cluster."""
        actions = [
            {"_index": index_name, "_id": doc.get("id", None),
             "_source": self._sanitize_ip_fields(doc)}
            for doc in documents
        ]
        total_success = 0
        try:
            for i in range(0, len(actions), self._BULK_BATCH_SIZE):
                batch = actions[i:i + self._BULK_BATCH_SIZE]
                success, errors = helpers.bulk(
                    self.client, batch, raise_on_error=False)
                if errors:
                    logger.warning("opensearch_bulk_errors",
                                   batch=i // self._BULK_BATCH_SIZE,
                                   count=len(errors))
                total_success += success
            return total_success
        except Exception as e:
            logger.error("opensearch_bulk_failed", error=str(e))
            return total_success

    # ----- Querying -----

    def search_alerts(self, query: dict, index: str = None,
                      size: int = 100, _already_scoped: bool = False) -> list[dict]:
        """Search enriched alerts.

        Automatically injects tenant filter for enriched-alert indices
        unless ``_already_scoped=True`` (caller already injected).
        """
        idx = index or self.indices.get("enriched_alerts", "ai-soc-enriched-alerts")
        if not _already_scoped and "wazuh-alerts" not in idx and "wazuh-states" not in idx:
            self._inject_tenant_filter(query)
        try:
            result = self.client.search(index=idx, body=query, size=size)
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception as e:
            logger.error("opensearch_search_failed", error=str(e))
            return []

    def tenant_scoped_search(self, index: str, body: dict,
                            size: int = 50,
                            allowed_agent_ids: list[str] = None) -> dict:
        """Search any index with tenant scoping.

        For Wazuh-native indices (no client_id), ``allowed_agent_ids``
        restricts results to the caller's tenant agents.  In multi-tenant
        mode, omitting this parameter fails closed (empty result).
        For enriched indices, tenant filter is injected automatically.
        """
        _is_wazuh_native = ("wazuh-alerts" in index or "wazuh-states" in index)
        if not _is_wazuh_native:
            self._inject_tenant_filter(body)
        elif allowed_agent_ids is not None:
            # Use safe query wrapper for Wazuh-native agent scoping
            self._add_query_filter(
                body, {"terms": {"agent.id": allowed_agent_ids}})
        elif _is_wazuh_native and is_multi_tenant():
            # Fail closed: Wazuh-native search without agent scope in MT mode.
            # Only cross-tenant admin context is allowed to bypass.
            cid = _tenant_ctx.get()
            if cid != _CROSS_TENANT:
                logger.warning("tenant_scoped_search_no_agents",
                               index=index,
                               msg="Wazuh-native search without allowed_agent_ids in MT mode — returning empty")
                return {"hits": {"hits": [], "total": {"value": 0}}}
        try:
            return self.client.search(index=index, body=body, size=size)
        except Exception as e:
            logger.error("tenant_scoped_search_failed", error=str(e))
            return {"hits": {"hits": [], "total": {"value": 0}}}

    def get_alert_history_for_rule(self, rule_id: int, days: int = 30,
                                    size: int = 100) -> list[dict]:
        """Get historical alerts for a specific rule."""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"rule_id": rule_id}},
                        {"range": {"timestamp": {"gte": f"now-{days}d"}}}
                    ]
                }
            },
            "sort": [{"timestamp": "desc"}]
        }
        self._inject_tenant_filter(query)
        return self.search_alerts(query, size=size, _already_scoped=True)

    def get_alert_history_for_source(self, src_ip: str, days: int = 30,
                                      size: int = 50) -> list[dict]:
        """Get historical alerts from a specific source IP."""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"src_ip": src_ip}},
                        {"range": {"timestamp": {"gte": f"now-{days}d"}}}
                    ]
                }
            },
            "sort": [{"timestamp": "desc"}]
        }
        self._inject_tenant_filter(query)
        return self.search_alerts(query, size=size, _already_scoped=True)

    def get_alert_history_for_user(self, username: str, days: int = 30,
                                    size: int = 50) -> list[dict]:
        """Get historical alerts involving a user."""
        query = {
            "query": {
                "bool": {
                    "should": [
                        {"term": {"src_user": username}},
                        {"term": {"dst_user": username}}
                    ],
                    "minimum_should_match": 1,
                    "must": [
                        {"range": {"timestamp": {"gte": f"now-{days}d"}}}
                    ]
                }
            },
            "sort": [{"timestamp": "desc"}]
        }
        self._inject_tenant_filter(query)
        return self.search_alerts(query, size=size, _already_scoped=True)

    def get_alert_history_for_agent(self, agent_id: str, days: int = 7,
                                     size: int = 100) -> list[dict]:
        """Get alert history for a Wazuh agent (host)."""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"agent_id": agent_id}},
                        {"range": {"timestamp": {"gte": f"now-{days}d"}}}
                    ]
                }
            },
            "sort": [{"timestamp": "desc"}]
        }
        self._inject_tenant_filter(query)
        return self.search_alerts(query, size=size, _already_scoped=True)

    def get_baseline_aggregation(self, field: str, agent_id: str = None,
                                  days: int = 30) -> dict:
        """Get baseline statistics for anomaly detection."""
        must_clauses = [{"range": {"timestamp": {"gte": f"now-{days}d"}}}]
        if agent_id:
            must_clauses.append({"term": {"agent_id": agent_id}})

        query = {
            "query": {"bool": {"must": must_clauses}},
            "aggs": {
                "daily_counts": {
                    "date_histogram": {
                        "field": "timestamp",
                        "calendar_interval": "day"
                    },
                    "aggs": {
                        "by_field": {"terms": {"field": field, "size": 50}}
                    }
                },
                "stats": {
                    "stats": {"field": "enrichment.risk_score"}
                }
            },
            "size": 0
        }
        self._inject_tenant_filter(query)
        try:
            result = self.client.search(
                index=self.indices.get("enriched_alerts", "ai-soc-enriched-alerts"),
                body=query
            )
            return result.get("aggregations", {})
        except Exception as e:
            logger.error("opensearch_baseline_failed", error=str(e))
            return {}

    def get_daily_alert_counts(self, dimension_field: str,
                               dimension_value: str,
                               days: int = 30) -> list[dict]:
        """
        Get daily alert counts for a specific dimension value over N days.
        Returns list of {date, count, avg_risk} per day.
        Used for behavioral baseline computation.
        """
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {dimension_field: dimension_value}},
                        {"range": {"timestamp": {"gte": f"now-{days}d"}}}
                    ]
                }
            },
            "aggs": {
                "daily": {
                    "date_histogram": {
                        "field": "timestamp",
                        "calendar_interval": "day"
                    },
                    "aggs": {
                        "avg_risk": {
                            "avg": {"field": "enrichment.risk_score"}
                        }
                    }
                }
            },
            "size": 0
        }
        self._inject_tenant_filter(query)
        try:
            idx = self.indices.get("enriched_alerts", "ai-soc-enriched-alerts")
            result = self.client.search(index=idx, body=query)
            buckets = result.get("aggregations", {}).get("daily", {}).get("buckets", [])
            return [
                {
                    "date": b["key_as_string"],
                    "count": b["doc_count"],
                    "avg_risk": b.get("avg_risk", {}).get("value", 0) or 0
                }
                for b in buckets
            ]
        except Exception as e:
            logger.error("daily_counts_query_failed",
                         field=dimension_field, value=dimension_value, error=str(e))
            return []

    def get_unique_dimension_values(self, field: str, days: int = 30,
                                     max_values: int = 500) -> list[str]:
        """Get unique values for a field over N days (for baseline computation)."""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": f"now-{days}d"}}}
                    ]
                }
            },
            "aggs": {
                "unique_vals": {
                    "terms": {"field": field, "size": max_values}
                }
            },
            "size": 0
        }
        self._inject_tenant_filter(query)
        try:
            idx = self.indices.get("enriched_alerts", "ai-soc-enriched-alerts")
            result = self.client.search(index=idx, body=query)
            buckets = result.get("aggregations", {}).get("unique_vals", {}).get("buckets", [])
            return [b["key"] for b in buckets]
        except Exception as e:
            logger.error("unique_values_query_failed", field=field, error=str(e))
            return []

    def get_alert_count_since(self, dimension_field: str,
                               dimension_value: str,
                               hours: int = 24) -> int:
        """Get alert count for a dimension value in the last N hours."""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {dimension_field: dimension_value}},
                        {"range": {"timestamp": {"gte": f"now-{hours}h"}}}
                    ]
                }
            }
        }
        self._inject_tenant_filter(query)
        try:
            idx = self.indices.get("enriched_alerts", "ai-soc-enriched-alerts")
            result = self.client.count(index=idx, body=query)
            return result.get("count", 0)
        except Exception as e:
            logger.warning("alert_count_query_failed",
                           field=dimension_field, value=dimension_value, error=str(e))
            return 0

    def get_correlated_events(self, alert: dict, window_minutes: int = 60,
                               size: int = 50) -> list[dict]:
        """Find events correlated by time, host, user, or IP."""
        should_clauses = []
        if alert.get("agent_id"):
            should_clauses.append({"term": {"agent_id": alert["agent_id"]}})
        if alert.get("src_ip"):
            should_clauses.append({"term": {"src_ip": alert["src_ip"]}})
        if alert.get("src_user"):
            should_clauses.append(
                {"bool": {"should": [
                    {"term": {"src_user": alert["src_user"]}},
                    {"term": {"dst_user": alert["src_user"]}}
                ]}}
            )

        if not should_clauses:
            return []

        query = {
            "query": {
                "bool": {
                    "should": should_clauses,
                    "minimum_should_match": 1,
                    "must": [
                        {"range": {"timestamp": {
                            "gte": f"{alert.get('timestamp', 'now')}||-{window_minutes}m",
                            "lte": f"{alert.get('timestamp', 'now')}||+{window_minutes}m"
                        }}}
                    ],
                    "must_not": [
                        {"term": {"alert_id": alert.get("alert_id", "")}}
                    ]
                }
            },
            "sort": [{"timestamp": "asc"}]
        }
        self._inject_tenant_filter(query)
        return self.search_alerts(query, size=size)

    # ----- Vulnerability Queries -----

    VULN_INDEX = "wazuh-states-vulnerabilities-*"

    def _build_agent_scope_filter(self, agent_id: str = None,
                                   allowed_agent_ids: list[str] = None) -> list[dict]:
        """Build agent.id filter clauses for Wazuh-native indices.

        Wazuh vulnerability/SCA indices do not carry client_id.  Tenant
        isolation is enforced by restricting queries to the set of agent IDs
        mapped to the caller's tenant via the tenant_agents table.
        """
        clauses = []
        if agent_id:
            clauses.append({"term": {"agent.id": agent_id}})
        if allowed_agent_ids is not None:
            clauses.append({"terms": {"agent.id": allowed_agent_ids}})
        return clauses

    def get_vulnerabilities(self, agent_id: str = None,
                            severity: str = None,
                            cve_id: str = None,
                            size: int = 200,
                            allowed_agent_ids: list[str] = None) -> list[dict]:
        """Query vulnerability state index.

        In multi-tenant mode, ``allowed_agent_ids`` MUST be provided to
        restrict results to the caller's tenant agents.
        """
        must = self._build_agent_scope_filter(agent_id, allowed_agent_ids)
        if severity:
            must.append({"term": {"vulnerability.severity": severity}})
        if cve_id:
            must.append({"term": {"vulnerability.id": cve_id}})
        query = {"query": {"bool": {"must": must}} if must else {"match_all": {}}}
        try:
            result = self.client.search(
                index=self.VULN_INDEX, body=query, size=size
            )
            return [h["_source"] for h in result["hits"]["hits"]]
        except Exception as e:
            logger.error("vuln_query_failed", error=str(e))
            return []

    def get_vulnerability_summary(self,
                                  allowed_agent_ids: list[str] = None) -> dict:
        """Aggregation: vulnerability counts by severity + affected agents.

        In multi-tenant mode, ``allowed_agent_ids`` restricts the scope.
        """
        scope = self._build_agent_scope_filter(
            allowed_agent_ids=allowed_agent_ids)
        base_query = ({"bool": {"must": scope}} if scope
                      else {"match_all": {}})
        query = {
            "query": base_query,
            "aggs": {
                "by_severity": {
                    "terms": {"field": "vulnerability.severity", "size": 10}
                },
                "affected_agents": {
                    "cardinality": {"field": "agent.id"}
                },
                "top_cves": {
                    "terms": {"field": "vulnerability.id", "size": 20}
                }
            },
            "size": 0
        }
        try:
            result = self.client.search(
                index=self.VULN_INDEX, body=query
            )
            aggs = result.get("aggregations", {})
            total = result.get("hits", {}).get("total", {}).get("value", 0)
            return {
                "total_vulnerabilities": total,
                "by_severity": {
                    b["key"]: b["doc_count"]
                    for b in aggs.get("by_severity", {}).get("buckets", [])
                },
                "affected_agents": aggs.get("affected_agents", {}).get("value", 0),
                "top_cves": [
                    {"cve": b["key"], "count": b["doc_count"]}
                    for b in aggs.get("top_cves", {}).get("buckets", [])
                ],
            }
        except Exception as e:
            logger.error("vuln_summary_failed", error=str(e))
            return {"total_vulnerabilities": 0, "by_severity": {},
                    "affected_agents": 0, "top_cves": []}

    def get_critical_vulnerabilities(self, limit: int = 50,
                                     allowed_agent_ids: list[str] = None) -> list[dict]:
        """Shortcut: get critical severity vulnerabilities."""
        return self.get_vulnerabilities(
            severity="Critical", size=limit,
            allowed_agent_ids=allowed_agent_ids)
