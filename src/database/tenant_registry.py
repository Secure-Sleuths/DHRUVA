"""
Tenant Service Registry — Manages per-tenant service instances.

Caches decrypted configs and lazily-initialized clients (WazuhClient,
OpenSearchClient, LLMBackend, NotificationService) per tenant.

Enhanced for multi-tenant LLM provider support with failover chains.
"""

import structlog
from src.database.tenant_crypto import decrypt_config, TenantCryptoError

logger = structlog.get_logger(__name__)


class TenantConfigUnavailable(Exception):
    """A tenant's config could not be decrypted (wrong/rotated/corrupt key).

    Raised to FAIL CLOSED: callers must NOT fall back to the global config or
    build any client for this tenant — doing so would silently run the tenant
    under global/other-tenant credentials, breaking tenant isolation. The
    affected tenant should be skipped (and logged) while others continue.

    This is distinct from a legitimately empty/partial tenant config (decrypt
    succeeds, returns ``{}``), where the intentional global fallback still
    applies.
    """

    def __init__(self, tenant_id: str, cause: Exception | None = None):
        self.tenant_id = tenant_id
        self.__cause__ = cause
        super().__init__(
            f"tenant config unavailable (decrypt failed) for tenant "
            f"{tenant_id!r}")


class TenantServiceRegistry:
    """Caches per-tenant service instances with lazy initialization."""

    def __init__(self, db, global_config: dict = None):
        self.db = db
        self._global_config = global_config or {}
        self._config_cache: dict = {}  # tenant_id -> decrypted config dict
        self._wazuh_clients: dict = {}
        self._opensearch_clients: dict = {}
        self._llm_backends: dict = {}  # tenant_id -> LLMBackend instance
        self._notification_services: dict = {}

    def _get_config(self, tenant_id: str) -> dict:
        """Get decrypted tenant config, cached in memory."""
        if tenant_id not in self._config_cache:
            tenant = self.db.get_tenant(tenant_id)
            if not tenant:
                return {}
            try:
                self._config_cache[tenant_id] = decrypt_config(
                    tenant.get("config_encrypted", ""), tenant_id=tenant_id)
            except TenantCryptoError as e:
                # FAIL CLOSED: a real decrypt failure (wrong/rotated/corrupt
                # key) must NOT cache {} — that empty config would flow into
                # get_wazuh_client and silently fall back to GLOBAL creds,
                # breaking tenant isolation. Do not cache; raise a typed error
                # so the per-tenant boundary skips this tenant only.
                logger.error("tenant_config_decrypt_failed",
                             tenant_id=tenant_id, error=str(e))
                raise TenantConfigUnavailable(tenant_id, cause=e) from e
        return self._config_cache[tenant_id]

    def reload_tenant(self, tenant_id: str):
        """Clear cached config and services for a tenant (call after config update)."""
        self._config_cache.pop(tenant_id, None)
        self._wazuh_clients.pop(tenant_id, None)
        self._opensearch_clients.pop(tenant_id, None)
        self._llm_backends.pop(tenant_id, None)
        self._notification_services.pop(tenant_id, None)
        logger.info("tenant_cache_cleared", tenant_id=tenant_id)

    def get_tenant_config(self, tenant_id: str) -> dict:
        """Get the full decrypted config for a tenant."""
        return self._get_config(tenant_id)

    def get_wazuh_client(self, tenant_id: str):
        """Get or create a WazuhClient for a tenant."""
        if tenant_id in self._wazuh_clients:
            return self._wazuh_clients[tenant_id]

        config = self._get_config(tenant_id)
        wazuh_cfg = config.get("wazuh", {})
        if not wazuh_cfg:
            return None

        try:
            from src.enrichment.wazuh_client import WazuhClient
            api_cfg = wazuh_cfg.get("api", wazuh_cfg)

            # Fall back to the global config when the per-tenant record is
            # legitimately empty/partial (decrypt SUCCEEDED, returned {} or a
            # partial wazuh block). Cheersin's case: a partial api_cfg left
            # verify_ssl defaulting to True with no ca_cert, which refused to
            # connect to a self-signed Wazuh stack — the global client (with
            # the operator-configured ca_cert) had been working fine.
            # NOTE: a genuine DECRYPT FAILURE no longer reaches here — it fails
            # closed in _get_config (TenantConfigUnavailable) so we never run a
            # tenant under global creds when its own secrets are unreadable.
            global_api = (
                self._global_config.get("wazuh", {}).get("api", {})
                if isinstance(self._global_config, dict)
                else {}
            )

            def _pick(*keys, default=None):
                for k in keys:
                    if k in api_cfg:
                        return api_cfg[k]
                    if k in global_api:
                        return global_api[k]
                return default

            client = WazuhClient(
                host=_pick("host", default=""),
                port=_pick("port", default=55000),
                username=_pick("username", "user", default="wazuh"),
                password=_pick("password", "pass", default=""),
                verify_ssl=_pick("ca_cert", "verify_ssl", default=True),
                tls_insecure_hostname=_pick("tls_insecure_hostname", default=False),
            )
            self._wazuh_clients[tenant_id] = client
            logger.info("tenant_wazuh_client_created", tenant_id=tenant_id)
            return client
        except Exception as e:
            logger.error("tenant_wazuh_client_failed",
                         tenant_id=tenant_id, error=str(e))
            return None

    def get_llm_config(self, tenant_id: str) -> dict:
        """Get LLM config for a tenant (provider, api_key, model, etc.)."""
        config = self._get_config(tenant_id)
        return config.get("llm") or config.get("claude", {})

    def get_llm_backend(self, tenant_id: str):
        """Get or create a tenant-specific LLM backend with failover support."""
        if tenant_id in self._llm_backends:
            return self._llm_backends[tenant_id]

        llm_config = self.get_llm_config(tenant_id)
        # Treat CLI-only configs (e.g. {mode: cli}) as "use global backend"
        # since they have no provider-specific keys for MultiProviderLLMBackend
        use_global = (not llm_config
                      or (llm_config.get("mode") == "cli"
                          and "providers" not in llm_config
                          and "primary_provider" not in llm_config))
        if use_global:
            # No per-tenant LLM config — fall back to global config via
            # legacy LLMBackend which understands the global config format
            # (provider configs as sibling keys, not nested under "providers:")
            if not (self._global_config.get("llm") or self._global_config.get("claude")):
                logger.warning("no_llm_config_for_tenant", tenant_id=tenant_id,
                              fallback="none_available")
                return None
            try:
                from src.agents.claude_backend import LLMBackend
                # WO-H50: pass the DB so usage is actually recorded. Without it,
                # LLMBackend._track short-circuits on `if not self._usage_db`
                # and every call goes unmetered — the cause of "0 usage rows
                # since restart" on a live install.
                backend = LLMBackend(self._global_config, db=self.db)
                self._llm_backends[tenant_id] = backend
                logger.info("tenant_llm_using_global_fallback",
                           tenant_id=tenant_id, provider=backend.mode)
                return backend
            except Exception as e:
                logger.error("tenant_llm_global_fallback_failed",
                            tenant_id=tenant_id, error=str(e))
                return None

        try:
            from src.agents.llm_providers.multi_provider import MultiProviderLLMBackend
            backend = MultiProviderLLMBackend(tenant_id, llm_config, self.db)
            self._llm_backends[tenant_id] = backend
            logger.info("tenant_llm_backend_created",
                       tenant_id=tenant_id,
                       primary_provider=backend.get_primary_provider())
            return backend
        except Exception as e:
            logger.error("tenant_llm_backend_creation_failed",
                        tenant_id=tenant_id, error=str(e))
            # Fallback to legacy single-provider backend
            try:
                from src.agents.claude_backend import LLMBackend
                backend = LLMBackend({"llm": llm_config}, db=self.db)  # WO-H50: meter usage
                self._llm_backends[tenant_id] = backend
                logger.info("tenant_llm_backend_fallback_created",
                           tenant_id=tenant_id, provider=backend.mode)
                return backend
            except Exception as fallback_error:
                logger.error("tenant_llm_backend_fallback_failed",
                            tenant_id=tenant_id, error=str(fallback_error))
                return None

    def query_dashboard_proxy(self, tenant_id: str, index: str,
                              query: dict) -> dict | None:
        """Run an OpenSearch query via the tenant's dashboard proxy.

        Returns the raw OpenSearch response dict, or None if the tenant
        has no dashboard_proxy configured.
        """
        config = self._get_config(tenant_id)
        proxy_cfg = config.get("dashboard_proxy")
        if not proxy_cfg:
            return None

        import urllib.parse
        import requests
        from src.enrichment.proxy_ssl import resolve_proxy_verify_ssl

        base_url = proxy_cfg["url"].rstrip("/")
        path = urllib.parse.quote(f"{index}/_search", safe="")
        url = f"{base_url}/api/console/proxy?path={path}&method=POST"

        # Same SSL policy as the EnrichmentService proxy path: default True;
        # explicit false honored only under DEV_MODE; otherwise forced True +
        # warned; per-call warning when genuinely off. An explicit
        # verify_ssl=false must never be silently honored.
        verify_ssl = resolve_proxy_verify_ssl(proxy_cfg)

        try:
            resp = requests.post(
                url, json=query,
                auth=(proxy_cfg["username"], proxy_cfg["password"]),
                headers={"osd-xsrf": "true",
                         "Content-Type": "application/json"},
                verify=verify_ssl,
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error("dashboard_proxy_query_failed",
                         tenant_id=tenant_id, index=index,
                         error=str(e)[:200])
            return None

    def get_auto_response_policy(self, tenant_id: str) -> dict:
        """Return the tenant's auto-response policy (M3).

        Source of truth for whether ANY active-response action may
        auto-execute for this tenant. Reads the ``auto_response`` block from
        the tenant's encrypted config and merges it over the operator-approved
        safe defaults (auto OFF). Strictly per-tenant: there is NO global
        fallback — tenant A's policy can never affect tenant B.

        Fail-closed: if the tenant's config cannot be decrypted, this
        propagates ``TenantConfigUnavailable`` (via ``_get_config``) so callers
        skip auto-response for that tenant rather than running it under
        global/empty config. A legitimately empty config yields the safe
        defaults (auto disabled).
        """
        config = self._get_config(tenant_id)  # may raise TenantConfigUnavailable
        raw = config.get("auto_response") or {}
        if not isinstance(raw, dict):
            raw = {}
        block_raw = raw.get("block_ip") or {}
        if not isinstance(block_raw, dict):
            block_raw = {}

        # Operator-approved ship defaults — auto OFF.
        defaults = {
            "auto_enabled": False,
            "triage_confidence_floor": 0.90,
            "ti_feed_confidence_floor": 80,   # 0-100, matches enricher scale
            "rate_cap_per_hour": 3,
            "ttl_seconds": 86400,             # 24h
            "never_block_allowlist": [],
        }
        block = {**defaults, **{k: v for k, v in block_raw.items()
                                if k in defaults and v is not None}}

        # Coerce / harden types — a malformed stored value must never enable
        # auto-block or weaken a floor. Fall back to the safe default instead.
        block["auto_enabled"] = block.get("auto_enabled") is True
        try:
            block["triage_confidence_floor"] = float(block["triage_confidence_floor"])
        except (TypeError, ValueError):
            block["triage_confidence_floor"] = defaults["triage_confidence_floor"]
        try:
            block["ti_feed_confidence_floor"] = float(block["ti_feed_confidence_floor"])
        except (TypeError, ValueError):
            block["ti_feed_confidence_floor"] = defaults["ti_feed_confidence_floor"]
        try:
            block["rate_cap_per_hour"] = int(block["rate_cap_per_hour"])
        except (TypeError, ValueError):
            block["rate_cap_per_hour"] = defaults["rate_cap_per_hour"]
        try:
            block["ttl_seconds"] = int(block["ttl_seconds"])
        except (TypeError, ValueError):
            block["ttl_seconds"] = defaults["ttl_seconds"]
        allow = block.get("never_block_allowlist")
        if not isinstance(allow, list):
            allow = []
        block["never_block_allowlist"] = [str(a) for a in allow if a is not None]

        return {"block_ip": block}

    def get_ti_api_keys(self, tenant_id: str) -> dict:
        """Get per-tenant TI API keys (abuseipdb, virustotal, otx)."""
        config = self._get_config(tenant_id)
        return config.get("ti_api_keys", {})

    def get_notification_config(self, tenant_id: str) -> dict:
        """Get per-tenant notification config (Slack webhook, email recipients)."""
        config = self._get_config(tenant_id)
        return config.get("notifications", {})

    def sync_tenant_agents(self, tenant_id: str) -> int:
        """Auto-discover and assign agents from a tenant's dedicated Wazuh server.

        For tenants with their own Wazuh client, fetches all agents and maps
        any unassigned ones to the tenant. Returns the number of newly assigned
        agents.
        """
        wazuh = self.get_wazuh_client(tenant_id)
        if not wazuh:
            return 0

        try:
            all_agents = wazuh.get_all_agents()
        except Exception as e:
            logger.warning("agent_sync_fetch_failed",
                           tenant_id=tenant_id, error=str(e)[:200])
            return 0

        existing = self.db.get_tenant_agent_ids(tenant_id)
        existing_set = set(existing) if existing else set()

        added = 0
        for agent in all_agents:
            agent_id = agent.get("id", "")
            if not agent_id or agent_id in existing_set:
                continue
            try:
                if self.db.add_tenant_agent(tenant_id, agent_id):
                    added += 1
                    logger.info("agent_auto_assigned",
                                tenant_id=tenant_id,
                                agent_id=agent_id,
                                agent_name=agent.get("name", ""))
            except Exception as e:
                logger.warning("agent_auto_assign_failed",
                               tenant_id=tenant_id,
                               agent_id=agent_id, error=str(e))
        return added

    def sync_all_tenant_agents(self) -> dict:
        """Run agent auto-sync for all tenants with dedicated Wazuh servers."""
        results = {}
        for tenant_id in self.get_active_tenant_ids():
            try:
                config = self._get_config(tenant_id)
            except TenantConfigUnavailable:
                # Fail closed per-tenant: skip and keep syncing others.
                logger.warning("tenant_skipped_config_unavailable",
                               tenant_id=tenant_id, phase="agent_sync")
                continue
            # Only sync tenants that have their own Wazuh config
            if config.get("wazuh", {}).get("api", {}).get("host"):
                added = self.sync_tenant_agents(tenant_id)
                if added:
                    results[tenant_id] = added
        return results

    def get_active_tenant_ids(self) -> list[str]:
        """Get list of active tenant IDs."""
        tenants = self.db.get_active_tenants()
        return [t["id"] for t in tenants]

    def get_active_tenants_with_config(self) -> list[dict]:
        """Get active tenants with their decrypted configs."""
        tenants = self.db.get_active_tenants()
        result = []
        for t in tenants:
            try:
                config = self._get_config(t["id"])
            except TenantConfigUnavailable:
                # Fail closed per-tenant: omit this tenant rather than
                # surfacing global/empty config under its id.
                logger.warning("tenant_skipped_config_unavailable",
                               tenant_id=t["id"], phase="list_with_config")
                continue
            result.append({**t, "config": config})
        return result
