"""
Tenant Service Registry — Manages per-tenant service instances.

Caches decrypted configs and lazily-initialized clients (WazuhClient,
OpenSearchClient, LLMBackend, NotificationService) per tenant.

Enhanced for multi-tenant LLM provider support with failover chains.
"""

import os
import structlog
from src.database.store import TenantRecordUnavailable
from src.database.tenant_crypto import decrypt_config, TenantCryptoError

logger = structlog.get_logger(__name__)


def _resolve_wazuh_verify(ca_cert, verify_ssl, tenant_id: str):
    """Resolve the effective ``verify=`` for a per-tenant WazuhClient.

    WO-S4. This used to be ``_pick("ca_cert", "verify_ssl", default=True)``,
    and ``_pick`` returns the FIRST KEY PRESENT — not the first *truthy* value.
    The shipped ``config/config.yaml`` sets ``wazuh.api.ca_cert: ""``, so every
    per-tenant client was built with ``verify_ssl=""``, which ``requests`` maps
    to ``cert_reqs="CERT_NONE"``. TLS verification was therefore off for all
    Wazuh Manager API traffic — which carries the Wazuh admin credentials as
    HTTP Basic on ``/security/user/authenticate``, and drives active response.

    Semantics now match the (already-correct) global path in
    ``src/enrichment/service.py``: a blank ``ca_cert`` is treated as ABSENT and
    falls through to ``verify_ssl``; a falsy ``verify_ssl`` is forced back to
    ``True`` outside DEV_MODE, as ``proxy_ssl.resolve_proxy_verify_ssl`` does.

    Returns ``True``, ``False`` (DEV_MODE opt-out only), or a CA-bundle path.
    """
    dev_mode = os.environ.get("DEV_MODE", "").lower() in ("1", "true", "yes")

    if isinstance(ca_cert, str) and ca_cert.strip():
        # An explicit CA bundle. Reject a path that does not exist rather than
        # handing it to requests, which would raise deep inside a later call.
        if os.path.exists(ca_cert):
            return ca_cert
        logger.warning("tenant_wazuh_ca_cert_missing",
                       tenant_id=tenant_id, ca_cert=ca_cert,
                       msg="Configured ca_cert path does not exist — "
                           "falling back to default verification.")

    if not isinstance(verify_ssl, bool):
        # A non-bool, non-path value (e.g. "" or None) is not a verification
        # policy. Never let it reach requests as a falsy verify=.
        verify_ssl = True

    if not verify_ssl and not dev_mode:
        logger.warning("tenant_wazuh_verify_ssl_forced_true",
                       tenant_id=tenant_id,
                       msg="Wazuh verify_ssl=false outside DEV_MODE — "
                           "defaulting to true. Set DEV_MODE=true to disable.")
        verify_ssl = True

    if not verify_ssl:
        logger.warning("tenant_wazuh_verify_ssl_disabled",
                       tenant_id=tenant_id,
                       msg="Wazuh TLS verification is DISABLED for this tenant "
                           "(DEV_MODE opt-out). Credentials are not protected.")

    return verify_ssl


class TenantConfigUnavailable(Exception):
    """A tenant's config could not be established.

    Two causes, one meaning — "we do not know this tenant's config":

      * ``decrypt failed``  — wrong/rotated/corrupt key (``TenantCryptoError``);
      * ``record read failed`` — the tenants table could not be read at all
        (``TenantRecordUnavailable``, WO-H91). This path used to arrive here as
        a plain ``{}`` from ``get_tenant`` and walk straight past the
        fail-closed guard below, which is the whole defect.

    Raised to FAIL CLOSED: callers must NOT fall back to the global config or
    build any client for this tenant — doing so would silently run the tenant
    under global/other-tenant credentials, breaking tenant isolation. The
    affected tenant should be skipped (and logged) while others continue.

    This is distinct from a legitimately empty/partial tenant config (the read
    and the decrypt both succeeded and returned ``{}``), and from a tenant that
    genuinely does not exist (``get_tenant`` returns ``{}``) — where the
    intentional global fallback still applies.
    """

    def __init__(self, tenant_id: str, cause: Exception | None = None,
                 reason: str = "decrypt failed"):
        self.tenant_id = tenant_id
        self.reason = reason
        self.__cause__ = cause
        super().__init__(
            f"tenant config unavailable ({reason}) for tenant "
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
        """Get decrypted tenant config, cached in memory.

        Returns ``{}`` for a tenant that genuinely does not exist (the
        deliberate global fallback). Raises ``TenantConfigUnavailable`` when
        the config could not be established at all — read failure or decrypt
        failure. Never caches either failure.
        """
        if tenant_id not in self._config_cache:
            try:
                tenant = self.db.get_tenant(tenant_id)
            except TenantRecordUnavailable as e:
                # WO-H91 FAIL CLOSED, same reason as the decrypt branch below.
                # `get_tenant` used to return {} for a failed READ as well as
                # for a genuinely absent tenant, so this path fell through the
                # `if not tenant: return {}` line and handed an empty config to
                # get_wazuh_client — which fills the gaps from the GLOBAL
                # config. A DB blip therefore ran a tenant under platform
                # credentials. Do not cache; raise the same typed error the
                # decrypt path raises, so every existing per-tenant boundary
                # already skips this tenant only.
                logger.error("tenant_config_record_read_failed",
                             tenant_id=tenant_id, error=str(e)[:200])
                raise TenantConfigUnavailable(
                    tenant_id, cause=e, reason="record read failed") from e
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
            # partial wazuh block). The case that surfaced it: a partial api_cfg left
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

            # The ssh_* settings are siblings of `api`, not members of it —
            # `wazuh.ssh_host`, not `wazuh.api.ssh_host` (see config.yaml and
            # service.py, which reads them off the wazuh block directly). Using
            # _pick for them would search only the api block and quietly return
            # the default forever, which is the same silent no-op WO-H83 exists
            # to fix. Hence a second resolver over the right level.
            global_wazuh = (
                self._global_config.get("wazuh", {})
                if isinstance(self._global_config, dict) else {}
            )

            def _pick_ssh(key, default=None):
                for src in (wazuh_cfg, api_cfg, global_wazuh):
                    if isinstance(src, dict) and key in src:
                        return src[key]
                return default

            client = WazuhClient(
                host=_pick("host", default=""),
                port=_pick("port", default=55000),
                username=_pick("username", "user", default="wazuh"),
                password=_pick("password", "pass", default=""),
                verify_ssl=_resolve_wazuh_verify(
                    _pick("ca_cert"), _pick("verify_ssl", default=True),
                    tenant_id),
                tls_insecure_hostname=_pick("tls_insecure_hostname", default=False),
                # WO-H83: this path forwarded NO ssh_* settings at all, so a
                # tenant-resolved client had no credentials and rule validation
                # could not run for any tenant. Worse than the wrong-host bug
                # it sits beside — that one at least reached a host — and both
                # surfaced as the same "manual tuning required" proposal state.
                ssh_host=_pick_ssh("ssh_host", default=""),
                ssh_user=_pick_ssh("ssh_user", default=""),
                ssh_password=_pick_ssh("ssh_password", default=""),
                ssh_key_path=_pick_ssh("ssh_key_path", default=""),
                ssh_key_passphrase=_pick_ssh("ssh_key_passphrase", default=""),
                ssh_sudo_nopasswd=_pick_ssh("ssh_sudo_nopasswd", default=False),
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
        """Get list of active tenant IDs.

        Propagates ``TenantListUnavailable`` (WO-H91 QA D2) when the list could
        not be read — never an empty list, which callers such as
        ``signature_validator._is_active_tenant`` would otherwise read as
        "this tenant is not active" for a reason they could not distinguish
        from revocation.

        Every caller catches, but do NOT read that as "all callers are safe":
        ``main.py:294`` catches and calls ``set_multi_tenant_mode(False)``,
        which disables tenant isolation and skips the RLS boot gate, and
        ``src/api/routes/llm_usage.py:186`` degrades to a 500. Both predate
        this change (the old ``[]`` reached the same place) and both are filed
        separately. See ``TenantListUnavailable`` in store.py for the detail.
        """
        tenants = self.db.get_active_tenants()
        return [t["id"] for t in tenants]

    def get_active_tenants_with_config(self) -> list[dict]:
        """Get active tenants with their decrypted configs.

        Propagates ``TenantListUnavailable`` on a failed read (WO-H91 QA D2);
        a per-tenant config failure still only omits that tenant.
        """
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
