"""
Enrichment Service - The context layer of DHRUVA.
Pulls alerts from Wazuh, enriches them with multiple context sources,
and stores the enriched data for agent consumption.
"""

import uuid
import json
import time
import math
import structlog
import requests as _requests
from datetime import datetime, timezone
from typing import Optional

from src.timestamps import parse_iso8601
from src.enrichment.wazuh_client import WazuhClient
from src.enrichment.opensearch_client import OpenSearchClient
from src.enrichment.enrichers import (
    AssetEnricher, IdentityEnricher,
    HistoricalEnricher, TimeContextEnricher,
    VulnerabilityContextEnricher, HostIntegrityContextEnricher
)
from src.enrichment.threat_intel.enricher import ThreatIntelEnricher
from src.database.store import SOCDatabase, _tenant_ctx, is_multi_tenant

logger = structlog.get_logger(__name__)

# WO-H13: bounded look-back overlap for late / out-of-order alerts.
# The WO-H9 forward-only ``search_after`` cursor on (timestamp, _id) never
# re-fetches an alert whose event ``timestamp`` lands BEHIND the current
# high-water mark (clock skew, delayed agent ingest, bulk backfill). Each poll
# therefore ALSO re-queries a small window immediately behind the high-water
# mark so an out-of-order arrival within that window is picked up; the durable
# processed-id dedup guarantees an already-handled alert is never re-triaged.
# The window is bounded so it can never degenerate into the old full re-scan.
# DOCUMENTED LIMIT: an alert arriving MORE than ``look_back_seconds`` behind the
# high-water mark (i.e. its event timestamp is older than high_water -
# look_back_seconds by the time we next poll) is NOT caught — that is the
# accepted bound, not a silent guarantee.
_DEFAULT_LOOK_BACK_SECONDS = 300      # 5 min — sensible default
_MAX_LOOK_BACK_SECONDS = 3600         # 1 h hard ceiling — keeps it a small
                                      # overlap, never the old sliding window


def _sort_value_to_millis(val) -> Optional[int]:
    """Convert a high-water cursor timestamp to epoch milliseconds.

    The direct OpenSearch path stores the ``search_after`` sort tuple whose
    first element is the date field's sort value — epoch millis (a number) by
    default. The proxy path stores an ISO-8601 timestamp string. Accept either
    and return epoch millis, or ``None`` if it can't be parsed.
    """
    if val is None:
        return None
    if isinstance(val, bool):
        return None
    if isinstance(val, (int, float)):
        return int(val)
    try:
        # WO-H116: the proxy path's ISO string is formatted by OpenSearch, not
        # by us, so it must go through the version-independent parser.
        parsed = parse_iso8601(str(val))
        return int(parsed.timestamp() * 1000)
    except Exception:
        # WO-H90 reviewed, left silent on purpose: this is a parse helper with a
        # documented `None` default (see the docstring above), it runs per alert,
        # and every caller already treats `None` as "no cursor value". A log here
        # would be a per-alert flood that tells an on-call person nothing.
        return None


def _time_context_block(container, source: str) -> dict:
    """Pull a ``time_context`` mapping out of ``container``, defensively.

    ``config/guidance/risk_criteria.yaml`` is operator-editable and now
    reloadable live, so a typo in it must not be able to stop the platform
    booting. A YAML *syntax* error was already handled (``_load_risk_criteria``
    catches it); a *type* error was not — ``{**rc_tc, **cfg_tc}`` raises
    ``TypeError`` if either side is a list or a scalar, and
    ``EnrichmentService.__init__`` does not guard it, so ``main.py`` would fail
    to start. Before WO-H76 a botched ``time_context`` was harmless simply
    because nothing read it.
    """
    if container is None:
        return {}
    if not isinstance(container, dict):
        logger.warning("time_context_source_not_a_mapping",
                       source=source, got=type(container).__name__,
                       msg="Expected a mapping — ignoring this source.")
        return {}
    block = container.get("time_context")
    if block is None:
        return {}
    if not isinstance(block, dict):
        logger.warning("time_context_block_not_a_mapping",
                       source=source, got=type(block).__name__,
                       msg="time_context must be a mapping of business_hours "
                           "/ maintenance_windows / risk_adjustments — "
                           "ignoring it.")
        return {}
    return block


def resolve_time_context_config(enrich_cfg: dict, risk_criteria: dict) -> dict:
    """Build the config dict handed to :class:`TimeContextEnricher` (WO-H76).

    The ``time_context`` block (business hours, timezone, maintenance windows,
    risk adjustments) lives in ``config/guidance/risk_criteria.yaml`` — it has
    never existed under ``enrichment:`` in config.yaml. The enricher was
    nevertheless constructed with the ``enrichment:`` section, so it always saw
    ``{}``: no business days, therefore never business hours, therefore a
    ``time_risk_multiplier`` of 1.0 in 0 of ~25k alerts across two live
    deployments.

    Backward compatible: if a deployment HAS put a ``time_context`` block under
    ``enrichment:``, it still works and wins — it is the explicit, deployment
    -local override. The merge is per top-level key
    (``business_hours`` / ``maintenance_windows`` / ``risk_adjustments``) so an
    override of just one of them keeps the rest from risk_criteria.yaml.
    """
    rc_tc = _time_context_block(risk_criteria, "risk_criteria.yaml")
    cfg_tc = _time_context_block(enrich_cfg, "config.yaml enrichment:")
    merged = {**rc_tc, **cfg_tc}

    # The merge is per TOP-LEVEL key, so an override that supplies its own
    # business_hours replaces the whole block — including a timezone it did not
    # restate. That silently reverts to UTC, which is exactly defect (2) coming
    # back through the documented backward-compat path. Say so.
    rc_bh = rc_tc.get("business_hours")
    cfg_bh = cfg_tc.get("business_hours")
    if isinstance(cfg_bh, dict) and isinstance(rc_bh, dict) \
            and rc_bh.get("timezone") and not cfg_bh.get("timezone"):
        logger.warning(
            "time_context_override_drops_timezone",
            dropped_timezone=rc_bh.get("timezone"),
            msg="enrichment.time_context.business_hours overrides the "
                "risk_criteria.yaml block but declares no `timezone`, so "
                "business hours will be evaluated in UTC. Restate the "
                "timezone in the override.")

    if not merged:
        logger.warning(
            "time_context_config_unresolved",
            msg="No time_context found in risk_criteria.yaml or in the "
                "enrichment: config section — every alert will be treated as "
                "business hours (time_risk_multiplier 1.0).")
    else:
        logger.info("time_context_config_resolved",
                    from_risk_criteria=bool(rc_tc),
                    from_enrichment_config=bool(cfg_tc),
                    business_days=len(
                        (merged.get("business_hours") or {}).get("days") or []),
                    timezone=(merged.get("business_hours") or {}).get(
                        "timezone") or merged.get("timezone") or "UTC",
                    maintenance_windows=len(
                        merged.get("maintenance_windows") or []))
    return {"time_context": merged}


class EnrichmentService:
    """
    Core enrichment pipeline:
    1. Poll Wazuh for new alerts
    2. Normalize alert fields
    3. Run through all enrichers
    4. Compute composite risk score
    5. Store enriched alert in OpenSearch + local DB cache
    """

    def __init__(self, config: dict, db: SOCDatabase, tenant_registry=None):
        self.config = config
        self.db = db
        self.processed_ids: set = db.get_processed_ids(hours=48)
        self._max_processed_cache = 10000

        logger.info("processed_ids_loaded_from_db", count=len(self.processed_ids))

        # Initialize Wazuh client
        import os as _os
        _dev_mode = _os.environ.get("DEV_MODE", "").lower() in ("1", "true", "yes")
        wazuh_cfg = config["wazuh"]
        # verify_ssl: True/False, or a path to CA cert for self-signed.
        # Outside DEV_MODE, default to True if config says False.
        _wazuh_ssl_cfg = wazuh_cfg["api"]["verify_ssl"]
        if not _wazuh_ssl_cfg and not _dev_mode:
            logger.warning("wazuh_verify_ssl_forced_true",
                           msg="Wazuh verify_ssl=false outside DEV_MODE — "
                               "defaulting to true. Set DEV_MODE=true to disable.")
            _wazuh_ssl_cfg = True
        wazuh_verify = wazuh_cfg["api"].get("ca_cert") or _wazuh_ssl_cfg
        self.wazuh = WazuhClient(
            host=wazuh_cfg["api"]["host"],
            port=wazuh_cfg["api"]["port"],
            username=wazuh_cfg["api"]["username"],
            password=wazuh_cfg["api"]["password"],
            verify_ssl=wazuh_verify,
            tls_insecure_hostname=wazuh_cfg["api"].get("tls_insecure_hostname", False),
            ssh_user=wazuh_cfg.get("ssh_user", ""),
            ssh_password=wazuh_cfg.get("ssh_password", ""),
            ssh_key_path=wazuh_cfg.get("ssh_key_path", ""),
            ssh_key_passphrase=wazuh_cfg.get("ssh_key_passphrase", ""),
            ssh_sudo_nopasswd=wazuh_cfg.get("ssh_sudo_nopasswd", False),
            # WO-H83: every OTHER ssh_* key was forwarded and this one was not,
            # so an operator who set it correctly got no signal it was ignored.
            ssh_host=wazuh_cfg.get("ssh_host", ""),
        )

        # Initialize OpenSearch client
        os_cfg = config["opensearch"]
        _os_ssl_cfg = os_cfg["verify_ssl"]
        if not _os_ssl_cfg and not _dev_mode:
            logger.warning("opensearch_verify_ssl_forced_true",
                           msg="OpenSearch verify_ssl=false outside DEV_MODE — "
                               "defaulting to true. Set DEV_MODE=true to disable.")
            _os_ssl_cfg = True
        # Pass verify_ssl (bool) and ca_certs (path) as separate kwargs.
        # Collapsing them into a single value silently drops the CA bundle.
        os_ca_cert = os_cfg.get("ca_cert") or None
        self.opensearch = OpenSearchClient(
            hosts=os_cfg["hosts"],
            username=os_cfg["username"],
            password=os_cfg["password"],
            verify_ssl=bool(_os_ssl_cfg),
            ca_certs=os_ca_cert,
            indices=os_cfg["indices"]
        )

        # Initialize enrichers
        enrich_cfg = config.get("enrichment", {})
        risk_criteria = self._load_risk_criteria(config)

        self.asset_enricher = AssetEnricher({
            **enrich_cfg.get("asset_inventory", {}),
            "risk_criteria": risk_criteria
        })
        self.identity_enricher = IdentityEnricher({
            **enrich_cfg.get("identity", {}),
            "risk_criteria": risk_criteria
        })
        self.threat_intel_enricher = ThreatIntelEnricher(
            enrich_cfg.get("threat_intel", {}),
            db=self.db,
        )
        self.historical_enricher = HistoricalEnricher(
            enrich_cfg.get("historical", {}),
            opensearch_client=self.opensearch,
            db=self.db
        )
        # WO-H76: the time_context block lives in risk_criteria.yaml, NOT in
        # the enrichment: section — passing enrich_cfg here gave the enricher
        # an empty config and made every alert "outside business hours".
        self.time_enricher = TimeContextEnricher(
            resolve_time_context_config(enrich_cfg, risk_criteria))

        # Per-tenant override registry. May be passed here OR set externally
        # (main.py sets self._tenant_registry after construction). The vuln
        # enricher reads it late via providers so either path works.
        self._tenant_registry = tenant_registry

        # Vulnerability/SCA host-context enricher (M4 + WO-H11). Vulns are read
        # from the Wazuh vuln STATE index in OpenSearch (the Manager API vuln
        # endpoint was removed in Wazuh 4.8+); SCA still uses the tenant-scoped
        # Wazuh client. It resolves the tenant from _tenant_ctx and, in
        # multi-tenant mode, scopes the vuln query to the tenant's mapped agents
        # (same fail-closed agent-id scoping as the alert-read path). In
        # single-tenant mode it falls back to the global self.wazuh client and
        # the shared self.opensearch handle with no agent restriction.
        self.vuln_context_enricher = VulnerabilityContextEnricher(
            enrich_cfg.get("vulnerability_context", {}),
            registry_provider=lambda: self._tenant_registry,
            wazuh_provider=lambda: self.wazuh,
            opensearch_provider=lambda: self.opensearch,
            # WO-H23: per-CVE EPSS/KEV lookups against the local (global) CVE TI
            # table. Display-only detail; never fed to an LLM prompt.
            db=self.db,
        )

        # Host-integrity (FIM/rootcheck) context enricher (M6b). Same tenant-
        # scoped, fail-safe pattern as M4: resolves the tenant from _tenant_ctx
        # and uses the tenant-scoped Wazuh client only; in single-tenant mode
        # it falls back to the global self.wazuh client. Rootcheck is the
        # primary driver; only RECENT FIM changes above a threshold engage.
        self.host_integrity_enricher = HostIntegrityContextEnricher(
            enrich_cfg.get("host_integrity_context", {}),
            registry_provider=lambda: self._tenant_registry,
            wazuh_provider=lambda: self.wazuh,
        )

        self.risk_criteria = risk_criteria
        logger.info("enrichment_service_initialized")
        self.alert_buffer = None

        # Self-heal cadence for a failed asset-inventory load. The real key is
        # enrichment.asset_inventory.refresh_interval_minutes — read by nothing
        # until now. An earlier version of this looked for a top-level assets:
        # block, which does not exist in config.yaml, so it silently fell back
        # to the default and left the operator's setting still dead.
        _ai_cfg = ((config or {}).get("enrichment", {}) or {}).get(
            "asset_inventory", {}) or {}
        try:
            _mins = float(_ai_cfg.get("refresh_interval_minutes", 5) or 5)
        except (TypeError, ValueError):
            _mins = 5.0
        # Floored at 60s so a persistent outage cannot turn into a DB hammer.
        self._asset_reload_cooldown = max(60.0, _mins * 60.0)
        # MEDIUM-2: keyed per tenant, like _reload_failed_tenants. A single
        # process-global timer let the busiest tenant take the only retry slot
        # at every cooldown expiry and starve a quieter tenant's recovery
        # indefinitely — the same cross-tenant coupling WO-S11 fixed for the
        # inventory itself.
        self._asset_reload_retry_after: dict = {}

        # Try loading enrichment data from DB (settings panel)
        self._try_db_load(db)

    def _maybe_self_heal_assets(self):
        """Retry a failed asset-inventory load, on a cooldown.

        ``reload_from_db`` is otherwise called only at startup and from the
        admin reload endpoint (``refresh_interval_minutes`` in config is read by
        nothing), so a single failure at boot pinned the inventory as degraded
        for the entire process lifetime. That is not a graceful degradation: it
        switches the pre-filter and the durable cache off and force-escalates
        every dismissal, at 0% or 100%, with no path back short of a restart.

        Cheap because it is gated on the enricher ALREADY reporting failure for
        this tenant, and then rate-limited — a persistent outage costs one DB
        attempt per cooldown, not one per alert.
        """
        db = getattr(self, "db", None)
        enricher = getattr(self, "asset_enricher", None)
        if db is None or enricher is None:
            return
        failed = getattr(enricher, "_reload_failed_tenants", None)
        if not failed:
            return
        from src.enrichment.enrichers import _tenant_slice_key
        try:
            key = _tenant_slice_key()
        except Exception as e:                           # noqa: BLE001
            # WO-H90: was a bare `except: return`. `_tenant_slice_key()` has its
            # own fallback and cannot normally raise, so this is belt-and-braces
            # — but if it ever does fire, asset-inventory self-heal is off and
            # the inventory stays degraded until a restart. `debug` because this
            # is gated per alert and the loud signal (asset_enrichment_failed)
            # is already being logged elsewhere; this is the trail that explains
            # why it never recovered.
            logger.debug("asset_self_heal_tenant_key_failed",
                         error=str(e)[:200])
            return
        if key not in failed:
            return
        now = time.monotonic()
        retry_after = getattr(self, "_asset_reload_retry_after", None)
        cooldown = getattr(self, "_asset_reload_cooldown", None)
        if retry_after is None or cooldown is None:
            return
        if now < retry_after.get(key, 0.0):
            return
        # Advanced BEFORE the attempt, so a persistent outage costs one DB call
        # per cooldown rather than one per alert.
        retry_after[key] = now + cooldown
        logger.info("asset_inventory_self_heal_attempt", tenant_slice=key)
        try:
            enricher.reload_from_db(db)
        except Exception as e:      # reload_from_db swallows its own, belt+braces
            logger.warning("asset_inventory_self_heal_failed", error=str(e))

    def _try_db_load(self, db):
        """Load enrichment data from DB, overriding YAML if DB has data."""
        try:
            self.asset_enricher.reload_from_db(db)
            self.identity_enricher.reload_from_db(db)
        except Exception as e:
            logger.warning("db_enrichment_load_failed", error=str(e))

    def reload_enrichers(self, db):
        """Reload all enricher data from DB. Called by admin settings API."""
        self._try_db_load(db)
        local_iocs_count = 0
        try:
            local_iocs_count = len(db.get_local_iocs(limit=10000))
        except Exception as e:                           # noqa: BLE001
            # WO-H90: was a bare `except: pass`. A failure here means the admin
            # reload screen reports "0 local IOCs" when the real answer is "we
            # could not ask" — so an operator who just imported an IOC list is
            # told their import did nothing.
            logger.warning("local_ioc_count_failed", error=str(e)[:200])
        return {
            "assets": len(self.asset_enricher.assets),
            "identities": len(self.identity_enricher.identities),
            "local_iocs": local_iocs_count,
        }

    def reload_risk_criteria(self) -> dict:
        """Re-read risk_criteria.yaml and refresh every enricher that uses it.

        WO-H76: ``self.risk_criteria`` was read once in ``__init__`` and never
        again, so editing ANY risk multiplier — asset criticality, user risk
        profile, the time-context adjustments — needed a full service restart.
        ``POST /api/guidance/reload`` reloaded only the triage agent's guidance
        text, which is a different consumer of the same file.

        Consumers refreshed here: ``_compute_risk_score`` (reads
        ``self.risk_criteria`` live), ``AssetEnricher`` and ``IdentityEnricher``
        (hold their own reference), and ``TimeContextEnricher`` (rebuilt — it is
        stateless, and its business-hours/timezone config is parsed at
        construction).

        ``IdentityEnricher`` is refreshed for consistency only: it stores
        ``risk_criteria`` but does not currently read it anywhere, so that half
        has no enrichment-side effect today. ``AssetEnricher`` genuinely reads
        it (hostname-pattern tiering), and ``_compute_risk_score`` reads
        ``self.risk_criteria`` live.

        ALL-OR-NOTHING. A failed/empty reload keeps the current criteria rather
        than silently zeroing scoring config, and the new time enricher is
        BUILT BEFORE anything is swapped in: committing risk_criteria and the
        asset enricher first and then raising left the service permanently
        half-reloaded (time context stuck on the old config with no retry)
        while the endpoint reported success.
        """
        risk_criteria = self._load_risk_criteria(self.config)
        if not risk_criteria:
            logger.warning("risk_criteria_reload_empty",
                           msg="Reload produced no risk criteria — keeping the "
                               "previously loaded copy.")
            return {"status": "error",
                    "message": "risk_criteria.yaml missing, empty or not a "
                               "mapping; kept previous criteria"}

        enrich_cfg = (self.config or {}).get("enrichment", {}) or {}
        try:
            new_time_enricher = TimeContextEnricher(
                resolve_time_context_config(enrich_cfg, risk_criteria))
        except Exception as e:
            logger.error("risk_criteria_reload_failed", error=str(e),
                         msg="Time-context rebuild failed — nothing was "
                             "swapped in, the previous criteria still apply.")
            return {"status": "error",
                    "message": "time context rebuild failed (%s); kept "
                               "previous criteria" % e}

        # ── commit point: nothing below may fail ──
        self.risk_criteria = risk_criteria
        for name in ("asset_enricher", "identity_enricher"):
            enricher = getattr(self, name, None)
            if enricher is not None:
                enricher.risk_criteria = risk_criteria
        self.time_enricher = new_time_enricher

        logger.info("risk_criteria_reloaded",
                    asset_tiers=len(risk_criteria.get("asset_criticality", {})),
                    user_profiles=len(
                        risk_criteria.get("user_risk_profiles", {})),
                    time_context=bool(risk_criteria.get("time_context")))
        return {
            "status": "ok",
            "asset_tiers": len(risk_criteria.get("asset_criticality", {})),
            "user_profiles": len(risk_criteria.get("user_risk_profiles", {})),
            "time_context": bool(risk_criteria.get("time_context")),
        }

    def _load_risk_criteria(self, config: dict) -> dict:
        """Load risk criteria from guidance directory."""
        try:
            import yaml
            guidance_cfg = config.get("guidance", {})
            base_path = guidance_cfg.get("base_path", "./config/guidance")
            criteria_file = guidance_cfg.get("risk_criteria", "risk_criteria.yaml")
            with open(f"{base_path}/{criteria_file}") as f:
                loaded = yaml.safe_load(f)
            if loaded is None:
                logger.error("risk_criteria_empty", file=criteria_file)
                return {}
            if not isinstance(loaded, dict):
                # An empty or list-rooted file used to propagate as None/list
                # into AssetEnricher.risk_criteria, where ``.get`` then raised
                # on EVERY alert. Fail to an empty mapping instead.
                logger.error("risk_criteria_not_a_mapping",
                             file=criteria_file, got=type(loaded).__name__)
                return {}
            return loaded
        except Exception as e:
            logger.error("risk_criteria_load_failed", error=str(e))
            return {}

    def normalize_alert(self, raw_alert: dict) -> dict:
        """Normalize Wazuh alert into a consistent schema."""
        rule = raw_alert.get("rule", {})
        agent = raw_alert.get("agent", {})
        data = raw_alert.get("data", {})

        # Extract MITRE info
        mitre = rule.get("mitre", {})
        mitre_tactics = mitre.get("tactic", [])
        mitre_techniques = mitre.get("id", [])

        # Extract source/destination from different alert types
        src_ip = (data.get("srcip") or data.get("src_ip") or
                  data.get("srcaddr") or raw_alert.get("data", {}).get("aws", {}).get("sourceIPAddress"))
        dst_ip = (data.get("dstip") or data.get("dst_ip") or data.get("dstaddr"))
        src_user = (data.get("srcuser") or data.get("src_user") or
                    data.get("dstuser") or data.get("user"))
        dst_user = data.get("dstuser") or data.get("dst_user")

        normalized = {
            "alert_id": raw_alert.get("id", str(uuid.uuid4())),
            "timestamp": raw_alert.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "rule_id": int(rule.get("id", 0)),
            "rule_level": int(rule.get("level", 0)),
            "rule_description": rule.get("description", ""),
            "rule_groups": rule.get("groups", []),
            "rule_mitre_tactics": mitre_tactics if isinstance(mitre_tactics, list) else [mitre_tactics],
            "rule_mitre_techniques": mitre_techniques if isinstance(mitre_techniques, list) else [mitre_techniques],
            "rule_pci_dss": rule.get("pci_dss", []),
            "rule_gdpr": rule.get("gdpr", []),
            "agent_id": agent.get("id", "000"),
            "agent_name": agent.get("name", "unknown"),
            "agent_ip": agent.get("ip", "") or None,
            "src_ip": src_ip or None,
            "dst_ip": dst_ip or None,
            "src_user": src_user,
            "dst_user": dst_user,
            "data": data,
            "full_log": raw_alert.get("full_log", ""),
            "decoder": raw_alert.get("decoder", {}),
            "location": raw_alert.get("location", ""),
        }

        # WO-H97 re-audit (F1): CARRY THE STRUCTURED EVENT OBJECTS THROUGH.
        #
        # A Wazuh FIM alert puts the changed file in a TOP-LEVEL ``syscheck``
        # object and carries no ``data`` at all — verified on both live tenants:
        # all 176 rule-110128 hits are
        #   {"syscheck": {"path": "/var/ossec/etc/rules/..."}, "location": "syscheck"}
        # This dict was built from ``rule``/``agent``/``data``/``full_log``/
        # ``decoder``/``location`` only, so every one of those objects was
        # DROPPED on the floor here — and it is this dict, not the raw alert,
        # that reaches the incident engine.
        #
        # That silently defeated the severity policy's path exclusion: with no
        # ``syscheck.path`` to read, the exclusion could never match, and the
        # ``detection_integrity`` floor fired at `high` on DHRUVA's OWN rule
        # validation probe file — several hundred pages a day. The exclusion was
        # correct and unreachable.
        #
        # Same list and same reason as ``webhook_handler.py::_normalize_alert``,
        # which has always done this; the two ingestion paths now agree. Copied
        # by reference like ``data`` above — nothing here mutates them.
        for _structured in ("syscheck", "rootcheck", "compliance",
                            "aws", "gcp", "office365"):
            if _structured in raw_alert:
                normalized[_structured] = raw_alert[_structured]
        # Stamp tenant identity — required for multi-tenant indexing
        tenant_id = _tenant_ctx.get()
        if tenant_id and tenant_id != "__CROSS_TENANT__":
            normalized["client_id"] = tenant_id
        return normalized

    def enrich_alert(self, normalized_alert: dict) -> dict:
        """Run all enrichers on a normalized alert and compute risk score."""
        self._maybe_self_heal_assets()
        enrichment = {}
        enricher_timings = {}

        # Asset context
        t0 = time.monotonic()
        try:
            asset_ctx = self.asset_enricher.enrich(normalized_alert)
            enrichment.update(asset_ctx)
        except Exception as e:
            logger.warning("asset_enrichment_failed", error=str(e))
            # Record the degradation rather than leaving it inferable only from
            # a missing key. asset_tier is one of the deterministic verdict
            # guard's trip conditions, and an absent key is indistinguishable
            # from "not a tier-1 asset" — which would turn the guard off
            # silently on exactly the alerts it exists for. See
            # src/agents/verdict_guard.py.
            enrichment.setdefault("degraded_enrichers", []).append("asset")
        enricher_timings["asset"] = round((time.monotonic() - t0) * 1000, 2)

        # Identity context
        t0 = time.monotonic()
        try:
            identity_ctx = self.identity_enricher.enrich(normalized_alert)
            enrichment.update(identity_ctx)
        except Exception as e:
            logger.warning("identity_enrichment_failed", error=str(e))
        enricher_timings["identity"] = round((time.monotonic() - t0) * 1000, 2)

        # Vulnerability / SCA host context (M4). Tenant-scoped, fail-safe:
        # any failure (incl. M2 fail-closed TenantConfigUnavailable) degrades
        # to multiplier 1.0 internally and never raises out of enrich().
        t0 = time.monotonic()
        try:
            vuln_ctx = self.vuln_context_enricher.enrich(normalized_alert)
            enrichment.update(vuln_ctx)
        except Exception as e:
            logger.warning("vuln_context_enrichment_failed", error=str(e))
        enricher_timings["vuln_context"] = round((time.monotonic() - t0) * 1000, 2)

        # Host-integrity (FIM/rootcheck) host context (M6b). Tenant-scoped,
        # fail-safe: any failure (incl. M2 fail-closed TenantConfigUnavailable)
        # degrades to multiplier 1.0 internally and never raises out of
        # enrich(); it never blocks the enrichment cycle.
        t0 = time.monotonic()
        try:
            host_integrity_ctx = self.host_integrity_enricher.enrich(normalized_alert)
            enrichment.update(host_integrity_ctx)
        except Exception as e:
            logger.warning("host_integrity_enrichment_failed", error=str(e))
        enricher_timings["host_integrity"] = round((time.monotonic() - t0) * 1000, 2)

        # Threat intelligence
        t0 = time.monotonic()
        try:
            ti_ctx = self.threat_intel_enricher.enrich(normalized_alert)
            enrichment.update(ti_ctx)
        except Exception as e:
            logger.warning("threat_intel_enrichment_failed", error=str(e))
            # threat_intel_hits / is_known_malicious are two of the three
            # verdict-guard trip conditions. Without this marker a TI outage
            # reads downstream as "clean", which is the most dangerous possible
            # default. See src/agents/verdict_guard.py.
            enrichment.setdefault("degraded_enrichers", []).append("threat_intel")
        enricher_timings["threat_intel"] = round((time.monotonic() - t0) * 1000, 2)

        # Historical context
        t0 = time.monotonic()
        try:
            hist_ctx = self.historical_enricher.enrich(normalized_alert)
            enrichment.update(hist_ctx)
        except Exception as e:
            logger.warning("historical_enrichment_failed", error=str(e))
        enricher_timings["historical"] = round((time.monotonic() - t0) * 1000, 2)

        # Time context
        t0 = time.monotonic()
        try:
            time_ctx = self.time_enricher.enrich(normalized_alert)
            enrichment.update(time_ctx)
        except Exception as e:
            logger.warning("time_enrichment_failed", error=str(e))
            # Same contract as asset/threat_intel above: an enricher that RAISED
            # must leave a trace, otherwise its absent keys read downstream as
            # "nothing to report". NOTE this does not trip the verdict guard —
            # "time" is deliberately not in verdict_guard.EVIDENCE_ENRICHERS, so
            # this is operator/audit visibility, not a dismissal block.
            enrichment.setdefault("degraded_enrichers", []).append("time")
        enricher_timings["time"] = round((time.monotonic() - t0) * 1000, 2)

        # Record enrichment latency metrics
        total_ms = sum(enricher_timings.values())
        self.db.record_metric("enrichment_latency_ms", total_ms, enricher_timings)
        enrichment["enricher_timings_ms"] = enricher_timings

        # Compute composite risk score with breakdown for audit trail
        risk_result = self._compute_risk_score(normalized_alert, enrichment)
        enrichment["risk_score"] = risk_result["score"]
        enrichment["risk_breakdown"] = risk_result["breakdown"]

        # Attach enrichment to alert
        normalized_alert["enrichment"] = enrichment
        return normalized_alert

    async def enrich_single_alert(self, alert: dict, tenant_id: str) -> dict:
        """Enrich a single alert (used by webhook ingestion).

        Sets tenant context, normalizes the alert into the canonical schema
        (including ``alert_id`` and ``client_id``), runs the full enrichment
        pipeline, and returns a schema-compatible enriched alert ready for
        indexing.
        """
        from src.database.store import _tenant_ctx
        token = _tenant_ctx.set(tenant_id)
        try:
            # Normalize — handles both raw Wazuh and webhook formats
            normalized = self.normalize_alert(alert)

            # Ensure canonical alert_id is present (webhook may use "id")
            if not normalized.get("alert_id") and alert.get("id"):
                normalized["alert_id"] = str(alert["id"])

            # Stamp tenant identity
            normalized["client_id"] = tenant_id

            # Run full enrichment (asset, identity, TI, historical, time, risk)
            enriched = self.enrich_alert(normalized)
            return enriched
        finally:
            _tenant_ctx.reset(token)

    # ── WO-H71: bounded scoring ──────────────────────────────────────────
    # Composition happens in LOG-ODDS and is squashed by a logistic at the
    # end, replacing "multiply nine independent factors, then clamp at 100".
    #
    # Three properties fall out of the shape rather than out of tuning:
    #
    #   BOUNDED BY CONSTRUCTION — the logistic maps any input into (0, 100),
    #   so nothing is destroyed at a ceiling. Under the old formula a raw 108
    #   and a raw 4,050 both persisted as exactly 100.
    #
    #   SUPPRESSIVE EVIDENCE CAN ACT — a negative adjustment moves the result
    #   at any magnitude. The old `fp_discount` was a multiplier floored at
    #   0.4 applied to a raw score often sitting 10x over the ceiling, so
    #   "this rule is a false positive 95% of the time" was computed, stored,
    #   displayed, and arithmetically incapable of changing the outcome.
    #
    #   DIMINISHING RETURNS — the logistic flattens near its extremes, so
    #   stacking boosts on an already-high score barely moves it. The old
    #   multiplier envelope reached ~60x.
    #
    # Measured on a live tenant against 305 reviewer-attributed human
    # labels (2026-08-12), leave-one-out:
    #
    #                          AUC     95% CI     at ceiling
    #   old multiplicative    0.354    +/-0.067      53%
    #   this formula          0.967    +/-0.019       0%
    #
    # The old score was not merely uninformative, it was INVERTED: mean score
    # 89.7 on analyst-confirmed false positives against 82.2 on true positives.
    _SCORE_PRIOR = 5.0        # smoothing strength, in pseudo-observations
    _SCORE_MAX_ADJ = 1.5      # total adjustment ceiling, in log-odds
    _SCORE_MIN_LABELS = 3     # below this a rule has no usable track record

    @staticmethod
    def _logit(p: float) -> float:
        p = min(max(p, 1e-6), 1.0 - 1e-6)
        return math.log(p / (1.0 - p))

    @staticmethod
    def _sigmoid(x: float) -> float:
        # Overflow-safe: math.exp(710) raises OverflowError, and a large
        # negative sum is reachable from a rule with a long clean record.
        if x >= 0:
            return 1.0 / (1.0 + math.exp(-min(x, 700.0)))
        e = math.exp(max(x, -700.0))
        return e / (1.0 + e)

    def _compute_risk_score(self, alert: dict, enrichment: dict) -> dict:
        """Dispatch to the configured scoring model.

        DEFAULTS TO ``bounded``. This was briefly shipped defaulting to
        ``legacy`` on the reasoning that a fresh install has no human labels to
        score on. That reasoning does not survive measurement: on the 308
        reviewer-attributed labels, the day-one signal available to any install
        (the Wazuh rule level) scores **AUC 0.518** while the legacy composite
        scores **0.351**. Legacy is not merely weaker on a cold start, it points
        the WRONG WAY — a coin toss beats it. A default that actively misleads
        is not a safe default, so ``legacy`` is retained only as an explicit
        escape hatch for a deployment that needs to reproduce old scores:

            enrichment:
              scoring:
                mode: legacy       # bounded (default) | legacy

        Both models populate ``breakdown``, so an operator can run either and
        compare distributions.
        """
        # getattr, not self.config: this dispatcher must degrade to the legacy
        # model on any construction that lacks config rather than raising —
        # a scorer that throws takes enrichment down with it.
        cfg = getattr(self, "config", None) or {}
        mode = str(((cfg.get("enrichment", {}) or {})
                    .get("scoring", {}) or {}).get("mode", "bounded")).lower()
        if mode == "legacy":
            return self._compute_risk_score_legacy(alert, enrichment)
        return self._compute_risk_score_bounded(alert, enrichment)

    def _compute_risk_score_bounded(self, alert: dict, enrichment: dict) -> dict:
        """WO-H71 replacement — see the block comment above for the rationale.

        The rule's own human-labelled track record supplies the base
        probability; bounded log-odds adjustments move it; a logistic squashes
        the result into (0, 100).

        A rule with fewer than ``_SCORE_MIN_LABELS`` human labels has NO usable
        track record. It falls back to the estate's base rate and is marked
        ``confident: False`` — deliberately not given an invented number, since
        inventing confidence is the failure this work order exists to fix.
        """
        rule_id = alert.get("rule_id", 0)
        scoring_cfg = ((self.risk_criteria or {}).get("scoring", {}) or {})

        # WO-H115 — WHO WROTE THE LABEL IS PART OF THE EVIDENCE.
        #
        # Every new deployment starts with zero labels, so every rule is
        # unlearned, so every alert takes the cold-start prior below and lands
        # in `high`. The only way out is for somebody to label alerts, and the
        # obvious shortcut is to let the platform label its own backlog. Do
        # that and the machine's opinion becomes indistinguishable from a
        # person's — it can make a rule QUIET with exactly the authority of an
        # analyst who looked.
        #
        # So machine labels are EVIDENCE, not TESTIMONY: they count, at a
        # discount, up to a hard cap, and they never confer confidence.
        # `confident` remains human-only, so everything downstream that already
        # respects it (the severity log line, the case view's "no track record
        # for this rule yet") keeps telling the truth.
        #
        # `machine_reviewers` is EMPTY by default, so a deployment that has
        # never used machine review scores exactly as it did before this change.
        machine_reviewers = [str(m) for m in
                             (scoring_cfg.get("machine_reviewers") or [])
                             if str(m).strip()]
        # getattr, not a direct call. A db object that predates WO-H115 has
        # `get_rule_human_outcomes` and not `get_rule_label_tiers`, and a bare
        # call would raise AttributeError straight into the broad except below
        # — silently scoring EVERY rule at the cold-start prior while logging a
        # lookup failure. "This method does not exist" is a programming error,
        # not a data condition, and must not be laundered into "this rule has
        # no history". So the older interface is used instead, which treats
        # every reviewer as human — exactly the behaviour before this change.
        #
        # The shape is CHECKED, not assumed. `getattr` alone is not enough: a
        # test double or a partially-migrated store can answer every attribute
        # and return something that is not a label split, and the broad except
        # below would then turn that into "this rule has no history" — scoring
        # the entire estate at the cold-start prior while logging a lookup
        # failure nobody reads.
        def _usable(t):
            if not isinstance(t, dict):
                return False
            for side in ("human", "machine"):
                part = t.get(side)
                if not isinstance(part, dict):
                    return False
                try:
                    int(part.get("n") or 0), int(part.get("k") or 0)
                except (TypeError, ValueError):
                    return False
            return True

        tiers = None
        _tiered = getattr(self.db, "get_rule_label_tiers", None)
        try:
            if callable(_tiered):
                tiers = _tiered(rule_id, machine_reviewers=machine_reviewers)
                if not _usable(tiers):
                    logger.warning("rule_label_tiers_malformed",
                                   rule_id=rule_id, got=type(tiers).__name__)
                    tiers = None
            if tiers is None:
                legacy = self.db.get_rule_human_outcomes(rule_id)
                tiers = {"human": {"n": int(legacy.get("total") or 0),
                                   "k": int(legacy.get("tp_count") or 0)},
                         "machine": {"n": 0, "k": 0}}
        except Exception as e:                      # noqa: BLE001 — never fail a score
            logger.warning("rule_history_lookup_failed",
                           rule_id=rule_id, error=str(e)[:200])
            tiers = {"human": {"n": 0, "k": 0}, "machine": {"n": 0, "k": 0}}

        base_rate = float(scoring_cfg.get("base_tp_rate", 0.5))
        # FAIL-SAFE COLD START. An unlearned rule must escalate until it earns
        # a lower score, not sit mid-scale where it escalates nothing.
        #
        # A fresh install has no human labels, so every alert would land on the
        # base rate. At 0.5 that is a score of 50 — below a typical escalation
        # threshold — so a genuine threat on a brand-new deployment would score
        # its way out of the queue on day one. Missing a real intrusion costs
        # more than an extra review, so unknown resolves upward.
        #
        # This is the cold-start prior ONLY. Once a rule has
        # ``_SCORE_MIN_LABELS`` human labels its own record takes over and this
        # value stops applying, so a noisy rule is loud briefly and then quiet.
        #
        # WO-H97 — THIS VALUE IS DELIBERATELY UNCHANGED, and the collision it
        # caused was fixed on the other side. With adjustments empty (which is
        # the norm: 400 of 400 recent decisions carry ``adjustments: {}``),
        # sigmoid(logit(0.75)) is exactly 0.75, so an unlearned rule scores
        # EXACTLY 75.00 — 3,208 of 35,129 decisions on a live tenant,
        # 9.1%. The incident engine's old ladder opened critical at ``>= 75``,
        # so every alert on a rule DHRUVA had not learned yet became a critical
        # incident. Nobody chose that; two independently sensible constants
        # happened to be equal.
        #
        # Lowering the prior to make the number look better would be wrong: the
        # comment above is explicit that a LOW-CONFIDENCE score is not a LOW
        # score, and "unknown" genuinely is mid-scale. So the BOUNDARY moved
        # instead (``src/incidents/severity.py``: critical at >= 80, which is
        # also what the SPA has always used), and 75.00 now lands in `high` —
        # escalated, at a 60-minute SLA, shown in the case view as "no track
        # record for this rule yet". Not critical, and not invisible.
        #
        # If you change this value, re-read src/incidents/severity.py first: a
        # band boundary must never sit on the score the model emits when it
        # knows nothing.
        unknown_rate = float(scoring_cfg.get("unknown_rule_tp_rate", 0.75))

        n_h = int((tiers.get("human") or {}).get("n") or 0)
        k_h = int((tiers.get("human") or {}).get("k") or 0)
        n_m = int((tiers.get("machine") or {}).get("n") or 0)
        k_m = int((tiers.get("machine") or {}).get("k") or 0)

        # Machine labels are discounted and then CAPPED. The cap is what stops
        # volume becoming authority: 5,000 machine labels are worth no more
        # than `machine_label_cap` observations, because they are one model's
        # opinion repeated, not independent evidence.
        weight = float(scoring_cfg.get("machine_label_weight", 0.25))
        cap = float(scoring_cfg.get("machine_label_cap", 10.0))
        eff_n_m = min(n_m * weight, cap) if n_m > 0 else 0.0
        eff_k_m = (k_m / n_m) * eff_n_m if n_m > 0 else 0.0

        min_labels = int(scoring_cfg.get("min_human_labels",
                                         self._SCORE_MIN_LABELS))
        # CONFIDENCE IS HUMAN-ONLY, deliberately. A machine may inform the
        # number; it may not vouch for it.
        confident = n_h >= min_labels

        # ONCE PEOPLE HAVE SPOKEN, THE MACHINE STOPS VOTING.
        #
        # Machine labels are a BRIDGE until analysts arrive, not a permanent
        # co-signer. The first cut kept both in the average, and with the cap at
        # 10 observations that meant four analysts saying "this is real" were
        # outnumbered 10:4 by a bot and the rule scored 34. A person who
        # actually looked must outrank any amount of machine opinion, so as
        # soon as the human record is usable the machine's is dropped whole.
        if confident:
            p = (k_h + self._SCORE_PRIOR * base_rate) / (n_h + self._SCORE_PRIOR)
        elif (n_h + eff_n_m) >= min_labels:
            p = ((k_h + eff_k_m + self._SCORE_PRIOR * base_rate)
                 / (n_h + eff_n_m + self._SCORE_PRIOR))
        else:
            p = unknown_rate

        if confident:
            label_tier = "human"
        elif eff_n_m > 0:
            label_tier = "assisted"
        else:
            label_tier = "none"

        n = n_h + n_m
        k = k_h + k_m
        hist_tp_rate = (k_h / n_h) if n_h else None

        # Adjustments are DELIBERATELY SPARSE. Every enrichment multiplier was
        # measured at or below 0.5 AUC on this estate — asset criticality
        # 0.488, vuln context 0.438, host integrity 0.475, baseline deviation
        # 0.442, time 0.318 — so none of them earns a weight yet. Adding a
        # factor here without measuring it first is how the old formula grew.
        adjustments = {}
        if enrichment.get("is_known_malicious"):
            # UNMEASURED on this estate (no sampled alert carried one). Kept on
            # first principles — a confirmed malicious IOC is evidence anywhere
            # — at a weight small enough that it cannot alone saturate.
            adjustments["known_malicious"] = 1.0
        elif (enrichment.get("threat_intel_hits") or 0) > 0:
            adjustments["threat_intel"] = 0.4

        raw_adj = sum(adjustments.values())
        adj = max(-self._SCORE_MAX_ADJ, min(self._SCORE_MAX_ADJ, raw_adj))
        log_odds = self._logit(p) + adj
        score = round(100.0 * self._sigmoid(log_odds), 2)

        return {
            "score": score,
            "breakdown": {
                "model": "bounded",
                "rule_tp_rate_human": hist_tp_rate,
                "rule_human_labels": n_h,
                "rule_human_tp": k_h,
                # WO-H115 provenance. `label_tier` is the field to read when
                # asking "did a person actually look at this rule?".
                "label_tier": label_tier,
                "rule_machine_labels": n_m,
                "rule_machine_tp": k_m,
                "machine_labels_effective": round(eff_n_m, 3),
                "base_rate": base_rate,
                "unknown_rule_rate": unknown_rate if not confident else None,
                "smoothed_p": round(p, 4),
                "adjustments": adjustments,
                "adjustment_total": round(adj, 4),
                "adjustment_clipped": raw_adj != adj,
                "log_odds": round(log_odds, 4),
                "confident": confident,
                # Why a low-confidence score is not a low score: an unknown rule
                # sits at the base rate, which is mid-scale, not zero.
                "confidence_reason": (
                    ("rule has %d human label(s); %d required%s"
                     % (n_h, min_labels,
                        (" — %d machine label(s) counted as %.1f observation(s)"
                         % (n_m, eff_n_m)) if n_m else ""))
                    if not confident else ""),
            },
        }

    def _compute_risk_score_legacy(self, alert: dict, enrichment: dict) -> dict:
        """The original multiplicative model. Retained as the default until an
        operator opts into ``bounded`` — see WO-H71 for why it saturates.

        Returns {"score": float, "breakdown": dict} so callers can store
        the individual multipliers for compliance explainability.
        """
        # Base severity from Wazuh rule level (1-15) mapped to 0-100
        base = (alert.get("rule_level", 0) / 15.0) * 100

        # Multipliers
        asset_mult = enrichment.get("asset_criticality_multiplier", 1.0)
        user_mult = enrichment.get("user_risk_multiplier", 1.0)
        time_mult = enrichment.get("time_risk_multiplier", 1.0)

        # Host vuln/SCA context (M4). Bounded by the enricher; default 1.0.
        # AMPLIFIES an existing signal — a low base stays low (multiplicative).
        vuln_context_mult = enrichment.get("vuln_context_multiplier", 1.0)

        # Host-integrity (FIM/rootcheck) context (M6b). Bounded by the enricher
        # (capped, default 1.0). Rootcheck-primary, thresholded-recent-FIM
        # secondary — sharpens an existing signal, never manufactures one.
        host_integrity_mult = enrichment.get("host_integrity_multiplier", 1.0)

        # MITRE priority boost
        mitre_boost = 1.0
        critical_techniques = []
        if self.risk_criteria:
            critical_techniques = (
                self.risk_criteria
                .get("mitre_attack_priority", {})
                .get("critical_techniques", [])
            )
        alert_techniques = alert.get("rule_mitre_techniques", [])
        if any(t in critical_techniques for t in alert_techniques):
            mitre_boost = 1.5

        # TI boost
        ti_boost = 1.0
        if enrichment.get("is_known_malicious"):
            ti_boost = 2.0
        elif enrichment.get("threat_intel_hits", 0) > 0:
            ti_boost = 1.3

        # Historical FP discount
        fp_discount = 1.0
        fp_rate = enrichment.get("historical_fp_rate", 0)
        if fp_rate > 0.8:
            fp_discount = 0.4
        elif fp_rate > 0.5:
            fp_discount = 0.6

        # Anomaly boost — elevate alerts deviating ABOVE behavioral baselines
        anomaly_boost = 1.0
        if enrichment.get("baseline_anomaly"):
            deviation = enrichment.get("baseline_deviation", 0)
            if deviation >= 4.0:
                anomaly_boost = 1.5
            elif deviation >= 3.0:
                anomaly_boost = 1.3
            elif deviation > 0:
                anomaly_boost = 1.15

        raw_score = (base * asset_mult * user_mult * time_mult
                     * mitre_boost * ti_boost * fp_discount * anomaly_boost
                     * vuln_context_mult * host_integrity_mult)
        clamped = min(100.0, max(0.0, round(raw_score, 2)))

        return {
            "score": clamped,
            "breakdown": {
                "base_severity": round(base, 2),
                "asset_multiplier": asset_mult,
                "user_multiplier": user_mult,
                "time_multiplier": time_mult,
                "mitre_boost": mitre_boost,
                "ti_boost": ti_boost,
                "fp_discount": fp_discount,
                "anomaly_boost": anomaly_boost,
                "vuln_context_multiplier": vuln_context_mult,
                "vuln_context_reason": enrichment.get("vuln_context_reason", ""),
                "host_integrity_multiplier": host_integrity_mult,
                "host_integrity_reason": enrichment.get("host_integrity_reason", ""),
                "host_rootcheck_findings": enrichment.get("host_rootcheck_findings", 0),
                "host_fim_recent_changes": enrichment.get("host_fim_recent_changes", 0),
                "raw_score": round(raw_score, 2),
                "clamped_score": clamped,
            },
        }

    def _fetch_alerts_dashboard_proxy(self, proxy_cfg: dict, query: dict,
                                       batch_size: int) -> list[dict]:
        """Fetch alerts via Wazuh Dashboard proxy when direct OpenSearch is unavailable.

        The Wazuh Dashboard (OSD) exposes a console proxy at:
          POST /api/console/proxy?path=<index>/_search&method=POST
        which forwards requests to the underlying OpenSearch indexer.
        """
        import urllib.parse
        from src.enrichment.proxy_ssl import resolve_proxy_verify_ssl
        base_url = proxy_cfg["url"].rstrip("/")
        username = proxy_cfg["username"]
        password = proxy_cfg["password"]

        # verify_ssl: True/False, or a path to CA cert for self-signed.
        # Shared policy (default True; explicit false honored only under
        # DEV_MODE; forced True + warned outside DEV_MODE; per-call warning
        # when genuinely off) lives in proxy_ssl.resolve_proxy_verify_ssl so
        # this path and tenant_registry.query_dashboard_proxy can't diverge.
        verify_ssl = resolve_proxy_verify_ssl(proxy_cfg)

        path = urllib.parse.quote("wazuh-alerts-4.x-*/_search", safe="")
        url = f"{base_url}/api/console/proxy?path={path}&method=POST"

        body = {**query, "size": batch_size}
        try:
            resp = _requests.post(
                url,
                json=body,
                auth=(username, password),
                headers={"osd-xsrf": "true", "Content-Type": "application/json"},
                verify=verify_ssl,
                timeout=30,
            )
            resp.raise_for_status()
            result = resp.json()
            raw_alerts = [hit["_source"] for hit in result.get("hits", {}).get("hits", [])]
            if raw_alerts:
                logger.info("alerts_fetched_via_dashboard_proxy",
                            count=len(raw_alerts), url=base_url)
            return raw_alerts
        except Exception as e:
            logger.error("dashboard_proxy_fetch_failed",
                         error=str(e)[:200], url=base_url)
            return []

    def process_batch(self) -> list[dict]:
        """
        Main processing loop iteration:
        1. Fetch new alerts from OpenSearch (wazuh-alerts-* index)
           — or via Dashboard proxy if tenant config specifies it
        2. Normalize and enrich each alert
        3. Store in enriched alerts index
        4. Return enriched alerts for agent processing
        """
        # Fail closed: in multi-tenant mode, tenant context MUST be set
        if is_multi_tenant():
            current = _tenant_ctx.get()
            if not current or current == "__CROSS_TENANT__":
                logger.error("process_batch_no_tenant_context",
                             msg="process_batch() called in MT mode without tenant context")
                return []

        wazuh_cfg = self.config["wazuh"]["alerts"]
        min_level = wazuh_cfg.get("min_severity", 3)
        batch_size = wazuh_cfg.get("batch_size", 50)
        # WO-H13: bounded look-back overlap window (seconds). Clamped to
        # [0, _MAX_LOOK_BACK_SECONDS]; 0 disables the look-back entirely. The
        # ceiling keeps it a small overlap and forbids regressing to the old
        # full sliding-window re-scan.
        _cfg_look_back = wazuh_cfg.get("look_back_seconds",
                                       _DEFAULT_LOOK_BACK_SECONDS)
        try:
            look_back_seconds = int(_cfg_look_back)
        except (TypeError, ValueError):
            look_back_seconds = _DEFAULT_LOOK_BACK_SECONDS
        look_back_seconds = max(0, min(look_back_seconds,
                                       _MAX_LOOK_BACK_SECONDS))

        # Determine fetch window: new tenants start from "now" (no backfill),
        # existing tenants use a rolling lookback window.
        # NOTE: _tenant_ctx is imported at module level — do NOT re-import here
        current_tenant = _tenant_ctx.get()
        if not hasattr(self, '_tenant_first_fetch'):
            self._tenant_first_fetch = {}
        if not hasattr(self, '_tenant_fetch_anchor'):
            self._tenant_fetch_anchor = {}  # tenant_id -> ISO timestamp of first poll
        if not hasattr(self, '_tenant_cursor'):
            # WO-H9: monotonic ASCENDING cursor per tenant. For the direct
            # OpenSearch path this holds the ``search_after`` sort tuple
            # ``[timestamp, _id]`` of the LAST alert fetched, so each poll pages
            # strictly FORWARD past that exact (timestamp, _id) position. A plain
            # gte-timestamp cursor would stall if >batch_size alerts shared one
            # exact timestamp (the same top-N would return forever and the cursor
            # never advances); pairing the timestamp with the tiebreaking ``_id``
            # via search_after makes progress strictly monotonic. In-memory: on
            # restart we re-seed from the fetch window and rely on the durable
            # processed-id dedup to skip already-HANDLED alerts.
            self._tenant_cursor = {}  # tenant_id -> [timestamp, _id] sort tuple
        if not hasattr(self, '_tenant_ts_floor'):
            # Proxy path only: a timestamp-string floor cursor (the dashboard
            # proxy does not return per-hit sort values, so search_after can't be
            # threaded through it). Advanced from the newest fetched timestamp.
            self._tenant_ts_floor = {}  # tenant_id -> ISO timestamp

        if current_tenant and current_tenant not in self._tenant_first_fetch:
            # First poll for this tenant — check if they have any processed alerts
            has_history = bool(self.db.is_alert_processed("__probe__") is not None
                               and len(self.processed_ids) > 0)
            if has_history:
                fetch_window = "now-24h"
            else:
                # New tenant with no history — only fetch from now onwards
                fetch_window = "now-1m"
                self._tenant_fetch_anchor[current_tenant] = datetime.now(
                    timezone.utc).isoformat()
                logger.info("new_tenant_first_fetch",
                            tenant=current_tenant,
                            message="First connection — fetching only new alerts, no backfill")
            self._tenant_first_fetch[current_tenant] = True
        elif current_tenant in self._tenant_fetch_anchor:
            # Subsequent polls for a newly-enrolled tenant — use the anchor
            # timestamp so we never backfill before enrollment time
            fetch_window = self._tenant_fetch_anchor[current_tenant]
        else:
            fetch_window = "now-24h"

        # WO-H9: prefer the monotonic ascending cursor once we have one for this
        # tenant, so each poll continues FORWARD from the last alert seen rather
        # than re-scanning a sliding desc window (which starved older alerts).

        # Resolve the fetch route first — proxy vs direct — because the cursor
        # strategy differs (search_after needs per-hit sort values the proxy
        # doesn't return).
        proxy_cfg = None
        if self._tenant_registry and current_tenant:
            tenant_cfg = self._tenant_registry.get_tenant_config(current_tenant)
            proxy_cfg = tenant_cfg.get("dashboard_proxy")

        # Precise ascending pagination cursor (direct path) vs timestamp floor.
        search_after = None
        if not proxy_cfg and current_tenant:
            search_after = self._tenant_cursor.get(current_tenant)
        # Timestamp floor: the proxy path's advancing cursor, or the first-poll
        # window before we have a precise cursor.
        lower_bound = fetch_window
        if proxy_cfg and current_tenant and current_tenant in self._tenant_ts_floor:
            lower_bound = self._tenant_ts_floor[current_tenant]

        # WO-H13: capture the high-water mark this poll STARTS from (the cursor
        # the forward scan pages past) BEFORE it is advanced below — the
        # look-back window is measured behind exactly this point. Direct path:
        # the timestamp element of the search_after tuple. Proxy path: the
        # pre-poll ISO timestamp floor. None on the first poll (no cursor yet),
        # where the wide initial fetch_window already covers late arrivals.
        high_water_val = None
        if search_after:
            high_water_val = search_after[0]
        elif proxy_cfg and current_tenant:
            high_water_val = self._tenant_ts_floor.get(current_tenant)

        # Fetch raw alerts from Wazuh's alert index in OpenSearch
        # In multi-tenant mode, scope by the current tenant's allowed agent IDs
        last_sort = None
        # Shared query scoping — min rule level + fail-closed per-tenant agent
        # scoping — built ONCE so the WO-H13 look-back query reuses the exact
        # same restrictions and can never widen a tenant's visibility.
        base_must = None
        try:
            base_must = [
                {"range": {"rule.level": {"gte": min_level}}},
            ]
            if is_multi_tenant() and current_tenant:
                allowed_agents = self.db.get_tenant_agent_ids(current_tenant)
                if allowed_agents is not None:
                    base_must.append({"terms": {"agent.id": allowed_agents}})
                else:
                    # No agent mapping in MT mode — fetch nothing (fail closed)
                    base_must.append({"terms": {"agent.id": []}})

            must_clauses = list(base_must)
            # Only apply the timestamp floor when we have NO precise
            # search_after cursor (first poll, or proxy path). Once search_after
            # is set it supersedes the floor and paginates strictly forward.
            if not search_after:
                must_clauses.append(
                    {"range": {"timestamp": {"gte": lower_bound}}})

            query = {
                "query": {"bool": {"must": must_clauses}},
                # ASCENDING (oldest-first) with a stable ``_id`` tiebreaker so the
                # search_after cursor advances monotonically and >batch_size
                # same-timestamp alerts can't stall the pipeline.
                "sort": [
                    {"timestamp": {"order": "asc"}},
                    {"_id": {"order": "asc"}},
                ],
            }
            if search_after:
                query["search_after"] = search_after

            if proxy_cfg:
                raw_alerts = self._fetch_alerts_dashboard_proxy(
                    proxy_cfg, query, batch_size)
            else:
                result = self.opensearch.client.search(
                    index="wazuh-alerts-4.x-*",
                    body=query,
                    size=batch_size
                )
                hits = result["hits"]["hits"]
                raw_alerts = [hit["_source"] for hit in hits]
                # Capture the LAST hit's sort values as the next search_after
                # cursor (ascending => last hit is the furthest-forward).
                if hits and "sort" in hits[-1]:
                    last_sort = hits[-1]["sort"]
                if raw_alerts:
                    logger.info("wazuh_alerts_fetched_from_opensearch", count=len(raw_alerts))
        except Exception as e:
            logger.error("wazuh_alerts_fetch_failed", error=str(e)[:200])
            raw_alerts = []

        # WO-H9: advance the cursor and emit the backlog-lag metric (how far
        # behind real time we are). We advance from the RAW batch — even alerts
        # that dedup out still count as "seen", so the cursor keeps moving
        # forward and never re-scans them.
        if current_tenant and raw_alerts:
            newest_ts = None
            for raw in raw_alerts:
                ts = raw.get("timestamp") or raw.get("@timestamp")
                if ts and (newest_ts is None or str(ts) > str(newest_ts)):
                    newest_ts = ts
            # Direct path: precise search_after cursor. Proxy path: timestamp
            # floor (advance only forward).
            if last_sort is not None:
                self._tenant_cursor[current_tenant] = last_sort
            elif proxy_cfg and newest_ts:
                prev = self._tenant_ts_floor.get(current_tenant)
                if prev is None or str(newest_ts) >= str(prev):
                    self._tenant_ts_floor[current_tenant] = newest_ts
            if newest_ts:
                try:
                    from datetime import datetime as _dt, timezone as _tz
                    # WO-H116: ``timestamp`` comes from Wazuh via OpenSearch as
                    # ``...905+0000`` — an offset with no colon, which
                    # ``fromisoformat`` REJECTS on Python < 3.11. This metric
                    # was therefore dead on every 3.10 deployment (876
                    # ``triage_backlog_metric_failed`` lines in one day on the
                    # live tenant) while dev and CI stayed green.
                    parsed = parse_iso8601(str(newest_ts))
                    lag = (_dt.now(_tz.utc) - parsed).total_seconds()
                    self.db.record_metric(
                        "triage_backlog_seconds", max(0.0, lag),
                        {"tenant": current_tenant,
                         "cursor": str(newest_ts),
                         "batch": len(raw_alerts)})
                except Exception as e:                   # noqa: BLE001
                    # WO-H90: was a bare `except: pass`. A failure here means the
                    # triage-backlog metric stops being recorded, so the "how far
                    # behind is triage" graph flatlines and nobody can tell a
                    # stalled pipeline from a quiet night. Once per collection
                    # cycle per tenant, not per alert.
                    logger.warning("triage_backlog_metric_failed",
                                   tenant=current_tenant,
                                   error=str(e)[:200])

        # WO-H13: bounded look-back overlap. In ADDITION to the forward scan,
        # re-query the small window immediately BEHIND the high-water mark so an
        # alert that arrived out-of-order within it (clock skew, delayed ingest,
        # backfill) is picked up. This does NOT touch the forward cursor or the
        # backlog metric — both stay driven solely by the forward scan above, so
        # the cursor still advances strictly monotonically and can't stall. The
        # look-back re-surfaces already-handled alerts too, but the processed-id
        # dedup in the loop below skips them, so only GENUINELY-new late arrivals
        # are triaged — never a re-triage. The same per-tenant agent scoping
        # (base_must) is reused, so tenant isolation is unchanged. Applies to
        # BOTH the direct-OpenSearch path and the dashboard-proxy path (a plain
        # bounded range query needs no per-hit sort values, unlike search_after).
        # DOCUMENTED BOUND: an alert whose event timestamp is older than
        # (high_water - look_back_seconds) by the time of this poll is NOT caught.
        if (look_back_seconds > 0 and base_must is not None
                and current_tenant and high_water_val is not None):
            hw_ms = _sort_value_to_millis(high_water_val)
            if hw_ms is not None:
                gte_ms = hw_ms - look_back_seconds * 1000
                lookback_must = list(base_must)
                lookback_must.append({
                    "range": {"timestamp": {
                        "gte": gte_ms, "lte": hw_ms,
                        "format": "epoch_millis"}}})
                lookback_query = {
                    "query": {"bool": {"must": lookback_must}},
                    # Ascending + stable _id tiebreaker, mirroring the forward
                    # query; bounded by batch_size so it can't become a re-scan.
                    "sort": [
                        {"timestamp": {"order": "asc"}},
                        {"_id": {"order": "asc"}},
                    ],
                }
                try:
                    if proxy_cfg:
                        lookback_raw = self._fetch_alerts_dashboard_proxy(
                            proxy_cfg, lookback_query, batch_size)
                    else:
                        lb_result = self.opensearch.client.search(
                            index="wazuh-alerts-4.x-*",
                            body=lookback_query,
                            size=batch_size,
                        )
                        lookback_raw = [h["_source"]
                                        for h in lb_result["hits"]["hits"]]
                    if lookback_raw:
                        raw_alerts = raw_alerts + lookback_raw
                        logger.info("triage_lookback_window_scanned",
                                    tenant=current_tenant,
                                    look_back_seconds=look_back_seconds,
                                    candidates=len(lookback_raw))
                except Exception as e:
                    logger.warning("triage_lookback_fetch_failed",
                                   error=str(e)[:200])

        enriched_batch = []
        for raw in raw_alerts:
            alert_id = raw.get("id", raw.get("_id", ""))
            if not alert_id:
                continue

            # Tenant-qualified cache key to prevent cross-tenant dedup collisions
            cache_key = f"{current_tenant}:{alert_id}" if current_tenant else alert_id

            # Check in-memory cache first, then Postgres
            if cache_key in self.processed_ids:
                continue
            if self.db.is_alert_processed(alert_id):
                self.processed_ids.add(cache_key)
                continue

            # Normalize
            normalized = self.normalize_alert(raw)

            # Enrich
            enriched = self.enrich_alert(normalized)

            # Store in enriched index (buffer on transient failure;
            # poison pills get buffered too and the buffer flush quarantines
            # them to the dead-letter table on next tick).
            from src.enrichment.opensearch_client import INDEX_OK
            stored = None
            try:
                stored = self.opensearch.index_enriched_alert(enriched)
            except Exception as idx_err:
                logger.warning("alert_index_exception",
                               error=str(idx_err)[:200])

            if stored != INDEX_OK:
                if self.alert_buffer:
                    buffered = self.alert_buffer.buffer_alert(enriched)
                    if buffered:
                        logger.warning("alert_buffered_opensearch_unavailable",
                                       alert_id=alert_id,
                                       index_result=stored,
                                       buffer_count=self.alert_buffer.get_buffer_count())
                    else:
                        logger.error("alert_buffer_failed",
                                     alert_id=alert_id)
                        continue  # Neither indexed nor buffered — retry
                else:
                    logger.error("alert_index_failed_no_buffer",
                                 alert_id=alert_id, index_result=stored)
                    continue  # Do NOT mark processed — alert should be retried

            # WO-H9 crash-safe checkpoint: do NOT durably mark processed here.
            # The DURABLE ``processed_alerts`` checkpoint is written only once an
            # alert is fully HANDLED — atomically with the triage decision save
            # (store.save_decision) for triaged alerts, or at the below-threshold
            # skip point in the fetch loop. Marking at enrichment (pre-triage)
            # meant a shutdown/crash that dropped the not-yet-triaged queue item
            # left the alert durably "processed" → never re-fetched → SILENT
            # detection loss. The IN-MEMORY add still de-dups boundary re-reads
            # within this process; it is cleared on restart, so a dropped alert
            # is safely re-fetched + re-enriched (idempotent by alert_id) +
            # re-triaged.
            self.processed_ids.add(cache_key)

            # Trim in-memory cache (Postgres is source of truth)
            if len(self.processed_ids) > self._max_processed_cache:
                self.processed_ids = self.db.get_processed_ids(hours=48)

            enriched_batch.append(enriched)

        if enriched_batch:
            logger.info("enrichment_batch_processed", count=len(enriched_batch))
            self.db.record_metric("alerts_enriched", len(enriched_batch))

        return enriched_batch

    def compute_baselines(self) -> dict:
        """
        Compute 30-day behavioral baselines per agent, user, and source IP.
        Queries OpenSearch for daily alert counts, computes mean/stddev,
        and stores results in Postgres for fast per-alert lookups.
        """
        hist_cfg = self.config.get("enrichment", {}).get("historical", {})
        window_days = hist_cfg.get("baseline_window_days", 30)

        dimensions = [
            ("agent", "agent_name"),
            ("src_ip", "src_ip"),
            ("src_user", "src_user"),
        ]

        stats = {"dimensions_processed": 0, "baselines_saved": 0, "errors": 0}

        for dim_name, os_field in dimensions:
            try:
                values = self.opensearch.get_unique_dimension_values(
                    os_field, days=window_days, max_values=500
                )
                logger.info("baseline_dimension_discovered",
                            dimension=dim_name, unique_values=len(values))

                for value in values:
                    if not value:
                        continue
                    try:
                        daily = self.opensearch.get_daily_alert_counts(
                            os_field, value, days=window_days
                        )
                        if len(daily) < 3:
                            continue  # Not enough data points

                        counts = [d["count"] for d in daily]
                        risks = [d["avg_risk"] for d in daily if d["avg_risk"]]

                        # Daily alert count baseline
                        count_mean = sum(counts) / len(counts)
                        count_var = sum((c - count_mean) ** 2 for c in counts) / len(counts)
                        count_std = math.sqrt(count_var)

                        self.db.save_baseline(
                            dimension=dim_name,
                            dimension_value=str(value),
                            metric="daily_alert_count",
                            mean=count_mean,
                            std_dev=count_std,
                            sample_count=len(counts),
                            window_days=window_days
                        )
                        stats["baselines_saved"] += 1

                        # Average risk score baseline
                        if risks:
                            risk_mean = sum(risks) / len(risks)
                            risk_var = sum((r - risk_mean) ** 2 for r in risks) / len(risks)
                            risk_std = math.sqrt(risk_var)

                            self.db.save_baseline(
                                dimension=dim_name,
                                dimension_value=str(value),
                                metric="daily_avg_risk",
                                mean=risk_mean,
                                std_dev=risk_std,
                                sample_count=len(risks),
                                window_days=window_days
                            )
                            stats["baselines_saved"] += 1

                    except Exception as e:
                        logger.warning("baseline_value_failed",
                                       dimension=dim_name, value=value, error=str(e))
                        stats["errors"] += 1

                stats["dimensions_processed"] += 1

            except Exception as e:
                logger.error("baseline_dimension_failed",
                             dimension=dim_name, error=str(e))
                stats["errors"] += 1

        self.db.record_metric("baselines_computed", stats["baselines_saved"], stats)
        logger.info("baseline_computation_completed", **stats)
        return stats

    def get_alert_context_for_agent(self, alert: dict,
                                     max_correlated: int = 20) -> dict:
        """
        Build the full context package an agent needs for triage.
        Includes the alert, its enrichment, and correlated events.
        """
        context = {
            "alert": alert,
            "enrichment": alert.get("enrichment", {}),
            "correlated_events": [],
            "rule_history": [],
            "source_history": [],
            "user_history": []
        }

        # Get correlated events
        try:
            correlated = self.opensearch.get_correlated_events(
                alert, window_minutes=60, size=max_correlated
            )
            context["correlated_events"] = correlated
        except Exception as e:
            logger.warning("correlation_failed", error=str(e))

        # Rule-specific history
        rule_id = alert.get("rule_id")
        if rule_id:
            context["rule_history"] = self.opensearch.get_alert_history_for_rule(
                rule_id, days=7, size=10
            )

        # Source IP history
        if alert.get("src_ip"):
            context["source_history"] = self.opensearch.get_alert_history_for_source(
                alert["src_ip"], days=7, size=10
            )

        return context
