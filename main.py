"""
DHRUVA - Main Orchestrator
SecureSleuths - Wazuh AI-Augmented Security Operations

This is the entry point that initializes all components and runs the
continuous processing loop.
"""

import os
import sys
import time
import uuid
import signal
import threading
import structlog
import yaml
from pathlib import Path
from datetime import datetime, timezone
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
from src.build_profile import resolve_build_profile
from src.__version__ import __version__

# Setup structured logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.ConsoleRenderer()
    ],
    wrapper_class=structlog.BoundLogger,
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
)
logger = structlog.get_logger("ai-soc")
BUILD_PROFILE = resolve_build_profile()
COMMUNITY_BUILD = BUILD_PROFILE == "community"

# Load environment — use explicit path for .pyc/.so compatibility
# (dotenv's auto-discovery fails with compiled bytecode)
try:
    _env_dir = os.path.dirname(os.path.abspath(__file__))
except NameError:
    _env_dir = os.getcwd()
load_dotenv(os.path.join(_env_dir, ".env"))

from src.database.store import SOCDatabase
from src.enrichment.service import EnrichmentService
from src.enrichment.wazuh_client import WazuhClient
from src.agents.triage_agent import TriageAgent
from src.incidents.engine import IncidentEngine
from src.incidents.sla import SLAManager
from src.metrics.calculator import MetricsCalculator
from src.mitre.coverage import MITRECoverageAnalyzer
from src.knowledge_base.service import KnowledgeBaseService
from src.database.tenant_registry import (
    TenantServiceRegistry, TenantConfigUnavailable)
from src.guidance.loader import GuidanceLoader
from src.api.server import app, init_api

# Optional paid modules — imported at runtime if available
def _try_import(module, name, *, paid: bool = False):
    if paid and COMMUNITY_BUILD:
        return None
    try:
        return getattr(__import__(module, fromlist=[name]), name)
    except ModuleNotFoundError as e:
        # Only suppress if the stripped module itself is missing (Community build).
        # Re-raise if a transitive dependency is broken — that's a real bug.
        if e.name and e.name != module and not module.startswith(e.name + "."):
            raise
        return None

DetectionAgent = _try_import("src.agents.detection_agent", "DetectionAgent", paid=True)
ThreatHuntAgent = _try_import("src.agents.hunt_agent", "ThreatHuntAgent", paid=True)
QueryAgent = _try_import("src.agents.query_agent", "QueryAgent", paid=True)
FeedbackLoopEngine = _try_import("src.feedback.loop", "FeedbackLoopEngine", paid=True)
SOAREngine = _try_import("src.soar.engine", "SOAREngine", paid=True)
TicketingService = _try_import("src.ticketing.service", "TicketingService", paid=True)
NotificationService = _try_import("src.notifications.service", "NotificationService", paid=True)
PipelineHealthMonitor = _try_import("src.pipeline.health_monitor", "PipelineHealthMonitor", paid=True)
AlertBuffer = _try_import("src.pipeline.alert_buffer", "AlertBuffer")
if AlertBuffer is None:
    # Community build — src/pipeline/ is stripped. Fall back to the bounded
    # in-memory ring so transient OpenSearch failures don't drop alerts.
    from src.enrichment.inmem_buffer import InMemoryAlertBuffer as AlertBuffer


class AISocPlatform:
    """
    Main platform orchestrator.

    Architecture:
    ┌─────────────────────────────────────────────────────────────────┐
    │                    AI SOC Platform                              │
    │                                                                 │
    │  ┌──────────┐    ┌──────────────┐    ┌───────────────────┐     │
    │  │  Wazuh   │───▶│  Enrichment  │───▶│   Triage Agent    │     │
    │  │  Alerts  │    │   Service    │    │   (Claude API)    │     │
    │  └──────────┘    └──────────────┘    └────────┬──────────┘     │
    │                         │                      │                │
    │                         ▼                      ▼                │
    │                  ┌──────────────┐    ┌───────────────────┐     │
    │                  │  OpenSearch  │    │    SQLite DB       │     │
    │                  │  (enriched)  │    │  (decisions/metrics│     │
    │                  └──────────────┘    └────────┬──────────┘     │
    │                                               │                │
    │                                               ▼                │
    │  ┌──────────────────────────────────────────────────────┐     │
    │  │              Feedback Loop Engine                     │     │
    │  │  ┌────────────┐  ┌──────────────┐  ┌─────────────┐ │     │
    │  │  │  Override   │  │  FP Pattern  │  │ Effectiveness│ │     │
    │  │  │  Analysis   │  │  Detection   │  │  Tracking    │ │     │
    │  │  └──────┬─────┘  └──────┬───────┘  └─────────────┘ │     │
    │  │         │               │                            │     │
    │  │         ▼               ▼                            │     │
    │  │  ┌──────────────────────────────────┐               │     │
    │  │  │     Detection Engineering Agent   │               │     │
    │  │  │     (Proposes rule improvements)  │               │     │
    │  │  └──────────────────────────────────┘               │     │
    │  └──────────────────────────────────────────────────────┘     │
    │                                                                 │
    │  ┌──────────────────────────────────────────────────────┐     │
    │  │  FastAPI Server (Dashboard + Human Review API)        │     │
    │  └──────────────────────────────────────────────────────┘     │
    └─────────────────────────────────────────────────────────────────┘
    """

    # Credentials that must be changed from defaults before production use
    INSECURE_DEFAULTS = {"wazuh", "admin", "CHANGE_ME", "password", "changeme", ""}

    def __init__(self, config_path: str = "config/config.yaml"):
        self.config = self._load_config(config_path)
        self.running = False
        self._shutdown_event = threading.Event()

        # Validate credentials at startup
        self._validate_credentials()

        # Validate platform license
        self._validate_license()

        # Initialize components
        logger.info("platform_initializing", version=__version__)
        logger.info("build_profile_selected", profile=BUILD_PROFILE)

        # Database — DATABASE_URL env wins, then config.database.dsn, else
        # hard-fail in SOCDatabase._resolve_dsn. SQLite ``database.path``
        # entries are deliberately ignored; operators on legacy configs
        # see a clear v4.9.0 cutover error instead of a silent fallback.
        db_cfg = self.config.get("database") or {}
        # Pool size: config database.pool_size → DB_POOL_SIZE env → default 20
        # (resolution + sizing arithmetic live in SOCDatabase).
        self.db = SOCDatabase(db_cfg.get("dsn"),
                              pool_size=db_cfg.get("pool_size"))
        logger.info("database_ready")

        # Seed admin user from env if DB has no users (backward compat)
        # Runs before tenant context exists — use cross_tenant bypass
        with self.db.cross_tenant():
            if self.db.get_user_count() == 0:
                from src.api.auth import hash_password
                from src.database.store import PlatformUser
                admin_user = os.getenv("SOC_ADMIN_USER", "admin")
                admin_pw = os.getenv("SOC_ADMIN_PASSWORD", "")
                admin_role = os.getenv("SOC_ADMIN_ROLE", "admin")
                if admin_role not in ("admin", "mssp_admin"):
                    admin_role = "admin"
                if admin_pw:
                    pw_hash, salt = hash_password(admin_pw)
                    now = datetime.now(timezone.utc).isoformat()
                    self.db.save_user(PlatformUser(
                        id=str(uuid.uuid4()), username=admin_user,
                        password_hash=pw_hash, salt=salt,
                        display_name="Platform Admin", email="",
                        role=admin_role, is_active=1,
                        created_at=now, updated_at=now,
                    ))
                    logger.info("admin_user_seeded", username=admin_user,
                                role=admin_role)
                else:
                    logger.critical("no_admin_password",
                                    message="SOC_ADMIN_PASSWORD not set and no users in DB. "
                                            "Cannot start without an admin user. "
                                            "Set SOC_ADMIN_PASSWORD in .env and restart.")
                    raise SystemExit(
                        "FATAL: SOC_ADMIN_PASSWORD is not set and no users exist in the "
                        "database. Set SOC_ADMIN_PASSWORD in your .env file to create "
                        "the initial admin user."
                    )

        # Seed default tenant if none exist (single-tenant → multi-tenant migration)
        self._seed_default_tenant()

        # Set tenant context for the rest of startup initialization
        default_tenant = self.config.get("client_id")
        if default_tenant:
            self.db.set_tenant(default_tenant)

        # Guidance
        self.guidance = GuidanceLoader(self.config)
        logger.info("guidance_loaded")

        # Enrichment service (includes Wazuh + OpenSearch clients)
        self.enrichment = EnrichmentService(self.config, self.db)
        logger.info("enrichment_service_ready")

        # Validate Wazuh/OpenSearch connectivity early (non-fatal, informational)
        self._check_infrastructure_services()

        # Cleanup stale validation temp file (prevents Wazuh crash on restart).
        # Only relevant when the Detection Agent is present — it's the
        # consumer of _ai_soc_validation_temp.xml. On Community the
        # DetectionAgent module is stripped, the temp file is never written,
        # and the Wazuh API user typically lacks rule-management permission
        # — the delete attempt would log a misleading 403 every boot.
        if DetectionAgent:
            try:
                self.enrichment.wazuh._delete_rule_file("_ai_soc_validation_temp.xml")
            except Exception:
                pass

        # Threat Intelligence Collector
        from src.enrichment.threat_intel.collector import ThreatIntelCollector
        ti_cfg = self.config.get("threat_intel", {})
        if ti_cfg.get("enabled", True):
            self.ti_collector = ThreatIntelCollector(ti_cfg, self.db)
            # Wire the collector into the enricher for on-demand lookups
            self.enrichment.threat_intel_enricher.ti_collector = self.ti_collector
            logger.info("threat_intel_collector_ready",
                         feeds=len(self.ti_collector.feeds))
        else:
            self.ti_collector = None
            logger.info("threat_intel_collector_disabled")

        # Knowledge Base
        self.knowledge_base = KnowledgeBaseService(self.config, self.db)
        if self.knowledge_base.enabled:
            try:
                count = self.knowledge_base.index_guidance_docs(self.guidance)
                logger.info("kb_guidance_indexed", count=count)
            except Exception as e:
                logger.warning("kb_guidance_index_failed", error=str(e))

        # Tenant Service Registry (multi-tenancy) — must be before TriageAgent
        self.tenant_registry = TenantServiceRegistry(self.db, global_config=self.config)
        self.enrichment._tenant_registry = self.tenant_registry
        logger.info("tenant_registry_ready")

        # Detect multi-tenant mode: if more than one active tenant exists,
        # enable fail-closed tenant isolation across OpenSearch/Wazuh queries.
        from src.database.store import set_multi_tenant_mode, is_multi_tenant
        try:
            active_tenants = self.tenant_registry.get_active_tenant_ids()
            _is_mt = len(active_tenants) > 1
            set_multi_tenant_mode(_is_mt)
        except Exception:
            set_multi_tenant_mode(False)

        # WO-H12-followup: RLS-active boot gate. In multi-tenant mode the Postgres
        # RLS backstop (WO-H12) is the structural tenant-isolation guarantee — but
        # it is SILENTLY bypassed when DHRUVA connects as a superuser / BYPASSRLS
        # role (e.g. the docker-compose bundled-db default). Refuse to start rather
        # than run with a backstop that isn't actually in effect. Single-tenant mode
        # skips this (RLS is not the isolation boundary there).
        if is_multi_tenant():
            _rls_ok, _rls_reason = self.db.verify_rls_active()
            if not _rls_ok:
                raise SystemExit(
                    "FATAL: multi-tenant mode is active but Postgres Row-Level "
                    "Security is NOT in effect — the tenant backstop is silently "
                    f"bypassed. {_rls_reason} Fix: run DHRUVA as a NON-superuser, "
                    "NON-BYPASSRLS DB role (see docs/MULTI-TENANT.md §Row-Level "
                    "Security) and ensure migration 0006 has run. Refusing to start."
                )
            logger.info("rls_backstop_active", detail=_rls_reason)
        else:
            logger.info("rls_backstop_skipped", reason="single-tenant mode")

        # Triage Agent (with multi-tenant LLM support)
        self.triage_agent = TriageAgent(
            self.config, self.db, self.enrichment, self.guidance,
            knowledge_base=self.knowledge_base,
            tenant_registry=self.tenant_registry
        )
        logger.info("triage_agent_ready", multi_tenant=True)

        # Detection Agent (requires "detection" feature + module)
        self.detection_agent = None
        if self._license_info.has_feature("detection") and DetectionAgent:
            self.detection_agent = DetectionAgent(
                self.config, self.db, self.enrichment.wazuh
            )
            logger.info("detection_agent_ready")
        elif not self._license_info.has_feature("detection"):
            logger.warning("detection_agent_disabled_by_license")

        # Feedback Loop Engine (requires detection agent + module)
        self.feedback_engine = None
        if self.detection_agent and FeedbackLoopEngine:
            self.feedback_engine = FeedbackLoopEngine(
                self.config, self.db, self.detection_agent,
                knowledge_base=self.knowledge_base
            )
            logger.info("feedback_engine_ready")

        # Threat Hunting Agent (requires "hunt" feature + module)
        self.hunt_agent = None
        if self._license_info.has_feature("hunt") and ThreatHuntAgent:
            self.hunt_agent = ThreatHuntAgent(
                self.config, self.db, self.enrichment.opensearch,
                knowledge_base=self.knowledge_base
            )
            logger.info("hunt_agent_ready")
        elif not self._license_info.has_feature("hunt"):
            logger.warning("hunt_agent_disabled_by_license")

        # Notification Service (requires "notifications_full" feature + module)
        self.notifications = None
        if self._license_info.has_feature("notifications_full") and NotificationService:
            self.notifications = NotificationService(self.config)
            logger.info("notification_service_ready")
        elif not self._license_info.has_feature("notifications_full"):
            logger.warning("notification_service_disabled_by_license")

        # SLA Manager
        self.sla_manager = SLAManager(
            self.config, self.db, self.notifications)
        logger.info("sla_manager_ready")

        # Metrics Calculator
        self.metrics_calculator = MetricsCalculator(self.db)
        logger.info("metrics_calculator_ready")

        # SOAR Engine (requires "soar" feature + module)
        self.soar_engine = None
        if self._license_info.has_feature("soar") and SOAREngine:
            self.soar_engine = SOAREngine(
                self.config, self.db, self.enrichment.wazuh, self.notifications,
                tenant_registry=self.tenant_registry)
            logger.info("soar_engine_ready")
        elif not self._license_info.has_feature("soar"):
            logger.warning("soar_engine_disabled_by_license")

        # Ticketing Service (requires "ticketing" feature + module)
        self.ticketing_service = None
        if self._license_info.has_feature("ticketing") and TicketingService:
            self.ticketing_service = TicketingService(
                self.config, self.db, self.notifications)
            logger.info("ticketing_service_ready")
        elif not self._license_info.has_feature("ticketing"):
            logger.warning("ticketing_service_disabled_by_license")

        # MITRE Coverage Analyzer
        self.mitre_analyzer = MITRECoverageAnalyzer(self.db)
        try:
            self.mitre_analyzer.compute_coverage()
            logger.info("mitre_coverage_computed_on_startup")
        except Exception as e:
            logger.warning("mitre_startup_coverage_failed", error=str(e))
        logger.info("mitre_analyzer_ready")

        # Incident Grouping Engine
        self.incident_engine = IncidentEngine(
            self.config, self.db, self.notifications, self.sla_manager,
            soar_engine=self.soar_engine,
            ticketing_service=self.ticketing_service)
        logger.info("incident_engine_ready")

        # WO-H9: parallel-triage dispatcher. The fetch loop enqueues enriched
        # alerts; a bounded pool of workers drains them in risk-priority order,
        # each triaging one alert under its own tenant context and then running
        # the per-decision downstream (incident grouping + SOAR eval). This
        # replaces the old inline/serial ``for`` in run_alert_loop.
        from src.agents.triage_dispatcher import TriageDispatcher
        triage_cfg = self.config.get("agents", {}).get("triage", {})
        max_workers = int(triage_cfg.get("max_workers", 4))
        # WO-H32 QA: in CLI mode every LLM call is a whole `claude` subprocess
        # (~40s, real memory) — don't spawn them concurrently; clamp to one
        # worker. Detected the same way the backend itself decides: the
        # anthropic provider's resolved ``sub_mode``. API mode (and
        # non-anthropic providers, which have no sub_mode) keep the configured
        # value. Multi-tenant resolves backends per tenant (legacy ``claude``
        # is None) so THIS clamp can't see them — there, WO-H37 clamps at the
        # backend instead: MultiProviderLLMBackend._sem_for serializes calls
        # through any CLI-resolved provider (1 permit), while the shared
        # worker pool keeps the configured size for API-mode tenants.
        _provider = getattr(
            getattr(self.triage_agent, "claude", None), "provider", None)
        if getattr(_provider, "sub_mode", "") == "cli" and max_workers > 1:
            logger.info("triage_concurrency_clamped_cli",
                        requested=max_workers, effective=1)
            max_workers = 1
        self.triage_dispatcher = TriageDispatcher(
            self.triage_agent, self.db,
            max_workers=max_workers,
            on_decision=self._process_decision_downstream,
            max_queue=int(triage_cfg.get("max_queue", 1000)),
        )
        logger.info("triage_dispatcher_ready", max_workers=max_workers)

        # Pipeline Health Monitor (optional)
        self.pipeline_monitor = None
        if PipelineHealthMonitor:
            self.pipeline_monitor = PipelineHealthMonitor(
                self.config, self.db, self.enrichment.opensearch,
                self.enrichment.wazuh, self.notifications)
            logger.info("pipeline_monitor_ready")

        # Alert Buffer: paid (durable, Postgres-backed) when available,
        # in-memory ring buffer on Community as a fallback so transient
        # OpenSearch failures don't drop alerts.
        self.alert_buffer = None
        if AlertBuffer:
            self.alert_buffer = AlertBuffer(self.db)
            self.enrichment.alert_buffer = self.alert_buffer
            buffer_kind = AlertBuffer.__name__
            logger.info("alert_buffer_ready", kind=buffer_kind,
                        durable=buffer_kind != "InMemoryAlertBuffer")

        # Natural Language Query Agent (requires "nl_query" feature + module)
        self.query_agent = None
        if self._license_info.has_feature("nl_query") and QueryAgent:
            self.query_agent = QueryAgent(
                self.config, self.db, self.enrichment.opensearch,
                self.enrichment.wazuh,
                knowledge_base=self.knowledge_base,
                tenant_registry=self.tenant_registry,
            )
            logger.info("query_agent_ready")
        elif not self._license_info.has_feature("nl_query"):
            logger.warning("query_agent_disabled_by_license")

        # Validate Claude backend now that agents are initialized
        self._check_claude_backend()

        # Enforce max_agents license limit
        if self._license_info.max_agents > 0:
            try:
                agents = self.enrichment.wazuh.get_all_agents()
                active = [a for a in agents if a.get("status") == "active"]
                if not self._license_info.check_agent_limit(len(active)):
                    logger.critical("license_agent_limit_exceeded",
                                    active_agents=len(active),
                                    max_agents=self._license_info.max_agents)
                    raise SystemExit(
                        f"License allows {self._license_info.max_agents} agents "
                        f"but {len(active)} are active. "
                        f"Contact SecureSleuths to upgrade your license."
                    )
                logger.info("license_agent_check_ok",
                            active=len(active),
                            limit=self._license_info.max_agents)
            except SystemExit:
                raise
            except Exception as e:
                logger.warning("license_agent_check_skipped", error=str(e))

        # Initialize API with dependencies
        init_api(
            db=self.db,
            enrichment=self.enrichment,
            triage_agent=self.triage_agent,
            detection_agent=self.detection_agent,
            feedback_engine=self.feedback_engine,
            hunt_agent=self.hunt_agent,
            query_agent=self.query_agent,
            notifications=self.notifications,
            config=self.config,
            license_info=self._license_info,
            ti_collector=self.ti_collector,
            sla_manager=self.sla_manager,
            metrics_calculator=self.metrics_calculator,
            soar_engine=self.soar_engine,
            mitre_analyzer=self.mitre_analyzer,
            ticketing_service=self.ticketing_service,
            knowledge_base=self.knowledge_base,
            pipeline_monitor=self.pipeline_monitor,
            alert_buffer=self.alert_buffer,
            tenant_registry=self.tenant_registry,
            incident_engine=self.incident_engine,
        )
        logger.info("api_initialized")

        # Scheduler for periodic tasks
        self.scheduler = BackgroundScheduler()

        logger.info("platform_initialized")

    def _load_config(self, config_path: str) -> dict:
        """Load and resolve configuration.

        Layering (lowest precedence first):
          1. Encrypted base — `config.enc` shipped in the build.
          2. Operator overlay — `config.yaml` written by the deployment
             wizard or hand-edited by the operator.
          3. Environment variables resolved into ${VAR} placeholders.

        Both files are optional; at least one must exist. When both are
        present, the YAML overlay deep-merges on top of the encrypted base
        so that wizard-produced settings take effect against a production
        (encrypted) build. Before v4.8.5 the encrypted file silently
        suppressed the YAML overlay, making every wizard write dead code.
        """
        enc_path = config_path.replace(".yaml", ".enc")
        config: dict = {}

        if os.path.exists(enc_path):
            config = self._decrypt_config(enc_path)

        if os.path.exists(config_path):
            try:
                with open(config_path) as f:
                    overlay = yaml.safe_load(f) or {}
            except yaml.YAMLError as e:
                logger.critical("config_yaml_syntax_error", error=str(e),
                                path=config_path)
                raise SystemExit(f"Config file {config_path} has invalid YAML: {e}")
            if config:
                config = self._deep_merge(config, overlay)
                logger.info("config_overlay_applied", overlay=config_path,
                            base=enc_path)
            else:
                config = overlay

        if not config:
            logger.critical("config_missing", enc_path=enc_path,
                            yaml_path=config_path)
            raise SystemExit(
                f"No configuration found. Expected one of: {enc_path} "
                f"(encrypted base) or {config_path} (plaintext overlay)."
            )

        # Resolve environment variables
        config = self._resolve_env_vars(config)
        self._warn_unresolved_env_vars(config)
        return config

    @staticmethod
    def _deep_merge(base: dict, overlay: dict) -> dict:
        """Recursively merge `overlay` into `base`, returning a new dict.

        Overlay scalars and lists replace base values outright; dicts merge
        key-by-key. Mirrors typical config-overlay semantics (Helm/Kustomize
        style) — operators expect setting one nested key in the YAML to
        override only that key, not blank out its siblings.
        """
        if not isinstance(base, dict) or not isinstance(overlay, dict):
            return overlay
        merged = dict(base)
        for key, overlay_val in overlay.items():
            base_val = merged.get(key)
            if isinstance(base_val, dict) and isinstance(overlay_val, dict):
                merged[key] = AISocPlatform._deep_merge(base_val, overlay_val)
            else:
                merged[key] = overlay_val
        return merged

    def _decrypt_config(self, enc_path: str) -> dict:
        """Decrypt an encrypted config file."""
        import base64
        import json
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes

        _CONFIG_SALT = b"dhruva-config-v4.5"
        _PLATFORM_ANCHOR = b"YGFqaFqnOyHtBSl0n/lK0vgBSziBL73VXd73GQtvTI8="

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=_CONFIG_SALT,
            info=b"config-encryption",
        )
        raw_key = hkdf.derive(_PLATFORM_ANCHOR)
        key = base64.urlsafe_b64encode(raw_key)
        fernet = Fernet(key)

        try:
            with open(enc_path, "rb") as f:
                ciphertext = f.read()
            plaintext = fernet.decrypt(ciphertext)
            return json.loads(plaintext)
        except Exception as e:
            logger.critical("config_decrypt_failed", path=enc_path, error=str(e))
            raise SystemExit(
                f"Failed to decrypt config {enc_path}. "
                f"Build may be corrupted — contact SecureSleuths."
            )

    def _warn_unresolved_env_vars(self, obj, path=""):
        """Log warnings for any ${VAR} patterns that were not resolved."""
        if isinstance(obj, str):
            if obj.startswith("${") and obj.endswith("}"):
                logger.warning("unresolved_env_var", path=path, var=obj)
        elif isinstance(obj, dict):
            for k, v in obj.items():
                self._warn_unresolved_env_vars(
                    v, f"{path}.{k}" if path else k)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                self._warn_unresolved_env_vars(v, f"{path}[{i}]")

    def _resolve_env_vars(self, obj):
        """Recursively resolve ${ENV_VAR} patterns."""
        if isinstance(obj, str):
            if obj.startswith("${") and obj.endswith("}"):
                env_key = obj[2:-1]
                return os.environ.get(env_key, obj)
            return obj
        elif isinstance(obj, dict):
            return {k: self._resolve_env_vars(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._resolve_env_vars(i) for i in obj]
        return obj

    def _validate_credentials(self):
        """Warn on insecure default credentials at startup."""
        warnings = []
        wazuh_pw = self.config.get("wazuh", {}).get("api", {}).get("password", "")
        if wazuh_pw.lower() in self.INSECURE_DEFAULTS:
            warnings.append("WAZUH_API_PASSWORD is a default/weak value")

        os_pw = self.config.get("opensearch", {}).get("password", "")
        if os_pw.lower() in self.INSECURE_DEFAULTS:
            warnings.append("OPENSEARCH_PASSWORD is a default/weak value")

        jwt_secret = self.config.get("api", {}).get("auth", {}).get("jwt_secret", "")
        if not jwt_secret or jwt_secret in self.INSECURE_DEFAULTS or len(jwt_secret) < 32:
            warnings.append("JWT_SECRET is empty, weak, or less than 32 characters")

        soc_pw = os.getenv("SOC_ADMIN_PASSWORD", "")
        if not soc_pw or soc_pw.lower() in self.INSECURE_DEFAULTS:
            warnings.append("SOC_ADMIN_PASSWORD is not set or uses a default value")

        # TLS verification checks
        dev_mode = os.environ.get("DEV_MODE", "").lower() in ("1", "true", "yes")
        if not dev_mode:
            wazuh_ssl = self.config.get("wazuh", {}).get("api", {}).get("verify_ssl", True)
            if not wazuh_ssl:
                warnings.append(
                    "WAZUH verify_ssl is disabled. TLS verification should be "
                    "enabled in production. Set DEV_MODE=true to suppress.")
            os_ssl = self.config.get("opensearch", {}).get("verify_ssl", True)
            if not os_ssl:
                warnings.append(
                    "OPENSEARCH verify_ssl is disabled. TLS verification should "
                    "be enabled in production. Set DEV_MODE=true to suppress.")

        if warnings:
            for w in warnings:
                logger.warning("insecure_credential", issue=w)
            if not dev_mode:
                logger.critical(
                    "credential_security_check",
                    message=f"{len(warnings)} insecure credential(s) detected. "
                            "Refusing to start in production mode. "
                            "Fix credentials in .env or set DEV_MODE=true.",
                )
                raise SystemExit(
                    f"FATAL: {len(warnings)} insecure credential(s) detected. "
                    "Update .env or set DEV_MODE=true to bypass."
                )
            else:
                logger.warning(
                    "credential_security_check",
                    message=f"{len(warnings)} insecure credential(s) detected. "
                            "Update .env before deploying to production. "
                            "(DEV_MODE=true — continuing anyway)",
                )

    def _validate_license(self):
        """Validate the platform license at startup.

        If no license file is found, the platform runs as Community edition
        (free forever, no key required).  A valid signed license upgrades
        the tier to Team or Enterprise.
        """
        from src.licensing import (
            LicenseValidator, LicenseError, LicenseFileNotFoundError,
            LicenseInfo, TIER_PRESETS,
        )

        license_path = self.config.get("licensing", {}).get(
            "license_file", "license.key"
        )

        try:
            validator = LicenseValidator(license_path)
            self._license_info = validator.validate()

            days_left = self._license_info.days_remaining
            logger.info(
                "license_valid",
                client=self._license_info.client_name,
                client_id=self._license_info.client_id,
                tier=self._license_info.tier,
                expires=self._license_info.expires_at.isoformat(),
                days_remaining=days_left,
            )

            if days_left <= 14:
                logger.warning(
                    "license_expiring_soon",
                    days_remaining=days_left,
                    message=f"License expires in {days_left} days. "
                            f"Contact SecureSleuths to renew.",
                )

        except LicenseFileNotFoundError:
            # No license file — run as Community edition (free forever)
            defaults = TIER_PRESETS["community"]
            self._license_info = LicenseInfo(
                client_name="Community Edition",
                client_id="community",
                issued_at=datetime.now(timezone.utc),
                expires_at=datetime(2099, 12, 31, tzinfo=timezone.utc),
                schema_version=2,
                tier="community",
                features=defaults["features"],
                max_agents=defaults["max_agents"],
                max_users=defaults["max_users"],
                max_triage_daily=defaults["max_triage_daily"],
                max_nl_queries_daily=defaults["max_nl_queries_daily"],
                dashboard_tabs=defaults["dashboard_tabs"],
                audit_retention_days=defaults["audit_retention_days"],
                multi_tenant=defaults["multi_tenant"],
                custom_branding=defaults["custom_branding"],
                active_response_actions=defaults["active_response_actions"],
                notifications=defaults["notifications"],
            )
            logger.info(
                "community_edition",
                message="No license file found — running as Community edition (free)",
                tier="community",
                max_users=defaults["max_users"],
                features=len(defaults["features"]),
            )

        except LicenseError as e:
            logger.critical("license_validation_failed", error=str(e))
            raise SystemExit(str(e))

    def _seed_default_tenant(self):
        """Create default tenant from existing config if none exist.

        This handles the single-tenant → multi-tenant upgrade path.
        Existing installations get a default tenant auto-created from their
        current config.yaml and license client_id.
        """
        # Tenant seeding runs before any tenant context exists — bypass fail-closed filter
        from src.database.store import _tenant_ctx, _CROSS_TENANT
        _ctx_token = _tenant_ctx.set(_CROSS_TENANT)
        try:
            if self.db.tenant_exists():
                # Tenant already exists — still need to set client_id in config
                # so agents (triage, detection, etc.) tag new rows correctly.
                # Use license client_id to find the right tenant (not first alphabetically)
                license_client_id = getattr(self._license_info, "client_id", None)
                if license_client_id:
                    tenant = self.db.get_tenant(license_client_id)
                    if tenant:
                        tenant_id = tenant["id"]
                    else:
                        tenant_id = self.db.get_active_tenants()[0]["id"]
                else:
                    tenant_id = self.db.get_active_tenants()[0]["id"]
                self.config["client_id"] = tenant_id
                # Backfill any rows that still have NULL client_id
                # (happens when migration 7 ran before tenant was seeded)
                self.db.backfill_null_client_ids(tenant_id)
                return

            from src.database.tenant_crypto import encrypt_config

            # Build tenant config from existing flat config
            tenant_config = {}
            if "wazuh" in self.config:
                tenant_config["wazuh"] = self.config["wazuh"]
            if "opensearch" in self.config:
                tenant_config["opensearch"] = self.config["opensearch"]
            if "notifications" in self.config:
                tenant_config["notifications"] = self.config["notifications"]
            # Claude config
            agents_cfg = self.config.get("agents", {})
            if agents_cfg.get("claude_api_key"):
                tenant_config["claude"] = {
                    "mode": "api",
                    "api_key": agents_cfg["claude_api_key"],
                }
            else:
                tenant_config["claude"] = {"mode": "cli"}

            # Use license client_id as tenant ID, with env overrides for
            # multi-tenant deployments where the first tenant name matters
            tenant_id = getattr(self._license_info, "client_id", "default")
            tenant_name = (os.getenv("FIRST_TENANT_NAME")
                           or getattr(self._license_info, "client_name", "Default Tenant"))
            slug = (os.getenv("FIRST_TENANT_SLUG")
                    or tenant_id.lower().replace(" ", "-").replace("_", "-")[:50])

            now = datetime.now(timezone.utc).isoformat()
            self.db.save_tenant({
                "id": tenant_id,
                "name": tenant_name,
                "slug": slug,
                "config_encrypted": encrypt_config(tenant_config),
                "active": 1,
                "created_at": now,
                "updated_at": now,
            })

            # Associate existing admin user with this tenant
            admin_user = os.getenv("SOC_ADMIN_USER", "admin")
            self.db.set_user_tenant(admin_user, tenant_id)

            # Store tenant ID in config so agents tag new records correctly
            self.config["client_id"] = tenant_id
            self.config["_default_tenant_id"] = tenant_id

            logger.info("default_tenant_seeded",
                         tenant_id=tenant_id,
                         tenant_name=tenant_name)

        except Exception as e:
            logger.warning("default_tenant_seed_failed", error=str(e))
        finally:
            _tenant_ctx.reset(_ctx_token)

    def _check_llm_health_periodic(self):
        """WO-H46-c: alert when triage is failing closed instead of working.

        A dead LLM backend is invisible in ordinary metrics: triage fails
        CLOSED, so every un-analyzed alert is still written as an escalated
        ``needs_investigation`` decision. The queue looks BUSY, not BROKEN. On
        one install that masquerade ran long enough to bank 1398 un-analyzed
        rows — 20% of its decision history — before anyone noticed.

        This turns that silence into a periodic CRITICAL log line. It is
        deliberately observation-only: it never stops the platform, because
        ingestion, enrichment, correlation and the deterministic
        always-escalate rules all keep working without an LLM.
        """
        try:
            stats = self.db.get_llm_failure_rate(hours=1)
        except Exception as e:  # noqa: BLE001 — a health probe must not crash the scheduler
            logger.warning("llm_health_check_failed", error=str(e))
            return

        if stats["total"] == 0:
            return  # nothing triaged this hour; nothing to say

        if stats["failed"] == stats["total"]:
            logger.critical(
                "llm_backend_down",
                failed=stats["failed"], total=stats["total"],
                message="EVERY triage call in the last hour failed. Alerts are "
                        "being escalated WITHOUT analysis — the queue will look "
                        "busy while nothing is actually being triaged.",
                remediation="Check the LLM backend: expired `claude login` "
                            "session, empty/invalid ANTHROPIC_API_KEY, or a "
                            "provider outage.")
        elif stats["failure_rate"] >= 0.25:
            logger.error(
                "llm_backend_degraded",
                failed=stats["failed"], total=stats["total"],
                failure_rate=round(stats["failure_rate"], 3),
                message="A significant share of triage calls are failing; those "
                        "alerts were escalated without analysis.")
        else:
            logger.info("llm_health_ok",
                        failed=stats["failed"], total=stats["total"])

    def _check_license_periodic(self):
        """Periodic license expiry check. Shuts down platform if expired."""
        from src.licensing import LicenseValidator, LicenseExpiredError, LicenseError

        license_path = self.config.get("licensing", {}).get(
            "license_file", "license.key"
        )

        try:
            validator = LicenseValidator(license_path)
            info = validator.validate()
            days_left = info.days_remaining

            if days_left <= 7:
                logger.warning("license_expiring_soon",
                               days_remaining=days_left)
            else:
                logger.info("license_check_ok", days_remaining=days_left)

        except LicenseExpiredError:
            logger.critical(
                "license_expired_shutdown",
                message="Platform license has expired. Initiating shutdown. "
                        "Contact SecureSleuths (info@securesleuths.com) to renew.",
            )
            self.running = False
            self._shutdown_event.set()

        except LicenseError as e:
            logger.critical("license_check_failed_shutdown", error=str(e))
            self.running = False
            self._shutdown_event.set()

    def _check_infrastructure_services(self):
        """Validate connectivity to Wazuh and OpenSearch at startup.

        Both are non-fatal — the platform starts in degraded mode and
        retries on each polling cycle.
        """
        degraded = []

        # Check OpenSearch (non-fatal)
        try:
            info = self.enrichment.opensearch.client.info()
            logger.info("health_check_opensearch_ok",
                        version=info.get("version", {}).get("number", "?"))
        except Exception as e:
            degraded.append(f"OpenSearch: {e}")
            logger.warning("health_check_opensearch_failed", error=str(e))

        # Check Wazuh API (non-fatal)
        try:
            self.enrichment.wazuh._authenticate()
            logger.info("health_check_wazuh_ok")
        except Exception as e:
            degraded.append(f"Wazuh API: {e}")
            logger.warning("health_check_wazuh_failed", error=str(e))

        if degraded:
            logger.warning("startup_degraded_mode",
                           unavailable=degraded, count=len(degraded),
                           message="Platform starting in degraded mode — "
                                   "data services unavailable, will retry on each cycle")

        logger.info("startup_health_checks_passed",
                     degraded=len(degraded) > 0)

    def _check_claude_backend(self):
        """Validate Claude backend connectivity. Fatal if unreachable."""
        try:
            # In multi-tenant mode, triage_agent.claude is None (resolved per-request)
            if self.triage_agent.claude is None:
                logger.info("health_check_claude_ok", mode="multi-tenant")
                return
            if self.triage_agent.claude.mode == "api":
                if not getattr(self.triage_agent.claude, "client", None):
                    raise SystemExit(
                        "Claude API client not initialized. "
                        "Check ANTHROPIC_API_KEY in .env.")
                logger.info("health_check_claude_ok", mode="api")
            else:
                logger.info("health_check_claude_ok", mode="cli")
        except SystemExit:
            raise
        except Exception as e:
            logger.critical("health_check_claude_failed", error=str(e))
            raise SystemExit(f"Claude health check failed: {e}")

    def _setup_signal_handlers(self):
        """Handle graceful shutdown."""
        def handler(signum, frame):
            logger.info("shutdown_signal_received", signal=signum)
            self._shutdown_event.set()
            self.running = False

        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)

    def _leader_job(self, job_id: str, fn):
        """WO-H9 leader election wrapper for a scheduled job.

        Guards ``fn`` with a per-job ``pg_try_advisory_lock`` so that with N
        replicas/processes sharing one Postgres, EXACTLY ONE runs the job at a
        time. A non-leader SKIPS the cycle (it does NOT block then double-run) —
        the whole point is that a second replica must not, e.g., fire an
        active-response block or a TI-collection write twice.

        Applied only to jobs whose side effects are SHARED (DB / OpenSearch /
        Wazuh / external). Per-process, in-memory jobs (guidance reload, license
        state refresh) are intentionally NOT wrapped — every replica needs to
        run those locally.
        """
        def _wrapped():
            try:
                with self.db.job_lock(f"dhruva:job:{job_id}") as is_leader:
                    if not is_leader:
                        logger.info("scheduled_job_skipped_not_leader",
                                    job=job_id)
                        return
                    fn()
            except Exception as e:
                logger.error("scheduled_job_failed", job=job_id,
                             error=str(e))
        return _wrapped

    def _schedule_periodic_tasks(self):
        """Schedule background tasks."""
        agents_cfg = self.config.get("agents", {})

        # Detection analysis cycle (requires detection agent)
        det_cfg = agents_cfg.get("detection", {})
        if det_cfg.get("enabled", True) and self.detection_agent:
            interval = det_cfg.get("run_interval_minutes", 60)
            self.scheduler.add_job(
                self._leader_job('detection_cycle', self._run_detection_cycle),
                'interval',
                minutes=interval,
                id='detection_cycle',
                name='Detection Engineering Cycle',
                max_instances=1, coalesce=True,
            )
            logger.info("detection_cycle_scheduled", interval_min=interval)

        # Feedback loop cycle (requires feedback engine)
        fb_cfg = self.config.get("feedback", {})
        if fb_cfg.get("enabled", True) and self.feedback_engine:
            interval = fb_cfg.get("pattern_analysis_interval_hours", 4)
            self.scheduler.add_job(
                self._leader_job('feedback_cycle', self._run_feedback_cycle),
                'interval',
                hours=interval,
                id='feedback_cycle',
                name='Feedback Loop Cycle',
                max_instances=1, coalesce=True,
            )
            logger.info("feedback_cycle_scheduled", interval_hrs=interval)

        # Guidance reload (pick up file changes)
        # WO-H9: intentionally NOT leader-gated — this mutates per-process
        # in-memory guidance, so EVERY replica must reload its own copy.
        self.scheduler.add_job(
            self.guidance.reload,
            'interval',
            minutes=15,
            id='guidance_reload',
            name='Guidance Reload'
        )

        # Threat hunt cycle (requires hunt agent)
        hunt_cfg = agents_cfg.get("hunt", {})
        if hunt_cfg.get("enabled", True) and self.hunt_agent:
            hunt_interval = hunt_cfg.get("run_interval_hours", 6)
            self.scheduler.add_job(
                self._leader_job('hunt_cycle', self._run_hunt_cycle),
                'interval',
                hours=hunt_interval,
                id='hunt_cycle',
                name='Threat Hunt Cycle',
                max_instances=1, coalesce=True,
            )
            logger.info("hunt_cycle_scheduled", interval_hrs=hunt_interval)

        # Behavioral baseline computation (requires baselines feature)
        if self._license_info.has_feature("baselines"):
            baseline_interval = self.config.get("enrichment", {}).get(
                "historical", {}
            ).get("baseline_refresh_hours", 6)
            self.scheduler.add_job(
                self._leader_job('baseline_computation', self._compute_baselines),
                'interval',
                hours=baseline_interval,
                id='baseline_computation',
                name='Behavioral Baseline Computation',
                max_instances=1, coalesce=True,
            )
            logger.info("baseline_computation_scheduled", interval_hrs=baseline_interval)

        # Daily cleanup of old processed alert records
        def _safe_cleanup():
            try:
                with self.db.cross_tenant():
                    self.db.cleanup_old_processed(days=7)
            except Exception as e:
                logger.warning("processed_cleanup_failed", error=str(e))

        self.scheduler.add_job(
            self._leader_job('processed_cleanup', _safe_cleanup),
            'interval',
            hours=24,
            id='processed_cleanup',
            name='Processed Alerts Cleanup'
        )

        # WO-H28: daily retention prune for ever-growing tables
        # (operational_metrics, agent_decisions, decision_audit_trail,
        # soar_executions, llm_usage_metrics, webhook_requests, budget
        # reservations). Windows are config-driven (retention.days.*,
        # 0 = keep forever); deletes run in batches; leader-gated so only
        # one replica prunes.
        ret_cfg = self.config.get("retention", {}) or {}
        if ret_cfg.get("enabled", True):
            def _retention_prune():
                try:
                    with self.db.cross_tenant():
                        results = self.db.prune_expired_rows(
                            ret_cfg.get("days", {}) or {},
                            batch_size=int(ret_cfg.get("batch_size", 10000)))
                    logger.info("retention_prune_cycle_completed",
                                deleted={t: n for t, n in results.items() if n})
                except Exception as e:
                    logger.error("retention_prune_cycle_failed", error=str(e))
            self.scheduler.add_job(
                self._leader_job('retention_prune', _retention_prune),
                'cron',
                hour=int(ret_cfg.get("run_hour", 3)),
                minute=15,
                id='retention_prune',
                name='Retention Prune',
                max_instances=1, coalesce=True,
            )
            logger.info("retention_prune_scheduled",
                        run_hour=int(ret_cfg.get("run_hour", 3)))

        # License expiry check
        license_check_hrs = self.config.get("licensing", {}).get(
            "check_interval_hours", 24
        )
        # WO-H9: NOT leader-gated — each replica must re-check its own license
        # state (per-process ``_license_info``), so all replicas run this.
        self.scheduler.add_job(
            self._check_license_periodic,
            'interval',
            hours=license_check_hrs,
            id='license_check',
            name='License Expiry Check'
        )

        # WO-H46-c: LLM-backend health. Observation-only — never stops the
        # platform, because a dead LLM does not stop ingestion/enrichment.
        # Frequent (default 15 min) because the failure mode is silent: triage
        # fails closed, so a broken backend reads as a busy escalation queue.
        llm_health_mins = self.config.get("health", {}).get(
            "llm_check_interval_minutes", 15
        )
        self.scheduler.add_job(
            self._check_llm_health_periodic,
            'interval',
            minutes=llm_health_mins,
            id='llm_health_check',
            name='LLM Backend Health Check'
        )

        # Threat intelligence feed collection
        if self.ti_collector:
            ti_interval = self.config.get("threat_intel", {}).get(
                "collect_interval_minutes", 30
            )
            self.scheduler.add_job(
                self._leader_job('ti_collection', self._run_ti_collection),
                'interval',
                minutes=ti_interval,
                id='ti_collection',
                name='Threat Intel Feed Collection'
            )
            # Daily IOC expiry cleanup — cross-tenant (TI is shared)
            def _ti_cleanup():
                with self.db.cross_tenant():
                    self.ti_collector.cleanup_expired()
            self.scheduler.add_job(
                self._leader_job('ti_ioc_cleanup', _ti_cleanup),
                'interval',
                hours=24,
                id='ti_ioc_cleanup',
                name='TI IOC Expiry Cleanup'
            )
            logger.info("ti_collection_scheduled", interval_min=ti_interval)

        # SLA breach checker (requires sla feature) — per-tenant
        if self._license_info.has_feature("sla"):
            def _sla_check():
                for tid in self._get_active_tenant_ids():
                    try:
                        self.db.set_tenant(tid)
                        self.sla_manager.check_sla_breaches()
                    except Exception as e:
                        logger.error("sla_breach_check_failed", tenant=tid, error=str(e))
            self.scheduler.add_job(
                self._leader_job('sla_breach_check', _sla_check),
                'interval',
                minutes=5,
                id='sla_breach_check',
                name='SLA Breach Checker'
            )
            logger.info("sla_breach_checker_scheduled")

        # Daily MTT metrics rollup (1 AM UTC) — per-tenant
        def _mtt_rollup():
            for tid in self._get_active_tenant_ids():
                try:
                    self.db.set_tenant(tid)
                    self.metrics_calculator.compute_daily_rollup()
                except Exception as e:
                    logger.error("mtt_rollup_failed", tenant=tid, error=str(e))
        self.scheduler.add_job(
            self._leader_job('daily_mtt_rollup', _mtt_rollup),
            'cron',
            hour=1,
            minute=0,
            id='daily_mtt_rollup',
            name='Daily MTT Metrics Rollup'
        )
        logger.info("daily_mtt_rollup_scheduled")

        # Daily MITRE coverage computation (2 AM UTC) — per-tenant
        def _mitre_coverage():
            for tid in self._get_active_tenant_ids():
                try:
                    self.db.set_tenant(tid)
                    self.mitre_analyzer.compute_coverage()
                except Exception as e:
                    logger.error("mitre_coverage_failed", tenant=tid, error=str(e))
        self.scheduler.add_job(
            self._leader_job('daily_mitre_coverage', _mitre_coverage),
            'cron',
            hour=2,
            minute=0,
            id='daily_mitre_coverage',
            name='Daily MITRE Coverage Computation'
        )
        logger.info("daily_mitre_coverage_scheduled")

        # Knowledge Base: re-index guidance docs — cross-tenant (guidance is shared)
        if self.knowledge_base and self.knowledge_base.enabled:
            def _kb_reindex():
                with self.db.cross_tenant():
                    self.knowledge_base.index_guidance_docs(self.guidance)
            self.scheduler.add_job(
                self._leader_job('kb_guidance_reindex', _kb_reindex),
                'interval',
                minutes=15,
                id='kb_guidance_reindex',
                name='KB Guidance Re-index'
            )

        # Ticketing: sync polling and retry — per-tenant
        if self.ticketing_service and self.ticketing_service.enabled:
            sync_min = self.ticketing_service.sync_interval_minutes
            def _ticketing_sync():
                for tid in self._get_active_tenant_ids():
                    try:
                        self.db.set_tenant(tid)
                        self.ticketing_service.sync_poll()
                    except Exception as e:
                        logger.error("ticketing_sync_failed", tenant=tid, error=str(e))
            def _ticketing_retry():
                for tid in self._get_active_tenant_ids():
                    try:
                        self.db.set_tenant(tid)
                        self.ticketing_service.retry_failed()
                    except Exception as e:
                        logger.error("ticketing_retry_failed", tenant=tid, error=str(e))
            self.scheduler.add_job(
                self._leader_job('ticketing_sync_poll', _ticketing_sync),
                'interval',
                minutes=sync_min,
                id='ticketing_sync_poll',
                name='Ticketing Sync Poll'
            )
            self.scheduler.add_job(
                self._leader_job('ticketing_retry_failed', _ticketing_retry),
                'interval',
                minutes=15,
                id='ticketing_retry_failed',
                name='Ticketing Retry Failed'
            )
            logger.info("ticketing_scheduler_ready",
                        sync_interval=sync_min)

        # Pipeline health monitoring (requires pipeline_health feature + module)
        pipeline_cfg = self.config.get("pipeline", {})
        if pipeline_cfg.get("enabled", True) and self._license_info.has_feature("pipeline_health") and self.pipeline_monitor:
            check_interval = pipeline_cfg.get("check_interval_minutes", 5)
            self.scheduler.add_job(
                self._leader_job('pipeline_health', self._run_pipeline_health_checks),
                'interval',
                minutes=check_interval,
                id='pipeline_health',
                name='Pipeline Health Monitoring',
                max_instances=1, coalesce=True,
            )
            logger.info("pipeline_health_scheduled", interval_min=check_interval)

        # Alert buffer flush (every 60 seconds) — only if module is present
        if self.alert_buffer:
            self.scheduler.add_job(
                self._leader_job('alert_buffer_flush', self._flush_alert_buffer),
                'interval',
                seconds=60,
                id='alert_buffer_flush',
                name='Alert Buffer Flush',
                max_instances=1, coalesce=True,
            )

        # WO-H32: triage queue depth/lag sampler (every 60 seconds). The
        # enqueue-time sample in the alert loop only fires when a batch is
        # queued, so it never shows the backlog DRAINING (or stalling) between
        # fetch cycles — this samples continuously.
        self.scheduler.add_job(
            self._leader_job('triage_queue_sampler', self._sample_triage_queue),
            'interval',
            seconds=60,
            id='triage_queue_sampler',
            name='Triage Queue Depth/Lag Sampler',
            max_instances=1, coalesce=True,
        )

        # Analyst workload monitoring (every 30 minutes)
        self.scheduler.add_job(
            self._leader_job('analyst_workload_check', self._check_analyst_workload),
            'interval',
            minutes=30,
            id='analyst_workload_check',
            name='Analyst Workload Monitor',
            max_instances=1, coalesce=True,
        )

        self.scheduler.start()

    def _get_active_tenant_ids(self) -> list[str]:
        """Get all active tenant IDs for per-tenant scheduled jobs."""
        try:
            with self.db.cross_tenant():
                tenants = self.db.get_active_tenants()
            return [t["id"] for t in tenants]
        except Exception:
            # Fallback: use the default tenant from config
            default = self.config.get("client_id")
            return [default] if default else []

    def _run_pipeline_health_checks(self):
        """Wrapper for pipeline health monitoring."""
        try:
            with self.db.cross_tenant():
                self.pipeline_monitor.check_log_source_heartbeats()
                self.pipeline_monitor.check_eps_anomaly()
                self.pipeline_monitor.check_parser_failures()
        except Exception as e:
            logger.error("pipeline_health_check_failed", error=str(e))

    def _flush_alert_buffer(self):
        """Flush buffered alerts to OpenSearch when available."""
        try:
            with self.db.cross_tenant():
                count = self.alert_buffer.get_buffer_count()
                if count > 0 and self.enrichment.opensearch.is_available():
                    flushed = self.alert_buffer.flush_to_opensearch(
                        self.enrichment.opensearch)
                    if flushed > 0:
                        logger.info("alert_buffer_flushed", count=flushed)
        except Exception as e:
            logger.error("alert_buffer_flush_failed", error=str(e))

    def _sample_triage_queue(self):
        """WO-H32: record triage queue depth + lag for every active tenant.

        The dispatcher queue is process-global (all tenants share the worker
        pool), so each tenant's dashboard sees the shared pipeline's health —
        the same semantics as the enqueue-time ``triage_queue_depth`` sample.
        ``triage_queue_lag_seconds`` is the peak time an alert WAITED in the
        queue during the sample window: rising lag with steady depth = the
        workers can't keep up with the arrival rate."""
        try:
            m = self.triage_dispatcher.queue_metrics()
        except Exception as e:
            logger.error("triage_queue_sample_failed", error=str(e))
            return
        for tid in self._get_active_tenant_ids():
            try:
                self.db.set_tenant(tid)
                self.db.record_metric("triage_queue_depth", m["depth"],
                                      {"tenant": tid, "sampled": True})
                self.db.record_metric(
                    "triage_queue_lag_seconds", m["max_wait_seconds"],
                    {"tenant": tid,
                     "last_wait_seconds": m["last_wait_seconds"]})
            except Exception as e:
                logger.warning("triage_queue_sample_write_failed",
                               tenant=tid, error=str(e))

    def _check_analyst_workload(self):
        """Check analyst workload per tenant."""
        for tenant_id in self._get_active_tenant_ids():
            try:
                self.db.set_tenant(tenant_id)
                max_per = self.config.get("incidents", {}).get("max_per_analyst", 15)
                overloaded = self.metrics_calculator.check_analyst_workload(max_per)
                for analyst in overloaded:
                    if analyst["is_overloaded"] and self.notifications:
                        self.notifications.notify_workload_warning(
                            analyst["analyst"], analyst)
            except TenantConfigUnavailable:
                logger.error("tenant_skipped_config_unavailable",
                             tenant_id=tenant_id, phase="analyst_workload")
                continue
            except Exception as e:
                logger.error("analyst_workload_check_failed",
                             tenant=tenant_id, error=str(e))

    def _run_detection_cycle(self):
        """Wrapper for scheduled detection analysis — runs per tenant."""
        for tenant_id in self._get_active_tenant_ids():
            try:
                self.db.set_tenant(tenant_id)
                proposals = self.detection_agent.run_analysis_cycle()
                if proposals:
                    logger.info("detection_cycle_proposals",
                                 tenant=tenant_id, count=len(proposals))
            except TenantConfigUnavailable:
                logger.error("tenant_skipped_config_unavailable",
                             tenant_id=tenant_id, phase="detection_cycle")
                continue
            except Exception as e:
                logger.error("detection_cycle_failed",
                             tenant=tenant_id, error=str(e))

    def _run_hunt_cycle(self):
        """Wrapper for scheduled threat hunt cycle — runs per tenant."""
        for tenant_id in self._get_active_tenant_ids():
            try:
                self.db.set_tenant(tenant_id)
                results = self.hunt_agent.run_hunt_cycle()
                logger.info("hunt_cycle_results",
                             tenant=tenant_id,
                             hypotheses=results.get("hypotheses_generated", 0),
                             hits=results.get("findings_with_results", 0))
            except TenantConfigUnavailable:
                logger.error("tenant_skipped_config_unavailable",
                             tenant_id=tenant_id, phase="hunt_cycle")
                continue
            except Exception as e:
                logger.error("hunt_cycle_failed",
                             tenant=tenant_id, error=str(e))

    def _compute_baselines(self):
        """Wrapper for scheduled baseline computation — runs per tenant."""
        for tenant_id in self._get_active_tenant_ids():
            try:
                self.db.set_tenant(tenant_id)
                stats = self.enrichment.compute_baselines()
                logger.info("baseline_computation_results",
                             tenant=tenant_id,
                             baselines_saved=stats.get("baselines_saved", 0))
            except TenantConfigUnavailable:
                logger.error("tenant_skipped_config_unavailable",
                             tenant_id=tenant_id, phase="baseline_computation")
                continue
            except Exception as e:
                logger.error("baseline_computation_failed",
                             tenant=tenant_id, error=str(e))

    def _run_feedback_cycle(self):
        """Wrapper for scheduled feedback analysis — runs per tenant."""
        for tenant_id in self._get_active_tenant_ids():
            try:
                self.db.set_tenant(tenant_id)
                results = self.feedback_engine.run_feedback_cycle()
                logger.info("feedback_cycle_results",
                             tenant=tenant_id,
                             overrides=len(results.get("override_patterns", [])),
                             fp_patterns=len(results.get("fp_patterns", [])))
            except TenantConfigUnavailable:
                logger.error("tenant_skipped_config_unavailable",
                             tenant_id=tenant_id, phase="feedback_cycle")
                continue
            except Exception as e:
                logger.error("feedback_cycle_failed",
                             tenant=tenant_id, error=str(e))

    def _run_ti_collection(self):
        """Wrapper for TI feed collection — global (feeds are shared)."""
        try:
            with self.db.cross_tenant():
                results = self.ti_collector.collect_all()
                logger.info("ti_collection_results",
                             feeds_collected=results.get("feeds_collected", 0),
                             iocs=results.get("total_iocs", 0))
                self.db.record_metric("ti_iocs_collected",
                                      results.get("total_iocs", 0),
                                      results)
        except Exception as e:
            logger.error("ti_collection_failed", error=str(e))

    def _get_alert_loop_tenants(self) -> list[str]:
        """Return list of tenant IDs to poll for alerts.

        In multi-tenant mode, iterates all active tenants.
        In single-tenant mode, uses the configured default tenant.
        """
        from src.database.store import is_multi_tenant
        if is_multi_tenant():
            try:
                return self.tenant_registry.get_active_tenant_ids()
            except Exception:
                pass
        default_tenant = self.config.get("client_id")
        return [default_tenant] if default_tenant else ["default"]

    def _process_decision_downstream(self, decision, alert: dict, tenant_id: str):
        """WO-H9 per-decision downstream — runs on a triage WORKER thread under
        the item's tenant context (the dispatcher set it before calling us).

        Mirrors the post-triage work the old inline loop did per batch, but for
        one decision: incident grouping, SOAR evaluation, and the ``triage_call``
        metric. Active-response inside SOAR remains human-approved and is now
        double-fire-safe (see src/soar/engine.py serialized_section guard).
        """
        # Belt-and-suspenders: re-pin tenant context on this worker thread.
        self.db.set_tenant(tenant_id)
        try:
            self.db.record_metric("triage_call", 1,
                                  {"alert_id": decision.alert_id})
        except Exception:
            pass

        # Incident grouping (single-decision batch — grouping is incremental,
        # so per-alert is correct, just not batched).
        try:
            self.incident_engine.process_decisions([decision], [alert])
        except Exception as e:
            logger.warning("incident_grouping_failed",
                           alert_id=decision.alert_id, error=str(e)[:200])

        # SOAR playbook evaluation for actionable verdicts.
        if self.soar_engine and decision.verdict in (
                "true_positive", "needs_investigation"):
            try:
                inc_id = None
                try:
                    row = self.db._get_conn().execute(
                        "SELECT incident_id FROM incident_alerts "
                        "WHERE decision_id = %s LIMIT 1",
                        (decision.id,)).fetchone()
                    if row:
                        inc_id = row["incident_id"]
                except Exception:
                    pass
                self.soar_engine.evaluate(decision, alert, incident_id=inc_id)
            except Exception as e:
                logger.warning("soar_evaluate_failed",
                               alert_id=decision.alert_id, error=str(e)[:200])

    def run_alert_loop(self):
        """
        Main alert FETCH loop (producer).

        Continuously polls Wazuh/OpenSearch for new alerts, enriches them, and
        ENQUEUES the risk-worthy ones onto the triage dispatcher. Triage itself
        (and its downstream incident/SOAR work) runs on the dispatcher's bounded
        worker pool — decoupled from this loop so a slow ~40s triage can't stall
        fetching and a critical alert is triaged ahead of low-value noise.

        WO-H9 leader election: the per-cycle body is guarded by a
        ``pg_try_advisory_lock`` so that with multiple replicas sharing one
        Postgres, EXACTLY ONE actually fetches + enqueues (and therefore drives
        active response). A standby replica keeps looping and simply skips the
        body until it wins the lock (e.g. when the leader dies) — no
        block-then-double-run.

        In multi-tenant mode, iterates all active tenants each cycle.
        """
        poll_interval = self.config.get("wazuh", {}).get("alerts", {}).get(
            "poll_interval_seconds", 10)
        min_risk = 10
        logger.info("alert_loop_started", poll_interval=poll_interval)

        # Agent auto-sync: discover and assign new agents from dedicated
        # Wazuh servers. Runs at startup and every 5 minutes.
        _agent_sync_interval = 300  # 5 minutes
        _last_agent_sync = 0

        while self.running and not self._shutdown_event.is_set():
            try:
                # Leader election: only ONE replica runs the fetch/enqueue body.
                with self.db.job_lock("dhruva:job:alert_loop") as is_leader:
                    if not is_leader:
                        logger.debug("alert_loop_cycle_skipped_not_leader")
                    else:
                        self._run_alert_loop_cycle(
                            min_risk, _last_agent_sync, _agent_sync_interval)
                        # _run_alert_loop_cycle returns the updated agent-sync
                        # clock via instance attr to keep the signature simple.
                        _last_agent_sync = self._last_agent_sync_clock
            except Exception as e:
                logger.error("alert_loop_error", error=str(e))

            # WO-H10 liveness heartbeat: record once per iteration REGARDLESS of
            # leadership — this proves the loop THREAD is alive (a standby that
            # is healthily skipping is still alive). Read by /api/health.
            try:
                from src.api.liveness import record_cycle
                record_cycle()
            except Exception:
                pass

            # Wait before next poll
            self._shutdown_event.wait(timeout=poll_interval)

        logger.info("alert_loop_stopped")

    def _run_alert_loop_cycle(self, min_risk: int, last_agent_sync: float,
                              agent_sync_interval: int):
        """One leader-only fetch+enqueue cycle. Extracted from run_alert_loop so
        the leader-election wrapper stays readable."""
        import time as _time
        _now = _time.monotonic()
        # Periodic agent auto-sync for tenants with dedicated Wazuh
        if _now - last_agent_sync >= agent_sync_interval:
            try:
                results = self.tenant_registry.sync_all_tenant_agents()
                if results:
                    logger.info("agent_auto_sync_completed",
                                tenants_synced=len(results),
                                details=results)
            except Exception as e:
                logger.warning("agent_auto_sync_failed", error=str(e)[:200])
            last_agent_sync = _now
        self._last_agent_sync_clock = last_agent_sync

        # Iterate all active tenants (single-tenant: just the default)
        enriched_alerts = []
        for tenant_id in self._get_alert_loop_tenants():
            self.db.set_tenant(tenant_id)
            try:
                batch = self.enrichment.process_batch()
            except TenantConfigUnavailable:
                # Fail closed, per-tenant: this tenant's secrets can't be
                # decrypted (wrong/rotated/corrupt key). Skip it so it never
                # runs under global creds — and keep all other tenants going.
                logger.error("tenant_skipped_config_unavailable",
                             tenant_id=tenant_id, phase="alert_loop")
                continue
            if batch:
                enriched_alerts.extend(batch)

        if not enriched_alerts:
            return

        # Group alerts by tenant for the daily-limit gate + enqueue.
        from collections import defaultdict
        by_tenant = defaultdict(list)
        for alert in enriched_alerts:
            tid = (alert.get("client_id")
                   or self.config.get("client_id")
                   or "default")
            by_tenant[tid].append(alert)

        for tid, tenant_alerts in by_tenant.items():
            self.db.set_tenant(tid)

            agent_worthy = [
                a for a in tenant_alerts
                if a.get("enrichment", {}).get("risk_score", 0) >= min_risk
            ]

            # WO-H9 crash-safe checkpoint: below-threshold alerts (risk <
            # min_risk) are never enqueued/triaged — they ARE handled (skipped
            # as noise), so checkpoint them durably HERE so they aren't
            # re-fetched forever. Triageable alerts are checkpointed atomically
            # with their triage decision (store.save_decision), NOT here.
            for a in tenant_alerts:
                if a.get("enrichment", {}).get("risk_score", 0) < min_risk:
                    try:
                        self.db.mark_alert_processed(
                            alert_id=a.get("alert_id") or a.get("id"),
                            rule_id=a.get("rule_id"),
                            rule_description=a.get("rule_description"),
                            verdict="below_threshold")
                    except Exception as e:
                        logger.warning("below_threshold_checkpoint_failed",
                                       alert_id=a.get("alert_id"),
                                       error=str(e)[:200])

            if not agent_worthy:
                continue

            # Check triage daily limit before enqueuing for AI triage.
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            today_count = self.db.get_metric_count(
                "triage_call", since_date=today)
            if (self._license_info.max_triage_daily > 0
                    and today_count >= self._license_info.max_triage_daily):
                logger.warning("triage_daily_limit_reached",
                               tier=self._license_info.tier,
                               limit=self._license_info.max_triage_daily,
                               count=today_count, tenant=tid)
                continue

            # Enqueue for the parallel worker pool (risk-priority ordering is
            # applied inside the dispatcher). The fetcher returns immediately.
            queued = self.triage_dispatcher.submit_batch(agent_worthy, tid)

            self.db.record_metric(
                "alert_loop_batch", len(tenant_alerts),
                {
                    "tenant": tid,
                    "enriched": len(tenant_alerts),
                    "enqueued": queued,
                    "skipped_low_risk": len(tenant_alerts) - len(agent_worthy),
                    "backlog_depth": self.triage_dispatcher.backlog_depth(),
                })
            # Emit backlog/queue-depth as its own metric for dashboards/alerting.
            self.db.record_metric(
                "triage_queue_depth",
                self.triage_dispatcher.backlog_depth(),
                {"tenant": tid})

    def start(self):
        """Start the full platform."""
        logger.info("platform_starting")
        self.running = True
        self._setup_signal_handlers()
        self._schedule_periodic_tasks()

        # Compute initial baselines in background so they're available immediately
        if self._license_info.has_feature("baselines"):
            baseline_thread = threading.Thread(
                target=self._compute_baselines,
                name="initial-baselines",
                daemon=True
            )
            baseline_thread.start()
            logger.info("initial_baseline_computation_started")

        # Run initial TI feed collection in background
        if self.ti_collector:
            ti_thread = threading.Thread(
                target=self._run_ti_collection,
                name="initial-ti-collection",
                daemon=True
            )
            ti_thread.start()
            logger.info("initial_ti_collection_started")

        # WO-H9: start the parallel-triage worker pool BEFORE the fetch loop so
        # workers are ready to drain the moment alerts are enqueued.
        self.triage_dispatcher.start()

        # Start alert processing loop (producer) in a thread
        alert_thread = threading.Thread(
            target=self.run_alert_loop,
            name="alert-loop",
            daemon=True
        )
        alert_thread.start()

        # Start API server (blocks)
        import uvicorn
        api_cfg = self.config.get("api", {})
        ssl_cfg = api_cfg.get("ssl", {})
        uvicorn_kwargs = {
            "host": api_cfg.get("host", "0.0.0.0"),
            "port": api_cfg.get("port", 8443),
            "log_level": "info",
        }
        if ssl_cfg.get("certfile") and ssl_cfg.get("keyfile"):
            uvicorn_kwargs["ssl_certfile"] = ssl_cfg["certfile"]
            uvicorn_kwargs["ssl_keyfile"] = ssl_cfg["keyfile"]
            logger.info("api_ssl_enabled",
                        certfile=ssl_cfg["certfile"])
        else:
            bind_host = api_cfg.get("host", "0.0.0.0")
            dev_mode = os.environ.get("DEV_MODE", "").lower() in ("1", "true", "yes")
            if bind_host != "127.0.0.1" and not dev_mode:
                raise SystemExit(
                    "FATAL: No SSL cert/key configured on a public bind address "
                    f"({bind_host}:{api_cfg.get('port', 8443)}). "
                    "Set api.ssl.certfile and api.ssl.keyfile for HTTPS, "
                    "or set DEV_MODE=true to allow plaintext HTTP."
                )
            else:
                logger.warning("api_ssl_disabled",
                               message="No SSL cert/key configured. "
                                       "Set api.ssl.certfile and api.ssl.keyfile "
                                       "for HTTPS.")
        uvicorn.run(app, **uvicorn_kwargs)

    def stop(self):
        """Graceful shutdown."""
        logger.info("platform_stopping")
        self.running = False
        self._shutdown_event.set()
        if hasattr(self, "scheduler") and self.scheduler.running:
            self.scheduler.shutdown(wait=True)
        # WO-H9: stop the triage worker pool with a BOUNDED drain so in-flight
        # alerts get their decision saved + checkpointed before exit (anything
        # past the deadline is left un-checkpointed and safely re-triaged on
        # restart — never silently dropped).
        if hasattr(self, "triage_dispatcher"):
            try:
                self.triage_dispatcher.stop(drain=True, timeout=15.0)
            except Exception:
                pass
        logger.info("platform_stopped")


def _run_alembic_upgrade():
    """Apply pending Alembic migrations against DATABASE_URL (Postgres).

    Invoked via ``python main.py --migrate`` from install.sh / docker
    entrypoints. Exits 0 on success, 1 on failure. Lives in main.py so
    the PyInstaller binary ships the alembic dependency transitively.

    Implementation note: ``script_location`` and ``sqlalchemy.url`` are
    both set on the Config object programmatically rather than relying
    on ``alembic.ini`` being shipped alongside the binary. Without this,
    a Docker / tarball install that doesn't ship the ini file blows up
    on first boot with ``CommandError: No 'script_location' key found
    in configuration``. The migrations directory ``src/database/
    migrations`` always ships (it's under ``src/``), so its absolute
    path is the durable source of truth.
    """
    from alembic import command
    from alembic.config import Config
    if not os.environ.get("DATABASE_URL"):
        sys.stderr.write(
            "error: DATABASE_URL not set — set it to your Postgres libpq URI "
            "before running --migrate (see docs/MIGRATION-FROM-SQLITE.md).\n")
        sys.exit(1)
    repo_root = Path(__file__).resolve().parent
    migrations_dir = repo_root / "src" / "database" / "migrations"
    cfg = Config()
    cfg.set_main_option("script_location", str(migrations_dir))
    cfg.set_main_option("sqlalchemy.url", os.environ["DATABASE_URL"])
    command.upgrade(cfg, "head")
    sys.stdout.write("alembic upgrade head OK\n")
    sys.exit(0)


def main():
    if "--migrate" in sys.argv[1:]:
        _run_alembic_upgrade()

    config_path = sys.argv[1] if len(sys.argv) > 1 else "config/config.yaml"

    if not Path(config_path).exists():
        logger.error("config_not_found", path=config_path)
        sys.exit(1)

    platform = AISocPlatform(config_path)

    try:
        platform.start()
    except KeyboardInterrupt:
        platform.stop()
    except Exception as e:
        logger.error("platform_fatal_error", error=str(e))
        platform.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()
