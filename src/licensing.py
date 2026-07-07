"""
SecureSleuths Platform License Validator — v2 (Tiered Licensing).

Validates Ed25519-signed license files with tier-based feature gating.
Schema v2 adds: tier, max_users, max_triage_daily, dashboard_tabs,
audit_retention_days, multi_tenant, custom_branding, rate limits.

Backwards-compatible: schema_version=1 licenses treated as "team".
"""

import base64
import json
import structlog
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

logger = structlog.get_logger(__name__)

# Ed25519 public key — split to avoid single-string extraction from binaries.
# Reassembled at runtime; each fragment is meaningless alone.
_K = [
    b'\x60\x61\x6a\x68\x5a\xa7\x3b\x21',
    b'\xed\x05\x29\x74\x9f\xf9\x4a\xd2',
    b'\xf8\x01\x4b\x38\x81\x2f\xbd\xd5',
    b'\x5d\xde\xf7\x19\x0b\x6f\x4c\x8f',
]
_PUBLIC_KEY_RAW = b''.join(_K)


# -- Tier Presets -------------------------------------------------------------
# These define the DEFAULT values for each tier. Individual license payloads
# can override any field (e.g., a Starter client who negotiated 150 agents).

TIER_PRESETS = {
    # ── Community (Free, self-hosted) ──────────────────────────────────────
    # Core platform: AI triage, enrichment, MITRE, 7 TI feeds, KB, incidents.
    # 5 users, unlimited agents and alerts.  No license file required.
    "community": {
        "features": [
            "triage", "enrichment", "ti_feeds_tier1",
            "anonymization", "incidents",
            "mitre", "knowledge_base",
        ],
        "max_agents": 0,                  # 0 = unlimited
        "max_users": 5,
        "max_triage_daily": 0,            # 0 = unlimited
        "max_nl_queries_daily": 0,        # feature not included (gated separately)
        "dashboard_tabs": [
            "overview", "triage", "incidents", "feedback",
            "mitre", "knowledge_base",
        ],
        "audit_retention_days": 30,
        "multi_tenant": False,
        "custom_branding": False,
        "active_response_actions": [],
        "notifications": [],
    },
    # ── Team ($999/mo) ─────────────────────────────────────────────────────
    # Everything in Community + detection, query, feedback loop, notifications,
    # ticketing, reporting, pipeline health. 25 users, 1 Tier-2 TI feed.
    "team": {
        "features": [
            # Community features
            "triage", "enrichment", "ti_feeds_tier1",
            "anonymization", "incidents",
            "mitre", "knowledge_base",
            # Team additions
            "detection", "nl_query", "feedback_loop",
            "notifications_full", "ticketing", "reports",
            "ti_feeds_tier2", "daily_review",
            "baselines", "pipeline_health",
            "host_integrity",
        ],
        "max_agents": 0,                  # unlimited
        "max_users": 25,
        "max_triage_daily": 0,            # unlimited
        "max_nl_queries_daily": 0,        # unlimited
        "dashboard_tabs": ["all"],
        "audit_retention_days": 90,
        "multi_tenant": False,
        "custom_branding": False,
        "active_response_actions": [],
        "notifications": ["email", "slack"],
    },
    # ── Enterprise ($2,999/mo) ─────────────────────────────────────────────
    # Everything in Team + hunt, active response, SOAR, vuln mgmt, compliance,
    # multi-tenancy, SSO, shift mgmt, advanced metrics. Unlimited everything.
    "enterprise": {
        "features": [
            # Community features
            "triage", "enrichment", "ti_feeds_tier1",
            "anonymization", "incidents",
            "mitre", "knowledge_base",
            # Team features
            "detection", "nl_query", "feedback_loop",
            "notifications_full", "ticketing", "reports",
            "ti_feeds_tier2", "daily_review",
            "baselines", "pipeline_health",
            "host_integrity",
            # Enterprise additions
            "hunt", "active_response_full", "soar",
            "vuln_remediation", "compliance_sca",
            "sla", "incidents_merge",
            "multi_tenant", "sso",
        ],
        "max_agents": 0,                  # unlimited
        "max_users": 0,                   # unlimited
        "max_triage_daily": 0,            # unlimited
        "max_nl_queries_daily": 0,        # unlimited
        "dashboard_tabs": ["all"],
        "audit_retention_days": 365,
        "multi_tenant": True,
        "custom_branding": False,
        "active_response_actions": [
            "block_ip", "unblock_ip", "isolate_host", "unisolate_host",
            "kill_process", "disable_user", "enable_user",
            "quarantine_file", "restart_agent",
        ],
        "notifications": ["email", "slack"],
    },
}

# All known dashboard tabs (for "all" expansion)
ALL_DASHBOARD_TABS = [
    "overview", "triage", "incidents", "daily_review",
    "detection", "hunt", "feedback", "metrics", "reports",
    "soar", "mitre", "investigate", "respond",
    "threat_intel", "knowledge_base", "tickets", "admin",
    # M6 host-integrity read views (paid: host_integrity feature)
    "fim", "rootcheck", "registry", "groups",
]


# -- Exceptions ---------------------------------------------------------------

class LicenseError(Exception):
    """Base license error."""

class LicenseFileNotFoundError(LicenseError):
    """License file does not exist."""

class LicenseFormatError(LicenseError):
    """License file is malformed."""

class LicenseSignatureError(LicenseError):
    """Signature verification failed."""

class LicenseExpiredError(LicenseError):
    """License has expired."""

class LicenseFeatureError(LicenseError):
    """Feature not available in current tier."""

class LicenseLimitError(LicenseError):
    """Resource limit exceeded for current tier."""


# -- Data ---------------------------------------------------------------------

@dataclass
class LicenseInfo:
    # Identity
    client_name: str
    client_id: str
    issued_at: datetime
    expires_at: datetime
    schema_version: int = 2

    # Tier
    tier: str = "community"

    # Features (explicit list from payload, merged with tier defaults)
    features: list[str] = field(default_factory=lambda: ["full"])

    # Capacity limits (0 = unlimited)
    max_agents: int = 0
    max_users: int = 0
    max_triage_daily: int = 0
    max_nl_queries_daily: int = 0

    # Dashboard
    dashboard_tabs: list[str] = field(default_factory=lambda: ["all"])

    # Operations
    audit_retention_days: int = 90
    multi_tenant: bool = False
    custom_branding: bool = False
    active_response_actions: list[str] = field(default_factory=list)
    notifications: list[str] = field(default_factory=list)

    # -- Computed properties ---------------------------------------------------

    @property
    def days_remaining(self) -> int:
        delta = self.expires_at - datetime.now(timezone.utc)
        return max(0, delta.days)

    @property
    def is_free_tier(self) -> bool:
        return self.tier == "community"

    @property
    def allowed_tabs(self) -> list[str]:
        """Resolve 'all' to the full tab list."""
        if "all" in self.dashboard_tabs:
            return ALL_DASHBOARD_TABS
        return self.dashboard_tabs

    # -- Feature checks --------------------------------------------------------

    def has_feature(self, feature: str) -> bool:
        """Check if the license includes a specific feature.

        Schema v2+ licenses are intended to ship explicit feature lists.
        However, both the CLI license generator and the license-manager
        UI have shipped licenses with `features=["full"]` in the past.
        Rather than silently downgrading these to no-features (which is
        what v4.8.4 did and what bricked cheersin's first license), we
        expand "full" to the tier's preset feature list at check time.
        Behavior is therefore:
          - v1 licenses: "full" is the legacy wildcard, all features pass.
          - v2+ explicit: only listed features pass.
          - v2+ with "full": expands to TIER_PRESETS[self.tier]["features"].
        """
        if feature in self.features:
            return True
        if "full" not in self.features:
            return False
        if self.schema_version < 2:
            return True
        # v2+ with "full" — expand to the tier's explicit feature list.
        tier_features = TIER_PRESETS.get(self.tier, {}).get("features", [])
        return feature in tier_features

    def require_feature(self, feature: str, label: str = None):
        """Raise LicenseFeatureError if feature is not available."""
        if not self.has_feature(feature):
            display = label or feature.replace("_", " ").title()
            raise LicenseFeatureError(
                f"{display} is not available on the {self.tier.title()} plan. "
                f"Contact SecureSleuths to upgrade your license."
            )

    # -- Capacity checks -------------------------------------------------------
    #
    # Treat None and 0 identically: both mean "unlimited". An incomplete or
    # hand-edited license payload that has `max_users: null` (cheersin's
    # reissued v4.8.4 license is the case that surfaced this) previously
    # tripped a TypeError on `int < None` inside require_user_quota — which
    # FastAPI rendered as a confusing 403 with a quota-exceeded message even
    # though the operator had set no quota at all.

    def check_agent_limit(self, current_agents: int) -> bool:
        """Check if agent count is within license limit. None/0 = unlimited."""
        if self.max_agents in (None, 0):
            return True
        return current_agents <= self.max_agents

    def check_user_limit(self, current_users: int) -> bool:
        """Check if user count is within license limit. None/0 = unlimited."""
        if self.max_users in (None, 0):
            return True
        return current_users < self.max_users

    def check_triage_limit(self, today_count: int) -> bool:
        """Check if daily triage calls are within limit. None/0 = unlimited."""
        if self.max_triage_daily in (None, 0):
            return True
        return today_count < self.max_triage_daily

    def check_nl_query_limit(self, today_count: int) -> bool:
        """Check if daily NL queries are within limit. None/0 = unlimited."""
        if self.max_nl_queries_daily in (None, 0):
            return True
        return today_count < self.max_nl_queries_daily

    def check_active_response(self, action: str) -> bool:
        """Check if a specific active response action is allowed."""
        if self.has_feature("active_response_full"):
            return True
        return action in self.active_response_actions

    def check_tab_access(self, tab: str) -> bool:
        """Check if a dashboard tab is allowed."""
        return tab in self.allowed_tabs

    def check_notification_channel(self, channel: str) -> bool:
        """Check if a notification channel is allowed."""
        if self.has_feature("notifications_full"):
            return True
        return channel in self.notifications

    # -- Summary for API / dashboard -------------------------------------------

    def to_dict(self) -> dict:
        """Full license info for admin API."""
        return {
            "client_name": self.client_name,
            "client_id": self.client_id,
            "tier": self.tier,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "days_remaining": self.days_remaining,
            "features": self.features,
            "limits": {
                "max_agents": self.max_agents,
                "max_users": self.max_users,
                "max_triage_daily": self.max_triage_daily,
                "max_nl_queries_daily": self.max_nl_queries_daily,
            },
            "dashboard_tabs": self.allowed_tabs,
            "audit_retention_days": self.audit_retention_days,
            "multi_tenant": self.multi_tenant,
            "custom_branding": self.custom_branding,
            "active_response_actions": self.active_response_actions,
            "notifications": self.notifications,
            "schema_version": self.schema_version,
        }

    def to_brief(self) -> dict:
        """Compact summary for the dashboard header badge."""
        return {
            "tier": self.tier,
            "days_remaining": self.days_remaining,
            "max_agents": self.max_agents,
            "tabs": len(self.allowed_tabs),
        }


# -- Validator ----------------------------------------------------------------

class LicenseValidator:
    """Validates SecureSleuths platform licenses (v1 and v2)."""

    def __init__(self, license_path: str = "license.key"):
        self.license_path = license_path

    def validate(self) -> LicenseInfo:
        """Full validation: file exists, signature valid, not expired.

        Returns LicenseInfo on success.
        Raises LicenseError subclass on failure.
        """
        # Step 1: Read the file
        try:
            with open(self.license_path) as f:
                content = f.read().strip()
        except FileNotFoundError:
            raise LicenseFileNotFoundError(
                f"License file not found at '{self.license_path}'. "
                f"Contact SecureSleuths (info@securesleuths.in) to obtain a license."
            )

        # Step 2: Parse two-line format (base64 payload + base64 signature)
        lines = content.splitlines()
        if len(lines) != 2:
            raise LicenseFormatError(
                f"License file is malformed (expected 2 lines, got {len(lines)}). "
                f"The file may be corrupted. Contact SecureSleuths for a replacement."
            )

        try:
            payload_bytes = base64.b64decode(lines[0])
            signature = base64.b64decode(lines[1])
        except Exception:
            raise LicenseFormatError(
                "License file contains invalid base64 encoding. "
                "Contact SecureSleuths for a replacement."
            )

        # Step 3: Verify Ed25519 signature
        try:
            public_key = Ed25519PublicKey.from_public_bytes(_PUBLIC_KEY_RAW)
            public_key.verify(signature, payload_bytes)
        except InvalidSignature:
            raise LicenseSignatureError(
                "License signature verification failed. "
                "The license file may be corrupted or tampered with. "
                "Contact SecureSleuths for a valid license."
            )

        # Step 4: Parse payload
        try:
            payload = json.loads(payload_bytes)
        except json.JSONDecodeError:
            raise LicenseFormatError(
                "License payload is not valid JSON. "
                "Contact SecureSleuths for a replacement."
            )

        required_fields = ["client_name", "client_id", "expires_at"]
        for fld in required_fields:
            if fld not in payload:
                raise LicenseFormatError(
                    f"License payload missing required field: {fld}. "
                    f"Contact SecureSleuths for a valid license."
                )

        # Step 5: Parse dates
        try:
            expires_at = datetime.fromisoformat(
                payload["expires_at"].replace("Z", "+00:00")
            )
            issued_at = datetime.fromisoformat(
                payload.get("issued_at", payload["expires_at"]).replace("Z", "+00:00")
            )
        except (ValueError, TypeError) as e:
            raise LicenseFormatError(
                f"License contains invalid date format: {e}. "
                f"Contact SecureSleuths for a replacement."
            )

        # Step 6: Check expiry
        now = datetime.now(timezone.utc)
        if now >= expires_at:
            raise LicenseExpiredError(
                f"License expired on {expires_at.strftime('%Y-%m-%d')}. "
                f"Client: {payload['client_name']}. "
                f"Contact SecureSleuths (info@securesleuths.in) to renew."
            )

        # Step 7: Build LicenseInfo with tier resolution
        schema_version = payload.get("schema_version", 1)
        tier = payload.get("tier", "team")

        # For v1 licenses (no tier field), treat as team (full paid features)
        if schema_version == 1:
            tier = "team"
            logger.info("license_v1_compat", tier="team",
                        msg="v1 license treated as team tier")

        # Resolve tier defaults, then overlay payload-specific overrides
        defaults = TIER_PRESETS.get(tier, TIER_PRESETS["team"]).copy()

        # Normalize the features list. Both the CLI and the license-manager
        # UI have at various points emitted features=["full"] as a wildcard
        # placeholder. Without this remap, schema-v2 licenses with "full"
        # silently disable every paid feature at runtime (the bug that
        # bricked cheersin's first license — Detection/Hunt/SOAR/Tickets
        # all 403 until reissued).
        raw_features = payload.get("features", defaults["features"])
        if isinstance(raw_features, list) and "full" in raw_features:
            logger.warning("license_full_feature_remapped",
                           tier=tier, schema_version=schema_version,
                           msg="'full' wildcard expanded to tier feature list")
            raw_features = defaults["features"]

        return LicenseInfo(
            client_name=payload["client_name"],
            client_id=payload["client_id"],
            issued_at=issued_at,
            expires_at=expires_at,
            schema_version=schema_version,
            tier=tier,
            features=raw_features,
            max_agents=payload.get("max_agents", defaults["max_agents"]),
            max_users=payload.get("max_users", defaults["max_users"]),
            max_triage_daily=payload.get(
                "max_triage_daily", defaults["max_triage_daily"]),
            max_nl_queries_daily=payload.get(
                "max_nl_queries_daily", defaults["max_nl_queries_daily"]),
            dashboard_tabs=payload.get(
                "dashboard_tabs", defaults["dashboard_tabs"]),
            audit_retention_days=payload.get(
                "audit_retention_days", defaults["audit_retention_days"]),
            multi_tenant=payload.get(
                "multi_tenant", defaults["multi_tenant"]),
            custom_branding=payload.get(
                "custom_branding", defaults["custom_branding"]),
            active_response_actions=payload.get(
                "active_response_actions",
                defaults["active_response_actions"]),
            notifications=payload.get(
                "notifications", defaults["notifications"]),
        )
