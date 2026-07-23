"""
Pydantic request models and constants shared across API route modules.
"""

import html as _html_mod
import re as _re_mod
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator


def sanitize_user_text(text: str, max_len: int = 5000) -> str:
    """HTML-escape user-supplied text to prevent stored XSS."""
    if not text:
        return text
    return _html_mod.escape(text[:max_len])


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALLOWED_VERDICTS = {"true_positive", "false_positive", "needs_investigation", "auto_close"}
ALLOWED_ACTIONS = {"approve", "reject"}
ALLOWED_INCIDENT_STATUSES = {"open", "investigating", "resolved", "closed"}
ALLOWED_AR_ACTIONS = {
    "block_ip", "unblock_ip", "isolate_host", "unisolate_host",
    "kill_process", "disable_user", "enable_user",
    "quarantine_file", "restart_agent",
}
ALLOWED_HUNT_STATUSES = {"confirmed", "dismissed"}
ALLOWED_ROLES = {"admin", "senior_analyst", "analyst", "read_only"}
ALLOWED_KB_DOC_TYPES = {
    "analyst_note", "investigation_pattern", "feedback_pattern",
    "hunt_finding", "incident_learning", "guidance",
}

PLAIN_SUMMARY_PROMPT = """You are a security advisor writing for a non-technical IT manager.
Explain this security incident in plain, clear English.

CRITICAL: Respond in PLAIN TEXT only. Do NOT use JSON, code blocks,
markdown, or any structured format. Just write natural paragraphs
that a non-technical person can read like an email.

Do NOT use jargon like "IOC", "lateral movement", "C2", "exfiltration",
"MITRE ATT&CK", "brute force" without immediately explaining what it means
in simple terms.

Structure your response with these headings (plain text, not markdown):

WHAT HAPPENED
Write 1-2 sentences explaining what occurred in plain English.

WHAT IS AT RISK
Name which computers, users, or data could be affected.

HOW SERIOUS IS THIS
Say Low, Medium, High, or Critical — with a one-sentence reason.

WHAT YOU SHOULD DO
List 1-3 concrete action steps the IT person can take right now.

Keep the total response under 200 words. Be direct and reassuring —
if the AI already handled something automatically, say so clearly."""


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class CreateTicketRequest(BaseModel):
    incident_id: str
    provider: Optional[str] = None
    summary: Optional[str] = None

    @field_validator("incident_id")
    @classmethod
    def validate_incident_id(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("incident_id is required")
        return v

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v):
        if v is not None:
            allowed = {"jira", "servicenow", "pagerduty"}
            if v not in allowed:
                raise ValueError(f"provider must be one of {allowed}")
        return v


class NLQueryRequest(BaseModel):
    question: str

    @field_validator("question")
    @classmethod
    def validate_question(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) < 3:
            raise ValueError("question must be at least 3 characters")
        if len(v) > 1000:
            raise ValueError("question must be under 1000 characters")
        return v


class HumanReviewRequest(BaseModel):
    decision_id: str
    human_verdict: str
    # WO-B2: reason is MANDATORY and audited. A verdict change may not be
    # recorded without a human-supplied justification.
    reason: str
    notes: Optional[str] = None

    @field_validator("human_verdict")
    @classmethod
    def validate_verdict(cls, v: str) -> str:
        if v not in ALLOWED_VERDICTS:
            raise ValueError(f"verdict must be one of {ALLOWED_VERDICTS}")
        return v

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("reason is required and must not be empty")
        if len(v) > 2000:
            raise ValueError("reason must be under 2000 characters")
        return v

    @field_validator("notes")
    @classmethod
    def validate_notes_length(cls, v: Optional[str]) -> Optional[str]:
        if v and len(v) > 2000:
            raise ValueError("notes must be under 2000 characters")
        return v


class ProposalReviewRequest(BaseModel):
    proposal_id: str
    action: str
    notes: Optional[str] = None

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        if v not in ALLOWED_ACTIONS:
            raise ValueError(f"action must be one of {ALLOWED_ACTIONS}")
        return v


class HuntReviewRequest(BaseModel):
    finding_id: str
    status: str
    confirmed: bool
    notes: Optional[str] = None

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        if v not in ALLOWED_HUNT_STATUSES:
            raise ValueError(f"status must be one of {ALLOWED_HUNT_STATUSES}")
        return v

    @field_validator("notes")
    @classmethod
    def validate_notes_length(cls, v: Optional[str]) -> Optional[str]:
        if v and len(v) > 2000:
            raise ValueError("notes must be under 2000 characters")
        return v


class IncidentAssignRequest(BaseModel):
    assigned_to: str

    @field_validator("assigned_to")
    @classmethod
    def validate_assigned_to(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 100:
            raise ValueError("assigned_to must be 1-100 characters")
        return v


class IncidentStatusRequest(BaseModel):
    status: str
    # WO-B3: reason is MANDATORY and audited. An incident status change may
    # not be recorded without a human-supplied justification.
    reason: str

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        if v not in ALLOWED_INCIDENT_STATUSES:
            raise ValueError(f"status must be one of {ALLOWED_INCIDENT_STATUSES}")
        return v

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("reason is required and must not be empty")
        if len(v) > 2000:
            raise ValueError("reason must be under 2000 characters")
        return v


class IncidentNoteRequest(BaseModel):
    note: str

    @field_validator("note")
    @classmethod
    def validate_note(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 5000:
            raise ValueError("note must be 1-5000 characters")
        return v


class IncidentMergeRequest(BaseModel):
    target_id: str
    source_ids: list[str]

    @field_validator("source_ids")
    @classmethod
    def validate_source_ids(cls, v: list[str]) -> list[str]:
        if len(v) < 1 or len(v) > 20:
            raise ValueError("source_ids must contain 1-20 incident IDs")
        return v


class BatchSummaryRequest(BaseModel):
    incident_ids: list[str]

    @field_validator("incident_ids")
    @classmethod
    def validate_ids(cls, v: list[str]) -> list[str]:
        return v[:10]  # Cap at 10


class CreateUserRequest(BaseModel):
    username: str
    password: str
    display_name: str = ""
    email: str = ""
    role: str = "analyst"

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        v = v.strip().lower()
        if not v or len(v) < 2 or len(v) > 50:
            raise ValueError("username must be 2-50 chars")
        if not _re_mod.match(r"^[a-z0-9._-]+$", v):
            raise ValueError("lowercase alphanumeric, dots, hyphens, underscores only")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        if len(v) < 12:
            raise ValueError("password must be at least 12 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("password must contain at least one digit")
        if not any(c in "!@#$%^&*()-_=+[]{}|;:',.<>?/`~" for c in v):
            raise ValueError("password must contain at least one special character")
        return v

    @field_validator("role")
    @classmethod
    def validate_role(cls, v):
        if v not in ALLOWED_ROLES:
            raise ValueError(f"role must be one of {ALLOWED_ROLES}")
        return v


class UpdateUserRequest(BaseModel):
    display_name: Optional[str] = None
    email: Optional[str] = None
    role: Optional[str] = None
    password: Optional[str] = None
    is_active: Optional[bool] = None

    @field_validator("role")
    @classmethod
    def validate_role(cls, v):
        if v is not None and v not in ALLOWED_ROLES:
            raise ValueError(f"role must be one of {ALLOWED_ROLES}")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        if v is None:
            return v
        if len(v) < 12:
            raise ValueError("password must be at least 12 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("password must contain at least one digit")
        if not any(c in "!@#$%^&*()-_=+[]{}|;:',.<>?/`~" for c in v):
            raise ValueError("password must contain at least one special character")
        return v


class RemediationRequest(BaseModel):
    agent_id: str
    package_name: str
    package_version: str = ""

    @field_validator("agent_id")
    @classmethod
    def validate_agent_id(cls, v: str) -> str:
        import re
        v = v.strip()
        if not v or not re.match(r'^\d{1,5}$', v):
            raise ValueError("invalid agent_id — must be 1-5 digit number")
        return v

    @field_validator("package_name")
    @classmethod
    def validate_pkg(cls, v: str) -> str:
        import re
        v = v.strip()
        if not v or len(v) > 200:
            raise ValueError("invalid package_name")
        # Allowlist: standard Linux package name format only
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._+\-]{0,199}$', v):
            raise ValueError(
                "package_name must start with alphanumeric and contain "
                "only alphanumeric, dots, underscores, plus signs, and hyphens"
            )
        return v


class ActiveResponseRequest(BaseModel):
    action: str
    agent_id: str
    target: Optional[str] = None  # IP, PID, username, or file path
    timeout: Optional[int] = 3600

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        if v not in ALLOWED_AR_ACTIONS:
            raise ValueError(f"action must be one of {sorted(ALLOWED_AR_ACTIONS)}")
        return v

    @field_validator("agent_id")
    @classmethod
    def validate_agent_id(cls, v: str) -> str:
        if not _re_mod.match(r"^\d{1,5}$", v.strip()):
            raise ValueError("agent_id must be a numeric Wazuh agent ID (1-5 digits)")
        return v.strip()

    @model_validator(mode="after")
    def validate_target(self):
        """Validate target format based on action type to prevent injection."""
        import re as _re
        action = self.action
        target = self.target

        # Actions that don't need a target
        if action in ("isolate_host", "unisolate_host", "restart_agent"):
            return self

        if not target:
            raise ValueError(f"target is required for action '{action}'")

        # Block shell metacharacters universally
        _dangerous = set(";&|$(){}[]`!\\\n\r\x00")
        if any(c in _dangerous for c in target):
            raise ValueError("target contains forbidden characters")

        if action in ("block_ip", "unblock_ip"):
            import ipaddress as _ipaddress
            try:
                _ipaddress.ip_address(target)
            except ValueError:
                raise ValueError("target must be a valid IP address")

        elif action == "kill_process":
            if not _re.match(r"^\d{1,7}$", target):
                raise ValueError("target must be a numeric PID")

        elif action in ("disable_user", "enable_user"):
            if not _re.match(r"^[a-zA-Z0-9._@\\-]{1,128}$", target):
                raise ValueError(
                    "target must be a valid username "
                    "(alphanumeric, dots, dashes, underscores, max 128 chars)"
                )

        elif action == "quarantine_file":
            if not target.startswith("/"):
                raise ValueError("target must be an absolute file path")
            if ".." in target:
                raise ValueError("target must not contain path traversal (..)")
            if not _re.match(r"^[a-zA-Z0-9/_.\-]+$", target):
                raise ValueError("target contains invalid characters for a file path")
            if len(target) > 512:
                raise ValueError("target path too long (max 512)")

        return self


class AutoBlockPolicyRequest(BaseModel):
    """Per-tenant auto-block policy (M3). admin-only, own-tenant.

    Explicit schema to prevent mass assignment. All fields optional so an
    admin can patch a single knob; unspecified fields keep their stored value
    (or the safe default). auto_enabled ships OFF.
    """
    auto_enabled: Optional[bool] = None
    triage_confidence_floor: Optional[float] = Field(None, ge=0.0, le=1.0)
    ti_feed_confidence_floor: Optional[float] = Field(None, ge=0.0, le=100.0)
    rate_cap_per_hour: Optional[int] = Field(None, ge=0, le=1000)
    ttl_seconds: Optional[int] = Field(None, ge=60, le=604800)  # 1min..7d
    never_block_allowlist: Optional[list] = None

    @field_validator("never_block_allowlist")
    @classmethod
    def validate_allowlist(cls, v):
        if v is None:
            return v
        import ipaddress as _ip
        if not isinstance(v, list):
            raise ValueError("never_block_allowlist must be a list")
        if len(v) > 1000:
            raise ValueError("never_block_allowlist too large (max 1000)")
        cleaned = []
        for entry in v:
            entry = str(entry).strip()
            if not entry:
                continue
            try:
                _ip.ip_network(entry, strict=False)
            except ValueError:
                raise ValueError(f"invalid IP/CIDR in allowlist: {entry}")
            cleaned.append(entry)
        return cleaned


class ProposeResponseRequest(ActiveResponseRequest):
    """Propose (queue) an active-response action for approval (M3).

    Reuses ActiveResponseRequest's injection-safe validation; adds optional
    linkage to the triggering alert/incident for the audit trail.
    """
    alert_id: Optional[str] = None
    incident_id: Optional[str] = None
    reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Tenant management models (Fix W11 — mass assignment prevention)
# ---------------------------------------------------------------------------

class TenantConfigRequest(BaseModel):
    """Explicit schema for tenant config to prevent mass assignment."""
    wazuh: Optional[dict] = None
    llm: Optional[dict] = None
    notifications: Optional[dict] = None
    dashboard_proxy: Optional[dict] = None
    ti_api_keys: Optional[dict] = None


class CreateTenantRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    slug: str = Field(..., min_length=3, max_length=50)
    config: TenantConfigRequest = TenantConfigRequest()

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        # Pydantic's min_length=1 only checks raw length; whitespace-only
        # strings (e.g. "   ") would slip through and end up persisted as
        # empty after the route's .strip() call. Strip first, then verify.
        v = v.strip()
        if not v:
            raise ValueError("name cannot be empty or whitespace-only")
        if len(v) > 200:
            raise ValueError("name must be at most 200 characters")
        return v

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, v: str) -> str:
        v = v.strip().lower()
        if not _re_mod.match(r'^[a-z0-9][a-z0-9_-]{1,48}[a-z0-9]$', v):
            raise ValueError(
                "slug must be 3-50 lowercase alphanumeric with hyphens/underscores")
        return v


# ---------------------------------------------------------------------------
# Incident sub-resource models (Fix W12/W45 — mass assignment prevention)
# ---------------------------------------------------------------------------

class EvidenceRequest(BaseModel):
    type: str = Field("note", max_length=50)
    description: str = Field("", max_length=5000)
    ref_id: Optional[str] = Field(None, max_length=200)

    @field_validator("description")
    @classmethod
    def sanitize_desc(cls, v: str) -> str:
        return sanitize_user_text(v) if v else v

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        allowed = {"note", "artifact", "screenshot", "log", "ioc", "file", "other"}
        if v not in allowed:
            raise ValueError(f"type must be one of {sorted(allowed)}")
        return v


class IncidentReviewRequest(BaseModel):
    review_date: Optional[str] = None
    participants: list[str] = Field(default_factory=list)
    timeline_accuracy: str = Field("", max_length=2000)
    detection_gap: str = Field("", max_length=2000)
    response_effectiveness: str = Field("", max_length=2000)
    lessons_learned: str = Field("", max_length=5000)
    action_items: list[dict] = Field(default_factory=list)
    detection_backlog_items: list[dict] = Field(default_factory=list)
    status: str = Field("draft", max_length=50)

    @field_validator("lessons_learned")
    @classmethod
    def sanitize_lessons(cls, v: str) -> str:
        return sanitize_user_text(v) if v else v

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        allowed = {"draft", "in_review", "completed"}
        if v not in allowed:
            raise ValueError(f"status must be one of {sorted(allowed)}")
        return v


class FlagInterestingRequest(BaseModel):
    flagged: bool = True
    notes: str = Field("", max_length=2000)

    @field_validator("notes")
    @classmethod
    def sanitize_notes(cls, v: str) -> str:
        return sanitize_user_text(v) if v else v


class HandoffRequest(BaseModel):
    shift_from: str = Field(..., min_length=1, max_length=100)
    shift_to: str = Field(..., min_length=1, max_length=100)


# ---------------------------------------------------------------------------
# Settings panel models (assets, identities, local IOCs)
# ---------------------------------------------------------------------------

ALLOWED_ASSET_TIERS = {
    "tier_1_critical", "tier_2_important", "tier_3_standard",
    "tier_4_low", "unknown",
}
ALLOWED_ENVIRONMENTS = {
    "production", "staging", "development", "testing", "unknown",
}
ALLOWED_RISK_LEVELS = {
    "critical", "high_risk", "elevated", "standard", "low_risk",
}
ALLOWED_IOC_TYPES = {"ip", "domain", "hash"}
ALLOWED_IOC_SEVERITIES = {"critical", "high", "medium", "low", "info"}


class CreateAssetRequest(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=253)
    tier: str = "unknown"
    owner: str = Field("unknown", max_length=200)
    environment: str = "unknown"
    criticality_multiplier: float = Field(1.0, ge=0.1, le=10.0)
    tags: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("hostname is required")
        return sanitize_user_text(v, max_len=253)

    @field_validator("tier")
    @classmethod
    def validate_tier(cls, v):
        if v not in ALLOWED_ASSET_TIERS:
            raise ValueError(f"tier must be one of {sorted(ALLOWED_ASSET_TIERS)}")
        return v

    @field_validator("environment")
    @classmethod
    def validate_env(cls, v):
        if v not in ALLOWED_ENVIRONMENTS:
            raise ValueError(
                f"environment must be one of {sorted(ALLOWED_ENVIRONMENTS)}")
        return v

    @field_validator("tags", "services")
    @classmethod
    def validate_list_items(cls, v):
        return [sanitize_user_text(item.strip(), max_len=100) for item in v[:20]]


class UpdateAssetRequest(BaseModel):
    tier: Optional[str] = None
    owner: Optional[str] = None
    environment: Optional[str] = None
    criticality_multiplier: Optional[float] = Field(None, ge=0.1, le=10.0)
    tags: Optional[list[str]] = None
    services: Optional[list[str]] = None

    @field_validator("tier")
    @classmethod
    def validate_tier(cls, v):
        if v is not None and v not in ALLOWED_ASSET_TIERS:
            raise ValueError(f"tier must be one of {sorted(ALLOWED_ASSET_TIERS)}")
        return v

    @field_validator("environment")
    @classmethod
    def validate_env(cls, v):
        if v is not None and v not in ALLOWED_ENVIRONMENTS:
            raise ValueError(
                f"environment must be one of {sorted(ALLOWED_ENVIRONMENTS)}")
        return v

    @field_validator("tags", "services")
    @classmethod
    def validate_list_items(cls, v):
        if v is None:
            return v
        return [sanitize_user_text(item.strip(), max_len=100) for item in v[:20]]


# WO-H57 — verdicts an admin may set on a cached entry. Kept to BENIGN /
# non-escalating dispositions: the cache is only ever consulted for
# dedup-eligible (non-escalate) alerts, so an edit here can never turn into a
# suppression of an escalate-eligible alert.
ALLOWED_CACHE_VERDICTS = frozenset({
    "auto_close", "false_positive", "benign", "needs_investigation",
    "closed", "resolved",
})


class UpdateDecisionCacheRequest(BaseModel):
    """Edit a persistent decision-cache entry (WO-H57 Decision Cache tab).

    ``enabled=false`` stops reuse (the next matching alert goes back to the LLM);
    ``verdict`` / ``reasoning`` let an analyst downgrade or annotate a cached
    call. Delete is a separate endpoint.
    """
    enabled: Optional[bool] = None
    verdict: Optional[str] = None
    reasoning: Optional[str] = None

    @field_validator("verdict")
    @classmethod
    def validate_verdict(cls, v):
        if v is not None and v.lower() not in ALLOWED_CACHE_VERDICTS:
            raise ValueError(
                f"verdict must be one of {sorted(ALLOWED_CACHE_VERDICTS)}")
        return v.lower() if v is not None else v

    @field_validator("reasoning")
    @classmethod
    def validate_reasoning(cls, v):
        if v is None:
            return v
        return sanitize_user_text(v.strip(), max_len=2000)


class CreateIdentityRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=128)
    risk_level: str = "standard"
    risk_multiplier: float = Field(1.0, ge=0.1, le=10.0)
    is_admin: bool = False
    is_service_account: bool = False
    roles: list[str] = Field(default_factory=list)
    department: str = Field("unknown", max_length=200)
    known_ips: list[str] = Field(default_factory=list)
    onboarded_date: Optional[str] = None

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("username is required")
        return sanitize_user_text(v, max_len=128)

    @field_validator("risk_level")
    @classmethod
    def validate_risk_level(cls, v):
        if v not in ALLOWED_RISK_LEVELS:
            raise ValueError(
                f"risk_level must be one of {sorted(ALLOWED_RISK_LEVELS)}")
        return v

    @field_validator("roles")
    @classmethod
    def validate_roles(cls, v):
        return [sanitize_user_text(r.strip(), max_len=100) for r in v[:20]]

    @field_validator("known_ips")
    @classmethod
    def validate_known_ips(cls, v):
        import ipaddress as _ipa
        validated = []
        for ip in v[:50]:
            try:
                _ipa.ip_address(ip.strip())
                validated.append(ip.strip())
            except ValueError:
                raise ValueError(f"invalid IP address: {ip}")
        return validated


class UpdateIdentityRequest(BaseModel):
    risk_level: Optional[str] = None
    risk_multiplier: Optional[float] = Field(None, ge=0.1, le=10.0)
    is_admin: Optional[bool] = None
    is_service_account: Optional[bool] = None
    roles: Optional[list[str]] = None
    department: Optional[str] = None
    known_ips: Optional[list[str]] = None
    onboarded_date: Optional[str] = None

    @field_validator("risk_level")
    @classmethod
    def validate_risk_level(cls, v):
        if v is not None and v not in ALLOWED_RISK_LEVELS:
            raise ValueError(
                f"risk_level must be one of {sorted(ALLOWED_RISK_LEVELS)}")
        return v

    @field_validator("known_ips")
    @classmethod
    def validate_known_ips(cls, v):
        if v is None:
            return v
        import ipaddress as _ipa
        validated = []
        for ip in v[:50]:
            try:
                _ipa.ip_address(ip.strip())
                validated.append(ip.strip())
            except ValueError:
                raise ValueError(f"invalid IP address: {ip}")
        return validated


class CreateLocalIOCRequest(BaseModel):
    ioc_type: str
    value: str = Field(..., min_length=1, max_length=512)
    severity: str = "medium"
    description: str = Field("", max_length=1000)

    @field_validator("ioc_type")
    @classmethod
    def validate_ioc_type(cls, v):
        if v not in ALLOWED_IOC_TYPES:
            raise ValueError(f"ioc_type must be one of {sorted(ALLOWED_IOC_TYPES)}")
        return v

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v):
        if v not in ALLOWED_IOC_SEVERITIES:
            raise ValueError(
                f"severity must be one of {sorted(ALLOWED_IOC_SEVERITIES)}")
        return v

    @field_validator("value")
    @classmethod
    def validate_value(cls, v):
        return sanitize_user_text(v.strip(), max_len=512)

    @field_validator("description")
    @classmethod
    def validate_description(cls, v):
        return sanitize_user_text(v, max_len=1000) if v else v
