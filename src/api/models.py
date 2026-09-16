"""
Pydantic request models and constants shared across API route modules.
"""

import html as _html_mod
import re as _re_mod
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


def sanitize_user_text(text: str, max_len: int = 5000) -> str:
    """HTML-escape user-supplied text to prevent stored XSS."""
    if not text:
        return text
    return _html_mod.escape(text[:max_len])


# Single source of truth for the platform password complexity policy. Returns
# an error message string when the password is non-compliant, else None. Used
# by the Pydantic user models (which raise ValueError -> 422) and by the
# self-service change-password route (which raises HTTPException(400)).
_PASSWORD_SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}|;:',.<>?/`~"


def password_policy_error(v: str) -> Optional[str]:
    """Validate a password against the platform policy.

    Returns None if compliant, otherwise a human-readable reason. Do not weaken
    these rules — they are shared by admin user-management and self-service.
    """
    if len(v) < 12:
        return "password must be at least 12 characters"
    if not any(c.isupper() for c in v):
        return "password must contain at least one uppercase letter"
    if not any(c.islower() for c in v):
        return "password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in v):
        return "password must contain at least one digit"
    if not any(c in _PASSWORD_SPECIAL_CHARS for c in v):
        return "password must contain at least one special character"
    return None


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALLOWED_VERDICTS = {"true_positive", "false_positive", "needs_investigation", "auto_close"}
ALLOWED_ACTIONS = {"approve", "reject"}
ALLOWED_INCIDENT_STATUSES = {"open", "investigating", "resolved", "closed"}

#: WO-H112 — the constrained closure reason. Kept in lockstep with `_REASONS`
#: in migration 0017, which enforces the same set as a CHECK constraint.
#:
#: These are the five answers that can be counted. "normal action" — the string
#: an analyst actually used to close the one real intrusion of August — is not
#: among them, and that is the entire point.
ALLOWED_CLOSURE_REASONS = {
    "true_positive",       # real, and acted on
    "benign_positive",     # the rule fired correctly; the activity was authorised
    "false_positive",      # the rule should not have fired
    "duplicate",           # already covered by another case
    "insufficient_data",   # could not be decided with what was available
}

#: The statuses that END an investigation, and therefore require a structured
#: closure reason. Moving to `investigating` does not.
CLOSING_STATUSES = {"resolved", "closed"}
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

from src.agents.prompts import PROMPT_INJECTION_GUARD as _PROMPT_INJECTION_GUARD

# WO-S14: this prompt consumes incident titles, rule descriptions and triage
# reasoning — all derived from ingested Wazuh alert content, which an attacker
# on a monitored host controls (a failed SSH login puts the attacker's chosen
# username into the incident title via IncidentEngine._generate_title). It
# carried NONE of the injection protections the triage, hunt and query prompts
# use, so the attacker could write the plain-English narrative a non-technical
# stakeholder reads about their own intrusion — and the result is CACHED in the
# incident timeline and re-served to every later viewer.
PLAIN_SUMMARY_PROMPT = """You are a security advisor writing for a non-technical IT manager.
Explain this security incident in plain, clear English.
""" + _PROMPT_INJECTION_GUARD + """

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

    # WO-H112. `reason` is prose for a human to read; `closure_reason` is the
    # one field a metric can be computed from. Required only when the status
    # actually ends the investigation — see CLOSING_STATUSES.
    closure_reason: Optional[str] = None
    #: The closer's explicit judgement on the AI. Optional: absent means "not
    #: stated", which is NOT the same as "the AI was right", and nothing
    #: downstream may read it as agreement.
    ai_was_wrong: Optional[bool] = None
    # QA L3: analyst-writable free text bound, like every other such field.
    ai_wrong_detail: Optional[str] = Field(default=None, max_length=4000)

    @field_validator("closure_reason")
    @classmethod
    def validate_closure_reason(cls, v):
        if v is None:
            return v
        v = str(v).strip().lower()
        if v not in ALLOWED_CLOSURE_REASONS:
            raise ValueError(
                "closure_reason must be one of %s"
                % sorted(ALLOWED_CLOSURE_REASONS))
        return v

    @model_validator(mode="after")
    def require_closure_reason_when_closing(self):
        """A case may not be closed without a countable reason.

        Free text alone is what produced "normal action" on the one alert this
        month that mattered. It reads fine and it measures nothing.
        """
        if self.status in CLOSING_STATUSES and not self.closure_reason:
            raise ValueError(
                "closure_reason is required when status is %s — one of %s"
                % (sorted(CLOSING_STATUSES), sorted(ALLOWED_CLOSURE_REASONS)))
        return self

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


class IncidentVerdictPropagationRequest(BaseModel):
    """WO-H85 — apply ONE human verdict to an incident's member alerts.

    Deliberately SEPARATE from ``IncidentStatusRequest``. Closing an incident
    cascades WORK-ITEM state (``resolved_at``) and nothing else; putting a
    verdict on every alert an incident grouped is a different, far more
    consequential claim — those alerts were correlated, not individually judged.

    ``confirm`` is the opt-in: it DEFAULTS TO FALSE and the route refuses the
    request without it, so the propagation can never be a side effect of a
    client that simply omitted the flag. ``reason`` is mandatory and free text,
    exactly like the verdict and status reasons — the value is the specific
    finding, which no enum captures.
    """

    human_verdict: str
    reason: str
    confirm: bool = False

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
        err = password_policy_error(v)
        if err:
            raise ValueError(err)
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
        err = password_policy_error(v)
        if err:
            raise ValueError(err)
        return v


class ChangePasswordRequest(BaseModel):
    """Self-service password change (POST /api/my/password).

    Deliberately NO Pydantic complexity validator: the route enforces the
    policy inline via ``password_policy_error`` so violations return 400
    (per WO-H58 DoD) rather than Pydantic's 422, and so the ``new ==
    current`` cross-field rule lives next to it.
    """
    current_password: str
    new_password: str


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


# -- Shift SCHEDULE editing (WO-H79) ----------------------------------------
# Shape-only validation lives here (types, lengths, weekday names). The
# SEMANTIC rules — analysts must exist and be active in platform_users, every
# shift must be staffed, the on-call primary must be on that shift, no analyst
# on two overlapping shifts, and the day must tile 24 hours with no gap or
# overlap — live in src/team/shift_manager.validate_shift_schedule, because
# they need the user table and the runtime shift-matching rule. That module is
# PAID (stripped in Community), so it is imported inside the route, never here.

ALLOWED_WEEKDAYS = {"monday", "tuesday", "wednesday", "thursday", "friday",
                    "saturday", "sunday"}


class ShiftDefinitionRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    # A whole hour (14 — the original schema) or "HH:MM" (18:30). A SOC on a
    # half-hour UTC offset cannot describe itself in whole hours (WO-H77).
    start_utc: Any
    end_utc: Any
    days: list[str] = Field(default_factory=list, max_length=7)
    analysts: list[str] = Field(default_factory=list, max_length=50)
    on_call_primary: str = Field("", max_length=100)

    @field_validator("name")
    @classmethod
    def sanitize_name(cls, v: str) -> str:
        v = sanitize_user_text(v.strip(), max_len=100)
        if not v:
            raise ValueError("shift name is required")
        return v

    @field_validator("start_utc", "end_utc")
    @classmethod
    def time_is_scalar(cls, v):
        """Only a shape check — the real parse is the shift manager's."""
        if isinstance(v, bool) or not isinstance(v, (int, float, str)):
            raise ValueError(
                'shift times must be a whole hour (0-24) or "HH:MM" UTC')
        if isinstance(v, str) and len(v) > 5:
            raise ValueError('shift times must be a whole hour (0-24) or "HH:MM" UTC')
        return v

    @field_validator("days")
    @classmethod
    def validate_days(cls, v: list[str]) -> list[str]:
        out = []
        for day in v:
            day_norm = str(day).strip().lower()
            if day_norm not in ALLOWED_WEEKDAYS:
                raise ValueError(f"'{day}' is not a weekday name")
            if day_norm not in out:
                out.append(day_norm)
        return out

    @field_validator("analysts")
    @classmethod
    def validate_analysts(cls, v: list[str]) -> list[str]:
        return [str(a).strip() for a in v]


class ShiftScheduleRequest(BaseModel):
    shifts: list[ShiftDefinitionRequest] = Field(default_factory=list,
                                                 max_length=50)
    # IANA zone (e.g. "Asia/Kolkata") the operator entered the times in. Used
    # ONLY to regenerate the local-time comments beside each UTC boundary, so
    # the file stays readable to the person who owns the rota. Never affects
    # the stored values, which are always UTC.
    timezone: Optional[str] = Field(None, max_length=64)
    # Explicit confirmation that an EXISTING but unparseable schedule file may
    # be replaced. Defaults to false: a file that failed to parse is a rota of
    # unknown content, not an empty one, and overwriting it silently is the
    # failure mode this whole feature exists to remove. The server 409s until
    # the operator opts in.
    overwrite_unreadable: bool = False

    @field_validator("timezone")
    @classmethod
    def sanitize_timezone(cls, v):
        if v is None:
            return v
        v = v.strip()
        if not v:
            return None
        if not _re_mod.fullmatch(r"[A-Za-z0-9_+\-/]{1,64}", v):
            raise ValueError("timezone must be an IANA zone name")
        return v


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
