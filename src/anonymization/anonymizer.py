"""
AlertAnonymizer — pre-processing layer between enriched alerts and LLM prompts.

Replaces client-sensitive identifiers (hostnames, internal IPs, usernames)
with deterministic opaque tokens while preserving:
  - External/attacker IPs (needed for IOC correlation)
  - Command lines, file paths, process names (needed for LOLBin / malware detection)
  - All enrichment metadata tags (asset_tier, user_risk_level, etc.)

Tokens are deterministic (SHA-256 prefix) so the same entity always maps to
the same token, enabling Claude to reason about repeated appearances.

AIS1 adds an always-on regex layer that redacts SEMANTIC PII (emails, phones,
US/IN national IDs) from free-text fields (rule_description, location, raw log
bodies) using the SAME reversible token scheme. It is gated on
``anonymization.free_text_pii`` and NEVER touches detection-relevant keys
(command lines / file paths / process names) — enforced structurally via a
field allowlist plus a detection key exclude-set.

HONEST BOUNDARY (WO-H10) — what this DOES and does NOT strip:
  * DOES tokenize structural identifiers: top-level hostnames, internal IPs,
    usernames, and — nested inside raw ``data`` — Windows event identity fields
    (``TargetUserName`` / ``SubjectUserName`` / ``SamAccountName`` /
    ``WorkstationName`` / ``ComputerName`` …). See ``_HOST_IDENTITY_KEYS`` /
    ``_USER_IDENTITY_KEYS``.
  * DOES redact free-text semantic PII (email/phone/national-ID) from
    non-detection string leaves.
  * DOES NOT strip usernames/paths that live INSIDE a command line, file path,
    or process-image field. Those keys (``_DETECTION_EXCLUDE_KEYS``) are passed
    to the LLM verbatim ON PURPOSE — LOLBin / malware / persistence detection
    depends on the exact command text, which routinely contains a username
    (e.g. ``C:\\Users\\jdoe\\...`` or ``runas /user:jdoe``). So this is NOT a
    guarantee that "no PII ever reaches the LLM"; it is a guarantee that
    identifiers in structured identity fields are tokenized while
    detection-bearing text is preserved.
"""

import hashlib
import ipaddress
import json
import re
import threading
import structlog
from typing import Optional

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Free-text PII detectors (regex layer — AIS1)
#
# These redact SEMANTIC PII (emails, phones, national IDs) that lands in
# free-text fields (rule_description, log/message bodies) — content the
# structural tokenizer above deliberately does NOT touch. Matches are
# replaced with the SAME reversible salted-token scheme via ``_tokenize``,
# so ``deanonymize_text``/``deanonymize_dict`` restore them unchanged.
#
# Deliberate ordering (applied EMAIL → NATIONAL-ID → PHONE):
#   * EMAIL first, so the digits inside an address' local/domain part are
#     already tokenized before the phone/ID detectors run.
#   * NATIONAL-ID before PHONE, so structured IDs (SSN 3-2-4, Aadhaar) are
#     not partially eaten by the conservative phone matcher.
# ---------------------------------------------------------------------------

# RFC-5321-ish, deliberately permissive on the local part.
_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)+"
)

# National-ID detectors, keyed by locale. Kept conservative and anchored on
# word boundaries so they do not chew through arbitrary numeric identifiers.
_NATIONAL_ID_RES = {
    # US SSN — 3-2-4 with hyphen separators.
    "US": [re.compile(r"\b\d{3}-\d{2}-\d{4}\b")],
    "IN": [
        # Aadhaar — 4-4-4 spaced (first digit 2-9 per UIDAI spec).
        re.compile(r"\b[2-9]\d{3}\s\d{4}\s\d{4}\b"),
        # Aadhaar — 12 contiguous digits (first digit 2-9).
        re.compile(r"\b[2-9]\d{11}\b"),
        # PAN — 5 letters, 4 digits, 1 letter.
        re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
    ],
}

# PHONE — deliberately CONSERVATIVE. Requires phone-shaped formatting so we
# under-match rather than clobber ports, rule IDs, timestamps, or bare
# numeric identifiers in command lines. A match needs one of:
#   * a leading + country code with grouping separators (US 3-3-4, IN 5-5,
#     UK, etc.), OR
#   * a bare E.164 number (+ followed by 10-15 contiguous digits), OR
#   * a parenthesized area code, OR
#   * a 3-3-4 grouping with explicit . / space / - separators.
_PHONE_RES = [
    # +CC with separated groups, e.g. +1 415-555-2671, +44 20 7946 0958,
    # +91 98765 43210 (Indian mobile — 5+5 grouping).
    re.compile(r"\+\d{1,3}(?:[\s.\-]\d{2,5}){2,5}\b"),
    # Bare E.164, e.g. +14155552671, +919876543210.
    re.compile(r"\+\d{10,15}\b"),
    # Parenthesized area code, e.g. (415) 555-2671
    re.compile(r"\(\d{3}\)[\s.\-]?\d{3}[\s.\-]\d{4}\b"),
    # 3-3-4 with separators, e.g. 415-555-2671 / 415.555.2671 / 415 555 2671
    re.compile(r"\b\d{3}[.\s\-]\d{3}[.\s\-]\d{4}\b"),
]

# ---------------------------------------------------------------------------
# Emitted-token grammar (WO-H20)
#
# Every prefix ``_tokenize`` can produce. Structural identity leaves emit
# HOST / USER / INT-IP / OWNER (see the ``_tokenize("…")`` call sites); the
# free-text PII detectors emit EMAIL / NID / PHONE (the prefixes in
# ``_redact_free_text``'s ``detector_groups``). Kept as the single source so
# the pre-claim regex below can never drift from what ``_tokenize`` actually
# emits. If a new prefix is added, add it here too.
_IDENTITY_TOKEN_PREFIXES = ("HOST", "USER", "INT-IP", "OWNER")
_FREE_TEXT_TOKEN_PREFIXES = ("EMAIL", "NID", "PHONE")
_ALL_TOKEN_PREFIXES = _IDENTITY_TOKEN_PREFIXES + _FREE_TEXT_TOKEN_PREFIXES

# Shape of an already-emitted token: ``PREFIX-<12 lowercase hex>`` (the digest is
# ``sha256(...).hexdigest()[:12]``). Prefixes are alternated longest-first so the
# hyphenated ``INT-IP`` cannot be shadowed by a shorter alternative. Used by
# ``_redact_free_text`` to pre-claim token spans injected by an EARLIER
# anonymization pass, so no PII detector can re-consume/double-wrap them.
_TOKEN_SPAN_RE = re.compile(
    r"(?:"
    + "|".join(
        re.escape(p)
        for p in sorted(_ALL_TOKEN_PREFIXES, key=len, reverse=True)
    )
    + r")-[0-9a-f]{12}"
)

# Keys inside raw alert ``data`` whose STRING leaves are DETECTION-RELEVANT
# (command lines, file paths, process/image names). Their values are never
# passed through the PII redactor — guaranteeing structural preservation of
# LOLBin / malware indicators. Compared case-insensitively.
_DETECTION_EXCLUDE_KEYS = frozenset({
    "command",
    "commandline",
    "cmdline",
    "image",
    "path",
    "process",
    "parentimage",
    "parentcommandline",
    "exepath",
    "currentdirectory",
    # Defensive additions (Sysmon / EDR field names carrying cmd/path/script
    # content). Noted for qa-auditor review — see WO report.
    "originalfilename",
    "parentprocessname",
    "processname",
    "scriptblocktext",
    "executable",
})


# Keys inside raw alert ``data`` whose STRING leaf is a HOSTNAME / computer
# identity — including Windows Security-event and Sysmon field names. Their
# leaf value is tokenized with the HOST prefix (gated on ``anon_hostnames`` +
# ``scrub_data_field``). Compared case-insensitively.
_HOST_IDENTITY_KEYS = frozenset({
    "workstationname",
    "computername",
    "computer",
    "dnshostname",
    "hostname",
    "host",
    "agent_name",
    "agentname",
})

# Keys inside raw alert ``data`` whose STRING leaf is a USERNAME / account
# identity — including Windows Security-event field names (WO-H10). Their leaf
# value is tokenized with the USER prefix (gated on ``anon_usernames`` +
# ``scrub_data_field``). Compared case-insensitively.
_USER_IDENTITY_KEYS = frozenset({
    "targetusername",
    "subjectusername",
    "samaccountname",
    "accountname",
    "account_name",
    "user",
    "username",
    "srcuser",
    "dstuser",
    "src_user",
    "dst_user",
})

# Keys whose STRING leaf is an IP — tokenized (INT-IP) ONLY when the value is an
# internal address; external/attacker IPs pass through for IOC correlation.
_IP_IDENTITY_KEYS = frozenset({
    "srcip", "dstip", "src_ip", "dst_ip", "ip", "agent_ip", "agentip",
})

# Sentinel / non-identifying leaf values that are never worth tokenizing.
_SENTINEL_IDENTITY_VALUES = frozenset({
    "", "-", "n/a", "na", "unknown", "system", "local service",
    "network service", "anonymous logon",
})


class AlertAnonymizer:
    """Anonymizes client-sensitive fields in alert data before LLM submission."""

    # Default RFC1918 + loopback + link-local ranges
    _DEFAULT_INTERNAL_NETWORKS = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "fc00::/7",       # IPv6 unique local
        "fe80::/10",      # IPv6 link-local
    ]

    def __init__(self, config: dict, db=None):
        """
        Args:
            config: Platform config dict (reads 'anonymization' section).
            db: Optional SOCDatabase instance. When provided, every token ↔
                original mapping is persisted to the anon_mappings table for
                audit and correlation lookup.
        """
        anon_cfg = config.get("anonymization", {})
        self.enabled = anon_cfg.get("enabled", True)
        self.db = db

        # Build internal network list
        extra_ranges = anon_cfg.get("internal_ip_ranges", [])
        raw_ranges = self._DEFAULT_INTERNAL_NETWORKS + extra_ranges
        self.internal_networks = []
        for cidr in raw_ranges:
            try:
                self.internal_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                logger.warning("invalid_internal_range", cidr=cidr)

        # Per-field toggles (all on by default)
        fields = anon_cfg.get("fields", {})
        self.anon_hostnames = fields.get("hostnames", True)
        self.anon_internal_ips = fields.get("internal_ips", True)
        self.anon_usernames = fields.get("usernames", True)
        self.anon_asset_owner = fields.get("asset_owner", True)
        self.scrub_data_field = fields.get("scrub_data_field", True)

        # Free-text semantic PII redaction (AIS1) — always-on regex layer.
        self.free_text_pii = anon_cfg.get("free_text_pii", True)
        self.national_id_locales = anon_cfg.get("national_id_locales", ["US", "IN"])
        # Pre-resolve the active national-ID detector list once.
        self._national_id_res = []
        for loc in self.national_id_locales:
            self._national_id_res.extend(_NATIONAL_ID_RES.get(str(loc).upper(), []))

        # Salt for deterministic hashing — required for persistence
        import secrets as _secrets
        configured_salt = anon_cfg.get("hash_salt", "")
        if not configured_salt or configured_salt == "ai-soc-anon-v1":
            from src.database.store import is_multi_tenant
            if is_multi_tenant():
                raise RuntimeError(
                    "FATAL: anonymization.hash_salt is required in multi-tenant mode. "
                    "Set a persistent random value in config or ANONYMIZATION_SALT env var "
                    "to ensure consistent anonymization tokens across restarts."
                )
            self._salt = _secrets.token_hex(32)
            logger.warning("anonymization_salt_auto_generated",
                           message="Set anonymization.hash_salt in config for persistence across restarts")
        else:
            self._salt = configured_salt

        # Bidirectional lookup: token → original, original → token.
        # WO-H32 QA: ONE shared instance is hit by N parallel triage workers,
        # so the maps need a lock — writers (_tokenize) mutate under it and
        # iterating readers take a list() snapshot under it, otherwise a
        # concurrent insert raises "dictionary changed size during iteration"
        # mid-deanonymization. Thread-safety ONLY: tokens, redaction, and the
        # text that reaches the LLM are byte-identical to the unlocked code.
        self._to_token: dict[str, str] = {}
        self._to_original: dict[str, str] = {}
        self._maps_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def anonymize_alert_context(self, context: dict) -> dict:
        """Anonymize a full triage context dict (alert + enrichment + correlated).

        Returns a deep-copied dict with sensitive fields replaced by tokens.
        Does NOT mutate the original.
        """
        if not self.enabled:
            return context

        # Deep copy to avoid mutating the original enriched alert
        ctx = json.loads(json.dumps(context, default=str))

        alert = ctx.get("alert", {})
        enrichment = ctx.get("enrichment", {})

        # Collect known internal identifiers for data-field scrubbing
        known_values = {}  # original → token

        # -- Hostname --
        if self.anon_hostnames and alert.get("agent_name"):
            orig = alert["agent_name"]
            token = self._tokenize("HOST", orig)
            known_values[orig] = token
            alert["agent_name"] = token

        # -- Internal IPs --
        if self.anon_internal_ips:
            for field in ("agent_ip", "src_ip", "dst_ip"):
                ip_val = alert.get(field)
                if ip_val and self._is_internal_ip(ip_val):
                    token = self._tokenize("INT-IP", ip_val)
                    known_values[ip_val] = token
                    alert[field] = token

        # -- Usernames --
        if self.anon_usernames:
            for field in ("src_user", "dst_user"):
                user_val = alert.get(field)
                if user_val and user_val not in ("N/A", "", "SYSTEM", "LOCAL SERVICE"):
                    token = self._tokenize("USER", user_val)
                    known_values[user_val] = token
                    alert[field] = token

        # -- Asset owner --
        if self.anon_asset_owner and enrichment.get("asset_owner"):
            orig = enrichment["asset_owner"]
            if orig != "unknown":
                token = self._tokenize("OWNER", orig)
                known_values[orig] = token
                enrichment["asset_owner"] = token

        # -- Free-text semantic PII (AIS1): alert-level allowlist --
        for field in ("rule_description", "location"):
            if alert.get(field):
                alert[field] = self._redact_free_text(alert[field])

        # -- Scrub data field (selective replacement within raw JSON) --
        if self.scrub_data_field and alert.get("data"):
            data = alert["data"]
            if known_values:
                data = self._scrub_dict(data, known_values)
            # WO-H10: tokenize nested Windows identity fields
            # (TargetUserName/SubjectUserName/WorkstationName/…) AND redact
            # free-text PII in leaf strings, skipping detection keys. This
            # supersedes the prior PII-only pass so identifiers the free-text
            # regexes don't recognise (bare usernames/hostnames) are still
            # tokenized inside ``data``.
            data = self._anonymize_node(data)
            alert["data"] = data

        # -- Correlated events --
        for evt in ctx.get("correlated_events", []):
            if self.anon_hostnames and evt.get("agent_name"):
                evt["agent_name"] = self._tokenize("HOST", evt["agent_name"])
            if self.anon_internal_ips:
                for field in ("src_ip", "dst_ip"):
                    ip_val = evt.get(field)
                    if ip_val and self._is_internal_ip(ip_val):
                        evt[field] = self._tokenize("INT-IP", ip_val)
            if evt.get("rule_description"):
                evt["rule_description"] = self._redact_free_text(evt["rule_description"])

        # -- Anomaly details --
        for detail in enrichment.get("baseline_anomaly_details", []):
            dim = detail.get("dimension", "")
            val = detail.get("value", "")
            if not val:
                continue
            if dim == "agent" and self.anon_hostnames:
                detail["value"] = self._tokenize("HOST", val)
            elif dim == "src_ip" and self.anon_internal_ips and self._is_internal_ip(val):
                detail["value"] = self._tokenize("INT-IP", val)
            elif dim == "src_user" and self.anon_usernames:
                detail["value"] = self._tokenize("USER", val)

        ctx["alert"] = alert
        ctx["enrichment"] = enrichment
        return ctx

    def anonymize_query_results(self, results: list[dict]) -> list[dict]:
        """Anonymize query result hits before synthesis prompt."""
        if not self.enabled:
            return results

        results = json.loads(json.dumps(results, default=str))

        for result in results:
            sample_hits = result.get("sample_hits", [])
            for i, hit in enumerate(sample_hits):
                if self.anon_hostnames and hit.get("agent_name"):
                    hit["agent_name"] = self._tokenize("HOST", hit["agent_name"])
                if self.anon_internal_ips:
                    for field in ("src_ip", "dst_ip"):
                        ip_val = hit.get(field)
                        if ip_val and self._is_internal_ip(ip_val):
                            hit[field] = self._tokenize("INT-IP", ip_val)
                if self.anon_usernames:
                    for field in ("src_user", "dst_user"):
                        user_val = hit.get(field)
                        if user_val and user_val not in ("N/A", "", "SYSTEM", "LOCAL SERVICE"):
                            hit[field] = self._tokenize("USER", user_val)
                # Free-text semantic PII in leaf strings (skips detection keys).
                sample_hits[i] = self._redact_dict_free_text(hit)

        return results

    def anonymize_incident(self, incident: dict) -> dict:
        """Anonymize incident fields for plain-summary generation."""
        if not self.enabled:
            return incident

        incident = dict(incident)  # shallow copy

        if self.anon_hostnames:
            incident["affected_hosts"] = self._anonymize_json_list(
                incident.get("affected_hosts", "[]"), "HOST"
            )
        if self.anon_usernames:
            incident["affected_users"] = self._anonymize_json_list(
                incident.get("affected_users", "[]"), "USER"
            )
        if self.anon_internal_ips:
            incident["affected_ips"] = self._anonymize_ip_list(
                incident.get("affected_ips", "[]")
            )
        # Free-text semantic PII in incident summary fields that reach the LLM.
        for field in ("title", "description", "summary"):
            if isinstance(incident.get(field), str) and incident[field]:
                incident[field] = self._redact_free_text(incident[field])
        return incident

    def anonymize_fp_text(self, text: str) -> str:
        """Scrub known tokens from free-text fields (FP reasoning, enrichment summary)."""
        if not self.enabled or not text:
            return text
        # Snapshot under the lock (WO-H32: a parallel worker may _tokenize
        # mid-iteration); insertion order — and therefore replacement order
        # and output — is identical to iterating the live dict.
        with self._maps_lock:
            items = list(self._to_token.items())
        for original, token in items:
            text = text.replace(original, token)
        return text

    def deanonymize_text(self, text: str) -> str:
        """Restore original values in Claude's response text."""
        if not self.enabled or not text:
            return text
        # Snapshot under the lock (WO-H32) — see anonymize_fp_text.
        with self._maps_lock:
            items = list(self._to_original.items())
        for token, original in items:
            text = text.replace(token, original)
        return text

    def deanonymize_dict(self, d: dict) -> dict:
        """Recursively deanonymize all string values in a dict."""
        if not self.enabled:
            return d
        return json.loads(self.deanonymize_text(json.dumps(d, default=str)))

    def anonymize_generic(self, obj):
        """Anonymize an ARBITRARY nested structure (dict / list / str).

        Used by paths whose payload does not fit the ``{alert, enrichment,
        correlated_events}`` shape — notably the threat-hunt agent's aggregated
        intelligence context, which the previous implementation sent to the LLM
        with **zero** anonymization (WO-H10 Fix 1).

        Applies the same boundary as ``anonymize_alert_context``'s ``data``
        scrubbing: tokenizes hostname/username/internal-IP identity leaves
        (including nested Windows event fields), redacts free-text PII in the
        remaining string leaves, and preserves detection-relevant keys
        (command lines / file paths / process-image names) verbatim. Returns a
        deep copy — the input is not mutated. Restore with ``deanonymize_dict``
        / ``deanonymize_text``.
        """
        if not self.enabled:
            return obj
        return self._anonymize_node(
            json.loads(json.dumps(obj, default=str)))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _anonymize_node(self, node, key_lower: Optional[str] = None):
        """Recursively tokenize identity leaves and redact free-text PII.

        Boundary rules (identical guarantees to the alert-context path):
          * A leaf under a key in ``_DETECTION_EXCLUDE_KEYS`` is preserved
            verbatim — the structural guarantee that command lines / file paths
            / process-image names (which by design carry usernames) reach the
            LLM unchanged for detection.
          * A leaf under a hostname / username / internal-IP identity key is
            tokenized (gated on the matching ``anon_*`` toggle).
          * Every other string leaf goes through free-text PII redaction
            (gated on ``free_text_pii``).
        """
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                kl = str(k).lower()
                if kl in _DETECTION_EXCLUDE_KEYS:
                    out[k] = v  # detection-relevant subtree — preserve verbatim
                else:
                    out[k] = self._anonymize_node(v, kl)
            return out
        if isinstance(node, list):
            return [self._anonymize_node(item, key_lower) for item in node]
        if isinstance(node, str):
            return self._anonymize_identity_or_text(key_lower, node)
        return node

    def _anonymize_identity_or_text(self, key_lower: Optional[str],
                                    value: str) -> str:
        """Tokenize a string leaf if its key marks it as an identity, else
        redact free-text PII. See ``_anonymize_node`` for the boundary rules."""
        if not value:
            return value
        # Already an emitted token (e.g. a value the earlier ``_scrub_dict``
        # pass in ``anonymize_alert_context`` replaced with USER-/HOST-/INT-IP-):
        # never re-tokenize it — double-wrapping would break the reversible
        # ordered de-anonymization.
        if value in self._to_original:
            return value
        if key_lower in _HOST_IDENTITY_KEYS and self.anon_hostnames:
            if value.strip().lower() not in _SENTINEL_IDENTITY_VALUES:
                return self._tokenize("HOST", value)
            return value
        if key_lower in _USER_IDENTITY_KEYS and self.anon_usernames:
            if value.strip().lower() not in _SENTINEL_IDENTITY_VALUES:
                return self._tokenize("USER", value)
            return value
        if key_lower in _IP_IDENTITY_KEYS and self.anon_internal_ips:
            if self._is_internal_ip(value):
                return self._tokenize("INT-IP", value)
            return value  # external IP preserved for IOC correlation
        # Not an identity leaf → free-text PII redaction only.
        return self._redact_free_text(value)

    def _redact_free_text(self, text: str) -> str:
        """Redact semantic PII (email/phone/national-ID) from a free-text string.

        Reuses the reversible salted-token scheme (``_tokenize``) so every
        redaction is restored unchanged by ``deanonymize_text`` /
        ``deanonymize_dict``.

        SINGLE-PASS design (reversibility-critical): every detector scans the
        ORIGINAL text only. Matches are collected with a fixed priority
        (EMAIL → NATIONAL-ID → PHONE), overlapping candidates are dropped in
        priority order, and tokens are substituted in ONE left-to-right
        rebuild at the end. Within this call a detector never sees text that
        already contains a token it emitted, so no token can be
        re-consumed/double-wrapped by a LATER detector in the SAME call.

        CROSS-PASS immunity (WO-H20): that single-pass argument does NOT cover
        tokens injected by an EARLIER pass. The detection rule-fix path composes
        ``anonymize_generic(anonymize_fp_text(xml))``, so this method routinely
        runs over text that already carries ``PREFIX-<hex>`` tokens from the
        ``anonymize_fp_text`` pass. If such a token's 12-hex digest happens to be
        all-decimal with a leading 2-9 (≈1/346 tokens), the IN Aadhaar-12
        detector would re-match the digest and re-wrap it as ``…-NID-<hex>``,
        breaking ``deanonymize_text``. To prevent this, we pre-claim the spans of
        any already-emitted tokens BEFORE the detector loop; the existing
        ``_overlaps`` machinery then makes every PII detector skip them. These
        spans are only PROTECTED — never re-tokenized (they are already tokens).
        Genuine PII in real free text (an actual Aadhaar/SSN/email/phone that is
        NOT part of a token) is unaffected and still redacted.
        """
        if not self.enabled or not self.free_text_pii or not text:
            return text
        if not isinstance(text, str):
            return text

        # Detector groups in priority order: EMAIL first, NATIONAL-ID before
        # PHONE (structured IDs must win over the conservative phone matcher).
        detector_groups = [
            ("EMAIL", (_EMAIL_RE,)),
            ("NID", tuple(self._national_id_res)),
            ("PHONE", tuple(_PHONE_RES)),
        ]

        claimed: list[tuple[int, int]] = []  # non-overlapping accepted spans

        def _overlaps(s: int, e: int) -> bool:
            return any(not (e <= cs or s >= ce) for cs, ce in claimed)

        # WO-H20: pre-claim spans of tokens THIS instance actually emitted in an
        # earlier anonymize_fp_text / anonymize_generic pass. Seeding them into
        # ``claimed`` — before any detector runs — makes every PII detector skip
        # them via ``_overlaps``, so a token's all-decimal digest can never be
        # re-matched (e.g. by the Aadhaar-12 pattern) and double-wrapped, which
        # would break the reversible de-anonymization. They are protected only,
        # not re-tokenized.
        #
        # The ``in self._to_original`` gate is load-bearing: because decimal
        # digits are valid hex, a REAL 12-digit Aadhaar wearing a prefix costume
        # in the ORIGINAL free text (e.g. ``NID-234567890123``) is token-SHAPED
        # but was never emitted by this instance, so it is NOT in ``_to_original``
        # and MUST fall through to normal redaction. Only genuinely-emitted
        # tokens are immune — that is exactly the cross-pass case (the offending
        # token came from this same instance's earlier pass).
        for tok_m in _TOKEN_SPAN_RE.finditer(text):
            if tok_m.group(0) in self._to_original:
                claimed.append((tok_m.start(), tok_m.end()))

        matches: list[tuple[int, int, str, str]] = []  # (start, end, prefix, value)
        for prefix, regexes in detector_groups:
            for rx in regexes:
                for m in rx.finditer(text):
                    s, e = m.start(), m.end()
                    if _overlaps(s, e):
                        continue
                    claimed.append((s, e))
                    matches.append((s, e, prefix, m.group(0)))

        if not matches:
            return text

        # Single left-to-right rebuild; tokens are inserted here and never
        # re-scanned by any detector.
        matches.sort(key=lambda t: t[0])
        out: list[str] = []
        last = 0
        for s, e, prefix, value in matches:
            out.append(text[last:s])
            out.append(self._tokenize(prefix, value))
            last = e
        out.append(text[last:])
        return "".join(out)

    def _redact_dict_free_text(self, data, parent_key: Optional[str] = None):
        """Recursively redact free-text PII in leaf string values.

        Leaves whose key (case-insensitive) is in ``_DETECTION_EXCLUDE_KEYS``
        are passed through untouched — this is the structural guarantee that
        command lines, file paths, and process/image names are never
        tokenized as PII.
        """
        if not self.enabled or not self.free_text_pii:
            return data
        if isinstance(data, dict):
            out = {}
            for k, v in data.items():
                if str(k).lower() in _DETECTION_EXCLUDE_KEYS:
                    out[k] = v  # detection-relevant subtree — preserve verbatim
                else:
                    out[k] = self._redact_dict_free_text(v, k)
            return out
        if isinstance(data, list):
            return [self._redact_dict_free_text(item, parent_key) for item in data]
        if isinstance(data, str):
            return self._redact_free_text(data)
        return data

    def _tokenize(self, prefix: str, value: str) -> str:
        """Generate a deterministic opaque token for a value.

        Same input always produces the same token (SHA-256 prefix, 48-bit).
        Registers the mapping in both directions and persists to DB.
        """
        if value in self._to_token:
            return self._to_token[value]

        digest = hashlib.sha256(
            f"{self._salt}:{prefix}:{value}".encode()
        ).hexdigest()[:12]
        token = f"{prefix}-{digest}"

        with self._maps_lock:  # WO-H32: guard against snapshotting readers
            self._to_token[value] = token
            self._to_original[token] = value

        # Persist to Postgres for audit/correlation lookup
        if self.db is not None:
            try:
                self.db.save_anon_mapping(token, value, prefix)
            except Exception as e:
                logger.warning("anon_mapping_persist_failed", token=token, error=str(e))

        return token

    def _is_internal_ip(self, ip_str: str) -> bool:
        """Check if an IP belongs to a configured internal range."""
        try:
            addr = ipaddress.ip_address(ip_str)
            return any(addr in net for net in self.internal_networks)
        except (ValueError, TypeError):
            return False

    def _scrub_dict(self, data: dict, known_values: dict) -> dict:
        """Replace known sensitive values inside the raw data dict.

        Walks the dict recursively and does string replacement on
        leaf values. Preserves structure, commands, file paths, etc.
        """
        return json.loads(
            self._scrub_string(json.dumps(data, default=str), known_values)
        )

    def _scrub_string(self, text: str, known_values: dict) -> str:
        """Replace all occurrences of known values in a string."""
        for original, token in known_values.items():
            if original and len(original) >= 3:  # skip trivially short values
                text = text.replace(original, token)
        return text

    def _anonymize_json_list(self, json_str: str, prefix: str) -> str:
        """Parse a JSON array string, anonymize each element, return JSON."""
        try:
            items = json.loads(json_str) if isinstance(json_str, str) else json_str
            if not isinstance(items, list):
                return json_str
            return json.dumps([self._tokenize(prefix, str(item)) for item in items])
        except (json.JSONDecodeError, TypeError):
            return json_str

    def _anonymize_ip_list(self, json_str: str) -> str:
        """Anonymize IPs in a JSON array — internal only, external pass through."""
        try:
            items = json.loads(json_str) if isinstance(json_str, str) else json_str
            if not isinstance(items, list):
                return json_str
            result = []
            for ip in items:
                ip_s = str(ip)
                if self._is_internal_ip(ip_s):
                    result.append(self._tokenize("INT-IP", ip_s))
                else:
                    result.append(ip_s)  # external — keep for IOC correlation
            return json.dumps(result)
        except (json.JSONDecodeError, TypeError):
            return json_str
