"""
Guidance Loader - Loads and manages SOC guidance documents.
These encode institutional knowledge that aligns agents with your team's judgment.

Supports both plaintext YAML (development) and encrypted .enc files (production builds).
Encrypted files are decrypted at runtime using a key derived from platform constants.
"""

import base64
import yaml
import json
import structlog
from pathlib import Path
from typing import Optional
from cachetools import TTLCache

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

logger = structlog.get_logger(__name__)

# -- Guidance decryption (mirrors scripts/build_hardening/encrypt_guidance.py) --

_PLATFORM_ANCHOR = b"YGFqaFqnOyHtBSl0n/lK0vgBSziBL73VXd73GQtvTI8="
_BUILD_SALT = b"dhruva-guidance-v4.5"


def _derive_guidance_key() -> bytes:
    """Derive Fernet key for encrypted guidance files."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_BUILD_SALT,
        info=b"guidance-encryption",
    )
    raw_key = hkdf.derive(_PLATFORM_ANCHOR)
    return base64.urlsafe_b64encode(raw_key)


def _decrypt_guidance(enc_path: Path) -> dict:
    """Decrypt a .enc guidance file and return parsed dict."""
    key = _derive_guidance_key()
    fernet = Fernet(key)
    ciphertext = enc_path.read_bytes()
    plaintext = fernet.decrypt(ciphertext)
    return json.loads(plaintext)


class GuidanceLoader:
    """
    Loads guidance documents (playbooks, risk criteria, escalation logic)
    and formats them for injection into agent prompts.
    """

    def __init__(self, config: dict):
        guidance_cfg = config.get("guidance", {})
        self.base_path = Path(guidance_cfg.get("base_path", "./config/guidance"))
        self.risk_criteria_file = guidance_cfg.get("risk_criteria", "risk_criteria.yaml")
        self.escalation_file = guidance_cfg.get("escalation_logic", "escalation_logic.yaml")
        self.playbooks_dir = guidance_cfg.get("playbooks_dir", "playbooks")

        self._cache = TTLCache(maxsize=50, ttl=300)  # 5-min cache
        self._playbooks: dict = {}
        self._risk_criteria: dict = {}
        self._escalation_logic: dict = {}

        self._load_all()

    def _load_all(self):
        """Load all guidance documents."""
        self._load_risk_criteria()
        self._load_escalation_logic()
        self._load_playbooks()
        self._compute_guidance_hashes()
        logger.info("guidance_loaded",
                     playbooks=len(self._playbooks),
                     risk_criteria=bool(self._risk_criteria),
                     escalation_logic=bool(self._escalation_logic))

    def _load_yaml(self, path: Path, required: bool = False) -> dict:
        """Load a guidance file. Tries encrypted (.enc) first, then plaintext YAML.

        Production builds ship only .enc files. Development uses plaintext YAML.
        If required=True, raise on failure instead of returning empty dict.
        """
        # Try encrypted version first (production builds)
        enc_path = path.with_suffix(".enc")
        if enc_path.exists():
            try:
                data = _decrypt_guidance(enc_path)
                if required and not data:
                    raise ValueError(f"Guidance file is empty: {enc_path}")
                return data
            except InvalidToken:
                logger.error("guidance_decryption_failed", path=str(enc_path))
                if required:
                    raise SystemExit(
                        f"Failed to decrypt guidance file {enc_path}. "
                        f"Build may be corrupted — contact SecureSleuths."
                    )
                return {}
            except Exception as e:
                if required:
                    logger.critical("required_guidance_load_failed",
                                    path=str(enc_path), error=str(e))
                    raise SystemExit(
                        f"Failed to load required guidance file {enc_path}: {e}"
                    )
                logger.error("guidance_load_error", path=str(enc_path), error=str(e))
                return {}

        # Fall back to plaintext YAML (development mode)
        try:
            with open(path) as f:
                data = yaml.safe_load(f) or {}
                if required and not data:
                    raise ValueError(f"Guidance file is empty: {path}")
                return data
        except FileNotFoundError:
            if required:
                logger.critical("required_guidance_file_missing", path=str(path))
                raise SystemExit(
                    f"Required guidance file not found: {path}. "
                    f"Platform cannot start without risk criteria and escalation logic."
                )
            logger.warning("guidance_file_not_found", path=str(path))
            return {}
        except SystemExit:
            raise
        except Exception as e:
            if required:
                logger.critical("required_guidance_load_failed",
                                path=str(path), error=str(e))
                raise SystemExit(
                    f"Failed to load required guidance file {path}: {e}"
                )
            logger.error("guidance_load_error", path=str(path), error=str(e))
            return {}

    def _load_risk_criteria(self):
        self._risk_criteria = self._load_yaml(
            self.base_path / self.risk_criteria_file, required=True
        )

    def _load_escalation_logic(self):
        self._escalation_logic = self._load_yaml(
            self.base_path / self.escalation_file, required=True
        )

    def _load_playbooks(self):
        """Load all playbooks from the playbooks directory.
        Supports both .enc (production) and .yaml (development) formats.
        """
        pb_dir = self.base_path / self.playbooks_dir
        if not pb_dir.exists():
            logger.warning("playbooks_dir_not_found", path=str(pb_dir))
            return

        # Try encrypted playbooks first (production)
        enc_files = list(pb_dir.glob("*.enc"))
        if enc_files:
            for enc_file in enc_files:
                try:
                    data = _decrypt_guidance(enc_file)
                    name = enc_file.stem
                    self._playbooks[name] = data
                except Exception as e:
                    logger.error("playbook_load_failed",
                                 file=str(enc_file), error=str(e))
            return

        # Fall back to plaintext YAML (development)
        for pb_file in pb_dir.glob("*.yaml"):
            try:
                data = self._load_yaml(pb_file)
                name = pb_file.stem
                self._playbooks[name] = data
            except Exception as e:
                logger.error("playbook_load_failed",
                             file=str(pb_file), error=str(e))

    def _compute_guidance_hashes(self):
        """Compute SHA-256 hashes of guidance files for audit trail."""
        import hashlib
        self._guidance_hashes = {}
        for name, path in [
            ("risk_criteria", self.base_path / self.risk_criteria_file),
            ("escalation_logic", self.base_path / self.escalation_file),
        ]:
            try:
                content = path.read_bytes()
                self._guidance_hashes[name] = hashlib.sha256(content).hexdigest()[:16]
            except Exception:
                self._guidance_hashes[name] = "unavailable"
        # Hash all playbook files combined
        pb_dir = self.base_path / self.playbooks_dir
        if pb_dir.exists():
            combined = b""
            for pb_file in sorted(pb_dir.glob("*.yaml")):
                try:
                    combined += pb_file.read_bytes()
                except Exception:
                    pass
            if combined:
                self._guidance_hashes["playbooks"] = hashlib.sha256(combined).hexdigest()[:16]

    def get_version_info(self) -> dict:
        """Return guidance version info for decision audit trail."""
        from src.agents.prompts import PROMPT_VERSION
        return {
            "prompt_version": PROMPT_VERSION,
            "guidance_hashes": getattr(self, "_guidance_hashes", {}),
        }

    def reload(self):
        """Force reload all guidance documents."""
        self._cache.clear()
        self._load_all()

    # ----- Formatted Output for Prompts -----

    def get_risk_criteria(self) -> dict:
        """Get raw risk criteria dict."""
        return self._risk_criteria

    def get_risk_criteria_text(self) -> str:
        """Format risk criteria for inclusion in agent prompts."""
        cache_key = "risk_criteria_text"
        if cache_key in self._cache:
            return self._cache[cache_key]

        rc = self._risk_criteria
        lines = ["## Risk Criteria\n"]

        # Asset criticality
        lines.append("### Asset Criticality Tiers")
        for tier, cfg in rc.get("asset_criticality", {}).items():
            lines.append(f"- **{tier}** (multiplier: {cfg.get('risk_multiplier', 1.0)}): "
                         f"{cfg.get('description', '')}")

        # User risk profiles
        lines.append("\n### User Risk Profiles")
        for profile, cfg in rc.get("user_risk_profiles", {}).items():
            lines.append(f"- **{profile}** (multiplier: {cfg.get('risk_multiplier', 1.0)}): "
                         f"{cfg.get('description', '')}")

        # MITRE priorities
        lines.append("\n### Critical MITRE Techniques")
        techniques = rc.get("mitre_attack_priority", {}).get("critical_techniques", [])
        lines.append(f"Techniques requiring elevated attention: {', '.join(techniques)}")

        # Time context
        lines.append("\n### Time-Based Risk Adjustments")
        adj = rc.get("time_context", {}).get("risk_adjustments", {})
        for k, v in adj.items():
            lines.append(f"- {k}: {v}")

        # Risk formula
        formula = rc.get("composite_risk_formula", "")
        if formula:
            lines.append(f"\n### Risk Score Formula\n{formula}")

        text = "\n".join(lines)
        self._cache[cache_key] = text
        return text

    def get_escalation_logic_text(self) -> str:
        """Format escalation logic for inclusion in agent prompts."""
        cache_key = "escalation_text"
        if cache_key in self._cache:
            return self._cache[cache_key]

        el = self._escalation_logic
        lines = ["## Escalation Logic\n"]

        # Auto-close conditions
        lines.append("### Auto-Close Conditions (ALL conditions must be true)")
        for condition in el.get("auto_close_conditions", []):
            lines.append(f"\n**{condition['name']}** (min confidence: {condition.get('confidence_floor', 0.85)})")
            for c in condition.get("conditions", []):
                lines.append(f"  - {c.get('field')} {c.get('operator', 'matches')} {c.get('value', c.get('match', c.get('in', c.get('not_in', ''))))}")

        # Always escalate
        lines.append("\n### ALWAYS Escalate (ANY condition triggers)")
        for condition in el.get("always_escalate", []):
            lines.append(f"\n**{condition['name']}**")
            for c in condition.get("conditions", []):
                lines.append(f"  - {c.get('field')} {c.get('operator', 'matches')} {c.get('value', c.get('match', c.get('in', '')))}")

        text = "\n".join(lines)
        self._cache[cache_key] = text
        return text

    def get_all_playbooks(self) -> dict:
        """Get all loaded playbooks."""
        return self._playbooks

    def get_playbook(self, name: str) -> Optional[dict]:
        """Get a specific playbook by name."""
        return self._playbooks.get(name)

    def format_playbook(self, name: str) -> str:
        """Format a playbook for inclusion in agent prompts."""
        cache_key = f"playbook_{name}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        pb = self._playbooks.get(name)
        if not pb:
            return "No playbook available."

        lines = [f"## Investigation Playbook: {pb.get('name', name)}\n"]

        # Investigation steps
        lines.append("### Investigation Steps")
        for step in pb.get("investigation_steps", []):
            lines.append(f"\n**Step {step['step']}: {step['name']}**")
            if step.get("query_template"):
                lines.append(f"Query: ```{step['query_template'][:200]}...```")
            lines.append(f"Assessment criteria:\n{step.get('assess', '')}")

        # Verdict criteria
        lines.append("\n### Verdict Criteria")
        for verdict_type, criteria in pb.get("verdict_criteria", {}).items():
            lines.append(f"\n**{verdict_type}**:")
            for c in criteria:
                lines.append(f"  - {c}")

        # Recommended actions
        lines.append("\n### Recommended Actions")
        for action_type, actions in pb.get("recommended_actions", {}).items():
            lines.append(f"\n**{action_type}**:")
            for a in actions:
                lines.append(f"  - {a}")

        text = "\n".join(lines)
        self._cache[cache_key] = text
        return text
