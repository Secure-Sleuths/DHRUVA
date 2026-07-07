"""
Tenant configuration encryption — Fernet (AES-128-CBC) for secrets at rest.

Uses a TENANT_ENCRYPTION_KEY env var to encrypt/decrypt all tenant config
blobs stored in the tenants table. This protects multi-org credentials
(Wazuh passwords, API keys, Slack webhooks) at rest in the Postgres database.

Versioned ciphertext (M2 item 3)
--------------------------------
Ciphertext is stored as ``v<N>:<fernet_token>``. The ``v<N>`` tag records the
master *generation* a token was encrypted under. An untagged token is treated
as generation 1 (legacy data written before this scheme).

Two master generations can be active at once during rotation:
  - ``TENANT_ENCRYPTION_KEY``      — the new/current master (CURRENT_GENERATION)
  - ``TENANT_ENCRYPTION_KEY_OLD``  — the previous master (CURRENT_GENERATION-1)

``encrypt_config`` ALWAYS writes the current generation. ``decrypt_config`` can
resolve BOTH generations, so every row is readable at every instant of a
rotation (no unreadable window). A Fernet token is key-bound: a gen-1 token
returns ``InvalidToken`` under the gen-2 key, so no single row is ever
decryptable by two generations — the tag just makes selection explicit.

The current generation is **env-driven** via ``TENANT_KEY_GENERATION`` (default
1). EACH rotation bumps it, so a 2nd/3rd rotation correctly advances the
``v<N>:`` tag (1→2→3 …). At every generation N, ``TENANT_ENCRYPTION_KEY`` is the
gen-N master and ``TENANT_ENCRYPTION_KEY_OLD`` is the gen-(N-1) master. Older
generations than N-1 are intentionally NOT resolvable (they fail closed) — a
rotation must complete its re-encrypt sweep before the next one starts.
"""

import json
import os
import structlog
from cryptography.fernet import Fernet, InvalidToken

logger = structlog.get_logger(__name__)


def _current_generation() -> int:
    """The generation ``TENANT_ENCRYPTION_KEY`` represents / ``encrypt_config``
    writes, read from ``TENANT_KEY_GENERATION`` (default 1).

    Read at call time (not import time) so a rotation that bumps the env var
    plus ``_reset_fernet_cache()`` takes effect without a process restart, and
    so tests can advance the generation.
    """
    raw = os.environ.get("TENANT_KEY_GENERATION", "1")
    try:
        gen = int(raw)
    except (TypeError, ValueError):
        logger.warning("tenant_key_generation_invalid",
                       value=raw, msg="TENANT_KEY_GENERATION not an int — using 1")
        return 1
    return gen if gen >= 1 else 1


# Back-compat module attribute. NOTE: this is a snapshot taken at import time;
# code paths use the live ``_current_generation()`` instead. Kept so existing
# callers/tests that read ``CURRENT_GENERATION`` for the *import-time* value
# still work.
CURRENT_GENERATION = _current_generation()

# Cache of master Fernet instances keyed by generation number.
_fernet_by_gen: dict = {}


class TenantCryptoError(ValueError):
    """Raised when a tenant config cannot be decrypted (fail-closed signal)."""


def _master_key_for_gen(generation: int) -> str:
    """Return the raw master key string for a generation, or "" if unset.

    The CURRENT generation maps to ``TENANT_ENCRYPTION_KEY``; the previous
    generation maps to ``TENANT_ENCRYPTION_KEY_OLD``. Other generations are not
    configurable at runtime.
    """
    cur = _current_generation()
    if generation == cur:
        return os.environ.get("TENANT_ENCRYPTION_KEY", "")
    if generation == cur - 1:
        return os.environ.get("TENANT_ENCRYPTION_KEY_OLD", "")
    return ""


def _get_fernet(generation: int = None) -> Fernet:
    """Get or initialize the master Fernet cipher for a generation.

    In multi-tenant mode, refuses to start with a missing or invalid CURRENT
    key to prevent data loss (encrypted configs become undecryptable after
    restart). In single-tenant mode, auto-generates a key with a warning for
    backward compat. Non-current generations (e.g. the OLD rotation key) must
    be explicitly configured; if absent a KeyError is raised so the caller can
    fall through to the current generation.
    """
    if generation is None:
        generation = _current_generation()
    cached = _fernet_by_gen.get(generation)
    if cached is not None:
        return cached

    from src.database.store import is_multi_tenant
    _is_mt = is_multi_tenant()

    key = _master_key_for_gen(generation)

    if generation != _current_generation():
        # Rotation/old generations are optional. Absence is not fatal.
        if not key:
            raise KeyError(f"no master key configured for generation {generation}")
        try:
            f = Fernet(key.encode() if isinstance(key, str) else key)
        except Exception as e:
            raise RuntimeError(
                f"TENANT_ENCRYPTION_KEY_OLD (generation {generation}) is not a "
                f"valid Fernet key: {e}")
        _fernet_by_gen[generation] = f
        return f

    # ── current generation (TENANT_ENCRYPTION_KEY) ──
    if not key:
        if _is_mt:
            raise RuntimeError(
                "FATAL: TENANT_ENCRYPTION_KEY is required in multi-tenant mode. "
                "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\" "
                "and add it to your .env file."
            )
        # Single-tenant: auto-generate and warn
        key = Fernet.generate_key().decode()
        logger.warning(
            "tenant_encryption_key_generated",
            message="No TENANT_ENCRYPTION_KEY set. Generated a new key. "
                    "Set TENANT_ENCRYPTION_KEY in your .env file to persist "
                    "across restarts.")
        os.environ["TENANT_ENCRYPTION_KEY"] = key

    try:
        f = Fernet(key.encode() if isinstance(key, str) else key)
    except Exception:
        if _is_mt:
            raise RuntimeError(
                "FATAL: TENANT_ENCRYPTION_KEY is not a valid Fernet key. "
                "Previously encrypted tenant configs will be undecryptable. "
                "Fix the key in your .env file before restarting."
            )
        key = Fernet.generate_key().decode()
        f = Fernet(key.encode())
        logger.error(
            "tenant_encryption_key_invalid",
            message="TENANT_ENCRYPTION_KEY is not a valid Fernet key. "
                    "Generated a temporary key. Data encrypted with the old "
                    "key will not be decryptable.")

    _fernet_by_gen[generation] = f
    return f


def _reset_fernet_cache():
    """Clear the master Fernet cache and re-snapshot CURRENT_GENERATION.

    Call after any env change (notably ``TENANT_KEY_GENERATION``,
    ``TENANT_ENCRYPTION_KEY``, ``TENANT_ENCRYPTION_KEY_OLD``) so the new
    generation/keys take effect without a process restart. Refreshing the
    ``CURRENT_GENERATION`` module attribute keeps back-compat readers in sync.
    """
    global CURRENT_GENERATION
    _fernet_by_gen.clear()
    CURRENT_GENERATION = _current_generation()


def _derive_tenant_fernet(tenant_id: str, generation: int = None) -> Fernet:
    """Derive a per-tenant Fernet key from a master generation using HKDF."""
    import base64
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    if generation is None:
        generation = _current_generation()

    # Ensure the requested generation's master is loadable (raises KeyError
    # if an old generation isn't configured).
    _get_fernet(generation)
    master_str = _master_key_for_gen(generation)
    master_key = base64.urlsafe_b64decode(master_str.encode())
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"dhruva-tenant-{tenant_id}".encode(),
    ).derive(master_key)
    # Fernet key = url-safe base64 of 32 bytes
    fernet_key = base64.urlsafe_b64encode(derived)
    return Fernet(fernet_key)


def _split_version(encrypted: str) -> tuple[int, str]:
    """Parse a ``v<N>:<token>`` tag. Untagged tokens are generation 1."""
    if encrypted[:1] == "v":
        head, sep, rest = encrypted.partition(":")
        if sep and head[1:].isdigit():
            return int(head[1:]), rest
    return 1, encrypted


def is_current_generation(encrypted: str, tenant_id: str = None) -> bool:
    """Return True if a token is already at the CURRENT generation.

    Used by the rotation tool for idempotency: a token is "current" iff it is
    tagged ``v<CURRENT_GENERATION>:`` AND it decrypts under the current master
    alone (not via the OLD rotation key). A token written under the old master
    but coincidentally carrying the current tag would fail the decrypt check.
    """
    if not encrypted:
        return True  # nothing to rotate
    cur = _current_generation()
    gen, token = _split_version(encrypted)
    if gen != cur:
        return False
    token_bytes = token.encode("utf-8")
    # Try the CURRENT generation only (per-tenant derived, then global).
    candidates = []
    if tenant_id:
        try:
            candidates.append(_derive_tenant_fernet(tenant_id, cur))
        except Exception:
            pass
    try:
        candidates.append(_get_fernet(cur))
    except Exception:
        pass
    for f in candidates:
        try:
            f.decrypt(token_bytes)
            return True
        except InvalidToken:
            continue
    return False


def encrypt_config(config: dict, tenant_id: str = None) -> str:
    """Encrypt a tenant config dict to a version-tagged Fernet token string.

    Always writes the CURRENT generation tag (``v<N>:``).
    """
    cur = _current_generation()
    f = (_derive_tenant_fernet(tenant_id, cur)
         if tenant_id else _get_fernet(cur))
    plaintext = json.dumps(config, default=str).encode("utf-8")
    token = f.encrypt(plaintext).decode("utf-8")
    return f"v{cur}:{token}"


def decrypt_config(encrypted: str, tenant_id: str = None) -> dict:
    """Decrypt a (possibly version-tagged) Fernet token to a config dict.

    Resolution order for a tagged token at generation ``g``:
      1. per-tenant key derived from generation ``g``
      2. per-tenant key derived from the OTHER available generation (rotation)
      3. global (non-derived) master key of generation ``g`` — legacy data
         encrypted before per-tenant key derivation
      4. global master key of the OTHER generation

    Returns ``{}`` for empty input (legitimately-empty tenant config). Raises
    ``TenantCryptoError`` (a ``ValueError`` subclass) only on a GENUINE decrypt
    failure — wrong/rotated/corrupt token under every available key. Callers
    rely on this to fail closed; an empty config and a failed decrypt are
    distinct outcomes.
    """
    if not encrypted:
        return {}

    tagged_gen, token = _split_version(encrypted)
    token_bytes = token.encode("utf-8")

    # Candidate generations to try: the tagged one first, then the other
    # available master (so rotation works regardless of tag direction).
    cur = _current_generation()
    gens = [tagged_gen]
    for g in (cur, cur - 1):
        if g not in gens:
            gens.append(g)

    last_err: Exception | None = None

    for gen in gens:
        # (a) per-tenant derived key for this generation
        if tenant_id:
            try:
                f = _derive_tenant_fernet(tenant_id, gen)
            except KeyError:
                f = None  # generation's master not configured — skip
            except Exception as e:
                last_err = e
                f = None
            if f is not None:
                try:
                    return json.loads(f.decrypt(token_bytes))
                except InvalidToken as e:
                    last_err = e
                except json.JSONDecodeError as e:
                    # Decrypt succeeded but payload is not JSON — corrupt.
                    last_err = e

        # (b) global (non-derived) master key for this generation —
        # legacy data encrypted before per-tenant key derivation existed.
        try:
            f = _get_fernet(gen)
        except (KeyError, RuntimeError):
            f = None
        if f is not None:
            try:
                return json.loads(f.decrypt(token_bytes))
            except InvalidToken as e:
                last_err = e
            except json.JSONDecodeError as e:
                last_err = e

    logger.error("tenant_config_decrypt_failed",
                 tenant_id=tenant_id, error=str(last_err))
    raise TenantCryptoError(
        f"Failed to decrypt tenant config: {last_err}")
