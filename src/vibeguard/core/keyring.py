"""Encrypted API key storage using Fernet.

Keys are stored encrypted in ~/.vibeguard/keys/ and never leave the local machine.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel

if TYPE_CHECKING:
    from cryptography.fernet import Fernet

# Storage locations
KEYS_DIR = Path.home() / ".vibeguard" / "keys"
MASTER_KEY_FILE = KEYS_DIR / "master.key"
PROVIDERS_FILE = KEYS_DIR / "providers.enc"


class ProviderKeys(BaseModel):
    """Container for provider API keys."""

    openai: str | None = None
    anthropic: str | None = None
    google: str | None = None
    azure_openai: str | None = None
    mistral: str | None = None
    groq: str | None = None


def _ensure_keys_dir() -> None:
    """Ensure the keys directory exists with proper permissions."""
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    # Set directory permissions to owner only (700)
    try:
        KEYS_DIR.chmod(stat.S_IRWXU)
    except OSError:
        # Windows may not support chmod fully
        pass


def _ensure_master_key() -> bytes:
    """Get or create the master encryption key."""
    from cryptography.fernet import Fernet

    _ensure_keys_dir()

    if MASTER_KEY_FILE.exists():
        return MASTER_KEY_FILE.read_bytes()

    # Generate new key
    key = Fernet.generate_key()
    MASTER_KEY_FILE.write_bytes(key)

    # Restrict permissions (owner only - 600)
    try:
        MASTER_KEY_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        # Windows may not support chmod fully
        pass

    return key


def _get_fernet() -> Fernet:
    """Get Fernet instance with master key."""
    from cryptography.fernet import Fernet

    return Fernet(_ensure_master_key())


def save_key(provider: str, api_key: str) -> None:
    """Save an API key for a provider.

    Args:
        provider: Provider name (openai, anthropic, google, etc.)
        api_key: The API key to store

    Raises:
        ValueError: If provider is not supported
    """
    keys = load_all_keys()

    # Validate provider name
    if provider not in ProviderKeys.model_fields:
        raise ValueError(f"Unknown provider: {provider}")

    setattr(keys, provider, api_key)

    # Encrypt and save
    fernet = _get_fernet()
    encrypted = fernet.encrypt(keys.model_dump_json().encode("utf-8"))

    _ensure_keys_dir()
    PROVIDERS_FILE.write_bytes(encrypted)

    # Restrict permissions (owner only - 600)
    try:
        PROVIDERS_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        # Windows may not support chmod fully
        pass


def load_key(provider: str) -> str | None:
    """Load an API key for a provider.

    Args:
        provider: Provider name

    Returns:
        The API key or None if not configured
    """
    keys = load_all_keys()
    return getattr(keys, provider, None)


def load_all_keys() -> ProviderKeys:
    """Load all stored API keys.

    Returns:
        ProviderKeys with all configured keys
    """
    if not PROVIDERS_FILE.exists():
        return ProviderKeys()

    try:
        from cryptography.fernet import InvalidToken

        fernet = _get_fernet()
        decrypted = fernet.decrypt(PROVIDERS_FILE.read_bytes())
        return ProviderKeys.model_validate_json(decrypted)
    except (InvalidToken, json.JSONDecodeError):
        # Corrupted or wrong key - return empty
        return ProviderKeys()


def delete_key(provider: str) -> bool:
    """Delete an API key for a provider.

    Args:
        provider: Provider name

    Returns:
        True if key was deleted, False if not configured

    Raises:
        ValueError: If provider is not supported
    """
    if provider not in ProviderKeys.model_fields:
        raise ValueError(f"Unknown provider: {provider}")

    keys = load_all_keys()

    if getattr(keys, provider) is None:
        return False

    setattr(keys, provider, None)

    # Re-encrypt and save
    fernet = _get_fernet()
    encrypted = fernet.encrypt(keys.model_dump_json().encode("utf-8"))
    PROVIDERS_FILE.write_bytes(encrypted)

    return True


def list_providers() -> list[str]:
    """List all supported providers.

    Returns:
        List of provider names
    """
    return list(ProviderKeys.model_fields.keys())


def get_configured_providers() -> list[str]:
    """List providers with configured keys.

    Returns:
        List of provider names that have keys set
    """
    keys = load_all_keys()
    return [p for p in list_providers() if getattr(keys, p) is not None]
