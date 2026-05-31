"""Tests for keyring module - encrypted API key storage."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from vibeguard.core import keyring


@pytest.fixture
def temp_keys_dir(tmp_path: Path) -> Path:
    """Create a temporary keys directory."""
    keys_dir = tmp_path / ".vibeguard" / "keys"
    keys_dir.mkdir(parents=True)
    return keys_dir


@pytest.fixture(autouse=True)
def mock_keys_dir(tmp_path: Path) -> None:
    """Mock the keys directory to use temp path."""
    keys_dir = tmp_path / ".vibeguard" / "keys"
    master_key = keys_dir / "master.key"
    providers_file = keys_dir / "providers.enc"

    with (
        patch.object(keyring, "KEYS_DIR", keys_dir),
        patch.object(keyring, "MASTER_KEY_FILE", master_key),
        patch.object(keyring, "PROVIDERS_FILE", providers_file),
    ):
        yield


class TestListProviders:
    """Tests for list_providers()."""

    def test_returns_all_supported_providers(self) -> None:
        """Should return all supported provider names."""
        providers = keyring.list_providers()
        assert "openai" in providers
        assert "anthropic" in providers
        assert "google" in providers
        assert len(providers) >= 4

    def test_returns_list(self) -> None:
        """Should return a list type."""
        providers = keyring.list_providers()
        assert isinstance(providers, list)


class TestSaveKey:
    """Tests for save_key()."""

    def test_saves_openai_key(self) -> None:
        """Should save an OpenAI API key."""
        keyring.save_key("openai", "sk-test-key-12345")
        loaded = keyring.load_key("openai")
        assert loaded == "sk-test-key-12345"

    def test_saves_anthropic_key(self) -> None:
        """Should save an Anthropic API key."""
        keyring.save_key("anthropic", "sk-ant-test-key")
        loaded = keyring.load_key("anthropic")
        assert loaded == "sk-ant-test-key"

    def test_overwrites_existing_key(self) -> None:
        """Should overwrite an existing key."""
        keyring.save_key("openai", "old-key")
        keyring.save_key("openai", "new-key")
        loaded = keyring.load_key("openai")
        assert loaded == "new-key"

    def test_raises_for_unknown_provider(self) -> None:
        """Should raise ValueError for unknown provider."""
        with pytest.raises(ValueError, match="Unknown provider"):
            keyring.save_key("unknown_provider", "some-key")

    def test_preserves_other_keys(self) -> None:
        """Should preserve other keys when saving a new one."""
        keyring.save_key("openai", "openai-key")
        keyring.save_key("anthropic", "anthropic-key")

        assert keyring.load_key("openai") == "openai-key"
        assert keyring.load_key("anthropic") == "anthropic-key"


class TestLoadKey:
    """Tests for load_key()."""

    def test_returns_none_for_unconfigured_provider(self) -> None:
        """Should return None if provider has no key."""
        loaded = keyring.load_key("openai")
        assert loaded is None

    def test_returns_saved_key(self) -> None:
        """Should return the saved key."""
        keyring.save_key("google", "google-api-key")
        loaded = keyring.load_key("google")
        assert loaded == "google-api-key"


class TestLoadAllKeys:
    """Tests for load_all_keys()."""

    def test_returns_empty_when_no_keys(self) -> None:
        """Should return empty ProviderKeys when no keys stored."""
        keys = keyring.load_all_keys()
        assert keys.openai is None
        assert keys.anthropic is None

    def test_returns_all_saved_keys(self) -> None:
        """Should return all saved keys."""
        keyring.save_key("openai", "openai-key")
        keyring.save_key("anthropic", "anthropic-key")

        keys = keyring.load_all_keys()
        assert keys.openai == "openai-key"
        assert keys.anthropic == "anthropic-key"
        assert keys.google is None


class TestDeleteKey:
    """Tests for delete_key()."""

    def test_deletes_existing_key(self) -> None:
        """Should delete an existing key and return True."""
        keyring.save_key("openai", "test-key")
        result = keyring.delete_key("openai")

        assert result is True
        assert keyring.load_key("openai") is None

    def test_returns_false_for_nonexistent_key(self) -> None:
        """Should return False if key doesn't exist."""
        result = keyring.delete_key("openai")
        assert result is False

    def test_raises_for_unknown_provider(self) -> None:
        """Should raise ValueError for unknown provider."""
        with pytest.raises(ValueError, match="Unknown provider"):
            keyring.delete_key("unknown_provider")

    def test_preserves_other_keys(self) -> None:
        """Should preserve other keys when deleting one."""
        keyring.save_key("openai", "openai-key")
        keyring.save_key("anthropic", "anthropic-key")

        keyring.delete_key("openai")

        assert keyring.load_key("openai") is None
        assert keyring.load_key("anthropic") == "anthropic-key"


class TestGetConfiguredProviders:
    """Tests for get_configured_providers()."""

    def test_returns_empty_list_when_no_keys(self) -> None:
        """Should return empty list when no keys configured."""
        providers = keyring.get_configured_providers()
        assert providers == []

    def test_returns_configured_providers(self) -> None:
        """Should return list of providers with keys."""
        keyring.save_key("openai", "openai-key")
        keyring.save_key("google", "google-key")

        providers = keyring.get_configured_providers()
        assert "openai" in providers
        assert "google" in providers
        assert "anthropic" not in providers


class TestEncryption:
    """Tests for encryption/decryption."""

    def test_key_is_encrypted_on_disk(self, tmp_path: Path) -> None:
        """Should encrypt keys when saving to disk."""
        keyring.save_key("openai", "secret-api-key")

        # Read raw file content
        providers_file = tmp_path / ".vibeguard" / "keys" / "providers.enc"
        raw_content = providers_file.read_bytes()

        # Should not contain plaintext key
        assert b"secret-api-key" not in raw_content

    def test_encryption_roundtrip(self) -> None:
        """Should correctly decrypt encrypted keys."""
        original_key = "sk-very-secret-key-12345"
        keyring.save_key("openai", original_key)
        loaded = keyring.load_key("openai")
        assert loaded == original_key

    def test_handles_unicode_keys(self) -> None:
        """Should handle keys with unicode characters."""
        unicode_key = "sk-test-key-\u00e9\u00e8\u00ea"
        keyring.save_key("openai", unicode_key)
        loaded = keyring.load_key("openai")
        assert loaded == unicode_key


class TestMasterKey:
    """Tests for master key management."""

    def test_creates_master_key_on_first_use(self, tmp_path: Path) -> None:
        """Should create master key file on first save."""
        master_key_file = tmp_path / ".vibeguard" / "keys" / "master.key"
        assert not master_key_file.exists()

        keyring.save_key("openai", "test-key")

        assert master_key_file.exists()

    def test_reuses_existing_master_key(self, tmp_path: Path) -> None:
        """Should reuse existing master key."""
        keyring.save_key("openai", "key1")
        master_key_file = tmp_path / ".vibeguard" / "keys" / "master.key"
        original_key = master_key_file.read_bytes()

        keyring.save_key("anthropic", "key2")
        reused_key = master_key_file.read_bytes()

        assert original_key == reused_key
