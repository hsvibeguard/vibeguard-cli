"""Tests for keys CLI command."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from vibeguard.cli.main import app
from vibeguard.core import keyring

runner = CliRunner()


@pytest.fixture(autouse=True)
def mock_keys_storage(tmp_path) -> None:  # type: ignore[no-untyped-def]
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


class TestKeysSet:
    """Tests for 'vibeguard keys set' command."""

    def test_sets_openai_key(self) -> None:
        """Should set an OpenAI API key."""
        result = runner.invoke(app, ["keys", "set", "openai", "sk-test-key"])
        assert result.exit_code == 0
        assert "saved" in result.output.lower()
        assert keyring.load_key("openai") == "sk-test-key"

    def test_sets_anthropic_key(self) -> None:
        """Should set an Anthropic API key."""
        result = runner.invoke(app, ["keys", "set", "anthropic", "sk-ant-test"])
        assert result.exit_code == 0
        assert keyring.load_key("anthropic") == "sk-ant-test"

    def test_rejects_unknown_provider(self) -> None:
        """Should reject unknown provider."""
        result = runner.invoke(app, ["keys", "set", "unknown", "some-key"])
        assert result.exit_code != 0
        assert "error" in result.output.lower()


class TestKeysGet:
    """Tests for 'vibeguard keys get' command."""

    def test_shows_masked_key(self) -> None:
        """Should show masked key by default."""
        keyring.save_key("openai", "sk-very-long-secret-key-12345")
        result = runner.invoke(app, ["keys", "get", "openai"])

        assert result.exit_code == 0
        assert "sk-very-" in result.output
        assert "2345" in result.output
        assert "very-long-secret-key" not in result.output

    def test_shows_full_key_with_flag(self) -> None:
        """Should show full key with --show flag."""
        keyring.save_key("openai", "sk-secret-key")
        result = runner.invoke(app, ["keys", "get", "openai", "--show"])

        assert result.exit_code == 0
        assert "sk-secret-key" in result.output

    def test_shows_not_configured(self) -> None:
        """Should indicate when key is not configured."""
        result = runner.invoke(app, ["keys", "get", "openai"])

        assert result.exit_code == 0
        assert "not configured" in result.output.lower()

    def test_rejects_unknown_provider(self) -> None:
        """Should reject unknown provider."""
        result = runner.invoke(app, ["keys", "get", "unknown"])
        assert result.exit_code != 0
        assert "error" in result.output.lower()


class TestKeysDelete:
    """Tests for 'vibeguard keys delete' command."""

    def test_deletes_existing_key(self) -> None:
        """Should delete an existing key."""
        keyring.save_key("openai", "sk-test")
        result = runner.invoke(app, ["keys", "delete", "openai"])

        assert result.exit_code == 0
        assert "deleted" in result.output.lower()
        assert keyring.load_key("openai") is None

    def test_handles_nonexistent_key(self) -> None:
        """Should handle deletion of non-existent key."""
        result = runner.invoke(app, ["keys", "delete", "openai"])

        assert result.exit_code == 0
        assert "no key" in result.output.lower()

    def test_rejects_unknown_provider(self) -> None:
        """Should reject unknown provider."""
        result = runner.invoke(app, ["keys", "delete", "unknown"])
        assert result.exit_code != 0


class TestKeysList:
    """Tests for 'vibeguard keys list' command."""

    def test_lists_all_providers(self) -> None:
        """Should list all supported providers."""
        result = runner.invoke(app, ["keys", "list"])

        assert result.exit_code == 0
        assert "openai" in result.output.lower()
        assert "anthropic" in result.output.lower()
        assert "google" in result.output.lower()

    def test_shows_configured_status(self) -> None:
        """Should show which providers are configured."""
        keyring.save_key("openai", "sk-test")
        result = runner.invoke(app, ["keys", "list"])

        assert result.exit_code == 0
        assert "configured" in result.output.lower()
        assert "not set" in result.output.lower()

    def test_shows_storage_location(self) -> None:
        """Should mention storage location."""
        result = runner.invoke(app, ["keys", "list"])

        assert result.exit_code == 0
        assert ".vibeguard/keys" in result.output
