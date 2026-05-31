"""Tests for license gating module."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from vibeguard.core import auth as auth_module
from vibeguard.core import keyring
from vibeguard.core.license import (
    ProFeatureError,
    get_license_status,
    has_llm_configured,
    is_pro_licensed,
    require_llm_key,
    require_patch_capability,
    require_pro_license,
)
from vibeguard.models.auth import AuthToken


@pytest.fixture(autouse=True)
def mock_keys_storage(tmp_path):  # type: ignore[no-untyped-def]
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


@pytest.fixture
def mock_valid_token():
    """Mock a valid auth token."""
    token = AuthToken(
        token="test-token",
        expires_at=datetime.now(UTC) + timedelta(days=7),
        entitlements=["pro.patch", "pro.apply"],
        plan="pro",
    )
    with patch.object(auth_module, "get_cached_token", return_value=token):
        yield token


@pytest.fixture
def mock_expired_token():
    """Mock an expired auth token."""
    # get_cached_token returns None for expired tokens
    with patch.object(auth_module, "get_cached_token", return_value=None):
        yield


@pytest.fixture
def mock_no_token():
    """Mock no auth token."""
    with patch.object(auth_module, "get_cached_token", return_value=None):
        yield


class TestIsProLicensed:
    """Tests for is_pro_licensed function."""

    def test_returns_false_when_no_token(self, mock_no_token) -> None:
        """Should return False when no auth token exists."""
        assert is_pro_licensed() is False

    def test_returns_false_when_only_llm_key(self, mock_no_token) -> None:
        """Should return False even with LLM key but no token."""
        keyring.save_key("openai", "test-key-123")
        assert is_pro_licensed() is False

    def test_returns_true_with_valid_token(self, mock_valid_token) -> None:
        """Should return True when valid auth token exists."""
        assert is_pro_licensed() is True

    def test_returns_true_with_token_even_without_llm_key(self, mock_valid_token) -> None:
        """Should return True with token even without LLM key."""
        # Don't set any LLM keys
        assert is_pro_licensed() is True


class TestHasLlmConfigured:
    """Tests for has_llm_configured function."""

    def test_returns_false_when_no_keys(self) -> None:
        """Should return False when no LLM keys configured."""
        assert has_llm_configured() is False

    def test_returns_true_with_openai_key(self) -> None:
        """Should return True when OpenAI key is configured."""
        keyring.save_key("openai", "test-key-123")
        assert has_llm_configured() is True

    def test_returns_true_with_any_provider_key(self) -> None:
        """Should return True with any supported provider key."""
        keyring.save_key("anthropic", "test-key-456")
        assert has_llm_configured() is True


class TestRequireProLicense:
    """Tests for require_pro_license function."""

    def test_raises_error_when_no_token(self, mock_no_token) -> None:
        """Should raise ProFeatureError when no token exists."""
        with pytest.raises(ProFeatureError) as exc_info:
            require_pro_license("Test feature")

        assert "Test feature" in str(exc_info.value)
        assert "requires a Pro license" in str(exc_info.value)
        assert "vibeguard auth login" in str(exc_info.value)

    def test_does_not_raise_with_valid_token(self, mock_valid_token) -> None:
        """Should not raise when valid token exists."""
        # Should not raise
        require_pro_license("Test feature")

    def test_error_includes_activation_guidance(self, mock_no_token) -> None:
        """Should guide users to auth login in error message."""
        with pytest.raises(ProFeatureError) as exc_info:
            require_pro_license()

        error_msg = str(exc_info.value)
        assert "vibeguard auth login" in error_msg
        assert "vibeguard.co/pricing" in error_msg

    def test_default_feature_name(self, mock_no_token) -> None:
        """Should use default feature name if not specified."""
        with pytest.raises(ProFeatureError) as exc_info:
            require_pro_license()

        assert "This feature" in str(exc_info.value)


class TestRequireLlmKey:
    """Tests for require_llm_key function."""

    def test_raises_error_when_no_keys(self) -> None:
        """Should raise ProFeatureError when no LLM keys configured."""
        with pytest.raises(ProFeatureError) as exc_info:
            require_llm_key("Test feature")

        assert "LLM API key" in str(exc_info.value)
        assert "vibeguard keys set" in str(exc_info.value)

    def test_does_not_raise_with_key(self) -> None:
        """Should not raise when an LLM key is configured."""
        keyring.save_key("openai", "test-key")
        # Should not raise
        require_llm_key("Test feature")


class TestRequirePatchCapability:
    """Tests for require_patch_capability function."""

    def test_raises_error_when_no_token(self, mock_no_token) -> None:
        """Should raise when no token even with LLM key."""
        keyring.save_key("openai", "test-key")

        with pytest.raises(ProFeatureError) as exc_info:
            require_patch_capability()

        assert "Pro license" in str(exc_info.value)

    def test_raises_error_when_no_llm_key(self, mock_valid_token) -> None:
        """Should raise when no LLM key even with valid token."""
        # Don't set any LLM keys

        with pytest.raises(ProFeatureError) as exc_info:
            require_patch_capability()

        assert "LLM API key" in str(exc_info.value)

    def test_does_not_raise_with_token_and_key(self, mock_valid_token) -> None:
        """Should not raise when both token and LLM key exist."""
        keyring.save_key("openai", "test-key")
        # Should not raise
        require_patch_capability()


class TestGetLicenseStatus:
    """Tests for get_license_status function."""

    def test_returns_not_pro_when_no_token(self, mock_no_token) -> None:
        """Should return is_pro=False when no token."""
        status = get_license_status()

        assert status["is_pro"] is False
        assert status["configured_providers"] == []
        assert status["can_patch"] is False

    def test_returns_pro_with_valid_token(self, mock_valid_token) -> None:
        """Should return is_pro=True with valid token."""
        status = get_license_status()

        assert status["is_pro"] is True
        assert status["plan"] == "pro"
        assert "pro.patch" in status["entitlements"]

    def test_returns_can_patch_with_token_and_key(self, mock_valid_token) -> None:
        """Should return can_patch=True with both token and LLM key."""
        keyring.save_key("openai", "test-key")

        status = get_license_status()

        assert status["is_pro"] is True
        assert status["has_llm_key"] is True
        assert status["can_patch"] is True

    def test_returns_configured_providers(self, mock_no_token) -> None:
        """Should list all configured LLM providers."""
        keyring.save_key("openai", "key-1")
        keyring.save_key("anthropic", "key-2")

        status = get_license_status()

        assert status["is_pro"] is False  # No token
        assert status["has_llm_key"] is True
        assert len(status["configured_providers"]) == 2
        assert "openai" in status["configured_providers"]
        assert "anthropic" in status["configured_providers"]
