"""Tests for auth integration - login, status, logout, token refresh, API client."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from typer.testing import CliRunner

from vibeguard.cli.main import app
from vibeguard.core import auth as auth_module
from vibeguard.core import keyring
from vibeguard.core.auth import (
    LicenseError,
    NetworkError,
    activate_license,
    clear_auth_cache,
    ensure_valid_token,
    get_cached_token,
    get_entitlements,
    load_auth_cache,
    refresh_token,
    save_token_to_cache,
    should_refresh_token,
)
from vibeguard.models.auth import ActivateResponse, AuthToken, RefreshResponse

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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


@pytest.fixture(autouse=True)
def mock_auth_storage(tmp_path):  # type: ignore[no-untyped-def]
    """Redirect auth storage to temp path for test isolation."""
    auth_dir = tmp_path / ".vibeguard"
    machine_id_file = auth_dir / "machine_id"
    auth_cache_file = auth_dir / "auth.json"

    with (
        patch.object(auth_module, "AUTH_DIR", auth_dir),
        patch.object(auth_module, "MACHINE_ID_FILE", machine_id_file),
        patch.object(auth_module, "AUTH_CACHE_FILE", auth_cache_file),
    ):
        yield


@pytest.fixture
def valid_activate_response() -> ActivateResponse:
    """Build a valid ActivateResponse for mocking."""
    return ActivateResponse(
        token="tok_test_abc123",
        expires_at=datetime.now(UTC) + timedelta(days=7),
        entitlements=["pro.patch", "pro.apply", "bundles.v1"],
        plan="pro",
        license_id="lic_test_001",
    )


@pytest.fixture
def valid_refresh_response() -> RefreshResponse:
    """Build a valid RefreshResponse for mocking."""
    return RefreshResponse(
        token="tok_refreshed_xyz",
        expires_at=datetime.now(UTC) + timedelta(days=7),
        entitlements=["pro.patch", "pro.apply", "bundles.v1"],
    )


@pytest.fixture
def saved_valid_token(valid_activate_response) -> AuthToken:
    """Save a valid token to the cache and return it."""
    return save_token_to_cache(
        valid_activate_response,
        license_id="lic_test_001",
        plan="pro",
    )


@pytest.fixture
def saved_expired_token() -> AuthToken:
    """Save an expired token to the cache and return it."""
    resp = ActivateResponse(
        token="tok_expired",
        expires_at=datetime.now(UTC) - timedelta(hours=1),
        entitlements=["pro.patch"],
        plan="pro",
        license_id="lic_expired",
    )
    return save_token_to_cache(resp, license_id="lic_expired", plan="pro")


@pytest.fixture
def saved_near_expiry_token() -> AuthToken:
    """Save a token that expires in 12 hours (inside refresh threshold)."""
    resp = ActivateResponse(
        token="tok_near_expiry",
        expires_at=datetime.now(UTC) + timedelta(hours=12),
        entitlements=["pro.patch", "pro.apply"],
        plan="pro",
        license_id="lic_near",
    )
    return save_token_to_cache(resp, license_id="lic_near", plan="pro")


def _mock_httpx_post(status_code: int, json_body: dict | None = None, *, raise_error: type[Exception] | None = None):
    """Create a mock httpx.AsyncClient context manager returning a configured response."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    if json_body is not None:
        mock_response.json.return_value = json_body

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.get = AsyncMock(return_value=mock_response)

    if raise_error is not None:
        mock_client.post = AsyncMock(side_effect=raise_error)
        mock_client.get = AsyncMock(side_effect=raise_error)

    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=False)

    return mock_cm, mock_client


# ===========================================================================
# 1. Login Flow
# ===========================================================================


class TestAuthLogin:
    """Tests for 'vibeguard auth login <key>'."""

    def test_login_success(self, valid_activate_response) -> None:
        """Valid key should activate, save token, and show success."""
        resp_json = valid_activate_response.model_dump(mode="json")
        mock_cm, _ = _mock_httpx_post(200, resp_json)

        with patch("vibeguard.core.auth.httpx.AsyncClient", return_value=mock_cm):
            result = runner.invoke(app, ["auth", "login", "VGPRO-TEST-1234-ABCD"])

        assert result.exit_code == 0
        assert "activated" in result.output.lower() or "success" in result.output.lower()

        # Token should be persisted
        cached = load_auth_cache()
        assert cached is not None
        assert cached.token is not None
        assert cached.token.token == "tok_test_abc123"

    def test_login_invalid_key(self) -> None:
        """Server returns 404 for unknown key -- should show error."""
        mock_cm, _ = _mock_httpx_post(404, {"error": "License key not found"})

        with patch("vibeguard.core.auth.httpx.AsyncClient", return_value=mock_cm):
            result = runner.invoke(app, ["auth", "login", "VGPRO-INVALID-KEY"])

        assert result.exit_code != 0
        assert "failed" in result.output.lower() or "not found" in result.output.lower()

    def test_login_max_activations(self) -> None:
        """Server returns 403 for activation limit -- should show message."""
        mock_cm, _ = _mock_httpx_post(403, {"error": "Activation limit reached"})

        with patch("vibeguard.core.auth.httpx.AsyncClient", return_value=mock_cm):
            result = runner.invoke(app, ["auth", "login", "VGPRO-MAXED-OUT"])

        assert result.exit_code != 0
        assert "failed" in result.output.lower() or "limit" in result.output.lower()

    def test_login_network_error(self) -> None:
        """Connection refused should show network error with retry guidance."""
        mock_cm, _ = _mock_httpx_post(
            0,
            raise_error=httpx.ConnectError("Connection refused"),
        )

        with patch("vibeguard.core.auth.httpx.AsyncClient", return_value=mock_cm):
            result = runner.invoke(app, ["auth", "login", "VGPRO-NETWORK-FAIL"])

        assert result.exit_code != 0
        output_lower = result.output.lower()
        assert "failed" in output_lower or "connect" in output_lower or "error" in output_lower

    def test_login_already_logged_in(self, saved_valid_token) -> None:
        """Existing valid token with same key should show 'already logged in' and exit 0."""
        result = runner.invoke(app, ["auth", "login", saved_valid_token.license_id])

        assert result.exit_code == 0
        assert "already logged in" in result.output.lower()

    def test_login_saves_auth_cache(self, valid_activate_response) -> None:
        """After successful login, auth.json should contain correct data."""
        resp_json = valid_activate_response.model_dump(mode="json")
        mock_cm, _ = _mock_httpx_post(200, resp_json)

        with patch("vibeguard.core.auth.httpx.AsyncClient", return_value=mock_cm):
            runner.invoke(app, ["auth", "login", "VGPRO-SAVE-TEST"])

        cache = load_auth_cache()
        assert cache is not None
        assert cache.version == 1
        assert cache.token is not None
        assert cache.token.plan == "pro"
        assert "pro.patch" in cache.token.entitlements
        assert cache.machine is not None
        assert len(cache.machine.machine_id) > 0

    def test_login_missing_key_shows_usage(self) -> None:
        """Calling login with no key should show usage guidance."""
        result = runner.invoke(app, ["auth", "login"])

        # Either shows usage or error about missing key
        output_lower = result.output.lower()
        assert "missing" in output_lower or "usage" in output_lower or "error" in output_lower


# ===========================================================================
# 2. Status Flow
# ===========================================================================


class TestAuthStatus:
    """Tests for 'vibeguard auth status'."""

    def test_status_active_license(self, saved_valid_token) -> None:
        """Valid cached token should show plan, expiry, and entitlements."""
        result = runner.invoke(app, ["auth", "status"])

        assert result.exit_code == 0
        output_lower = result.output.lower()
        assert "pro" in output_lower
        assert "licensed" in output_lower or "status" in output_lower

    def test_status_expired_license(self, saved_expired_token) -> None:
        """Expired token should show expired status."""
        result = runner.invoke(app, ["auth", "status"])

        assert result.exit_code == 0
        output_lower = result.output.lower()
        # get_cached_token returns None for expired tokens, so status is "not licensed"
        assert "free" in output_lower or "not licensed" in output_lower or "upgrade" in output_lower

    def test_status_no_auth(self) -> None:
        """No cached token should show 'not logged in' or free tier."""
        result = runner.invoke(app, ["auth", "status"])

        assert result.exit_code == 0
        output_lower = result.output.lower()
        assert "free" in output_lower or "not licensed" in output_lower or "upgrade" in output_lower


# ===========================================================================
# 3. Logout Flow
# ===========================================================================


class TestAuthLogout:
    """Tests for 'vibeguard auth logout'."""

    def test_logout_clears_cache(self, saved_valid_token) -> None:
        """Logout should remove auth.json and show success."""
        # Verify token exists first
        assert get_cached_token() is not None

        result = runner.invoke(app, ["auth", "logout"])

        assert result.exit_code == 0
        assert "logged out" in result.output.lower()

        # Token should be gone
        assert get_cached_token() is None
        assert load_auth_cache() is None

    def test_logout_when_not_logged_in(self) -> None:
        """Logout without token should show graceful message."""
        result = runner.invoke(app, ["auth", "logout"])

        assert result.exit_code == 0
        output_lower = result.output.lower()
        assert "not" in output_lower and "logged in" in output_lower


# ===========================================================================
# 4. Token Refresh
# ===========================================================================


class TestTokenRefresh:
    """Tests for token refresh logic."""

    def test_refresh_when_near_expiry(self, saved_near_expiry_token, valid_refresh_response) -> None:
        """Token expiring in 12h should be auto-refreshed when possible."""
        assert should_refresh_token(saved_near_expiry_token) is True

        resp_json = valid_refresh_response.model_dump(mode="json")
        mock_cm, mock_client = _mock_httpx_post(200, resp_json)

        with patch("vibeguard.core.auth.httpx.AsyncClient", return_value=mock_cm):
            token = asyncio.run(ensure_valid_token())

        assert token is not None
        assert token.token == "tok_refreshed_xyz"

        # Verify the post was called (refresh happened)
        mock_client.post.assert_called_once()

    def test_refresh_failure_offline_grace(self, saved_near_expiry_token) -> None:
        """Refresh fails but token still valid -- should return cached token."""
        mock_cm, _ = _mock_httpx_post(
            0,
            raise_error=httpx.ConnectError("Offline"),
        )

        with patch("vibeguard.core.auth.httpx.AsyncClient", return_value=mock_cm):
            token = asyncio.run(ensure_valid_token())

        # Should still return the near-expiry token (offline grace)
        assert token is not None
        assert token.token == "tok_near_expiry"

    def test_refresh_failure_expired(self, saved_expired_token) -> None:
        """Refresh fails and token already expired -- should return None."""
        # get_cached_token returns None for expired tokens,
        # so ensure_valid_token should also return None
        token = asyncio.run(ensure_valid_token())
        assert token is None

    def test_refresh_success_saves_new_token(self, saved_near_expiry_token, valid_refresh_response) -> None:
        """After successful refresh, new token should be written to cache."""
        resp_json = valid_refresh_response.model_dump(mode="json")
        mock_cm, _ = _mock_httpx_post(200, resp_json)

        with patch("vibeguard.core.auth.httpx.AsyncClient", return_value=mock_cm):
            asyncio.run(ensure_valid_token())

        # Read cache from disk
        cache = load_auth_cache()
        assert cache is not None
        assert cache.token is not None
        assert cache.token.token == "tok_refreshed_xyz"

    def test_should_refresh_false_when_fresh(self, saved_valid_token) -> None:
        """Token with >24h remaining should NOT trigger refresh."""
        assert should_refresh_token(saved_valid_token) is False

    def test_should_refresh_true_when_near(self, saved_near_expiry_token) -> None:
        """Token with <24h remaining should trigger refresh."""
        assert should_refresh_token(saved_near_expiry_token) is True


# ===========================================================================
# 5. API Client Functions
# ===========================================================================


class TestActivateLicenseAPI:
    """Tests for activate_license HTTP call."""

    def test_activate_license_http_call(self, valid_activate_response) -> None:
        """Verify correct endpoint, payload, and headers."""
        resp_json = valid_activate_response.model_dump(mode="json")
        mock_cm, mock_client = _mock_httpx_post(200, resp_json)

        with patch("vibeguard.core.auth.httpx.AsyncClient", return_value=mock_cm):
            result = asyncio.run(activate_license("VGPRO-TEST-KEY"))

        assert result.token == "tok_test_abc123"

        # Verify the POST call
        call_args = mock_client.post.call_args
        url = call_args[0][0] if call_args[0] else call_args[1].get("url", "")
        assert "/v1/licenses/activate" in url

        json_body = call_args[1].get("json", {}) if call_args[1] else {}
        assert json_body["license_key"] == "VGPRO-TEST-KEY"
        assert "machine_id" in json_body
        assert len(json_body["machine_id"]) > 0

    def test_activate_raises_license_error_on_401(self) -> None:
        """Server 401 should raise LicenseError."""
        mock_cm, _ = _mock_httpx_post(401, {"error": "Invalid license key"})

        with (
            patch("vibeguard.core.auth.httpx.AsyncClient", return_value=mock_cm),
            pytest.raises(LicenseError, match="Invalid license key"),
        ):
            asyncio.run(activate_license("BAD-KEY"))

    def test_activate_raises_license_error_on_404(self) -> None:
        """Server 404 should raise LicenseError."""
        mock_cm, _ = _mock_httpx_post(404, {"error": "Not found"})

        with (
            patch("vibeguard.core.auth.httpx.AsyncClient", return_value=mock_cm),
            pytest.raises(LicenseError, match="not found"),
        ):
            asyncio.run(activate_license("MISSING-KEY"))

    def test_activate_raises_license_error_on_403(self) -> None:
        """Server 403 should raise LicenseError about activation limit."""
        mock_cm, _ = _mock_httpx_post(403, {"error": "Activation limit reached"})

        with (
            patch("vibeguard.core.auth.httpx.AsyncClient", return_value=mock_cm),
            pytest.raises(LicenseError, match="activation limit"),
        ):
            asyncio.run(activate_license("MAXED-KEY"))

    def test_activate_raises_network_error(self) -> None:
        """Connection failure should raise NetworkError."""
        mock_cm, _ = _mock_httpx_post(
            0,
            raise_error=httpx.ConnectError("Connection refused"),
        )

        with (
            patch("vibeguard.core.auth.httpx.AsyncClient", return_value=mock_cm),
            pytest.raises(NetworkError, match="Could not connect"),
        ):
            asyncio.run(activate_license("ANY-KEY"))


class TestRefreshTokenAPI:
    """Tests for refresh_token HTTP call."""

    def test_refresh_returns_new_token(self, valid_refresh_response) -> None:
        """Successful refresh should return new token."""
        resp_json = valid_refresh_response.model_dump(mode="json")
        mock_cm, _ = _mock_httpx_post(200, resp_json)

        with patch("vibeguard.core.auth.httpx.AsyncClient", return_value=mock_cm):
            result = asyncio.run(refresh_token("tok_old"))

        assert result.token == "tok_refreshed_xyz"

    def test_refresh_sends_bearer_header(self, valid_refresh_response) -> None:
        """Refresh should send Authorization: Bearer header."""
        resp_json = valid_refresh_response.model_dump(mode="json")
        mock_cm, mock_client = _mock_httpx_post(200, resp_json)

        with patch("vibeguard.core.auth.httpx.AsyncClient", return_value=mock_cm):
            asyncio.run(refresh_token("tok_current"))

        call_args = mock_client.post.call_args
        headers = call_args[1].get("headers", {})
        assert headers.get("Authorization") == "Bearer tok_current"

    def test_refresh_raises_license_error_on_401(self) -> None:
        """Expired token on refresh should raise LicenseError."""
        mock_cm, _ = _mock_httpx_post(401, {"error": "Token expired"})

        with (
            patch("vibeguard.core.auth.httpx.AsyncClient", return_value=mock_cm),
            pytest.raises(LicenseError, match="expired or revoked"),
        ):
            asyncio.run(refresh_token("tok_dead"))

    def test_refresh_raises_network_error(self) -> None:
        """Offline refresh should raise NetworkError."""
        mock_cm, _ = _mock_httpx_post(
            0,
            raise_error=httpx.ConnectError("Offline"),
        )

        with (
            patch("vibeguard.core.auth.httpx.AsyncClient", return_value=mock_cm),
            pytest.raises(NetworkError),
        ):
            asyncio.run(refresh_token("tok_any"))


class TestGetEntitlementsAPI:
    """Tests for get_entitlements HTTP call."""

    def test_get_entitlements_with_bearer(self) -> None:
        """Verify Authorization header is sent."""
        mock_cm, mock_client = _mock_httpx_post(
            200,
            {"entitlements": ["pro.patch", "pro.apply"]},
        )

        with patch("vibeguard.core.auth.httpx.AsyncClient", return_value=mock_cm):
            result = asyncio.run(get_entitlements("tok_valid"))

        assert "pro.patch" in result
        assert "pro.apply" in result

        call_args = mock_client.get.call_args
        headers = call_args[1].get("headers", {})
        assert headers.get("Authorization") == "Bearer tok_valid"

    def test_get_entitlements_endpoint(self) -> None:
        """Verify correct endpoint is called."""
        mock_cm, mock_client = _mock_httpx_post(
            200,
            {"entitlements": []},
        )

        with patch("vibeguard.core.auth.httpx.AsyncClient", return_value=mock_cm):
            asyncio.run(get_entitlements("tok_test"))

        call_args = mock_client.get.call_args
        url = call_args[0][0] if call_args[0] else call_args[1].get("url", "")
        assert "/v1/entitlements" in url

    def test_get_entitlements_raises_on_401(self) -> None:
        """Invalid token should raise LicenseError."""
        mock_cm, _ = _mock_httpx_post(401, {"error": "Invalid token"})

        with (
            patch("vibeguard.core.auth.httpx.AsyncClient", return_value=mock_cm),
            pytest.raises(LicenseError, match="Invalid or expired token"),
        ):
            asyncio.run(get_entitlements("tok_bad"))

    def test_api_timeout(self) -> None:
        """Verify 30-second timeout is applied to the HTTP client."""
        assert auth_module.API_TIMEOUT == 30.0


# ===========================================================================
# 6. Cache & Machine ID helpers
# ===========================================================================


class TestAuthCacheHelpers:
    """Tests for cache load/save/clear and machine ID."""

    def test_clear_auth_cache_returns_true_when_exists(self, saved_valid_token) -> None:
        """clear_auth_cache returns True when file existed."""
        assert clear_auth_cache() is True

    def test_clear_auth_cache_returns_false_when_missing(self) -> None:
        """clear_auth_cache returns False when no file."""
        assert clear_auth_cache() is False

    def test_machine_id_persists(self) -> None:
        """Machine ID should remain the same across calls."""
        from vibeguard.core.auth import get_or_create_machine_id

        mid1 = get_or_create_machine_id()
        mid2 = get_or_create_machine_id()
        assert mid1 == mid2
        assert len(mid1) == 36  # UUID format

    def test_save_and_load_roundtrip(self, valid_activate_response) -> None:
        """Token saved should be loadable."""
        save_token_to_cache(valid_activate_response, license_id="lic_rt", plan="pro")

        cache = load_auth_cache()
        assert cache is not None
        assert cache.token is not None
        assert cache.token.license_id == "lic_rt"
        assert cache.token.plan == "pro"
        assert cache.token.token == "tok_test_abc123"
