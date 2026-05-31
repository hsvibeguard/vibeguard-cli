"""Authentication and license management for Pro features.

Handles machine ID generation, token storage, and API communication
with the VibeGuard license server.
"""

from __future__ import annotations

import stat
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from vibeguard.models.auth import (
    ActivateResponse,
    AuthCache,
    AuthToken,
    MachineInfo,
    RefreshResponse,
)

# Storage locations
AUTH_DIR = Path.home() / ".vibeguard"
MACHINE_ID_FILE = AUTH_DIR / "machine_id"
AUTH_CACHE_FILE = AUTH_DIR / "auth.json"

# API configuration
API_BASE_URL = "https://api-cli-2.vibeguard.co"
API_TIMEOUT = 30.0

# Token management
TOKEN_REFRESH_THRESHOLD = timedelta(hours=24)


class AuthError(Exception):
    """Raised when authentication fails."""

    pass


class NetworkError(AuthError):
    """Raised when network communication fails."""

    pass


class LicenseError(AuthError):
    """Raised when license validation fails."""

    pass


def _ensure_auth_dir() -> None:
    """Ensure the auth directory exists with proper permissions."""
    AUTH_DIR.mkdir(parents=True, exist_ok=True)
    try:
        AUTH_DIR.chmod(stat.S_IRWXU)  # 700 - owner only
    except OSError:
        pass  # Windows compatibility


def _set_file_permissions(path: Path) -> None:
    """Set restrictive permissions on a file (owner read/write only)."""
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 600
    except OSError:
        pass  # Windows compatibility


def get_or_create_machine_id() -> str:
    """Get existing machine ID or generate a new UUID.

    The machine ID is stored in ~/.vibeguard/machine_id and uniquely
    identifies this installation for license activation purposes.

    Returns:
        The machine ID as a string UUID
    """
    _ensure_auth_dir()

    if MACHINE_ID_FILE.exists():
        return MACHINE_ID_FILE.read_text().strip()

    # Generate new machine ID
    machine_id = str(uuid.uuid4())
    MACHINE_ID_FILE.write_text(machine_id)
    _set_file_permissions(MACHINE_ID_FILE)

    return machine_id


def load_auth_cache() -> AuthCache | None:
    """Load cached auth data from ~/.vibeguard/auth.json.

    Returns:
        AuthCache if file exists and is valid, None otherwise
    """
    if not AUTH_CACHE_FILE.exists():
        return None

    try:
        return AuthCache.model_validate_json(AUTH_CACHE_FILE.read_text())
    except Exception:
        # Corrupted cache - return None
        return None


def save_auth_cache(cache: AuthCache) -> None:
    """Save auth cache with restrictive permissions.

    Args:
        cache: The AuthCache to save
    """
    _ensure_auth_dir()
    AUTH_CACHE_FILE.write_text(cache.model_dump_json(indent=2))
    _set_file_permissions(AUTH_CACHE_FILE)


def clear_auth_cache() -> bool:
    """Delete auth cache (logout).

    Returns:
        True if cache was deleted, False if it didn't exist
    """
    if AUTH_CACHE_FILE.exists():
        AUTH_CACHE_FILE.unlink()
        return True
    return False


def get_cached_token() -> AuthToken | None:
    """Get token from cache if still valid (not expired).

    Returns:
        AuthToken if valid, None if missing or expired
    """
    cache = load_auth_cache()
    if cache is None or cache.token is None:
        return None

    # Check if token is expired
    now = datetime.now(UTC)
    # Handle naive datetime by assuming UTC
    expires_at = cache.token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)

    if expires_at <= now:
        return None

    return cache.token


def should_refresh_token(token: AuthToken) -> bool:
    """Check if token should be refreshed (expires within 24 hours).

    Args:
        token: The token to check

    Returns:
        True if token should be refreshed
    """
    now = datetime.now(UTC)
    expires_at = token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)

    return (expires_at - now) < TOKEN_REFRESH_THRESHOLD


def get_token_time_remaining(token: AuthToken) -> timedelta:
    """Get time remaining until token expires.

    Args:
        token: The token to check

    Returns:
        Time remaining as timedelta (may be negative if expired)
    """
    now = datetime.now(UTC)
    expires_at = token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)

    return expires_at - now


async def activate_license(license_key: str) -> ActivateResponse:
    """Activate a license key for this machine.

    Sends the license key and machine ID to the server to receive
    an authentication token.

    Args:
        license_key: The license key to activate

    Returns:
        ActivateResponse with token and entitlements

    Raises:
        NetworkError: If server is unreachable
        LicenseError: If license is invalid or activation limit reached
    """
    machine_id = get_or_create_machine_id()

    try:
        async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
            response = await client.post(
                f"{API_BASE_URL}/v1/licenses/activate",
                json={"license_key": license_key, "machine_id": machine_id},
            )

            if response.status_code == 200:
                return ActivateResponse.model_validate(response.json())

            # Handle error responses
            try:
                error_data = response.json()
                error_msg = error_data.get("error", "Unknown error")
                error_detail = error_data.get("detail", "")
            except Exception:
                error_msg = f"Server returned status {response.status_code}"
                error_detail = ""

            if response.status_code == 401:
                raise LicenseError(f"Invalid license key: {error_msg}")
            elif response.status_code == 403:
                raise LicenseError(
                    f"License activation limit reached: {error_msg}\n"
                    "Deactivate another machine at https://vibeguard.co/account"
                )
            elif response.status_code == 404:
                raise LicenseError("License key not found")
            else:
                detail = f" - {error_detail}" if error_detail else ""
                raise LicenseError(f"{error_msg}{detail}")

    except httpx.RequestError as e:
        raise NetworkError(
            f"Could not connect to license server: {e}\n"
            "Check your internet connection and try again."
        ) from e


async def refresh_token(current_token: str) -> RefreshResponse:
    """Refresh an existing token.

    Args:
        current_token: The current valid token

    Returns:
        RefreshResponse with new token

    Raises:
        NetworkError: If server is unreachable
        LicenseError: If token is invalid or license revoked
    """
    try:
        async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
            response = await client.post(
                f"{API_BASE_URL}/v1/licenses/refresh-token",
                headers={"Authorization": f"Bearer {current_token}"},
            )

            if response.status_code == 200:
                return RefreshResponse.model_validate(response.json())

            if response.status_code == 401:
                raise LicenseError(
                    "Token expired or revoked. Please login again:\n"
                    "  vibeguard auth login <your-license-key>"
                )
            else:
                raise LicenseError(f"Token refresh failed: {response.status_code}")

    except httpx.RequestError as e:
        raise NetworkError(f"Could not connect to license server: {e}") from e


async def get_entitlements(token: str) -> list[str]:
    """Get current entitlements for a token.

    Args:
        token: The authentication token

    Returns:
        List of entitlement strings

    Raises:
        NetworkError: If server is unreachable
        LicenseError: If token is invalid
    """
    try:
        async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
            response = await client.get(
                f"{API_BASE_URL}/v1/entitlements",
                headers={"Authorization": f"Bearer {token}"},
            )

            if response.status_code == 200:
                data = response.json()
                return data.get("entitlements", [])

            if response.status_code == 401:
                raise LicenseError("Invalid or expired token")
            else:
                raise LicenseError(f"Failed to get entitlements: {response.status_code}")

    except httpx.RequestError as e:
        raise NetworkError(f"Could not connect to license server: {e}") from e


def save_token_to_cache(
    response: ActivateResponse | RefreshResponse,
    *,
    license_id: str | None = None,
    plan: str | None = None,
) -> AuthToken:
    """Save a token response to the auth cache.

    Args:
        response: The activation or refresh response
        license_id: Optional license ID to store
        plan: Optional plan name to store

    Returns:
        The saved AuthToken
    """
    machine_id = get_or_create_machine_id()

    # Build token object
    token = AuthToken(
        token=response.token,
        expires_at=response.expires_at,
        entitlements=response.entitlements,
        license_id=license_id or getattr(response, "license_id", None),
        plan=plan or getattr(response, "plan", None),
        last_refresh=datetime.now(UTC),
    )

    # Build cache
    cache = AuthCache(
        version=1,
        token=token,
        machine=MachineInfo(
            machine_id=machine_id,
            created_at=datetime.now(UTC),
        ),
    )

    save_auth_cache(cache)
    return token


async def ensure_valid_token() -> AuthToken | None:
    """Get valid token, refreshing if needed and online.

    This function implements offline grace period logic:
    - If token is valid and fresh, return it
    - If token needs refresh and we're online, refresh it
    - If token is valid but refresh fails (offline), return cached token
    - If token is expired, return None

    Returns:
        Valid AuthToken or None if no valid token available
    """
    token = get_cached_token()

    if token is None:
        return None

    # Token is still valid - check if we should refresh
    if should_refresh_token(token):
        try:
            response = await refresh_token(token.token)
            token = save_token_to_cache(
                response,
                license_id=token.license_id,
                plan=token.plan,
            )
        except (NetworkError, LicenseError):
            # Refresh failed - use cached token if still valid
            # (offline grace period)
            pass

    return token


def mask_license_key(license_key: str) -> str:
    """Mask a license key for display (show prefix only).

    Args:
        license_key: The full license key

    Returns:
        Masked key showing only prefix
    """
    if len(license_key) > 12:
        return license_key[:8] + "..." + license_key[-4:]
    return "****"
