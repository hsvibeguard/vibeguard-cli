"""License gating for Pro features.

Pro features are gated by server-issued entitlement tokens.
BYOK LLM keys are separately required for patch generation.
"""

from __future__ import annotations

from typing import Any

from vibeguard.core.keyring import get_configured_providers


class ProFeatureError(Exception):
    """Raised when a Pro feature is accessed without a license."""

    pass


def is_pro_licensed() -> bool:
    """Check if the user has Pro features enabled.

    Pro features are enabled when a valid entitlement token exists.
    Note: BYOK LLM key is separately required for patch generation.

    Returns:
        True if Pro features are available, False otherwise
    """
    from vibeguard.core.auth import get_cached_token

    token = get_cached_token()
    if token is None:
        return False

    # Token exists and get_cached_token already checks expiry
    return True


def has_llm_configured() -> bool:
    """Check if a BYOK LLM key is configured.

    This is required for patch generation but is separate from
    the Pro license check.

    Returns:
        True if at least one LLM provider is configured
    """
    providers = get_configured_providers()
    return len(providers) > 0


def require_pro_license(feature_name: str = "This feature") -> None:
    """Require Pro license to continue.

    Args:
        feature_name: Name of the feature for error message

    Raises:
        ProFeatureError: If no valid entitlement token exists
    """
    if not is_pro_licensed():
        raise ProFeatureError(
            f"{feature_name} requires a Pro license.\n\n"
            "Activate your license with:\n"
            "  vibeguard auth login <your-license-key>\n\n"
            "Get a license at: https://vibeguard.co/pricing"
        )


def require_llm_key(feature_name: str = "This feature") -> None:
    """Require BYOK LLM key to continue.

    Args:
        feature_name: Name of the feature for error message

    Raises:
        ProFeatureError: If no LLM provider is configured
    """
    if not has_llm_configured():
        raise ProFeatureError(
            f"{feature_name} requires an LLM API key.\n\n"
            "Configure your BYOK key with:\n"
            "  vibeguard keys set openai <your-api-key>\n"
            "  vibeguard keys set anthropic <your-api-key>\n\n"
            "Supported: openai, anthropic, google, azure_openai, mistral, groq"
        )


def require_patch_capability(feature_name: str = "Patch generation") -> None:
    """Require both Pro license AND BYOK LLM key.

    This is the check for patch/apply commands which need:
    1. A valid entitlement token (Pro license)
    2. A configured LLM API key (for actual generation)

    Args:
        feature_name: Name of the feature for error message

    Raises:
        ProFeatureError: If license or LLM key is missing
    """
    require_pro_license(feature_name)
    require_llm_key(feature_name)


def get_license_status() -> dict[str, Any]:
    """Get detailed license status.

    Returns:
        Dictionary with license information:
        - is_pro: Whether Pro features are available
        - token_expires_at: Token expiry datetime or None
        - entitlements: List of entitlements or empty list
        - plan: Plan name or None
        - configured_providers: List of configured LLM providers
        - has_llm_key: Whether at least one LLM key is configured
        - can_patch: Whether patch generation is available
    """
    from vibeguard.core.auth import get_cached_token

    token = get_cached_token()
    providers = get_configured_providers()

    is_pro = token is not None
    has_llm = len(providers) > 0

    return {
        "is_pro": is_pro,
        "token_expires_at": token.expires_at if token else None,
        "entitlements": token.entitlements if token else [],
        "plan": token.plan if token else None,
        "configured_providers": providers,
        "has_llm_key": has_llm,
        "can_patch": is_pro and has_llm,
    }


def get_token_expiry_message() -> str | None:
    """Get a human-readable token expiry message.

    Returns:
        Message about token expiry, or None if not logged in
    """
    from vibeguard.core.auth import get_cached_token, get_token_time_remaining

    token = get_cached_token()
    if token is None:
        return None

    remaining = get_token_time_remaining(token)
    if remaining.total_seconds() <= 0:
        return "Token has expired"

    days = remaining.days
    hours = remaining.seconds // 3600

    if days > 1:
        return f"Token expires in {days} days"
    elif days == 1:
        return f"Token expires in 1 day, {hours} hours"
    elif hours > 0:
        return f"Token expires in {hours} hours"
    else:
        minutes = remaining.seconds // 60
        return f"Token expires in {minutes} minutes"


def get_license_status_with_grace() -> dict[str, Any]:
    """Get detailed license status including grace period information.

    This function calculates the license status for displaying expiry
    banners in CLI commands. It returns information about:
    - Whether the license is valid (including grace period)
    - Whether currently in grace period
    - Time remaining until expiry

    The grace period is 48 hours after license expiration. During grace,
    the license is still valid but users should be warned to renew.

    Returns:
        Dictionary with:
        - valid: bool - True if license is currently usable
        - in_grace: bool - True if in grace period (expired but within 48h)
        - hours_left: int - Hours remaining (in grace period)
        - days_left: int - Days remaining until expiry (when not in grace)
        - license_expires_at: datetime | None - When license expires
        - grace_end: datetime | None - When grace period ends
    """
    from vibeguard.core.auth import get_cached_token, get_token_time_remaining

    token = get_cached_token()
    if token is None:
        return {
            "valid": False,
            "in_grace": False,
            "hours_left": 0,
            "days_left": 0,
            "license_expires_at": None,
            "grace_end": None,
        }

    remaining = get_token_time_remaining(token)
    total_seconds = remaining.total_seconds()

    if total_seconds <= 0:
        # Token has fully expired (past grace period)
        return {
            "valid": False,
            "in_grace": False,
            "hours_left": 0,
            "days_left": 0,
            "license_expires_at": token.expires_at,
            "grace_end": token.expires_at,
        }

    # Token is still valid
    # Calculate days and hours
    days_left = remaining.days
    hours_left = remaining.seconds // 3600

    # Check if we're likely in grace period
    # Grace period detection heuristic: If token has < 48 hours AND
    # the token has specific grace indicators (will be enhanced when
    # backend adds explicit fields)
    #
    # For now, we detect grace by checking if the entitlements include
    # a grace marker OR if we're in the last 48 hours (conservative approach)
    #
    # TODO: When backend adds explicit in_grace field, use that instead
    in_grace = False

    # Check for explicit grace indicator in entitlements
    # Backend can add "grace.active" entitlement during grace period
    if token.entitlements and "grace.active" in token.entitlements:
        in_grace = True

    return {
        "valid": True,
        "in_grace": in_grace,
        "hours_left": hours_left if in_grace else 0,
        "days_left": days_left,
        "license_expires_at": token.expires_at,
        "grace_end": token.expires_at,  # Token expiry = grace end when bounded
    }
