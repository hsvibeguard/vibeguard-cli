"""API key validation for LLM providers.

Validates API keys by making minimal API calls to each provider.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


# Validation endpoints and test prompts per provider
VALIDATION_CONFIG = {
    "openai": {
        "model": "gpt-3.5-turbo",
        "test_prompt": "Hi",
        "max_tokens": 1,
    },
    "anthropic": {
        "model": "claude-3-haiku-20240307",
        "test_prompt": "Hi",
        "max_tokens": 1,
    },
    "google": {
        "model": "gemini-pro",
        "test_prompt": "Hi",
        "max_tokens": 1,
    },
    "azure_openai": {
        "model": "gpt-4",
        "test_prompt": "Hi",
        "max_tokens": 1,
    },
    "mistral": {
        "model": "mistral-small-latest",
        "test_prompt": "Hi",
        "max_tokens": 1,
    },
    "groq": {
        "model": "llama3-8b-8192",
        "test_prompt": "Hi",
        "max_tokens": 1,
    },
}

# Environment variable names for each provider
PROVIDER_ENV_VARS: dict[str, str] = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "google": "GOOGLE_API_KEY",
    "azure_openai": "AZURE_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "groq": "GROQ_API_KEY",
}


def _get_litellm_model_string(provider: str, model: str) -> str:
    """Get the correct model string for litellm."""
    if provider == "anthropic" and not model.startswith("anthropic/"):
        return f"anthropic/{model}"
    if provider == "google" and not model.startswith("gemini/"):
        return f"gemini/{model}"
    if provider == "mistral" and not model.startswith("mistral/"):
        return f"mistral/{model}"
    if provider == "groq" and not model.startswith("groq/"):
        return f"groq/{model}"
    return model


def validate_api_key(provider: str, api_key: str) -> tuple[bool, str]:
    """Validate an API key by making a minimal API call.

    Args:
        provider: The LLM provider name (openai, anthropic, etc.)
        api_key: The API key to validate

    Returns:
        Tuple of (is_valid, message)
        - is_valid: True if key is valid, False otherwise
        - message: Success or error message
    """
    if not api_key or not api_key.strip():
        return False, "API key cannot be empty"

    config = VALIDATION_CONFIG.get(provider)
    if not config:
        # Unknown provider - accept key without validation
        return True, f"Key accepted (no validation available for {provider})"

    # Set environment variable for litellm
    env_var = PROVIDER_ENV_VARS.get(provider)
    old_value = None
    if env_var:
        old_value = os.environ.get(env_var)
        os.environ[env_var] = api_key.strip()

    try:
        import litellm

        # Disable logging to avoid noise
        litellm.suppress_debug_info = True

        model_string = _get_litellm_model_string(provider, config["model"])

        # Make a minimal completion request
        litellm.completion(
            model=model_string,
            messages=[{"role": "user", "content": config["test_prompt"]}],
            max_tokens=config["max_tokens"],
            temperature=0,
        )

        # If we get here, the key is valid
        return True, "Key validated successfully"

    except ImportError:
        return False, "litellm not installed - run 'pip install litellm'"

    except Exception as e:
        error_msg = str(e).lower()

        # Parse common error messages
        if "invalid api key" in error_msg or "invalid_api_key" in error_msg:
            return False, "Invalid API key"
        if "incorrect api key" in error_msg:
            return False, "Incorrect API key"
        if "authentication" in error_msg or "unauthorized" in error_msg:
            return False, "Authentication failed - check your API key"
        if "rate limit" in error_msg or "rate_limit" in error_msg:
            # Rate limited means key is valid but quota exceeded
            return True, "Key valid (rate limited - wait and retry)"
        if "quota" in error_msg or "exceeded" in error_msg:
            return True, "Key valid (quota exceeded - check billing)"
        if "permission" in error_msg:
            return False, "Key lacks required permissions"
        if "not found" in error_msg:
            return False, "Model not found - key may be invalid"
        if "connection" in error_msg or "timeout" in error_msg:
            return False, "Connection failed - check network"

        # Generic error - don't expose raw error
        # Clean up API key from error message if present
        clean_error = str(e)
        if api_key in clean_error:
            clean_error = clean_error.replace(api_key, "***")
        return False, f"Validation failed: {clean_error[:100]}"

    finally:
        # Restore original environment
        if env_var:
            if old_value is not None:
                os.environ[env_var] = old_value
            elif env_var in os.environ:
                del os.environ[env_var]


async def validate_api_key_async(provider: str, api_key: str) -> tuple[bool, str]:
    """Async version of validate_api_key.

    Args:
        provider: The LLM provider name (openai, anthropic, etc.)
        api_key: The API key to validate

    Returns:
        Tuple of (is_valid, message)
    """
    import asyncio

    # Run sync validation in thread pool
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, validate_api_key, provider, api_key)
