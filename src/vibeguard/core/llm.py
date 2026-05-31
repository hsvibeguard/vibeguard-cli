"""LLM provider abstraction using litellm.

Provides a unified interface for calling various LLM providers
with automatic API key management from the keyring.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from pydantic import BaseModel

if TYPE_CHECKING:
    pass

# Default models for each provider
PROVIDER_MODELS: dict[str, str] = {
    "openai": "gpt-4-turbo-preview",
    "anthropic": "claude-3-opus-20240229",
    "google": "gemini-pro",
    "azure_openai": "gpt-4",
    "mistral": "mistral-large-latest",
    "groq": "llama3-70b-8192",
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


class LLMResponse(BaseModel):
    """Response from LLM call."""

    content: str
    model: str
    provider: str
    tokens_used: int | None = None


class LLMError(Exception):
    """Error during LLM call."""

    pass


def get_available_provider() -> str | None:
    """Get the first available provider with a configured key.

    Checks providers in preference order: openai, anthropic, google, etc.

    Returns:
        Provider name, or None if no provider configured
    """
    from vibeguard.core.keyring import get_configured_providers

    providers = get_configured_providers()
    if not providers:
        return None

    # Prefer OpenAI, then Anthropic, then others
    preferred_order = ["openai", "anthropic", "google", "mistral", "groq", "azure_openai"]
    for preferred in preferred_order:
        if preferred in providers:
            return preferred

    # Return first available if none in preferred list
    return providers[0]


async def generate(
    prompt: str,
    *,
    provider: str | None = None,
    model: str | None = None,
    max_tokens: int = 4096,
    temperature: float = 0.2,
) -> LLMResponse:
    """Generate text using the configured LLM.

    Args:
        prompt: The prompt to send to the LLM
        provider: Specific provider to use (auto-detected if None)
        model: Specific model to use (default for provider if None)
        max_tokens: Maximum tokens in response
        temperature: Sampling temperature (lower = more deterministic)

    Returns:
        LLMResponse with generated content

    Raises:
        LLMError: If no provider configured or call fails
    """
    from vibeguard.core.keyring import load_key

    # Auto-detect provider if not specified
    if provider is None:
        provider = get_available_provider()
        if provider is None:
            raise LLMError(
                "No LLM provider configured. "
                "Run 'vibeguard keys set <provider> <key>' first."
            )

    # Get API key
    api_key = load_key(provider)
    if not api_key:
        raise LLMError(f"No API key configured for provider: {provider}")

    # Use default model if not specified
    if model is None:
        model = PROVIDER_MODELS.get(provider)
        if model is None:
            raise LLMError(f"No default model for provider: {provider}")

    # Set environment variable for litellm
    env_var = PROVIDER_ENV_VARS.get(provider)
    if env_var:
        os.environ[env_var] = api_key

    try:
        import litellm

        # Construct model string for litellm
        # For some providers, litellm needs a prefix (e.g., "anthropic/claude-3...")
        model_string = _get_litellm_model_string(provider, model)

        response = await litellm.acompletion(
            model=model_string,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=temperature,
        )

        content = response.choices[0].message.content or ""
        tokens = response.usage.total_tokens if response.usage else None

        return LLMResponse(
            content=content,
            model=model,
            provider=provider,
            tokens_used=tokens,
        )

    except ImportError:
        raise LLMError("litellm not installed. Run 'pip install litellm'.")
    except Exception as e:
        # Clean up error message
        error_msg = str(e)
        # Don't expose API keys in error messages
        if api_key and api_key in error_msg:
            error_msg = error_msg.replace(api_key, "***")
        raise LLMError(f"LLM call failed: {error_msg}")


def _get_litellm_model_string(provider: str, model: str) -> str:
    """Get the correct model string for litellm.

    litellm uses different prefixes for different providers.

    Args:
        provider: Provider name
        model: Model name

    Returns:
        Model string formatted for litellm
    """
    # Some providers need prefixes
    if provider == "anthropic" and not model.startswith("anthropic/"):
        return f"anthropic/{model}"
    if provider == "google" and not model.startswith("gemini/"):
        return f"gemini/{model}"
    if provider == "mistral" and not model.startswith("mistral/"):
        return f"mistral/{model}"
    if provider == "groq" and not model.startswith("groq/"):
        return f"groq/{model}"

    # OpenAI and Azure don't need prefixes
    return model


def get_model_for_provider(provider: str) -> str | None:
    """Get the default model for a provider.

    Args:
        provider: Provider name

    Returns:
        Default model name, or None if provider unknown
    """
    return PROVIDER_MODELS.get(provider)


def list_supported_providers() -> list[str]:
    """List all supported LLM providers.

    Returns:
        List of provider names
    """
    return list(PROVIDER_MODELS.keys())
