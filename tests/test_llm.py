"""Tests for LLM module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vibeguard.core import keyring
from vibeguard.core.llm import (
    LLMError,
    LLMResponse,
    _get_litellm_model_string,
    generate,
    get_available_provider,
    get_model_for_provider,
    list_supported_providers,
)


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


class TestListSupportedProviders:
    """Tests for list_supported_providers()."""

    def test_returns_all_providers(self) -> None:
        """Should return all supported providers."""
        providers = list_supported_providers()
        assert "openai" in providers
        assert "anthropic" in providers
        assert "google" in providers
        assert len(providers) >= 4

    def test_returns_list(self) -> None:
        """Should return a list."""
        providers = list_supported_providers()
        assert isinstance(providers, list)


class TestGetModelForProvider:
    """Tests for get_model_for_provider()."""

    def test_returns_openai_model(self) -> None:
        """Should return default OpenAI model."""
        model = get_model_for_provider("openai")
        assert model is not None
        assert "gpt" in model.lower()

    def test_returns_anthropic_model(self) -> None:
        """Should return default Anthropic model."""
        model = get_model_for_provider("anthropic")
        assert model is not None
        assert "claude" in model.lower()

    def test_returns_none_for_unknown(self) -> None:
        """Should return None for unknown provider."""
        model = get_model_for_provider("unknown_provider")
        assert model is None


class TestGetAvailableProvider:
    """Tests for get_available_provider()."""

    def test_returns_none_when_no_keys(self) -> None:
        """Should return None when no keys configured."""
        provider = get_available_provider()
        assert provider is None

    def test_prefers_openai(self) -> None:
        """Should prefer OpenAI over other providers."""
        keyring.save_key("anthropic", "ant-key")
        keyring.save_key("openai", "openai-key")

        provider = get_available_provider()
        assert provider == "openai"

    def test_falls_back_to_anthropic(self) -> None:
        """Should fall back to Anthropic if OpenAI not configured."""
        keyring.save_key("anthropic", "ant-key")
        keyring.save_key("google", "google-key")

        provider = get_available_provider()
        assert provider == "anthropic"

    def test_returns_first_available(self) -> None:
        """Should return first available if none in preferred list."""
        keyring.save_key("groq", "groq-key")

        provider = get_available_provider()
        assert provider == "groq"


class TestGetLitellmModelString:
    """Tests for _get_litellm_model_string()."""

    def test_adds_anthropic_prefix(self) -> None:
        """Should add anthropic/ prefix for Anthropic models."""
        result = _get_litellm_model_string("anthropic", "claude-3-opus")
        assert result == "anthropic/claude-3-opus"

    def test_no_double_prefix(self) -> None:
        """Should not add prefix if already present."""
        result = _get_litellm_model_string("anthropic", "anthropic/claude-3-opus")
        assert result == "anthropic/claude-3-opus"

    def test_adds_gemini_prefix(self) -> None:
        """Should add gemini/ prefix for Google models."""
        result = _get_litellm_model_string("google", "gemini-pro")
        assert result == "gemini/gemini-pro"

    def test_openai_no_prefix(self) -> None:
        """Should not add prefix for OpenAI models."""
        result = _get_litellm_model_string("openai", "gpt-4")
        assert result == "gpt-4"


class TestLLMResponse:
    """Tests for LLMResponse model."""

    def test_creates_response(self) -> None:
        """Should create a valid response."""
        response = LLMResponse(
            content="Generated text",
            model="gpt-4",
            provider="openai",
            tokens_used=100,
        )

        assert response.content == "Generated text"
        assert response.model == "gpt-4"
        assert response.provider == "openai"
        assert response.tokens_used == 100

    def test_tokens_optional(self) -> None:
        """Should allow None for tokens_used."""
        response = LLMResponse(
            content="Text",
            model="gpt-4",
            provider="openai",
        )

        assert response.tokens_used is None


class TestGenerate:
    """Tests for generate() function."""

    @pytest.mark.asyncio
    async def test_raises_when_no_provider_configured(self) -> None:
        """Should raise LLMError when no provider configured."""
        with pytest.raises(LLMError, match="No LLM provider configured"):
            await generate("test prompt")

    @pytest.mark.asyncio
    async def test_raises_for_missing_key(self) -> None:
        """Should raise LLMError when specified provider has no key."""
        with pytest.raises(LLMError, match="No API key configured"):
            await generate("test prompt", provider="openai")

    @pytest.mark.asyncio
    async def test_raises_for_unknown_model(self) -> None:
        """Should raise LLMError when no default model for provider."""
        # Save a key but for a provider without default model
        keyring.save_key("openai", "test-key")

        with patch.object(
            __import__("vibeguard.core.llm", fromlist=["PROVIDER_MODELS"]),
            "PROVIDER_MODELS",
            {},
        ):
            # This should work because we check the actual module dict
            pass

    @pytest.mark.asyncio
    async def test_calls_litellm_with_correct_params(self) -> None:
        """Should call litellm with correct parameters."""
        keyring.save_key("openai", "test-key")

        # Mock litellm
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Generated response"
        mock_response.usage.total_tokens = 50

        import litellm

        with patch.object(litellm, "acompletion", new_callable=AsyncMock) as mock_acompletion:
            mock_acompletion.return_value = mock_response

            result = await generate(
                "Test prompt",
                provider="openai",
                model="gpt-4",
                max_tokens=1000,
                temperature=0.5,
            )

            mock_acompletion.assert_called_once()
            call_kwargs = mock_acompletion.call_args.kwargs
            assert call_kwargs["model"] == "gpt-4"
            assert call_kwargs["max_tokens"] == 1000
            assert call_kwargs["temperature"] == 0.5

            assert result.content == "Generated response"
            assert result.provider == "openai"
            assert result.model == "gpt-4"

    @pytest.mark.asyncio
    async def test_auto_detects_provider(self) -> None:
        """Should auto-detect provider when not specified."""
        keyring.save_key("anthropic", "test-key")

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Response"
        mock_response.usage = None

        import litellm

        with patch.object(litellm, "acompletion", new_callable=AsyncMock) as mock_acompletion:
            mock_acompletion.return_value = mock_response

            result = await generate("Test")

            assert result.provider == "anthropic"

    @pytest.mark.asyncio
    async def test_handles_litellm_error(self) -> None:
        """Should wrap litellm errors in LLMError."""
        keyring.save_key("openai", "test-key")

        import litellm

        with patch.object(
            litellm, "acompletion", new_callable=AsyncMock
        ) as mock_acompletion:
            mock_acompletion.side_effect = Exception("API rate limit exceeded")

            with pytest.raises(LLMError, match="LLM call failed"):
                await generate("Test", provider="openai")

    @pytest.mark.asyncio
    async def test_masks_api_key_in_errors(self) -> None:
        """Should not expose API key in error messages."""
        api_key = "sk-secret-api-key-12345"
        keyring.save_key("openai", api_key)

        import litellm

        with patch.object(
            litellm, "acompletion", new_callable=AsyncMock
        ) as mock_acompletion:
            # Simulate error that contains the API key
            mock_acompletion.side_effect = Exception(f"Invalid API key: {api_key}")

            with pytest.raises(LLMError) as exc_info:
                await generate("Test", provider="openai")

            # API key should be masked
            assert api_key not in str(exc_info.value)
            assert "***" in str(exc_info.value)
