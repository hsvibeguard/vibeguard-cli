"""Tests for the bundle delivery system."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from vibeguard.core.bundles import (
    _DEFAULT_FIX_PROMPT,
    BundleError,
    ensure_bundle,
    fetch_bundle,
    get_cached_version,
    get_hardcoded_fallback,
    get_patch_rule,
    get_prompt,
    load_bundle_metadata,
    load_cached_bundle,
    save_bundle,
)
from vibeguard.models.auth import Bundle, BundleMetadata

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def bundles_dir(tmp_path: Path):
    """Override BUNDLES_DIR to use tmp_path."""
    bundle_dir = tmp_path / "bundles"
    bundle_dir.mkdir()
    with (
        patch("vibeguard.core.bundles.BUNDLES_DIR", bundle_dir),
        patch("vibeguard.core.bundles.BUNDLE_FILE", bundle_dir / "current.json"),
        patch("vibeguard.core.bundles.BUNDLE_META_FILE", bundle_dir / "meta.json"),
    ):
        yield bundle_dir


@pytest.fixture()
def sample_bundle() -> Bundle:
    """Create a sample bundle for testing."""
    return Bundle(
        version="1.0.0",
        prompts={
            "fix_prompt": "Custom fix prompt for {scanner} {file_path}",
            "patch_system": "Custom system prompt",
        },
        patch_rules={
            "max_tokens": 8192,
            "temperature": 0.1,
        },
        defaults={
            "bundle_fetch_interval_hours": 12,
        },
    )


@pytest.fixture()
def cached_bundle(bundles_dir: Path, sample_bundle: Bundle):
    """Write a sample bundle to the cache."""
    bundle_file = bundles_dir / "current.json"
    bundle_file.write_text(sample_bundle.model_dump_json(indent=2), encoding="utf-8")

    meta = BundleMetadata(
        version=sample_bundle.version,
        downloaded_at=datetime.now(UTC),
        sha256="abc123",
        is_current=True,
    )
    meta_file = bundles_dir / "meta.json"
    meta_file.write_text(meta.model_dump_json(indent=2), encoding="utf-8")
    return sample_bundle


# ---------------------------------------------------------------------------
# load_cached_bundle
# ---------------------------------------------------------------------------


class TestLoadCachedBundle:
    """Tests for load_cached_bundle()."""

    def test_returns_none_when_no_cache(self, bundles_dir: Path):
        result = load_cached_bundle()
        assert result is None

    def test_returns_bundle_from_valid_cache(self, cached_bundle: Bundle):
        result = load_cached_bundle()
        assert result is not None
        assert result.version == "1.0.0"
        assert "fix_prompt" in result.prompts

    def test_returns_none_on_corrupted_cache(self, bundles_dir: Path):
        bundle_file = bundles_dir / "current.json"
        bundle_file.write_text("not valid json{{{", encoding="utf-8")
        result = load_cached_bundle()
        assert result is None

    def test_returns_none_on_invalid_structure(self, bundles_dir: Path):
        bundle_file = bundles_dir / "current.json"
        bundle_file.write_text('{"not_a_bundle": true}', encoding="utf-8")
        result = load_cached_bundle()
        assert result is None


# ---------------------------------------------------------------------------
# load_bundle_metadata
# ---------------------------------------------------------------------------


class TestLoadBundleMetadata:
    """Tests for load_bundle_metadata()."""

    def test_returns_none_when_no_meta(self, bundles_dir: Path):
        result = load_bundle_metadata()
        assert result is None

    def test_returns_metadata_from_cache(self, cached_bundle: Bundle):
        result = load_bundle_metadata()
        assert result is not None
        assert result.version == "1.0.0"
        assert result.sha256 == "abc123"

    def test_returns_none_on_corrupted_meta(self, bundles_dir: Path):
        meta_file = bundles_dir / "meta.json"
        meta_file.write_text("bad json", encoding="utf-8")
        result = load_bundle_metadata()
        assert result is None


# ---------------------------------------------------------------------------
# save_bundle
# ---------------------------------------------------------------------------


class TestSaveBundle:
    """Tests for save_bundle()."""

    def test_saves_bundle_to_disk(self, bundles_dir: Path, sample_bundle: Bundle):
        save_bundle(sample_bundle, sha256="deadbeef")

        bundle_file = bundles_dir / "current.json"
        assert bundle_file.exists()
        data = json.loads(bundle_file.read_text(encoding="utf-8"))
        assert data["version"] == "1.0.0"

    def test_saves_metadata_with_sha256(self, bundles_dir: Path, sample_bundle: Bundle):
        save_bundle(sample_bundle, sha256="deadbeef")

        meta_file = bundles_dir / "meta.json"
        assert meta_file.exists()
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
        assert meta["sha256"] == "deadbeef"
        assert meta["version"] == "1.0.0"
        assert meta["is_current"] is True

    def test_creates_bundles_directory(self, tmp_path: Path, sample_bundle: Bundle):
        new_dir = tmp_path / "new_bundles"
        with (
            patch("vibeguard.core.bundles.BUNDLES_DIR", new_dir),
            patch("vibeguard.core.bundles.BUNDLE_FILE", new_dir / "current.json"),
            patch("vibeguard.core.bundles.BUNDLE_META_FILE", new_dir / "meta.json"),
        ):
            save_bundle(sample_bundle)
            assert new_dir.exists()
            assert (new_dir / "current.json").exists()


# ---------------------------------------------------------------------------
# get_cached_version
# ---------------------------------------------------------------------------


class TestGetCachedVersion:
    """Tests for get_cached_version()."""

    def test_returns_none_when_no_cache(self, bundles_dir: Path):
        result = get_cached_version()
        assert result is None

    def test_returns_version_from_cache(self, cached_bundle: Bundle):
        result = get_cached_version()
        assert result == "1.0.0"


# ---------------------------------------------------------------------------
# fetch_bundle (async)
# ---------------------------------------------------------------------------


class TestFetchBundle:
    """Tests for fetch_bundle()."""

    @pytest.mark.asyncio
    async def test_fetches_new_bundle(self, bundles_dir: Path, sample_bundle: Bundle):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = sample_bundle.model_dump()
        mock_response.content = sample_bundle.model_dump_json().encode()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("vibeguard.core.bundles.httpx.AsyncClient", return_value=mock_client):
            result = await fetch_bundle("test-token")
            assert result is not None
            assert result.version == "1.0.0"

    @pytest.mark.asyncio
    async def test_returns_none_on_304(self, bundles_dir: Path):
        mock_response = MagicMock()
        mock_response.status_code = 304

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("vibeguard.core.bundles.httpx.AsyncClient", return_value=mock_client):
            result = await fetch_bundle("test-token")
            assert result is None

    @pytest.mark.asyncio
    async def test_raises_on_401(self, bundles_dir: Path):
        mock_response = MagicMock()
        mock_response.status_code = 401

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("vibeguard.core.bundles.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(BundleError, match="Unauthorized"):
                await fetch_bundle("bad-token")

    @pytest.mark.asyncio
    async def test_raises_on_network_error(self, bundles_dir: Path):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("vibeguard.core.bundles.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(BundleError, match="Network error"):
                await fetch_bundle("test-token")

    @pytest.mark.asyncio
    async def test_sends_cached_version_as_etag(self, cached_bundle: Bundle):
        mock_response = MagicMock()
        mock_response.status_code = 304

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("vibeguard.core.bundles.httpx.AsyncClient", return_value=mock_client):
            await fetch_bundle("test-token")

            # Verify If-None-Match header was sent
            call_kwargs = mock_client.get.call_args
            headers = call_kwargs.kwargs.get("headers", {})
            assert headers.get("If-None-Match") == "1.0.0"


# ---------------------------------------------------------------------------
# ensure_bundle (async)
# ---------------------------------------------------------------------------


class TestEnsureBundle:
    """Tests for ensure_bundle()."""

    @pytest.mark.asyncio
    async def test_returns_fetched_bundle_when_online(self, bundles_dir: Path):
        new_bundle = Bundle(version="2.0.0", prompts={"fix_prompt": "v2"})

        with patch("vibeguard.core.bundles.fetch_bundle", new_callable=AsyncMock) as mock:
            mock.return_value = new_bundle
            result = await ensure_bundle("test-token")
            assert result.version == "2.0.0"

    @pytest.mark.asyncio
    async def test_returns_cached_when_fetch_returns_none(self, cached_bundle: Bundle):
        with patch("vibeguard.core.bundles.fetch_bundle", new_callable=AsyncMock) as mock:
            mock.return_value = None  # 304 Not Modified
            result = await ensure_bundle("test-token")
            assert result.version == "1.0.0"

    @pytest.mark.asyncio
    async def test_returns_cached_bundle_when_offline(self, cached_bundle: Bundle):
        with patch("vibeguard.core.bundles.fetch_bundle", new_callable=AsyncMock) as mock:
            mock.side_effect = BundleError("Network error")
            result = await ensure_bundle("test-token")
            assert result.version == "1.0.0"

    @pytest.mark.asyncio
    async def test_returns_hardcoded_when_no_cache(self, bundles_dir: Path):
        with patch("vibeguard.core.bundles.fetch_bundle", new_callable=AsyncMock) as mock:
            mock.side_effect = BundleError("Network error")
            result = await ensure_bundle("test-token")
            assert result.version == "0.0.0-builtin"
            assert "fix_prompt" in result.prompts

    @pytest.mark.asyncio
    async def test_skips_fetch_when_no_token(self, cached_bundle: Bundle):
        with patch("vibeguard.core.bundles.fetch_bundle", new_callable=AsyncMock) as mock:
            result = await ensure_bundle(None)
            mock.assert_not_called()
            assert result.version == "1.0.0"

    @pytest.mark.asyncio
    async def test_hardcoded_fallback_when_no_token_no_cache(self, bundles_dir: Path):
        result = await ensure_bundle(None)
        assert result.version == "0.0.0-builtin"


# ---------------------------------------------------------------------------
# get_hardcoded_fallback
# ---------------------------------------------------------------------------


class TestGetHardcodedFallback:
    """Tests for get_hardcoded_fallback()."""

    def test_returns_valid_bundle(self):
        bundle = get_hardcoded_fallback()
        assert bundle.version == "0.0.0-builtin"
        assert isinstance(bundle.prompts, dict)
        assert isinstance(bundle.patch_rules, dict)

    def test_contains_fix_prompt_key(self):
        bundle = get_hardcoded_fallback()
        assert "fix_prompt" in bundle.prompts

    def test_fix_prompt_matches_default(self):
        bundle = get_hardcoded_fallback()
        assert bundle.prompts["fix_prompt"] == _DEFAULT_FIX_PROMPT

    def test_contains_patch_rules(self):
        bundle = get_hardcoded_fallback()
        assert bundle.patch_rules["max_tokens"] == 4096
        assert bundle.patch_rules["temperature"] == 0.2


# ---------------------------------------------------------------------------
# get_prompt / get_patch_rule
# ---------------------------------------------------------------------------


class TestGetPrompt:
    """Tests for get_prompt()."""

    def test_returns_bundle_prompt_when_exists(self, sample_bundle: Bundle):
        result = get_prompt(sample_bundle, "fix_prompt", "fallback")
        assert result == "Custom fix prompt for {scanner} {file_path}"

    def test_returns_fallback_when_key_missing(self, sample_bundle: Bundle):
        result = get_prompt(sample_bundle, "nonexistent_key", "my_fallback")
        assert result == "my_fallback"

    def test_returns_fallback_for_empty_bundle(self):
        empty = Bundle(version="0.0.0")
        result = get_prompt(empty, "fix_prompt", "fallback_prompt")
        assert result == "fallback_prompt"


class TestGetPatchRule:
    """Tests for get_patch_rule()."""

    def test_returns_rule_when_exists(self, sample_bundle: Bundle):
        result = get_patch_rule(sample_bundle, "max_tokens", 4096)
        assert result == 8192

    def test_returns_fallback_when_key_missing(self, sample_bundle: Bundle):
        result = get_patch_rule(sample_bundle, "nonexistent", 42)
        assert result == 42

    def test_returns_none_default_fallback(self, sample_bundle: Bundle):
        result = get_patch_rule(sample_bundle, "nonexistent")
        assert result is None


# ---------------------------------------------------------------------------
# build_fix_prompt with bundle
# ---------------------------------------------------------------------------


class TestBuildFixPromptWithBundle:
    """Tests for build_fix_prompt accepting bundle parameter."""

    @pytest.fixture()
    def mock_finding(self):
        """Create a minimal mock finding."""
        from vibeguard.models.finding import Finding, Severity

        return Finding(
            id="test123",
            scanner="semgrep",
            rule_id="python.security.eval",
            severity=Severity.HIGH,
            category="security",
            title="Use of eval()",
            message="Avoid eval() as it can execute arbitrary code.",
            file_path="app/main.py",
            line_start=42,
        )

    def test_uses_default_when_bundle_is_none(self, mock_finding, tmp_path: Path):
        from vibeguard.cli.fix import build_fix_prompt

        prompt = build_fix_prompt(mock_finding, tmp_path, bundle=None)
        assert "security expert" in prompt
        assert "semgrep" in prompt

    def test_uses_bundle_prompt_when_provided(self, mock_finding, tmp_path: Path):
        from vibeguard.cli.fix import build_fix_prompt

        bundle = Bundle(
            version="1.0.0",
            prompts={
                "fix_prompt": "CUSTOM TEMPLATE: {scanner} found issue in {file_path}",
            },
        )
        prompt = build_fix_prompt(mock_finding, tmp_path, bundle=bundle)
        assert prompt.startswith("CUSTOM TEMPLATE:")
        assert "semgrep" in prompt
        assert "app/main.py" in prompt

    def test_uses_default_when_bundle_key_missing(self, mock_finding, tmp_path: Path):
        from vibeguard.cli.fix import build_fix_prompt

        bundle = Bundle(
            version="1.0.0",
            prompts={},  # No fix_prompt key
        )
        prompt = build_fix_prompt(mock_finding, tmp_path, bundle=bundle)
        assert "security expert" in prompt  # Falls back to default
