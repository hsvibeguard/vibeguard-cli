"""Tests for bootstrap functionality."""

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from vibeguard.core.bootstrap import (
    BootstrapResult,
    BootstrapSummary,
    ScannerStatus,
    _is_binary_available,
    _is_docker_available,
    bootstrap_scanners,
)
from vibeguard.core.cache import save_scan
from vibeguard.models.finding import Category, Finding, Severity
from vibeguard.models.scan_result import ScanResult
from vibeguard.scanners import load_manifest


class TestScannerStatus:
    """Tests for ScannerStatus enum."""

    def test_status_values(self) -> None:
        """Test that ScannerStatus has expected values."""
        assert ScannerStatus.READY == "ready"
        assert ScannerStatus.DOWNLOADED == "downloaded"
        assert ScannerStatus.INSTALLED == "installed"
        assert ScannerStatus.DOCKER_ONLY == "docker_only"
        assert ScannerStatus.UNAVAILABLE == "unavailable"


class TestBootstrapResult:
    """Tests for BootstrapResult dataclass."""

    def test_result_creation(self) -> None:
        """Test creating a BootstrapResult."""
        result = BootstrapResult(
            name="gitleaks",
            display_name="Gitleaks",
            status=ScannerStatus.READY,
            message="Available in PATH",
        )
        assert result.name == "gitleaks"
        assert result.display_name == "Gitleaks"
        assert result.status == ScannerStatus.READY
        assert result.message == "Available in PATH"

    def test_result_default_message(self) -> None:
        """Test BootstrapResult with default empty message."""
        result = BootstrapResult(
            name="gitleaks",
            display_name="Gitleaks",
            status=ScannerStatus.READY,
        )
        assert result.message == ""


class TestBootstrapSummary:
    """Tests for BootstrapSummary dataclass."""

    def test_summary_counts(self) -> None:
        """Test that BootstrapSummary calculates counts correctly."""
        results = [
            BootstrapResult("a", "A", ScannerStatus.READY),
            BootstrapResult("b", "B", ScannerStatus.READY),
            BootstrapResult("c", "C", ScannerStatus.DOWNLOADED),
            BootstrapResult("d", "D", ScannerStatus.INSTALLED),
            BootstrapResult("e", "E", ScannerStatus.DOCKER_ONLY),
            BootstrapResult("f", "F", ScannerStatus.UNAVAILABLE),
        ]
        summary = BootstrapSummary(results=results)

        assert summary.ready_count == 2
        assert summary.downloaded_count == 1
        assert summary.installed_count == 1
        assert summary.docker_only_count == 1
        assert summary.unavailable_count == 1

    def test_summary_total_available(self) -> None:
        """Test that total_available excludes unavailable."""
        results = [
            BootstrapResult("a", "A", ScannerStatus.READY),
            BootstrapResult("b", "B", ScannerStatus.DOWNLOADED),
            BootstrapResult("c", "C", ScannerStatus.DOCKER_ONLY),
            BootstrapResult("d", "D", ScannerStatus.UNAVAILABLE),
        ]
        summary = BootstrapSummary(results=results)

        assert summary.total_available == 3  # Excludes unavailable


class TestBinaryAvailable:
    """Tests for _is_binary_available function."""

    def test_available_binary(self) -> None:
        """Test detecting available binary (python should always exist)."""
        # Python should be available on any system running these tests
        assert _is_binary_available("python") or _is_binary_available("python3")

    def test_unavailable_binary(self) -> None:
        """Test detecting unavailable binary."""
        assert not _is_binary_available("nonexistent_binary_xyz_123")


class TestDockerAvailable:
    """Tests for _is_docker_available function."""

    def test_docker_check_does_not_raise(self) -> None:
        """Test that _is_docker_available doesn't raise exceptions."""
        # This test just ensures the function doesn't crash
        result = _is_docker_available()
        assert isinstance(result, bool)


class TestLoadManifestWithPip:
    """Tests for loading manifests with pip configuration."""

    def test_bandit_manifest_has_pip_config(self) -> None:
        """Test that bandit manifest includes pip configuration."""
        manifest = load_manifest("bandit")
        assert manifest.pip_config is not None
        assert manifest.pip_config.package_name == "bandit"
        assert "pip" in manifest.install_strategies

    def test_gitleaks_manifest_no_pip_config(self) -> None:
        """Test that gitleaks manifest has no pip configuration."""
        manifest = load_manifest("gitleaks")
        assert manifest.pip_config is None
        assert "pip" not in manifest.install_strategies

    def test_semgrep_manifest_has_pip_config(self) -> None:
        """Test that semgrep manifest can fall back to pip installation."""
        manifest = load_manifest("semgrep")
        assert manifest.pip_config is not None
        assert manifest.pip_config.package_name == "semgrep"
        assert "pip" in manifest.install_strategies


class TestBootstrapScanners:
    """Tests for bootstrap_scanners function."""

    @pytest.mark.asyncio
    async def test_bootstrap_with_missing_manifest(self) -> None:
        """Test bootstrapping with a non-existent scanner."""
        summary = await bootstrap_scanners(["nonexistent_scanner"])

        assert len(summary.results) == 1
        assert summary.results[0].status == ScannerStatus.UNAVAILABLE
        assert summary.results[0].message == "Manifest not found"

    @pytest.mark.asyncio
    async def test_bootstrap_no_download_option(self) -> None:
        """Test bootstrapping with no_download option skips downloads."""
        with patch(
            "vibeguard.core.bootstrap._is_binary_available", return_value=False
        ), patch(
            "vibeguard.core.bootstrap.get_cached_binary", return_value=None
        ), patch(
            "vibeguard.core.bootstrap._try_download", new_callable=AsyncMock
        ) as mock_download, patch(
            "vibeguard.core.bootstrap._is_docker_available", return_value=True
        ):
            summary = await bootstrap_scanners(["gitleaks"], no_download=True)

            # Should not attempt download
            mock_download.assert_not_called()
            # Should fall back to Docker
            assert summary.results[0].status == ScannerStatus.DOCKER_ONLY

    @pytest.mark.asyncio
    async def test_bootstrap_no_pip_install_option(self) -> None:
        """Test bootstrapping with no_pip_install option skips pip installs."""
        with patch(
            "vibeguard.core.bootstrap._is_binary_available", return_value=False
        ), patch(
            "vibeguard.core.bootstrap._try_pip_install"
        ) as mock_pip:
            await bootstrap_scanners(["bandit"], no_pip_install=True)

            # Should not attempt pip install
            mock_pip.assert_not_called()

    @pytest.mark.asyncio
    async def test_bootstrap_scanner_ready_in_path(self) -> None:
        """Test bootstrapping when scanner is already in PATH."""
        with patch(
            "vibeguard.core.bootstrap._is_binary_available", return_value=True
        ):
            summary = await bootstrap_scanners(["gitleaks"])

            assert summary.results[0].status == ScannerStatus.READY
            assert "PATH" in summary.results[0].message

    @pytest.mark.asyncio
    async def test_bootstrap_scanner_already_cached(self) -> None:
        """Test bootstrapping when scanner is already downloaded/cached."""
        mock_path = Path("/mock/path/gitleaks")
        with patch(
            "vibeguard.core.bootstrap._is_binary_available", return_value=False
        ), patch(
            "vibeguard.core.bootstrap.get_cached_binary", return_value=mock_path
        ):
            summary = await bootstrap_scanners(["gitleaks"])

            assert summary.results[0].status == ScannerStatus.READY
            assert "Cached" in summary.results[0].message

    @pytest.mark.asyncio
    async def test_bootstrap_multiple_scanners(self) -> None:
        """Test bootstrapping multiple scanners."""
        with patch(
            "vibeguard.core.bootstrap._is_binary_available", return_value=True
        ):
            summary = await bootstrap_scanners(["gitleaks", "trivy", "bandit"])

            assert len(summary.results) == 3
            assert summary.ready_count == 3


class TestCacheEncoding:
    """Tests for cache encoding (UTF-8)."""

    @pytest.fixture
    def temp_repo(self, tmp_path: Path) -> Path:
        """Create a temporary repository directory."""
        return tmp_path

    @pytest.fixture
    def sample_result_with_unicode(self) -> ScanResult:
        """Create a scan result with unicode characters."""
        finding = Finding(
            scanner="semgrep",
            rule_id="test.rule",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            title="Test Finding with Unicode",
            message="Unicode: \u4e2d\u6587 \u65e5\u672c\u8a9e \ud55c\uad6d\uc5b4",  # CJK
            file_path="test_\u00e9\u00e8\u00ea.py",  # French accents
            line_start=1,
        )
        return ScanResult(
            repo_root="/path/to/repo",
            started_at=datetime.now(),
            finished_at=datetime.now(),
            findings=[finding],
            scanners_run=["semgrep"],
            scanners_skipped=[],
            partial=False,
        )

    def test_cache_saves_unicode_correctly(
        self, temp_repo: Path, sample_result_with_unicode: ScanResult
    ) -> None:
        """Test that cache saves unicode characters correctly."""
        cache_path = save_scan(sample_result_with_unicode, temp_repo)

        # Read back with explicit UTF-8 encoding
        content = cache_path.read_text(encoding="utf-8")
        data = json.loads(content)

        # Verify unicode is preserved
        finding_data = data["scan_result"]["findings"][0]
        assert "\u4e2d\u6587" in finding_data["message"]  # Chinese
        assert "\u65e5\u672c\u8a9e" in finding_data["message"]  # Japanese
        assert "\ud55c\uad6d\uc5b4" in finding_data["message"]  # Korean
        assert "\u00e9" in finding_data["file_path"]  # French accent

    def test_cache_file_is_utf8_encoded(
        self, temp_repo: Path, sample_result_with_unicode: ScanResult
    ) -> None:
        """Test that cache file is properly UTF-8 encoded."""
        cache_path = save_scan(sample_result_with_unicode, temp_repo)

        # Read as bytes and verify it's valid UTF-8
        raw_bytes = cache_path.read_bytes()
        decoded = raw_bytes.decode("utf-8")  # Should not raise
        assert "\u4e2d\u6587" in decoded


class TestAssetResolverSelection:
    """Tests for asset resolver (download config) selection."""

    def test_gitleaks_has_download_config(self) -> None:
        """Test that Gitleaks manifest has download configuration."""
        manifest = load_manifest("gitleaks")
        assert manifest.download_config is not None
        assert "github.com/gitleaks" in manifest.download_config.url_template
        assert manifest.download_config.binary_name == "gitleaks"

    def test_trivy_has_download_config(self) -> None:
        """Test that Trivy manifest has download configuration."""
        manifest = load_manifest("trivy")
        assert manifest.download_config is not None
        assert "aquasecurity/trivy" in manifest.download_config.url_template
        assert manifest.download_config.binary_name == "trivy"

    def test_trufflehog_has_download_config(self) -> None:
        """Test that TruffleHog manifest has download configuration."""
        manifest = load_manifest("trufflehog")
        assert manifest.download_config is not None
        assert manifest.download_config.binary_name == "trufflehog"

    def test_bandit_no_download_config(self) -> None:
        """Test that Bandit (pip-only) has no download configuration."""
        manifest = load_manifest("bandit")
        assert manifest.download_config is None
        assert manifest.pip_config is not None

    def test_semgrep_no_download_config(self) -> None:
        """Test that Semgrep has no download configuration (docker fallback)."""
        manifest = load_manifest("semgrep")
        assert manifest.download_config is None
        assert manifest.docker_config is not None

    def test_download_config_has_windows_override(self) -> None:
        """Test that download configs specify Windows archive type where needed."""
        manifest = load_manifest("gitleaks")
        assert manifest.download_config is not None
        assert manifest.download_config.windows_archive_type == "zip"

        manifest = load_manifest("trivy")
        assert manifest.download_config is not None
        assert manifest.download_config.windows_archive_type == "zip"
