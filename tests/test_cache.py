"""Tests for scan cache functionality."""

import json
from datetime import datetime
from pathlib import Path

import pytest

from vibeguard.core import cache
from vibeguard.models.finding import Category, Finding, Severity
from vibeguard.models.scan_result import ScanResult


@pytest.fixture
def temp_repo(tmp_path: Path) -> Path:
    """Create a temporary repository directory."""
    return tmp_path


@pytest.fixture
def sample_result() -> ScanResult:
    """Create a sample scan result."""
    finding = Finding(
        scanner="semgrep",
        rule_id="test.rule",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        title="Test Finding",
        message="This is a test finding",
        file_path="test.py",
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


class TestSaveScan:
    """Tests for save_scan function."""

    def test_save_creates_file(self, temp_repo: Path, sample_result: ScanResult) -> None:
        """Test that save_scan creates a cache file."""
        cache_path = cache.save_scan(sample_result, temp_repo)

        assert cache_path.exists()
        assert cache_path.parent == temp_repo / ".vibeguard" / "cache"
        assert cache_path.name.startswith("scan_")
        assert cache_path.suffix == ".json"

    def test_save_creates_directories(self, temp_repo: Path, sample_result: ScanResult) -> None:
        """Test that save_scan creates cache directories if needed."""
        cache_path = cache.save_scan(sample_result, temp_repo)

        assert (temp_repo / ".vibeguard" / "cache").exists()
        assert cache_path.exists()

    def test_saved_json_is_valid(self, temp_repo: Path, sample_result: ScanResult) -> None:
        """Test that saved file contains valid JSON."""
        cache_path = cache.save_scan(sample_result, temp_repo)
        data = json.loads(cache_path.read_text())

        assert "schema_version" in data
        assert "vibeguard_version" in data
        assert "scan_result" in data

    def test_saved_scan_result_complete(self, temp_repo: Path, sample_result: ScanResult) -> None:
        """Test that scan result is completely saved."""
        cache_path = cache.save_scan(sample_result, temp_repo)
        data = json.loads(cache_path.read_text())

        scan_data = data["scan_result"]
        assert scan_data["repo_root"] == sample_result.repo_root
        assert len(scan_data["findings"]) == 1
        assert scan_data["scanners_run"] == ["semgrep"]


class TestLoadLatestScan:
    """Tests for load_latest_scan function."""

    def test_load_returns_result(self, temp_repo: Path, sample_result: ScanResult) -> None:
        """Test that load_latest_scan returns saved result."""
        cache.save_scan(sample_result, temp_repo)
        loaded = cache.load_latest_scan(temp_repo)

        assert loaded is not None
        assert loaded.repo_root == sample_result.repo_root
        assert len(loaded.findings) == 1

    def test_load_returns_none_if_no_cache(self, temp_repo: Path) -> None:
        """Test that load_latest_scan returns None if no cache exists."""
        result = cache.load_latest_scan(temp_repo)
        assert result is None

    def test_load_returns_newest(self, temp_repo: Path, sample_result: ScanResult) -> None:
        """Test that load_latest_scan returns the newest scan."""
        # Save first scan
        cache.save_scan(sample_result, temp_repo)

        # Modify and save second scan
        sample_result.scanners_run = ["semgrep", "gitleaks"]
        cache.save_scan(sample_result, temp_repo)

        loaded = cache.load_latest_scan(temp_repo)
        assert loaded is not None
        assert loaded.scanners_run == ["semgrep", "gitleaks"]


class TestListCachedScans:
    """Tests for list_cached_scans function."""

    def test_list_returns_empty_if_no_cache(self, temp_repo: Path) -> None:
        """Test list returns empty if no cache directory."""
        result = cache.list_cached_scans(temp_repo)
        assert result == []

    def test_list_returns_files(self, temp_repo: Path, sample_result: ScanResult) -> None:
        """Test list returns cached scan files."""
        import time

        cache.save_scan(sample_result, temp_repo)
        time.sleep(0.01)  # Ensure different timestamps
        cache.save_scan(sample_result, temp_repo)

        files = cache.list_cached_scans(temp_repo)
        assert len(files) == 2
        assert all(f.name.startswith("scan_") for f in files)

    def test_list_ordered_newest_first(self, temp_repo: Path, sample_result: ScanResult) -> None:
        """Test list is ordered with newest first."""
        import time

        cache.save_scan(sample_result, temp_repo)
        time.sleep(0.1)  # Ensure different timestamps
        second = cache.save_scan(sample_result, temp_repo)

        files = cache.list_cached_scans(temp_repo)
        assert files[0] == second


class TestClearCache:
    """Tests for clear_cache function."""

    def test_clear_removes_files(self, temp_repo: Path, sample_result: ScanResult) -> None:
        """Test clear_cache removes all cache files."""
        import time

        cache.save_scan(sample_result, temp_repo)
        time.sleep(0.01)  # Ensure different timestamps
        cache.save_scan(sample_result, temp_repo)

        deleted = cache.clear_cache(temp_repo)

        assert deleted == 2
        assert cache.list_cached_scans(temp_repo) == []

    def test_clear_returns_zero_if_empty(self, temp_repo: Path) -> None:
        """Test clear_cache returns 0 if no cache."""
        deleted = cache.clear_cache(temp_repo)
        assert deleted == 0
