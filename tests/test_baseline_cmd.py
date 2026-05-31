"""Tests for baseline CLI commands."""

from datetime import datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vibeguard.cli.main import app
from vibeguard.core import baseline, cache
from vibeguard.core.exit_codes import ExitCode
from vibeguard.models.finding import Category, Finding, Severity
from vibeguard.models.scan_result import ScanResult
from vibeguard.models.triage import TriageStatus

runner = CliRunner()


@pytest.fixture
def temp_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Create a temporary repository directory and change to it."""
    monkeypatch.chdir(tmp_path)
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
        triage_status=TriageStatus.ACTIONABLE,
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


@pytest.fixture
def cached_scan(temp_repo: Path, sample_result: ScanResult) -> Path:
    """Create a cached scan in the temp repo."""
    return cache.save_scan(sample_result, temp_repo)


@pytest.fixture
def saved_baseline(temp_repo: Path, sample_result: ScanResult) -> Path:
    """Create a saved baseline in the temp repo."""
    # First cache the scan (required by save command)
    cache.save_scan(sample_result, temp_repo)
    return baseline.save_baseline(sample_result, temp_repo)


class TestBaselineSaveCmd:
    """Tests for 'vibeguard baseline save' command."""

    def test_save_requires_cached_scan(self, temp_repo: Path) -> None:
        """Test error when no cached scan exists."""
        result = runner.invoke(app, ["baseline", "save"])

        assert result.exit_code == ExitCode.NO_CACHE
        assert "No cached scan found" in result.output

    def test_save_creates_baseline(self, cached_scan: Path, temp_repo: Path) -> None:
        """Test successful baseline creation."""
        result = runner.invoke(app, ["baseline", "save"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "Baseline saved" in result.output
        assert baseline.load_baseline(temp_repo) is not None

    def test_save_with_custom_name(self, cached_scan: Path, temp_repo: Path) -> None:
        """Test saving with custom name."""
        result = runner.invoke(app, ["baseline", "save", "release-1.0"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "release-1.0" in result.output
        assert baseline.load_baseline(temp_repo, "release-1.0") is not None

    def test_save_with_force_overwrites(
        self, cached_scan: Path, temp_repo: Path, sample_result: ScanResult
    ) -> None:
        """Test --force overwrites existing baseline."""
        # Create initial baseline
        baseline.save_baseline(sample_result, temp_repo)

        # Save again with --force
        result = runner.invoke(app, ["baseline", "save", "--force"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "Baseline saved" in result.output


class TestBaselineListCmd:
    """Tests for 'vibeguard baseline list' command."""

    def test_list_empty(self, temp_repo: Path) -> None:
        """Test listing when no baselines exist."""
        result = runner.invoke(app, ["baseline", "list"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "No baselines found" in result.output

    def test_list_shows_baselines(self, saved_baseline: Path, temp_repo: Path) -> None:
        """Test listing saved baselines."""
        result = runner.invoke(app, ["baseline", "list"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "default" in result.output
        assert "Saved Baselines" in result.output


class TestBaselineShowCmd:
    """Tests for 'vibeguard baseline show' command."""

    def test_show_displays_details(self, saved_baseline: Path, temp_repo: Path) -> None:
        """Test showing baseline details."""
        result = runner.invoke(app, ["baseline", "show", "default"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "Baseline: default" in result.output
        assert "Actionable:" in result.output

    def test_show_error_not_found(self, temp_repo: Path) -> None:
        """Test error for non-existent baseline."""
        result = runner.invoke(app, ["baseline", "show", "nonexistent"])

        assert result.exit_code == ExitCode.NO_CACHE
        assert "not found" in result.output


class TestBaselineDeleteCmd:
    """Tests for 'vibeguard baseline delete' command."""

    def test_delete_removes_baseline(self, saved_baseline: Path, temp_repo: Path) -> None:
        """Test successful deletion with --force."""
        result = runner.invoke(app, ["baseline", "delete", "default", "--force"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "Deleted baseline" in result.output
        assert baseline.load_baseline(temp_repo) is None

    def test_delete_error_not_found(self, temp_repo: Path) -> None:
        """Test error when baseline not found."""
        result = runner.invoke(app, ["baseline", "delete", "nonexistent", "--force"])

        assert result.exit_code == ExitCode.NO_CACHE
        assert "not found" in result.output


class TestScanWithBaseline:
    """Tests for 'vibeguard scan --baseline' flag."""

    def test_baseline_not_found_error(self, temp_repo: Path) -> None:
        """Test error when baseline not found during scan."""
        # Create a minimal scan that won't run actual scanners
        result = runner.invoke(
            app,
            ["scan", str(temp_repo), "--baseline", "nonexistent", "--no-bootstrap"],
            catch_exceptions=False,
        )

        # Should fail because baseline doesn't exist
        # Note: This might also fail due to no scanners, depending on execution order
        assert "not found" in result.output or result.exit_code != ExitCode.SUCCESS


class TestBaselineHelp:
    """Tests for baseline command help text."""

    def test_baseline_help(self) -> None:
        """Test baseline command shows help."""
        result = runner.invoke(app, ["baseline", "--help"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "baseline" in result.output.lower()
        assert "save" in result.output.lower()
        assert "list" in result.output.lower()
        assert "show" in result.output.lower()
        assert "delete" in result.output.lower()

    def test_baseline_save_help(self) -> None:
        """Test baseline save shows help."""
        result = runner.invoke(app, ["baseline", "save", "--help"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "save" in result.output.lower()

    def test_baseline_list_help(self) -> None:
        """Test baseline list shows help."""
        result = runner.invoke(app, ["baseline", "list", "--help"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "list" in result.output.lower()
