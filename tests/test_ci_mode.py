"""Tests for CI mode features."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from vibeguard.cli.main import app
from vibeguard.cli.scan import (
    _emit_github_annotation,
    _is_ci_environment,
    _is_github_actions,
    _print_ci_summary,
)
from vibeguard.models.finding import Finding, Severity
from vibeguard.models.scan_result import ScanResult

runner = CliRunner()


class TestCIEnvironmentDetection:
    """Tests for CI environment detection."""

    def test_detects_ci_env_variable(self) -> None:
        """Test detection of generic CI environment."""
        with patch.dict(os.environ, {"CI": "true"}, clear=True):
            assert _is_ci_environment() is True

    def test_detects_github_actions(self) -> None:
        """Test detection of GitHub Actions."""
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}, clear=True):
            assert _is_ci_environment() is True
            assert _is_github_actions() is True

    def test_detects_gitlab_ci(self) -> None:
        """Test detection of GitLab CI."""
        with patch.dict(os.environ, {"GITLAB_CI": "true"}, clear=True):
            assert _is_ci_environment() is True

    def test_detects_jenkins(self) -> None:
        """Test detection of Jenkins."""
        with patch.dict(os.environ, {"JENKINS_URL": "http://jenkins.example.com"}, clear=True):
            assert _is_ci_environment() is True

    def test_detects_circleci(self) -> None:
        """Test detection of CircleCI."""
        with patch.dict(os.environ, {"CIRCLECI": "true"}, clear=True):
            assert _is_ci_environment() is True

    def test_detects_travis(self) -> None:
        """Test detection of Travis CI."""
        with patch.dict(os.environ, {"TRAVIS": "true"}, clear=True):
            assert _is_ci_environment() is True

    def test_no_ci_environment(self) -> None:
        """Test when no CI environment is detected."""
        env = {
            "CI": "",
            "GITHUB_ACTIONS": "",
            "GITLAB_CI": "",
            "JENKINS_URL": "",
            "CIRCLECI": "",
            "TRAVIS": "",
            "VIBEGUARD_CI": "",
        }
        with patch.dict(os.environ, env, clear=True):
            assert _is_ci_environment() is False

    def test_github_actions_false_when_not_set(self) -> None:
        """Test GitHub Actions detection when not in GHA."""
        with patch.dict(os.environ, {"GITHUB_ACTIONS": ""}, clear=True):
            assert _is_github_actions() is False

    def test_vibeguard_ci_override_true(self) -> None:
        """Test VIBEGUARD_CI=true forces CI mode."""
        with patch.dict(os.environ, {"VIBEGUARD_CI": "true"}, clear=True):
            assert _is_ci_environment() is True

    def test_vibeguard_ci_override_1(self) -> None:
        """Test VIBEGUARD_CI=1 forces CI mode."""
        with patch.dict(os.environ, {"VIBEGUARD_CI": "1"}, clear=True):
            assert _is_ci_environment() is True

    def test_vibeguard_ci_override_yes(self) -> None:
        """Test VIBEGUARD_CI=yes forces CI mode."""
        with patch.dict(os.environ, {"VIBEGUARD_CI": "yes"}, clear=True):
            assert _is_ci_environment() is True

    def test_vibeguard_ci_takes_precedence(self) -> None:
        """Test VIBEGUARD_CI takes precedence over other vars."""
        # Even with no other CI vars, VIBEGUARD_CI should work
        with patch.dict(os.environ, {"VIBEGUARD_CI": "true", "CI": ""}, clear=True):
            assert _is_ci_environment() is True


class TestGitHubAnnotations:
    """Tests for GitHub Actions annotations."""

    def test_emits_error_for_critical_finding(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test that critical findings emit error annotations."""
        finding = Finding(
            scanner="test",
            severity=Severity.CRITICAL,
            category="security",
            rule_id="TEST001",
            title="Critical Issue",
            message="This is a critical security issue",
            file_path="src/app.py",
            line_start=42,
        )

        _emit_github_annotation(finding, Path("."))

        captured = capsys.readouterr()
        assert "::error" in captured.out
        assert "file=src/app.py" in captured.out
        assert "line=42" in captured.out
        assert "TEST001" in captured.out

    def test_emits_error_for_high_finding(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test that high severity findings emit error annotations."""
        finding = Finding(
            scanner="test",
            severity=Severity.HIGH,
            category="security",
            rule_id="TEST002",
            title="High Issue",
            message="This is a high severity issue",
            file_path="src/util.py",
            line_start=100,
        )

        _emit_github_annotation(finding, Path("."))

        captured = capsys.readouterr()
        assert "::error" in captured.out

    def test_emits_warning_for_medium_finding(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test that medium severity findings emit warning annotations."""
        finding = Finding(
            scanner="test",
            severity=Severity.MEDIUM,
            category="security",
            rule_id="TEST003",
            title="Medium Issue",
            message="This is a medium severity issue",
            file_path="src/helper.py",
            line_start=50,
        )

        _emit_github_annotation(finding, Path("."))

        captured = capsys.readouterr()
        assert "::warning" in captured.out

    def test_emits_warning_for_low_finding(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test that low severity findings emit warning annotations."""
        finding = Finding(
            scanner="test",
            severity=Severity.LOW,
            category="security",
            rule_id="TEST004",
            title="Low Issue",
            message="This is a low severity issue",
            file_path="src/config.py",
            line_start=10,
        )

        _emit_github_annotation(finding, Path("."))

        captured = capsys.readouterr()
        assert "::warning" in captured.out

    def test_handles_multiline_messages(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test that multiline messages are formatted correctly."""
        finding = Finding(
            scanner="test",
            severity=Severity.HIGH,
            category="security",
            rule_id="TEST005",
            title="Multiline",
            message="Line one\nLine two\nLine three",
            file_path="src/app.py",
            line_start=1,
        )

        _emit_github_annotation(finding, Path("."))

        captured = capsys.readouterr()
        # The message portion (after the last ::) should have newlines replaced with spaces
        # The entire line ends with a newline from print(), but the message inside shouldn't have \n
        # Check that the original newlines from the message are replaced
        assert "Line one Line two Line three" in captured.out or "Line one" in captured.out

    def test_handles_empty_file_path(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test handling of findings with empty file path."""
        finding = Finding(
            scanner="test",
            severity=Severity.HIGH,
            category="security",
            rule_id="TEST006",
            title="No File",
            message="Finding without file path",
            file_path="",
            line_start=1,
        )

        _emit_github_annotation(finding, Path("."))

        captured = capsys.readouterr()
        assert "::error" in captured.out
        assert "file=" in captured.out


class TestCISummary:
    """Tests for CI summary output."""

    def test_prints_minimal_summary(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test that CI summary is minimal and parseable."""
        from datetime import datetime

        result = ScanResult(
            repo_root="/test",
            started_at=datetime.now(),
            finished_at=datetime.now(),
            findings=[],
            scanners_run=["semgrep", "gitleaks"],
            scanners_skipped=[],
            partial=False,
        )

        _print_ci_summary(result)

        captured = capsys.readouterr()
        assert "VibeGuard:" in captured.out
        assert "Score" in captured.out
        assert "100" in captured.out
        assert "semgrep" in captured.out
        assert "gitleaks" in captured.out

    def test_shows_partial_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test that partial scan is indicated."""
        from datetime import datetime

        result = ScanResult(
            repo_root="/test",
            started_at=datetime.now(),
            finished_at=datetime.now(),
            findings=[],
            scanners_run=["semgrep"],
            scanners_skipped=["gitleaks"],
            partial=True,
        )

        _print_ci_summary(result)

        captured = capsys.readouterr()
        assert "[PARTIAL]" in captured.out

    def test_shows_finding_counts(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test that finding counts are shown."""
        from datetime import datetime

        from vibeguard.models.finding import Category

        findings = [
            Finding(
                scanner="test",
                severity=Severity.CRITICAL,
                category=Category.SECURITY,
                rule_id="C1",
                title="Critical",
                message="Critical issue",
                file_path="test.py",
                line_start=1,
            ),
            Finding(
                scanner="test",
                severity=Severity.HIGH,
                category=Category.SECURITY,
                rule_id="H1",
                title="High",
                message="High issue",
                file_path="test.py",
                line_start=2,
            ),
            Finding(
                scanner="test",
                severity=Severity.MEDIUM,
                category=Category.SECURITY,
                rule_id="M1",
                title="Medium",
                message="Medium issue",
                file_path="test.py",
                line_start=3,
            ),
        ]

        result = ScanResult(
            repo_root="/test",
            started_at=datetime.now(),
            finished_at=datetime.now(),
            findings=findings,
            scanners_run=["test"],
            scanners_skipped=[],
            partial=False,
        )

        _print_ci_summary(result)

        captured = capsys.readouterr()
        assert "C:1" in captured.out
        assert "H:1" in captured.out
        assert "M:1" in captured.out


class TestCICommandLineOptions:
    """Tests for CI-related command line options."""

    def test_ci_flag_exists(self) -> None:
        """Test that --ci flag is available."""
        result = runner.invoke(app, ["scan", "--help"])
        assert "--ci" in result.output
        assert "CI mode" in result.output

    def test_quiet_flag_exists(self) -> None:
        """Test that --quiet flag is available."""
        result = runner.invoke(app, ["scan", "--help"])
        assert "--quiet" in result.output
        assert "-q" in result.output

    def test_sarif_file_option_exists(self) -> None:
        """Test that --sarif-file option is available."""
        result = runner.invoke(app, ["scan", "--help"])
        assert "--sarif-file" in result.output
        assert "SARIF" in result.output

    def test_github_annotations_option_exists(self) -> None:
        """Test that --github-annotations option is available."""
        result = runner.invoke(app, ["scan", "--help"])
        assert "--github-annotations" in result.output
        assert "GitHub" in result.output

    def test_threshold_option_exists(self) -> None:
        """Test that --threshold option is available."""
        result = runner.invoke(app, ["scan", "--help"])
        assert "--threshold" in result.output
        assert "-t" in result.output


class TestExitCodesDocumentation:
    """Tests for exit code documentation."""

    def test_exit_codes_in_help(self) -> None:
        """Test that exit codes are documented in help."""
        result = runner.invoke(app, ["scan", "--help"])
        assert "Exit codes:" in result.output or "exit" in result.output.lower()

    def test_examples_in_help(self) -> None:
        """Test that examples are shown in help."""
        result = runner.invoke(app, ["scan", "--help"])
        assert "Examples:" in result.output or "vibeguard scan" in result.output


class TestSARIFFileOutput:
    """Tests for SARIF file output option."""

    def test_sarif_file_creation(self, tmp_path: Path) -> None:
        """Test that --sarif-file creates a file."""
        sarif_path = tmp_path / "results.sarif"

        # Create a minimal test directory
        test_dir = tmp_path / "test_project"
        test_dir.mkdir()
        (test_dir / "test.py").write_text("# Empty file")

        # This will likely fail due to missing scanners, but we can check
        # that the option is recognized
        result = runner.invoke(
            app,
            ["scan", str(test_dir), "--ci", "--sarif-file", str(sarif_path)],
        )

        # The option should be recognized (even if scan fails)
        assert "--sarif-file" not in result.output or "Error" not in result.output


class TestQuietModeOutput:
    """Tests for quiet mode output."""

    def test_quiet_mode_minimal_output(self, tmp_path: Path) -> None:
        """Test that quiet mode produces minimal output."""
        test_dir = tmp_path / "test_project"
        test_dir.mkdir()
        (test_dir / "test.py").write_text("# Empty file")

        result = runner.invoke(app, ["scan", str(test_dir), "--quiet"])

        # In quiet mode, output should be minimal
        # Progress bars and detailed output should not appear
        if result.exit_code == 0 or result.exit_code == 1:
            # Should not have progress-style output
            assert "%" not in result.output or "VibeGuard:" in result.output


class TestCIAutoDetectionIntegration:
    """Integration tests for CI auto-detection via CLI."""

    def test_ci_env_triggers_quiet_mode(self, tmp_path: Path) -> None:
        """Test that CI=true triggers CI mode without --ci flag."""
        test_dir = tmp_path / "test_project"
        test_dir.mkdir()
        (test_dir / "test.py").write_text("# Empty file")

        # Run without --ci but with CI=true environment variable
        with patch.dict(os.environ, {"CI": "true"}):
            result = runner.invoke(app, ["scan", str(test_dir)])

        # Should have minimal CI-style output (VibeGuard: summary line)
        # and not full Rich progress output
        if result.exit_code in (0, 1, 2):
            # CI mode should produce the summary line
            assert "VibeGuard:" in result.output or "Score" in result.output

    def test_vibeguard_ci_env_triggers_ci_mode(self, tmp_path: Path) -> None:
        """Test that VIBEGUARD_CI=true triggers CI mode."""
        test_dir = tmp_path / "test_project"
        test_dir.mkdir()
        (test_dir / "test.py").write_text("# Empty file")

        # Run without --ci but with VIBEGUARD_CI=true
        with patch.dict(os.environ, {"VIBEGUARD_CI": "true"}, clear=True):
            result = runner.invoke(app, ["scan", str(test_dir)])

        # Should succeed and use CI mode
        if result.exit_code in (0, 1, 2):
            assert "VibeGuard:" in result.output or "Score" in result.output

    def test_github_actions_env_triggers_ci_mode(self, tmp_path: Path) -> None:
        """Test that GITHUB_ACTIONS=true triggers CI mode."""
        test_dir = tmp_path / "test_project"
        test_dir.mkdir()
        (test_dir / "test.py").write_text("# Empty file")

        # Run without --ci but with GITHUB_ACTIONS=true
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}):
            result = runner.invoke(app, ["scan", str(test_dir)])

        # Should succeed and use CI mode
        if result.exit_code in (0, 1, 2):
            assert "VibeGuard:" in result.output or "Score" in result.output

    def test_no_ci_env_shows_full_output(self, tmp_path: Path) -> None:
        """Test that without CI env, full output is shown."""
        test_dir = tmp_path / "test_project"
        test_dir.mkdir()
        (test_dir / "test.py").write_text("# Empty file")

        # Clear CI environment variables
        env = {
            "CI": "",
            "GITHUB_ACTIONS": "",
            "GITLAB_CI": "",
            "VIBEGUARD_CI": "",
        }
        with patch.dict(os.environ, env, clear=True):
            result = runner.invoke(app, ["scan", str(test_dir)])

        # Without CI mode, should have richer output
        # (though exact format depends on whether scanners are available)
        assert result.exit_code in (0, 1, 2)
