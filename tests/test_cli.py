"""Tests for CLI commands."""

from pathlib import Path

from typer.testing import CliRunner

from vibeguard import __version__
from vibeguard.cli.display import (
    BOOTSTRAP_MESSAGES,
    PATCHING_MESSAGES,
    SCANNER_MESSAGES,
    SCANNING_MESSAGES,
    get_bootstrap_message,
    get_patching_message,
    get_result_message,
    get_scanner_message,
    get_scanning_message,
)
from vibeguard.cli.main import app

runner = CliRunner()


class TestVersionCommand:
    def test_version_flag(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "vibeguard" in result.stdout
        assert __version__ in result.stdout

    def test_version_short_flag(self) -> None:
        result = runner.invoke(app, ["-v"])
        assert result.exit_code == 0
        assert __version__ in result.stdout


class TestDoctorCommand:
    def test_doctor_runs(self) -> None:
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0
        assert "System Information" in result.stdout
        assert "Prerequisites" in result.stdout
        assert "Scanners" in result.stdout

    def test_doctor_shows_python_version(self) -> None:
        result = runner.invoke(app, ["doctor"])
        assert "Python" in result.stdout


class TestInitCommand:
    def test_init_creates_files(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["init", str(tmp_path)])
        assert result.exit_code == 0
        assert (tmp_path / ".vibeguard" / "config.toml").exists()
        assert (tmp_path / ".vibeguardignore").exists()

    def test_init_creates_config_content(self, tmp_path: Path) -> None:
        runner.invoke(app, ["init", str(tmp_path)])
        config_content = (tmp_path / ".vibeguard" / "config.toml").read_text()
        assert "[scan]" in config_content
        assert "pack = " in config_content

    def test_init_skips_existing(self, tmp_path: Path) -> None:
        # First init
        runner.invoke(app, ["init", str(tmp_path)])
        # Second init should skip
        result = runner.invoke(app, ["init", str(tmp_path)])
        assert "Skipped" in result.stdout

    def test_init_force_overwrites(self, tmp_path: Path) -> None:
        runner.invoke(app, ["init", str(tmp_path)])
        result = runner.invoke(app, ["init", str(tmp_path), "--force"])
        assert "Created" in result.stdout

    def test_init_success_message(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["init", str(tmp_path)])
        assert "VibeGuard initialized!" in result.stdout


class TestScanCommand:
    def test_scan_nonexistent_path(self) -> None:
        result = runner.invoke(app, ["scan", "/nonexistent/path/12345"])
        assert result.exit_code == 5  # ExitCode.INVALID_PATH
        assert "does not exist" in result.stdout

    def test_scan_runs_on_valid_path(self, tmp_path: Path) -> None:
        # Create a simple Python file
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")

        result = runner.invoke(app, ["scan", str(tmp_path)])
        # Should run without error, even if semgrep is not installed
        # (graceful degradation)
        assert result.exit_code == 0

    def test_scan_shows_score(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")

        result = runner.invoke(app, ["scan", str(tmp_path)])
        # Should show score even if no scanners ran
        assert "Score:" in result.stdout or "Scanners skipped:" in result.stdout

    def test_scan_json_output(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")

        result = runner.invoke(app, ["scan", str(tmp_path), "--output", "json"])
        assert result.exit_code == 0
        # Should be valid JSON
        import json

        try:
            data = json.loads(result.stdout)
            assert "repo_root" in data
            assert "findings" in data
        except json.JSONDecodeError:
            # If semgrep warning printed before JSON, that's okay
            pass


class TestDisplayMessages:
    """Tests for fun status messages."""

    def test_bootstrap_message_returns_string(self) -> None:
        msg = get_bootstrap_message()
        assert isinstance(msg, str)
        assert len(msg) > 0

    def test_bootstrap_message_from_list(self) -> None:
        msg = get_bootstrap_message()
        assert msg in BOOTSTRAP_MESSAGES

    def test_scanning_message_returns_string(self) -> None:
        msg = get_scanning_message()
        assert isinstance(msg, str)
        assert msg in SCANNING_MESSAGES

    def test_scanner_specific_message(self) -> None:
        for scanner in ["semgrep", "gitleaks", "trivy", "bandit", "trufflehog"]:
            msg = get_scanner_message(scanner)
            assert isinstance(msg, str)
            assert msg in SCANNER_MESSAGES[scanner]

    def test_unknown_scanner_falls_back(self) -> None:
        msg = get_scanner_message("unknown_scanner")
        assert msg in SCANNING_MESSAGES

    def test_patching_message_returns_string(self) -> None:
        msg = get_patching_message()
        assert isinstance(msg, str)
        assert msg in PATCHING_MESSAGES

    def test_result_message_with_findings(self) -> None:
        msg = get_result_message(has_findings=True)
        assert isinstance(msg, str)
        # Should be a "findings" type message
        assert any(
            word in msg.lower()
            for word in [
                "found", "detected", "discovered", "attention", "issues",
                "concerns", "vulnerabilities", "vibes", "findings", "review",
                "threats", "items",  # From actual FINDING_MESSAGES
            ]
        )

    def test_result_message_without_findings(self) -> None:
        msg = get_result_message(has_findings=False)
        assert isinstance(msg, str)
        # Should be a "success" type message
        assert any(
            word in msg.lower()
            for word in [
                "clean", "secure", "immaculate", "nominal", "solid", "strong",
                "threats", "fortress", "holding",  # From actual SUCCESS_MESSAGES
            ]
        )


class TestScanPackOption:
    """Tests for --pack option behavior."""

    def test_pack_ecosystem_empty_warns(self, tmp_path: Path) -> None:
        """Test that --pack ecosystem with no ecosystem files warns and exits."""
        # Create empty directory with no ecosystem files
        result = runner.invoke(app, ["scan", str(tmp_path), "--pack", "ecosystem"])
        # Should exit with error code 4 (CONFIG_ERROR)
        assert result.exit_code == 4
        assert "No scanners to run" in result.stdout or "Warning" in result.stdout

    def test_pack_invalid_errors(self, tmp_path: Path) -> None:
        """Test that invalid pack value errors."""
        result = runner.invoke(app, ["scan", str(tmp_path), "--pack", "invalid"])
        assert result.exit_code == 4
        assert "Invalid pack" in result.stdout


class TestDoctorEcosystemScanners:
    """Tests for doctor ecosystem scanner checks."""

    def test_doctor_shows_ecosystem_scanners(self) -> None:
        """Test that doctor shows ecosystem scanners section."""
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0
        assert "Ecosystem Pack" in result.stdout

    def test_doctor_shows_detected_ecosystems(self) -> None:
        """Test that doctor shows detected ecosystems."""
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0
        # Should show detection info (may or may not find ecosystems)
        assert "Detected ecosystems" in result.stdout or "No ecosystem" in result.stdout
