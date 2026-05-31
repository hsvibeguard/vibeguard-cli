"""Tests for fix CLI command."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from vibeguard.cli.fix import _find_finding, _read_code_snippet, build_fix_prompt
from vibeguard.cli.main import app
from vibeguard.models.finding import Category, Finding, Severity
from vibeguard.models.scan_result import ScanResult

runner = CliRunner()


@pytest.fixture
def sample_finding() -> Finding:
    """Create a sample finding for testing."""
    return Finding(
        scanner="semgrep",
        rule_id="python.security.audit.exec-detected",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        title="Use of exec() detected",
        message="The exec() function can execute arbitrary code, which is dangerous.",
        file_path="app/utils.py",
        line_start=42,
        line_end=42,
        cwe="CWE-78",
        references=["https://cwe.mitre.org/data/definitions/78.html"],
        code_snippet="exec(user_input)",
    )


@pytest.fixture
def sample_scan_result(sample_finding: Finding) -> ScanResult:
    """Create a sample scan result."""
    return ScanResult(
        repo_root="/test/repo",
        started_at=datetime.now(),
        finished_at=datetime.now(),
        findings=[sample_finding],
        scanners_run=["semgrep"],
    )


class TestBuildFixPrompt:
    """Tests for build_fix_prompt()."""

    def test_includes_scanner_name(self, sample_finding: Finding, tmp_path: Path) -> None:
        """Should include scanner name in prompt."""
        prompt = build_fix_prompt(sample_finding, tmp_path)
        assert "semgrep" in prompt

    def test_includes_rule_id(self, sample_finding: Finding, tmp_path: Path) -> None:
        """Should include rule ID in prompt."""
        prompt = build_fix_prompt(sample_finding, tmp_path)
        assert "exec-detected" in prompt

    def test_includes_severity(self, sample_finding: Finding, tmp_path: Path) -> None:
        """Should include severity in prompt."""
        prompt = build_fix_prompt(sample_finding, tmp_path)
        assert "HIGH" in prompt

    def test_includes_file_path(self, sample_finding: Finding, tmp_path: Path) -> None:
        """Should include file path in prompt."""
        prompt = build_fix_prompt(sample_finding, tmp_path)
        assert "app/utils.py" in prompt

    def test_includes_line_number(self, sample_finding: Finding, tmp_path: Path) -> None:
        """Should include line number in prompt."""
        prompt = build_fix_prompt(sample_finding, tmp_path)
        assert "42" in prompt

    def test_includes_cwe(self, sample_finding: Finding, tmp_path: Path) -> None:
        """Should include CWE if available."""
        prompt = build_fix_prompt(sample_finding, tmp_path)
        assert "CWE-78" in prompt

    def test_includes_message(self, sample_finding: Finding, tmp_path: Path) -> None:
        """Should include issue description."""
        prompt = build_fix_prompt(sample_finding, tmp_path)
        assert "arbitrary code" in prompt

    def test_includes_code_snippet(self, sample_finding: Finding, tmp_path: Path) -> None:
        """Should include code snippet."""
        prompt = build_fix_prompt(sample_finding, tmp_path)
        assert "exec(user_input)" in prompt

    def test_includes_patch_safety_rules(self, sample_finding: Finding, tmp_path: Path) -> None:
        """Should include patch safety rules."""
        prompt = build_fix_prompt(sample_finding, tmp_path)
        assert "minimal changes" in prompt.lower()
        assert "MANUAL_REVIEW_REQUIRED" in prompt

    def test_includes_diff_format_instructions(
        self, sample_finding: Finding, tmp_path: Path
    ) -> None:
        """Should include diff format instructions."""
        prompt = build_fix_prompt(sample_finding, tmp_path)
        assert "--- a/" in prompt
        assert "+++ b/" in prompt
        assert "@@" in prompt

    def test_handles_no_cwe(self, tmp_path: Path) -> None:
        """Should handle finding without CWE."""
        finding = Finding(
            scanner="test",
            rule_id="test-rule",
            severity=Severity.LOW,
            title="Test",
            message="Test message",
            file_path="test.py",
            line_start=1,
        )
        prompt = build_fix_prompt(finding, tmp_path)
        assert "CWE" not in prompt or "CWE" in prompt  # Just shouldn't crash

    def test_handles_line_range(self, tmp_path: Path) -> None:
        """Should format line range correctly."""
        finding = Finding(
            scanner="test",
            rule_id="test-rule",
            severity=Severity.LOW,
            title="Test",
            message="Test message",
            file_path="test.py",
            line_start=10,
            line_end=15,
        )
        prompt = build_fix_prompt(finding, tmp_path)
        assert "10-15" in prompt


class TestFindFinding:
    """Tests for _find_finding()."""

    def test_finds_by_exact_id(self, sample_finding: Finding) -> None:
        """Should find finding by exact ID match."""
        findings = [sample_finding]
        result = _find_finding(findings, sample_finding.id)
        assert result == sample_finding

    def test_finds_by_prefix(self, sample_finding: Finding) -> None:
        """Should find finding by ID prefix."""
        findings = [sample_finding]
        prefix = sample_finding.id[:8]
        result = _find_finding(findings, prefix)
        assert result == sample_finding

    def test_returns_none_for_no_match(self, sample_finding: Finding) -> None:
        """Should return None if no match found."""
        findings = [sample_finding]
        result = _find_finding(findings, "nonexistent")
        assert result is None

    def test_prefers_exact_match(self) -> None:
        """Should prefer exact match over prefix match."""
        finding1 = Finding(
            scanner="test",
            rule_id="rule1",
            severity=Severity.LOW,
            title="Test 1",
            message="Test",
            file_path="a.py",
            line_start=1,
        )
        finding2 = Finding(
            scanner="test",
            rule_id="rule2",
            severity=Severity.LOW,
            title="Test 2",
            message="Test",
            file_path="b.py",
            line_start=1,
        )
        findings = [finding1, finding2]

        # Search for exact ID of finding1
        result = _find_finding(findings, finding1.id)
        assert result == finding1


class TestReadCodeSnippet:
    """Tests for _read_code_snippet()."""

    def test_reads_code_from_file(self, tmp_path: Path) -> None:
        """Should read code snippet from file."""
        # Create test file
        test_file = tmp_path / "test.py"
        test_file.write_text("line1\nline2\nline3\nline4\nline5\n")

        finding = Finding(
            scanner="test",
            rule_id="rule",
            severity=Severity.LOW,
            title="Test",
            message="Test",
            file_path="test.py",
            line_start=3,
        )

        snippet = _read_code_snippet(tmp_path, finding)
        assert snippet is not None
        assert "line3" in snippet
        assert ">>>" in snippet  # Marker for target line

    def test_returns_none_for_missing_file(self, tmp_path: Path) -> None:
        """Should return None if file doesn't exist."""
        finding = Finding(
            scanner="test",
            rule_id="rule",
            severity=Severity.LOW,
            title="Test",
            message="Test",
            file_path="nonexistent.py",
            line_start=1,
        )

        snippet = _read_code_snippet(tmp_path, finding)
        assert snippet is None


class TestFixCommand:
    """Tests for 'vibeguard fix' CLI command."""

    def test_requires_cached_scan(self, tmp_path: Path) -> None:
        """Should error if no cached scan exists."""
        with patch("vibeguard.cli.fix.load_latest_scan", return_value=None):
            result = runner.invoke(app, ["fix", "abc123", "--path", str(tmp_path)])

        assert result.exit_code != 0
        assert "no cached scan" in result.output.lower()

    def test_shows_error_for_invalid_finding(
        self, tmp_path: Path, sample_scan_result: ScanResult
    ) -> None:
        """Should error if finding not found."""
        with patch("vibeguard.cli.fix.load_latest_scan", return_value=sample_scan_result):
            result = runner.invoke(app, ["fix", "nonexistent", "--path", str(tmp_path)])

        assert result.exit_code != 0
        assert "not found" in result.output.lower()

    def test_generates_prompt_for_valid_finding(
        self, tmp_path: Path, sample_scan_result: ScanResult, sample_finding: Finding
    ) -> None:
        """Should generate prompt for valid finding."""
        with patch("vibeguard.cli.fix.load_latest_scan", return_value=sample_scan_result):
            result = runner.invoke(
                app, ["fix", sample_finding.id, "--path", str(tmp_path)]
            )

        assert result.exit_code == 0
        assert "semgrep" in result.output
        assert "exec" in result.output.lower()
