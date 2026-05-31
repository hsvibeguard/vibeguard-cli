"""Tests for Bandit parser."""

import json

import pytest

from vibeguard.models.finding import Category, Severity
from vibeguard.scanners.parsers import bandit


class TestParseOutput:
    """Tests for parse_output function."""

    def test_parse_valid_output(self, bandit_json_output: str) -> None:
        """Test parsing valid Bandit output."""
        findings = bandit.parse_output(bandit_json_output)

        assert len(findings) == 3
        assert all(f.scanner == "bandit" for f in findings)
        assert all(f.category == Category.SECURITY for f in findings)

    def test_parse_empty_results(self) -> None:
        """Test parsing empty results array."""
        data = json.dumps({"results": [], "errors": []})
        findings = bandit.parse_output(data)
        assert findings == []

    def test_parse_empty_string(self) -> None:
        """Test parsing empty string."""
        findings = bandit.parse_output("")
        assert findings == []

    def test_parse_invalid_json(self) -> None:
        """Test that invalid JSON raises ValueError."""
        with pytest.raises(ValueError, match="Invalid Bandit JSON"):
            bandit.parse_output("not valid json")

    def test_extract_fields(self, bandit_json_output: str) -> None:
        """Test that all fields are extracted correctly."""
        findings = bandit.parse_output(bandit_json_output)
        finding = findings[0]  # B605 shell injection

        assert finding.rule_id == "B605"
        assert finding.title == "Start Process With A Shell"
        assert finding.file_path == "app/utils.py"
        assert finding.line_start == 42
        assert finding.cwe == "CWE-78"
        assert len(finding.references) == 1
        assert "bandit.readthedocs.io" in finding.references[0]
        assert finding.code_snippet is not None

    def test_severity_high_high_is_critical(self, bandit_json_output: str) -> None:
        """Test HIGH severity + HIGH confidence = CRITICAL."""
        findings = bandit.parse_output(bandit_json_output)
        shell_finding = next(f for f in findings if f.rule_id == "B605")
        assert shell_finding.severity == Severity.CRITICAL

    def test_severity_low_is_low(self, bandit_json_output: str) -> None:
        """Test LOW severity maps to LOW."""
        findings = bandit.parse_output(bandit_json_output)
        password_finding = next(f for f in findings if f.rule_id == "B105")
        assert password_finding.severity == Severity.LOW

    def test_severity_medium_is_medium(self, bandit_json_output: str) -> None:
        """Test MEDIUM severity maps to MEDIUM."""
        findings = bandit.parse_output(bandit_json_output)
        eval_finding = next(f for f in findings if f.rule_id == "B307")
        assert eval_finding.severity == Severity.MEDIUM

    def test_category_always_security(self, bandit_json_output: str) -> None:
        """Test all findings have SECURITY category."""
        findings = bandit.parse_output(bandit_json_output)
        assert all(f.category == Category.SECURITY for f in findings)

    def test_line_range_extraction(self, bandit_json_output: str) -> None:
        """Test line range is extracted correctly."""
        findings = bandit.parse_output(bandit_json_output)
        eval_finding = next(f for f in findings if f.rule_id == "B307")
        assert eval_finding.line_start == 88
        assert eval_finding.line_end == 89

    def test_parse_single_result(self) -> None:
        """Test parsing a single result."""
        data = json.dumps({
            "results": [
                {
                    "filename": "test.py",
                    "issue_severity": "HIGH",
                    "issue_confidence": "HIGH",
                    "issue_text": "Test issue",
                    "line_number": 10,
                    "test_id": "B101",
                    "test_name": "assert_used"
                }
            ]
        })
        findings = bandit.parse_output(data)

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].rule_id == "B101"

    def test_malformed_entry_skipped(self) -> None:
        """Test that malformed entries are skipped."""
        data = json.dumps({
            "results": [
                {},  # Empty entry should be skipped
                {
                    "filename": "test.py",
                    "test_id": "B101",
                    "issue_severity": "LOW"
                }
            ]
        })
        findings = bandit.parse_output(data)
        assert len(findings) >= 1

    def test_fingerprint_generated(self, bandit_json_output: str) -> None:
        """Test fingerprint is generated for each finding."""
        findings = bandit.parse_output(bandit_json_output)
        for finding in findings:
            assert finding.fingerprint is not None
            assert finding.rule_id in finding.fingerprint


class TestDetermineSeverity:
    """Tests for severity determination."""

    def test_high_high_is_critical(self) -> None:
        """Test HIGH severity + HIGH confidence = CRITICAL."""
        assert bandit._determine_severity("HIGH", "HIGH") == Severity.CRITICAL

    def test_high_medium_is_high(self) -> None:
        """Test HIGH severity + MEDIUM confidence = HIGH."""
        assert bandit._determine_severity("HIGH", "MEDIUM") == Severity.HIGH

    def test_high_low_is_high(self) -> None:
        """Test HIGH severity + LOW confidence = HIGH."""
        assert bandit._determine_severity("HIGH", "LOW") == Severity.HIGH

    def test_medium_high_is_medium(self) -> None:
        """Test MEDIUM severity stays MEDIUM regardless of confidence."""
        assert bandit._determine_severity("MEDIUM", "HIGH") == Severity.MEDIUM

    def test_low_is_low(self) -> None:
        """Test LOW severity maps to LOW."""
        assert bandit._determine_severity("LOW", "HIGH") == Severity.LOW

    def test_unknown_defaults_to_medium(self) -> None:
        """Test unknown severity defaults to MEDIUM."""
        assert bandit._determine_severity("UNKNOWN", "HIGH") == Severity.MEDIUM
