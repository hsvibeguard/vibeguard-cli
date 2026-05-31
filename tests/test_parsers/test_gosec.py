"""Tests for Gosec parser."""

import json

import pytest

from vibeguard.models.finding import Category, Severity
from vibeguard.scanners.parsers import gosec


class TestParseOutput:
    """Tests for parse_output function."""

    def test_parse_valid_output(self, gosec_json_output: str) -> None:
        """Test parsing valid Gosec output."""
        findings = gosec.parse_output(gosec_json_output)

        assert len(findings) == 3
        assert all(f.scanner == "gosec" for f in findings)
        assert all(f.category == Category.SECURITY for f in findings)

    def test_parse_empty_issues(self) -> None:
        """Test parsing output with empty Issues."""
        data = json.dumps({"Issues": []})
        findings = gosec.parse_output(data)
        assert findings == []

    def test_parse_no_issues_key(self) -> None:
        """Test parsing output without Issues key."""
        data = json.dumps({"Stats": {"files": 0}})
        findings = gosec.parse_output(data)
        assert findings == []

    def test_parse_empty_string(self) -> None:
        """Test parsing empty string."""
        findings = gosec.parse_output("")
        assert findings == []

    def test_parse_invalid_json(self) -> None:
        """Test that invalid JSON raises ValueError."""
        with pytest.raises(ValueError, match="Invalid Gosec JSON"):
            gosec.parse_output("not valid json")

    def test_extract_fields(self, gosec_json_output: str) -> None:
        """Test that all fields are extracted correctly."""
        findings = gosec.parse_output(gosec_json_output)
        finding = findings[0]

        assert finding.rule_id == "G101"
        assert finding.file_path == "cmd/server.go"
        assert finding.line_start == 15
        assert finding.cwe == "CWE-798"
        assert finding.code_snippet == 'password := "admin123"'
        assert finding.fingerprint == "G101:cmd/server.go:15"

    def test_severity_mapping_high(self, gosec_json_output: str) -> None:
        """Test HIGH severity mapping."""
        findings = gosec.parse_output(gosec_json_output)
        high_finding = next(f for f in findings if f.rule_id == "G101")
        assert high_finding.severity == Severity.HIGH

    def test_severity_mapping_medium(self, gosec_json_output: str) -> None:
        """Test MEDIUM severity mapping."""
        findings = gosec.parse_output(gosec_json_output)
        medium_finding = next(f for f in findings if f.rule_id == "G104")
        assert medium_finding.severity == Severity.MEDIUM

    def test_severity_mapping_low(self, gosec_json_output: str) -> None:
        """Test LOW severity mapping."""
        findings = gosec.parse_output(gosec_json_output)
        low_finding = next(f for f in findings if f.rule_id == "G304")
        assert low_finding.severity == Severity.LOW

    def test_category_always_security(self, gosec_json_output: str) -> None:
        """Test all findings have SECURITY category."""
        findings = gosec.parse_output(gosec_json_output)
        assert all(f.category == Category.SECURITY for f in findings)

    def test_cwe_extraction(self, gosec_json_output: str) -> None:
        """Test CWE is extracted when available."""
        findings = gosec.parse_output(gosec_json_output)
        # First issue has CWE
        assert findings[0].cwe == "CWE-798"
        # Third issue has no CWE
        assert findings[2].cwe is None

    def test_fingerprint_format(self, gosec_json_output: str) -> None:
        """Test fingerprint format is rule_id:file:line."""
        findings = gosec.parse_output(gosec_json_output)
        for finding in findings:
            assert ":" in finding.fingerprint
            assert finding.rule_id in finding.fingerprint

    def test_malformed_entry_defaults(self) -> None:
        """Test that entries with missing fields use defaults."""
        data = json.dumps({"Issues": [{}]})
        findings = gosec.parse_output(data)
        assert len(findings) == 1
        assert findings[0].rule_id == "unknown"


class TestSeverityMapping:
    """Tests for severity mapping."""

    def test_high_mapping(self) -> None:
        """Test HIGH maps correctly."""
        assert gosec.SEVERITY_MAP["HIGH"] == Severity.HIGH

    def test_medium_mapping(self) -> None:
        """Test MEDIUM maps correctly."""
        assert gosec.SEVERITY_MAP["MEDIUM"] == Severity.MEDIUM

    def test_low_mapping(self) -> None:
        """Test LOW maps correctly."""
        assert gosec.SEVERITY_MAP["LOW"] == Severity.LOW
