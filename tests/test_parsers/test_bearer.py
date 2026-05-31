"""Tests for Bearer parser."""

import json

import pytest

from vibeguard.models.finding import Category, Severity
from vibeguard.scanners.parsers import bearer


class TestParseOutput:
    """Tests for parse_output function."""

    def test_parse_valid_output(self, bearer_json_output: str) -> None:
        """Test parsing valid Bearer output."""
        findings = bearer.parse_output(bearer_json_output)

        assert len(findings) == 3
        assert all(f.scanner == "bearer" for f in findings)
        assert all(f.category == Category.SECURITY for f in findings)

    def test_parse_empty_array(self) -> None:
        """Test parsing empty results array."""
        findings = bearer.parse_output("[]")
        assert findings == []

    def test_parse_empty_string(self) -> None:
        """Test parsing empty string."""
        findings = bearer.parse_output("")
        assert findings == []

    def test_parse_invalid_json(self) -> None:
        """Test that invalid JSON raises ValueError."""
        with pytest.raises(ValueError, match="Invalid Bearer JSON"):
            bearer.parse_output("not valid json")

    def test_extract_fields(self, bearer_json_output: str) -> None:
        """Test that all fields are extracted correctly."""
        findings = bearer.parse_output(bearer_json_output)
        finding = findings[0]

        assert finding.rule_id == "javascript_lang_hardcoded_secret"
        assert finding.file_path == "src/config.js"
        assert finding.line_start == 12
        assert finding.cwe == "CWE-798"
        assert len(finding.references) == 1
        assert "docs.bearer.com" in finding.references[0]

    def test_severity_mapping_critical(self, bearer_json_output: str) -> None:
        """Test critical severity mapping."""
        findings = bearer.parse_output(bearer_json_output)
        critical = next(f for f in findings if f.rule_id == "javascript_lang_hardcoded_secret")
        assert critical.severity == Severity.CRITICAL

    def test_severity_mapping_high(self, bearer_json_output: str) -> None:
        """Test high severity mapping."""
        findings = bearer.parse_output(bearer_json_output)
        high = next(f for f in findings if f.rule_id == "ruby_lang_sql_injection")
        assert high.severity == Severity.HIGH

    def test_severity_mapping_warning_to_info(self, bearer_json_output: str) -> None:
        """Test warning maps to INFO."""
        findings = bearer.parse_output(bearer_json_output)
        warning = next(f for f in findings if f.rule_id == "javascript_lang_logger")
        assert warning.severity == Severity.INFO

    def test_category_always_security(self, bearer_json_output: str) -> None:
        """Test all findings have SECURITY category."""
        findings = bearer.parse_output(bearer_json_output)
        assert all(f.category == Category.SECURITY for f in findings)

    def test_cwe_extraction(self, bearer_json_output: str) -> None:
        """Test CWE IDs are extracted correctly."""
        findings = bearer.parse_output(bearer_json_output)
        finding = findings[1]  # SQL injection
        assert finding.cwe == "CWE-89"

    def test_documentation_url_in_references(self, bearer_json_output: str) -> None:
        """Test documentation URL is included in references."""
        findings = bearer.parse_output(bearer_json_output)
        finding_with_url = findings[0]
        assert len(finding_with_url.references) > 0

        # Third finding has no doc URL
        finding_no_url = findings[2]
        assert len(finding_no_url.references) == 0

    def test_fingerprint_format(self, bearer_json_output: str) -> None:
        """Test fingerprint format is rule_id:file:line."""
        findings = bearer.parse_output(bearer_json_output)
        for finding in findings:
            assert ":" in finding.fingerprint
            assert finding.rule_id in finding.fingerprint

    def test_parse_object_with_results_key(self) -> None:
        """Test parsing object-wrapped output."""
        data = json.dumps({
            "results": [
                {
                    "rule_id": "test_rule",
                    "severity": "medium",
                    "description": "Test issue",
                    "filename": "test.py",
                    "line_number": 1,
                    "cwe_ids": []
                }
            ]
        })
        findings = bearer.parse_output(data)
        assert len(findings) == 1

    def test_malformed_entry_defaults(self) -> None:
        """Test that entries with missing fields use defaults."""
        data = json.dumps([{}])
        findings = bearer.parse_output(data)
        assert len(findings) == 1
        assert findings[0].rule_id == "unknown"


class TestSeverityMapping:
    """Tests for severity mapping."""

    def test_critical_mapping(self) -> None:
        """Test critical maps correctly."""
        assert bearer.SEVERITY_MAP["critical"] == Severity.CRITICAL

    def test_high_mapping(self) -> None:
        """Test high maps correctly."""
        assert bearer.SEVERITY_MAP["high"] == Severity.HIGH

    def test_medium_mapping(self) -> None:
        """Test medium maps correctly."""
        assert bearer.SEVERITY_MAP["medium"] == Severity.MEDIUM

    def test_low_mapping(self) -> None:
        """Test low maps correctly."""
        assert bearer.SEVERITY_MAP["low"] == Severity.LOW

    def test_warning_mapping(self) -> None:
        """Test warning maps to INFO."""
        assert bearer.SEVERITY_MAP["warning"] == Severity.INFO
