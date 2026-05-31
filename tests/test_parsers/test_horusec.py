"""Tests for Horusec parser."""

import json

import pytest

from vibeguard.models.finding import Category, Severity
from vibeguard.scanners.parsers import horusec


class TestParseOutput:
    """Tests for parse_output function."""

    def test_parse_valid_output(self, horusec_json_output: str) -> None:
        """Test parsing valid Horusec output."""
        findings = horusec.parse_output(horusec_json_output)

        assert len(findings) == 3
        assert all(f.scanner == "horusec" for f in findings)
        assert all(f.category == Category.SECURITY for f in findings)

    def test_parse_empty_vulnerabilities(self) -> None:
        """Test parsing output with empty analysisVulnerabilities."""
        data = json.dumps({"analysisVulnerabilities": []})
        findings = horusec.parse_output(data)
        assert findings == []

    def test_parse_no_vulnerabilities_key(self) -> None:
        """Test parsing output without analysisVulnerabilities key."""
        data = json.dumps({"id": "test-analysis"})
        findings = horusec.parse_output(data)
        assert findings == []

    def test_parse_empty_string(self) -> None:
        """Test parsing empty string."""
        findings = horusec.parse_output("")
        assert findings == []

    def test_parse_invalid_json(self) -> None:
        """Test that invalid JSON raises ValueError."""
        with pytest.raises(ValueError, match="Invalid Horusec JSON"):
            horusec.parse_output("not valid json")

    def test_extract_fields(self, horusec_json_output: str) -> None:
        """Test that all fields are extracted correctly."""
        findings = horusec.parse_output(horusec_json_output)
        finding = findings[0]

        assert finding.file_path == "src/database/query.py"
        assert finding.line_start == 25
        assert finding.code_snippet is not None
        assert "SELECT" in finding.code_snippet
        assert finding.fingerprint == "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"

    def test_severity_mapping_high(self, horusec_json_output: str) -> None:
        """Test HIGH severity mapping."""
        findings = horusec.parse_output(horusec_json_output)
        high = next(f for f in findings if "SQL injection" in f.message)
        assert high.severity == Severity.HIGH

    def test_severity_mapping_critical(self, horusec_json_output: str) -> None:
        """Test CRITICAL severity mapping."""
        findings = horusec.parse_output(horusec_json_output)
        critical = next(f for f in findings if "password" in f.message.lower())
        assert critical.severity == Severity.CRITICAL

    def test_severity_mapping_low(self, horusec_json_output: str) -> None:
        """Test LOW severity mapping."""
        findings = horusec.parse_output(horusec_json_output)
        low = next(f for f in findings if "random" in f.message.lower())
        assert low.severity == Severity.LOW

    def test_category_always_security(self, horusec_json_output: str) -> None:
        """Test all findings have SECURITY category."""
        findings = horusec.parse_output(horusec_json_output)
        assert all(f.category == Category.SECURITY for f in findings)

    def test_vuln_hash_as_fingerprint(self, horusec_json_output: str) -> None:
        """Test vulnHash is used as fingerprint."""
        findings = horusec.parse_output(horusec_json_output)
        for finding in findings:
            assert finding.fingerprint is not None
            assert len(finding.fingerprint) > 0

    def test_rule_id_from_hash(self, horusec_json_output: str) -> None:
        """Test rule_id is derived from vulnHash (first 32 chars)."""
        findings = horusec.parse_output(horusec_json_output)
        for finding in findings:
            assert len(finding.rule_id) <= 32

    def test_malformed_entry_skipped(self) -> None:
        """Test that malformed entries are skipped."""
        data = json.dumps({"analysisVulnerabilities": [{}]})
        findings = horusec.parse_output(data)
        assert len(findings) == 0

    def test_empty_vulnerability_object_skipped(self) -> None:
        """Test entry with empty vulnerabilities dict is skipped."""
        data = json.dumps({"analysisVulnerabilities": [{"vulnerabilities": {}}]})
        findings = horusec.parse_output(data)
        assert len(findings) == 0


class TestSeverityMapping:
    """Tests for severity mapping."""

    def test_critical_mapping(self) -> None:
        """Test CRITICAL maps correctly."""
        assert horusec.SEVERITY_MAP["CRITICAL"] == Severity.CRITICAL

    def test_high_mapping(self) -> None:
        """Test HIGH maps correctly."""
        assert horusec.SEVERITY_MAP["HIGH"] == Severity.HIGH

    def test_medium_mapping(self) -> None:
        """Test MEDIUM maps correctly."""
        assert horusec.SEVERITY_MAP["MEDIUM"] == Severity.MEDIUM

    def test_low_mapping(self) -> None:
        """Test LOW maps correctly."""
        assert horusec.SEVERITY_MAP["LOW"] == Severity.LOW

    def test_info_mapping(self) -> None:
        """Test INFO maps correctly."""
        assert horusec.SEVERITY_MAP["INFO"] == Severity.INFO
