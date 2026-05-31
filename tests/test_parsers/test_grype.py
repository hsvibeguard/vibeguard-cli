"""Tests for Grype parser."""

import json

import pytest

from vibeguard.models.finding import Category, Severity
from vibeguard.scanners.parsers import grype


class TestParseOutput:
    """Tests for parse_output function."""

    def test_parse_valid_output(self, grype_json_output: str) -> None:
        """Test parsing valid Grype output."""
        findings = grype.parse_output(grype_json_output)

        assert len(findings) == 3
        assert all(f.scanner == "grype" for f in findings)
        assert all(f.category == Category.VULNERABILITY for f in findings)

    def test_parse_empty_matches(self) -> None:
        """Test parsing output with empty matches."""
        data = json.dumps({"matches": []})
        findings = grype.parse_output(data)
        assert findings == []

    def test_parse_no_matches_key(self) -> None:
        """Test parsing output without matches key."""
        data = json.dumps({"source": {"type": "directory"}})
        findings = grype.parse_output(data)
        assert findings == []

    def test_parse_empty_string(self) -> None:
        """Test parsing empty string."""
        findings = grype.parse_output("")
        assert findings == []

    def test_parse_invalid_json(self) -> None:
        """Test that invalid JSON raises ValueError."""
        with pytest.raises(ValueError, match="Invalid Grype JSON"):
            grype.parse_output("not valid json")

    def test_extract_fields(self, grype_json_output: str) -> None:
        """Test that all fields are extracted correctly."""
        findings = grype.parse_output(grype_json_output)
        finding = findings[0]

        assert finding.rule_id == "CVE-2024-1234"
        assert finding.title == "CVE-2024-1234: example-lib@1.5.0"
        assert finding.file_path == "example-lib"
        assert finding.fingerprint == "CVE-2024-1234:example-lib:1.5.0"

    def test_severity_mapping_critical(self, grype_json_output: str) -> None:
        """Test Critical severity mapping."""
        findings = grype.parse_output(grype_json_output)
        critical = next(f for f in findings if f.rule_id == "CVE-2024-1234")
        assert critical.severity == Severity.CRITICAL

    def test_severity_mapping_high(self, grype_json_output: str) -> None:
        """Test High severity mapping."""
        findings = grype.parse_output(grype_json_output)
        high = next(f for f in findings if f.rule_id == "CVE-2024-5678")
        assert high.severity == Severity.HIGH

    def test_severity_mapping_negligible(self, grype_json_output: str) -> None:
        """Test Negligible maps to INFO."""
        findings = grype.parse_output(grype_json_output)
        info = next(f for f in findings if f.rule_id == "CVE-2024-9999")
        assert info.severity == Severity.INFO

    def test_category_always_vulnerability(self, grype_json_output: str) -> None:
        """Test all findings have VULNERABILITY category."""
        findings = grype.parse_output(grype_json_output)
        assert all(f.category == Category.VULNERABILITY for f in findings)

    def test_fix_version_in_message(self, grype_json_output: str) -> None:
        """Test that fix version is included in message when available."""
        findings = grype.parse_output(grype_json_output)
        finding = next(f for f in findings if f.rule_id == "CVE-2024-1234")
        assert "2.0.1" in finding.message

    def test_fingerprint_format(self, grype_json_output: str) -> None:
        """Test fingerprint format includes vuln_id:package:version."""
        findings = grype.parse_output(grype_json_output)
        for finding in findings:
            assert ":" in finding.fingerprint
            assert finding.rule_id in finding.fingerprint

    def test_malformed_entry_defaults(self) -> None:
        """Test that entries with missing fields use defaults."""
        data = json.dumps({"matches": [{}]})
        findings = grype.parse_output(data)
        assert len(findings) == 1
        assert findings[0].rule_id == "unknown"


class TestSeverityMapping:
    """Tests for severity mapping."""

    def test_critical_mapping(self) -> None:
        """Test Critical maps correctly."""
        assert grype.SEVERITY_MAP["Critical"] == Severity.CRITICAL

    def test_high_mapping(self) -> None:
        """Test High maps correctly."""
        assert grype.SEVERITY_MAP["High"] == Severity.HIGH

    def test_medium_mapping(self) -> None:
        """Test Medium maps correctly."""
        assert grype.SEVERITY_MAP["Medium"] == Severity.MEDIUM

    def test_low_mapping(self) -> None:
        """Test Low maps correctly."""
        assert grype.SEVERITY_MAP["Low"] == Severity.LOW

    def test_negligible_mapping(self) -> None:
        """Test Negligible maps to INFO."""
        assert grype.SEVERITY_MAP["Negligible"] == Severity.INFO
