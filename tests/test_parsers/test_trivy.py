"""Tests for Trivy parser."""

import json

import pytest

from vibeguard.models.finding import Category, Severity
from vibeguard.scanners.parsers import trivy


class TestParseOutput:
    """Tests for parse_output function."""

    def test_parse_valid_output(self, trivy_json_output: str) -> None:
        """Test parsing valid Trivy output."""
        findings = trivy.parse_output(trivy_json_output)

        assert len(findings) == 3  # 2 npm + 1 pip
        assert all(f.scanner == "trivy" for f in findings)
        assert all(f.category == Category.VULNERABILITY for f in findings)

    def test_parse_empty_results(self) -> None:
        """Test parsing output with empty Results."""
        data = json.dumps({"Results": []})
        findings = trivy.parse_output(data)
        assert findings == []

    def test_parse_no_results_key(self) -> None:
        """Test parsing output without Results key."""
        data = json.dumps({"SchemaVersion": 2})
        findings = trivy.parse_output(data)
        assert findings == []

    def test_parse_no_vulnerabilities(self) -> None:
        """Test parsing Results with no Vulnerabilities."""
        data = json.dumps({
            "Results": [{"Target": "test.txt", "Vulnerabilities": None}]
        })
        findings = trivy.parse_output(data)
        assert findings == []

    def test_parse_empty_string(self) -> None:
        """Test parsing empty string."""
        findings = trivy.parse_output("")
        assert findings == []

    def test_parse_invalid_json(self) -> None:
        """Test that invalid JSON raises ValueError."""
        with pytest.raises(ValueError, match="Invalid Trivy JSON"):
            trivy.parse_output("not valid json")

    def test_extract_fields(self, trivy_json_output: str) -> None:
        """Test that all fields are extracted correctly."""
        findings = trivy.parse_output(trivy_json_output)
        lodash_finding = next(
            f
            for f in findings
            if "lodash" in f.rule_id.lower() or "lodash" in f.title.lower()
        )

        assert lodash_finding.rule_id == "CVE-2024-1234"
        assert "lodash" in lodash_finding.title.lower()
        assert lodash_finding.file_path == "package-lock.json"
        assert lodash_finding.cwe == "CWE-400"
        assert len(lodash_finding.references) > 0

    def test_severity_mapping_critical(self, trivy_json_output: str) -> None:
        """Test CRITICAL severity mapping."""
        findings = trivy.parse_output(trivy_json_output)
        critical_finding = next(f for f in findings if f.severity == Severity.CRITICAL)
        assert critical_finding is not None

    def test_severity_mapping_high(self, trivy_json_output: str) -> None:
        """Test HIGH severity mapping."""
        findings = trivy.parse_output(trivy_json_output)
        high_finding = next(f for f in findings if f.severity == Severity.HIGH)
        assert high_finding is not None

    def test_severity_mapping_medium(self, trivy_json_output: str) -> None:
        """Test MEDIUM severity mapping."""
        findings = trivy.parse_output(trivy_json_output)
        medium_finding = next(f for f in findings if f.severity == Severity.MEDIUM)
        assert medium_finding is not None

    def test_category_always_vulnerability(self, trivy_json_output: str) -> None:
        """Test all findings have VULNERABILITY category."""
        findings = trivy.parse_output(trivy_json_output)
        assert all(f.category == Category.VULNERABILITY for f in findings)

    def test_fix_version_in_message(self, trivy_json_output: str) -> None:
        """Test that fix version is included in message when available."""
        findings = trivy.parse_output(trivy_json_output)
        lodash_finding = next(f for f in findings if "lodash" in f.fingerprint.lower())
        assert "4.17.21" in lodash_finding.message

    def test_fingerprint_format(self, trivy_json_output: str) -> None:
        """Test fingerprint format includes vuln ID and package."""
        findings = trivy.parse_output(trivy_json_output)
        for finding in findings:
            assert ":" in finding.fingerprint
            assert finding.rule_id in finding.fingerprint

    def test_parse_multiple_targets(self, trivy_json_output: str) -> None:
        """Test parsing vulnerabilities from multiple targets."""
        findings = trivy.parse_output(trivy_json_output)

        npm_findings = [f for f in findings if "package-lock" in f.file_path]
        pip_findings = [f for f in findings if "requirements" in f.file_path]

        assert len(npm_findings) == 2
        assert len(pip_findings) == 1


class TestSeverityMapping:
    """Tests for severity mapping."""

    def test_critical_mapping(self) -> None:
        """Test CRITICAL maps correctly."""
        assert trivy.SEVERITY_MAP["CRITICAL"] == Severity.CRITICAL

    def test_high_mapping(self) -> None:
        """Test HIGH maps correctly."""
        assert trivy.SEVERITY_MAP["HIGH"] == Severity.HIGH

    def test_medium_mapping(self) -> None:
        """Test MEDIUM maps correctly."""
        assert trivy.SEVERITY_MAP["MEDIUM"] == Severity.MEDIUM

    def test_low_mapping(self) -> None:
        """Test LOW maps correctly."""
        assert trivy.SEVERITY_MAP["LOW"] == Severity.LOW

    def test_unknown_mapping(self) -> None:
        """Test UNKNOWN maps to INFO."""
        assert trivy.SEVERITY_MAP["UNKNOWN"] == Severity.INFO
