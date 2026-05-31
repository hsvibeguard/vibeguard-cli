"""Tests for npm audit parser."""

import json

import pytest

from vibeguard.models.finding import Category, Severity
from vibeguard.scanners.parsers import npm_audit


class TestParseOutput:
    """Tests for parse_output function."""

    def test_parse_valid_v7_output(self, npm_audit_v7_json_output: str) -> None:
        """Test parsing valid npm audit v7+ output."""
        findings = npm_audit.parse_output(npm_audit_v7_json_output)

        # Should have findings for lodash and axios (minimist has string via, no details)
        assert len(findings) >= 2
        assert all(f.scanner == "npm_audit" for f in findings)
        assert all(f.category == Category.VULNERABILITY for f in findings)

    def test_parse_empty_results(self) -> None:
        """Test parsing output with no vulnerabilities."""
        data = json.dumps({"vulnerabilities": {}, "metadata": {}})
        findings = npm_audit.parse_output(data)
        assert findings == []

    def test_parse_empty_string(self) -> None:
        """Test parsing empty string."""
        findings = npm_audit.parse_output("")
        assert findings == []

    def test_parse_invalid_json(self) -> None:
        """Test that invalid JSON raises ValueError."""
        with pytest.raises(ValueError, match="Invalid npm audit JSON"):
            npm_audit.parse_output("not valid json")

    def test_extract_fields(self, npm_audit_v7_json_output: str) -> None:
        """Test that fields are extracted correctly."""
        findings = npm_audit.parse_output(npm_audit_v7_json_output)

        # Find lodash finding
        lodash_finding = next((f for f in findings if "lodash" in f.fingerprint), None)
        assert lodash_finding is not None

        assert lodash_finding.file_path == "package.json"
        assert lodash_finding.line_start == 1
        assert "Prototype Pollution" in lodash_finding.title or "lodash" in lodash_finding.title

    def test_severity_critical(self, npm_audit_v7_json_output: str) -> None:
        """Test critical severity mapping."""
        findings = npm_audit.parse_output(npm_audit_v7_json_output)
        axios_finding = next((f for f in findings if "axios" in f.fingerprint), None)
        assert axios_finding is not None
        assert axios_finding.severity == Severity.CRITICAL

    def test_severity_high(self, npm_audit_v7_json_output: str) -> None:
        """Test high severity mapping."""
        findings = npm_audit.parse_output(npm_audit_v7_json_output)
        lodash_finding = next((f for f in findings if "lodash" in f.fingerprint), None)
        assert lodash_finding is not None
        assert lodash_finding.severity == Severity.HIGH

    def test_cwe_extraction(self, npm_audit_v7_json_output: str) -> None:
        """Test CWE is extracted from via info."""
        findings = npm_audit.parse_output(npm_audit_v7_json_output)
        # At least one finding should have a CWE
        cwe_findings = [f for f in findings if f.cwe is not None]
        assert len(cwe_findings) >= 1

    def test_references_extraction(self, npm_audit_v7_json_output: str) -> None:
        """Test references are extracted."""
        findings = npm_audit.parse_output(npm_audit_v7_json_output)
        # Findings with via objects should have references
        ref_findings = [f for f in findings if f.references]
        assert len(ref_findings) >= 1

    def test_category_always_vulnerability(self, npm_audit_v7_json_output: str) -> None:
        """Test all findings have VULNERABILITY category."""
        findings = npm_audit.parse_output(npm_audit_v7_json_output)
        assert all(f.category == Category.VULNERABILITY for f in findings)

    def test_fingerprint_generated(self, npm_audit_v7_json_output: str) -> None:
        """Test fingerprint is generated for each finding."""
        findings = npm_audit.parse_output(npm_audit_v7_json_output)
        for finding in findings:
            assert finding.fingerprint is not None
            assert "npm_audit" in finding.fingerprint


class TestSeverityMapping:
    """Tests for severity mapping."""

    def test_critical_maps_to_critical(self) -> None:
        """Test critical severity."""
        assert npm_audit.SEVERITY_MAP["critical"] == Severity.CRITICAL

    def test_high_maps_to_high(self) -> None:
        """Test high severity."""
        assert npm_audit.SEVERITY_MAP["high"] == Severity.HIGH

    def test_moderate_maps_to_medium(self) -> None:
        """Test moderate severity."""
        assert npm_audit.SEVERITY_MAP["moderate"] == Severity.MEDIUM

    def test_low_maps_to_low(self) -> None:
        """Test low severity."""
        assert npm_audit.SEVERITY_MAP["low"] == Severity.LOW

    def test_info_maps_to_info(self) -> None:
        """Test info severity."""
        assert npm_audit.SEVERITY_MAP["info"] == Severity.INFO


class TestLegacyFormat:
    """Tests for legacy npm audit format (pre-v7)."""

    def test_parse_legacy_advisories(self) -> None:
        """Test parsing legacy advisories format."""
        data = json.dumps({
            "advisories": {
                "1234": {
                    "module_name": "example-package",
                    "severity": "high",
                    "title": "Example Vulnerability",
                    "overview": "This is a vulnerability description.",
                    "vulnerable_versions": "<1.0.0",
                    "patched_versions": ">=1.0.0",
                    "url": "https://npmjs.com/advisories/1234"
                }
            }
        })
        findings = npm_audit.parse_output(data)

        assert len(findings) == 1
        assert findings[0].scanner == "npm_audit"
        assert findings[0].severity == Severity.HIGH
        assert "example-package" in findings[0].fingerprint

    def test_empty_advisories(self) -> None:
        """Test empty advisories object."""
        data = json.dumps({"advisories": {}})
        findings = npm_audit.parse_output(data)
        assert findings == []
