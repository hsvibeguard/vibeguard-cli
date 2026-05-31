"""Tests for pip-audit parser."""

import json

import pytest

from vibeguard.models.finding import Category, Severity
from vibeguard.scanners.parsers import pip_audit


class TestParseOutput:
    """Tests for parse_output function."""

    def test_parse_valid_output(self, pip_audit_json_output: str) -> None:
        """Test parsing valid pip-audit output."""
        findings = pip_audit.parse_output(pip_audit_json_output)

        # Should have 3 vulnerabilities (flask, requests, cryptography)
        assert len(findings) == 3
        assert all(f.scanner == "pip_audit" for f in findings)
        assert all(f.category == Category.VULNERABILITY for f in findings)

    def test_parse_empty_dependencies(self) -> None:
        """Test parsing output with no dependencies."""
        data = json.dumps({"dependencies": []})
        findings = pip_audit.parse_output(data)
        assert findings == []

    def test_parse_no_vulnerabilities(self) -> None:
        """Test parsing output with dependencies but no vulnerabilities."""
        data = json.dumps({
            "dependencies": [
                {"name": "requests", "version": "2.31.0", "vulns": []},
                {"name": "flask", "version": "3.0.0", "vulns": []}
            ]
        })
        findings = pip_audit.parse_output(data)
        assert findings == []

    def test_parse_empty_string(self) -> None:
        """Test parsing empty string."""
        findings = pip_audit.parse_output("")
        assert findings == []

    def test_parse_invalid_json(self) -> None:
        """Test that invalid JSON raises ValueError."""
        with pytest.raises(ValueError, match="Invalid pip-audit JSON"):
            pip_audit.parse_output("not valid json")

    def test_extract_fields(self, pip_audit_json_output: str) -> None:
        """Test that fields are extracted correctly."""
        findings = pip_audit.parse_output(pip_audit_json_output)

        # Find flask finding
        flask_finding = next((f for f in findings if "flask" in f.fingerprint), None)
        assert flask_finding is not None

        assert flask_finding.rule_id == "PYSEC-2023-62"
        assert "flask" in flask_finding.message.lower()
        assert flask_finding.file_path == "requirements.txt"
        assert flask_finding.line_start == 1

    def test_aliases_extracted(self, pip_audit_json_output: str) -> None:
        """Test that CVE aliases are included in message."""
        findings = pip_audit.parse_output(pip_audit_json_output)

        # Flask has CVE alias
        flask_finding = next((f for f in findings if "flask" in f.fingerprint), None)
        assert flask_finding is not None
        assert "CVE-2023-30861" in flask_finding.message

    def test_fix_versions_included(self, pip_audit_json_output: str) -> None:
        """Test that fix versions are included in message."""
        findings = pip_audit.parse_output(pip_audit_json_output)

        flask_finding = next((f for f in findings if "flask" in f.fingerprint), None)
        assert flask_finding is not None
        assert "Fixed in" in flask_finding.message or "2.2.5" in flask_finding.message

    def test_references_generated(self, pip_audit_json_output: str) -> None:
        """Test that references are generated for PYSEC IDs."""
        findings = pip_audit.parse_output(pip_audit_json_output)

        for finding in findings:
            assert len(finding.references) >= 1
            # Should have OSV link for PYSEC
            osv_refs = [r for r in finding.references if "osv.dev" in r]
            assert len(osv_refs) >= 1

    def test_category_always_vulnerability(self, pip_audit_json_output: str) -> None:
        """Test all findings have VULNERABILITY category."""
        findings = pip_audit.parse_output(pip_audit_json_output)
        assert all(f.category == Category.VULNERABILITY for f in findings)

    def test_fingerprint_generated(self, pip_audit_json_output: str) -> None:
        """Test fingerprint is generated for each finding."""
        findings = pip_audit.parse_output(pip_audit_json_output)
        for finding in findings:
            assert finding.fingerprint is not None
            assert "pip_audit" in finding.fingerprint

    def test_fingerprint_includes_version(self, pip_audit_json_output: str) -> None:
        """Test fingerprint includes package version."""
        findings = pip_audit.parse_output(pip_audit_json_output)

        flask_finding = next((f for f in findings if "flask" in f.fingerprint), None)
        assert flask_finding is not None
        assert "1.0.0" in flask_finding.fingerprint


class TestDetermineSeverity:
    """Tests for severity determination based on description."""

    def test_rce_is_critical(self) -> None:
        """Test RCE keywords result in CRITICAL severity."""
        severity = pip_audit._determine_severity("remote code execution vulnerability")
        assert severity == Severity.CRITICAL

    def test_arbitrary_code_is_critical(self) -> None:
        """Test arbitrary code keywords result in CRITICAL severity."""
        severity = pip_audit._determine_severity("allows arbitrary code execution")
        assert severity == Severity.CRITICAL

    def test_sql_injection_is_high(self) -> None:
        """Test SQL injection is HIGH severity."""
        severity = pip_audit._determine_severity("SQL injection vulnerability")
        assert severity == Severity.HIGH

    def test_xss_is_high(self) -> None:
        """Test XSS is HIGH severity."""
        severity = pip_audit._determine_severity("cross-site scripting (XSS)")
        assert severity == Severity.HIGH

    def test_dos_is_medium(self) -> None:
        """Test DoS is MEDIUM severity."""
        severity = pip_audit._determine_severity("denial of service attack")
        assert severity == Severity.MEDIUM

    def test_timing_attack_is_low(self) -> None:
        """Test timing attack is LOW severity."""
        severity = pip_audit._determine_severity("timing attack vulnerability")
        assert severity == Severity.LOW

    def test_unknown_defaults_to_high(self) -> None:
        """Test unknown description defaults to HIGH."""
        severity = pip_audit._determine_severity("some generic vulnerability")
        assert severity == Severity.HIGH

    def test_empty_description_defaults_to_high(self) -> None:
        """Test empty description defaults to HIGH."""
        severity = pip_audit._determine_severity("")
        assert severity == Severity.HIGH


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_missing_vulns_key(self) -> None:
        """Test handling of missing vulns key."""
        data = json.dumps({
            "dependencies": [
                {"name": "package", "version": "1.0.0"}
                # No vulns key
            ]
        })
        findings = pip_audit.parse_output(data)
        assert findings == []

    def test_malformed_dependency_entry(self) -> None:
        """Test handling of malformed dependency entries."""
        data = json.dumps({
            "dependencies": [
                {},  # Empty entry
                {"name": "package", "version": "1.0.0", "vulns": [
                    {"id": "PYSEC-1", "description": "Test"}
                ]}
            ]
        })
        findings = pip_audit.parse_output(data)
        assert len(findings) == 1

    def test_array_format_fallback(self) -> None:
        """Test handling of older array format."""
        # Some versions output array directly
        data = json.dumps([
            {
                "name": "package",
                "version": "1.0.0",
                "vulns": [{"id": "PYSEC-1", "fix_versions": [], "aliases": []}]
            }
        ])
        findings = pip_audit.parse_output(data)
        assert len(findings) == 1
