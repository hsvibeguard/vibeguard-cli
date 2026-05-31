"""Tests for cargo-audit parser."""

import json

import pytest

from vibeguard.models.finding import Category, Severity
from vibeguard.scanners.parsers import cargo_audit


class TestParseOutput:
    """Tests for parse_output function."""

    def test_parse_valid_output(self, cargo_audit_json_output: str) -> None:
        """Test parsing valid cargo-audit output."""
        findings = cargo_audit.parse_output(cargo_audit_json_output)

        # Should have 2 vulnerabilities (hyper, tokio)
        assert len(findings) == 2
        assert all(f.scanner == "cargo_audit" for f in findings)
        assert all(f.category == Category.VULNERABILITY for f in findings)

    def test_parse_empty_vulnerabilities(self) -> None:
        """Test parsing output with no vulnerabilities."""
        data = json.dumps({
            "vulnerabilities": {"list": [], "count": 0}
        })
        findings = cargo_audit.parse_output(data)
        assert findings == []

    def test_parse_empty_string(self) -> None:
        """Test parsing empty string."""
        findings = cargo_audit.parse_output("")
        assert findings == []

    def test_parse_invalid_json(self) -> None:
        """Test that invalid JSON raises ValueError."""
        with pytest.raises(ValueError, match="Invalid cargo-audit JSON"):
            cargo_audit.parse_output("not valid json")

    def test_extract_fields(self, cargo_audit_json_output: str) -> None:
        """Test that fields are extracted correctly."""
        findings = cargo_audit.parse_output(cargo_audit_json_output)

        # Find hyper finding
        hyper_finding = next((f for f in findings if "hyper" in f.fingerprint), None)
        assert hyper_finding is not None

        assert hyper_finding.rule_id == "RUSTSEC-2024-0001"
        assert "hyper" in hyper_finding.message.lower()
        assert hyper_finding.file_path == "Cargo.toml"
        assert hyper_finding.line_start == 1

    def test_advisory_title_used(self, cargo_audit_json_output: str) -> None:
        """Test that advisory title is used as finding title."""
        findings = cargo_audit.parse_output(cargo_audit_json_output)

        hyper_finding = next((f for f in findings if "hyper" in f.fingerprint), None)
        assert hyper_finding is not None
        assert "Integer overflow" in hyper_finding.title

    def test_patched_versions_included(self, cargo_audit_json_output: str) -> None:
        """Test that patched versions are included in message."""
        findings = cargo_audit.parse_output(cargo_audit_json_output)

        hyper_finding = next((f for f in findings if "hyper" in f.fingerprint), None)
        assert hyper_finding is not None
        assert "Patched in" in hyper_finding.message or ">=0.14.28" in hyper_finding.message

    def test_references_generated(self, cargo_audit_json_output: str) -> None:
        """Test that references are generated for RustSec IDs."""
        findings = cargo_audit.parse_output(cargo_audit_json_output)

        for finding in findings:
            assert len(finding.references) >= 1
            # Should have RustSec link
            rustsec_refs = [r for r in finding.references if "rustsec.org" in r]
            assert len(rustsec_refs) >= 1

    def test_cve_alias_in_references(self, cargo_audit_json_output: str) -> None:
        """Test that CVE aliases generate NVD links."""
        findings = cargo_audit.parse_output(cargo_audit_json_output)

        # hyper has CVE alias
        hyper_finding = next((f for f in findings if "hyper" in f.fingerprint), None)
        assert hyper_finding is not None

        nvd_refs = [r for r in hyper_finding.references if "nvd.nist.gov" in r]
        assert len(nvd_refs) >= 1

    def test_category_always_vulnerability(self, cargo_audit_json_output: str) -> None:
        """Test all findings have VULNERABILITY category."""
        findings = cargo_audit.parse_output(cargo_audit_json_output)
        assert all(f.category == Category.VULNERABILITY for f in findings)

    def test_fingerprint_generated(self, cargo_audit_json_output: str) -> None:
        """Test fingerprint is generated for each finding."""
        findings = cargo_audit.parse_output(cargo_audit_json_output)
        for finding in findings:
            assert finding.fingerprint is not None
            assert "cargo_audit" in finding.fingerprint


class TestDetermineSeverity:
    """Tests for severity determination."""

    def test_memory_corruption_is_critical(self) -> None:
        """Test memory corruption category is CRITICAL."""
        severity = cargo_audit._determine_severity(None, ["memory-corruption"])
        assert severity == Severity.CRITICAL

    def test_code_execution_is_critical(self) -> None:
        """Test code execution category is CRITICAL."""
        severity = cargo_audit._determine_severity(None, ["code-execution"])
        assert severity == Severity.CRITICAL

    def test_denial_of_service_is_medium(self) -> None:
        """Test denial-of-service category is MEDIUM."""
        severity = cargo_audit._determine_severity(None, ["denial-of-service"])
        assert severity == Severity.MEDIUM

    def test_unknown_category_defaults_to_high(self) -> None:
        """Test unknown category defaults to HIGH."""
        severity = cargo_audit._determine_severity(None, ["unknown-category"])
        assert severity == Severity.HIGH

    def test_empty_categories_defaults_to_high(self) -> None:
        """Test empty categories defaults to HIGH."""
        severity = cargo_audit._determine_severity(None, [])
        assert severity == Severity.HIGH


class TestCVSSParsing:
    """Tests for CVSS score parsing."""

    def test_parse_cvss_float(self) -> None:
        """Test parsing CVSS as float string."""
        score = cargo_audit._parse_cvss_score("9.8")
        assert score == 9.8

    def test_parse_cvss_vector_returns_none(self) -> None:
        """Test CVSS vector string returns None (falls back to categories)."""
        score = cargo_audit._parse_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        # Vector parsing is not implemented, should return None
        assert score is None

    def test_parse_empty_cvss(self) -> None:
        """Test empty CVSS returns None."""
        score = cargo_audit._parse_cvss_score("")
        assert score is None

    def test_parse_none_cvss(self) -> None:
        """Test None CVSS returns None."""
        score = cargo_audit._parse_cvss_score(None)
        assert score is None


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_missing_advisory(self) -> None:
        """Test handling of missing advisory in vulnerability."""
        data = json.dumps({
            "vulnerabilities": {
                "list": [
                    {"package": {"name": "test", "version": "1.0.0"}}
                    # No advisory
                ],
                "count": 1
            }
        })
        findings = cargo_audit.parse_output(data)
        # Should skip malformed entry
        assert findings == []

    def test_missing_package_info(self) -> None:
        """Test handling of missing package info uses advisory package."""
        data = json.dumps({
            "vulnerabilities": {
                "list": [
                    {
                        "advisory": {
                            "id": "RUSTSEC-2024-TEST",
                            "package": "from-advisory",
                            "title": "Test"
                        },
                        "versions": {"patched": [], "unaffected": []}
                        # No package section
                    }
                ],
                "count": 1
            }
        })
        findings = cargo_audit.parse_output(data)
        assert len(findings) == 1
        assert "from-advisory" in findings[0].fingerprint

    def test_missing_versions_section(self) -> None:
        """Test handling of missing versions section."""
        data = json.dumps({
            "vulnerabilities": {
                "list": [
                    {
                        "advisory": {
                            "id": "RUSTSEC-2024-TEST",
                            "package": "test",
                            "title": "Test"
                        },
                        "package": {"name": "test", "version": "1.0.0"}
                        # No versions section
                    }
                ],
                "count": 1
            }
        })
        findings = cargo_audit.parse_output(data)
        assert len(findings) == 1
        assert "No patch available" in findings[0].message
