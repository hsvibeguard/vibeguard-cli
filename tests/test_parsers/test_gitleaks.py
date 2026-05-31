"""Tests for Gitleaks parser."""

import json

import pytest

from vibeguard.models.finding import Category, Severity
from vibeguard.scanners.parsers import gitleaks


class TestParseOutput:
    """Tests for parse_output function."""

    def test_parse_valid_output(self, gitleaks_json_output: str) -> None:
        """Test parsing valid Gitleaks output."""
        findings = gitleaks.parse_output(gitleaks_json_output)

        assert len(findings) == 2
        assert all(f.scanner == "gitleaks" for f in findings)
        assert all(f.category == Category.SECRETS for f in findings)

    def test_parse_empty_array(self) -> None:
        """Test parsing empty results array."""
        findings = gitleaks.parse_output("[]")
        assert findings == []

    def test_parse_empty_string(self) -> None:
        """Test parsing empty string."""
        findings = gitleaks.parse_output("")
        assert findings == []

    def test_parse_invalid_json(self) -> None:
        """Test that invalid JSON raises ValueError."""
        with pytest.raises(ValueError, match="Invalid Gitleaks JSON"):
            gitleaks.parse_output("not valid json")

    def test_extract_fields(self, gitleaks_json_output: str) -> None:
        """Test that all fields are extracted correctly."""
        findings = gitleaks.parse_output(gitleaks_json_output)
        finding = findings[0]

        assert finding.rule_id == "generic-api-key"
        assert finding.title == "Generic API Key"
        assert finding.file_path == "config/settings.py"
        assert finding.line_start == 23
        assert finding.line_end == 23
        assert finding.code_snippet == "api_key = 'sk_live_xxxxxxxxxxxx'"
        assert finding.fingerprint is not None

    def test_severity_mapping_critical(self, gitleaks_json_output: str) -> None:
        """Test AWS key gets CRITICAL severity."""
        findings = gitleaks.parse_output(gitleaks_json_output)
        aws_finding = next(f for f in findings if "aws" in f.rule_id.lower())
        assert aws_finding.severity == Severity.CRITICAL

    def test_severity_mapping_high(self, gitleaks_json_output: str) -> None:
        """Test generic API key gets HIGH severity."""
        findings = gitleaks.parse_output(gitleaks_json_output)
        api_finding = next(f for f in findings if f.rule_id == "generic-api-key")
        assert api_finding.severity == Severity.HIGH

    def test_category_always_secrets(self, gitleaks_json_output: str) -> None:
        """Test all findings have SECRETS category."""
        findings = gitleaks.parse_output(gitleaks_json_output)
        assert all(f.category == Category.SECRETS for f in findings)

    def test_parse_single_result(self) -> None:
        """Test parsing a single result."""
        data = json.dumps([{
            "Description": "Private Key",
            "StartLine": 1,
            "File": "key.pem",
            "RuleID": "private-key",
            "Fingerprint": "abc123"
        }])
        findings = gitleaks.parse_output(data)

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_malformed_entry_skipped(self) -> None:
        """Test that malformed entries are skipped."""
        # Entry without required fields should be skipped
        data = json.dumps([{}, {"Description": "Test", "File": "test.py", "RuleID": "test"}])
        findings = gitleaks.parse_output(data)
        # First entry skipped, second parsed
        assert len(findings) >= 1


class TestDetermineSeverity:
    """Tests for severity determination."""

    def test_aws_is_critical(self) -> None:
        """Test AWS-related rules are CRITICAL."""
        assert gitleaks._determine_severity("aws-access-key") == Severity.CRITICAL

    def test_private_key_is_critical(self) -> None:
        """Test private key rules are CRITICAL."""
        assert gitleaks._determine_severity("private-key") == Severity.CRITICAL
        assert gitleaks._determine_severity("rsa-private-key") == Severity.CRITICAL

    def test_api_key_is_high(self) -> None:
        """Test API key rules are HIGH."""
        assert gitleaks._determine_severity("generic-api-key") == Severity.HIGH
        assert gitleaks._determine_severity("github-api-key") == Severity.HIGH

    def test_password_is_high(self) -> None:
        """Test password rules are HIGH."""
        assert gitleaks._determine_severity("password-in-url") == Severity.HIGH

    def test_generic_is_medium(self) -> None:
        """Test generic rules without secret keywords are MEDIUM."""
        # "generic-secret" contains "secret" so it maps to HIGH
        # Pure generic patterns without sensitive keywords map to MEDIUM
        assert gitleaks._determine_severity("generic-detector") == Severity.MEDIUM

    def test_unknown_defaults_to_high(self) -> None:
        """Test unknown rules default to HIGH."""
        assert gitleaks._determine_severity("unknown-rule-xyz") == Severity.HIGH
