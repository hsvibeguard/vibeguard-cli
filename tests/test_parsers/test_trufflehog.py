"""Tests for TruffleHog parser."""

import json

from vibeguard.models.finding import Category, Severity
from vibeguard.scanners.parsers import trufflehog


class TestParseOutput:
    """Tests for parse_output function."""

    def test_parse_valid_output(self, trufflehog_jsonl_output: str) -> None:
        """Test parsing valid TruffleHog output."""
        findings = trufflehog.parse_output(trufflehog_jsonl_output)

        assert len(findings) == 3
        assert all(f.scanner == "trufflehog" for f in findings)
        assert all(f.category == Category.SECRETS for f in findings)

    def test_parse_empty_string(self) -> None:
        """Test parsing empty string."""
        findings = trufflehog.parse_output("")
        assert findings == []

    def test_parse_blank_lines(self) -> None:
        """Test parsing output with blank lines."""
        data = json.dumps({
            "DetectorName": "Test",
            "SourceMetadata": {"Data": {"Filesystem": {"file": "test.py", "line": 1}}}
        })
        output = f"\n{data}\n\n"
        findings = trufflehog.parse_output(output)
        assert len(findings) == 1

    def test_parse_invalid_json_line_skipped(self) -> None:
        """Test that invalid JSON lines are skipped."""
        valid = json.dumps({
            "DetectorName": "Test",
            "SourceMetadata": {"Data": {"Filesystem": {"file": "test.py", "line": 1}}}
        })
        output = f"invalid json\n{valid}\nmore invalid"
        findings = trufflehog.parse_output(output)
        assert len(findings) == 1

    def test_extract_fields(self, trufflehog_jsonl_output: str) -> None:
        """Test that all fields are extracted correctly."""
        findings = trufflehog.parse_output(trufflehog_jsonl_output)
        aws_finding = next(f for f in findings if f.rule_id == "AWS" or "AWS" in f.title)

        assert aws_finding.file_path == "config/secrets.py"
        assert aws_finding.line_start == 15
        assert "AWS" in aws_finding.title
        assert "Verified" in aws_finding.title
        assert aws_finding.fingerprint is not None
        assert aws_finding.code_snippet is not None

    def test_verified_secret_is_critical(self, trufflehog_jsonl_output: str) -> None:
        """Test verified secrets are CRITICAL."""
        findings = trufflehog.parse_output(trufflehog_jsonl_output)
        aws_finding = next(f for f in findings if "AWS" in f.title)
        assert aws_finding.severity == Severity.CRITICAL
        assert "Verified" in aws_finding.title

    def test_aws_unverified_is_critical(self) -> None:
        """Test AWS credentials are CRITICAL even unverified."""
        data = json.dumps({
            "DetectorName": "AWS",
            "Verified": False,
            "SourceMetadata": {"Data": {"Filesystem": {"file": "test.py", "line": 1}}}
        })
        findings = trufflehog.parse_output(data)
        assert findings[0].severity == Severity.CRITICAL

    def test_private_key_is_critical(self, trufflehog_jsonl_output: str) -> None:
        """Test private keys are CRITICAL."""
        findings = trufflehog.parse_output(trufflehog_jsonl_output)
        key_finding = next(f for f in findings if "PrivateKey" in f.title)
        assert key_finding.severity == Severity.CRITICAL

    def test_slack_token_is_high(self, trufflehog_jsonl_output: str) -> None:
        """Test Slack tokens are HIGH."""
        findings = trufflehog.parse_output(trufflehog_jsonl_output)
        slack_finding = next(f for f in findings if "Slack" in f.title)
        assert slack_finding.severity == Severity.HIGH

    def test_category_always_secrets(self, trufflehog_jsonl_output: str) -> None:
        """Test all findings have SECRETS category."""
        findings = trufflehog.parse_output(trufflehog_jsonl_output)
        assert all(f.category == Category.SECRETS for f in findings)

    def test_parse_single_line(self) -> None:
        """Test parsing a single JSON line."""
        data = json.dumps({
            "DetectorName": "GitHub",
            "DetectorType": 2,
            "Verified": False,
            "Redacted": "ghp_***",
            "SourceMetadata": {"Data": {"Filesystem": {"file": "test.py", "line": 5}}}
        })
        findings = trufflehog.parse_output(data)

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].file_path == "test.py"
        assert findings[0].line_start == 5

    def test_fingerprint_generated(self, trufflehog_jsonl_output: str) -> None:
        """Test fingerprint is generated for each finding."""
        findings = trufflehog.parse_output(trufflehog_jsonl_output)
        for finding in findings:
            assert finding.fingerprint is not None
            assert "trufflehog" in finding.fingerprint

    def test_redacted_in_snippet(self, trufflehog_jsonl_output: str) -> None:
        """Test redacted value is used as code snippet."""
        findings = trufflehog.parse_output(trufflehog_jsonl_output)
        aws_finding = next(f for f in findings if "AWS" in f.title)
        assert "***" in aws_finding.code_snippet

    def test_verified_message(self, trufflehog_jsonl_output: str) -> None:
        """Test verified secrets have appropriate message."""
        findings = trufflehog.parse_output(trufflehog_jsonl_output)
        aws_finding = next(f for f in findings if "AWS" in f.title)
        assert "verified" in aws_finding.message.lower()


class TestDetermineSeverity:
    """Tests for severity determination."""

    def test_verified_is_critical(self) -> None:
        """Test verified secrets are always CRITICAL."""
        assert trufflehog._determine_severity("Unknown", True) == Severity.CRITICAL

    def test_aws_is_critical(self) -> None:
        """Test AWS detector is CRITICAL."""
        assert trufflehog._determine_severity("AWS", False) == Severity.CRITICAL

    def test_gcp_is_critical(self) -> None:
        """Test GCP detector is CRITICAL."""
        assert trufflehog._determine_severity("GCP", False) == Severity.CRITICAL

    def test_azure_is_critical(self) -> None:
        """Test Azure detector is CRITICAL."""
        assert trufflehog._determine_severity("Azure", False) == Severity.CRITICAL

    def test_private_key_is_critical(self) -> None:
        """Test PrivateKey detector is CRITICAL."""
        assert trufflehog._determine_severity("PrivateKey", False) == Severity.CRITICAL

    def test_github_is_high(self) -> None:
        """Test GitHub detector is HIGH."""
        assert trufflehog._determine_severity("GitHub", False) == Severity.HIGH

    def test_slack_is_high(self) -> None:
        """Test Slack detector is HIGH."""
        assert trufflehog._determine_severity("Slack", False) == Severity.HIGH

    def test_stripe_is_high(self) -> None:
        """Test Stripe detector is HIGH."""
        assert trufflehog._determine_severity("Stripe", False) == Severity.HIGH

    def test_api_pattern_is_high(self) -> None:
        """Test detectors with 'api' pattern are HIGH."""
        assert trufflehog._determine_severity("CustomAPIKey", False) == Severity.HIGH

    def test_token_pattern_is_high(self) -> None:
        """Test detectors with 'token' pattern are HIGH."""
        assert trufflehog._determine_severity("CustomToken", False) == Severity.HIGH

    def test_unknown_is_medium(self) -> None:
        """Test unknown detectors are MEDIUM."""
        assert trufflehog._determine_severity("SomeRandomDetector", False) == Severity.MEDIUM
