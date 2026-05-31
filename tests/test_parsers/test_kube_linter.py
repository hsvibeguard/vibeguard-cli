"""Tests for kube-linter parser."""

import json

import pytest

from vibeguard.models.finding import Category, Severity
from vibeguard.scanners.parsers import kube_linter


class TestParseOutput:
    """Tests for parse_output function."""

    def test_parse_valid_output(self, kube_linter_json_output: str) -> None:
        """Test parsing valid kube-linter output."""
        findings = kube_linter.parse_output(kube_linter_json_output)

        assert len(findings) == 3
        assert all(f.scanner == "kube-linter" for f in findings)
        assert all(f.category == Category.MISCONFIGURATION for f in findings)

    def test_parse_empty_reports(self) -> None:
        """Test parsing output with empty Reports."""
        data = json.dumps({"Reports": []})
        findings = kube_linter.parse_output(data)
        assert findings == []

    def test_parse_no_reports_key(self) -> None:
        """Test parsing output without Reports key."""
        data = json.dumps({"Summary": {}})
        findings = kube_linter.parse_output(data)
        assert findings == []

    def test_parse_empty_string(self) -> None:
        """Test parsing empty string."""
        findings = kube_linter.parse_output("")
        assert findings == []

    def test_parse_invalid_json(self) -> None:
        """Test that invalid JSON raises ValueError."""
        with pytest.raises(ValueError, match="Invalid kube-linter JSON"):
            kube_linter.parse_output("not valid json")

    def test_extract_fields(self, kube_linter_json_output: str) -> None:
        """Test that all fields are extracted correctly."""
        findings = kube_linter.parse_output(kube_linter_json_output)
        finding = findings[0]

        assert finding.rule_id == "run-as-non-root"
        assert "runAsNonRoot" in finding.message
        assert finding.file_path == "default/Deployment/my-deploy"
        assert finding.fingerprint == "run-as-non-root:default/Deployment/my-deploy"

    def test_security_checks_high_severity(self, kube_linter_json_output: str) -> None:
        """Test security-sensitive checks get HIGH severity."""
        findings = kube_linter.parse_output(kube_linter_json_output)
        run_as_non_root = next(f for f in findings if f.rule_id == "run-as-non-root")
        assert run_as_non_root.severity == Severity.HIGH

    def test_non_security_checks_medium_severity(self, kube_linter_json_output: str) -> None:
        """Test non-security checks get MEDIUM severity."""
        findings = kube_linter.parse_output(kube_linter_json_output)
        latest_tag = next(f for f in findings if f.rule_id == "latest-tag")
        assert latest_tag.severity == Severity.MEDIUM

    def test_category_always_misconfiguration(self, kube_linter_json_output: str) -> None:
        """Test all findings have MISCONFIGURATION category."""
        findings = kube_linter.parse_output(kube_linter_json_output)
        assert all(f.category == Category.MISCONFIGURATION for f in findings)

    def test_remediation_in_message(self, kube_linter_json_output: str) -> None:
        """Test remediation is included in message."""
        findings = kube_linter.parse_output(kube_linter_json_output)
        finding = findings[0]
        assert "Remediation:" in finding.message

    def test_object_info_in_file_path(self, kube_linter_json_output: str) -> None:
        """Test K8s object info forms the file_path."""
        findings = kube_linter.parse_output(kube_linter_json_output)
        # Check different namespaces/kinds
        deploy_finding = next(f for f in findings if "Deployment" in f.file_path)
        assert "default" in deploy_finding.file_path

        stateful_finding = next(f for f in findings if "StatefulSet" in f.file_path)
        assert "staging" in stateful_finding.file_path

    def test_malformed_entry_defaults(self) -> None:
        """Test that entries with missing fields use defaults."""
        data = json.dumps({"Reports": [{}]})
        findings = kube_linter.parse_output(data)
        assert len(findings) == 1
        assert findings[0].rule_id == "unknown"


class TestHighSeverityChecks:
    """Tests for security-sensitive check classification."""

    def test_run_as_non_root_is_high(self) -> None:
        """Test run-as-non-root is in HIGH_SEVERITY_CHECKS."""
        assert "run-as-non-root" in kube_linter.HIGH_SEVERITY_CHECKS

    def test_no_read_only_root_fs_is_high(self) -> None:
        """Test no-read-only-root-fs is in HIGH_SEVERITY_CHECKS."""
        assert "no-read-only-root-fs" in kube_linter.HIGH_SEVERITY_CHECKS

    def test_privileged_container_is_high(self) -> None:
        """Test privileged-container is in HIGH_SEVERITY_CHECKS."""
        assert "privileged-container" in kube_linter.HIGH_SEVERITY_CHECKS
