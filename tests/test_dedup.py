"""Tests for finding deduplication."""


from vibeguard.core.dedup import (
    _normalize_fingerprint,
    _normalize_rule_id,
    _should_replace,
    count_by_scanner,
    deduplicate_findings,
    group_findings_by_file,
)
from vibeguard.models.finding import Category, Finding, Severity


class TestDeduplicateFindings:
    """Tests for deduplicate_findings function."""

    def test_empty_list(self) -> None:
        """Test deduplicating empty list."""
        result = deduplicate_findings([])
        assert result == []

    def test_single_finding(self) -> None:
        """Test single finding passes through unchanged."""
        finding = Finding(
            scanner="semgrep",
            rule_id="test-rule",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            title="Test",
            message="Test message",
            file_path="test.py",
            line_start=10,
        )
        result = deduplicate_findings([finding])
        assert len(result) == 1
        assert result[0] == finding

    def test_exact_duplicates_removed(self) -> None:
        """Test exact duplicates are removed."""
        finding1 = Finding(
            scanner="semgrep",
            rule_id="test-rule",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            title="Test",
            message="Test message",
            file_path="test.py",
            line_start=10,
        )
        finding2 = Finding(
            scanner="semgrep",
            rule_id="test-rule",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            title="Test",
            message="Test message",
            file_path="test.py",
            line_start=10,
        )
        result = deduplicate_findings([finding1, finding2])
        assert len(result) == 1

    def test_keeps_higher_severity(self) -> None:
        """Test higher severity finding is kept."""
        low_finding = Finding(
            scanner="scanner1",
            rule_id="test-rule",
            severity=Severity.LOW,
            category=Category.SECURITY,
            title="Test",
            message="Test message",
            file_path="test.py",
            line_start=10,
        )
        high_finding = Finding(
            scanner="scanner2",
            rule_id="test-rule",
            severity=Severity.CRITICAL,
            category=Category.SECURITY,
            title="Test",
            message="Test message",
            file_path="test.py",
            line_start=10,
        )
        # Order shouldn't matter - critical should be kept
        result = deduplicate_findings([low_finding, high_finding])
        assert len(result) == 1
        assert result[0].severity == Severity.CRITICAL

    def test_nearby_lines_grouped(self) -> None:
        """Test findings on nearby lines are grouped."""
        finding1 = Finding(
            scanner="semgrep",
            rule_id="test-rule",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            title="Test",
            message="Test message",
            file_path="test.py",
            line_start=10,
        )
        finding2 = Finding(
            scanner="semgrep",
            rule_id="test-rule",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            title="Test",
            message="Test message",
            file_path="test.py",
            line_start=12,  # Within LINE_PROXIMITY (5)
        )
        result = deduplicate_findings([finding1, finding2])
        assert len(result) == 1

    def test_different_files_not_deduped(self) -> None:
        """Test findings in different files are not deduplicated."""
        finding1 = Finding(
            scanner="semgrep",
            rule_id="test-rule",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            title="Test",
            message="Test message",
            file_path="test1.py",
            line_start=10,
        )
        finding2 = Finding(
            scanner="semgrep",
            rule_id="test-rule",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            title="Test",
            message="Test message",
            file_path="test2.py",
            line_start=10,
        )
        result = deduplicate_findings([finding1, finding2])
        assert len(result) == 2

    def test_different_rules_not_deduped(self) -> None:
        """Test findings with different rules are not deduplicated."""
        finding1 = Finding(
            scanner="semgrep",
            rule_id="rule-a",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            title="Test",
            message="Test message",
            file_path="test.py",
            line_start=10,
        )
        finding2 = Finding(
            scanner="semgrep",
            rule_id="rule-b",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            title="Test",
            message="Test message",
            file_path="test.py",
            line_start=10,
        )
        result = deduplicate_findings([finding1, finding2])
        assert len(result) == 2

    def test_cross_scanner_dedup_aws(self) -> None:
        """Test cross-scanner dedup for AWS credentials."""
        gitleaks_finding = Finding(
            scanner="gitleaks",
            rule_id="aws-access-key-id",
            severity=Severity.CRITICAL,
            category=Category.SECRETS,
            title="AWS Key",
            message="AWS key found",
            file_path="config.py",
            line_start=5,
        )
        trufflehog_finding = Finding(
            scanner="trufflehog",
            rule_id="AWS",
            severity=Severity.CRITICAL,
            category=Category.SECRETS,
            title="AWS Key",
            message="AWS key found",
            file_path="config.py",
            line_start=5,
        )
        result = deduplicate_findings([gitleaks_finding, trufflehog_finding])
        assert len(result) == 1

    def test_prefers_finding_with_cwe(self) -> None:
        """Test that finding with CWE is preferred."""
        without_cwe = Finding(
            scanner="scanner1",
            rule_id="test-rule",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            title="Test",
            message="Test message",
            file_path="test.py",
            line_start=10,
        )
        with_cwe = Finding(
            scanner="scanner2",
            rule_id="test-rule",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            title="Test",
            message="Test message",
            file_path="test.py",
            line_start=10,
            cwe="CWE-89",
        )
        result = deduplicate_findings([without_cwe, with_cwe])
        assert len(result) == 1
        assert result[0].cwe == "CWE-89"


class TestNormalizeRuleId:
    """Tests for _normalize_rule_id function."""

    def test_aws_patterns(self) -> None:
        """Test AWS-related patterns are normalized."""
        assert _normalize_rule_id("aws-access-key-id") == "aws-credential"
        assert _normalize_rule_id("AWS") == "aws-credential"
        assert _normalize_rule_id("amazon-credentials") == "aws-credential"

    def test_private_key_patterns(self) -> None:
        """Test private key patterns are normalized."""
        assert _normalize_rule_id("private-key") == "private-key"
        assert _normalize_rule_id("ssh-private-key") == "private-key"
        assert _normalize_rule_id("RSA-key") == "private-key"

    def test_api_key_patterns(self) -> None:
        """Test API key patterns are normalized."""
        assert _normalize_rule_id("generic-api-key") == "api-key"
        assert _normalize_rule_id("apikey") == "api-key"
        assert _normalize_rule_id("api_key_exposed") == "api-key"

    def test_password_patterns(self) -> None:
        """Test password patterns are normalized."""
        assert _normalize_rule_id("hardcoded-password") == "password"
        assert _normalize_rule_id("passwd-in-url") == "password"

    def test_injection_patterns(self) -> None:
        """Test injection patterns are normalized."""
        assert _normalize_rule_id("sql-injection") == "injection"
        assert _normalize_rule_id("sqli-vulnerability") == "injection"

    def test_cve_preserved(self) -> None:
        """Test CVE IDs are preserved."""
        assert _normalize_rule_id("CVE-2024-1234") == "cve-2024-1234"

    def test_unknown_rule_lowercase(self) -> None:
        """Test unknown rules are lowercased."""
        assert _normalize_rule_id("CustomRule123") == "customrule123"


class TestNormalizeFingerprint:
    """Tests for _normalize_fingerprint function."""

    def test_normalizes_path(self) -> None:
        """Test path normalization."""
        finding = Finding(
            scanner="test",
            rule_id="rule",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            title="Test",
            message="Test",
            file_path="./src\\test.py",
            line_start=10,
        )
        fp = _normalize_fingerprint(finding)
        assert "src/test.py" in fp
        assert "./" not in fp
        assert "\\" not in fp

    def test_groups_nearby_lines(self) -> None:
        """Test nearby lines produce same fingerprint."""
        finding1 = Finding(
            scanner="test",
            rule_id="rule",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            title="Test",
            message="Test",
            file_path="test.py",
            line_start=10,
        )
        finding2 = Finding(
            scanner="test",
            rule_id="rule",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            title="Test",
            message="Test",
            file_path="test.py",
            line_start=12,
        )
        assert _normalize_fingerprint(finding1) == _normalize_fingerprint(finding2)


class TestShouldReplace:
    """Tests for _should_replace function."""

    def test_replaces_higher_severity(self) -> None:
        """Test higher severity replaces lower."""
        low = Finding(
            scanner="a", rule_id="r", severity=Severity.LOW,
            category=Category.SECURITY, title="T", message="M",
            file_path="f", line_start=1,
        )
        high = Finding(
            scanner="a", rule_id="r", severity=Severity.HIGH,
            category=Category.SECURITY, title="T", message="M",
            file_path="f", line_start=1,
        )
        assert _should_replace(low, high) is True
        assert _should_replace(high, low) is False

    def test_replaces_for_cwe(self) -> None:
        """Test finding with CWE replaces one without."""
        without_cwe = Finding(
            scanner="a", rule_id="r", severity=Severity.HIGH,
            category=Category.SECURITY, title="T", message="M",
            file_path="f", line_start=1,
        )
        with_cwe = Finding(
            scanner="a", rule_id="r", severity=Severity.HIGH,
            category=Category.SECURITY, title="T", message="M",
            file_path="f", line_start=1, cwe="CWE-89",
        )
        assert _should_replace(without_cwe, with_cwe) is True

    def test_replaces_for_more_references(self) -> None:
        """Test finding with more references replaces one with fewer."""
        few_refs = Finding(
            scanner="a", rule_id="r", severity=Severity.HIGH,
            category=Category.SECURITY, title="T", message="M",
            file_path="f", line_start=1, references=[],
        )
        more_refs = Finding(
            scanner="a", rule_id="r", severity=Severity.HIGH,
            category=Category.SECURITY, title="T", message="M",
            file_path="f", line_start=1, references=["http://example.com"],
        )
        assert _should_replace(few_refs, more_refs) is True


class TestGroupFindingsByFile:
    """Tests for group_findings_by_file function."""

    def test_empty_list(self) -> None:
        """Test grouping empty list."""
        result = group_findings_by_file([])
        assert result == {}

    def test_single_file(self) -> None:
        """Test grouping findings from single file."""
        findings = [
            Finding(
                scanner="test", rule_id="r1", severity=Severity.HIGH,
                category=Category.SECURITY, title="T", message="M",
                file_path="test.py", line_start=10,
            ),
            Finding(
                scanner="test", rule_id="r2", severity=Severity.HIGH,
                category=Category.SECURITY, title="T", message="M",
                file_path="test.py", line_start=20,
            ),
        ]
        result = group_findings_by_file(findings)
        assert len(result) == 1
        assert "test.py" in result
        assert len(result["test.py"]) == 2

    def test_multiple_files(self) -> None:
        """Test grouping findings from multiple files."""
        findings = [
            Finding(
                scanner="test", rule_id="r1", severity=Severity.HIGH,
                category=Category.SECURITY, title="T", message="M",
                file_path="file1.py", line_start=10,
            ),
            Finding(
                scanner="test", rule_id="r2", severity=Severity.HIGH,
                category=Category.SECURITY, title="T", message="M",
                file_path="file2.py", line_start=5,
            ),
        ]
        result = group_findings_by_file(findings)
        assert len(result) == 2
        assert "file1.py" in result
        assert "file2.py" in result

    def test_sorted_by_line(self) -> None:
        """Test findings within file are sorted by line number."""
        findings = [
            Finding(
                scanner="test", rule_id="r2", severity=Severity.HIGH,
                category=Category.SECURITY, title="T", message="M",
                file_path="test.py", line_start=20,
            ),
            Finding(
                scanner="test", rule_id="r1", severity=Severity.HIGH,
                category=Category.SECURITY, title="T", message="M",
                file_path="test.py", line_start=5,
            ),
        ]
        result = group_findings_by_file(findings)
        assert result["test.py"][0].line_start == 5
        assert result["test.py"][1].line_start == 20


class TestCountByScanner:
    """Tests for count_by_scanner function."""

    def test_empty_list(self) -> None:
        """Test counting empty list."""
        result = count_by_scanner([])
        assert result == {}

    def test_single_scanner(self) -> None:
        """Test counting findings from single scanner."""
        findings = [
            Finding(
                scanner="semgrep", rule_id="r1", severity=Severity.HIGH,
                category=Category.SECURITY, title="T", message="M",
                file_path="test.py", line_start=10,
            ),
            Finding(
                scanner="semgrep", rule_id="r2", severity=Severity.HIGH,
                category=Category.SECURITY, title="T", message="M",
                file_path="test.py", line_start=20,
            ),
        ]
        result = count_by_scanner(findings)
        assert result == {"semgrep": 2}

    def test_multiple_scanners(self) -> None:
        """Test counting findings from multiple scanners."""
        findings = [
            Finding(
                scanner="semgrep", rule_id="r1", severity=Severity.HIGH,
                category=Category.SECURITY, title="T", message="M",
                file_path="test.py", line_start=10,
            ),
            Finding(
                scanner="gitleaks", rule_id="r2", severity=Severity.HIGH,
                category=Category.SECRETS, title="T", message="M",
                file_path="test.py", line_start=20,
            ),
            Finding(
                scanner="semgrep", rule_id="r3", severity=Severity.HIGH,
                category=Category.SECURITY, title="T", message="M",
                file_path="test.py", line_start=30,
            ),
        ]
        result = count_by_scanner(findings)
        assert result == {"semgrep": 2, "gitleaks": 1}
