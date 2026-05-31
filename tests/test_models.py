"""Tests for Pydantic models."""

from datetime import datetime

from vibeguard.models.finding import Category, Finding, Severity
from vibeguard.models.scan_result import ScanResult


class TestFinding:
    def test_create_minimal_finding(self) -> None:
        finding = Finding(
            scanner="semgrep",
            rule_id="python.security.eval",
            severity=Severity.HIGH,
            title="Use of eval",
            message="Avoid using eval()",
            file_path="app.py",
            line_start=10,
        )
        assert finding.scanner == "semgrep"
        assert finding.severity == Severity.HIGH
        assert finding.id is not None
        assert len(finding.id) == 16

    def test_finding_id_is_stable(self) -> None:
        """Same input should produce same ID."""
        f1 = Finding(
            scanner="semgrep",
            rule_id="rule1",
            severity=Severity.HIGH,
            title="Test",
            message="Test message",
            file_path="test.py",
            line_start=1,
        )
        f2 = Finding(
            scanner="semgrep",
            rule_id="rule1",
            severity=Severity.HIGH,
            title="Test",
            message="Test message",
            file_path="test.py",
            line_start=1,
        )
        assert f1.id == f2.id

    def test_finding_id_differs_for_different_location(self) -> None:
        f1 = Finding(
            scanner="semgrep",
            rule_id="rule1",
            severity=Severity.HIGH,
            title="Test",
            message="Test",
            file_path="test.py",
            line_start=1,
        )
        f2 = Finding(
            scanner="semgrep",
            rule_id="rule1",
            severity=Severity.HIGH,
            title="Test",
            message="Test",
            file_path="test.py",
            line_start=2,  # Different line
        )
        assert f1.id != f2.id

    def test_finding_default_category(self) -> None:
        finding = Finding(
            scanner="test",
            rule_id="test-rule",
            severity=Severity.LOW,
            title="Test",
            message="Test",
            file_path="test.py",
            line_start=1,
        )
        assert finding.category == Category.SECURITY

    def test_finding_optional_fields(self) -> None:
        finding = Finding(
            scanner="test",
            rule_id="test-rule",
            severity=Severity.LOW,
            title="Test",
            message="Test",
            file_path="test.py",
            line_start=1,
        )
        assert finding.line_end is None
        assert finding.cwe is None
        assert finding.references == []
        assert finding.code_snippet is None
        assert finding.fingerprint is None


class TestScanResult:
    def test_empty_scan_result(self) -> None:
        result = ScanResult(
            repo_root="/path/to/repo",
            started_at=datetime.now(),
        )
        assert result.score == 100
        assert result.grade == "A+"
        assert result.counts.critical == 0
        assert result.counts.high == 0
        assert result.counts.medium == 0
        assert result.counts.low == 0
        assert result.counts.info == 0

    def test_score_calculation_critical(self) -> None:
        result = ScanResult(
            repo_root="/path",
            started_at=datetime.now(),
            findings=[
                Finding(
                    scanner="test",
                    rule_id="r1",
                    severity=Severity.CRITICAL,
                    title="Critical issue",
                    message="Bad",
                    file_path="a.py",
                    line_start=1,
                ),
            ],
        )
        # Base 100 - 20 (critical) = 80
        assert result.score == 80
        assert result.grade == "B"  # 80 < 85, so grade is B

    def test_score_calculation_mixed(self) -> None:
        result = ScanResult(
            repo_root="/path",
            started_at=datetime.now(),
            findings=[
                Finding(
                    scanner="test",
                    rule_id="r1",
                    severity=Severity.CRITICAL,
                    title="Critical issue",
                    message="Bad",
                    file_path="a.py",
                    line_start=1,
                ),
                Finding(
                    scanner="test",
                    rule_id="r2",
                    severity=Severity.HIGH,
                    title="High issue",
                    message="Bad",
                    file_path="b.py",
                    line_start=1,
                ),
            ],
        )
        # Base 100 - 20 (critical) - 10 (high) = 70
        assert result.score == 70
        assert result.grade == "B"

    def test_score_minimum_zero(self) -> None:
        """Score should not go below 0 even with many findings across categories."""
        # Create findings across multiple categories to exceed caps
        findings = []
        # 10 critical security findings (default category)
        for i in range(10):
            findings.append(Finding(
                scanner="test",
                rule_id=f"r{i}",
                severity=Severity.CRITICAL,
                category=Category.SECURITY,
                title="Critical",
                message="Bad",
                file_path=f"sec{i}.py",
                line_start=1,
            ))
        # 10 critical secret findings
        for i in range(10):
            findings.append(Finding(
                scanner="test",
                rule_id=f"s{i}",
                severity=Severity.CRITICAL,
                category=Category.SECRETS,
                title="Secret",
                message="Bad",
                file_path=f"secret{i}.py",
                line_start=1,
            ))
        # 10 critical vulnerability findings
        for i in range(10):
            findings.append(Finding(
                scanner="test",
                rule_id=f"v{i}",
                severity=Severity.CRITICAL,
                category=Category.VULNERABILITY,
                title="Vuln",
                message="Bad",
                file_path=f"vuln{i}.py",
                line_start=1,
            ))

        result = ScanResult(
            repo_root="/path",
            started_at=datetime.now(),
            findings=findings,
        )
        # With category cap of 50, each category contributes max 50
        # 3 categories * 50 = 150, but score floors at 0
        assert result.score == 0
        assert result.grade == "F"

    def test_score_category_cap(self) -> None:
        """Score deductions should be capped per category."""
        # 10 critical security findings = 200 points, but capped at 50
        findings = [
            Finding(
                scanner="test",
                rule_id=f"r{i}",
                severity=Severity.CRITICAL,
                category=Category.SECURITY,
                title="Critical",
                message="Bad",
                file_path=f"{i}.py",
                line_start=1,
            )
            for i in range(10)
        ]
        result = ScanResult(
            repo_root="/path",
            started_at=datetime.now(),
            findings=findings,
        )
        # Base 100 - 50 (capped) = 50
        assert result.score == 50
        assert result.grade == "C"

    def test_grade_boundaries(self) -> None:
        def make_result(findings_count: int, severity: Severity) -> ScanResult:
            findings = [
                Finding(
                    scanner="test",
                    rule_id=f"r{i}",
                    severity=severity,
                    title="Issue",
                    message="Bad",
                    file_path=f"{i}.py",
                    line_start=1,
                )
                for i in range(findings_count)
            ]
            return ScanResult(
                repo_root="/path",
                started_at=datetime.now(),
                findings=findings,
            )

        # A+ requires score >= 95 (max 2 low or 1 medium)
        assert make_result(0, Severity.LOW).grade == "A+"
        assert make_result(2, Severity.LOW).grade == "A+"  # 100 - 4 = 96
        assert make_result(3, Severity.LOW).grade == "A"   # 100 - 6 = 94

        # A requires score >= 85
        assert make_result(1, Severity.MEDIUM).grade == "A+"  # 100 - 5 = 95
        assert make_result(3, Severity.MEDIUM).grade == "A"   # 100 - 15 = 85

        # B requires score >= 70
        assert make_result(1, Severity.CRITICAL).grade == "B"  # 100 - 20 = 80
        assert make_result(2, Severity.CRITICAL).grade == "C"  # 100 - 40 = 60

    def test_partial_scan(self) -> None:
        result = ScanResult(
            repo_root="/path",
            started_at=datetime.now(),
            scanners_run=["semgrep"],
            scanners_skipped=["gitleaks"],
            partial=True,
        )
        assert result.partial is True
        assert "gitleaks" in result.scanners_skipped
