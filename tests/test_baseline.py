"""Tests for baseline functionality."""

import json
import time
from datetime import datetime
from pathlib import Path

import pytest

from vibeguard.core import baseline
from vibeguard.models.baseline import BaselineFinding, ComparisonResult
from vibeguard.models.finding import Category, Finding, Severity
from vibeguard.models.scan_result import ScanResult
from vibeguard.models.triage import TriageStatus


@pytest.fixture
def temp_repo(tmp_path: Path) -> Path:
    """Create a temporary repository directory."""
    return tmp_path


@pytest.fixture
def sample_finding() -> Finding:
    """Create a sample finding."""
    return Finding(
        scanner="semgrep",
        rule_id="python.security.injection",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        title="SQL Injection",
        message="User input used in SQL query",
        file_path="app/database.py",
        line_start=42,
        triage_status=TriageStatus.ACTIONABLE,
    )


@pytest.fixture
def sample_result(sample_finding: Finding) -> ScanResult:
    """Create a sample scan result."""
    return ScanResult(
        repo_root="/path/to/repo",
        started_at=datetime.now(),
        finished_at=datetime.now(),
        findings=[sample_finding],
        scanners_run=["semgrep"],
        scanners_skipped=[],
        partial=False,
    )


@pytest.fixture
def sample_result_with_multiple_findings() -> ScanResult:
    """Create a sample scan result with multiple findings."""
    findings = [
        Finding(
            scanner="semgrep",
            rule_id="python.security.injection",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            title="SQL Injection",
            message="User input used in SQL query",
            file_path="app/database.py",
            line_start=42,
            triage_status=TriageStatus.ACTIONABLE,
        ),
        Finding(
            scanner="gitleaks",
            rule_id="aws-access-key-id",
            severity=Severity.CRITICAL,
            category=Category.SECRETS,
            title="AWS Access Key",
            message="AWS access key found in code",
            file_path="config.py",
            line_start=10,
            triage_status=TriageStatus.ACTIONABLE,
        ),
        Finding(
            scanner="bandit",
            rule_id="B101",
            severity=Severity.LOW,
            category=Category.SECURITY,
            title="Assert used",
            message="Use of assert detected",
            file_path="tests/test_app.py",
            line_start=5,
            triage_status=TriageStatus.NEEDS_REVIEW,  # Not actionable
        ),
    ]
    return ScanResult(
        repo_root="/path/to/repo",
        started_at=datetime.now(),
        finished_at=datetime.now(),
        findings=findings,
        scanners_run=["semgrep", "gitleaks", "bandit"],
        scanners_skipped=[],
        partial=False,
    )


class TestSaveBaseline:
    """Tests for save_baseline function."""

    def test_save_creates_file(self, temp_repo: Path, sample_result: ScanResult) -> None:
        """Test that save_baseline creates a baseline file."""
        baseline_path = baseline.save_baseline(sample_result, temp_repo)

        assert baseline_path.exists()
        assert baseline_path.parent == temp_repo / ".vibeguard" / "baselines"
        assert baseline_path.name == "default.json"

    def test_save_with_custom_name(self, temp_repo: Path, sample_result: ScanResult) -> None:
        """Test saving baseline with custom name."""
        baseline_path = baseline.save_baseline(sample_result, temp_repo, name="release-1.0")

        assert baseline_path.exists()
        assert baseline_path.name == "release-1.0.json"

    def test_save_creates_directories(self, temp_repo: Path, sample_result: ScanResult) -> None:
        """Test that save_baseline creates directories if needed."""
        baseline_path = baseline.save_baseline(sample_result, temp_repo)

        assert (temp_repo / ".vibeguard" / "baselines").exists()
        assert baseline_path.exists()

    def test_saved_json_is_valid(self, temp_repo: Path, sample_result: ScanResult) -> None:
        """Test that saved file contains valid JSON."""
        baseline_path = baseline.save_baseline(sample_result, temp_repo)
        data = json.loads(baseline_path.read_text(encoding="utf-8"))

        assert "schema_version" in data
        assert "name" in data
        assert "findings" in data
        assert "created_at" in data

    def test_save_overwrites_existing(self, temp_repo: Path, sample_result: ScanResult) -> None:
        """Test that saving baseline overwrites existing."""
        baseline.save_baseline(sample_result, temp_repo)

        # Modify and save again
        sample_result.scanners_run = ["semgrep", "gitleaks"]
        baseline.save_baseline(sample_result, temp_repo)

        loaded = baseline.load_baseline(temp_repo)
        assert loaded is not None
        assert loaded.scanners_used == ["semgrep", "gitleaks"]

    def test_save_stores_only_actionable(
        self, temp_repo: Path, sample_result_with_multiple_findings: ScanResult
    ) -> None:
        """Test that only actionable findings are stored in baseline."""
        baseline.save_baseline(sample_result_with_multiple_findings, temp_repo)
        loaded = baseline.load_baseline(temp_repo)

        assert loaded is not None
        # Should only have 2 actionable findings (not the NEEDS_REVIEW one)
        assert len(loaded.findings) == 2
        assert loaded.actionable_count == 2


class TestLoadBaseline:
    """Tests for load_baseline function."""

    def test_load_returns_baseline(self, temp_repo: Path, sample_result: ScanResult) -> None:
        """Test that load_baseline returns saved baseline."""
        baseline.save_baseline(sample_result, temp_repo)
        loaded = baseline.load_baseline(temp_repo)

        assert loaded is not None
        assert loaded.name == "default"
        assert len(loaded.findings) == 1

    def test_load_with_custom_name(self, temp_repo: Path, sample_result: ScanResult) -> None:
        """Test loading baseline with custom name."""
        baseline.save_baseline(sample_result, temp_repo, name="release-1.0")
        loaded = baseline.load_baseline(temp_repo, name="release-1.0")

        assert loaded is not None
        assert loaded.name == "release-1.0"

    def test_load_returns_none_if_not_found(self, temp_repo: Path) -> None:
        """Test that load_baseline returns None if not found."""
        result = baseline.load_baseline(temp_repo)
        assert result is None

    def test_load_returns_none_for_wrong_name(
        self, temp_repo: Path, sample_result: ScanResult
    ) -> None:
        """Test that load_baseline returns None for wrong name."""
        baseline.save_baseline(sample_result, temp_repo, name="release-1.0")
        result = baseline.load_baseline(temp_repo, name="nonexistent")
        assert result is None

    def test_load_handles_invalid_json(self, temp_repo: Path) -> None:
        """Test that load_baseline handles invalid JSON."""
        baselines_dir = temp_repo / ".vibeguard" / "baselines"
        baselines_dir.mkdir(parents=True)
        (baselines_dir / "default.json").write_text("not valid json")

        result = baseline.load_baseline(temp_repo)
        assert result is None


class TestListBaselines:
    """Tests for list_baselines function."""

    def test_list_returns_empty_if_no_baselines(self, temp_repo: Path) -> None:
        """Test list returns empty if no baselines exist."""
        result = baseline.list_baselines(temp_repo)
        assert result == []

    def test_list_returns_all_baselines(self, temp_repo: Path, sample_result: ScanResult) -> None:
        """Test list returns all baselines."""
        baseline.save_baseline(sample_result, temp_repo, name="baseline-1")
        time.sleep(0.01)
        baseline.save_baseline(sample_result, temp_repo, name="baseline-2")

        baselines = baseline.list_baselines(temp_repo)

        assert len(baselines) == 2
        names = [b.name for b in baselines]
        assert "baseline-1" in names
        assert "baseline-2" in names

    def test_list_sorted_by_date_newest_first(
        self, temp_repo: Path, sample_result: ScanResult
    ) -> None:
        """Test list is sorted with newest first."""
        baseline.save_baseline(sample_result, temp_repo, name="old")
        time.sleep(0.1)
        baseline.save_baseline(sample_result, temp_repo, name="new")

        baselines = baseline.list_baselines(temp_repo)

        assert baselines[0].name == "new"
        assert baselines[1].name == "old"


class TestDeleteBaseline:
    """Tests for delete_baseline function."""

    def test_delete_removes_file(self, temp_repo: Path, sample_result: ScanResult) -> None:
        """Test delete_baseline removes the file."""
        baseline.save_baseline(sample_result, temp_repo)
        assert baseline.load_baseline(temp_repo) is not None

        result = baseline.delete_baseline(temp_repo, "default")

        assert result is True
        assert baseline.load_baseline(temp_repo) is None

    def test_delete_returns_false_if_not_found(self, temp_repo: Path) -> None:
        """Test delete_baseline returns False if not found."""
        result = baseline.delete_baseline(temp_repo, "nonexistent")
        assert result is False

    def test_delete_specific_baseline(self, temp_repo: Path, sample_result: ScanResult) -> None:
        """Test deleting specific baseline leaves others."""
        baseline.save_baseline(sample_result, temp_repo, name="keep")
        baseline.save_baseline(sample_result, temp_repo, name="delete")

        baseline.delete_baseline(temp_repo, "delete")

        baselines = baseline.list_baselines(temp_repo)
        assert len(baselines) == 1
        assert baselines[0].name == "keep"


class TestCompareToBaseline:
    """Tests for compare_to_baseline function."""

    def test_no_changes(self, temp_repo: Path, sample_result: ScanResult) -> None:
        """Test comparison with identical findings."""
        baseline.save_baseline(sample_result, temp_repo)
        loaded = baseline.load_baseline(temp_repo)
        assert loaded is not None

        comparison = baseline.compare_to_baseline(sample_result, loaded)

        assert comparison.baseline_name == "default"
        assert len(comparison.new_findings) == 0
        assert len(comparison.fixed_findings) == 0
        assert comparison.unchanged_count == 1
        assert comparison.has_regressions is False

    def test_detects_new_findings(self, temp_repo: Path) -> None:
        """Test detection of regressions (new findings)."""
        # Create baseline with one finding
        old_finding = Finding(
            scanner="semgrep",
            rule_id="old-rule",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            title="Old Finding",
            message="Old issue",
            file_path="old.py",
            line_start=10,
            triage_status=TriageStatus.ACTIONABLE,
        )
        old_result = ScanResult(
            repo_root="/path/to/repo",
            started_at=datetime.now(),
            finished_at=datetime.now(),
            findings=[old_finding],
            scanners_run=["semgrep"],
            scanners_skipped=[],
            partial=False,
        )
        baseline.save_baseline(old_result, temp_repo)
        loaded = baseline.load_baseline(temp_repo)
        assert loaded is not None

        # New scan has the old finding plus a new one
        new_finding = Finding(
            scanner="gitleaks",
            rule_id="new-rule",
            severity=Severity.CRITICAL,
            category=Category.SECRETS,
            title="New Finding",
            message="New issue",
            file_path="new.py",
            line_start=20,
            triage_status=TriageStatus.ACTIONABLE,
        )
        new_result = ScanResult(
            repo_root="/path/to/repo",
            started_at=datetime.now(),
            finished_at=datetime.now(),
            findings=[old_finding, new_finding],
            scanners_run=["semgrep", "gitleaks"],
            scanners_skipped=[],
            partial=False,
        )

        comparison = baseline.compare_to_baseline(new_result, loaded)

        assert len(comparison.new_findings) == 1
        assert comparison.new_findings[0].title == "New Finding"
        assert comparison.has_regressions is True
        assert comparison.regression_count == 1

    def test_detects_fixed_findings(self, temp_repo: Path) -> None:
        """Test detection of improvements (fixed findings)."""
        # Baseline has two findings
        finding1 = Finding(
            scanner="semgrep",
            rule_id="rule-1",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            title="Finding 1",
            message="Issue 1",
            file_path="file1.py",
            line_start=10,
            triage_status=TriageStatus.ACTIONABLE,
        )
        finding2 = Finding(
            scanner="semgrep",
            rule_id="rule-2",
            severity=Severity.MEDIUM,
            category=Category.SECURITY,
            title="Finding 2",
            message="Issue 2",
            file_path="file2.py",
            line_start=20,
            triage_status=TriageStatus.ACTIONABLE,
        )
        old_result = ScanResult(
            repo_root="/path/to/repo",
            started_at=datetime.now(),
            finished_at=datetime.now(),
            findings=[finding1, finding2],
            scanners_run=["semgrep"],
            scanners_skipped=[],
            partial=False,
        )
        baseline.save_baseline(old_result, temp_repo)
        loaded = baseline.load_baseline(temp_repo)
        assert loaded is not None

        # New scan only has one finding (the other is fixed)
        new_result = ScanResult(
            repo_root="/path/to/repo",
            started_at=datetime.now(),
            finished_at=datetime.now(),
            findings=[finding1],
            scanners_run=["semgrep"],
            scanners_skipped=[],
            partial=False,
        )

        comparison = baseline.compare_to_baseline(new_result, loaded)

        assert len(comparison.fixed_findings) == 1
        assert comparison.fixed_findings[0].title == "Finding 2"
        assert comparison.improvement_count == 1
        assert comparison.has_regressions is False

    def test_mixed_changes(self, temp_repo: Path) -> None:
        """Test with mix of new, fixed, and unchanged findings."""
        # Baseline: A, B
        finding_a = Finding(
            scanner="semgrep",
            rule_id="rule-a",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            title="Finding A",
            message="Issue A",
            file_path="a.py",
            line_start=10,
            triage_status=TriageStatus.ACTIONABLE,
        )
        finding_b = Finding(
            scanner="semgrep",
            rule_id="rule-b",
            severity=Severity.MEDIUM,
            category=Category.SECURITY,
            title="Finding B",
            message="Issue B",
            file_path="b.py",
            line_start=20,
            triage_status=TriageStatus.ACTIONABLE,
        )
        old_result = ScanResult(
            repo_root="/path/to/repo",
            started_at=datetime.now(),
            finished_at=datetime.now(),
            findings=[finding_a, finding_b],
            scanners_run=["semgrep"],
            scanners_skipped=[],
            partial=False,
        )
        baseline.save_baseline(old_result, temp_repo)
        loaded = baseline.load_baseline(temp_repo)
        assert loaded is not None

        # Current: A (unchanged), C (new) - B is fixed
        finding_c = Finding(
            scanner="semgrep",
            rule_id="rule-c",
            severity=Severity.LOW,
            category=Category.SECURITY,
            title="Finding C",
            message="Issue C",
            file_path="c.py",
            line_start=30,
            triage_status=TriageStatus.ACTIONABLE,
        )
        new_result = ScanResult(
            repo_root="/path/to/repo",
            started_at=datetime.now(),
            finished_at=datetime.now(),
            findings=[finding_a, finding_c],
            scanners_run=["semgrep"],
            scanners_skipped=[],
            partial=False,
        )

        comparison = baseline.compare_to_baseline(new_result, loaded)

        assert comparison.unchanged_count == 1  # A
        assert len(comparison.new_findings) == 1  # C
        assert len(comparison.fixed_findings) == 1  # B
        assert comparison.has_regressions is True

    def test_line_shift_not_regression(self, temp_repo: Path) -> None:
        """Test that minor line shifts don't count as regressions.

        Fingerprint buckets lines by LINE_PROXIMITY (5), so a finding
        that moves a few lines should still match.
        """
        # Baseline has finding at line 42
        old_finding = Finding(
            scanner="semgrep",
            rule_id="python.security.injection",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            title="SQL Injection",
            message="Issue",
            file_path="database.py",
            line_start=42,
            triage_status=TriageStatus.ACTIONABLE,
        )
        old_result = ScanResult(
            repo_root="/path/to/repo",
            started_at=datetime.now(),
            finished_at=datetime.now(),
            findings=[old_finding],
            scanners_run=["semgrep"],
            scanners_skipped=[],
            partial=False,
        )
        baseline.save_baseline(old_result, temp_repo)
        loaded = baseline.load_baseline(temp_repo)
        assert loaded is not None

        # New scan has same finding at line 43 (within same bucket: 42//5 = 8, 43//5 = 8)
        new_finding = Finding(
            scanner="semgrep",
            rule_id="python.security.injection",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            title="SQL Injection",
            message="Issue",
            file_path="database.py",
            line_start=43,  # Moved by 1 line
            triage_status=TriageStatus.ACTIONABLE,
        )
        new_result = ScanResult(
            repo_root="/path/to/repo",
            started_at=datetime.now(),
            finished_at=datetime.now(),
            findings=[new_finding],
            scanners_run=["semgrep"],
            scanners_skipped=[],
            partial=False,
        )

        comparison = baseline.compare_to_baseline(new_result, loaded)

        # Should be treated as unchanged (same bucket)
        assert comparison.unchanged_count == 1
        assert len(comparison.new_findings) == 0
        assert len(comparison.fixed_findings) == 0


class TestFindingToBaseline:
    """Tests for _finding_to_baseline function."""

    def test_converts_all_fields(self, sample_finding: Finding) -> None:
        """Test all required fields are converted."""
        bf = baseline._finding_to_baseline(sample_finding)

        assert bf.finding_id == sample_finding.id
        assert bf.scanner == sample_finding.scanner
        assert bf.rule_id == sample_finding.rule_id
        assert bf.severity == sample_finding.severity
        assert bf.file_path == sample_finding.file_path
        assert bf.line_start == sample_finding.line_start
        assert bf.triage_status == sample_finding.triage_status
        assert bf.title == sample_finding.title

    def test_generates_fingerprint(self, sample_finding: Finding) -> None:
        """Test fingerprint is generated."""
        bf = baseline._finding_to_baseline(sample_finding)

        assert bf.fingerprint is not None
        assert len(bf.fingerprint) > 0


class TestComparisonResultProperties:
    """Tests for ComparisonResult model properties."""

    def test_has_regressions_true(self) -> None:
        """Test has_regressions returns True when new findings exist."""
        bf = BaselineFinding(
            fingerprint="test:fingerprint:0",
            finding_id="abc123",
            scanner="semgrep",
            rule_id="test-rule",
            severity=Severity.HIGH,
            file_path="test.py",
            line_start=1,
            title="Test",
        )
        result = ComparisonResult(
            baseline_name="test",
            new_findings=[bf],
            fixed_findings=[],
            unchanged_count=0,
        )

        assert result.has_regressions is True
        assert result.regression_count == 1

    def test_has_regressions_false(self) -> None:
        """Test has_regressions returns False when no new findings."""
        result = ComparisonResult(
            baseline_name="test",
            new_findings=[],
            fixed_findings=[],
            unchanged_count=5,
        )

        assert result.has_regressions is False
        assert result.regression_count == 0

    def test_improvement_count(self) -> None:
        """Test improvement_count property."""
        bf = BaselineFinding(
            fingerprint="test:fingerprint:0",
            finding_id="abc123",
            scanner="semgrep",
            rule_id="test-rule",
            severity=Severity.HIGH,
            file_path="test.py",
            line_start=1,
            title="Test",
        )
        result = ComparisonResult(
            baseline_name="test",
            new_findings=[],
            fixed_findings=[bf, bf],
            unchanged_count=0,
        )

        assert result.improvement_count == 2


class TestHasAnyBaselines:
    """Tests for has_any_baselines function."""

    def test_no_baselines_dir(self, temp_repo: Path) -> None:
        """Returns False when baselines directory does not exist."""
        assert baseline.has_any_baselines(temp_repo) is False

    def test_empty_baselines_dir(self, temp_repo: Path) -> None:
        """Returns False when baselines directory is empty."""
        baselines_dir = temp_repo / ".vibeguard" / "baselines"
        baselines_dir.mkdir(parents=True)
        assert baseline.has_any_baselines(temp_repo) is False

    def test_with_baselines(self, temp_repo: Path, sample_result: ScanResult) -> None:
        """Returns True when baselines exist."""
        baseline.save_baseline(sample_result, temp_repo)
        assert baseline.has_any_baselines(temp_repo) is True

    def test_with_multiple_baselines(self, temp_repo: Path, sample_result: ScanResult) -> None:
        """Returns True when multiple baselines exist."""
        baseline.save_baseline(sample_result, temp_repo, name="one")
        baseline.save_baseline(sample_result, temp_repo, name="two")
        assert baseline.has_any_baselines(temp_repo) is True


class TestFilterComparison:
    """Tests for filter_comparison function."""

    @pytest.fixture
    def comparison_with_mixed_findings(self) -> ComparisonResult:
        """Create a comparison result with mixed severity and scanner findings."""
        new_findings = [
            BaselineFinding(
                fingerprint="new:critical:semgrep:0",
                finding_id="n1",
                scanner="semgrep",
                rule_id="rule-crit",
                severity=Severity.CRITICAL,
                file_path="a.py",
                line_start=1,
                title="Critical from semgrep",
            ),
            BaselineFinding(
                fingerprint="new:high:gitleaks:0",
                finding_id="n2",
                scanner="gitleaks",
                rule_id="rule-high",
                severity=Severity.HIGH,
                file_path="b.py",
                line_start=2,
                title="High from gitleaks",
            ),
            BaselineFinding(
                fingerprint="new:low:semgrep:0",
                finding_id="n3",
                scanner="semgrep",
                rule_id="rule-low",
                severity=Severity.LOW,
                file_path="c.py",
                line_start=3,
                title="Low from semgrep",
            ),
        ]
        fixed_findings = [
            BaselineFinding(
                fingerprint="fix:medium:bandit:0",
                finding_id="f1",
                scanner="bandit",
                rule_id="B101",
                severity=Severity.MEDIUM,
                file_path="d.py",
                line_start=4,
                title="Medium from bandit",
            ),
            BaselineFinding(
                fingerprint="fix:high:semgrep:0",
                finding_id="f2",
                scanner="semgrep",
                rule_id="rule-high-fix",
                severity=Severity.HIGH,
                file_path="e.py",
                line_start=5,
                title="High from semgrep fixed",
            ),
        ]
        return ComparisonResult(
            baseline_name="test",
            new_findings=new_findings,
            fixed_findings=fixed_findings,
            unchanged_count=10,
        )

    def test_no_filter(self, comparison_with_mixed_findings: ComparisonResult) -> None:
        """No filter returns all findings."""
        result = baseline.filter_comparison(comparison_with_mixed_findings)
        assert len(result.new_findings) == 3
        assert len(result.fixed_findings) == 2
        assert result.unchanged_count == 10

    def test_filter_by_min_severity_high(self, comparison_with_mixed_findings: ComparisonResult) -> None:
        """Filter by min_severity=high excludes low and medium."""
        result = baseline.filter_comparison(comparison_with_mixed_findings, min_severity="high")
        assert len(result.new_findings) == 2  # critical + high
        assert len(result.fixed_findings) == 1  # only high
        # Low finding should be excluded
        assert all(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in result.new_findings)

    def test_filter_by_min_severity_critical(self, comparison_with_mixed_findings: ComparisonResult) -> None:
        """Filter by min_severity=critical includes only critical."""
        result = baseline.filter_comparison(comparison_with_mixed_findings, min_severity="critical")
        assert len(result.new_findings) == 1
        assert result.new_findings[0].severity == Severity.CRITICAL
        assert len(result.fixed_findings) == 0

    def test_filter_by_scanner(self, comparison_with_mixed_findings: ComparisonResult) -> None:
        """Filter by scanner name."""
        result = baseline.filter_comparison(comparison_with_mixed_findings, scanner="semgrep")
        assert len(result.new_findings) == 2  # critical + low from semgrep
        assert all(f.scanner == "semgrep" for f in result.new_findings)
        assert len(result.fixed_findings) == 1  # high from semgrep
        assert result.fixed_findings[0].scanner == "semgrep"

    def test_filter_by_scanner_case_insensitive(self, comparison_with_mixed_findings: ComparisonResult) -> None:
        """Scanner filter should be case insensitive."""
        result = baseline.filter_comparison(comparison_with_mixed_findings, scanner="Semgrep")
        assert len(result.new_findings) == 2

    def test_filter_by_scanner_and_severity(self, comparison_with_mixed_findings: ComparisonResult) -> None:
        """Filter by both scanner and min_severity."""
        result = baseline.filter_comparison(
            comparison_with_mixed_findings,
            min_severity="high",
            scanner="semgrep",
        )
        assert len(result.new_findings) == 1  # only critical from semgrep
        assert result.new_findings[0].severity == Severity.CRITICAL
        assert len(result.fixed_findings) == 1  # high from semgrep

    def test_filter_preserves_baseline_name(self, comparison_with_mixed_findings: ComparisonResult) -> None:
        """Filtered result should preserve baseline name."""
        result = baseline.filter_comparison(comparison_with_mixed_findings, min_severity="critical")
        assert result.baseline_name == "test"

    def test_filter_preserves_unchanged_count(self, comparison_with_mixed_findings: ComparisonResult) -> None:
        """Filtered result should preserve unchanged count."""
        result = baseline.filter_comparison(comparison_with_mixed_findings, min_severity="critical")
        assert result.unchanged_count == 10

    def test_filter_no_match(self, comparison_with_mixed_findings: ComparisonResult) -> None:
        """Filter that matches nothing returns empty lists."""
        result = baseline.filter_comparison(comparison_with_mixed_findings, scanner="nonexistent")
        assert len(result.new_findings) == 0
        assert len(result.fixed_findings) == 0
