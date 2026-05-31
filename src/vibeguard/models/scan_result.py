"""ScanResult model for complete scan results."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, computed_field

from vibeguard.models.finding import Category, Finding, Severity
from vibeguard.models.triage import TriageStatus

# Scoring constants
SEVERITY_DEDUCTIONS = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}
CATEGORY_CAP = 50  # Max deduction per category


class SeverityCounts(BaseModel):
    """Count of findings by severity."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanResult(BaseModel):
    """Complete result of a security scan."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="ignore",  # Allow extra fields for deserialization of cached data
    )

    repo_root: str = Field(..., description="Root path that was scanned")
    started_at: datetime = Field(..., description="Scan start time")
    finished_at: datetime | None = Field(None, description="Scan end time")
    findings: list[Finding] = Field(default_factory=list)
    scanners_run: list[str] = Field(default_factory=list)
    scanners_skipped: list[str] = Field(default_factory=list)
    partial: bool = Field(default=False, description="True if any scanner failed")

    def _calculate_score(self, findings_list: list[Finding]) -> int:
        """Calculate score from a list of findings.

        Scoring algorithm v2:
        - Base: 100
        - Deductions per severity: Critical -20, High -10, Medium -5, Low -2
        - Cap: Max 50 points deducted per category
        """
        base = 100

        # Group deductions by category
        by_category: dict[Category, int] = {}
        for finding in findings_list:
            penalty = SEVERITY_DEDUCTIONS.get(finding.severity, 0)
            by_category[finding.category] = by_category.get(finding.category, 0) + penalty

        # Apply cap per category
        total_deduction = sum(min(v, CATEGORY_CAP) for v in by_category.values())
        return max(0, base - total_deduction)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def actionable_findings(self) -> list[Finding]:
        """Findings that are actionable (need fixing)."""
        return [
            f for f in self.findings
            if f.triage_status == TriageStatus.ACTIONABLE
        ]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def needs_review_findings(self) -> list[Finding]:
        """Findings that need human review."""
        return [
            f for f in self.findings
            if f.triage_status == TriageStatus.NEEDS_REVIEW
        ]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ignored_findings(self) -> list[Finding]:
        """Findings that were auto-ignored."""
        return [
            f for f in self.findings
            if f.triage_status == TriageStatus.IGNORED
        ]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def actionable_score(self) -> int:
        """Score based on actionable findings only (drives grade)."""
        return self._calculate_score(self.actionable_findings)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def raw_score(self) -> int:
        """Score based on all findings (for transparency)."""
        return self._calculate_score(self.findings)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def noise_ratio(self) -> float:
        """Ratio of ignored findings to total findings.

        A high noise ratio indicates effective filtering of false positives.
        """
        total = len(self.findings)
        if total == 0:
            return 0.0
        return len(self.ignored_findings) / total

    @computed_field  # type: ignore[prop-decorator]
    @property
    def counts(self) -> SeverityCounts:
        """Calculate counts by severity (actionable findings only)."""
        counts = SeverityCounts()
        for finding in self.actionable_findings:
            match finding.severity:
                case Severity.CRITICAL:
                    counts.critical += 1
                case Severity.HIGH:
                    counts.high += 1
                case Severity.MEDIUM:
                    counts.medium += 1
                case Severity.LOW:
                    counts.low += 1
                case Severity.INFO:
                    counts.info += 1
        return counts

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total_counts(self) -> SeverityCounts:
        """Calculate counts by severity (all findings, for transparency)."""
        counts = SeverityCounts()
        for finding in self.findings:
            match finding.severity:
                case Severity.CRITICAL:
                    counts.critical += 1
                case Severity.HIGH:
                    counts.high += 1
                case Severity.MEDIUM:
                    counts.medium += 1
                case Severity.LOW:
                    counts.low += 1
                case Severity.INFO:
                    counts.info += 1
        return counts

    @computed_field  # type: ignore[prop-decorator]
    @property
    def score(self) -> int:
        """Primary score (based on actionable findings).

        This is the main score shown in reports and used for CI pass/fail.
        """
        return self.actionable_score

    @computed_field  # type: ignore[prop-decorator]
    @property
    def grade(self) -> str:
        """Calculate letter grade based on actionable score.

        Grade bands:
        - A+ >= 95
        - A >= 85
        - B >= 70
        - C >= 50
        - D >= 30
        - F < 30
        """
        s = self.score
        if s >= 95:
            return "A+"
        elif s >= 85:
            return "A"
        elif s >= 70:
            return "B"
        elif s >= 50:
            return "C"
        elif s >= 30:
            return "D"
        else:
            return "F"
