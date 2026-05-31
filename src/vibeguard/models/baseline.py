"""Baseline models for regression checking."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from vibeguard.models.finding import Severity
from vibeguard.models.triage import TriageStatus


class BaselineFinding(BaseModel):
    """Minimal finding data stored in baseline.

    Stores just enough information to:
    1. Match against future scans (fingerprint)
    2. Display meaningful comparison info (title, severity, location)
    """

    model_config = ConfigDict(extra="ignore")

    fingerprint: str = Field(..., description="Normalized fingerprint for matching")
    finding_id: str = Field(..., description="Original finding ID for reference")
    scanner: str = Field(..., description="Scanner that found this issue")
    rule_id: str = Field(..., description="Original rule ID from scanner")
    severity: Severity = Field(..., description="Severity at baseline time")
    file_path: str = Field(..., description="Path to affected file")
    line_start: int = Field(..., description="Starting line number")
    triage_status: TriageStatus = Field(
        default=TriageStatus.ACTIONABLE,
        description="Triage status at baseline time",
    )
    title: str = Field(..., description="Short title for display")


class Baseline(BaseModel):
    """Stored baseline of security findings.

    A baseline captures the security state at a point in time,
    allowing future scans to detect regressions (new issues)
    and improvements (fixed issues).
    """

    model_config = ConfigDict(extra="ignore")

    schema_version: int = Field(default=1, description="Schema version for migrations")
    name: str = Field(..., description="Baseline name (e.g., 'default', 'release-1.0')")
    created_at: datetime = Field(
        default_factory=datetime.now,
        description="When baseline was created",
    )
    vibeguard_version: str = Field(..., description="VibeGuard version used")
    repo_root: str = Field(..., description="Repository root at baseline time")
    findings: list[BaselineFinding] = Field(
        default_factory=list,
        description="All actionable findings in baseline",
    )

    # Metadata for display
    total_count: int = Field(default=0, description="Total findings before triage")
    actionable_count: int = Field(default=0, description="Actionable findings count")
    scanners_used: list[str] = Field(
        default_factory=list,
        description="Scanners that ran during baseline scan",
    )


class ComparisonResult(BaseModel):
    """Result of comparing a scan against a baseline.

    Categorizes findings into:
    - new_findings: Regressions (in current scan, not in baseline)
    - fixed_findings: Improvements (in baseline, not in current scan)
    - unchanged_count: Still present in both
    """

    model_config = ConfigDict(extra="ignore")

    baseline_name: str = Field(..., description="Name of baseline compared against")
    new_findings: list[BaselineFinding] = Field(
        default_factory=list,
        description="Regressions: findings in current scan but not baseline",
    )
    fixed_findings: list[BaselineFinding] = Field(
        default_factory=list,
        description="Improvements: findings in baseline but not current scan",
    )
    unchanged_count: int = Field(
        default=0,
        description="Count of findings present in both",
    )

    @property
    def has_regressions(self) -> bool:
        """True if new findings (regressions) were detected."""
        return len(self.new_findings) > 0

    @property
    def regression_count(self) -> int:
        """Number of new findings (regressions)."""
        return len(self.new_findings)

    @property
    def improvement_count(self) -> int:
        """Number of fixed findings (improvements)."""
        return len(self.fixed_findings)
