"""Baseline storage and comparison logic for regression checking."""

import json
from pathlib import Path

from pydantic import ValidationError

from vibeguard import __version__
from vibeguard.core.dedup import _normalize_fingerprint
from vibeguard.models.baseline import Baseline, BaselineFinding, ComparisonResult
from vibeguard.models.finding import Finding
from vibeguard.models.scan_result import ScanResult

BASELINE_DIR = ".vibeguard/baselines"
BASELINE_SCHEMA_VERSION = 1


def get_baselines_dir(repo_root: Path) -> Path:
    """Get the baselines directory path.

    Args:
        repo_root: Repository root path

    Returns:
        Path to baselines directory
    """
    return repo_root / BASELINE_DIR


def _finding_to_baseline(finding: Finding) -> BaselineFinding:
    """Convert a Finding to a BaselineFinding for storage.

    Args:
        finding: Full finding from scan result

    Returns:
        Minimal baseline finding for storage
    """
    return BaselineFinding(
        fingerprint=_normalize_fingerprint(finding),
        finding_id=finding.id,
        scanner=finding.scanner,
        rule_id=finding.rule_id,
        severity=finding.severity,
        file_path=finding.file_path,
        line_start=finding.line_start,
        triage_status=finding.triage_status,
        title=finding.title,
    )


def save_baseline(
    result: ScanResult,
    repo_root: Path,
    name: str = "default",
) -> Path:
    """Save current scan result as a baseline.

    Saves only actionable findings to the baseline file.
    Future scans can compare against this to detect regressions.

    Args:
        result: Scan result to save as baseline
        repo_root: Repository root path
        name: Baseline name (default: "default")

    Returns:
        Path to saved baseline file
    """
    baselines_dir = get_baselines_dir(repo_root)
    baselines_dir.mkdir(parents=True, exist_ok=True)

    # Convert actionable findings to baseline findings
    baseline_findings = [
        _finding_to_baseline(f) for f in result.actionable_findings
    ]

    baseline = Baseline(
        schema_version=BASELINE_SCHEMA_VERSION,
        name=name,
        vibeguard_version=__version__,
        repo_root=str(repo_root),
        findings=baseline_findings,
        total_count=len(result.findings),
        actionable_count=len(result.actionable_findings),
        scanners_used=result.scanners_run,
    )

    baseline_path = baselines_dir / f"{name}.json"
    baseline_path.write_text(baseline.model_dump_json(indent=2), encoding="utf-8")

    return baseline_path


def load_baseline(repo_root: Path, name: str = "default") -> Baseline | None:
    """Load a baseline by name.

    Args:
        repo_root: Repository root path
        name: Baseline name to load

    Returns:
        Baseline if found, None otherwise
    """
    baseline_path = get_baselines_dir(repo_root) / f"{name}.json"

    if not baseline_path.exists():
        return None

    try:
        data = json.loads(baseline_path.read_text(encoding="utf-8"))
        return Baseline.model_validate(data)
    except (json.JSONDecodeError, ValidationError):
        return None


def list_baselines(repo_root: Path) -> list[Baseline]:
    """List all saved baselines.

    Args:
        repo_root: Repository root path

    Returns:
        List of baselines sorted by creation date (newest first)
    """
    baselines_dir = get_baselines_dir(repo_root)

    if not baselines_dir.exists():
        return []

    baselines = []
    for path in baselines_dir.glob("*.json"):
        baseline = load_baseline(repo_root, path.stem)
        if baseline:
            baselines.append(baseline)

    return sorted(baselines, key=lambda b: b.created_at, reverse=True)


def has_any_baselines(repo_root: Path) -> bool:
    """Check if any baselines exist.

    Args:
        repo_root: Repository root path

    Returns:
        True if at least one baseline exists
    """
    baselines_dir = get_baselines_dir(repo_root)
    if not baselines_dir.exists():
        return False
    return any(baselines_dir.glob("*.json"))


def delete_baseline(repo_root: Path, name: str) -> bool:
    """Delete a baseline by name.

    Args:
        repo_root: Repository root path
        name: Baseline name to delete

    Returns:
        True if deleted, False if not found
    """
    baseline_path = get_baselines_dir(repo_root) / f"{name}.json"

    if not baseline_path.exists():
        return False

    baseline_path.unlink()
    return True


def compare_to_baseline(
    result: ScanResult,
    baseline: Baseline,
) -> ComparisonResult:
    """Compare scan result against a baseline.

    Uses normalized fingerprints for matching, which:
    - Groups by file path, rule pattern, and line bucket
    - Handles minor line shifts (within 5 lines)
    - Handles cross-scanner rule equivalence

    Categorizes findings into:
    - New (regressions): fingerprint in current but not baseline
    - Fixed (improvements): fingerprint in baseline but not current
    - Unchanged: fingerprint in both

    Args:
        result: Current scan result
        baseline: Baseline to compare against

    Returns:
        ComparisonResult with categorized findings
    """
    # Build fingerprint lookup for baseline
    baseline_fps: dict[str, BaselineFinding] = {
        f.fingerprint: f for f in baseline.findings
    }

    # Convert current findings to baseline format
    current_findings = [
        _finding_to_baseline(f) for f in result.actionable_findings
    ]
    current_fps: dict[str, BaselineFinding] = {
        f.fingerprint: f for f in current_findings
    }

    # Find new findings (regressions) - in current but not baseline
    new_fps = set(current_fps.keys()) - set(baseline_fps.keys())
    new_findings = [current_fps[fp] for fp in sorted(new_fps)]

    # Find fixed findings (improvements) - in baseline but not current
    fixed_fps = set(baseline_fps.keys()) - set(current_fps.keys())
    fixed_findings = [baseline_fps[fp] for fp in sorted(fixed_fps)]

    # Count unchanged - in both
    unchanged_fps = set(baseline_fps.keys()) & set(current_fps.keys())
    unchanged_count = len(unchanged_fps)

    return ComparisonResult(
        baseline_name=baseline.name,
        new_findings=new_findings,
        fixed_findings=fixed_findings,
        unchanged_count=unchanged_count,
    )


# Severity ordering for filter comparisons
_SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def filter_comparison(
    result: ComparisonResult,
    min_severity: str | None = None,
    scanner: str | None = None,
) -> ComparisonResult:
    """Filter comparison results by severity or scanner.

    Args:
        result: Comparison result to filter
        min_severity: Minimum severity level (critical, high, medium, low)
        scanner: Filter by scanner name

    Returns:
        New ComparisonResult with filtered findings lists
    """
    def _matches(finding: BaselineFinding) -> bool:
        if min_severity:
            threshold = _SEVERITY_ORDER.get(min_severity.lower(), 0)
            finding_level = _SEVERITY_ORDER.get(finding.severity.value.lower(), 0)
            if finding_level < threshold:
                return False
        if scanner and finding.scanner.lower() != scanner.lower():
            return False
        return True

    new_findings = [f for f in result.new_findings if _matches(f)]
    fixed_findings = [f for f in result.fixed_findings if _matches(f)]

    return ComparisonResult(
        baseline_name=result.baseline_name,
        new_findings=new_findings,
        fixed_findings=fixed_findings,
        unchanged_count=result.unchanged_count,
    )
