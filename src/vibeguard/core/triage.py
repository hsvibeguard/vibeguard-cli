"""Triage engine for classifying findings.

Applies deterministic triage rules to classify findings as actionable,
needs review, or ignored. All rules are deterministic for CI reproducibility.
"""

from pathlib import Path

from vibeguard.core.example_detector import is_example_secret
from vibeguard.core.ignore import get_effective_patterns, should_ignore
from vibeguard.core.path_classifier import classify_path
from vibeguard.models.finding import Category, Finding
from vibeguard.models.triage import PathClass, TriageReason, TriageStatus


class TriageEngine:
    """Deterministic triage engine for classifying findings.

    Applies a set of rules in priority order to classify each finding.
    The engine is stateless and produces consistent results for the same input.
    """

    def __init__(
        self,
        repo_root: Path,
        user_patterns: list[str] | None = None,
        use_default_ignores: bool = True,
        bypass_path_class: bool = False,
    ):
        """Initialize the triage engine.

        Args:
            repo_root: Root directory of the repository being scanned
            user_patterns: User-specified ignore patterns from .vibeguardignore
            use_default_ignores: Whether to apply built-in default ignore patterns
            bypass_path_class: If True, don't auto-ignore based on path classification
                (VCS, GENERATED, TEMP, THIRD_PARTY). Use this when the user explicitly
                wants to scan those directories.
        """
        self.repo_root = repo_root
        self.bypass_path_class = bypass_path_class
        self.patterns = get_effective_patterns(
            user_patterns=user_patterns,
            use_defaults=use_default_ignores,
        )

    def triage_finding(self, finding: Finding) -> Finding:
        """Apply triage rules to a single finding.

        Rules are applied in priority order (first match wins):
        1. VCS objects (.git/objects, etc.) → IGNORED (unless bypass_path_class)
        2. Generated/cache files → IGNORED (unless bypass_path_class)
        3. Temp files → IGNORED (unless bypass_path_class)
        4. Third-party code → IGNORED (unless bypass_path_class)
        5. Test fixtures (secrets only) → IGNORED (unless bypass_path_class)
        6. Example/placeholder secrets → IGNORED
        7. User ignore patterns → IGNORED
        8. Test files (non-secrets) → NEEDS_REVIEW (unless bypass_path_class)
        9. Everything else → ACTIONABLE

        Args:
            finding: The finding to triage

        Returns:
            New Finding with triage fields set (original is not modified)
        """
        # Classify the path
        path_class = classify_path(finding.file_path)

        # Apply rules in priority order
        status = TriageStatus.ACTIONABLE
        reason = TriageReason.NONE

        # Path-class-based rules (can be bypassed with bypass_path_class flag)
        if not self.bypass_path_class:
            # Rule 1: VCS objects
            if path_class == PathClass.VCS:
                status = TriageStatus.IGNORED
                reason = TriageReason.VCS_OBJECT

            # Rule 2: Generated/cache files
            elif path_class == PathClass.GENERATED:
                status = TriageStatus.IGNORED
                reason = TriageReason.GENERATED_CACHE

            # Rule 3: Temp files
            elif path_class == PathClass.TEMP:
                status = TriageStatus.IGNORED
                reason = TriageReason.TEMP_FILE

            # Rule 4: Third-party code
            elif path_class == PathClass.THIRD_PARTY:
                status = TriageStatus.IGNORED
                reason = TriageReason.THIRD_PARTY

            # Rule 5: Test fixtures (for secrets category only)
            # Secrets in test files are almost always intentional test data
            elif path_class == PathClass.TESTS and finding.category == Category.SECRETS:
                status = TriageStatus.IGNORED
                reason = TriageReason.TEST_FIXTURE

        # Continue with non-path-class rules if not already classified
        if status == TriageStatus.ACTIONABLE:
            # Rule 6: Example/placeholder secrets
            if is_example_secret(finding):
                status = TriageStatus.IGNORED
                reason = TriageReason.EXAMPLE_SECRET

            # Rule 7: User ignore patterns
            elif should_ignore(finding.file_path, self.patterns, self.repo_root):
                status = TriageStatus.IGNORED
                reason = TriageReason.USER_IGNORE

            # Rule 8: Test files (non-secrets) need review (unless bypassed)
            # Code vulnerabilities in tests might indicate bad patterns being tested
            elif not self.bypass_path_class and path_class == PathClass.TESTS:
                status = TriageStatus.NEEDS_REVIEW
                reason = TriageReason.TEST_FIXTURE

            # Rule 9: Everything else is actionable
            # (status and reason already set to defaults)

        # Create new finding with triage fields set
        return finding.model_copy(
            update={
                "triage_status": status,
                "triage_reason": reason,
                "path_class": path_class,
            }
        )

    def triage_findings(self, findings: list[Finding]) -> list[Finding]:
        """Apply triage to all findings.

        Args:
            findings: List of findings to triage

        Returns:
            List of findings with triage fields set
        """
        return [self.triage_finding(f) for f in findings]


def quick_triage(findings: list[Finding], repo_root: Path) -> list[Finding]:
    """Convenience function for quick triage with default settings.

    Args:
        findings: List of findings to triage
        repo_root: Root directory of the repository

    Returns:
        List of triaged findings
    """
    engine = TriageEngine(repo_root=repo_root)
    return engine.triage_findings(findings)


def get_triage_summary(findings: list[Finding]) -> dict[str, int]:
    """Get summary counts by triage status.

    Args:
        findings: List of triaged findings

    Returns:
        Dictionary with counts for each triage status
    """
    summary: dict[str, int] = {
        "actionable": 0,
        "needs_review": 0,
        "ignored": 0,
        "accepted": 0,
        "total": len(findings),
    }

    for finding in findings:
        match finding.triage_status:
            case TriageStatus.ACTIONABLE:
                summary["actionable"] += 1
            case TriageStatus.NEEDS_REVIEW:
                summary["needs_review"] += 1
            case TriageStatus.IGNORED:
                summary["ignored"] += 1
            case TriageStatus.ACCEPTED_RISK:
                summary["accepted"] += 1

    return summary


def get_ignored_by_reason(findings: list[Finding]) -> dict[str, int]:
    """Get breakdown of ignored findings by reason.

    Args:
        findings: List of triaged findings

    Returns:
        Dictionary with counts for each triage reason (ignored only)
    """
    breakdown: dict[str, int] = {}

    for finding in findings:
        if finding.triage_status == TriageStatus.IGNORED:
            reason_key = finding.triage_reason.value
            breakdown[reason_key] = breakdown.get(reason_key, 0) + 1

    return breakdown
