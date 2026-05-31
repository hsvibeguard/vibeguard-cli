"""Triage models for classifying findings.

Provides deterministic classification of findings into actionable vs. noise
categories, with detailed reasons for triage decisions.
"""

from enum import StrEnum


class TriageStatus(StrEnum):
    """Status of a finding after triage.

    Determines whether a finding is actionable, needs review, or can be ignored.
    """

    ACTIONABLE = "actionable"  # Real issue that needs fixing
    NEEDS_REVIEW = "needs_review"  # Ambiguous, requires human review
    IGNORED = "ignored"  # Auto-ignored by deterministic rules
    ACCEPTED_RISK = "accepted"  # Reviewed and accepted as low risk


class TriageReason(StrEnum):
    """Reason for triage classification.

    Explains why a finding was marked with a particular triage status.
    """

    NONE = "none"  # Default for actionable findings
    VCS_OBJECT = "vcs_object"  # .git/objects, .hg/, .svn/
    GENERATED_CACHE = "generated_cache"  # .mypy_cache, __pycache__, node_modules
    TEST_FIXTURE = "test_fixture"  # tests/, *_test.py, intentional test vulns
    EXAMPLE_SECRET = "example_secret"  # AKIAIOSFODNN7EXAMPLE, placeholder keys
    TEMP_FILE = "temp_file"  # /tmp/, .temp/, scratch directories
    THIRD_PARTY = "third_party"  # vendor/, external/, third_party/
    LOW_CONFIDENCE = "low_confidence"  # Scanner reported low confidence
    BASELINE_MATCH = "baseline_match"  # Already in baseline file
    USER_IGNORE = "user_ignore"  # Matched .vibeguardignore pattern


class PathClass(StrEnum):
    """Classification of file paths.

    Used to determine how findings in different path types should be triaged.
    """

    SOURCE = "source"  # Main source code
    TESTS = "tests"  # Test directories and files
    DOCS = "docs"  # Documentation
    GENERATED = "generated"  # Cache, build output, IDE files
    VCS = "vcs"  # Version control directories
    TEMP = "temp"  # Temporary files and directories
    THIRD_PARTY = "third_party"  # Vendored/external dependencies
    CONFIG = "config"  # Configuration files
