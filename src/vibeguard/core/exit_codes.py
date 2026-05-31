"""Exit codes for CI integration.

These exit codes allow scripts and CI systems to distinguish between
different outcomes without parsing output.
"""

from enum import IntEnum


class ExitCode(IntEnum):
    """VibeGuard CLI exit codes."""

    SUCCESS = 0  # Scan completed, no findings
    FINDINGS = 1  # Scan completed, findings detected
    SCAN_ERROR = 2  # Scanner failed / partial scan
    NO_CACHE = 3  # Report command: no cached scan found
    CONFIG_ERROR = 4  # Invalid configuration
    INVALID_PATH = 5  # Target path does not exist
    THRESHOLD_EXCEEDED = 10  # Score below --threshold
