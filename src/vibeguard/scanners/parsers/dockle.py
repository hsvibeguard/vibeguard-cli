"""Dockle output parser for container image security scanning."""

import json
from typing import Any

from vibeguard.models.finding import Category, Finding, Severity

# Dockle level mapping to VibeGuard severity
# Levels: FATAL, WARN, INFO, SKIP, PASS
LEVEL_MAP: dict[str, Severity] = {
    "FATAL": Severity.CRITICAL,
    "WARN": Severity.HIGH,
    "INFO": Severity.MEDIUM,
}

# CIS Docker Benchmark check IDs for categorization
# https://www.cisecurity.org/benchmark/docker
CIS_CHECKS = {
    # Container runtime
    "CIS-DI-0001": "Create a user for the container",
    "CIS-DI-0002": "Use trusted base images",
    "CIS-DI-0003": "Do not install unnecessary packages",
    "CIS-DI-0005": "Enable Content Trust for Docker",
    "CIS-DI-0006": "Add HEALTHCHECK instruction",
    "CIS-DI-0007": "Do not use update instructions alone",
    "CIS-DI-0008": "Remove setuid and setgid permissions",
    "CIS-DI-0009": "Use COPY instead of ADD",
    "CIS-DI-0010": "Do not store secrets in ENVA",
    "CIS-DI-0011": "Verify Docker images with signatures",
    # Dockle-specific checks
    "DKL-DI-0001": "Avoid 'sudo' command",
    "DKL-DI-0002": "Avoid sensitive directory",
    "DKL-DI-0003": "Avoid apt-get dist-upgrade",
    "DKL-DI-0004": "Use apk add --no-cache",
    "DKL-DI-0005": "Clear apt-get cache",
    "DKL-DI-0006": "Avoid latest tag",
    "DKL-LI-0001": "Avoid empty password",
    "DKL-LI-0002": "Check duplicate groups",
    "DKL-LI-0003": "Check duplicate users",
}


def parse_output(raw_output: str) -> list[Finding]:
    """Parse Dockle JSON output into normalized Findings.

    Dockle outputs JSON with structure:
    {
        "summary": {
            "fatal": 0,
            "warn": 2,
            "info": 3,
            "skip": 0,
            "pass": 10
        },
        "details": [
            {
                "code": "CIS-DI-0001",
                "title": "Create a user for the container",
                "level": "WARN",
                "alerts": ["Last user should not be root"]
            }
        ]
    }

    Args:
        raw_output: Raw JSON output from Dockle

    Returns:
        List of Finding objects for failed checks

    Raises:
        ValueError: If output cannot be parsed
    """
    if not raw_output or raw_output.strip() == "":
        return []

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid Dockle JSON output: {e}") from e

    findings: list[Finding] = []

    # Extract details array
    details = data.get("details", [])
    if not isinstance(details, list):
        return []

    for detail in details:
        finding = _parse_detail(detail)
        if finding:
            findings.append(finding)

    return findings


def _parse_detail(detail: dict[str, Any]) -> Finding | None:
    """Parse a single Dockle detail into a Finding.

    Args:
        detail: A detail dict from Dockle output

    Returns:
        Finding object or None if level is PASS/SKIP
    """
    try:
        level = detail.get("level", "").upper()

        # Skip PASS and SKIP levels - these are not findings
        if level in ("PASS", "SKIP", ""):
            return None

        severity = LEVEL_MAP.get(level, Severity.MEDIUM)

        code = detail.get("code", "UNKNOWN")
        title = detail.get("title", "Container security check")

        # Build message from alerts
        alerts = detail.get("alerts", [])
        if isinstance(alerts, list) and alerts:
            message = f"{title}\n\nAlerts:\n" + "\n".join(f"- {alert}" for alert in alerts)
        else:
            message = title

        # Determine category based on check type
        category = _determine_category(code)

        # Build references
        references: list[str] = []
        # Add CIS benchmark reference for CIS checks
        if code.startswith("CIS-"):
            references.append("https://www.cisecurity.org/benchmark/docker")
        # Add Dockle documentation for all checks
        references.append("https://github.com/goodwithtech/dockle#checkpoints")

        # Dockle scans images, not files - use "Dockerfile" as placeholder
        # The actual file doesn't exist in the scanned context
        file_path = "Dockerfile"

        # Build fingerprint
        fingerprint = f"dockle:{code}"

        return Finding(
            scanner="dockle",
            rule_id=code,
            severity=severity,
            category=category,
            title=f"[{code}] {title}",
            message=message,
            file_path=file_path,
            line_start=1,  # Dockle doesn't provide line numbers
            line_end=None,
            cwe=None,  # Dockle doesn't provide CWE mappings
            references=references,
            code_snippet=None,
            fingerprint=fingerprint,
        )
    except Exception:
        # Skip malformed detail entries
        return None


def _determine_category(code: str) -> Category:
    """Determine finding category from check code.

    Args:
        code: Check code like "CIS-DI-0001" or "DKL-DI-0001"

    Returns:
        Category enum value
    """
    # Security-critical checks
    security_checks = {
        "CIS-DI-0001",  # Run as non-root user
        "CIS-DI-0010",  # No secrets in ENV
        "DKL-DI-0001",  # Avoid sudo
        "DKL-DI-0002",  # Avoid sensitive directories
        "DKL-LI-0001",  # Avoid empty password
    }

    if code in security_checks:
        return Category.SECURITY

    # Default to BEST_PRACTICE for container checks
    return Category.BEST_PRACTICE
