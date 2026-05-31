"""Grype output parser."""

import json
from typing import Any

from vibeguard.models.finding import Category, Finding, Severity

SEVERITY_MAP: dict[str, Severity] = {
    "Critical": Severity.CRITICAL,
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Negligible": Severity.INFO,
}


def parse_output(raw_output: str) -> list[Finding]:
    """Parse Grype JSON output into normalized Findings."""
    if not raw_output or raw_output.strip() == "":
        return []

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid Grype JSON output: {e}") from e

    matches = data.get("matches", [])
    if not matches:
        return []

    findings: list[Finding] = []
    for match in matches:
        finding = _parse_match(match)
        if finding:
            findings.append(finding)

    return findings


def _parse_match(match: dict[str, Any]) -> Finding | None:
    """Parse a single Grype match into a Finding."""
    try:
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        vuln_id = vuln.get("id", "unknown")
        severity_str = vuln.get("severity", "Medium")
        severity = SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        pkg_name = artifact.get("name", "unknown")
        pkg_version = artifact.get("version", "unknown")
        description = vuln.get("description", "")

        # Build message with fix info if available
        fix_data = vuln.get("fix", {})
        fix_versions = fix_data.get("versions", []) if fix_data else []
        message = f"Vulnerability {vuln_id} in {pkg_name}@{pkg_version}"
        if description:
            message += f": {description}"
        if fix_versions:
            message += f" (fix available: {', '.join(fix_versions)})"

        return Finding(
            scanner="grype",
            rule_id=vuln_id,
            severity=severity,
            category=Category.VULNERABILITY,
            title=f"{vuln_id}: {pkg_name}@{pkg_version}",
            message=message,
            file_path=pkg_name,
            line_start=1,
            fingerprint=f"{vuln_id}:{pkg_name}:{pkg_version}",
        )
    except Exception:
        return None
