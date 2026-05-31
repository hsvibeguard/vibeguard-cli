"""Horusec output parser."""

import json
from typing import Any

from vibeguard.models.finding import Category, Finding, Severity

SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}


def parse_output(raw_output: str) -> list[Finding]:
    """Parse Horusec JSON output into normalized Findings."""
    if not raw_output or raw_output.strip() == "":
        return []

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid Horusec JSON output: {e}") from e

    analysis_vulns = data.get("analysisVulnerabilities", [])
    if not analysis_vulns:
        return []

    findings: list[Finding] = []
    for entry in analysis_vulns:
        finding = _parse_vulnerability(entry)
        if finding:
            findings.append(finding)

    return findings


def _parse_vulnerability(entry: dict[str, Any]) -> Finding | None:
    """Parse a single Horusec vulnerability entry into a Finding."""
    try:
        vuln = entry.get("vulnerabilities", {})
        if not vuln:
            return None

        severity_str = vuln.get("severity", "MEDIUM").upper()
        severity = SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        vuln_hash = vuln.get("vulnHash", "")
        details = vuln.get("details", "Security issue detected by Horusec")
        file_path = vuln.get("file", "")
        line = int(vuln.get("line", "1"))
        code = vuln.get("code", "")

        return Finding(
            scanner="horusec",
            rule_id=vuln_hash[:32] if vuln_hash else "unknown",
            severity=severity,
            category=Category.SECURITY,
            title=f"Horusec: {details[:80]}",
            message=details,
            file_path=file_path,
            line_start=max(line, 1),
            code_snippet=code if code else None,
            fingerprint=vuln_hash if vuln_hash else None,
        )
    except Exception:
        return None
