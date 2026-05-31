"""Gosec output parser."""

import json
from typing import Any

from vibeguard.models.finding import Category, Finding, Severity

SEVERITY_MAP: dict[str, Severity] = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def parse_output(raw_output: str) -> list[Finding]:
    """Parse Gosec JSON output into normalized Findings."""
    if not raw_output or raw_output.strip() == "":
        return []

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid Gosec JSON output: {e}") from e

    issues = data.get("Issues", [])
    if not issues:
        return []

    findings: list[Finding] = []
    for issue in issues:
        finding = _parse_issue(issue)
        if finding:
            findings.append(finding)

    return findings


def _parse_issue(issue: dict[str, Any]) -> Finding | None:
    """Parse a single Gosec issue into a Finding."""
    try:
        severity_str = issue.get("severity", "MEDIUM").upper()
        severity = SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        rule_id = issue.get("rule_id", "unknown")
        file_path = issue.get("file", "")
        line = int(issue.get("line", "1"))

        # Extract CWE if available
        cwe = None
        cwe_data = issue.get("cwe", {})
        if cwe_data and isinstance(cwe_data, dict):
            cwe_id = cwe_data.get("id")
            if cwe_id:
                cwe = f"CWE-{cwe_id}"

        return Finding(
            scanner="gosec",
            rule_id=rule_id,
            severity=severity,
            category=Category.SECURITY,
            title=f"Gosec {rule_id}: {issue.get('details', 'Security issue')}",
            message=issue.get("details", "Security issue detected by Gosec"),
            file_path=file_path,
            line_start=line,
            cwe=cwe,
            code_snippet=issue.get("code"),
            fingerprint=f"{rule_id}:{file_path}:{line}",
        )
    except Exception:
        return None
