"""Bandit output parser."""

import json
from typing import Any

from vibeguard.models.finding import Category, Finding, Severity

# Bandit severity + confidence mapping
# HIGH severity + HIGH confidence = CRITICAL
# Otherwise use the severity directly
SEVERITY_MAP: dict[str, Severity] = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def parse_output(raw_output: str) -> list[Finding]:
    """Parse Bandit JSON output into normalized Findings."""
    if not raw_output or raw_output.strip() == "":
        return []

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid Bandit JSON output: {e}") from e

    # Bandit outputs an object with "results" array
    results = data.get("results", [])
    if not isinstance(results, list):
        return []

    findings: list[Finding] = []
    for result in results:
        finding = _parse_result(result)
        if finding:
            findings.append(finding)

    return findings


def _parse_result(result: dict[str, Any]) -> Finding | None:
    """Parse a single Bandit result into a Finding."""
    try:
        severity_str = result.get("issue_severity", "MEDIUM").upper()
        confidence_str = result.get("issue_confidence", "MEDIUM").upper()
        severity = _determine_severity(severity_str, confidence_str)

        # Extract line range
        line_range = result.get("line_range", [])
        line_start = result.get("line_number", 1)
        line_end = line_range[-1] if line_range else None

        # Build CWE reference if available
        cwe = None
        cwe_info = result.get("issue_cwe", {})
        if cwe_info and isinstance(cwe_info, dict):
            cwe_id = cwe_info.get("id")
            if cwe_id:
                cwe = f"CWE-{cwe_id}"

        # Build references
        references: list[str] = []
        more_info = result.get("more_info")
        if more_info:
            references.append(more_info)

        return Finding(
            scanner="bandit",
            rule_id=result.get("test_id", "unknown"),
            severity=severity,
            category=Category.SECURITY,
            title=result.get("test_name", "Security Issue").replace("_", " ").title(),
            message=result.get("issue_text", "Security issue detected"),
            file_path=result.get("filename", ""),
            line_start=line_start,
            line_end=line_end,
            cwe=cwe,
            references=references,
            code_snippet=result.get("code"),
            fingerprint=f"{result.get('test_id', '')}:{result.get('filename', '')}:{line_start}",
        )
    except Exception:
        # Skip malformed results
        return None


def _determine_severity(severity: str, confidence: str) -> Severity:
    """Determine severity based on issue severity and confidence."""
    # HIGH severity + HIGH confidence = CRITICAL
    if severity == "HIGH" and confidence == "HIGH":
        return Severity.CRITICAL

    return SEVERITY_MAP.get(severity, Severity.MEDIUM)
