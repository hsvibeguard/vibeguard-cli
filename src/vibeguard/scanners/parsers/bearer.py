"""Bearer output parser."""

import json
from typing import Any

from vibeguard.models.finding import Category, Finding, Severity

SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "warning": Severity.INFO,
}


def parse_output(raw_output: str) -> list[Finding]:
    """Parse Bearer JSON output into normalized Findings."""
    if not raw_output or raw_output.strip() == "":
        return []

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid Bearer JSON output: {e}") from e

    # Bearer outputs an array of results or an object with results
    results = data if isinstance(data, list) else data.get("results", data.get("findings", []))
    if not isinstance(results, list):
        return []

    findings: list[Finding] = []
    for result in results:
        finding = _parse_result(result)
        if finding:
            findings.append(finding)

    return findings


def _parse_result(result: dict[str, Any]) -> Finding | None:
    """Parse a single Bearer result into a Finding."""
    try:
        severity_str = result.get("severity", "medium").lower()
        severity = SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        rule_id = result.get("rule_id", "unknown")
        description = result.get("description", "Security issue detected by Bearer")
        file_path = result.get("filename", "")
        line = result.get("line_number", 1)

        # Extract CWE IDs
        cwe_ids = result.get("cwe_ids", [])
        cwe = f"CWE-{cwe_ids[0]}" if cwe_ids else None

        # Build references list
        references: list[str] = []
        doc_url = result.get("documentation_url")
        if doc_url:
            references.append(doc_url)

        return Finding(
            scanner="bearer",
            rule_id=rule_id,
            severity=severity,
            category=Category.SECURITY,
            title=f"Bearer: {rule_id}",
            message=description,
            file_path=file_path,
            line_start=line,
            cwe=cwe,
            references=references,
            fingerprint=f"{rule_id}:{file_path}:{line}",
        )
    except Exception:
        return None
