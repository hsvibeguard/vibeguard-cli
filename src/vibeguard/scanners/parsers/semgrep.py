"""Semgrep output parser."""

import json
from typing import Any

from vibeguard.models.finding import Category, Finding, Severity

SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": Severity.CRITICAL,
    "WARNING": Severity.HIGH,
    "INFO": Severity.MEDIUM,
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def parse_output(raw_output: str) -> list[Finding]:
    """Parse Semgrep JSON output into normalized Findings."""
    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid Semgrep JSON output: {e}") from e

    findings: list[Finding] = []
    results = data.get("results", [])

    for match in results:
        finding = _parse_match(match)
        if finding:
            findings.append(finding)

    return findings


def _parse_match(match: dict[str, Any]) -> Finding | None:
    """Parse a single Semgrep match into a Finding."""
    try:
        extra = match.get("extra", {})
        metadata = extra.get("metadata", {})

        # Extract severity
        raw_severity = extra.get("severity", "INFO").upper()
        severity = SEVERITY_MAP.get(raw_severity, Severity.MEDIUM)

        # Extract CWE from metadata
        cwe = None
        cwe_data = metadata.get("cwe", [])
        if isinstance(cwe_data, list) and cwe_data:
            cwe = cwe_data[0] if isinstance(cwe_data[0], str) else str(cwe_data[0])
        elif isinstance(cwe_data, str):
            cwe = cwe_data

        # Extract references
        references = metadata.get("references", [])
        if isinstance(references, str):
            references = [references]

        # Determine category
        category = _determine_category(match.get("check_id", ""), metadata)

        return Finding(
            scanner="semgrep",
            rule_id=match.get("check_id", "unknown"),
            severity=severity,
            category=category,
            title=_extract_title(match.get("check_id", "")),
            message=extra.get("message", "No description provided"),
            file_path=match.get("path", ""),
            line_start=match.get("start", {}).get("line", 1),
            line_end=match.get("end", {}).get("line"),
            cwe=cwe,
            references=references,
            code_snippet=extra.get("lines"),
            fingerprint=extra.get("fingerprint"),
        )
    except Exception:
        # Skip malformed matches
        return None


def _extract_title(check_id: str) -> str:
    """Extract a human-readable title from check_id."""
    # check_id format: "language.category.rule-name"
    parts = check_id.split(".")
    if len(parts) >= 3:
        return parts[-1].replace("-", " ").replace("_", " ").title()
    return check_id


def _determine_category(check_id: str, metadata: dict[str, Any]) -> Category:
    """Determine the category based on check_id and metadata."""
    check_lower = check_id.lower()

    if "secret" in check_lower or "credential" in check_lower or "password" in check_lower:
        return Category.SECRETS
    elif "security" in check_lower or "injection" in check_lower or "xss" in check_lower:
        return Category.SECURITY
    elif "vulnerability" in check_lower or "cve" in check_lower:
        return Category.VULNERABILITY
    elif "best-practice" in check_lower or "correctness" in check_lower:
        return Category.BEST_PRACTICE

    # Check metadata for category hints
    owasp = metadata.get("owasp", [])
    if owasp:
        return Category.SECURITY

    return Category.SECURITY  # Default
