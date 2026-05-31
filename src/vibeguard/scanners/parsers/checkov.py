"""Checkov output parser for IaC policy scanning."""

import json
from typing import Any

from vibeguard.models.finding import Category, Finding, Severity

# Checkov severity mapping to VibeGuard severity
SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
    "UNKNOWN": Severity.MEDIUM,  # Default for unknown severity
}


def parse_output(raw_output: str) -> list[Finding]:
    """Parse Checkov JSON output into normalized Findings.

    Checkov outputs JSON with structure:
    {
        "passed_checks": [...],
        "failed_checks": [
            {
                "check": {
                    "id": "CKV_AWS_1",
                    "name": "Ensure IAM password policy requires...",
                    "guideline": "https://docs.checkov.io/..."
                },
                "check_result": {"result": "FAILED"},
                "file_path": "/terraform/main.tf",
                "file_line_range": [10, 15],
                "resource": "aws_iam_account_password_policy.strict",
                "severity": "MEDIUM"
            }
        ],
        "skipped_checks": [...]
    }

    Or for multiple check types, it may return a list of results:
    [
        {"check_type": "terraform", "results": {...}},
        {"check_type": "dockerfile", "results": {...}}
    ]

    Args:
        raw_output: Raw JSON output from Checkov

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
        raise ValueError(f"Invalid Checkov JSON output: {e}") from e

    findings: list[Finding] = []

    # Handle both single result format and multi-check-type format
    if isinstance(data, list):
        # Multi-check-type format: list of {check_type, results}
        for check_result in data:
            if isinstance(check_result, dict) and "results" in check_result:
                results = check_result.get("results", {})
                failed_checks = results.get("failed_checks", [])
                for check in failed_checks:
                    finding = _parse_failed_check(check)
                    if finding:
                        findings.append(finding)
    elif isinstance(data, dict):
        # Single result format or results wrapper
        if "results" in data:
            # Wrapped format: {"results": {"failed_checks": [...]}}
            results = data.get("results", {})
            if isinstance(results, dict):
                failed_checks = results.get("failed_checks", [])
            else:
                failed_checks = []
        else:
            # Direct format: {"failed_checks": [...]}
            failed_checks = data.get("failed_checks", [])

        for check in failed_checks:
            finding = _parse_failed_check(check)
            if finding:
                findings.append(finding)

    return findings


def _parse_failed_check(check: dict[str, Any]) -> Finding | None:
    """Parse a single failed check into a Finding.

    Args:
        check: A failed check dict from Checkov output

    Returns:
        Finding object or None if parsing fails
    """
    try:
        # Extract check info
        check_info = check.get("check", {})
        check_id = check_info.get("id", "UNKNOWN")
        check_name = check_info.get("name", "Security misconfiguration detected")
        guideline = check_info.get("guideline", "")

        # Extract file location
        file_path = check.get("file_path", "")
        # Remove leading slash if present (Checkov uses /path format)
        if file_path.startswith("/"):
            file_path = file_path[1:]

        # Extract line range
        line_range = check.get("file_line_range", [1, 1])
        line_start = line_range[0] if line_range else 1
        line_end = line_range[1] if len(line_range) > 1 else line_start

        # Determine severity
        severity_str = check.get("severity", "MEDIUM")
        if severity_str is None:
            severity_str = "MEDIUM"
        severity = SEVERITY_MAP.get(severity_str.upper(), Severity.MEDIUM)

        # Extract resource info for better context
        resource = check.get("resource", "")
        resource_address = check.get("resource_address", resource)

        # Build detailed message
        message = check_name
        if resource_address:
            message = f"{check_name}\n\nResource: {resource_address}"

        # Build references
        references: list[str] = []
        if guideline:
            references.append(guideline)

        # Extract CWE if available (some checks have it)
        cwe = None
        # Checkov doesn't typically include CWE, but check anyway
        if "cwe" in check:
            cwe = check["cwe"]

        # Build fingerprint for deduplication
        fingerprint = f"{check_id}:{file_path}:{line_start}"

        return Finding(
            scanner="checkov",
            rule_id=check_id,
            severity=severity,
            category=Category.MISCONFIGURATION,
            title=f"[{check_id}] {_truncate(check_name, 80)}",
            message=message,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            cwe=cwe,
            references=references,
            code_snippet=None,  # Checkov doesn't include code snippets
            fingerprint=fingerprint,
        )
    except Exception:
        # Skip malformed check entries
        return None


def _truncate(text: str, max_length: int) -> str:
    """Truncate text to max length with ellipsis."""
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."
