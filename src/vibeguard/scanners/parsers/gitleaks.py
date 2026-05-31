"""Gitleaks output parser."""

import json
from typing import Any

from vibeguard.models.finding import Category, Finding, Severity

# Gitleaks doesn't provide severity directly, so we map based on rule patterns
# More sensitive secret types get higher severity
SEVERITY_PATTERNS: dict[str, Severity] = {
    "aws": Severity.CRITICAL,
    "private-key": Severity.CRITICAL,
    "private_key": Severity.CRITICAL,
    "rsa": Severity.CRITICAL,
    "ssh": Severity.CRITICAL,
    "api-key": Severity.HIGH,
    "api_key": Severity.HIGH,
    "apikey": Severity.HIGH,
    "password": Severity.HIGH,
    "passwd": Severity.HIGH,
    "token": Severity.HIGH,
    "secret": Severity.HIGH,
    "credential": Severity.HIGH,
    "auth": Severity.HIGH,
    "bearer": Severity.HIGH,
    "jwt": Severity.HIGH,
    "oauth": Severity.HIGH,
    "slack": Severity.HIGH,
    "stripe": Severity.HIGH,
    "github": Severity.HIGH,
    "gitlab": Severity.HIGH,
    "heroku": Severity.HIGH,
    "sendgrid": Severity.HIGH,
    "twilio": Severity.HIGH,
    "generic": Severity.MEDIUM,
}


def parse_output(raw_output: str) -> list[Finding]:
    """Parse Gitleaks JSON array output into normalized Findings."""
    if not raw_output or raw_output.strip() == "":
        return []

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid Gitleaks JSON output: {e}") from e

    # Gitleaks outputs an array directly, not wrapped in object
    if not isinstance(data, list):
        data = [data] if data else []

    findings: list[Finding] = []
    for match in data:
        finding = _parse_match(match)
        if finding:
            findings.append(finding)

    return findings


def _parse_match(match: dict[str, Any]) -> Finding | None:
    """Parse a single Gitleaks match into a Finding."""
    try:
        rule_id = match.get("RuleID", "unknown")
        severity = _determine_severity(rule_id)

        return Finding(
            scanner="gitleaks",
            rule_id=rule_id,
            severity=severity,
            category=Category.SECRETS,
            title=match.get("Description", "Secret Detected"),
            message=f"Secret detected: {match.get('Description', 'Unknown secret type')}",
            file_path=match.get("File", ""),
            line_start=match.get("StartLine", 1),
            line_end=match.get("EndLine"),
            code_snippet=match.get("Match"),
            fingerprint=match.get("Fingerprint"),
        )
    except Exception:
        # Skip malformed matches
        return None


def _determine_severity(rule_id: str) -> Severity:
    """Determine severity based on rule ID patterns."""
    rule_lower = rule_id.lower()

    for pattern, severity in SEVERITY_PATTERNS.items():
        if pattern in rule_lower:
            return severity

    # Default to HIGH for unknown secret types (secrets are serious)
    return Severity.HIGH
