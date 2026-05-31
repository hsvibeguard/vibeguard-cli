"""TruffleHog output parser."""

import json
from typing import Any

from vibeguard.models.finding import Category, Finding, Severity

# TruffleHog detector types that indicate critical secrets
CRITICAL_DETECTORS: set[str] = {
    "AWS",
    "GCP",
    "Azure",
    "PrivateKey",
    "RSAPrivateKey",
    "SSHPrivateKey",
    "GitHubSSH",
}

# Detector types that indicate high severity secrets
HIGH_DETECTORS: set[str] = {
    "GitHub",
    "GitLab",
    "Slack",
    "Stripe",
    "Twilio",
    "SendGrid",
    "Mailchimp",
    "Heroku",
    "NPM",
    "PyPI",
    "Docker",
    "JWT",
    "OAuth",
    "APIKey",
    "GenericAPIKey",
}


def parse_output(raw_output: str) -> list[Finding]:
    """Parse TruffleHog JSON lines output into normalized Findings."""
    if not raw_output or raw_output.strip() == "":
        return []

    findings: list[Finding] = []

    # TruffleHog outputs one JSON object per line
    for line in raw_output.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        try:
            data = json.loads(line)
            finding = _parse_result(data)
            if finding:
                findings.append(finding)
        except json.JSONDecodeError:
            # Skip invalid JSON lines
            continue

    return findings


def _parse_result(data: dict[str, Any]) -> Finding | None:
    """Parse a single TruffleHog result into a Finding."""
    try:
        detector_name = data.get("DetectorName", "Unknown")
        verified = data.get("Verified", False)
        severity = _determine_severity(detector_name, verified)

        # Extract source metadata
        source_meta = data.get("SourceMetadata", {})
        source_data = source_meta.get("Data", {})

        # TruffleHog can scan filesystem, git, etc. - handle filesystem case
        fs_data = source_data.get("Filesystem", {})
        file_path = fs_data.get("file", "")
        line_start = fs_data.get("line", 1)

        # If not filesystem, try git source
        if not file_path:
            git_data = source_data.get("Git", {})
            file_path = git_data.get("file", "unknown")
            line_start = git_data.get("line", 1)

        # Build title
        title = f"{detector_name} Secret Detected"
        if verified:
            title += " (Verified)"

        # Build message
        redacted = data.get("Redacted", "")
        message = f"{detector_name} secret detected"
        if redacted:
            message += f": {redacted}"
        if verified:
            message += " - This secret has been verified as active"

        # Generate fingerprint from raw secret hash (not the actual secret)
        raw = data.get("Raw", "")
        fingerprint = f"trufflehog:{detector_name}:{file_path}:{line_start}"
        if raw:
            # Use first/last chars for uniqueness without exposing secret
            safe_suffix = f":{len(raw)}"
            fingerprint += safe_suffix

        # Use DetectorName as rule_id (DetectorType is an integer)
        return Finding(
            scanner="trufflehog",
            rule_id=detector_name,
            severity=severity,
            category=Category.SECRETS,
            title=title,
            message=message,
            file_path=file_path,
            line_start=line_start,
            line_end=None,
            code_snippet=data.get("Redacted"),
            fingerprint=fingerprint,
        )
    except Exception:
        # Skip malformed results
        return None


def _determine_severity(detector_name: str, verified: bool) -> Severity:
    """Determine severity based on detector type and verification status."""
    # Verified secrets are always critical
    if verified:
        return Severity.CRITICAL

    # Check against known critical patterns
    if detector_name in CRITICAL_DETECTORS:
        return Severity.CRITICAL

    # Check for critical patterns in detector name
    detector_lower = detector_name.lower()
    if any(p in detector_lower for p in ["aws", "gcp", "azure", "private", "ssh", "rsa"]):
        return Severity.CRITICAL

    # Check against known high severity detectors
    if detector_name in HIGH_DETECTORS:
        return Severity.HIGH

    # Check for high severity patterns
    if any(p in detector_lower for p in ["api", "token", "key", "secret", "auth", "password"]):
        return Severity.HIGH

    # Default to MEDIUM for unknown detectors
    return Severity.MEDIUM
