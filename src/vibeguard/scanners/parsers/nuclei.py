"""Nuclei JSONL output parser for HTTP vulnerability scanning.

Nuclei outputs JSON Lines format (one JSON object per line) with findings
from HTTP vulnerability templates. This parser normalizes the output to
the VibeGuard Finding model.
"""

import json
from typing import Any

from vibeguard.models.finding import Category, Finding, Severity

# Nuclei severity mapping (direct match)
SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.MEDIUM,
}

# Category mapping based on Nuclei template tags
TAG_TO_CATEGORY: dict[str, Category] = {
    # Vulnerabilities
    "cve": Category.VULNERABILITY,
    "vulnerability": Category.VULNERABILITY,
    "rce": Category.VULNERABILITY,
    "sqli": Category.VULNERABILITY,
    "xss": Category.SECURITY,
    "ssrf": Category.SECURITY,
    "lfi": Category.SECURITY,
    "rfi": Category.SECURITY,
    "xxe": Category.SECURITY,
    "idor": Category.SECURITY,
    "injection": Category.SECURITY,
    # Security issues
    "auth-bypass": Category.SECURITY,
    "default-login": Category.SECURITY,
    "unauth": Category.SECURITY,
    "traversal": Category.SECURITY,
    "redirect": Category.SECURITY,
    "cors": Category.SECURITY,
    "crlf": Category.SECURITY,
    # Secrets
    "token": Category.SECRETS,
    "secret": Category.SECRETS,
    "exposure": Category.SECRETS,
    "leak": Category.SECRETS,
    # Misconfigurations
    "misconfig": Category.MISCONFIGURATION,
    "config": Category.MISCONFIGURATION,
    "panel": Category.MISCONFIGURATION,
    "admin": Category.MISCONFIGURATION,
    "debug": Category.MISCONFIGURATION,
    "backup": Category.MISCONFIGURATION,
    # Best practices
    "tech": Category.BEST_PRACTICE,
    "detect": Category.BEST_PRACTICE,
    "ssl": Category.BEST_PRACTICE,
    "header": Category.BEST_PRACTICE,
}


def parse_output(raw_output: str) -> list[Finding]:
    """Parse Nuclei JSONL output into normalized Findings.

    Nuclei outputs JSON Lines format (one JSON object per line):
    {
        "template-id": "CVE-2021-44228-log4j-rce",
        "info": {
            "name": "Apache Log4j RCE",
            "severity": "critical",
            "description": "...",
            "reference": ["https://..."],
            "classification": {
                "cwe-id": ["CWE-502"],
                "cvss-metrics": "CVSS:3.1/AV:N/AC:L/...",
                "cvss-score": 10.0
            },
            "tags": ["cve", "rce", "log4j"]
        },
        "host": "http://localhost:8080",
        "matched-at": "http://localhost:8080/api/login",
        "matcher-name": "log4j",
        "type": "http",
        "timestamp": "2026-02-02T10:00:00.000Z"
    }

    Args:
        raw_output: Raw JSONL output from Nuclei

    Returns:
        List of normalized Finding objects
    """
    if not raw_output or raw_output.strip() == "":
        return []

    findings: list[Finding] = []

    # Process each line as a separate JSON object
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
            # Skip malformed lines (Nuclei may output status messages)
            continue

    return findings


def _parse_result(data: dict[str, Any]) -> Finding | None:
    """Parse a single Nuclei result into a Finding.

    Args:
        data: Parsed JSON object from one JSONL line

    Returns:
        Finding object or None if parsing fails
    """
    try:
        template_id = data.get("template-id", "unknown")
        info = data.get("info", {})

        # Extract severity
        severity_str = info.get("severity", "medium")
        if isinstance(severity_str, str):
            severity_str = severity_str.lower()
        else:
            severity_str = "medium"
        severity = SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        # Extract classification info
        classification = info.get("classification", {})
        cwe_ids = classification.get("cwe-id", [])
        cwe = cwe_ids[0] if cwe_ids else None

        # Determine category from tags
        # Nuclei tags can be a comma-separated string or a list
        tags_raw = info.get("tags", [])
        tags: list[str] = []
        if isinstance(tags_raw, str):
            # Split comma-separated tags and normalize
            tags = [t.strip().lower() for t in tags_raw.split(",") if t.strip()]
        elif isinstance(tags_raw, list):
            # Handle list of tags (normalize each)
            for t in tags_raw:
                if isinstance(t, str):
                    # Some lists may contain comma-separated strings too
                    tags.extend(
                        [part.strip().lower() for part in t.split(",") if part.strip()]
                    )
        category = _determine_category(tags)

        # Build references list
        references = info.get("reference", [])
        if isinstance(references, str):
            references = [references]
        elif references is None:
            references = []

        # Extract URL info - use matched-at if available, fallback to host
        matched_at = data.get("matched-at", "") or data.get("host", "")
        host = data.get("host", "")

        # Build descriptive message
        description = info.get("description", "")
        message_parts = []

        if description:
            message_parts.append(description)

        if matched_at and matched_at != description:
            message_parts.append(f"Matched at: {matched_at}")

        # Add CVSS score if available
        cvss_score = classification.get("cvss-score")
        if cvss_score:
            message_parts.append(f"CVSS Score: {cvss_score}")

        # Add matcher name if available
        matcher_name = data.get("matcher-name")
        if matcher_name:
            message_parts.append(f"Matcher: {matcher_name}")

        if message_parts:
            message = "\n".join(message_parts)
        else:
            message = f"Vulnerability detected at {matched_at}"

        # Generate fingerprint for deduplication
        # Include matched-at URL to distinguish different endpoints on same host
        # Also include matcher_name if present to distinguish different matches
        fingerprint_parts = [
            "nuclei",
            template_id,
            matched_at or host,  # Use full matched URL, fallback to host
        ]
        if matcher_name:
            fingerprint_parts.append(matcher_name)
        fingerprint = ":".join(fingerprint_parts)

        return Finding(
            scanner="nuclei",
            rule_id=template_id,
            severity=severity,
            category=category,
            title=info.get("name", template_id),
            message=message,
            file_path=matched_at,  # Use URL as "file_path" for DAST
            line_start=1,  # DAST doesn't have line numbers
            line_end=None,
            cwe=cwe,
            references=references,
            code_snippet=None,
            fingerprint=fingerprint,
        )
    except Exception:
        # Skip malformed results
        return None


def _determine_category(tags: list[str]) -> Category:
    """Determine category from Nuclei template tags.

    Args:
        tags: List of template tags

    Returns:
        Appropriate Category enum value
    """
    for tag in tags:
        if not isinstance(tag, str):
            continue
        tag_lower = tag.lower()
        if tag_lower in TAG_TO_CATEGORY:
            return TAG_TO_CATEGORY[tag_lower]

    # Default to SECURITY for DAST findings
    return Category.SECURITY
