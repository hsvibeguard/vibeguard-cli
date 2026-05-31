"""npm audit output parser.

Handles both npm v7+ format (vulnerabilities object) and older format (advisories).
"""

import json
from typing import Any

from vibeguard.models.finding import Category, Finding, Severity

# npm severity mapping to our standard severities
SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def parse_output(raw_output: str) -> list[Finding]:
    """Parse npm audit JSON output into normalized Findings.

    Handles both npm v7+ format and older npm versions.
    """
    if not raw_output or raw_output.strip() == "":
        return []

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid npm audit JSON output: {e}") from e

    # Detect format version and parse accordingly
    if "vulnerabilities" in data:
        # npm v7+ format
        return _parse_v7_format(data)
    elif "advisories" in data:
        # Older npm format
        return _parse_legacy_format(data)
    else:
        # No vulnerabilities found or unrecognized format
        return []


def _parse_v7_format(data: dict[str, Any]) -> list[Finding]:
    """Parse npm v7+ audit format.

    The vulnerabilities object is keyed by package name, with each entry
    containing severity, via (dependency chain), and effects.
    """
    findings: list[Finding] = []
    vulnerabilities = data.get("vulnerabilities", {})

    for pkg_name, vuln_info in vulnerabilities.items():
        if not isinstance(vuln_info, dict):
            continue

        finding = _parse_v7_vulnerability(pkg_name, vuln_info)
        if finding:
            findings.append(finding)

    return findings


def _parse_v7_vulnerability(pkg_name: str, vuln_info: dict[str, Any]) -> Finding | None:
    """Parse a single npm v7+ vulnerability entry."""
    try:
        severity_str = vuln_info.get("severity", "moderate").lower()
        severity = SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        # Build dependency chain from "via" field
        via = vuln_info.get("via", [])
        via_info = _extract_via_info(via)

        # Get the range of affected versions
        affected_range = vuln_info.get("range", "")

        # Build message with dependency context
        message_parts = [f"Vulnerable package: {pkg_name}"]
        if affected_range:
            message_parts.append(f"Affected versions: {affected_range}")
        if via_info.get("title"):
            message_parts.append(f"Issue: {via_info['title']}")
        if via_info.get("url"):
            message_parts.append(f"Advisory: {via_info['url']}")

        # Use fix availability info if present
        fix_available = vuln_info.get("fixAvailable")
        if fix_available and isinstance(fix_available, dict):
            fix_name = fix_available.get("name", "")
            fix_version = fix_available.get("version", "")
            if fix_name and fix_version:
                message_parts.append(f"Fix: Update {fix_name} to {fix_version}")
        elif fix_available is True:
            message_parts.append("Fix available via npm audit fix")

        # Build references
        references: list[str] = []
        if via_info.get("url"):
            references.append(via_info["url"])

        # Extract CWE if available
        cwe = None
        cwe_list = via_info.get("cwe", [])
        if cwe_list and isinstance(cwe_list, list):
            cwe = cwe_list[0] if cwe_list else None

        # Generate rule_id from advisory source or package
        rule_id = via_info.get("source") or f"npm-vuln-{pkg_name}"
        if isinstance(rule_id, int):
            rule_id = f"GHSA-{rule_id}"

        return Finding(
            scanner="npm_audit",
            rule_id=str(rule_id),
            severity=severity,
            category=Category.VULNERABILITY,
            title=via_info.get("title", f"Vulnerability in {pkg_name}"),
            message="\n".join(message_parts),
            file_path="package.json",
            line_start=1,
            line_end=None,
            cwe=cwe,
            references=references,
            code_snippet=None,
            fingerprint=f"npm_audit:{pkg_name}:{rule_id}",
        )
    except Exception:
        return None


def _extract_via_info(via: list[Any]) -> dict[str, Any]:
    """Extract vulnerability details from the 'via' field.

    The via field can contain strings (dependency names) or objects
    (vulnerability details).
    """
    info: dict[str, Any] = {}

    for item in via:
        if isinstance(item, dict):
            # This is the actual vulnerability info
            info["title"] = item.get("title", "")
            info["url"] = item.get("url", "")
            info["source"] = item.get("source")
            info["cwe"] = item.get("cwe", [])
            break  # Use the first detailed entry

    return info


def _parse_legacy_format(data: dict[str, Any]) -> list[Finding]:
    """Parse older npm audit format with advisories object."""
    findings: list[Finding] = []
    advisories = data.get("advisories", {})

    for advisory_id, advisory in advisories.items():
        if not isinstance(advisory, dict):
            continue

        finding = _parse_legacy_advisory(str(advisory_id), advisory)
        if finding:
            findings.append(finding)

    return findings


def _parse_legacy_advisory(advisory_id: str, advisory: dict[str, Any]) -> Finding | None:
    """Parse a single legacy npm advisory entry."""
    try:
        severity_str = advisory.get("severity", "moderate").lower()
        severity = SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        module_name = advisory.get("module_name", "unknown")
        title = advisory.get("title", f"Vulnerability in {module_name}")

        # Build message
        message_parts = [
            advisory.get("overview", ""),
            f"Vulnerable versions: {advisory.get('vulnerable_versions', 'unknown')}",
            f"Patched versions: {advisory.get('patched_versions', 'none')}",
        ]
        recommendation = advisory.get("recommendation")
        if recommendation:
            message_parts.append(f"Recommendation: {recommendation}")

        # References
        references: list[str] = []
        url = advisory.get("url")
        if url:
            references.append(url)
        refs = advisory.get("references")
        if refs:
            references.append(refs)

        # CWE
        cwe = None
        cwe_list = advisory.get("cwe", [])
        if cwe_list:
            cwe = cwe_list[0] if isinstance(cwe_list, list) else cwe_list

        return Finding(
            scanner="npm_audit",
            rule_id=f"npm-{advisory_id}",
            severity=severity,
            category=Category.VULNERABILITY,
            title=title,
            message="\n".join(filter(None, message_parts)),
            file_path="package.json",
            line_start=1,
            line_end=None,
            cwe=cwe,
            references=references,
            code_snippet=None,
            fingerprint=f"npm_audit:{module_name}:{advisory_id}",
        )
    except Exception:
        return None
