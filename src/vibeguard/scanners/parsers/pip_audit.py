"""pip-audit output parser.

Parses JSON output from pip-audit for Python dependency vulnerabilities.
"""

import json
from typing import Any

from vibeguard.models.finding import Category, Finding, Severity

# pip-audit doesn't provide severity directly, so we infer from advisory source
# PYSEC advisories often link to CVEs with severity info
# Default to HIGH since dependency vulns should be addressed
DEFAULT_SEVERITY = Severity.HIGH

# Keywords in descriptions that suggest severity
CRITICAL_KEYWORDS = ["remote code execution", "rce", "arbitrary code", "command injection"]
HIGH_KEYWORDS = ["sql injection", "xss", "cross-site", "authentication bypass", "privilege"]
MEDIUM_KEYWORDS = ["denial of service", "dos", "information disclosure", "path traversal"]
LOW_KEYWORDS = ["timing attack", "minor", "low impact"]


def parse_output(raw_output: str) -> list[Finding]:
    """Parse pip-audit JSON output into normalized Findings."""
    if not raw_output or raw_output.strip() == "":
        return []

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid pip-audit JSON output: {e}") from e

    # pip-audit outputs a "dependencies" array
    # Handle older format where root is directly an array
    if isinstance(data, list):
        dependencies = data
    elif isinstance(data, dict):
        dependencies = data.get("dependencies", [])
    else:
        return []

    if not isinstance(dependencies, list):
        return []

    findings: list[Finding] = []

    for dep in dependencies:
        if not isinstance(dep, dict):
            continue

        vulns = dep.get("vulns", [])
        if not vulns:
            continue

        pkg_name = dep.get("name", "unknown")
        pkg_version = dep.get("version", "unknown")

        for vuln in vulns:
            finding = _parse_vulnerability(pkg_name, pkg_version, vuln)
            if finding:
                findings.append(finding)

    return findings


def _parse_vulnerability(
    pkg_name: str, pkg_version: str, vuln: dict[str, Any]
) -> Finding | None:
    """Parse a single pip-audit vulnerability entry."""
    try:
        vuln_id = vuln.get("id", "unknown")
        description = vuln.get("description", "")
        fix_versions = vuln.get("fix_versions", [])
        aliases = vuln.get("aliases", [])

        # Determine severity from description keywords
        severity = _determine_severity(description)

        # Build title
        title = f"Vulnerability in {pkg_name} ({vuln_id})"

        # Build message
        message_parts = [
            f"Package: {pkg_name}=={pkg_version}",
            f"Vulnerability: {vuln_id}",
        ]
        if description:
            # Truncate long descriptions
            desc = description[:500] + "..." if len(description) > 500 else description
            message_parts.append(f"Description: {desc}")
        if fix_versions:
            fix_str = ", ".join(fix_versions)
            message_parts.append(f"Fixed in: {fix_str}")
        else:
            message_parts.append("No fix available yet")
        if aliases:
            message_parts.append(f"Related: {', '.join(aliases)}")

        # Extract CVE from aliases if present
        cwe = None
        cve = None
        for alias in aliases:
            if alias.startswith("CVE-"):
                cve = alias
                break

        # Build references
        references: list[str] = []
        # Add PyPI advisory link
        if vuln_id.startswith("PYSEC-"):
            references.append(f"https://osv.dev/vulnerability/{vuln_id}")
        # Add CVE link if available
        if cve:
            references.append(f"https://nvd.nist.gov/vuln/detail/{cve}")

        # Determine detection file based on common Python dep files
        file_path = "requirements.txt"

        return Finding(
            scanner="pip_audit",
            rule_id=vuln_id,
            severity=severity,
            category=Category.VULNERABILITY,
            title=title,
            message="\n".join(message_parts),
            file_path=file_path,
            line_start=1,
            line_end=None,
            cwe=cwe,
            references=references,
            code_snippet=None,
            fingerprint=f"pip_audit:{pkg_name}:{pkg_version}:{vuln_id}",
        )
    except Exception:
        return None


def _determine_severity(description: str) -> Severity:
    """Determine severity from vulnerability description keywords."""
    if not description:
        return DEFAULT_SEVERITY

    desc_lower = description.lower()

    # Check for critical indicators
    for keyword in CRITICAL_KEYWORDS:
        if keyword in desc_lower:
            return Severity.CRITICAL

    # Check for high severity indicators
    for keyword in HIGH_KEYWORDS:
        if keyword in desc_lower:
            return Severity.HIGH

    # Check for medium severity indicators
    for keyword in MEDIUM_KEYWORDS:
        if keyword in desc_lower:
            return Severity.MEDIUM

    # Check for low severity indicators
    for keyword in LOW_KEYWORDS:
        if keyword in desc_lower:
            return Severity.LOW

    # Default to high for unknown dependency vulnerabilities
    return DEFAULT_SEVERITY
