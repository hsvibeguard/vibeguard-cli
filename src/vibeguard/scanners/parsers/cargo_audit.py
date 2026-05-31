"""cargo-audit output parser.

Parses JSON output from cargo-audit for Rust dependency vulnerabilities.
"""

import json
from typing import Any

from vibeguard.models.finding import Category, Finding, Severity

# CVSS v3 score to severity mapping
CVSS_SEVERITY: list[tuple[float, Severity]] = [
    (9.0, Severity.CRITICAL),  # 9.0+ = Critical
    (7.0, Severity.HIGH),  # 7.0-8.9 = High
    (4.0, Severity.MEDIUM),  # 4.0-6.9 = Medium
    (0.1, Severity.LOW),  # 0.1-3.9 = Low
    (0.0, Severity.INFO),  # 0 = Info
]

# RustSec category to severity hints
CATEGORY_SEVERITY: dict[str, Severity] = {
    "code-execution": Severity.CRITICAL,
    "memory-corruption": Severity.CRITICAL,
    "memory-exposure": Severity.HIGH,
    "denial-of-service": Severity.MEDIUM,
    "file-disclosure": Severity.HIGH,
    "privilege-escalation": Severity.CRITICAL,
}

DEFAULT_SEVERITY = Severity.HIGH


def parse_output(raw_output: str) -> list[Finding]:
    """Parse cargo-audit JSON output into normalized Findings."""
    if not raw_output or raw_output.strip() == "":
        return []

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid cargo-audit JSON output: {e}") from e

    # cargo-audit outputs vulnerabilities under "vulnerabilities.list"
    vulns_data = data.get("vulnerabilities", {})
    if not isinstance(vulns_data, dict):
        return []

    vuln_list = vulns_data.get("list", [])
    if not isinstance(vuln_list, list):
        return []

    findings: list[Finding] = []

    for vuln in vuln_list:
        finding = _parse_vulnerability(vuln)
        if finding:
            findings.append(finding)

    return findings


def _parse_vulnerability(vuln: dict[str, Any]) -> Finding | None:
    """Parse a single cargo-audit vulnerability entry."""
    try:
        advisory = vuln.get("advisory", {})
        package_info = vuln.get("package", {})
        versions = vuln.get("versions", {})

        if not advisory:
            return None

        advisory_id = advisory.get("id", "unknown")
        pkg_name = package_info.get("name", advisory.get("package", "unknown"))
        pkg_version = package_info.get("version", "unknown")
        title = advisory.get("title", f"Vulnerability in {pkg_name}")
        description = advisory.get("description", "")
        date = advisory.get("date", "")
        aliases = advisory.get("aliases", [])
        cvss = advisory.get("cvss")
        categories = advisory.get("categories", [])

        # Determine severity
        severity = _determine_severity(cvss, categories)

        # Build message
        message_parts = [
            f"Package: {pkg_name}=={pkg_version}",
            f"Advisory: {advisory_id}",
        ]
        if date:
            message_parts.append(f"Published: {date}")
        if description:
            # Truncate long descriptions
            desc = description[:500] + "..." if len(description) > 500 else description
            message_parts.append(f"Description: {desc}")

        # Add fix information
        patched = versions.get("patched", [])
        if patched:
            message_parts.append(f"Patched in: {', '.join(patched)}")
        else:
            message_parts.append("No patch available yet")

        unaffected = versions.get("unaffected", [])
        if unaffected:
            message_parts.append(f"Unaffected: {', '.join(unaffected)}")

        if aliases:
            message_parts.append(f"Related: {', '.join(aliases)}")

        # Extract CVE from aliases
        cve = None
        for alias in aliases:
            if alias.startswith("CVE-"):
                cve = alias
                break

        # Build references
        references: list[str] = []
        # RustSec advisory link
        if advisory_id.startswith("RUSTSEC-"):
            references.append(f"https://rustsec.org/advisories/{advisory_id}")
        # crates.io link
        references.append(f"https://crates.io/crates/{pkg_name}")
        # CVE link if available
        if cve:
            references.append(f"https://nvd.nist.gov/vuln/detail/{cve}")

        return Finding(
            scanner="cargo_audit",
            rule_id=advisory_id,
            severity=severity,
            category=Category.VULNERABILITY,
            title=title,
            message="\n".join(message_parts),
            file_path="Cargo.toml",
            line_start=1,
            line_end=None,
            cwe=None,  # RustSec doesn't typically include CWE
            references=references,
            code_snippet=None,
            fingerprint=f"cargo_audit:{pkg_name}:{pkg_version}:{advisory_id}",
        )
    except Exception:
        return None


def _determine_severity(cvss: str | None, categories: list[str]) -> Severity:
    """Determine severity from CVSS score or advisory categories."""
    # First try to parse CVSS score
    if cvss:
        score = _parse_cvss_score(cvss)
        if score is not None:
            for threshold, severity in CVSS_SEVERITY:
                if score >= threshold:
                    return severity

    # Fall back to category-based severity
    for cat in categories:
        cat_lower = cat.lower().replace("_", "-")
        if cat_lower in CATEGORY_SEVERITY:
            return CATEGORY_SEVERITY[cat_lower]

    return DEFAULT_SEVERITY


def _parse_cvss_score(cvss: str) -> float | None:
    """Parse CVSS score from CVSS vector string.

    CVSS strings look like: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    Or sometimes just a float: 9.8
    """
    if not cvss:
        return None

    # Try parsing as a float directly
    try:
        return float(cvss)
    except ValueError:
        pass

    # Try extracting from CVSS vector
    # The score is typically not in the vector itself, so we estimate
    # based on the metrics if needed (or return None to fall back to categories)
    return None
