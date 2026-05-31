"""Trivy output parser."""

import json
from typing import Any

from vibeguard.models.finding import Category, Finding, Severity

SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


def parse_output(raw_output: str) -> list[Finding]:
    """Parse Trivy JSON output into normalized Findings."""
    if not raw_output or raw_output.strip() == "":
        return []

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid Trivy JSON output: {e}") from e

    findings: list[Finding] = []
    results = data.get("Results", [])

    for result in results:
        target = result.get("Target", "")
        vulnerabilities = result.get("Vulnerabilities") or []

        for vuln in vulnerabilities:
            finding = _parse_vulnerability(vuln, target)
            if finding:
                findings.append(finding)

    return findings


def _parse_vulnerability(vuln: dict[str, Any], target: str) -> Finding | None:
    """Parse a single Trivy vulnerability into a Finding."""
    try:
        severity_str = vuln.get("Severity", "UNKNOWN").upper()
        severity = SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        # Extract CWE from CweIDs array
        cwe = None
        cwe_ids = vuln.get("CweIDs", [])
        if cwe_ids and isinstance(cwe_ids, list):
            cwe = cwe_ids[0]

        # Build informative message
        pkg_name = vuln.get("PkgName", "unknown")
        installed = vuln.get("InstalledVersion", "unknown")
        fixed = vuln.get("FixedVersion", "")
        description = vuln.get("Description", "")

        message = description or f"Vulnerable package: {pkg_name}@{installed}"
        if fixed:
            message = f"{message} (Fix available: upgrade to {fixed})"

        # Extract references
        references = vuln.get("References", [])
        if isinstance(references, str):
            references = [references]

        vuln_id = vuln.get("VulnerabilityID", "unknown")

        return Finding(
            scanner="trivy",
            rule_id=vuln_id,
            severity=severity,
            category=Category.VULNERABILITY,
            title=vuln.get("Title", f"Vulnerability in {pkg_name}"),
            message=message,
            file_path=target,
            line_start=1,  # Trivy doesn't provide line numbers for dependency vulns
            cwe=cwe,
            references=references,
            fingerprint=f"{vuln_id}:{pkg_name}:{installed}",
        )
    except Exception:
        # Skip malformed vulnerabilities
        return None
