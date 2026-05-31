"""kube-linter output parser."""

import json
from typing import Any

from vibeguard.models.finding import Category, Finding, Severity

# Security-sensitive checks that should be mapped to HIGH severity
HIGH_SEVERITY_CHECKS: set[str] = {
    "run-as-non-root",
    "no-read-only-root-fs",
    "privilege-escalation-container",
    "privileged-container",
    "sensitive-host-mounts",
    "host-network",
    "host-pid",
    "host-ipc",
    "unsafe-sysctls",
    "writable-host-mount",
    "dangling-service",
    "deprecated-service-account-field",
}


def parse_output(raw_output: str) -> list[Finding]:
    """Parse kube-linter JSON output into normalized Findings."""
    if not raw_output or raw_output.strip() == "":
        return []

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid kube-linter JSON output: {e}") from e

    reports = data.get("Reports", [])
    if not reports:
        return []

    findings: list[Finding] = []
    for report in reports:
        finding = _parse_report(report)
        if finding:
            findings.append(finding)

    return findings


def _parse_report(report: dict[str, Any]) -> Finding | None:
    """Parse a single kube-linter report into a Finding."""
    try:
        check = report.get("Check", "unknown")
        diagnostic = report.get("Diagnostic", {})
        message = diagnostic.get("Message", "Kubernetes misconfiguration detected")
        remediation = report.get("Remediation", "")

        # Extract object info for file_path
        obj = report.get("Object", {})
        k8s_obj = obj.get("K8sObject", {})
        namespace = k8s_obj.get("Namespace", "default")
        name = k8s_obj.get("Name", "unknown")
        gvk = k8s_obj.get("GroupVersionKind", {})
        kind = gvk.get("Kind", "Unknown")

        # Determine severity
        severity = Severity.HIGH if check in HIGH_SEVERITY_CHECKS else Severity.MEDIUM

        full_message = message
        if remediation:
            full_message += f". Remediation: {remediation}"

        return Finding(
            scanner="kube-linter",
            rule_id=check,
            severity=severity,
            category=Category.MISCONFIGURATION,
            title=f"kube-linter: {check}",
            message=full_message,
            file_path=f"{namespace}/{kind}/{name}",
            line_start=1,
            fingerprint=f"{check}:{namespace}/{kind}/{name}",
        )
    except Exception:
        return None
