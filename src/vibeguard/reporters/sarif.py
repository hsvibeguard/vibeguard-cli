"""SARIF 2.1.0 report generator for GitHub Code Scanning integration."""

from typing import Any

from vibeguard import __version__
from vibeguard.models.finding import Finding, Severity
from vibeguard.models.scan_result import ScanResult

# SARIF severity level mapping
SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "warning",
    Severity.INFO: "note",
}

# Security severity score (0.0-10.0) for GitHub
SEVERITY_TO_SCORE: dict[Severity, str] = {
    Severity.CRITICAL: "9.0",
    Severity.HIGH: "7.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def _build_rule(finding: Finding, index: int) -> dict[str, Any]:
    """Build a SARIF rule object from a finding."""
    rule: dict[str, Any] = {
        "id": finding.rule_id,
        "name": finding.title[:256],
        "shortDescription": {"text": finding.title[:1024]},
        "fullDescription": {"text": finding.message[:1024]},
        "defaultConfiguration": {
            "level": SEVERITY_TO_LEVEL[finding.severity],
        },
        "properties": {
            "security-severity": SEVERITY_TO_SCORE[finding.severity],
            "tags": list(dict.fromkeys(["security", finding.category.value, finding.scanner])),
        },
    }

    if finding.cwe:
        rule["properties"]["tags"].append(f"external/cwe/{finding.cwe}")

    # First reference becomes the rule's help link (where GitHub wants it).
    if finding.references:
        rule["helpUri"] = finding.references[0]

    return rule


def _rel_uri(file_path: str, repo_root: str) -> str:
    """Return a repo-root-relative, forward-slashed URI.

    GitHub Code Scanning drops results whose artifactLocation URIs are absolute
    (or otherwise not relative to the repo root), so normalize here.
    """
    path = (file_path or "").replace("\\", "/")
    root = (repo_root or "").replace("\\", "/").rstrip("/")
    if root and path.startswith(root):
        path = path[len(root):]
    return path.lstrip("/")


def _build_result(finding: Finding, rule_index: int, repo_root: str = "") -> dict[str, Any]:
    """Build a SARIF result object from a finding."""
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": SEVERITY_TO_LEVEL[finding.severity],
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": _rel_uri(finding.file_path, repo_root),
                    },
                    "region": {
                        "startLine": finding.line_start,
                        "endLine": finding.line_end or finding.line_start,
                        "startColumn": 1,
                    },
                },
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": finding.id,
        },
    }

    # Add code snippet if available
    if finding.code_snippet:
        result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
            "text": finding.code_snippet[:1024]
        }

    # NOTE: references are exposed via the rule's helpUri (see _build_rule).
    # They must NOT be emitted as relatedLocations — GitHub Code Scanning
    # requires every relatedLocation to have a physicalLocation, and a bad one
    # fails the ENTIRE analysis ("buildRelatedLocations: expected physical location").

    return result


def to_sarif(result: ScanResult, include_suppressed: bool = False) -> dict[str, Any]:
    """Convert ScanResult to SARIF 2.1.0 format.

    This format is compatible with GitHub Code Scanning and other
    SARIF-consuming tools.

    By default, only actionable findings are included in the SARIF output.
    Suppressed findings (those marked as IGNORED by triage) are excluded
    to prevent noise in GitHub Code Scanning results.

    Args:
        result: The scan result to convert
        include_suppressed: If True, include all findings; if False (default),
            include only actionable findings

    Returns:
        SARIF 2.1.0 compliant dictionary
    """
    # Use actionable findings by default to avoid including triage-suppressed noise
    findings_to_export = result.findings if include_suppressed else result.actionable_findings

    # Build unique rules from findings (deduplicate by rule_id + scanner)
    rules: list[dict[str, Any]] = []
    rule_indices: dict[str, int] = {}  # (scanner, rule_id) -> index

    for finding in findings_to_export:
        key = f"{finding.scanner}:{finding.rule_id}"
        if key not in rule_indices:
            rule_indices[key] = len(rules)
            rules.append(_build_rule(finding, len(rules)))

    # Build results
    results: list[dict[str, Any]] = []
    for finding in findings_to_export:
        key = f"{finding.scanner}:{finding.rule_id}"
        rule_index = rule_indices[key]
        results.append(_build_result(finding, rule_index, result.repo_root))

    # Build invocation
    invocation: dict[str, Any] = {
        "executionSuccessful": not result.partial,
        "startTimeUtc": result.started_at.isoformat() + "Z",
    }
    if result.finished_at:
        invocation["endTimeUtc"] = result.finished_at.isoformat() + "Z"

    # Build the complete SARIF document
    sarif: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VibeGuard",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/hsvibeguard/vibeguard-cli",
                        "rules": rules,
                    },
                    "extensions": [
                        {
                            "name": scanner,
                            "version": "1.0.0",
                        }
                        for scanner in result.scanners_run
                    ],
                },
                "invocations": [invocation],
                "results": results,
            }
        ],
    }

    return sarif
