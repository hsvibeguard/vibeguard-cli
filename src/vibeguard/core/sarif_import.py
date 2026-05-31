"""SARIF 2.1.0 import module for external scan results.

This module parses SARIF files from external tools (CodeQL, Semgrep Cloud,
Snyk, etc.) and converts them into VibeGuard Finding objects.
"""

import json
from typing import Any

from vibeguard.models.finding import Category, Finding, Severity

# Reverse mapping: SARIF level to VibeGuard Severity
LEVEL_TO_SEVERITY: dict[str, Severity] = {
    "error": Severity.HIGH,  # Could be CRITICAL or HIGH
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}

# Security severity score to VibeGuard Severity
# SARIF security-severity ranges: 0.0-3.9=low, 4.0-6.9=medium, 7.0-8.9=high, 9.0-10.0=critical
SCORE_THRESHOLDS = [
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.0, Severity.LOW),
]


def parse_sarif(
    content: str,
    scanner_name: str | None = None,
) -> list[Finding]:
    """Parse SARIF 2.1.0 JSON into Finding objects.

    Supports SARIF files from:
    - CodeQL
    - Semgrep Cloud
    - Snyk
    - Checkmarx
    - Other SARIF 2.1.0 compliant tools

    Args:
        content: Raw SARIF JSON string
        scanner_name: Name to use for scanner field. If provided, overrides
            the tool name from SARIF metadata. If None, uses tool.driver.name
            from SARIF (falling back to "external" if not present).

    Returns:
        List of Finding objects

    Raises:
        ValueError: If content is not valid SARIF
    """
    if not content or content.strip() == "":
        return []

    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in SARIF file: {e}") from e

    # Validate SARIF structure
    if not isinstance(data, dict):
        raise ValueError("SARIF must be a JSON object")

    version = data.get("version", "")
    if not version.startswith("2."):
        raise ValueError(f"Unsupported SARIF version: {version}. Expected 2.x")

    runs = data.get("runs", [])
    if not isinstance(runs, list):
        raise ValueError("SARIF 'runs' must be an array")

    findings: list[Finding] = []

    for run in runs:
        if not isinstance(run, dict):
            continue

        # Extract tool info
        tool = run.get("tool", {})
        driver = tool.get("driver", {})
        # If scanner_name is provided (user override), use it; otherwise use SARIF tool name
        tool_name = scanner_name if scanner_name else driver.get("name", "external")

        # Build rule lookup for enrichment
        rules_list = driver.get("rules", [])
        rules_by_id = {rule.get("id", ""): rule for rule in rules_list if isinstance(rule, dict)}

        # Parse results
        results = run.get("results", [])
        for result in results:
            if not isinstance(result, dict):
                continue

            finding = _parse_result(result, rules_by_id, tool_name)
            if finding:
                findings.append(finding)

    return findings


def _parse_result(
    result: dict[str, Any],
    rules: dict[str, dict[str, Any]],
    tool_name: str,
) -> Finding | None:
    """Parse a single SARIF result into a Finding.

    Args:
        result: A result object from SARIF
        rules: Dict mapping rule IDs to rule objects
        tool_name: Name of the tool that produced this result

    Returns:
        Finding object or None if parsing fails
    """
    try:
        rule_id = result.get("ruleId", "unknown")
        rule = rules.get(rule_id, {})

        # Determine severity from multiple sources
        severity = _determine_severity(result, rule)

        # Extract location info
        locations = result.get("locations", [])
        file_path = ""
        line_start = 1
        line_end = None
        code_snippet = None

        if locations and isinstance(locations[0], dict):
            location = locations[0]
            physical = location.get("physicalLocation", {})
            artifact = physical.get("artifactLocation", {})
            region = physical.get("region", {})

            file_path = artifact.get("uri", "")
            # Remove file:// prefix if present
            if file_path.startswith("file://"):
                file_path = file_path[7:]
            # Remove leading slash on Windows paths like /C:/
            if len(file_path) > 2 and file_path[0] == "/" and file_path[2] == ":":
                file_path = file_path[1:]

            line_start = region.get("startLine", 1)
            line_end = region.get("endLine")

            snippet = region.get("snippet", {})
            if isinstance(snippet, dict):
                code_snippet = snippet.get("text")

        # Extract title and message
        title = _extract_title(rule, rule_id)
        message = _extract_message(result, rule)

        # Extract category from tags
        category = _extract_category(rule)

        # Extract CWE from tags
        cwe = _extract_cwe(rule)

        # Extract references
        references = _extract_references(result, rule)

        # Build fingerprint
        fingerprint = result.get("partialFingerprints", {}).get("primaryLocationLineHash")
        if not fingerprint:
            fingerprint = f"{tool_name}:{rule_id}:{file_path}:{line_start}"

        return Finding(
            scanner=tool_name.lower().replace(" ", "_"),
            rule_id=rule_id,
            severity=severity,
            category=category,
            title=title,
            message=message,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            cwe=cwe,
            references=references,
            code_snippet=code_snippet,
            fingerprint=fingerprint,
        )
    except Exception:
        # Skip malformed results
        return None


def _determine_severity(result: dict[str, Any], rule: dict[str, Any]) -> Severity:
    """Determine severity from SARIF result and rule.

    Priority:
    1. Rule's security-severity score (most accurate)
    2. Result's level
    3. Rule's defaultConfiguration.level
    4. Default to MEDIUM
    """
    # Try security-severity from rule properties
    props = rule.get("properties", {})
    if isinstance(props, dict):
        security_severity = props.get("security-severity")
        if security_severity:
            try:
                score = float(security_severity)
                for threshold, severity in SCORE_THRESHOLDS:
                    if score >= threshold:
                        return severity
            except (ValueError, TypeError):
                pass

    # Try result level
    level = result.get("level", "")
    if level and level in LEVEL_TO_SEVERITY:
        return LEVEL_TO_SEVERITY[level]

    # Try rule's default level
    default_config = rule.get("defaultConfiguration", {})
    if isinstance(default_config, dict):
        level = default_config.get("level", "")
        if level and level in LEVEL_TO_SEVERITY:
            return LEVEL_TO_SEVERITY[level]

    return Severity.MEDIUM


def _extract_title(rule: dict[str, Any], rule_id: str) -> str:
    """Extract title from rule."""
    # Try rule name first
    name = rule.get("name", "")
    if name:
        return name

    # Try shortDescription
    short_desc = rule.get("shortDescription", {})
    if isinstance(short_desc, dict) and short_desc.get("text"):
        return short_desc["text"]

    # Fall back to rule_id
    return rule_id


def _extract_message(result: dict[str, Any], rule: dict[str, Any]) -> str:
    """Extract message from result or rule."""
    # Try result message first
    message = result.get("message", {})
    if isinstance(message, dict) and message.get("text"):
        return message["text"]

    # Try rule fullDescription
    full_desc = rule.get("fullDescription", {})
    if isinstance(full_desc, dict) and full_desc.get("text"):
        return full_desc["text"]

    # Try rule shortDescription
    short_desc = rule.get("shortDescription", {})
    if isinstance(short_desc, dict) and short_desc.get("text"):
        return short_desc["text"]

    return "Security finding detected"


def _extract_category(rule: dict[str, Any]) -> Category:
    """Extract category from rule tags."""
    props = rule.get("properties", {})
    if not isinstance(props, dict):
        return Category.SECURITY

    tags = props.get("tags", [])
    if not isinstance(tags, list):
        return Category.SECURITY

    tags_lower = [t.lower() for t in tags if isinstance(t, str)]

    # Check for specific categories
    if "secrets" in tags_lower or "secret" in tags_lower:
        return Category.SECRETS
    if "vulnerability" in tags_lower or "cve" in tags_lower:
        return Category.VULNERABILITY
    if "misconfiguration" in tags_lower or "iac" in tags_lower:
        return Category.MISCONFIGURATION
    if "best-practice" in tags_lower or "quality" in tags_lower:
        return Category.BEST_PRACTICE

    return Category.SECURITY


def _extract_cwe(rule: dict[str, Any]) -> str | None:
    """Extract CWE from rule tags."""
    props = rule.get("properties", {})
    if not isinstance(props, dict):
        return None

    tags = props.get("tags", [])
    if not isinstance(tags, list):
        return None

    for tag in tags:
        if not isinstance(tag, str):
            continue
        # Look for patterns like "external/cwe/cwe-89" or "CWE-89"
        tag_upper = tag.upper()
        if "CWE-" in tag_upper:
            # Extract the CWE number
            parts = tag_upper.split("CWE-")
            if len(parts) > 1:
                cwe_num = parts[-1].split("/")[0].split(" ")[0]
                if cwe_num.isdigit():
                    return f"CWE-{cwe_num}"

    return None


def _extract_references(result: dict[str, Any], rule: dict[str, Any]) -> list[str]:
    """Extract references from result and rule."""
    references: list[str] = []

    # Check result's relatedLocations for URLs
    related = result.get("relatedLocations", [])
    for loc in related:
        if isinstance(loc, dict):
            msg = loc.get("message", {})
            if isinstance(msg, dict):
                text = msg.get("text", "")
                if isinstance(text, str) and text.startswith("http"):
                    references.append(text)

    # Check rule helpUri
    help_uri = rule.get("helpUri")
    if help_uri and isinstance(help_uri, str):
        references.append(help_uri)

    # Check rule help
    help_obj = rule.get("help", {})
    if isinstance(help_obj, dict):
        text = help_obj.get("text", "")
        if isinstance(text, str) and text.startswith("http"):
            references.append(text)

    return references[:5]  # Limit to 5 references
