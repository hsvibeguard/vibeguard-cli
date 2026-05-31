"""Finding deduplication logic."""

from vibeguard.models.finding import Finding, Severity

# Severity priority for deduplication (lower = higher priority to keep)
SEVERITY_PRIORITY: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

# Line proximity for grouping similar findings
LINE_PROXIMITY = 5


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings, preferring higher severity.

    Deduplication strategy:
    1. Group by normalized fingerprint (file + rule pattern + location)
    2. For duplicates at same location, keep highest severity
    3. For nearby duplicates (within LINE_PROXIMITY lines), keep one

    Args:
        findings: List of findings to deduplicate

    Returns:
        Deduplicated list of findings
    """
    if not findings:
        return []

    # Sort by severity (highest first) so we prefer critical over high, etc.
    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_PRIORITY.get(f.severity, 99),
    )

    seen: dict[str, Finding] = {}
    for finding in sorted_findings:
        key = _normalize_fingerprint(finding)

        if key not in seen:
            seen[key] = finding
        else:
            # Check if we should replace (e.g., for cross-scanner dedup)
            existing = seen[key]
            if _should_replace(existing, finding):
                seen[key] = finding

    return list(seen.values())


def _normalize_fingerprint(finding: Finding) -> str:
    """Generate a normalized fingerprint for dedup comparison.

    Groups findings that are likely the same issue:
    - Same file path
    - Same or similar rule (normalized)
    - Same or nearby line number (grouped by LINE_PROXIMITY)
    """
    # Normalize file path (strip leading ./ and normalize slashes)
    file_path = finding.file_path.replace("\\", "/").lstrip("./")

    # Normalize rule ID (extract base pattern)
    rule_base = _normalize_rule_id(finding.rule_id)

    # Group lines into buckets
    line_bucket = finding.line_start // LINE_PROXIMITY

    return f"{file_path}:{rule_base}:{line_bucket}"


def _normalize_rule_id(rule_id: str) -> str:
    """Normalize rule ID for comparison across scanners.

    Extracts core pattern to match similar rules:
    - 'B605' (Bandit) vs 'python.security.subprocess-shell' (Semgrep)
    - 'aws-access-key-id' (Gitleaks) vs 'AWS' (TruffleHog)
    """
    rule_lower = rule_id.lower()

    # Common patterns to normalize
    if any(p in rule_lower for p in ["aws", "amazon"]):
        return "aws-credential"
    if any(p in rule_lower for p in ["private", "ssh", "rsa"]):
        return "private-key"
    if any(p in rule_lower for p in ["api-key", "apikey", "api_key"]):
        return "api-key"
    if any(p in rule_lower for p in ["password", "passwd"]):
        return "password"
    if any(p in rule_lower for p in ["eval", "exec"]):
        return "code-execution"
    if any(p in rule_lower for p in ["inject", "sqli"]):
        return "injection"
    if any(p in rule_lower for p in ["shell", "command", "subprocess"]):
        return "command-injection"
    if any(p in rule_lower for p in ["xss", "cross-site"]):
        return "xss"
    if any(p in rule_lower for p in ["cve-"]):
        # Keep CVE IDs as-is for precise matching
        return rule_lower

    # Default: use the rule_id as-is (lowercase)
    return rule_lower


def _should_replace(existing: Finding, candidate: Finding) -> bool:
    """Determine if candidate should replace existing finding.

    Prefers:
    1. Higher severity (already handled by sort order, so this rarely fires)
    2. More specific scanner (TruffleHog verified > generic)
    3. More detailed message
    """
    # If candidate has higher severity, replace
    existing_priority = SEVERITY_PRIORITY.get(existing.severity, 99)
    candidate_priority = SEVERITY_PRIORITY.get(candidate.severity, 99)
    if candidate_priority < existing_priority:
        return True

    # Prefer scanners that provide more context
    if candidate.cwe and not existing.cwe:
        return True
    if len(candidate.references) > len(existing.references):
        return True

    return False


def group_findings_by_file(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Group findings by file path for reporting.

    Args:
        findings: List of findings to group

    Returns:
        Dictionary mapping file paths to their findings
    """
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        file_path = finding.file_path
        if file_path not in grouped:
            grouped[file_path] = []
        grouped[file_path].append(finding)

    # Sort findings within each file by line number
    for file_findings in grouped.values():
        file_findings.sort(key=lambda f: f.line_start)

    return grouped


def count_by_scanner(findings: list[Finding]) -> dict[str, int]:
    """Count findings by scanner.

    Args:
        findings: List of findings to count

    Returns:
        Dictionary mapping scanner names to finding counts
    """
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.scanner] = counts.get(finding.scanner, 0) + 1
    return counts
