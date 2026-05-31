"""Standalone HTML report generator with embedded CSS."""

import html
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from vibeguard import __version__
from vibeguard.models.finding import Severity
from vibeguard.models.scan_result import ScanResult
from vibeguard.models.triage import TriageReason

# Color mapping for severities
SEVERITY_COLORS = {
    Severity.CRITICAL: "#ef4444",  # Red
    Severity.HIGH: "#f97316",  # Orange
    Severity.MEDIUM: "#eab308",  # Yellow
    Severity.LOW: "#3b82f6",  # Blue
    Severity.INFO: "#6b7280",  # Gray
}

# Grade colors
GRADE_COLORS = {
    "A+": "#22c55e",
    "A": "#22c55e",
    "B": "#3b82f6",
    "C": "#eab308",
    "D": "#f97316",
    "F": "#ef4444",
}

# Triage reason labels
TRIAGE_REASON_LABELS = {
    TriageReason.NONE: "Actionable",
    TriageReason.VCS_OBJECT: "VCS Object",
    TriageReason.GENERATED_CACHE: "Cache/Generated",
    TriageReason.TEST_FIXTURE: "Test Fixture",
    TriageReason.EXAMPLE_SECRET: "Example Secret",
    TriageReason.TEMP_FILE: "Temp File",
    TriageReason.THIRD_PARTY: "Third Party",
    TriageReason.LOW_CONFIDENCE: "Low Confidence",
    TriageReason.BASELINE_MATCH: "Baseline Match",
    TriageReason.USER_IGNORE: "User Ignored",
}

CSS_STYLES = """
:root {
    --bg-primary: #0f172a;
    --bg-secondary: #1e293b;
    --bg-tertiary: #334155;
    --text-primary: #f1f5f9;
    --text-secondary: #94a3b8;
    --border-color: #475569;
    --accent: #8b5cf6;
    --success: #22c55e;
    --warning: #eab308;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family:
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        Roboto,
        "Helvetica Neue",
        Arial,
        sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    min-height: 100vh;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 2rem;
}

header {
    text-align: center;
    padding: 2rem 0;
    border-bottom: 1px solid var(--border-color);
    margin-bottom: 2rem;
}

.logo {
    font-size: 2.5rem;
    font-weight: 700;
    background: linear-gradient(135deg, var(--accent), #06b6d4);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 0.5rem;
}

.tagline {
    color: var(--text-secondary);
    font-size: 1rem;
}

/* Executive Summary */
.executive-summary {
    background: var(--bg-secondary);
    border-radius: 1rem;
    padding: 2rem;
    margin-bottom: 2rem;
    display: grid;
    grid-template-columns: 1fr 2fr;
    gap: 2rem;
    align-items: center;
}

.score-section {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 1rem;
}

.score-badge {
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 1.5rem 2rem;
    background: var(--bg-tertiary);
    border-radius: 1rem;
    border: 2px solid var(--border-color);
}

.score-value {
    font-size: 3rem;
    font-weight: 700;
}

.score-label {
    color: var(--text-secondary);
    font-size: 0.875rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
}

.grade-badge {
    font-size: 2rem;
    font-weight: 700;
    padding: 1rem 1.5rem;
    border-radius: 0.5rem;
}

.triage-summary {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 1rem;
}

.triage-card {
    background: var(--bg-tertiary);
    padding: 1.5rem;
    border-radius: 0.5rem;
    text-align: center;
}

.triage-card .count {
    font-size: 2.5rem;
    font-weight: 700;
}

.triage-card .label {
    color: var(--text-secondary);
    font-size: 0.875rem;
}

.triage-card.actionable .count { color: #ef4444; }
.triage-card.needs-review .count { color: #eab308; }
.triage-card.suppressed .count { color: #22c55e; }

.noise-indicator {
    grid-column: 1 / -1;
    background: var(--bg-tertiary);
    padding: 1rem;
    border-radius: 0.5rem;
    text-align: center;
}

.noise-header {
    display: flex;
    justify-content: space-between;
    font-size: 0.875rem;
}

.noise-bar {
    height: 8px;
    background: #374151;
    border-radius: 4px;
    overflow: hidden;
    margin: 0.5rem 0;
}

.noise-fill {
    height: 100%;
    background: linear-gradient(90deg, #22c55e, #3b82f6);
    transition: width 0.3s ease;
}

/* Meta info */
.meta-info {
    text-align: center;
    color: var(--text-secondary);
    margin-bottom: 2rem;
    font-size: 0.875rem;
}

/* Severity chips */
.severity-summary {
    display: flex;
    justify-content: center;
    gap: 1rem;
    flex-wrap: wrap;
    margin-bottom: 2rem;
}

.severity-chip {
    padding: 0.5rem 1rem;
    border-radius: 2rem;
    font-weight: 600;
    font-size: 0.875rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.severity-count {
    background: rgba(255, 255, 255, 0.2);
    padding: 0.125rem 0.5rem;
    border-radius: 1rem;
    font-size: 0.75rem;
}

/* Scanners info */
.scanners-info {
    background: var(--bg-secondary);
    padding: 1rem;
    border-radius: 0.5rem;
    margin-bottom: 2rem;
    text-align: center;
}

.scanners-info .label {
    color: var(--text-secondary);
    font-size: 0.875rem;
}

.scanners-info .value {
    font-weight: 600;
}

/* Warnings */
.partial-warning {
    background: rgba(234, 179, 8, 0.2);
    border: 1px solid #eab308;
    color: #fde047;
    padding: 1rem;
    border-radius: 0.5rem;
    margin-bottom: 2rem;
    text-align: center;
}

/* Findings sections */
.findings-section {
    background: var(--bg-secondary);
    border-radius: 0.5rem;
    overflow: hidden;
    margin-bottom: 2rem;
}

.findings-header {
    padding: 1rem 1.5rem;
    border-bottom: 1px solid var(--border-color);
    font-weight: 600;
    font-size: 1.125rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    cursor: pointer;
}

.findings-header:hover {
    background: var(--bg-tertiary);
}

.findings-header .toggle {
    color: var(--text-secondary);
}

.findings-content {
    max-height: 2000px;
    overflow: hidden;
    transition: max-height 0.3s ease;
}

.findings-content.collapsed {
    max-height: 0;
}

.findings-table {
    width: 100%;
    border-collapse: collapse;
}

.findings-table th {
    text-align: left;
    padding: 0.75rem 1rem;
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    font-weight: 600;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.findings-table td {
    padding: 0.75rem 1rem;
    border-bottom: 1px solid var(--border-color);
    vertical-align: top;
    font-size: 0.875rem;
}

.findings-table tr:last-child td {
    border-bottom: none;
}

.findings-table tr:hover {
    background: var(--bg-tertiary);
}

/* Badges */
.severity-badge {
    display: inline-block;
    padding: 0.25rem 0.5rem;
    border-radius: 0.25rem;
    font-weight: 600;
    font-size: 0.75rem;
    text-transform: uppercase;
}

.triage-badge {
    display: inline-block;
    padding: 0.25rem 0.5rem;
    border-radius: 0.25rem;
    font-size: 0.7rem;
    background: var(--bg-tertiary);
    color: var(--text-secondary);
}

/* Code elements */
.file-path {
    font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
    font-size: 0.8125rem;
    color: var(--accent);
    word-break: break-all;
}

.line-number {
    font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
    color: var(--text-secondary);
}

.rule-id {
    font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
    font-size: 0.8125rem;
    color: var(--text-secondary);
}

.message {
    max-width: 400px;
}

.code-snippet {
    background: var(--bg-primary);
    padding: 0.75rem;
    border-radius: 0.25rem;
    font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
    font-size: 0.75rem;
    margin-top: 0.5rem;
    overflow-x: auto;
    white-space: pre;
    line-height: 1.4;
}

.code-snippet .line-highlight {
    background: rgba(239, 68, 68, 0.2);
    display: block;
    margin: 0 -0.75rem;
    padding: 0 0.75rem;
}

/* Empty state */
.no-findings {
    text-align: center;
    padding: 3rem;
    color: var(--text-secondary);
}

.no-findings .icon {
    font-size: 3rem;
    margin-bottom: 1rem;
}

/* Suppressed breakdown */
.suppressed-breakdown {
    padding: 1rem 1.5rem;
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
}

.suppressed-tag {
    background: var(--bg-tertiary);
    padding: 0.25rem 0.75rem;
    border-radius: 1rem;
    font-size: 0.75rem;
    color: var(--text-secondary);
}

/* Footer */
footer {
    text-align: center;
    padding: 2rem;
    color: var(--text-secondary);
    font-size: 0.75rem;
    border-top: 1px solid var(--border-color);
    margin-top: 2rem;
}

/* Responsive */
@media (max-width: 768px) {
    .container {
        padding: 1rem;
    }

    .executive-summary {
        grid-template-columns: 1fr;
    }

    .triage-summary {
        grid-template-columns: 1fr;
    }

    .findings-table {
        display: block;
        overflow-x: auto;
    }
}

@media print {
    body {
        background: white;
        color: black;
    }

    .findings-table tr:hover {
        background: transparent;
    }
}
"""

JS_TOGGLE = """
<script>
function toggleSection(id) {
    const content = document.getElementById(id);
    const header = content.previousElementSibling;
    const toggle = header.querySelector('.toggle');
    content.classList.toggle('collapsed');
    toggle.textContent = content.classList.contains('collapsed') ? '▶' : '▼';
}
</script>
"""


def _escape(text: str) -> str:
    """Escape HTML entities to prevent XSS."""
    return html.escape(str(text))


def _format_datetime(dt: datetime) -> str:
    """Format datetime for display."""
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _load_code_context(
    file_path: str, line_start: int, repo_root: str, context_lines: int = 3
) -> str | None:
    """Load actual code from disk with context lines.

    Args:
        file_path: Path to the file
        line_start: Line number of the finding
        repo_root: Root directory of the scanned repo
        context_lines: Number of lines before/after to include

    Returns:
        Formatted code snippet with line numbers, or None if file can't be read

    Security:
        Validates that the resolved file path is within repo_root to prevent
        path traversal attacks (e.g., ../../.ssh/id_rsa).
    """
    try:
        # Resolve repo_root to absolute path
        repo_root_path = Path(repo_root).resolve()

        path = Path(file_path)
        if path.is_absolute():
            # Absolute paths: resolve and verify under repo_root
            resolved_path = path.resolve()
        else:
            # Relative paths: resolve relative to repo_root
            resolved_path = (repo_root_path / path).resolve()

        # Security check: ensure resolved path is within repo_root
        # This prevents path traversal attacks via symlinks or ../ sequences
        try:
            resolved_path.relative_to(repo_root_path)
        except ValueError:
            # Path escapes repo_root boundary - reject for security
            return None

        if not resolved_path.exists() or not resolved_path.is_file():
            return None

        # Additional check: don't follow symlinks to files outside repo
        if resolved_path.is_symlink():
            real_target = resolved_path.resolve(strict=True)
            try:
                real_target.relative_to(repo_root_path)
            except ValueError:
                # Symlink points outside repo_root - reject
                return None

        lines = resolved_path.read_text(encoding="utf-8", errors="replace").splitlines()

        start = max(0, line_start - context_lines - 1)
        end = min(len(lines), line_start + context_lines)

        result_lines = []
        for i in range(start, end):
            line_num = i + 1
            is_target = line_num == line_start
            prefix = f"{line_num:4d} | "
            escaped_line = _escape(lines[i])
            if is_target:
                result_lines.append(f'<span class="line-highlight">{prefix}{escaped_line}</span>')
            else:
                result_lines.append(f"{prefix}{escaped_line}")

        return "\n".join(result_lines)
    except Exception:
        return None


def to_html(result: ScanResult) -> str:
    """Convert ScanResult to standalone HTML report.

    Generates a complete HTML document with embedded CSS that can be
    viewed in any browser without external dependencies.

    Args:
        result: The scan result to convert

    Returns:
        Complete HTML document as string
    """
    grade_color = GRADE_COLORS.get(result.grade, "#6b7280")

    # Triage counts
    actionable_count = len(result.actionable_findings)
    needs_review_count = len(result.needs_review_findings)
    ignored_count = len(result.ignored_findings)
    total_count = len(result.findings)
    noise_pct = (ignored_count / total_count * 100) if total_count > 0 else 0

    # Build severity summary chips (actionable only)
    severity_chips = []
    c = result.counts
    severity_data = [
        (Severity.CRITICAL, c.critical, "Critical"),
        (Severity.HIGH, c.high, "High"),
        (Severity.MEDIUM, c.medium, "Medium"),
        (Severity.LOW, c.low, "Low"),
        (Severity.INFO, c.info, "Info"),
    ]

    for severity, count, label in severity_data:
        color = SEVERITY_COLORS[severity]
        severity_chips.append(
            f'<span class="severity-chip" style="background: {color}20; color: {color};">'
            f'{label} <span class="severity-count">{count}</span></span>'
        )

    # Build suppressed breakdown
    suppressed_by_reason: dict[str, int] = defaultdict(int)
    for finding in result.ignored_findings:
        reason_label = TRIAGE_REASON_LABELS.get(finding.triage_reason, finding.triage_reason.value)
        suppressed_by_reason[reason_label] += 1

    suppressed_tags = "".join(
        f'<span class="suppressed-tag">{_escape(reason)}: {count}</span>'
        for reason, count in sorted(suppressed_by_reason.items(), key=lambda x: -x[1])
    )

    # Build actionable findings rows (top priority)
    actionable_rows = []
    findings_to_show = result.actionable_findings[:50]  # Limit to top 50

    for finding in findings_to_show:
        severity_color = SEVERITY_COLORS[finding.severity]

        # Try to load actual code from disk, fallback to scanner snippet
        snippet_html = ""
        code = _load_code_context(finding.file_path, finding.line_start, result.repo_root)
        if code:
            snippet_html = f'<div class="code-snippet">{code}</div>'
        elif finding.code_snippet:
            snippet_html = f'<div class="code-snippet">{_escape(finding.code_snippet[:500])}</div>'

        actionable_rows.append(f"""
            <tr>
                <td>
                    <span class="severity-badge"
                        style="background: {severity_color}20; color: {severity_color};">
                        {_escape(finding.severity.value)}
                    </span>
                </td>
                <td>{_escape(finding.scanner)}</td>
                <td class="file-path">{_escape(finding.file_path)}</td>
                <td class="line-number">
                    {finding.line_start}{f'-{finding.line_end}' if finding.line_end else ''}
                </td>
                <td class="rule-id">{_escape(finding.rule_id)}</td>
                <td class="message">
                    {_escape(finding.message[:300])}
                    {snippet_html}
                </td>
            </tr>
        """)

    # Actionable findings section
    if actionable_rows:
        omitted = actionable_count - len(actionable_rows)
        omitted_note = (
            f'<p style="padding: 1rem; color: var(--text-secondary); text-align: center;">'
            f'Showing top 50 of {actionable_count} actionable findings ({omitted} more)</p>'
            if omitted > 0
            else ""
        )
        actionable_content = f"""
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Scanner</th>
                        <th>File</th>
                        <th>Line</th>
                        <th>Rule</th>
                        <th>Message</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(actionable_rows)}
                </tbody>
            </table>
            {omitted_note}
        """
    else:
        actionable_content = """
            <div class="no-findings">
                <div class="icon">&#10003;</div>
                <p>No actionable security findings. Great job!</p>
            </div>
        """

    # Build needs review rows
    needs_review_rows = []
    for finding in result.needs_review_findings[:20]:
        severity_color = SEVERITY_COLORS[finding.severity]
        reason_label = TRIAGE_REASON_LABELS.get(finding.triage_reason, finding.triage_reason.value)

        needs_review_rows.append(f"""
            <tr>
                <td>
                    <span class="severity-badge"
                        style="background: {severity_color}20; color: {severity_color};">
                        {_escape(finding.severity.value)}
                    </span>
                </td>
                <td>{_escape(finding.scanner)}</td>
                <td class="file-path">{_escape(finding.file_path)}</td>
                <td class="line-number">{finding.line_start}</td>
                <td class="rule-id">{_escape(finding.rule_id)}</td>
                <td><span class="triage-badge">{_escape(reason_label)}</span></td>
            </tr>
        """)

    needs_review_section = ""
    if needs_review_rows:
        omitted = needs_review_count - len(needs_review_rows)
        omitted_note = (
            f'<p style="padding: 0.5rem 1rem; color: var(--text-secondary); font-size: 0.75rem;">'
            f'Showing 20 of {needs_review_count} ({omitted} more)</p>'
            if omitted > 0
            else ""
        )
        needs_review_section = f"""
        <section class="findings-section">
            <div class="findings-header" onclick="toggleSection('needs-review-content')">
                <span>Needs Review ({needs_review_count})</span>
                <span class="toggle">▼</span>
            </div>
            <div id="needs-review-content" class="findings-content">
                <table class="findings-table">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Scanner</th>
                            <th>File</th>
                            <th>Line</th>
                            <th>Rule</th>
                            <th>Reason</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(needs_review_rows)}
                    </tbody>
                </table>
                {omitted_note}
            </div>
        </section>
        """

    # Build suppressed findings rows (collapsed by default)
    suppressed_rows = []
    for finding in result.ignored_findings[:100]:
        reason_label = TRIAGE_REASON_LABELS.get(finding.triage_reason, finding.triage_reason.value)

        suppressed_rows.append(f"""
            <tr>
                <td>{_escape(finding.scanner)}</td>
                <td class="file-path">{_escape(finding.file_path)}</td>
                <td class="line-number">{finding.line_start}</td>
                <td class="rule-id">{_escape(finding.rule_id)}</td>
                <td><span class="triage-badge">{_escape(reason_label)}</span></td>
            </tr>
        """)

    suppressed_section = ""
    if suppressed_rows:
        omitted = ignored_count - len(suppressed_rows)
        omitted_note = (
            f'<p style="padding: 0.5rem 1rem; color: var(--text-secondary); font-size: 0.75rem;">'
            f'Showing 100 of {ignored_count} ({omitted} more)</p>'
            if omitted > 0
            else ""
        )
        suppressed_section = f"""
        <section class="findings-section">
            <div class="findings-header" onclick="toggleSection('suppressed-content')">
                <span>Suppressed Findings ({ignored_count})</span>
                <span class="toggle">▶</span>
            </div>
            <div id="suppressed-content" class="findings-content collapsed">
                <div class="suppressed-breakdown">
                    {suppressed_tags}
                </div>
                <table class="findings-table">
                    <thead>
                        <tr>
                            <th>Scanner</th>
                            <th>File</th>
                            <th>Line</th>
                            <th>Rule</th>
                            <th>Reason</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(suppressed_rows)}
                    </tbody>
                </table>
                {omitted_note}
            </div>
        </section>
        """

    # Build partial scan warning
    partial_warning = ""
    if result.partial:
        partial_warning = """
            <div class="partial-warning">
                <strong>Warning:</strong> This scan is partial. Some scanners failed to complete.
            </div>
        """

    # Scanners info
    scanners_run = ", ".join(result.scanners_run) if result.scanners_run else "None"
    scanners_skipped = (
        ", ".join(result.scanners_skipped) if result.scanners_skipped else "None"
    )

    finished_at = (
        _format_datetime(result.finished_at) if result.finished_at else "In progress"
    )
    skipped_html = ""
    if result.scanners_skipped:
        skipped_html = (
            ' | <span class="label">Skipped:</span> '
            f'<span class="value">{_escape(scanners_skipped)}</span>'
        )

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VibeGuard Security Report</title>
    <style>
{CSS_STYLES}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">VibeGuard</div>
            <div class="tagline">Security Scan Report</div>
        </header>

        <!-- Executive Summary -->
        <section class="executive-summary">
            <div class="score-section">
                <div class="score-badge">
                    <span class="score-value">{result.score}</span>
                    <span class="score-label">Security Score</span>
                </div>
                <div class="grade-badge" style="background: {grade_color}20; color: {grade_color};">
                    {result.grade}
                </div>
            </div>

            <div class="triage-summary">
                <div class="triage-card actionable">
                    <div class="count">{actionable_count}</div>
                    <div class="label">Actionable</div>
                </div>
                <div class="triage-card needs-review">
                    <div class="count">{needs_review_count}</div>
                    <div class="label">Needs Review</div>
                </div>
                <div class="triage-card suppressed">
                    <div class="count">{ignored_count}</div>
                    <div class="label">Suppressed</div>
                </div>
                <div class="noise-indicator">
                    <div class="noise-header">
                        <span>Noise Ratio</span>
                        <span>{noise_pct:.1f}%</span>
                    </div>
                    <div class="noise-bar">
                        <div class="noise-fill" style="width: {noise_pct}%;"></div>
                    </div>
                    <div style="font-size: 0.75rem; color: var(--text-secondary);">
                        {ignored_count} of {total_count} findings auto-suppressed
                    </div>
                </div>
            </div>
        </section>

        <div class="meta-info">
            <p>Scanned: <strong>{_escape(result.repo_root)}</strong></p>
            <p>Started: {_format_datetime(result.started_at)} | Finished: {finished_at}</p>
        </div>

        <div class="severity-summary">
            {''.join(severity_chips)}
        </div>

        <div class="scanners-info">
            <span class="label">Scanners Run:</span>
            <span class="value">{_escape(scanners_run)}</span>
            {skipped_html}
        </div>

        {partial_warning}

        <!-- Actionable Findings (Primary Focus) -->
        <section class="findings-section">
            <div class="findings-header">
                Actionable Findings ({actionable_count})
            </div>
            <div class="findings-content">
                {actionable_content}
            </div>
        </section>

        {needs_review_section}

        {suppressed_section}

        <footer>
            Generated by VibeGuard v{__version__} | {_format_datetime(datetime.now(UTC))}
        </footer>
    </div>
    {JS_TOGGLE}
</body>
</html>"""

    return html_doc
