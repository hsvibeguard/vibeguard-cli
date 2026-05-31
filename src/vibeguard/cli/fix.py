"""Fix command - generates copy-paste prompts for manual LLM use (FREE tier)."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import questionary
import typer
from questionary import Style
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from vibeguard.cli.display import get_console
from vibeguard.core.cache import load_latest_scan
from vibeguard.core.exit_codes import ExitCode
from vibeguard.models.auth import Bundle
from vibeguard.models.finding import Finding, Severity

console = get_console()

# Questionary style matching VibeGuard branding
_style = Style([
    ("qmark", "fg:#673ab7 bold"),
    ("question", "bold"),
    ("answer", "fg:#00ff00 bold"),
    ("pointer", "fg:#673ab7 bold"),
    ("highlighted", "fg:#673ab7 bold"),
    ("selected", "fg:#00ff00"),
])

# Severity colors for display
SEVERITY_COLORS = {
    Severity.CRITICAL: "red bold",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

# Prompt template for security fixes (hardcoded fallback)
_DEFAULT_FIX_PROMPT = """\
You are a security expert helping fix a vulnerability in code.

## Finding Details
- **Scanner**: {scanner}
- **Rule**: {rule_id}
- **Severity**: {severity}
- **File**: {file_path}
- **Line**: {line_start}{line_end_str}
{cwe_section}
## Issue Description
{message}

## Affected Code
```
{code_snippet}
```

## Your Task
Generate a minimal, safe fix for this security issue. Follow these rules:

### Patch Safety Rules
1. Make minimal changes only - fix the vulnerability, nothing else
2. Do not add new dependencies unless absolutely required
3. Do not include any secrets, tokens, or credentials in your response
4. Preserve the existing code style and formatting
5. Output ONLY a valid unified diff (starting with --- and +++)
6. If you are uncertain about the fix, include a comment: # MANUAL_REVIEW_REQUIRED

### Expected Output Format
```diff
--- a/{file_path}
+++ b/{file_path}
@@ -line,count +line,count @@
 context line
-removed line
+added line
 context line
```

Generate the patch now:
"""


def fix(
    finding_id: str | None = typer.Argument(
        None,
        help="Finding ID (or prefix). If not provided, opens interactive mode.",
    ),
    path: Path = typer.Option(
        Path("."),
        "--path",
        "-p",
        help="Path to the scanned repository",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
    interactive: bool = typer.Option(
        None,
        "--interactive",
        "-i",
        help="Force interactive mode for selecting findings",
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        "-s",
        help="Filter by minimum severity (critical, high, medium, low)",
    ),
    bulk: bool = typer.Option(
        False,
        "--bulk",
        "-b",
        help="Bulk mode - select multiple findings to generate prompts for",
    ),
) -> None:
    """Generate a copy-paste prompt for fixing a security finding.

    This is a FREE feature. The prompt can be pasted into ChatGPT, Claude,
    or any other LLM to generate a fix.

    Run without arguments for interactive mode to browse and select findings.

    Example:
        vibeguard fix                    # Interactive mode
        vibeguard fix --bulk             # Select multiple findings
        vibeguard fix --severity high    # Filter by severity
        vibeguard fix abc123def456       # Generate prompt for specific finding
        vibeguard fix abc123             # Prefix matching
    """
    target = path.resolve()

    # Load cached bundle for prompt templates (no fetch - fix is FREE tier)
    from vibeguard.core.bundles import load_cached_bundle

    bundle = load_cached_bundle()

    # Load latest scan
    scan_result = load_latest_scan(target)

    if scan_result is None:
        console.print("[red]Error:[/red] No cached scan found.")
        console.print("Run [cyan]vibeguard scan[/cyan] first.")
        raise typer.Exit(ExitCode.NO_CACHE)

    # Use actionable findings only (triage-suppressed findings should not be prompted)
    if not scan_result.actionable_findings:
        if scan_result.findings:
            console.print(
                "[yellow]No actionable findings in cached scan.[/yellow] "
                f"({len(scan_result.findings)} suppressed by triage)"
            )
        else:
            console.print("[yellow]No findings in cached scan.[/yellow]")
        raise typer.Exit(ExitCode.SUCCESS)

    # Filter by severity if specified (from actionable findings only)
    findings = scan_result.actionable_findings
    if severity:
        min_severity = _parse_severity(severity)
        if min_severity is None:
            console.print(f"[red]Error:[/red] Invalid severity: {severity}")
            console.print("Valid options: critical, high, medium, low")
            raise typer.Exit(ExitCode.CONFIG_ERROR)
        severities = _get_severities_at_or_above(min_severity)
        findings = [f for f in findings if f.severity.value in severities]

    if not findings:
        console.print(f"[yellow]No findings matching severity filter: {severity}[/yellow]")
        raise typer.Exit(ExitCode.SUCCESS)

    # Determine if we should use interactive mode
    use_interactive = finding_id is None or interactive is True

    if use_interactive:
        # Interactive mode - main loop
        _interactive_fix_loop(findings, target, bulk, bundle=bundle)
        raise typer.Exit(ExitCode.SUCCESS)

    # Non-interactive mode - use provided finding_id
    # finding_id is guaranteed non-None here (interactive mode exits above)
    if finding_id is None:  # pragma: no cover
        raise RuntimeError("finding_id should not be None in non-interactive mode")
    finding: Finding | None = _find_finding(findings, finding_id)

    if finding is None:
        console.print(f"[red]Error:[/red] Finding not found: {finding_id}")
        console.print(
            "\n[dim]Tip: Run [cyan]vibeguard fix[/cyan] without arguments "
            "for interactive mode.[/dim]"
        )
        console.print("\nAvailable finding IDs:")
        for f in findings[:10]:
            color = SEVERITY_COLORS.get(f.severity, "white")
            console.print(
                f"  [green]{f.id[:12]}[/green]  [{color}]{f.severity.value:8}[/{color}]  "
                f"{f.title[:50]}"
            )
        if len(findings) > 10:
            console.print(f"  [dim]... and {len(findings) - 10} more[/dim]")
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    # Generate prompt for the single finding
    prompt = build_fix_prompt(finding, target, bundle=bundle)

    # In non-interactive mode (finding_id provided), just display and exit
    # Check if we're in a TTY for action menu
    import sys
    is_tty = sys.stdin.isatty() and sys.stdout.isatty()

    if is_tty:
        # Show prompt and action menu
        prompts = [(finding, prompt)]
        _display_prompts(prompts)
        _prompt_action_menu(prompts, findings, target, bulk=False)
    else:
        # Non-TTY: just display the prompt
        _display_single_prompt(finding, prompt)

    raise typer.Exit(ExitCode.SUCCESS)


def _interactive_fix_loop(
    findings: list[Finding],
    target: Path,
    bulk: bool,
    *,
    bundle: Bundle | None = None,
) -> None:
    """Main interactive loop for fix command.

    Args:
        findings: List of findings to choose from
        target: Repository root path
        bulk: Whether bulk mode is enabled
        bundle: Optional policy bundle for prompt templates
    """
    while True:
        console.print()
        _show_findings_summary(findings)
        console.print()

        # Select findings
        if bulk:
            selected_findings = _interactive_bulk_select(findings)
        else:
            selected_findings = _interactive_single_select(findings)

        if not selected_findings:
            console.print("[dim]No findings selected. Exiting.[/dim]")
            return

        # Generate and display prompts
        prompts = [
            (f, build_fix_prompt(f, target, bundle=bundle))
            for f in selected_findings
        ]
        _display_prompts(prompts)

        # Show action menu and handle user choice
        action = _prompt_action_menu(prompts, findings, target, bulk)

        if action == "exit":
            return
        elif action == "back":
            # Continue the loop to show selection again
            continue


def _display_single_prompt(finding: Finding, prompt: str) -> None:
    """Display a single fix prompt (non-interactive mode).

    Args:
        finding: The finding being fixed
        prompt: The generated prompt text
    """
    console.print(
        Panel.fit(
            f"[bold]{finding.title}[/bold]\n"
            f"[dim]{finding.file_path}:{finding.line_start}[/dim]",
            title="Generating fix prompt for",
        )
    )
    console.print()
    console.print("[bold cyan]Copy this prompt and paste into your LLM:[/bold cyan]")
    console.print()

    # Use syntax highlighting for the prompt
    syntax = Syntax(prompt, "markdown", theme="monokai", line_numbers=False)
    console.print(Panel(syntax, title="Fix Prompt", border_style="cyan"))

    console.print()
    console.print("[dim]Tip: Use 'vibeguard patch' for automatic LLM patch generation[/dim]")
    console.print("[dim]Tip: Run 'vibeguard fix' without arguments for interactive mode[/dim]")


def _display_prompts(prompts: list[tuple[Finding, str]]) -> None:
    """Display all generated prompts.

    Args:
        prompts: List of (finding, prompt_text) tuples
    """
    total = len(prompts)

    for i, (finding, prompt) in enumerate(prompts):
        console.print()

        # Show progress indicator
        if total > 1:
            console.print(f"[dim]Prompt {i + 1} of {total}[/dim]")

        # Display finding header
        console.print(
            Panel.fit(
                f"[bold]{finding.title}[/bold]\n"
                f"[dim]{finding.file_path}:{finding.line_start}[/dim]",
                title="Fix Prompt",
            )
        )
        console.print()

        # Use syntax highlighting for the prompt
        syntax = Syntax(prompt, "markdown", theme="monokai", line_numbers=False)
        console.print(Panel(syntax, border_style="cyan"))


def _prompt_action_menu(
    prompts: list[tuple[Finding, str]],
    all_findings: list[Finding],
    target: Path,
    bulk: bool,
) -> str:
    """Show action menu after displaying prompts.

    Args:
        prompts: List of (finding, prompt_text) tuples
        all_findings: Full list of findings for re-selection
        target: Repository root path
        bulk: Whether bulk mode is enabled

    Returns:
        Action taken: "exit", "back", or "continue"
    """
    total = len(prompts)
    prompt_text = "prompt" if total == 1 else f"{total} prompts"

    console.print()
    console.print(f"[bold green]Generated {prompt_text}![/bold green]")
    console.print()

    while True:
        # Build choices based on number of prompts
        choices = []

        # Copy options
        if total == 1:
            choices.append(
                questionary.Choice(
                    title="Copy prompt to clipboard",
                    value="copy"
                )
            )
        else:
            choices.extend([
                questionary.Choice(
                    title=f"Copy all {total} prompts to clipboard",
                    value="copy_all"
                ),
                questionary.Choice(
                    title="Copy prompts individually →",
                    value="copy_individual"
                ),
            ])

        # Export options
        choices.extend([
            questionary.Choice(
                title="Export as Markdown (.md)",
                value="export_md"
            ),
            questionary.Choice(
                title="Export as Text (.txt)",
                value="export_txt"
            ),
        ])

        # Navigation options
        choices.extend([
            questionary.Choice(
                title="← Select different finding(s)",
                value="back"
            ),
            questionary.Choice(
                title="Exit",
                value="exit"
            ),
        ])

        selection = questionary.select(
            "What would you like to do?",
            choices=choices,
            style=_style,
        ).ask()

        if selection is None or selection == "exit":
            return "exit"

        if selection == "back":
            return "back"

        if selection == "copy":
            _copy_to_clipboard([prompts[0][1]])
            console.print("[green]Prompt copied to clipboard![/green]")
            continue

        if selection == "copy_all":
            all_texts = [p[1] for p in prompts]
            _copy_to_clipboard(all_texts)
            console.print(f"[green]All {total} prompts copied to clipboard![/green]")
            continue

        if selection == "copy_individual":
            _copy_individual_prompts(prompts)
            continue

        if selection == "export_md":
            filepath = _export_prompts(prompts, "md", target)
            if filepath:
                console.print(f"[green]Exported to:[/green] {filepath}")
            continue

        if selection == "export_txt":
            filepath = _export_prompts(prompts, "txt", target)
            if filepath:
                console.print(f"[green]Exported to:[/green] {filepath}")
            continue


def _copy_individual_prompts(prompts: list[tuple[Finding, str]]) -> None:
    """Let user select and copy individual prompts."""
    choices = []

    for i, (finding, _) in enumerate(prompts):
        label = f"{i + 1}. {finding.id[:8]}  {finding.title[:40]}"
        if len(finding.title) > 40:
            label += "..."
        choices.append(questionary.Choice(title=label, value=i))

    choices.append(questionary.Choice(title="← Back", value="back"))

    selected = questionary.select(
        "Select prompt to copy:",
        choices=choices,
        style=_style,
    ).ask()

    if selected is None or selected == "back":
        return

    _, prompt_text = prompts[selected]
    _copy_to_clipboard([prompt_text])
    console.print(f"[green]Prompt {selected + 1} copied to clipboard![/green]")


def _copy_to_clipboard(texts: list[str]) -> None:
    """Copy text(s) to clipboard.

    Args:
        texts: List of text strings to copy (joined with separator)
    """
    try:
        import pyperclip

        # Join multiple prompts with a clear separator
        if len(texts) == 1:
            combined = texts[0]
        else:
            separator = "\n\n" + "=" * 80 + "\n\n"
            combined = separator.join(texts)

        pyperclip.copy(combined)
    except ImportError:
        console.print(
            "[yellow]Warning:[/yellow] pyperclip not installed. "
            "Run: pip install pyperclip"
        )
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] Could not copy to clipboard: {e}")
        console.print("[dim]Try installing xclip (Linux) or using export instead.[/dim]")


def _export_prompts(
    prompts: list[tuple[Finding, str]],
    format_type: str,
    target: Path,
) -> Path | None:
    """Export prompts to a file.

    Args:
        prompts: List of (finding, prompt_text) tuples
        format_type: "md" or "txt"
        target: Repository root path

    Returns:
        Path to exported file, or None if failed
    """
    # Create output directory
    output_dir = target / ".vibeguard" / "prompts"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    count = len(prompts)
    filename = f"fix-prompts-{count}x-{timestamp}.{format_type}"
    filepath = output_dir / filename

    try:
        if format_type == "md":
            content = _format_prompts_markdown(prompts)
        else:
            content = _format_prompts_text(prompts)

        filepath.write_text(content, encoding="utf-8")
        return filepath
    except Exception as e:
        console.print(f"[red]Error:[/red] Could not export: {e}")
        return None


def _format_prompts_markdown(prompts: list[tuple[Finding, str]]) -> str:
    """Format prompts as Markdown document.

    Args:
        prompts: List of (finding, prompt_text) tuples

    Returns:
        Markdown-formatted string
    """
    lines = [
        "# VibeGuard Fix Prompts",
        "",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total prompts: {len(prompts)}",
        "",
        "---",
        "",
    ]

    for i, (finding, prompt) in enumerate(prompts):
        lines.extend([
            f"## Prompt {i + 1}: {finding.title}",
            "",
            f"**Finding ID:** `{finding.id[:12]}`",
            f"**Severity:** {finding.severity.value}",
            f"**File:** `{finding.file_path}:{finding.line_start}`",
            "",
            "### Copy this prompt:",
            "",
            "```",
            prompt,
            "```",
            "",
            "---",
            "",
        ])

    return "\n".join(lines)


def _format_prompts_text(prompts: list[tuple[Finding, str]]) -> str:
    """Format prompts as plain text document.

    Args:
        prompts: List of (finding, prompt_text) tuples

    Returns:
        Plain text formatted string
    """
    lines = [
        "VIBEGUARD FIX PROMPTS",
        "=" * 60,
        "",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total prompts: {len(prompts)}",
        "",
        "=" * 60,
        "",
    ]

    for i, (finding, prompt) in enumerate(prompts):
        lines.extend([
            f"PROMPT {i + 1}: {finding.title}",
            "-" * 60,
            f"Finding ID: {finding.id[:12]}",
            f"Severity: {finding.severity.value}",
            f"File: {finding.file_path}:{finding.line_start}",
            "",
            "COPY THIS PROMPT:",
            "-" * 40,
            "",
            prompt,
            "",
            "=" * 60,
            "",
        ])

    return "\n".join(lines)


def _parse_severity(severity_str: str) -> Severity | None:
    """Parse severity string to Severity enum."""
    severity_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    return severity_map.get(severity_str.lower())


def _get_severities_at_or_above(min_severity: Severity) -> list[str]:
    """Get list of severity values at or above the minimum."""
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    min_idx = order.index(min_severity)
    return [s.value for s in order[:min_idx + 1]]


def _get_severity_counts(findings: list[Finding]) -> dict[Severity, int]:
    """Get count of findings by severity."""
    counts: dict[Severity, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _show_findings_summary(findings: list[Finding]) -> None:
    """Show a summary table of findings by severity."""
    table = Table(title="Findings Summary", show_header=True)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")

    severity_counts = _get_severity_counts(findings)

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            color = SEVERITY_COLORS.get(sev, "white")
            table.add_row(f"[{color}]{sev.value}[/{color}]", str(count))

    table.add_row("[bold]Total[/bold]", f"[bold]{len(findings)}[/bold]")
    console.print(table)


def _interactive_single_select(findings: list[Finding]) -> list[Finding]:
    """Interactive mode to select a single finding."""
    severity_counts = _get_severity_counts(findings)

    choices = [
        questionary.Choice(
            title=f"Generate prompts for all findings ({len(findings)} total)",
            value="all"
        ),
        questionary.Choice(
            title="Select by severity →",
            value="by_severity"
        ),
        questionary.Choice(
            title="Pick individual finding →",
            value="individual"
        ),
        questionary.Choice(
            title="Cancel",
            value="cancel"
        ),
    ]

    selection = questionary.select(
        "How would you like to select findings?",
        choices=choices,
        style=_style,
    ).ask()

    if selection is None or selection == "cancel":
        return []

    if selection == "all":
        return findings

    if selection == "by_severity":
        return _select_by_severity(findings, severity_counts)

    if selection == "individual":
        return _select_individual(findings)

    return []


def _interactive_bulk_select(findings: list[Finding]) -> list[Finding]:
    """Interactive mode to select multiple findings for bulk prompt generation."""
    severity_counts = _get_severity_counts(findings)
    critical_high_count = severity_counts.get(Severity.CRITICAL, 0) + \
        severity_counts.get(Severity.HIGH, 0)

    choices = [
        questionary.Choice(
            title=f"Generate prompts for all findings ({len(findings)} total)",
            value="all"
        ),
    ]

    # Add critical/high shortcut if there are any
    if critical_high_count > 0:
        choices.append(
            questionary.Choice(
                title=f"Generate prompts for Critical + High ({critical_high_count} findings)",
                value="critical_high"
            )
        )

    choices.extend([
        questionary.Choice(
            title="Select by severity →",
            value="by_severity"
        ),
        questionary.Choice(
            title="Pick individual findings (multi-select) →",
            value="individual"
        ),
        questionary.Choice(
            title="Cancel",
            value="cancel"
        ),
    ])

    selection = questionary.select(
        "How would you like to select findings?",
        choices=choices,
        style=_style,
    ).ask()

    if selection is None or selection == "cancel":
        return []

    if selection == "all":
        return findings

    if selection == "critical_high":
        return [
            f for f in findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]

    if selection == "by_severity":
        return _select_by_severity_multi(findings, severity_counts)

    if selection == "individual":
        return _select_individual_multi(findings)

    return []


def _select_by_severity(
    findings: list[Finding],
    severity_counts: dict[Severity, int]
) -> list[Finding]:
    """Let user select a single severity level."""
    choices = []

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            color = SEVERITY_COLORS.get(sev, "white")
            choices.append(
                questionary.Choice(
                    title=f"[{color}]{sev.value:8}[/{color}] ({count} findings)",
                    value=sev.value
                )
            )

    choices.append(questionary.Choice(title="← Back", value="back"))

    selected = questionary.select(
        "Select severity level:",
        choices=choices,
        style=_style,
    ).ask()

    if selected is None or selected == "back":
        return []

    # Return all findings of selected severity
    return [f for f in findings if f.severity.value == selected]


def _select_by_severity_multi(
    findings: list[Finding],
    severity_counts: dict[Severity, int]
) -> list[Finding]:
    """Let user select multiple severity levels."""
    choices = []

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            color = SEVERITY_COLORS.get(sev, "white")
            # Pre-check critical and high by default
            checked = sev in (Severity.CRITICAL, Severity.HIGH)
            choices.append(
                questionary.Choice(
                    title=f"[{color}]{sev.value:8}[/{color}] ({count} findings)",
                    value=sev.value,
                    checked=checked,
                )
            )

    console.print("[dim]Space to toggle, Enter to confirm[/dim]")

    selected = questionary.checkbox(
        "Select severity levels:",
        choices=choices,
        style=_style,
    ).ask()

    if selected is None or not selected:
        return []

    # Return all findings of selected severities
    selected_set = set(selected)
    return [f for f in findings if f.severity.value in selected_set]


def _select_individual(findings: list[Finding]) -> list[Finding]:
    """Let user select a single finding."""
    choices = []

    for f in findings:
        color = SEVERITY_COLORS.get(f.severity, "white")
        severity_badge = f"[{color}]{f.severity.value:8}[/{color}]"
        label = f"{f.id[:8]}  {severity_badge}  {f.title[:45]}"
        if len(f.title) > 45:
            label += "..."
        choices.append(questionary.Choice(title=label, value=f.id))

    choices.append(questionary.Choice(title="← Back", value="back"))

    selected = questionary.select(
        "Select finding:",
        choices=choices,
        style=_style,
    ).ask()

    if selected is None or selected == "back":
        return []

    # Find and return the selected finding
    for f in findings:
        if f.id == selected:
            return [f]

    return []


def _select_individual_multi(findings: list[Finding]) -> list[Finding]:
    """Let user select multiple individual findings."""
    choices = []

    for f in findings:
        color = SEVERITY_COLORS.get(f.severity, "white")
        severity_badge = f"[{color}]{f.severity.value:8}[/{color}]"
        file_loc = f"{f.file_path}:{f.line_start}" if f.file_path else ""
        label = f"{f.id[:8]}  {severity_badge}  {f.title[:35]}"
        if file_loc:
            label += f"  ({file_loc[:25]})"
        choices.append(questionary.Choice(title=label, value=f.id))

    console.print("[dim]Space to toggle, Enter to confirm[/dim]")

    selected = questionary.checkbox(
        "Select findings:",
        choices=choices,
        style=_style,
    ).ask()

    if selected is None or not selected:
        return []

    # Return selected findings
    selected_set = set(selected)
    return [f for f in findings if f.id in selected_set]


def _find_finding(findings: list[Finding], finding_id: str) -> Finding | None:
    """Find a finding by ID or prefix.

    Args:
        findings: List of findings to search
        finding_id: Full ID or prefix to match

    Returns:
        Matching finding or None
    """
    # Try exact match first
    for f in findings:
        if f.id == finding_id:
            return f

    # Try prefix match
    for f in findings:
        if f.id.startswith(finding_id):
            return f

    return None


def build_fix_prompt(
    finding: Finding,
    repo_root: Path,
    *,
    bundle: Bundle | None = None,
) -> str:
    """Build the fix prompt from a finding.

    Uses bundle-sourced prompt template if available,
    falling back to hardcoded template.

    Args:
        finding: The finding to generate a prompt for
        repo_root: Repository root path
        bundle: Optional policy bundle for prompt templates

    Returns:
        Complete prompt string
    """
    from vibeguard.core.bundles import get_prompt

    # Select template: bundle-sourced or hardcoded fallback
    template = _DEFAULT_FIX_PROMPT
    if bundle is not None:
        template = get_prompt(bundle, "fix_prompt", _DEFAULT_FIX_PROMPT)

    # Build optional sections
    has_range = finding.line_end and finding.line_end != finding.line_start
    line_end_str = f"-{finding.line_end}" if has_range else ""

    cwe_section = ""
    if finding.cwe:
        cwe_section = f"- **CWE**: {finding.cwe}\n"
    if finding.references:
        refs = ", ".join(finding.references[:3])
        cwe_section += f"- **References**: {refs}\n"

    # Get code snippet - either from finding or read from file
    code_snippet = finding.code_snippet
    if not code_snippet:
        code_snippet = _read_code_snippet(repo_root, finding)

    if not code_snippet:
        code_snippet = "(Code snippet not available)"

    return template.format(
        scanner=finding.scanner,
        rule_id=finding.rule_id,
        severity=finding.severity.value.upper(),
        file_path=finding.file_path,
        line_start=finding.line_start,
        line_end_str=line_end_str,
        cwe_section=cwe_section,
        message=finding.message,
        code_snippet=code_snippet,
    )


def _read_code_snippet(repo_root: Path, finding: Finding) -> str | None:
    """Read code snippet from file if not in finding.

    Args:
        repo_root: Repository root path
        finding: Finding to get snippet for

    Returns:
        Code snippet with line numbers, or None if unavailable
    """
    try:
        file_path = repo_root / finding.file_path
        if not file_path.exists():
            return None

        lines = file_path.read_text(encoding="utf-8").split("\n")
        start = max(0, finding.line_start - 3)  # 2 lines before
        end_line = finding.line_end or finding.line_start
        end = min(len(lines), end_line + 3)  # 2 lines after

        snippet_lines = []
        for i in range(start, end):
            line_num = i + 1
            marker = ">>>" if finding.line_start <= line_num <= end_line else "   "
            snippet_lines.append(f"{marker} {line_num:4d} | {lines[i]}")

        return "\n".join(snippet_lines)
    except Exception:
        return None
