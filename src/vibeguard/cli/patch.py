"""Patch command - generates unified diffs using BYOK LLM (PRO tier)."""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path

import questionary
import typer
from questionary import Style
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich.table import Table

from vibeguard.cli.banners import show_expiry_banner
from vibeguard.cli.display import (
    BRAND_COLOR,
    VIBEGUARD_SPINNER_NAME,
    get_console,
    get_patching_message,
)
from vibeguard.cli.fix import _find_finding, build_fix_prompt
from vibeguard.core.cache import load_latest_scan
from vibeguard.core.exit_codes import ExitCode
from vibeguard.core.license import (
    ProFeatureError,
    get_license_status_with_grace,
    require_patch_capability,
)
from vibeguard.core.llm import LLMError, LLMResponse, generate
from vibeguard.models.auth import Bundle
from vibeguard.models.finding import Finding, Severity
from vibeguard.models.patch import (
    PatchArtifact,
    extract_diff_from_response,
    validate_unified_diff,
)

console = get_console()

PATCHES_DIR = ".vibeguard/patches"

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


def patch(
    finding_id: str | None = typer.Argument(
        None,
        help="Finding ID (or prefix) to patch. If not provided, opens interactive mode.",
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
    provider: str | None = typer.Option(
        None,
        "--provider",
        help="LLM provider to use (auto-detected if not specified)",
    ),
    model: str | None = typer.Option(
        None,
        "--model",
        "-m",
        help="Specific model to use",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file (default: .vibeguard/patches/<finding-id>.patch)",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Show patch without saving",
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
        help="Bulk patch mode - select multiple findings to patch",
    ),
) -> None:
    """Generate a patch for a security finding using your LLM key.

    This is a PRO feature that requires a configured LLM API key.
    Run 'vibeguard keys set <provider> <key>' first.

    Run without arguments for interactive mode to browse and select findings.

    Example:
        vibeguard patch                    # Interactive mode
        vibeguard patch --bulk             # Select multiple findings
        vibeguard patch --severity high    # Filter by severity
        vibeguard patch abc123def456       # Patch specific finding
        vibeguard patch abc123 --dry-run   # Preview without saving
    """
    target = path.resolve()

    # Check Pro license AND BYOK LLM key
    try:
        require_patch_capability("Patch generation")
    except ProFeatureError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    # Show expiry/grace period banner if license is expiring soon
    license_status = get_license_status_with_grace()
    if license_status.get("valid"):
        show_expiry_banner(license_status)

    # Load bundle for prompt templates (Pro users can fetch from server)
    bundle = _load_bundle_for_patch()

    # Load latest scan
    scan_result = load_latest_scan(target)
    if scan_result is None:
        console.print("[red]Error:[/red] No cached scan found.")
        console.print("Run [cyan]vibeguard scan[/cyan] first.")
        raise typer.Exit(ExitCode.NO_CACHE)

    # Use actionable findings only (triage-suppressed findings should not be patched)
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
        # Interactive mode - let user select finding(s)
        if bulk:
            selected_findings = _interactive_bulk_select(findings)
        else:
            selected_findings = _interactive_single_select(findings)

        if not selected_findings:
            console.print("[dim]No findings selected. Exiting.[/dim]")
            raise typer.Exit(ExitCode.SUCCESS)

        # Process selected findings
        success_count = 0
        fail_count = 0
        total = len(selected_findings)

        for i, selected_finding in enumerate(selected_findings):
            remaining = total - i - 1
            console.print()

            # Show progress in bulk mode
            if total > 1:
                console.print(f"[dim]Patch {i + 1} of {total}[/dim]")

            result = _generate_and_save_patch(
                selected_finding, target, provider, model, output, dry_run,
                bundle=bundle,
            )
            if result:
                success_count += 1
            else:
                fail_count += 1

            # In bulk mode, ask if user wants to continue after each patch
            if remaining > 0 and not dry_run:
                console.print()
                continue_bulk = questionary.confirm(
                    f"Continue with remaining {remaining} patch(es)?",
                    default=True,
                    style=_style,
                ).ask()

                if not continue_bulk:
                    console.print("[dim]Stopping bulk patch operation.[/dim]")
                    break

        # Summary for bulk mode
        if total > 1:
            console.print()
            console.print(
                f"[bold]Bulk patch complete:[/bold] {success_count} succeeded, {fail_count} failed"
            )

        raise typer.Exit(ExitCode.SUCCESS if fail_count == 0 else ExitCode.SCAN_ERROR)

    # Non-interactive mode - use provided finding_id
    # finding_id is guaranteed non-None here (interactive mode exits above)
    if finding_id is None:  # pragma: no cover
        raise RuntimeError("finding_id should not be None in non-interactive mode")
    finding: Finding | None = _find_finding(findings, finding_id)

    if finding is None:
        console.print(f"[red]Error:[/red] Finding not found: {finding_id}")
        console.print(
            "\n[dim]Tip: Run [cyan]vibeguard patch[/cyan] without arguments "
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

    # Generate patch for the single finding
    result = _generate_and_save_patch(
        finding, target, provider, model, output, dry_run, bundle=bundle,
    )
    raise typer.Exit(ExitCode.SUCCESS if result else ExitCode.SCAN_ERROR)


def _load_bundle_for_patch() -> Bundle | None:
    """Load bundle for patch command, fetching if Pro licensed.

    Pro users can fetch from the server; falls back to cache or hardcoded.
    Never raises -- bundle failure should never block patching.
    """
    from vibeguard.core.auth import get_cached_token
    from vibeguard.core.bundles import (
        ensure_bundle,
        get_hardcoded_fallback,
        load_cached_bundle,
    )

    token = get_cached_token()
    token_str = token.token if token else None

    try:
        return asyncio.run(ensure_bundle(token_str))
    except Exception:
        # Bundle fetch failure should never block patching
        return load_cached_bundle() or get_hardcoded_fallback()


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


def _interactive_single_select(findings: list[Finding]) -> list[Finding]:
    """Interactive mode to select a single finding."""
    console.print()
    _show_findings_summary(findings)
    console.print()

    # Top-level selection menu
    severity_counts = _get_severity_counts(findings)

    choices = [
        questionary.Choice(
            title=f"Patch all findings ({len(findings)} total)",
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
    """Interactive mode to select multiple findings for bulk patching."""
    console.print()
    _show_findings_summary(findings)
    console.print()

    # Top-level selection menu
    severity_counts = _get_severity_counts(findings)
    critical_high_count = severity_counts.get(Severity.CRITICAL, 0) + \
        severity_counts.get(Severity.HIGH, 0)

    choices = [
        questionary.Choice(
            title=f"Patch all findings ({len(findings)} total)",
            value="all"
        ),
    ]

    # Add critical/high shortcut if there are any
    if critical_high_count > 0:
        choices.append(
            questionary.Choice(
                title=f"Patch all Critical + High ({critical_high_count} findings)",
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


def _generate_and_save_patch(
    finding: Finding,
    target: Path,
    provider: str | None,
    model: str | None,
    output: Path | None,
    dry_run: bool,
    *,
    bundle: Bundle | None = None,
) -> bool:
    """Generate and save a patch for a single finding.

    Returns True on success, False on failure.
    """
    # Build prompt (uses bundle template if available)
    prompt = build_fix_prompt(finding, target, bundle=bundle)

    # Generate patch using LLM
    console.print(
        Panel.fit(
            f"[bold]{finding.title}[/bold]\n"
            f"[dim]{finding.file_path}:{finding.line_start}[/dim]",
            title="Generating patch for",
        )
    )

    try:
        with Progress(
            SpinnerColumn(spinner_name=VIBEGUARD_SPINNER_NAME, style=BRAND_COLOR),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            msg = get_patching_message()
            task = progress.add_task(f"{msg}...", total=None)

            response = asyncio.run(
                _generate_patch_async(prompt, provider, model, bundle=bundle)
            )

            progress.remove_task(task)

        # Extract diff from response
        diff = extract_diff_from_response(response.content)
        if diff is None:
            console.print("[red]Error:[/red] Could not extract diff from LLM response.")
            console.print("\n[dim]Raw response (first 500 chars):[/dim]")
            console.print(response.content[:500])
            return False

        # Validate diff
        is_valid, error = validate_unified_diff(diff)
        if not is_valid:
            console.print(f"[red]Error:[/red] Invalid diff generated: {error}")
            console.print("\n[dim]Generated diff (first 500 chars):[/dim]")
            console.print(diff[:500])
            return False

        # Check for manual review marker
        manual_review = "MANUAL_REVIEW_REQUIRED" in diff

        # Create patch artifact
        artifact = PatchArtifact(
            finding_id=finding.id,
            file_path=finding.file_path,
            unified_diff=diff,
            provider=response.provider,
            model=response.model,
            generated_at=datetime.now(),
            manual_review_required=manual_review,
        )

        # Display the patch
        console.print()
        console.print("[green]Patch generated successfully![/green]")
        if response.tokens_used:
            console.print(f"[dim]Tokens used: {response.tokens_used}[/dim]")
        if manual_review:
            console.print(
                "[yellow]Note: Patch contains MANUAL_REVIEW_REQUIRED markers[/yellow]"
            )
        console.print()

        syntax = Syntax(diff, "diff", theme="monokai", line_numbers=True)
        console.print(Panel(syntax, title="Generated Patch"))

        # Save patch
        if not dry_run:
            if output:
                patch_path = output
            else:
                patches_dir = target / PATCHES_DIR
                patches_dir.mkdir(parents=True, exist_ok=True)
                patch_path = patches_dir / f"{finding.id}.patch"

            patch_path.write_text(diff, encoding="utf-8")
            console.print(f"\n[dim]Patch saved: {patch_path}[/dim]")

            # Also save metadata
            meta_path = patch_path.with_suffix(".json")
            meta_path.write_text(artifact.model_dump_json(indent=2), encoding="utf-8")
            console.print(f"[dim]Metadata saved: {meta_path}[/dim]")

            # Ask if user wants to apply the patch now
            console.print()
            apply_result = _prompt_apply_patch(patch_path, target, manual_review)

            if apply_result in ("skip", "dry_run"):
                console.print(f"[dim]To apply later: vibeguard apply {patch_path}[/dim]")
        else:
            console.print("\n[dim]Dry run - patch not saved[/dim]")

        return True

    except LLMError as e:
        console.print(f"[red]Error:[/red] {e}")
        return False


def _prompt_apply_patch(
    patch_path: Path,
    target: Path,
    manual_review: bool,
) -> str:
    """Prompt user to apply the patch now.

    Args:
        patch_path: Path to the generated patch file
        target: Repository path
        manual_review: Whether patch has manual review markers

    Returns:
        "applied", "dry_run", or "skip"
    """
    # Import apply functions here to avoid circular imports
    from vibeguard.cli.apply import (
        _check_working_directory,
        _git_apply,
        _git_apply_check,
        _is_git_repo,
    )

    # Build choices
    choices = [
        questionary.Choice(
            title="Yes, apply now",
            value="apply"
        ),
        questionary.Choice(
            title="Dry-run first (check without applying)",
            value="dry_run"
        ),
        questionary.Choice(
            title="No, I'll review and apply later",
            value="skip"
        ),
    ]

    # Add warning for manual review patches
    prompt_text = "Apply this patch now?"
    if manual_review:
        console.print(
            "[yellow]Note: This patch has MANUAL_REVIEW_REQUIRED markers. "
            "Review carefully before applying.[/yellow]"
        )

    selection = questionary.select(
        prompt_text,
        choices=choices,
        style=_style,
    ).ask()

    if selection is None or selection == "skip":
        return "skip"

    # Check if target is a git repo
    if not _is_git_repo(target):
        console.print("[red]Error:[/red] Not a git repository. Cannot apply patch.")
        console.print(f"[dim]To apply manually: git apply {patch_path}[/dim]")
        return "skip"

    # Check for uncommitted changes
    has_changes, status_output = _check_working_directory(target)
    if has_changes:
        console.print("\n[yellow]Warning:[/yellow] Working directory has uncommitted changes.")

        proceed = questionary.confirm(
            "Apply anyway?",
            default=False,
            style=_style,
        ).ask()

        if not proceed:
            return "skip"

    # Check if patch applies cleanly
    console.print("\n[dim]Checking if patch applies cleanly...[/dim]")
    can_apply, check_error = _git_apply_check(target, patch_path)

    if not can_apply:
        console.print("[red]Error:[/red] Patch cannot be applied cleanly.")
        console.print(f"[dim]{check_error}[/dim]")
        console.print("\n[dim]The code may have changed since the scan.[/dim]")
        console.print("[dim]Try running 'vibeguard scan' and 'vibeguard patch' again.[/dim]")
        return "skip"

    console.print("[green]Patch applies cleanly![/green]")

    # Dry run - just show result
    if selection == "dry_run":
        console.print("\n[dim]Dry run complete. Patch is ready to apply.[/dim]")

        apply_now = questionary.confirm(
            "Apply the patch now?",
            default=True,
            style=_style,
        ).ask()

        if not apply_now:
            return "dry_run"

    # Apply the patch
    console.print("\n[dim]Applying patch...[/dim]")
    success, apply_output = _git_apply(target, patch_path)

    if not success:
        console.print("[red]Error:[/red] Failed to apply patch.")
        console.print(f"[dim]{apply_output}[/dim]")
        return "skip"

    console.print("[green]Patch applied successfully![/green]")
    console.print()
    console.print("[dim]Next steps:[/dim]")
    console.print("  1. Review changes: [cyan]git diff[/cyan]")
    console.print("  2. Run tests to verify the fix")
    console.print("  3. Commit: [cyan]git commit -am 'Fix security finding'[/cyan]")

    return "applied"


async def _generate_patch_async(
    prompt: str,
    provider: str | None,
    model: str | None,
    *,
    bundle: Bundle | None = None,
) -> LLMResponse:
    """Generate patch using LLM.

    Args:
        prompt: The prompt to send
        provider: Optional provider override
        model: Optional model override
        bundle: Optional policy bundle for LLM configuration

    Returns:
        LLMResponse with generated content
    """
    from vibeguard.core.bundles import get_patch_rule

    max_tokens = get_patch_rule(bundle, "max_tokens", 4096) if bundle else 4096
    temperature = get_patch_rule(bundle, "temperature", 0.2) if bundle else 0.2

    return await generate(
        prompt,
        provider=provider,
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
    )
