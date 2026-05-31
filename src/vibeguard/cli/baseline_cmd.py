"""Baseline command - manage security baselines for regression checking."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.table import Table

from vibeguard.cli.display import get_console
from vibeguard.core import cache
from vibeguard.core.baseline import (
    delete_baseline,
    list_baselines,
    load_baseline,
    save_baseline,
)
from vibeguard.core.exit_codes import ExitCode

app = typer.Typer(
    name="baseline",
    help="Manage security baselines for regression checking.",
    invoke_without_command=True,
    no_args_is_help=True,
)

console = get_console()


@app.callback(invoke_without_command=True)
def baseline_callback(ctx: typer.Context) -> None:
    """Manage security baselines for regression checking.

    Baselines capture your security findings at a point in time,
    allowing you to detect regressions (new issues) in future scans.

    Examples:
        vibeguard baseline save                 # Save as "default"
        vibeguard baseline save release-1.0    # Save with custom name
        vibeguard baseline list                 # List all baselines
        vibeguard baseline show default         # Show baseline details
        vibeguard baseline delete old-baseline  # Delete a baseline

    To scan against a baseline:
        vibeguard scan . --baseline default
    """
    if ctx.invoked_subcommand is None:
        # Show help when no subcommand given
        console.print(ctx.get_help())


@app.command("save")
def save_cmd(
    name: str = typer.Argument(
        "default",
        help="Name for the baseline (default: 'default')",
    ),
    path: Path = typer.Option(
        Path("."),
        "--path",
        "-p",
        help="Repository path (default: current directory)",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite existing baseline without confirmation",
    ),
) -> None:
    """Save current scan as a baseline.

    Saves the most recent scan results as a named baseline.
    Future scans can compare against this baseline to detect regressions.

    Examples:
        vibeguard baseline save
        vibeguard baseline save release-1.0
        vibeguard baseline save --path /path/to/repo
        vibeguard baseline save release-1.0 --force
    """
    target = path.resolve()

    # Load latest scan
    result = cache.load_latest_scan(target)
    if result is None:
        console.print("[red]Error:[/red] No cached scan found.")
        console.print("[dim]Run 'vibeguard scan .' first.[/dim]")
        raise typer.Exit(ExitCode.NO_CACHE)

    # Check if baseline exists
    existing = load_baseline(target, name)
    if existing and not force:
        console.print(f"[yellow]Warning:[/yellow] Baseline '{name}' already exists.")
        console.print(f"  Created: {existing.created_at.strftime('%Y-%m-%d %H:%M')}")
        console.print(f"  Findings: {existing.actionable_count}")
        overwrite = typer.confirm("Overwrite?", default=False)
        if not overwrite:
            console.print("[dim]Cancelled.[/dim]")
            raise typer.Exit(ExitCode.SUCCESS)

    # Save baseline
    baseline_path = save_baseline(result, target, name)

    actionable_count = len(result.actionable_findings)
    console.print(f"[green]Baseline saved:[/green] {name}")
    console.print(f"  Findings: {actionable_count} actionable")
    console.print(f"  Scanners: {', '.join(result.scanners_run)}")
    console.print(f"  Path: {baseline_path}")
    console.print()
    console.print("[dim]Compare future scans with:[/dim]")
    console.print(f"[dim]  vibeguard scan . --baseline {name}[/dim]")


@app.command("list")
def list_cmd(
    path: Path = typer.Option(
        Path("."),
        "--path",
        "-p",
        help="Repository path",
    ),
) -> None:
    """List all saved baselines.

    Example:
        vibeguard baseline list
    """
    target = path.resolve()
    baselines = list_baselines(target)

    if not baselines:
        console.print("[yellow]No baselines found.[/yellow]")
        console.print("[dim]Create one with: vibeguard baseline save[/dim]")
        return

    table = Table(title="Saved Baselines")
    table.add_column("Name", style="cyan")
    table.add_column("Created", style="dim")
    table.add_column("Findings", justify="right")
    table.add_column("Scanners")

    for baseline in baselines:
        created = baseline.created_at.strftime("%Y-%m-%d %H:%M")
        scanners = ", ".join(baseline.scanners_used[:3])
        if len(baseline.scanners_used) > 3:
            scanners += "..."

        table.add_row(
            baseline.name,
            created,
            str(baseline.actionable_count),
            scanners,
        )

    console.print(table)
    console.print()
    console.print("[dim]Compare scans with: vibeguard scan . --baseline <name>[/dim]")


@app.command("show")
def show_cmd(
    name: str = typer.Argument(
        ...,
        help="Baseline name to show",
    ),
    path: Path = typer.Option(
        Path("."),
        "--path",
        "-p",
        help="Repository path",
    ),
) -> None:
    """Show details of a baseline.

    Example:
        vibeguard baseline show default
        vibeguard baseline show release-1.0
    """
    target = path.resolve()
    baseline = load_baseline(target, name)

    if baseline is None:
        console.print(f"[red]Error:[/red] Baseline '{name}' not found.")

        # Show available baselines
        available = list_baselines(target)
        if available:
            console.print("\n[dim]Available baselines:[/dim]")
            for b in available:
                console.print(f"  - {b.name}")
        else:
            console.print("\n[dim]No baselines saved. Create one with:[/dim]")
            console.print("[dim]  vibeguard baseline save[/dim]")

        raise typer.Exit(ExitCode.NO_CACHE)

    console.print(f"[bold]Baseline: {baseline.name}[/bold]")
    console.print(f"  Created: {baseline.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
    console.print(f"  VibeGuard Version: {baseline.vibeguard_version}")
    console.print(f"  Total Findings: {baseline.total_count}")
    console.print(f"  Actionable: {baseline.actionable_count}")
    console.print(f"  Scanners: {', '.join(baseline.scanners_used)}")

    if baseline.findings:
        console.print()

        # Show severity breakdown
        severity_counts: dict[str, int] = {}
        for f in baseline.findings:
            sev = f.severity.value.upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        console.print("[bold]Severity Breakdown:[/bold]")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in severity_counts:
                color = {
                    "CRITICAL": "red bold",
                    "HIGH": "red",
                    "MEDIUM": "yellow",
                    "LOW": "blue",
                    "INFO": "dim",
                }.get(sev, "white")
                console.print(f"  [{color}]{sev}:[/{color}] {severity_counts[sev]}")

    console.print()
    console.print("[dim]Compare against this baseline with:[/dim]")
    console.print(f"[dim]  vibeguard scan . --baseline {baseline.name}[/dim]")


@app.command("delete")
def delete_cmd(
    name: str = typer.Argument(
        ...,
        help="Baseline name to delete",
    ),
    path: Path = typer.Option(
        Path("."),
        "--path",
        "-p",
        help="Repository path",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Delete without confirmation",
    ),
) -> None:
    """Delete a baseline.

    Example:
        vibeguard baseline delete old-baseline
        vibeguard baseline delete old-baseline --force
    """
    target = path.resolve()

    # Check if baseline exists
    baseline = load_baseline(target, name)
    if baseline is None:
        console.print(f"[red]Error:[/red] Baseline '{name}' not found.")

        # Show available baselines
        available = list_baselines(target)
        if available:
            console.print("\n[dim]Available baselines:[/dim]")
            for b in available:
                console.print(f"  - {b.name}")

        raise typer.Exit(ExitCode.NO_CACHE)

    if not force:
        console.print(f"[yellow]About to delete baseline:[/yellow] {name}")
        console.print(f"  Created: {baseline.created_at.strftime('%Y-%m-%d %H:%M')}")
        console.print(f"  Findings: {baseline.actionable_count}")

        confirm = typer.confirm("Delete this baseline?", default=False)
        if not confirm:
            console.print("[dim]Cancelled.[/dim]")
            raise typer.Exit(ExitCode.SUCCESS)

    if delete_baseline(target, name):
        console.print(f"[green]Deleted baseline:[/green] {name}")
    else:
        console.print("[red]Error:[/red] Failed to delete baseline.")
        raise typer.Exit(ExitCode.CONFIG_ERROR)
