"""Import command for merging external scan results into VibeGuard.

Supports importing findings from:
- SARIF 2.1.0 files (CodeQL, Semgrep Cloud, Snyk, etc.)
- Generic JSON files (with --format flag)

Imported findings are merged with the cached scan results and can be
viewed with `vibeguard report` or compared against baselines.
"""

from datetime import datetime
from pathlib import Path

import typer
from rich.table import Table

from vibeguard.cli.display import get_console
from vibeguard.core import cache
from vibeguard.core.dedup import deduplicate_findings
from vibeguard.core.exit_codes import ExitCode
from vibeguard.core.ignore import load_ignore_patterns
from vibeguard.core.sarif_import import parse_sarif
from vibeguard.core.triage import TriageEngine
from vibeguard.models.finding import Finding
from vibeguard.models.scan_result import ScanResult

app = typer.Typer(
    name="import",
    help="Import external scan results into VibeGuard",
    invoke_without_command=True,
    no_args_is_help=True,
)

console = get_console()


@app.callback(invoke_without_command=True)
def import_callback(ctx: typer.Context) -> None:
    """Import external scan results from SARIF or JSON files.

    Example:
        vibeguard import sarif codeql-results.sarif
        vibeguard import sarif --scanner codeql results.sarif
    """
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


@app.command("sarif")
def import_sarif(
    sarif_file: Path = typer.Argument(
        ...,
        help="Path to SARIF 2.1.0 file",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    path: Path = typer.Option(
        Path("."),
        "--path",
        "-p",
        help="Repository path (for cache storage)",
        exists=True,
        file_okay=False,
        dir_okay=True,
    ),
    scanner: str | None = typer.Option(
        None,
        "--scanner",
        "-s",
        help="Scanner name override (uses SARIF tool name if not specified)",
    ),
    merge: bool = typer.Option(
        True,
        "--merge/--replace",
        help="Merge with existing cache or replace entirely",
    ),
) -> None:
    """Import findings from a SARIF 2.1.0 file.

    Supports SARIF files from CodeQL, Semgrep Cloud, Snyk, Checkmarx,
    and other SARIF-compliant tools.

    Examples:
        vibeguard import sarif codeql-results.sarif
        vibeguard import sarif --scanner codeql results.sarif
        vibeguard import sarif --replace snyk-output.sarif
        vibeguard import sarif --path /my/repo external-scan.sarif
    """
    target = path.resolve()

    console.print(f"[bold]Importing SARIF:[/bold] {sarif_file}")
    console.print(f"[dim]Repository:[/dim] {target}")
    console.print()

    # Read and parse SARIF file
    try:
        content = sarif_file.read_text(encoding="utf-8")
    except Exception as e:
        console.print(f"[red]Error reading file:[/red] {e}")
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    try:
        imported_findings = parse_sarif(content, scanner_name=scanner)
    except ValueError as e:
        console.print(f"[red]Error parsing SARIF:[/red] {e}")
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    console.print(f"[green]Parsed {len(imported_findings)} findings from SARIF[/green]")

    # Load existing cache if merging
    existing_findings: list[Finding] = []
    scanners_run: list[str] = []

    if merge:
        existing_result = cache.load_latest_scan(target)
        if existing_result:
            existing_findings = existing_result.findings
            scanners_run = existing_result.scanners_run.copy()
            count = len(existing_findings)
            console.print(f"[dim]Merging with existing cache ({count} findings)[/dim]")

    # Combine and deduplicate findings
    all_findings = existing_findings + imported_findings
    deduped_findings = deduplicate_findings(all_findings)

    # Get unique scanner name from imported findings
    imported_scanners = list(set(f.scanner for f in imported_findings))
    for s in imported_scanners:
        if s not in scanners_run:
            scanners_run.append(s)

    # Apply triage (load ignore patterns and classify findings)
    user_patterns = load_ignore_patterns(target)
    triage_engine = TriageEngine(repo_root=target, user_patterns=user_patterns)
    deduped_findings = triage_engine.triage_findings(deduped_findings)

    # Create new scan result
    result = ScanResult(
        repo_root=str(target),
        started_at=datetime.now(),
        finished_at=datetime.now(),
        findings=deduped_findings,
        scanners_run=scanners_run,
        scanners_skipped=[],
        partial=False,
    )

    # Save to cache
    cache.save_scan(result, target)

    # Show summary
    _show_import_summary(result, len(imported_findings), len(deduped_findings))

    raise typer.Exit(ExitCode.SUCCESS)


def _show_import_summary(result: ScanResult, imported_count: int, total_count: int) -> None:
    """Display import summary."""
    console.print()
    console.print("[bold green]Import successful![/bold green]")
    console.print()

    # Summary table
    table = Table(show_header=False, box=None)
    table.add_column("Metric", style="dim")
    table.add_column("Value", style="bold")

    table.add_row("Imported findings", str(imported_count))
    table.add_row("Total findings (after dedup)", str(total_count))
    table.add_row("Actionable findings", str(len(result.actionable_findings)))
    table.add_row("Score", f"{result.score}/100")
    table.add_row("Grade", result.grade)
    table.add_row("Scanners", ", ".join(result.scanners_run))

    console.print(table)
    console.print()
    console.print("[dim]Run 'vibeguard report' to view full report[/dim]")
    console.print("[dim]Run 'vibeguard baseline save' to save as baseline[/dim]")
