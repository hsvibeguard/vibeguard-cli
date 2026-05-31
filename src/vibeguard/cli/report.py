"""Report command - generate reports from cached scan results."""

import json
from pathlib import Path

import typer

from vibeguard.cli.display import get_console
from vibeguard.core import cache
from vibeguard.core.exit_codes import ExitCode
from vibeguard.reporters import generate_badge, to_html, to_pdf, to_sarif


def report(
    path: Path = typer.Argument(
        Path("."),
        help="Repository path (to find cached scan)",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
    format: str = typer.Option(
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal, json, sarif, html, pdf",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path (default: stdout)",
    ),
    badge: Path | None = typer.Option(
        None,
        "--badge",
        help="Generate badge SVG at specified path",
    ),
) -> None:
    """Generate reports from cached scan results.

    Uses the most recent scan from .vibeguard/cache/ to generate
    reports in various formats without re-running scanners.

    Examples:
        vibeguard report --format json
        vibeguard report --format sarif --output results.sarif
        vibeguard report --format html --output report.html
        vibeguard report --badge badge.svg
    """
    console = get_console()

    # Load cached scan
    result = cache.load_latest_scan(path)

    if result is None:
        console.print(
            "[red]Error:[/red] No cached scan found. Run 'vibeguard scan' first."
        )
        raise typer.Exit(ExitCode.NO_CACHE)

    # Generate badge if requested
    if badge:
        badge_svg = generate_badge(result.score, result.grade)
        badge.write_text(badge_svg, encoding="utf-8")
        console.print(f"[dim]Badge saved: {badge}[/dim]")

    # Generate report content
    content: str
    if format == "json":
        content = result.model_dump_json(indent=2)
    elif format == "sarif":
        sarif_data = to_sarif(result)
        content = json.dumps(sarif_data, indent=2)
    elif format == "html":
        content = to_html(result)
    elif format == "pdf":
        try:
            pdf_path = to_pdf(result, output_path=output)
        except RuntimeError as e:
            console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(ExitCode.CONFIG_ERROR)
        console.print(f"[green]PDF report saved:[/green] {pdf_path}")
        if result.actionable_findings:
            raise typer.Exit(ExitCode.FINDINGS)
        else:
            raise typer.Exit(ExitCode.SUCCESS)
    elif format == "terminal":
        # Import here to avoid circular import
        from vibeguard.cli.scan import _print_results

        _print_results(result)
        # Exit based on actionable findings (suppressed findings don't count)
        if result.actionable_findings:
            raise typer.Exit(ExitCode.FINDINGS)
        else:
            raise typer.Exit(ExitCode.SUCCESS)
    else:
        console.print(
            f"[red]Error:[/red] Unknown format '{format}'. "
            "Use: terminal, json, sarif, html, pdf"
        )
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    # Output to file or stdout
    if output:
        output.write_text(content, encoding="utf-8")
        console.print(f"[green]Report saved:[/green] {output}")
    else:
        console.print(content)

    # Exit based on actionable findings (suppressed findings don't count)
    if result.actionable_findings:
        raise typer.Exit(ExitCode.FINDINGS)
    else:
        raise typer.Exit(ExitCode.SUCCESS)
