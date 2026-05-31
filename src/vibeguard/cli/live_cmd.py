"""Live DAST scanning command for HTTP vulnerability detection.

This command uses Nuclei templates to detect HTTP vulnerabilities on
running web applications. It is EXPERIMENTAL and requires explicit
consent for non-localhost targets.

Safety Controls:
- Localhost targets work without flags
- External targets require --i-own-this flag
- Dangerous templates (dos, intrusive, bruteforce) are excluded
- Rate limiting is enforced
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys

import typer
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm
from rich.table import Table

from vibeguard.cli.display import (
    BRAND_COLOR,
    VIBEGUARD_SPINNER_NAME,
    get_console,
)
from vibeguard.core.exit_codes import ExitCode
from vibeguard.core.url_validator import (
    get_safety_warning,
    normalize_url,
    validate_url,
)
from vibeguard.models.finding import Finding, Severity
from vibeguard.scanners.parsers.nuclei import parse_output
from vibeguard.scanners.runners.local import LocalRunner

# Pattern to validate template path (alphanumeric, dashes, underscores, slashes, dots)
SAFE_PATH_PATTERN = re.compile(r"^[\w\-./\\]+$")

# Pattern to validate tags (alphanumeric, dashes, commas)
SAFE_TAGS_PATTERN = re.compile(r"^[\w\-,]+$")

# Pattern to validate severity (alphanumeric, commas)
SAFE_SEVERITY_PATTERN = re.compile(r"^[a-zA-Z,]+$")

console = get_console()

# Severity styles for display
SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

# Default excluded tags for safety
EXCLUDED_TAGS = "dos,intrusive,bruteforce,fuzzing"


def live(
    url: str = typer.Argument(
        ...,
        help="Target URL to scan (e.g., http://localhost:8080)",
    ),
    i_own_this: bool = typer.Option(
        False,
        "--i-own-this",
        help="REQUIRED for non-localhost targets. Confirms you have permission to scan.",
    ),
    rate_limit: int = typer.Option(
        50,
        "--rate-limit",
        "-r",
        help="Maximum requests per second (default: 50)",
        min=1,
        max=500,
    ),
    timeout: int = typer.Option(
        10,
        "--timeout",
        help="Request timeout in seconds (default: 10)",
        min=1,
        max=60,
    ),
    templates: str | None = typer.Option(
        None,
        "--templates",
        "-t",
        help="Specific template directory or file to use",
    ),
    tags: str | None = typer.Option(
        None,
        "--tags",
        help="Filter templates by tags (comma-separated, e.g., cve,xss)",
    ),
    severity_filter: str | None = typer.Option(
        None,
        "--severity",
        "-s",
        help="Filter by severity (comma-separated, e.g., critical,high)",
    ),
    output: str = typer.Option(
        "terminal",
        "--output",
        "-o",
        help="Output format: terminal, json",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress progress output",
    ),
    scan_timeout: int = typer.Option(
        300,
        "--scan-timeout",
        help="Total scan timeout in seconds (default: 300)",
        min=30,
        max=1800,
    ),
) -> None:
    """[EXPERIMENTAL] Run HTTP vulnerability scan on a target URL.

    This command uses Nuclei templates to detect HTTP vulnerabilities
    on running web applications.

    SAFETY RESTRICTIONS:
      - Localhost targets (127.0.0.1, localhost) work without flags
      - Non-localhost targets REQUIRE --i-own-this flag
      - Dangerous templates (dos, intrusive, bruteforce) are excluded
      - Rate limiting is enforced to prevent abuse

    LEGAL NOTICE:
      Only scan targets you own or have explicit permission to test.
      Unauthorized security scanning may violate computer crime laws.

    \b
    Examples:
      vibeguard live http://localhost:8080
      vibeguard live http://localhost:3000 --tags cve,xss
      vibeguard live https://myapp.example.com --i-own-this
      vibeguard live http://localhost:8080 --rate-limit 10
      vibeguard live http://localhost:8080 --severity critical,high
    """
    # Normalize and validate URL
    url = normalize_url(url)
    validation = validate_url(url)

    if not validation.is_valid:
        console.print(f"[red]Error:[/red] {validation.error}")
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    # Safety check: non-localhost requires --i-own-this
    if not validation.is_localhost:
        warning = get_safety_warning(url, validation.is_localhost)
        if warning:
            console.print()
            console.print(f"[yellow]{warning}[/yellow]")
            console.print()

        if not i_own_this:
            console.print(
                "[red]Error:[/red] Non-localhost targets require --i-own-this flag."
            )
            console.print()
            console.print("[dim]This safety check ensures you only scan targets you own.[/dim]")
            console.print("[dim]Add --i-own-this to confirm authorization.[/dim]")
            raise typer.Exit(ExitCode.CONFIG_ERROR)

        # Double-check with interactive confirmation for external targets
        if not quiet:
            console.print(
                Panel(
                    f"[yellow bold]You are about to scan an external target:[/yellow bold]\n\n"
                    f"  URL: {url}\n"
                    f"  Host: {validation.host}\n"
                    f"  Port: {validation.port or 'default'}\n\n"
                    "[red]Unauthorized scanning may be illegal.[/red]\n"
                    "Confirm you have permission to scan this target.",
                    title="External Target Warning",
                    border_style="yellow",
                )
            )
            if not Confirm.ask("Continue with scan?", default=False):
                console.print("[dim]Scan cancelled.[/dim]")
                raise typer.Exit(ExitCode.SUCCESS)

    # Check if Nuclei is available
    runner = LocalRunner(
        binary_name="nuclei",
        check_command="nuclei -version",
        version="3.2.0",
    )

    if not runner.is_available():
        console.print("[red]Error:[/red] Nuclei is not installed or not found.")
        console.print()
        console.print("[dim]Install Nuclei using one of these methods:[/dim]")
        console.print(
            "  [cyan]go install "
            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest[/cyan]"
        )
        console.print("  [cyan]brew install nuclei[/cyan]  [dim](macOS)[/dim]")
        console.print(
            "  [cyan]Download from "
            "https://github.com/projectdiscovery/nuclei/releases[/cyan]"
        )
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    # Run the scan
    if not quiet:
        console.print()
        console.print(
            Panel(
                f"[bold]Target:[/bold] {url}\n"
                f"[bold]Rate Limit:[/bold] {rate_limit} req/s\n"
                f"[bold]Timeout:[/bold] {timeout}s per request\n"
                f"[bold]Excluded Tags:[/bold] {EXCLUDED_TAGS}",
                title="[bold cyan]DAST Scan Configuration[/bold cyan]",
                border_style="cyan",
            )
        )
        console.print()

    findings = asyncio.run(
        _run_live_scan(
            runner=runner,
            url=url,
            rate_limit=rate_limit,
            timeout=timeout,
            templates=templates,
            tags=tags,
            severity_filter=severity_filter,
            quiet=quiet,
            scan_timeout=scan_timeout,
        )
    )

    # Output results
    if output == "json":
        findings_json = [f.model_dump(mode="json") for f in findings]
        console.print(json.dumps(findings_json, indent=2, default=str))
    else:
        _print_live_results(findings, url)

    # Exit code based on findings
    if findings:
        raise typer.Exit(ExitCode.FINDINGS)
    raise typer.Exit(ExitCode.SUCCESS)


def _validate_template_path(path: str) -> bool:
    """Validate template path to prevent command injection.

    Args:
        path: Template path to validate

    Returns:
        True if path is safe, False otherwise
    """
    if not path:
        return False
    # Must match safe path pattern (no shell metacharacters)
    if not SAFE_PATH_PATTERN.match(path):
        return False
    # No command separators or dangerous characters
    dangerous_chars = [";", "&", "|", "$", "`", "(", ")", "<", ">", "!", "'", '"']
    return not any(c in path for c in dangerous_chars)


def _validate_tags(tags_str: str) -> bool:
    """Validate tags string to prevent command injection.

    Args:
        tags_str: Comma-separated tags

    Returns:
        True if tags are safe, False otherwise
    """
    if not tags_str:
        return False
    return bool(SAFE_TAGS_PATTERN.match(tags_str))


def _validate_severity(severity_str: str) -> bool:
    """Validate severity filter to prevent command injection.

    Args:
        severity_str: Comma-separated severity levels

    Returns:
        True if severity filter is safe, False otherwise
    """
    if not severity_str:
        return False
    return bool(SAFE_SEVERITY_PATTERN.match(severity_str))


async def _run_live_scan(
    runner: LocalRunner,
    url: str,
    rate_limit: int,
    timeout: int,
    templates: str | None,
    tags: str | None,
    severity_filter: str | None,
    quiet: bool,
    scan_timeout: int,
) -> list[Finding]:
    """Run the Nuclei scan using subprocess with argument list (no shell).

    Args:
        runner: LocalRunner instance
        url: Target URL
        rate_limit: Max requests per second
        timeout: Per-request timeout
        templates: Optional template path
        tags: Optional tag filter
        severity_filter: Optional severity filter
        quiet: Suppress progress output
        scan_timeout: Total scan timeout

    Returns:
        List of findings

    Raises:
        typer.Exit: If input validation fails
    """
    # Validate optional inputs to prevent injection
    if templates and not _validate_template_path(templates):
        console.print(
            "[red]Error:[/red] Invalid template path. "
            "Path must only contain alphanumeric characters, dashes, underscores, "
            "slashes, and dots."
        )
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    if tags and not _validate_tags(tags):
        console.print(
            "[red]Error:[/red] Invalid tags. "
            "Tags must only contain alphanumeric characters, dashes, and commas."
        )
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    if severity_filter and not _validate_severity(severity_filter):
        console.print(
            "[red]Error:[/red] Invalid severity filter. "
            "Severity must only contain letters and commas "
            "(e.g., critical,high,medium)."
        )
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    # Build command as argument list (NOT a shell string) to prevent injection
    cmd_args: list[str] = [
        runner.get_binary_path(),  # Use resolved binary path
        "-target", url,
        "-jsonl",  # JSONL output
        "-silent",  # Reduce noise
        "-exclude-tags", EXCLUDED_TAGS,
        "-rate-limit", str(rate_limit),
        "-timeout", str(timeout),
    ]

    # Add optional filters (already validated above)
    if templates:
        cmd_args.extend(["-templates", templates])

    if tags:
        cmd_args.extend(["-tags", tags])

    if severity_filter:
        cmd_args.extend(["-severity", severity_filter])

    # Run Nuclei with progress indicator using subprocess_exec (no shell)
    if not quiet:
        with Progress(
            SpinnerColumn(spinner_name=VIBEGUARD_SPINNER_NAME, style=BRAND_COLOR),
            TextColumn("[bold blue]Scanning {task.fields[url]}..."),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("scan", url=url)
            result = await _run_subprocess_exec(cmd_args, scan_timeout)
            progress.update(task, completed=True)
    else:
        result = await _run_subprocess_exec(cmd_args, scan_timeout)

    # Check for errors
    if result.get("error"):
        if not quiet:
            console.print(f"[yellow]Warning:[/yellow] {result['error']}")

    # Parse output
    if result.get("stdout"):
        return parse_output(result["stdout"])

    # Nuclei may return exit code 0 with no findings, or exit code 1 with findings
    # We need to handle both cases
    return []


async def _run_subprocess_exec(
    cmd_args: list[str],
    timeout: int,
) -> dict[str, str | int | None]:
    """Run command using subprocess_exec (no shell) to prevent command injection.

    Args:
        cmd_args: List of command arguments
        timeout: Timeout in seconds

    Returns:
        Dict with stdout, stderr, exit_code, and error fields
    """
    try:
        # Build environment with UTF-8 encoding on Windows
        env = os.environ.copy()
        if sys.platform == "win32":
            env["PYTHONUTF8"] = "1"
            env["PYTHONIOENCODING"] = "utf-8"

        # Use create_subprocess_exec (NOT shell) to prevent injection
        process = await asyncio.create_subprocess_exec(
            *cmd_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )

        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout,
        )

        return {
            "stdout": stdout_bytes.decode("utf-8", errors="replace"),
            "stderr": stderr_bytes.decode("utf-8", errors="replace"),
            "exit_code": process.returncode,
            "error": None,
        }

    except TimeoutError:
        return {
            "stdout": "",
            "stderr": "",
            "exit_code": -1,
            "error": f"Scan timed out after {timeout}s",
        }
    except FileNotFoundError:
        return {
            "stdout": "",
            "stderr": "",
            "exit_code": -1,
            "error": "Nuclei binary not found",
        }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": str(e),
            "exit_code": -1,
            "error": str(e),
        }


def _print_live_results(findings: list[Finding], url: str) -> None:
    """Print live scan results.

    Args:
        findings: List of findings
        url: Target URL
    """
    console.print()

    if not findings:
        console.print(
            Panel(
                "[green]No vulnerabilities detected[/green]\n\n"
                f"Target: {url}\n"
                "[dim]Note: Only safe templates were used. Dangerous templates[/dim]\n"
                "[dim](dos, intrusive, bruteforce) are excluded by default.[/dim]",
                title="[bold green]Live Scan Complete[/bold green]",
                border_style="green",
            )
        )
        return

    # Count by severity
    severity_counts = {s: 0 for s in Severity}
    for f in findings:
        severity_counts[f.severity] += 1

    # Summary panel
    crit_style = SEVERITY_STYLES[Severity.CRITICAL]
    high_style = SEVERITY_STYLES[Severity.HIGH]
    med_style = SEVERITY_STYLES[Severity.MEDIUM]
    low_style = SEVERITY_STYLES[Severity.LOW]
    info_style = SEVERITY_STYLES[Severity.INFO]

    summary_lines = [
        f"[yellow bold]Vulnerabilities detected: {len(findings)}[/yellow bold]",
        "",
        f"[{crit_style}]Critical: {severity_counts[Severity.CRITICAL]}[/]  "
        f"[{high_style}]High: {severity_counts[Severity.HIGH]}[/]  "
        f"[{med_style}]Medium: {severity_counts[Severity.MEDIUM]}[/]  "
        f"[{low_style}]Low: {severity_counts[Severity.LOW]}[/]  "
        f"[{info_style}]Info: {severity_counts[Severity.INFO]}[/]",
        "",
        f"Target: {url}",
    ]

    console.print(
        Panel(
            "\n".join(summary_lines),
            title="[bold yellow]Live Scan Results[/bold yellow]",
            border_style="yellow",
        )
    )

    # Findings table
    console.print()
    table = Table(title=f"Findings ({len(findings)})")
    table.add_column("Severity", width=10)
    table.add_column("Template", max_width=35)
    table.add_column("Name", max_width=40)
    table.add_column("Matched At", max_width=50)

    # Sort by severity (critical first)
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 5))

    # Show up to 50 findings
    for finding in sorted_findings[:50]:
        style = SEVERITY_STYLES[finding.severity]
        table.add_row(
            f"[{style}]{finding.severity.value.upper()}[/]",
            finding.rule_id[:35] if finding.rule_id else "",
            finding.title[:40] if finding.title else "",
            finding.file_path[:50] if finding.file_path else "",
        )

    console.print(table)

    if len(findings) > 50:
        console.print(f"[dim]... and {len(findings) - 50} more findings[/dim]")

    # Recommendations
    console.print()
    console.print("[bold]Next Steps:[/bold]")
    console.print("  1. Review findings and prioritize by severity")
    console.print("  2. Use [cyan]vibeguard fix <finding-id>[/cyan] to generate fix prompts")
    console.print("  3. Test fixes in a staging environment before production")
