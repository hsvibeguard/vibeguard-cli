"""Scan command for running security scanners."""

import asyncio
import importlib
import json
import os
import platform
import shlex
import subprocess
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from vibeguard.cli.display import (
    BRAND_COLOR,
    VIBEGUARD_SPINNER_NAME,
    get_bootstrap_message,
    get_result_message,
    get_scanner_message,
)
from vibeguard.core import cache
from vibeguard.core.baseline import compare_to_baseline, has_any_baselines, load_baseline, save_baseline
from vibeguard.core.bootstrap import ScannerStatus, bootstrap_scanners
from vibeguard.core.config import VibeGuardConfig, load_config
from vibeguard.core.dedup import deduplicate_findings
from vibeguard.core.downloader import DownloadConfig as DLConfig
from vibeguard.core.downloader import download_binary
from vibeguard.core.exit_codes import ExitCode
from vibeguard.core.ignore import load_ignore_patterns
from vibeguard.core.repo_detector import get_detection_summary, get_ecosystem_scanners
from vibeguard.core.triage import TriageEngine, get_ignored_by_reason, get_triage_summary
from vibeguard.models.baseline import ComparisonResult
from vibeguard.models.finding import Finding, Severity
from vibeguard.models.scan_result import ScanResult
from vibeguard.models.triage import TriageReason
from vibeguard.reporters import generate_badge, to_html, to_pdf, to_sarif
from vibeguard.scanners import ScannerManifest, load_manifest
from vibeguard.scanners.runners.docker import DockerRunner
from vibeguard.scanners.runners.local import LocalRunner

console = Console()

# CI environment detection
def _is_ci_environment() -> bool:
    """Detect if running in a CI environment.

    Checks for VIBEGUARD_CI first (explicit override), then common CI variables.
    """
    # VIBEGUARD_CI is explicit override with highest precedence
    if os.environ.get("VIBEGUARD_CI", "").lower() in ("true", "1", "yes"):
        return True

    ci_vars = ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "CIRCLECI", "TRAVIS"]
    return any(os.environ.get(var) for var in ci_vars)


def _is_github_actions() -> bool:
    """Detect if running in GitHub Actions."""
    return os.environ.get("GITHUB_ACTIONS") == "true"


def _emit_github_annotation(finding: Finding, repo_root: Path) -> None:
    """Emit GitHub Actions workflow annotation for a finding."""
    # Map severity to annotation type
    level = "error" if finding.severity in (Severity.CRITICAL, Severity.HIGH) else "warning"

    # Format the annotation
    file_path = finding.file_path or ""
    line = finding.line_start or 1
    message = finding.message.replace("\n", " ").replace("%", "%25")
    title = f"[{finding.scanner}] {finding.rule_id}"

    print(f"::{level} file={file_path},line={line},title={title}::{message}")

# Core scanners to run
CORE_SCANNERS = ["semgrep", "gitleaks", "trivy", "bandit", "trufflehog"]

# Ecosystem scanners (auto-detected based on repo files)
ECOSYSTEM_SCANNERS = ["npm_audit", "pip_audit", "cargo_audit", "gosec", "checkov"]

# Differentiation scanners (included in --pack full)
DIFFERENTIATION_SCANNERS = ["grype", "bearer", "horusec", "kube_linter", "dockle"]

# Valid pack options
VALID_PACKS = ["core", "ecosystem", "full", "auto"]


def _quote_path_for_shell(path: str) -> str:
    """Quote a path for shell execution in a platform-aware way.

    On Windows, shlex.quote() produces single-quoted strings that cmd.exe
    doesn't understand. We use subprocess.list2cmdline() for Windows and
    shlex.quote() for POSIX systems.

    Args:
        path: The path string to quote

    Returns:
        Properly quoted path for the current platform
    """
    if platform.system() == "Windows":
        # subprocess.list2cmdline handles Windows quoting (double quotes)
        # We pass a single-element list to quote just this path
        return subprocess.list2cmdline([path])
    else:
        # POSIX systems use shlex.quote (single quotes)
        return shlex.quote(path)


def _get_pip_audit_command(target: Path) -> str | None:
    """Determine the appropriate pip-audit command for a project.

    pip-audit without arguments scans the current Python environment.
    This function detects project dependency files and returns a command
    that scopes the scan to project dependencies only.

    Returns:
        Command string if dependency files found, None to skip pip-audit
    """
    # Quote path for shell safety (handles spaces and special characters)
    quoted_target = _quote_path_for_shell(str(target))

    # Check for requirements.txt (most explicit)
    requirements_txt = target / "requirements.txt"
    if requirements_txt.exists():
        quoted_req = _quote_path_for_shell(str(requirements_txt))
        return f"pip-audit --format json --desc -r {quoted_req}"

    # Check for requirements/ directory with multiple files
    # Use deterministic priority: base.txt > requirements.txt > dev.txt > sorted alphabetically
    requirements_dir = target / "requirements"
    if requirements_dir.exists() and requirements_dir.is_dir():
        req_files = list(requirements_dir.glob("*.txt"))
        if req_files:
            # Priority order for common naming conventions
            priority_names = [
                "base.txt", "requirements.txt", "main.txt", "prod.txt", "production.txt"
            ]
            selected_file = None

            for priority_name in priority_names:
                for req_file in req_files:
                    if req_file.name.lower() == priority_name:
                        selected_file = req_file
                        break
                if selected_file:
                    break

            # Fallback to alphabetically first file for determinism
            if not selected_file:
                selected_file = sorted(req_files, key=lambda p: p.name.lower())[0]

            quoted_req = _quote_path_for_shell(str(selected_file))
            return f"pip-audit --format json --desc -r {quoted_req}"

    # Check for pyproject.toml with dependencies
    pyproject = target / "pyproject.toml"
    if pyproject.exists():
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore[import-not-found,no-redef]
        try:
            content = pyproject.read_text(encoding="utf-8")
            data = tomllib.loads(content)
            # Check for project dependencies (PEP 621)
            if "project" in data and "dependencies" in data.get("project", {}):
                return f"pip-audit --format json --desc --path {quoted_target}"
            # Check for poetry dependencies
            if "tool" in data and "poetry" in data.get("tool", {}):
                poetry = data["tool"]["poetry"]
                if "dependencies" in poetry:
                    return f"pip-audit --format json --desc --path {quoted_target}"
            # Check for flit dependencies
            if "tool" in data and "flit" in data.get("tool", {}):
                return f"pip-audit --format json --desc --path {quoted_target}"
        except Exception:
            pass

    # Check for Pipfile (Pipenv)
    pipfile = target / "Pipfile"
    if pipfile.exists():
        return f"pip-audit --format json --desc --path {quoted_target}"

    # Check for setup.py
    setup_py = target / "setup.py"
    if setup_py.exists():
        return f"pip-audit --format json --desc --path {quoted_target}"

    # No Python dependency file found - skip pip-audit
    return None


def _auto_generate_report(result: ScanResult, target: Path, config: VibeGuardConfig) -> None:
    """Auto-generate report based on config settings."""
    # Generate timestamp for filename
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = config.report.filename_template.replace("{datetime}", timestamp)

    # Determine output directory
    output_dir = target / config.report.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate report based on format
    report_format = config.report.format
    if report_format == "html":
        report_path = output_dir / f"{filename}.html"
        report_content = to_html(result)
    elif report_format == "json":
        report_path = output_dir / f"{filename}.json"
        report_content = result.model_dump_json(indent=2)
    elif report_format == "sarif":
        report_path = output_dir / f"{filename}.sarif"
        sarif_data = to_sarif(result)
        report_content = json.dumps(sarif_data, indent=2)
    elif report_format == "pdf":
        report_path = output_dir / f"{filename}.pdf"
        try:
            to_pdf(result, output_path=report_path)
        except RuntimeError:
            return  # weasyprint not installed, skip silently
        console.print(f"[green]Report saved:[/green] {report_path}")
        return
    else:
        return  # Unknown format, skip

    # Write report
    report_path.write_text(report_content, encoding="utf-8")
    console.print(f"[green]Report saved:[/green] {report_path}")


def scan(
    path: Path = typer.Argument(
        Path("."),
        help="Path to scan (default: current directory)",
    ),
    pack: str = typer.Option(
        "full",
        "--pack",
        "-p",
        help="Scanner pack: core, ecosystem, full (default), or auto",
    ),
    output: str = typer.Option(
        "terminal",
        "--output",
        "-o",
        help="Output format: terminal, json, sarif, html, pdf",
    ),
    save_cache: bool = typer.Option(
        True,
        "--cache/--no-cache",
        help="Save results to .vibeguard/cache/",
    ),
    bootstrap: bool = typer.Option(
        True,
        "--bootstrap/--no-bootstrap",
        help="Auto-install missing scanners before scanning",
    ),
    no_download: bool = typer.Option(
        False,
        "--no-download",
        help="Skip downloading scanner binaries",
    ),
    no_pip_install: bool = typer.Option(
        False,
        "--no-pip-install",
        help="Skip installing pip packages",
    ),
    ci: bool = typer.Option(
        False,
        "--ci",
        help="CI mode: deterministic, no downloads or installs, quiet output",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress progress output (only show summary)",
    ),
    sarif_file: Path | None = typer.Option(
        None,
        "--sarif-file",
        help="Write SARIF output to file (for GitHub Code Scanning)",
    ),
    github_annotations: bool = typer.Option(
        False,
        "--github-annotations",
        help="Emit GitHub Actions annotations for findings",
    ),
    badge: Path | None = typer.Option(
        None,
        "--badge",
        help="Generate badge SVG at specified path",
    ),
    threshold: int = typer.Option(
        0,
        "--threshold",
        "-t",
        help="Minimum score threshold (exit 10 if below)",
    ),
    no_report: bool = typer.Option(
        False,
        "--no-report",
        help="Skip auto-generating report (overrides config)",
    ),
    no_default_ignore: bool = typer.Option(
        False,
        "--no-default-ignore",
        help="Disable all default ignores: pattern list AND path classification "
        "(node_modules, .git, tests, vendor, etc.)",
    ),
    baseline_name: str | None = typer.Option(
        None,
        "--baseline",
        "-b",
        help="Compare against a saved baseline for regression checking",
    ),
    baseline_min_severity: str | None = typer.Option(
        None,
        "--baseline-min-severity",
        help="Filter baseline comparison by minimum severity (critical, high, medium, low)",
    ),
    baseline_scanner: str | None = typer.Option(
        None,
        "--baseline-scanner",
        help="Filter baseline comparison by scanner name",
    ),
    image: str | None = typer.Option(
        None,
        "--image",
        help="Docker image to scan with Dockle (e.g., 'myapp:latest', 'nginx:1.25')",
    ),
) -> None:
    """Run security scanners on a codebase.

    Scanner packs:
      core      - 5 core scanners (semgrep, gitleaks, trivy, bandit, trufflehog)
      ecosystem - Auto-detected ecosystem scanners (npm-audit, pip-audit, cargo-audit, gosec)
      full      - All scanners including differentiation (grype, bearer, horusec, kube-linter) (default)
      auto      - Core + auto-detected ecosystem

    Container scanning:
      --image IMAGE  - Run Dockle scanner on a Docker image (CIS Benchmark compliance)

    Exit codes:
      0 - Success, no findings
      1 - Success, findings detected
      2 - Scan error (partial scan)
      10 - Score below threshold

    Examples:
      vibeguard scan .
      vibeguard scan . --pack core
      vibeguard scan . --pack core --ci
      vibeguard scan . --ci --sarif-file results.sarif
      vibeguard scan . --threshold 70 --quiet
      vibeguard scan . --output json > results.json
      vibeguard scan . --baseline default
      vibeguard scan . --image myapp:latest
    """
    target = path.resolve()

    if not target.exists():
        if not quiet:
            console.print(f"[red]Error:[/red] Path does not exist: {target}")
        raise typer.Exit(ExitCode.INVALID_PATH)

    # Validate pack option
    if pack not in VALID_PACKS:
        if not quiet:
            valid = ", ".join(VALID_PACKS)
            console.print(f"[red]Error:[/red] Invalid pack '{pack}'. Must be one of: {valid}")
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    # Load configuration
    config = load_config(target)

    # Auto-detect CI environment if --ci not explicitly passed
    if not ci and _is_ci_environment():
        ci = True

    # CI mode implies no bootstrap and quiet output
    if ci:
        bootstrap = False
        no_download = True
        no_pip_install = True
        quiet = True
        # Auto-enable GitHub annotations if in GitHub Actions
        if _is_github_actions() and not github_annotations:
            github_annotations = True

    # Run async scan with bootstrap
    result = asyncio.run(
        _run_scan(
            target,
            save_cache,
            pack=pack,
            bootstrap=bootstrap,
            no_download=no_download,
            no_pip_install=no_pip_install,
            quiet=quiet,
            no_default_ignore=no_default_ignore,
            image=image,
        )
    )

    # Auto-generate report based on config (unless --no-report or CI mode)
    if config.report.auto_generate and not no_report and not ci:
        _auto_generate_report(result, target, config)

    # Auto-baseline on first scan
    if save_cache and not baseline_name:
        try:
            if not has_any_baselines(target):
                save_baseline(result, target, name="initial")
                if not quiet:
                    console.print(
                        "[dim]Saved initial baseline "
                        "(use --baseline initial for regression checks)[/dim]"
                    )
        except Exception:
            pass  # Never block scan on baseline save failure

    # Baseline comparison if requested
    comparison = None
    if baseline_name:
        baseline = load_baseline(target, baseline_name)
        if baseline is None:
            if not quiet:
                console.print(f"[red]Error:[/red] Baseline '{baseline_name}' not found.")
                console.print("[dim]Create one with: vibeguard baseline save[/dim]")
            raise typer.Exit(ExitCode.NO_CACHE)

        comparison = compare_to_baseline(result, baseline)
        if baseline_min_severity or baseline_scanner:
            from vibeguard.core.baseline import filter_comparison
            comparison = filter_comparison(
                comparison,
                min_severity=baseline_min_severity,
                scanner=baseline_scanner,
            )
        if not quiet:
            _print_comparison_summary(comparison)

    # Write SARIF file if requested
    if sarif_file:
        sarif_data = to_sarif(result)
        sarif_file.write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")
        if not quiet:
            console.print(f"[green]SARIF written:[/green] {sarif_file}")

    # Emit GitHub annotations if requested (only for actionable findings)
    if github_annotations and result.actionable_findings:
        for finding in result.actionable_findings:
            _emit_github_annotation(finding, target)

    # Generate badge if requested
    if badge:
        badge_svg = generate_badge(result.score, result.grade)
        badge.write_text(badge_svg, encoding="utf-8")
        if not quiet:
            console.print(f"[dim]Badge saved: {badge}[/dim]")

    # Output results based on format
    if output == "json":
        console.print(result.model_dump_json(indent=2))
    elif output == "sarif":
        sarif_data = to_sarif(result)
        console.print(json.dumps(sarif_data, indent=2))
    elif output == "html":
        console.print(to_html(result))
    elif output == "pdf":
        try:
            pdf_path = to_pdf(result)
            console.print(f"[green]PDF report saved:[/green] {pdf_path}")
        except RuntimeError as e:
            console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(ExitCode.CONFIG_ERROR)
    elif not quiet:
        _print_results(result)
    else:
        # Quiet mode: minimal summary
        _print_ci_summary(result)

    # Determine exit code
    if result.partial:
        raise typer.Exit(ExitCode.SCAN_ERROR)
    elif threshold > 0 and result.score < threshold:
        if not quiet:
            console.print(
                f"[red]Score {result.score} is below threshold {threshold}[/red]"
            )
        raise typer.Exit(ExitCode.THRESHOLD_EXCEEDED)
    elif comparison is not None:
        # Baseline mode: exit 1 if regressions, 0 if only improvements or unchanged
        if comparison.has_regressions:
            if not quiet:
                console.print(
                    f"[red]Regressions detected: {comparison.regression_count} new finding(s)[/red]"
                )
            raise typer.Exit(ExitCode.FINDINGS)
        else:
            if not quiet and comparison.improvement_count > 0:
                fixed = comparison.improvement_count
                console.print(f"[green]No regressions! {fixed} finding(s) fixed.[/green]")
            raise typer.Exit(ExitCode.SUCCESS)
    elif result.actionable_findings:
        raise typer.Exit(ExitCode.FINDINGS)
    else:
        raise typer.Exit(ExitCode.SUCCESS)


def _print_ci_summary(result: ScanResult) -> None:
    """Print minimal CI-friendly summary."""
    c = result.counts
    findings_summary = f"C:{c.critical} H:{c.high} M:{c.medium} L:{c.low}"
    scanners = ",".join(result.scanners_run)
    partial_flag = " [PARTIAL]" if result.partial else ""
    score_info = f"Score {result.score}/100 ({result.grade})"
    actionable = len(result.actionable_findings)
    total = len(result.findings)
    findings_info = f"Findings: {actionable}/{total}"
    summary = f"VibeGuard: {score_info} | {findings_summary} | {findings_info}"
    print(f"{summary} | Scanners: {scanners}{partial_flag}")


def _print_comparison_summary(comparison: ComparisonResult) -> None:
    """Print baseline comparison summary.

    Args:
        comparison: Result of comparing scan against baseline
    """
    console.print()
    console.print(f"[bold]Baseline Comparison: {comparison.baseline_name}[/bold]")

    new_count = len(comparison.new_findings)
    fixed_count = len(comparison.fixed_findings)
    unchanged = comparison.unchanged_count

    # Summary line with color coding
    if new_count > 0:
        console.print(f"  [red]New (Regressions): {new_count}[/red]")
    else:
        console.print("  [green]New (Regressions): 0[/green]")

    if fixed_count > 0:
        console.print(f"  [green]Fixed (Improvements): {fixed_count}[/green]")
    else:
        console.print("  [dim]Fixed (Improvements): 0[/dim]")

    console.print(f"  [dim]Unchanged: {unchanged}[/dim]")

    # Show new findings (regressions) with details
    if comparison.new_findings:
        console.print()
        console.print("[red bold]Regressions (new findings):[/red bold]")
        for f in comparison.new_findings[:10]:
            sev = f.severity.value.upper()
            sev_colors = {
                "CRITICAL": "red bold",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "blue",
                "INFO": "dim",
            }
            color = sev_colors.get(sev, "white")
            title = f.title[:50] + ("..." if len(f.title) > 50 else "")
            console.print(
                f"  [red]-[/red] [{color}]{sev}[/{color}] "
                f"{f.file_path}:{f.line_start} - {title}"
            )
        if len(comparison.new_findings) > 10:
            console.print(f"  [dim]... and {len(comparison.new_findings) - 10} more[/dim]")

    # Show fixed findings (improvements) with details
    if comparison.fixed_findings:
        console.print()
        console.print("[green bold]Improvements (fixed findings):[/green bold]")
        for f in comparison.fixed_findings[:5]:
            sev = f.severity.value.upper()
            title = f.title[:50] + ("..." if len(f.title) > 50 else "")
            console.print(
                f"  [green]+[/green] [dim]{sev}[/dim] "
                f"{f.file_path}:{f.line_start} - {title}"
            )
        if len(comparison.fixed_findings) > 5:
            console.print(f"  [dim]... and {len(comparison.fixed_findings) - 5} more[/dim]")

    console.print()


def _format_duration(seconds: float) -> str:
    """Format duration in human-readable form."""
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    else:
        mins = int(seconds // 60)
        secs = seconds % 60
        return f"{mins}m {secs:.0f}s"


def _get_scanners_for_pack(pack: str, target: Path) -> tuple[list[str], list[str]]:
    """Determine which scanners to run based on pack and repo detection.

    Returns:
        Tuple of (scanners_to_run, detected_ecosystems)
    """
    detected_ecosystem_scanners: list[str] = []

    if pack == "core":
        return CORE_SCANNERS.copy(), []
    elif pack == "ecosystem":
        detected_ecosystem_scanners = get_ecosystem_scanners(target)
        return detected_ecosystem_scanners, detected_ecosystem_scanners
    elif pack == "full":
        all_scanners = CORE_SCANNERS + ECOSYSTEM_SCANNERS + DIFFERENTIATION_SCANNERS
        return all_scanners, ECOSYSTEM_SCANNERS.copy()
    else:  # "auto" - default
        detected_ecosystem_scanners = get_ecosystem_scanners(target)
        return CORE_SCANNERS + detected_ecosystem_scanners, detected_ecosystem_scanners


async def _run_scan(
    target: Path,
    save_cache_flag: bool = True,
    *,
    pack: str = "full",
    bootstrap: bool = True,
    no_download: bool = False,
    no_pip_install: bool = False,
    quiet: bool = False,
    no_default_ignore: bool = False,
    image: str | None = None,
) -> ScanResult:
    """Execute the scan asynchronously."""
    started_at = datetime.now()
    scan_start_time = time.time()
    scanners_run: list[str] = []
    scanners_skipped: list[str] = []
    all_findings: list[Finding] = []
    partial = False
    scanner_times: dict[str, float] = {}

    # Determine scanners to run based on pack
    scanners_to_run, detected_ecosystem_scanners = _get_scanners_for_pack(pack, target)

    # Add Dockle scanner when --image is provided
    if image and "dockle" not in scanners_to_run:
        scanners_to_run.append("dockle")
        if not quiet:
            console.print(f"[cyan]Container image scan:[/cyan] {image}")
            console.print()

    # Warn if --pack ecosystem results in no scanners
    if not scanners_to_run:
        if not quiet:
            console.print(
                "[yellow]Warning:[/yellow] No scanners to run. "
                "No ecosystem files detected (package.json, requirements.txt, Cargo.toml)."
            )
            console.print(
                "[dim]Use --pack core or --pack full to run scanners anyway.[/dim]"
            )
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    # Show ecosystem detection results
    if not quiet and detected_ecosystem_scanners:
        detection_summary = get_detection_summary(target)
        if detection_summary:
            ecosystems_str = ", ".join(f"{k} ({v})" for k, v in detection_summary.items())
            console.print(f"[cyan]Detected ecosystems:[/cyan] {ecosystems_str}")
            console.print()

    # Bootstrap phase: ensure scanners are available
    if bootstrap and not quiet:
        with Progress(
            SpinnerColumn(spinner_name=VIBEGUARD_SPINNER_NAME, style=BRAND_COLOR),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            bootstrap_msg = get_bootstrap_message()
            task = progress.add_task(f"{bootstrap_msg}...", total=None)
            summary = await bootstrap_scanners(
                scanners_to_run,
                no_download=no_download,
                no_pip_install=no_pip_install,
            )
            progress.remove_task(task)

        # Force clean line separation after progress bar
        print("", flush=True)

        # Report bootstrap results
        if summary.downloaded_count > 0:
            downloaded = [
                r.display_name
                for r in summary.results
                if r.status == ScannerStatus.DOWNLOADED
            ]
            console.print(f"[green]Downloaded:[/green] {', '.join(downloaded)}")

        if summary.installed_count > 0:
            installed = [
                r.display_name
                for r in summary.results
                if r.status == ScannerStatus.INSTALLED
            ]
            console.print(f"[green]Installed:[/green] {', '.join(installed)}")

        if summary.unavailable_count > 0:
            # Separate OS-incompatible from generally unavailable
            os_unavailable = [
                r.display_name
                for r in summary.results
                if r.status == ScannerStatus.UNAVAILABLE and "Not available on" in r.message
            ]
            other_unavailable = [
                r.display_name
                for r in summary.results
                if r.status == ScannerStatus.UNAVAILABLE and "Not available on" not in r.message
            ]
            if os_unavailable:
                console.print(
                    f"[dim]Skipped (no Windows build):[/dim] {', '.join(os_unavailable)}"
                )
            if other_unavailable:
                console.print(
                    f"[yellow]Unavailable:[/yellow] {', '.join(other_unavailable)} "
                    "(will be skipped)"
                )

        console.print()
    elif bootstrap:
        # Quiet bootstrap - just run it without progress display
        await bootstrap_scanners(
            scanners_to_run,
            no_download=no_download,
            no_pip_install=no_pip_install,
        )

    # Scanner progress with progress bar (or quiet mode)
    total_scanners = len(scanners_to_run)
    findings_count = 0

    if not quiet:
        with Progress(
            SpinnerColumn(spinner_name=VIBEGUARD_SPINNER_NAME, style=BRAND_COLOR),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TextColumn("•"),
            TimeElapsedColumn(),
            TextColumn("•"),
            TextColumn("[cyan]{task.fields[findings]} findings"),
            console=console,
            transient=False,
        ) as progress:
            main_task = progress.add_task(
                "Scanning",
                total=total_scanners,
                findings=0,
            )

            for i, scanner_name in enumerate(scanners_to_run):
                scanner_msg = get_scanner_message(scanner_name)
                progress.update(main_task, description=f"{scanner_msg}")

                scanner_start = time.time()
                findings, success = await _run_scanner(
                    scanner_name, target, quiet=quiet, image=image
                )
                scanner_elapsed = time.time() - scanner_start
                scanner_times[scanner_name] = scanner_elapsed

                if success is True:
                    scanners_run.append(scanner_name)
                    all_findings.extend(findings)
                    findings_count += len(findings)
                elif success is None:
                    # Intentional skip (e.g., no dependency files for pip-audit)
                    # Don't add to scanners_run, don't set partial (not an error)
                    scanners_skipped.append(scanner_name)
                else:
                    # Actual failure
                    scanners_skipped.append(scanner_name)
                    partial = True

                progress.update(main_task, completed=i + 1, findings=findings_count)

            progress.update(main_task, description="[green]Scan complete!", refresh=True)

        # Force clean line separation after progress bar
        # This prevents Rich's terminal control codes from interfering with subsequent output
        print("", flush=True)  # Raw print to ensure clean line
        console.print()

        # Show scanner timing breakdown
        console.print("[dim]Scanner times:[/dim]")
        for scanner_name in scanners_to_run:
            if scanner_name in scanner_times:
                elapsed = scanner_times[scanner_name]
                is_run = scanner_name in scanners_run
                status = "[green]✓[/green]" if is_run else "[yellow]⊘[/yellow]"
                console.print(f"  {status} {scanner_name}: {_format_duration(elapsed)}")
        console.print()
    else:
        # Quiet mode: no progress display
        for scanner_name in scanners_to_run:
            scanner_start = time.time()
            findings, success = await _run_scanner(scanner_name, target, quiet=quiet, image=image)
            scanner_elapsed = time.time() - scanner_start
            scanner_times[scanner_name] = scanner_elapsed

            if success is True:
                scanners_run.append(scanner_name)
                all_findings.extend(findings)
                findings_count += len(findings)
            elif success is None:
                # Intentional skip (e.g., no dependency files for pip-audit)
                # Don't add to scanners_run, don't set partial (not an error)
                scanners_skipped.append(scanner_name)
            else:
                # Actual failure
                scanners_skipped.append(scanner_name)
                partial = True

    # Deduplicate findings across scanners
    deduped_findings = deduplicate_findings(all_findings)
    dedup_removed = len(all_findings) - len(deduped_findings)
    if dedup_removed > 0 and not quiet:
        console.print(f"[dim]Deduplicated: removed {dedup_removed} duplicate findings[/dim]")

    # Apply triage engine to classify findings
    # When --no-default-ignore is set, we bypass both:
    # 1. Default ignore patterns (use_default_ignores=False)
    # 2. Path-class auto-ignores (bypass_path_class=True) for VCS, GENERATED, TESTS, etc.
    ignore_patterns = load_ignore_patterns(target)
    triage_engine = TriageEngine(
        repo_root=target,
        user_patterns=ignore_patterns,
        use_default_ignores=not no_default_ignore,
        bypass_path_class=no_default_ignore,
    )
    triaged_findings = triage_engine.triage_findings(deduped_findings)

    # Show triage summary
    if not quiet:
        triage_summary = get_triage_summary(triaged_findings)
        actionable_count = triage_summary["actionable"]
        needs_review_count = triage_summary["needs_review"]
        ignored_count = triage_summary["ignored"]
        total = triage_summary["total"]

        if ignored_count > 0:
            noise_pct = (ignored_count / total * 100) if total > 0 else 0
            console.print(
                f"[dim]Triage: {actionable_count} actionable, "
                f"{needs_review_count} need review, "
                f"{ignored_count} suppressed ({noise_pct:.1f}% noise)[/dim]"
            )

            # Show breakdown by reason
            reason_breakdown = get_ignored_by_reason(triaged_findings)
            if reason_breakdown:
                reason_parts = []
                reason_labels = {
                    TriageReason.VCS_OBJECT: "VCS",
                    TriageReason.GENERATED_CACHE: "cache",
                    TriageReason.TEST_FIXTURE: "tests",
                    TriageReason.EXAMPLE_SECRET: "examples",
                    TriageReason.TEMP_FILE: "temp",
                    TriageReason.THIRD_PARTY: "vendor",
                    TriageReason.USER_IGNORE: "ignore",
                }
                for reason, count in reason_breakdown.items():
                    label = reason_labels.get(TriageReason(reason), reason)
                    reason_parts.append(f"{label}:{count}")
                console.print(f"[dim]  Suppressed by: {', '.join(reason_parts)}[/dim]")

    result = ScanResult(
        repo_root=str(target),
        started_at=started_at,
        finished_at=datetime.now(),
        findings=triaged_findings,
        scanners_run=scanners_run,
        scanners_skipped=scanners_skipped,
        partial=partial,
    )

    # Show total scan time
    total_elapsed = time.time() - scan_start_time
    if not quiet:
        console.print(f"[dim]Total scan time: {_format_duration(total_elapsed)}[/dim]")

    # Save to cache if enabled
    if save_cache_flag:
        try:
            cache_path = cache.save_scan(result, target)
            if not quiet:
                console.print(f"[dim]Results cached: {cache_path.name}[/dim]")
        except Exception as e:
            if not quiet:
                console.print(f"[yellow]Warning:[/yellow] Failed to cache results: {e}")

    # Fire-and-forget scan submission for Pro users
    try:
        from vibeguard.core.telemetry import submit_scan
        submit_scan(result)
    except Exception:
        pass  # Never block on telemetry

    return result


async def _run_scanner(
    name: str, target: Path, *, quiet: bool = False, image: str | None = None
) -> tuple[list[Finding], bool | None]:
    """Run a scanner with fallback strategies.

    Tries in order: local binary -> downloaded binary -> docker

    Args:
        name: Scanner name
        target: Target directory to scan
        quiet: Suppress progress output
        image: Docker image to scan (for Dockle scanner)

    Returns:
        Tuple of (findings, status) where status is:
        - True: Scanner ran successfully
        - False: Scanner failed to run (error)
        - None: Scanner was intentionally skipped (e.g., no dependency files)
    """
    try:
        manifest = load_manifest(name)
    except FileNotFoundError:
        if not quiet:
            console.print(f"[yellow]Warning:[/yellow] {name} manifest not found")
        return [], False

    # Special handling for pip-audit to scope to project dependencies
    if name == "pip_audit":
        pip_audit_cmd = _get_pip_audit_command(target)
        if pip_audit_cmd is None:
            if not quiet:
                console.print(
                    "[dim]pip-audit: skipped "
                    "(no requirements.txt, pyproject.toml, or Pipfile found)[/dim]"
                )
            # Return None to indicate intentional skip (not success, not error)
            return [], None
        # Override the command in the manifest for this run
        manifest = manifest.model_copy(
            update={"execution": manifest.execution.model_copy(update={"command": pip_audit_cmd})}
        )

    # Special handling for Dockle - requires --image flag
    if name == "dockle":
        if not image:
            if not quiet:
                console.print(
                    "[dim]dockle: skipped "
                    "(requires --image flag, e.g., vibeguard scan . --image myapp:latest)[/dim]"
                )
            return [], None
        # Substitute {image} placeholder in the command
        dockle_cmd = manifest.execution.command.replace("{image}", image)
        manifest = manifest.model_copy(
            update={"execution": manifest.execution.model_copy(update={"command": dockle_cmd})}
        )

    # Get the parser function
    parse_fn = _get_parser(manifest)
    if not parse_fn:
        if not quiet:
            console.print(f"[yellow]Warning:[/yellow] {name} parser not found")
        return [], False

    # Try strategies in order
    for strategy in manifest.install_strategies:
        if strategy == "local":
            result = await _try_local(manifest, target, quiet=quiet)
            if result is not None:
                return _parse_result(result, parse_fn, name, quiet=quiet)

        elif strategy == "download":
            result = await _try_download(manifest, target, quiet=quiet)
            if result is not None:
                return _parse_result(result, parse_fn, name, quiet=quiet)

        elif strategy == "docker":
            result = await _try_docker(manifest, target, quiet=quiet)
            if result is not None:
                return _parse_result(result, parse_fn, name, quiet=quiet)

    if not quiet:
        console.print(
            f"[yellow]Warning:[/yellow] {manifest.display_name} not available "
            "(install locally, or ensure Docker is running)"
        )
    return [], False


# Whitelist of allowed parser modules to prevent arbitrary code loading
# These are the only modules that can be dynamically imported as parsers
ALLOWED_PARSER_MODULES = frozenset([
    "vibeguard.scanners.parsers.semgrep",
    "vibeguard.scanners.parsers.gitleaks",
    "vibeguard.scanners.parsers.trivy",
    "vibeguard.scanners.parsers.bandit",
    "vibeguard.scanners.parsers.trufflehog",
    "vibeguard.scanners.parsers.npm_audit",
    "vibeguard.scanners.parsers.pip_audit",
    "vibeguard.scanners.parsers.cargo_audit",
    "vibeguard.scanners.parsers.checkov",
    "vibeguard.scanners.parsers.dockle",
    "vibeguard.scanners.parsers.nuclei",
    "vibeguard.scanners.parsers.gosec",
    "vibeguard.scanners.parsers.grype",
    "vibeguard.scanners.parsers.kube_linter",
    "vibeguard.scanners.parsers.bearer",
    "vibeguard.scanners.parsers.horusec",
])


def _get_parser(manifest: ScannerManifest) -> Callable[[str], list[Finding]] | None:
    """Dynamically import and return the parser function.

    Only imports from ALLOWED_PARSER_MODULES to prevent arbitrary code loading.
    """
    # Security: Only allow importing from known parser modules
    if manifest.parser_module not in ALLOWED_PARSER_MODULES:
        return None
    try:
        # Safe: parser_module is validated against ALLOWED_PARSER_MODULES whitelist above
        # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
        module = importlib.import_module(manifest.parser_module)
        return getattr(module, manifest.parser_function)  # type: ignore[no-any-return]
    except (ImportError, AttributeError):
        return None


def _parse_result(
    stdout: str,
    parse_fn: Callable[[str], list[Finding]],
    scanner_name: str,
    *,
    quiet: bool = False,
) -> tuple[list[Finding], bool]:
    """Parse scanner output into findings."""
    try:
        findings = parse_fn(stdout)
        return findings, True
    except ValueError as e:
        if not quiet:
            console.print(f"[yellow]Warning:[/yellow] Failed to parse {scanner_name} output: {e}")
        return [], False


async def _try_local(manifest: ScannerManifest, target: Path, *, quiet: bool = False) -> str | None:
    """Try running scanner with local binary."""
    if not manifest.local_config:
        return None

    runner = LocalRunner(
        binary_name=manifest.local_config.binary_name or manifest.name,
        check_command=manifest.local_config.check_command,
        version=manifest.version,
    )

    if not runner.is_available():
        return None

    if not quiet:
        console.print(f"[dim]Using local {manifest.display_name}[/dim]")
    result = await runner.run(
        manifest.execution.command,
        target,
        timeout=manifest.execution.timeout,
    )

    # Many scanners return exit code 1 when findings exist
    if result.success or result.exit_code == 1:
        return result.stdout

    return None


async def _try_download(
    manifest: ScannerManifest, target: Path, *, quiet: bool = False
) -> str | None:
    """Try downloading and running scanner binary."""
    if not manifest.download_config:
        return None

    # Create download config for downloader
    dl_config = DLConfig(
        version=manifest.version,
        url_template=manifest.download_config.url_template,
        binary_name=manifest.download_config.binary_name,
        archive_type=manifest.download_config.archive_type,
        windows_archive_type=manifest.download_config.windows_archive_type,
        windows_arch=manifest.download_config.windows_arch,
    )

    # Download if not already cached
    binary_path = await download_binary(dl_config)
    if not binary_path:
        return None

    if not quiet:
        console.print(f"[dim]Using downloaded {manifest.display_name}[/dim]")

    # Create runner with the downloaded binary path
    runner = LocalRunner(
        binary_name=manifest.download_config.binary_name,
        version=manifest.version,
    )
    runner._binary_path = str(binary_path)

    result = await runner.run(
        manifest.execution.command,
        target,
        timeout=manifest.execution.timeout,
    )

    if result.success or result.exit_code == 1:
        return result.stdout

    return None


async def _try_docker(
    manifest: ScannerManifest, target: Path, *, quiet: bool = False
) -> str | None:
    """Try running scanner with Docker."""
    if not manifest.docker_config or not manifest.docker_execution:
        return None

    docker_runner = DockerRunner(
        image=manifest.docker_config.image or f"{manifest.name}:latest",
        mount_mode=manifest.docker_config.mount_mode,
        workdir=manifest.docker_execution.workdir or "/src",
    )

    if not docker_runner.is_available():
        return None

    if not quiet:
        console.print(f"[dim]Using Docker for {manifest.display_name}[/dim]")
    result = await docker_runner.run(
        manifest.docker_execution.command,
        target,
        timeout=manifest.execution.timeout,
    )

    if result.success or result.exit_code == 1:
        return result.stdout

    return None


def _print_results(result: ScanResult) -> None:
    """Print scan results to terminal."""
    # Score panel with triage summary
    grade_colors = {
        "A+": "green",
        "A": "green",
        "B": "blue",
        "C": "yellow",
        "D": "red",
        "F": "red",
    }
    grade_color = grade_colors.get(result.grade, "white")

    actionable_count = len(result.actionable_findings)
    needs_review_count = len(result.needs_review_findings)
    ignored_count = len(result.ignored_findings)
    total_count = len(result.findings)

    console.print()
    console.print(
        Panel.fit(
            f"[bold {grade_color}]Score: {result.score}/100 ({result.grade})[/bold {grade_color}]\n"
            f"[green]Actionable: {actionable_count}[/green]  "
            f"[yellow]Needs Review: {needs_review_count}[/yellow]  "
            f"[dim]Suppressed: {ignored_count}[/dim]",
            title="VibeGuard Security Report",
        )
    )
    console.print()

    # Noise ratio indicator
    if total_count > 0 and ignored_count > 0:
        noise_pct = (ignored_count / total_count * 100)
        console.print(f"[dim]Noise Ratio: {noise_pct:.1f}% of findings auto-suppressed[/dim]")
        console.print()

    # Summary counts (actionable only)
    c = result.counts
    console.print(
        f"[red]Critical: {c.critical}[/red]  "
        f"[orange1]High: {c.high}[/orange1]  "
        f"[yellow]Medium: {c.medium}[/yellow]  "
        f"[blue]Low: {c.low}[/blue]  "
        f"[dim]Info: {c.info}[/dim]"
    )
    console.print()

    # Scanners status
    if result.scanners_run:
        console.print(f"[green]Scanners run:[/green] {', '.join(result.scanners_run)}")
    if result.scanners_skipped:
        console.print(
            f"[yellow]Scanners skipped:[/yellow] {', '.join(result.scanners_skipped)}"
        )
    if result.partial:
        console.print("[yellow]Note: Scan is partial due to scanner failures[/yellow]")
    console.print()

    # Actionable findings table (primary focus)
    if result.actionable_findings:
        table = Table(title=f"Actionable Findings ({actionable_count})")
        table.add_column("Severity", width=10)
        table.add_column("Scanner", width=10)
        table.add_column("File", max_width=35)
        table.add_column("Line", width=6, justify="right")
        table.add_column("Rule", max_width=25)
        table.add_column("Message", max_width=45)

        severity_styles = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "orange1",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }

        for finding in result.actionable_findings[:50]:  # Limit display
            table.add_row(
                f"[{severity_styles[finding.severity]}]{finding.severity.value.upper()}[/]",
                finding.scanner,
                str(finding.file_path)[:35],
                str(finding.line_start),
                finding.rule_id[:25],
                finding.message[:45] + ("..." if len(finding.message) > 45 else ""),
            )

        console.print(table)

        if actionable_count > 50:
            console.print(f"[dim]... and {actionable_count - 50} more actionable findings[/dim]")

    # Needs review findings (if any)
    if result.needs_review_findings:
        console.print()
        console.print(f"[yellow]Needs Review ({needs_review_count}):[/yellow]")
        for finding in result.needs_review_findings[:10]:
            console.print(
                f"  [dim]{finding.severity.value.upper()}[/dim] "
                f"{finding.file_path}:{finding.line_start} - {finding.rule_id}"
            )
        if needs_review_count > 10:
            console.print(f"  [dim]... and {needs_review_count - 10} more[/dim]")

    # Show export tips if any findings
    if result.findings:
        console.print()
        console.print("[dim]Export options:[/dim]")
        console.print("[dim]  vibeguard report --format html --output report.html[/dim]")
        console.print("[dim]  vibeguard report --format json --output results.json[/dim]")
        console.print("[dim]  vibeguard report --format sarif --output results.sarif[/dim]")
        console.print("[dim]  vibeguard report --badge badge.svg[/dim]")
    elif not result.actionable_findings and not result.needs_review_findings:
        success_msg = get_result_message(has_findings=False)
        console.print(f"[green]{success_msg}[/green]")

    # Final flush to ensure clean separation from any subsequent output
    print("", flush=True)
