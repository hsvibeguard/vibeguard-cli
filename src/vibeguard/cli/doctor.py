"""Doctor command for environment checks."""

import platform
import shlex
import shutil
import subprocess  # nosec B404  # noqa: S404  # needed for scanner checks
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from vibeguard.core.downloader import get_cached_binary
from vibeguard.core.repo_detector import get_detection_summary
from vibeguard.scanners import load_manifest

console = Console()

# Scanner info: (name, binary_name, docker_image)
CORE_SCANNERS = [
    ("semgrep", "semgrep", "returntocorp/semgrep"),
    ("gitleaks", "gitleaks", "zricethezav/gitleaks"),
    ("trivy", "trivy", "aquasec/trivy"),
    ("bandit", "bandit", None),  # pip only, no docker
    ("trufflehog", "trufflehog", "trufflesecurity/trufflehog"),
]

# Ecosystem scanners: (name, check_command, install_hint)
# check_command is used to verify the scanner is actually available
ECOSYSTEM_SCANNERS = [
    ("npm_audit", "npm --version", "Bundled with Node.js"),
    ("pip_audit", "pip-audit --version", "pip install pip-audit"),
    ("cargo_audit", "cargo audit --version", "cargo install cargo-audit"),
]


def doctor() -> None:
    """Check environment and scanner availability."""
    console.print(Panel.fit("[bold blue]VibeGuard Doctor[/bold blue]"))
    console.print()

    # System info
    _print_system_info()

    # Prerequisites
    _check_prerequisites()

    # Core Scanners
    _check_scanners()

    # Ecosystem Scanners
    _check_ecosystem_scanners()

    # Detected ecosystems in current directory
    _show_detected_ecosystems()


def _print_system_info() -> None:
    """Display system information."""
    table = Table(title="System Information", show_header=False)
    table.add_column("Property", style="cyan")
    table.add_column("Value")

    table.add_row("OS", platform.system())
    table.add_row("Architecture", platform.machine())
    table.add_row("Python", platform.python_version())

    console.print(table)
    console.print()


def _check_prerequisites() -> None:
    """Check for required tools."""
    table = Table(title="Prerequisites")
    table.add_column("Tool", style="cyan")
    table.add_column("Status")
    table.add_column("Action")

    # Git
    git_path = shutil.which("git")
    if git_path:
        table.add_row("git", "[green]Found[/green]", f"[dim]{git_path}[/dim]")
    else:
        table.add_row("git", "[red]Not found[/red]", "Install git: https://git-scm.com/")

    # Docker
    docker_path = shutil.which("docker")
    if docker_path:
        table.add_row("docker", "[green]Found[/green]", f"[dim]{docker_path}[/dim]")
    else:
        table.add_row(
            "docker",
            "[yellow]Not found[/yellow]",
            "Optional: https://docker.com/",
        )

    console.print(table)
    console.print()


def _check_scanners() -> None:
    """Check for available scanners."""
    table = Table(title="Scanners (Core Pack)")
    table.add_column("Scanner", style="cyan")
    table.add_column("Status", width=14)
    table.add_column("Source", width=20)

    docker_available = shutil.which("docker") is not None
    all_ready = True
    missing_scanners = []

    for name, binary, docker_image in CORE_SCANNERS:
        # Check system PATH first
        system_path = shutil.which(binary)
        if system_path:
            table.add_row(name, "[green]Ready[/green]", f"[dim]PATH: {binary}[/dim]")
            continue

        # Check downloaded cache
        try:
            manifest = load_manifest(name)
            version = manifest.version
            cached = get_cached_binary(binary, version)
            if cached:
                table.add_row(name, "[green]Ready[/green]", "[dim]Cached[/dim]")
                continue
        except FileNotFoundError:
            pass

        # Check Docker fallback
        if docker_image and docker_available:
            table.add_row(name, "[blue]Docker[/blue]", f"[dim]{docker_image}[/dim]")
            continue

        # Not available
        all_ready = False
        missing_scanners.append(name)
        if docker_image:
            table.add_row(name, "[yellow]Missing[/yellow]", "[dim]Install or start Docker[/dim]")
        else:
            table.add_row(name, "[yellow]Missing[/yellow]", "[dim]pip install required[/dim]")

    console.print(table)
    console.print()

    # Summary and tips
    if all_ready:
        console.print("[green]All core scanners ready![/green]")
    elif missing_scanners:
        console.print(
            "[yellow]Some scanners missing.[/yellow] "
            "They will be auto-installed on first scan."
        )
        console.print("Or install manually:")
        for scanner in missing_scanners:
            if scanner == "bandit":
                console.print("  [cyan]pip install bandit[/cyan]")
            elif scanner == "semgrep":
                console.print("  [cyan]pip install semgrep[/cyan]")
            else:
                console.print(f"  [dim]{scanner} will be auto-downloaded on scan[/dim]")
    console.print()


def _check_ecosystem_scanners() -> None:
    """Check for ecosystem scanner availability."""
    table = Table(title="Scanners (Ecosystem Pack)")
    table.add_column("Scanner", style="cyan")
    table.add_column("Status", width=14)
    table.add_column("Install", width=30)

    for name, check_command, install_hint in ECOSYSTEM_SCANNERS:
        # Run the check command to verify scanner is available
        is_available = _run_check_command(check_command)

        if is_available:
            table.add_row(name, "[green]Ready[/green]", f"[dim]{check_command.split()[0]}[/dim]")
        else:
            # Check if it's pip-audit which can be auto-installed
            if name == "pip_audit":
                table.add_row(name, "[blue]Auto-install[/blue]", f"[dim]{install_hint}[/dim]")
            else:
                table.add_row(name, "[yellow]Not found[/yellow]", f"[dim]{install_hint}[/dim]")

    console.print(table)
    console.print()


def _run_check_command(command: str) -> bool:
    """Run a check command and return True if it succeeds.

    The command is split using shlex to avoid shell injection.
    Commands are expected to be simple version checks from trusted sources
    (hardcoded in ECOSYSTEM_SCANNERS).
    """
    try:
        # Split command safely without shell interpretation
        args = shlex.split(command)
        result = subprocess.run(  # nosec B603
            args,
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError):
        return False


def _show_detected_ecosystems() -> None:
    """Show ecosystems detected in current directory."""
    cwd = Path.cwd()
    detection = get_detection_summary(cwd)

    if detection:
        console.print("[cyan]Detected ecosystems in current directory:[/cyan]")
        for ecosystem, file in detection.items():
            console.print(f"  • {ecosystem} [dim](found {file})[/dim]")
        console.print()
        console.print(
            "[dim]Run [cyan]vibeguard scan .[/cyan] to scan with "
            "auto-detected ecosystem scanners.[/dim]"
        )
    else:
        console.print(
            "[dim]No ecosystem-specific files detected. "
            "Use [cyan]--pack full[/cyan] to run all scanners.[/dim]"
        )
    console.print()
