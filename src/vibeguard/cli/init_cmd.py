"""Init command for project initialization."""

from pathlib import Path

import typer

from vibeguard.cli.display import get_console, print_banner
from vibeguard.core.resources import get_templates_dir

console = get_console()

DEFAULT_CONFIG = """\
# VibeGuard Configuration
# https://github.com/vibeguard/vibeguard-cli

[scan]
# Scanner pack to use: core, ecosystem, full
pack = "core"

# Timeout per scanner in seconds
timeout = 300

# Minimum severity to report: critical, high, medium, low, info
min_severity = "low"

[output]
# Default output format: terminal, json, sarif, html
format = "terminal"

[report]
# Auto-generate report after each scan
auto_generate = true

# Report format: html, json, sarif
format = "html"

# Directory for generated reports (relative to scanned path)
output_dir = "."

# Filename template ({datetime} replaced with timestamp)
filename_template = "vibeguard-report-{datetime}"

[scoring]
# Enable score calculation
enabled = true
"""

DEFAULT_IGNORE = """\
# VibeGuard Ignore File
# Patterns to exclude from scanning (gitignore syntax)

# Dependencies
node_modules/
vendor/
.venv/
venv/
__pycache__/

# Build outputs
dist/
build/
*.egg-info/

# Test fixtures (may contain intentional vulnerabilities)
# tests/fixtures/

# Generated files
*.min.js
*.bundle.js
"""


_TEMPLATES_DIR = get_templates_dir()


def init(
    path: Path = typer.Argument(
        Path("."),
        help="Path to initialize (default: current directory)",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite existing config files",
    ),
    ci: bool = typer.Option(
        False,
        "--ci",
        help="Generate a GitHub Actions workflow for CI security scanning",
    ),
) -> None:
    """Initialize VibeGuard in a directory."""
    print_banner(console)

    target = path.resolve()
    vibeguard_dir = target / ".vibeguard"
    config_path = vibeguard_dir / "config.toml"
    ignore_path = target / ".vibeguardignore"

    # Create .vibeguard directory
    if not vibeguard_dir.exists():
        vibeguard_dir.mkdir(parents=True)
        console.print(f"[green]Created[/green] {vibeguard_dir}")

    # Create config.toml
    if config_path.exists() and not force:
        console.print(f"[yellow]Skipped[/yellow] {config_path} (already exists)")
    else:
        config_path.write_text(DEFAULT_CONFIG)
        console.print(f"[green]Created[/green] {config_path}")

    # Create .vibeguardignore
    if ignore_path.exists() and not force:
        console.print(f"[yellow]Skipped[/yellow] {ignore_path} (already exists)")
    else:
        ignore_path.write_text(DEFAULT_IGNORE)
        console.print(f"[green]Created[/green] {ignore_path}")

    # Create GitHub Actions workflow if --ci is passed
    if ci:
        workflow_dir = target / ".github" / "workflows"
        workflow_path = workflow_dir / "vibeguard.yml"

        if workflow_path.exists() and not force:
            console.print(f"[yellow]Skipped[/yellow] {workflow_path} (already exists)")
        else:
            workflow_dir.mkdir(parents=True, exist_ok=True)
            template = (_TEMPLATES_DIR / "github-actions.yml").read_text()
            workflow_path.write_text(template)
            console.print(f"[green]Created[/green] {workflow_path}")
            console.print("Created .github/workflows/vibeguard.yml — push to trigger scans")

    console.print()
    console.print("[bold green]VibeGuard initialized![/bold green]")
    console.print("Run [cyan]vibeguard scan .[/cyan] to start scanning.")
