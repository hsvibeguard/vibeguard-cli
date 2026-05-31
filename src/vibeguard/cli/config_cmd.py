"""Config command - manage VibeGuard settings."""

from __future__ import annotations

from pathlib import Path

import questionary
import typer
from questionary import Style
from rich.table import Table

from vibeguard.cli.display import get_console
from vibeguard.core.config import find_config_file, load_config, save_config

app = typer.Typer(
    name="config",
    help="Manage VibeGuard configuration settings.",
    invoke_without_command=True,
)

console = get_console()

# Custom style for questionary
custom_style = Style([
    ("qmark", "fg:#673ab7 bold"),
    ("question", "bold"),
    ("answer", "fg:#00ff00 bold"),
    ("pointer", "fg:#673ab7 bold"),
    ("highlighted", "fg:#673ab7 bold"),
    ("selected", "fg:#00ff00"),
])


@app.callback(invoke_without_command=True)
def config_callback(ctx: typer.Context) -> None:
    """Manage VibeGuard configuration settings."""
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


@app.command("show")
def show_config(
    path: Path = typer.Argument(
        Path("."),
        help="Path to search for config (default: current directory)",
    ),
) -> None:
    """Show current configuration settings.

    Example:
        vibeguard config show
    """
    config_path = find_config_file(path)
    config = load_config(path)

    if config_path:
        console.print(f"[dim]Config file: {config_path}[/dim]\n")
    else:
        console.print("[dim]Using default settings (no config file found)[/dim]\n")

    # Scan settings
    table = Table(title="Scan Settings")
    table.add_column("Setting", style="cyan")
    table.add_column("Value")
    table.add_row("pack", config.scan.pack)
    table.add_row("timeout", str(config.scan.timeout))
    table.add_row("min_severity", config.scan.min_severity)
    console.print(table)
    console.print()

    # Report settings
    table = Table(title="Report Settings")
    table.add_column("Setting", style="cyan")
    table.add_column("Value")
    table.add_row("auto_generate", "[green]Yes[/green]" if config.report.auto_generate else "[red]No[/red]")
    table.add_row("format", config.report.format)
    table.add_row("output_dir", config.report.output_dir)
    table.add_row("filename_template", config.report.filename_template)
    console.print(table)
    console.print()

    # Output settings
    table = Table(title="Output Settings")
    table.add_column("Setting", style="cyan")
    table.add_column("Value")
    table.add_row("format", config.output.format)
    console.print(table)


@app.command("set")
def set_config(
    key: str = typer.Argument(..., help="Setting key (e.g., report.auto_generate, report.format)"),
    value: str = typer.Argument(..., help="Setting value"),
    path: Path = typer.Option(
        Path("."),
        "--path",
        "-p",
        help="Path to config directory",
    ),
) -> None:
    """Set a configuration value.

    Examples:
        vibeguard config set report.auto_generate true
        vibeguard config set report.format json
        vibeguard config set report.output_dir ./reports
    """
    config_path = find_config_file(path)
    if not config_path:
        config_path = path.resolve() / ".vibeguard" / "config.toml"

    config = load_config(path)

    # Parse the key path
    parts = key.split(".")
    if len(parts) != 2:
        console.print("[red]Error:[/red] Invalid key format. Use section.setting (e.g., report.format)")
        raise typer.Exit(1)

    section, setting = parts

    # Update the config based on section
    try:
        if section == "report":
            if setting == "auto_generate":
                config.report.auto_generate = value.lower() in ("true", "yes", "1", "on")
            elif setting == "format":
                if value not in ("html", "json", "sarif"):
                    console.print("[red]Error:[/red] Invalid format. Choose: html, json, sarif")
                    raise typer.Exit(1)
                config.report.format = value  # type: ignore
            elif setting == "output_dir":
                config.report.output_dir = value
            elif setting == "filename_template":
                config.report.filename_template = value
            else:
                console.print(f"[red]Error:[/red] Unknown setting: report.{setting}")
                raise typer.Exit(1)
        elif section == "scan":
            if setting == "pack":
                if value not in ("core", "ecosystem", "full"):
                    console.print("[red]Error:[/red] Invalid pack. Choose: core, ecosystem, full")
                    raise typer.Exit(1)
                config.scan.pack = value  # type: ignore
            elif setting == "timeout":
                config.scan.timeout = int(value)
            elif setting == "min_severity":
                if value not in ("critical", "high", "medium", "low", "info"):
                    console.print("[red]Error:[/red] Invalid severity. Choose: critical, high, medium, low, info")
                    raise typer.Exit(1)
                config.scan.min_severity = value  # type: ignore
            else:
                console.print(f"[red]Error:[/red] Unknown setting: scan.{setting}")
                raise typer.Exit(1)
        elif section == "output":
            if setting == "format":
                if value not in ("terminal", "json", "sarif", "html"):
                    console.print("[red]Error:[/red] Invalid format. Choose: terminal, json, sarif, html")
                    raise typer.Exit(1)
                config.output.format = value  # type: ignore
            else:
                console.print(f"[red]Error:[/red] Unknown setting: output.{setting}")
                raise typer.Exit(1)
        else:
            console.print(f"[red]Error:[/red] Unknown section: {section}")
            console.print("Available sections: scan, output, report")
            raise typer.Exit(1)

        # Save the config
        save_config(config, config_path)
        console.print(f"[green]Updated:[/green] {key} = {value}")
        console.print(f"[dim]Saved to: {config_path}[/dim]")

    except ValueError as e:
        console.print(f"[red]Error:[/red] Invalid value: {e}")
        raise typer.Exit(1)


@app.command("edit")
def edit_config_interactive(
    path: Path = typer.Argument(
        Path("."),
        help="Path to search for config (default: current directory)",
    ),
) -> None:
    """Interactively edit report settings.

    Example:
        vibeguard config edit
    """
    config_path = find_config_file(path)
    if not config_path:
        config_path = path.resolve() / ".vibeguard" / "config.toml"

    config = load_config(path)

    console.print("[bold]Report Settings[/bold]\n")

    # Auto-generate
    auto_gen = questionary.confirm(
        "Auto-generate report after scan?",
        default=config.report.auto_generate,
        style=custom_style,
    ).ask()

    if auto_gen is None:
        raise typer.Exit()

    config.report.auto_generate = auto_gen

    if auto_gen:
        # Format
        fmt = questionary.select(
            "Report format:",
            choices=["html", "json", "sarif"],
            default=config.report.format,
            style=custom_style,
        ).ask()

        if fmt is None:
            raise typer.Exit()

        config.report.format = fmt  # type: ignore

        # Output directory
        output_dir = questionary.text(
            "Output directory (relative to scan path):",
            default=config.report.output_dir,
            style=custom_style,
        ).ask()

        if output_dir is None:
            raise typer.Exit()

        config.report.output_dir = output_dir

        # Filename template
        filename = questionary.text(
            "Filename template ({datetime} for timestamp):",
            default=config.report.filename_template,
            style=custom_style,
        ).ask()

        if filename is None:
            raise typer.Exit()

        config.report.filename_template = filename

    # Save
    save_config(config, config_path)
    console.print("\n[green]Settings saved![/green]")
    console.print(f"[dim]Config file: {config_path}[/dim]")
