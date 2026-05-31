"""Main CLI entry point for VibeGuard."""

import sys
import threading
import warnings

# Suppress Windows asyncio pipe transport warnings (cosmetic, harmless)
if sys.platform == "win32":
    warnings.filterwarnings("ignore", message="unclosed transport", category=ResourceWarning)

import questionary
import typer
from questionary import Style
from rich.console import Console
from rich.live import Live
from rich.spinner import Spinner
from rich.text import Text

from vibeguard import __version__
from vibeguard.cli import (
    apply,
    auth_cmd,
    baseline_cmd,
    config_cmd,
    doctor,
    fix,
    import_cmd,
    init_cmd,
    keys,
    live_cmd,
    patch,
    report,
    scan,
)
from vibeguard.cli.display import (
    BRAND_COLOR,
    VIBEGUARD_SPINNER_NAME,
    get_console,
    print_banner,
)
from vibeguard.core.license import is_pro_licensed

app = typer.Typer(
    name="vibeguard",
    help="Unified security scanner orchestrator for local repos",
    invoke_without_command=True,
    rich_markup_mode="rich",
)

console = Console()

# Register subcommands
app.command(name="doctor")(doctor.doctor)
app.command(name="init")(init_cmd.init)
app.command(name="scan")(scan.scan)
app.command(name="report")(report.report)
app.command(name="fix")(fix.fix)
app.command(name="patch")(patch.patch)
app.command(name="apply")(apply.apply)
app.command(name="live")(live_cmd.live)
app.add_typer(keys.app, name="keys")
app.add_typer(config_cmd.app, name="config")
app.add_typer(baseline_cmd.app, name="baseline")
app.add_typer(import_cmd.app, name="import")
app.add_typer(auth_cmd.app, name="auth")


def version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold]vibeguard[/bold] version {__version__}")
        raise typer.Exit()


# Custom style for questionary
custom_style = Style([
    ("qmark", "fg:#673ab7 bold"),
    ("question", "bold"),
    ("answer", "fg:#00ff00 bold"),
    ("pointer", "fg:#673ab7 bold"),
    ("highlighted", "fg:#673ab7 bold"),
    ("selected", "fg:#00ff00"),
])

# Command descriptions for interactive menu
# tier: "free" = available to all, "pro" = requires Pro license
COMMANDS = [
    {"name": "scan", "description": "Run security scanners on a codebase",
     "has_subcommands": False, "tier": "free"},
    {"name": "live", "description": "[EXPERIMENTAL] Run DAST scan on a live URL",
     "has_subcommands": False, "tier": "free"},
    {"name": "doctor", "description": "Check environment and scanner availability",
     "has_subcommands": False, "tier": "free"},
    {"name": "init", "description": "Initialize VibeGuard in a directory",
     "has_subcommands": False, "tier": "free"},
    {"name": "report", "description": "Generate reports from cached scan results",
     "has_subcommands": False, "tier": "free"},
    {"name": "fix", "description": "Generate a copy-paste prompt for fixing a finding",
     "has_subcommands": False, "tier": "free"},
    {"name": "patch", "description": "Generate a patch using your LLM key (Pro)",
     "has_subcommands": False, "tier": "pro"},
    {"name": "apply", "description": "Apply a patch with git safety checks (Pro)",
     "has_subcommands": False, "tier": "pro"},
    {"name": "auth", "description": "Manage Pro license authentication",
     "has_subcommands": True, "tier": "free"},
    {"name": "keys", "description": "Manage LLM API keys for patch generation",
     "has_subcommands": True, "tier": "free"},
    {"name": "config", "description": "Manage settings (auto-report, format, etc.)",
     "has_subcommands": True, "tier": "free"},
    {"name": "baseline", "description": "Manage security baselines for regression checking",
     "has_subcommands": True, "tier": "free"},
    {"name": "import", "description": "Import external scan results (SARIF)",
     "has_subcommands": True, "tier": "free"},
]

# Subcommands for nested menus
KEYS_SUBCOMMANDS = [
    {"name": "list", "description": "List all configured API keys"},
    {"name": "set", "description": "Store an API key for an LLM provider"},
    {"name": "get", "description": "Check if an API key is configured"},
    {"name": "delete", "description": "Delete an API key for a provider"},
]

CONFIG_SUBCOMMANDS = [
    {"name": "show", "description": "Show current settings"},
    {"name": "edit", "description": "Interactively edit report settings"},
    {"name": "set", "description": "Set a specific setting value"},
]

BASELINE_SUBCOMMANDS = [
    {"name": "save", "description": "Save current scan as a baseline"},
    {"name": "list", "description": "List all saved baselines"},
    {"name": "show", "description": "Show baseline details"},
    {"name": "delete", "description": "Delete a baseline"},
]

IMPORT_SUBCOMMANDS = [
    {"name": "sarif", "description": "Import from SARIF 2.1.0 file (CodeQL, Snyk, etc.)"},
]

AUTH_SUBCOMMANDS = [
    {"name": "login", "description": "Activate Pro license for this machine"},
    {"name": "status", "description": "Show current license status"},
    {"name": "logout", "description": "Deactivate license and clear token"},
]


def _validate_key_with_spinner(provider: str, api_key: str) -> tuple[bool, str]:
    """Validate an API key with a spinner animation.

    Args:
        provider: The LLM provider name
        api_key: The API key to validate

    Returns:
        Tuple of (is_valid, message)
    """
    from vibeguard.core.validate import validate_api_key

    result: tuple[bool, str] = (False, "Validation failed")
    validation_done = threading.Event()

    def do_validation() -> None:
        nonlocal result
        try:
            result = validate_api_key(provider, api_key)
        except Exception as e:
            result = (False, f"Validation error: {e}")
        finally:
            validation_done.set()

    # Start validation in background thread
    thread = threading.Thread(target=do_validation, daemon=True)
    thread.start()

    # Show spinner while validating (using VibeGuard brand spinner)
    spinner = Spinner(VIBEGUARD_SPINNER_NAME, text=Text(" Validating...", style=BRAND_COLOR))
    with Live(spinner, console=console, transient=True, refresh_per_second=10):
        # Wait for validation to complete (with timeout)
        validation_done.wait(timeout=30)

    return result


def show_keys_submenu() -> list[str]:
    """Show keys subcommand menu and return argv."""
    choices = [
        questionary.Choice(
            title=f"{cmd['name']:10} - {cmd['description']}",
            value=cmd['name']
        )
        for cmd in KEYS_SUBCOMMANDS
    ]
    choices.append(questionary.Choice(title="← Back", value="back"))

    selected = questionary.select(
        "Keys - What would you like to do?",
        choices=choices,
        style=custom_style,
    ).ask()

    if selected is None or selected == "back":
        return []

    # For set/get/delete, we need provider argument
    if selected in ("set", "get", "delete"):
        from vibeguard.core.keyring import list_providers
        providers = list_providers()

        provider = questionary.select(
            "Select provider:",
            choices=providers + ["← Back"],
            style=custom_style,
        ).ask()

        if provider is None or provider == "← Back":
            return []

        if selected == "set":
            # Show paste hint
            console.print("[dim]Tip: Right-click or Ctrl+V to paste your API key[/dim]")

            api_key = questionary.password(
                f"Enter API key for {provider}:",
                style=custom_style,
            ).ask()

            if api_key is None or not api_key.strip():
                return []

            # Validate the key with spinner
            is_valid, message = _validate_key_with_spinner(provider, api_key)

            if not is_valid:
                console.print(f"[red]✗ {message}[/red]")
                # Ask if they want to try again
                retry = questionary.confirm(
                    "Try entering the key again?",
                    default=True,
                    style=custom_style,
                ).ask()
                if retry:
                    return show_keys_submenu()  # Recursively show menu again
                return []

            console.print(f"[green]✓ {message}[/green]")
            return ["vibeguard", "keys", "set", provider, api_key]

        return ["vibeguard", "keys", selected, provider]

    return ["vibeguard", "keys", selected]


def show_config_submenu() -> list[str]:
    """Show config subcommand menu and return argv."""
    choices = [
        questionary.Choice(
            title=f"{cmd['name']:10} - {cmd['description']}",
            value=cmd['name']
        )
        for cmd in CONFIG_SUBCOMMANDS
    ]
    choices.append(questionary.Choice(title="← Back", value="back"))

    selected = questionary.select(
        "Config - What would you like to do?",
        choices=choices,
        style=custom_style,
    ).ask()

    if selected is None or selected == "back":
        return []

    if selected == "set":
        # Prompt for key and value
        key = questionary.text(
            "Setting key (e.g., report.auto_generate, report.format):",
            style=custom_style,
        ).ask()

        if key is None or not key.strip():
            return []

        value = questionary.text(
            f"Value for {key}:",
            style=custom_style,
        ).ask()

        if value is None:
            return []

        return ["vibeguard", "config", "set", key, value]

    return ["vibeguard", "config", selected]


def show_baseline_submenu() -> list[str]:
    """Show baseline subcommand menu and return argv."""
    choices = [
        questionary.Choice(
            title=f"{cmd['name']:10} - {cmd['description']}",
            value=cmd['name']
        )
        for cmd in BASELINE_SUBCOMMANDS
    ]
    choices.append(questionary.Choice(title="← Back", value="back"))

    selected = questionary.select(
        "Baseline - What would you like to do?",
        choices=choices,
        style=custom_style,
    ).ask()

    if selected is None or selected == "back":
        return []

    if selected == "save":
        # Optionally prompt for baseline name
        name = questionary.text(
            "Baseline name (Enter for 'default'):",
            default="default",
            style=custom_style,
        ).ask()

        if name is None:
            return []

        return ["vibeguard", "baseline", "save", name.strip() or "default"]

    if selected in ("show", "delete"):
        # List available baselines for selection
        from pathlib import Path

        from vibeguard.core.baseline import list_baselines

        baselines = list_baselines(Path("."))

        if not baselines:
            console.print("[yellow]No baselines found.[/yellow]")
            console.print("[dim]Create one with: vibeguard baseline save[/dim]")
            return []

        baseline_choices = [
            questionary.Choice(
                title=f"{b.name} ({b.actionable_count} findings, {b.created_at:%Y-%m-%d})",
                value=b.name
            )
            for b in baselines
        ]
        baseline_choices.append(questionary.Choice(title="← Back", value="back"))

        selected_baseline = questionary.select(
            f"Select baseline to {selected}:",
            choices=baseline_choices,
            style=custom_style,
        ).ask()

        if selected_baseline is None or selected_baseline == "back":
            return []

        return ["vibeguard", "baseline", selected, selected_baseline]

    return ["vibeguard", "baseline", selected]


def show_import_submenu() -> list[str]:
    """Show import subcommand menu and return argv."""
    choices = [
        questionary.Choice(
            title=f"{cmd['name']:10} - {cmd['description']}",
            value=cmd['name']
        )
        for cmd in IMPORT_SUBCOMMANDS
    ]
    choices.append(questionary.Choice(title="← Back", value="back"))

    selected = questionary.select(
        "Import - What would you like to do?",
        choices=choices,
        style=custom_style,
    ).ask()

    if selected is None or selected == "back":
        return []

    if selected == "sarif":
        # Prompt for SARIF file path
        from pathlib import Path

        sarif_path = questionary.path(
            "Path to SARIF file:",
            style=custom_style,
        ).ask()

        if sarif_path is None or not sarif_path.strip():
            return []

        sarif_file = Path(sarif_path.strip())
        if not sarif_file.exists():
            console.print(f"[red]File not found:[/red] {sarif_file}")
            return []

        return ["vibeguard", "import", "sarif", str(sarif_file)]

    return ["vibeguard", "import", selected]


def show_auth_submenu() -> list[str]:
    """Show auth subcommand menu and return argv."""
    choices = [
        questionary.Choice(
            title=f"{cmd['name']:10} - {cmd['description']}",
            value=cmd['name']
        )
        for cmd in AUTH_SUBCOMMANDS
    ]
    choices.append(questionary.Choice(title="← Back", value="back"))

    selected = questionary.select(
        "Auth - What would you like to do?",
        choices=choices,
        style=custom_style,
    ).ask()

    if selected is None or selected == "back":
        return []

    if selected == "login":
        # Prompt for license key
        console.print("[dim]Tip: Right-click or Ctrl+V to paste your license key[/dim]")

        license_key = questionary.text(
            "Enter your license key:",
            style=custom_style,
        ).ask()

        if license_key is None or not license_key.strip():
            return []

        return ["vibeguard", "auth", "login", license_key.strip()]

    return ["vibeguard", "auth", selected]


def run_command(argv: list[str]) -> None:
    """Run a command and catch Exit to allow menu to continue."""
    sys.argv = argv
    try:
        app(standalone_mode=False)
    except SystemExit:
        pass  # Ignore exit, we'll show menu again
    except typer.Exit:
        pass  # Ignore exit, we'll show menu again


def run_custom_command() -> None:
    """Prompt for and run a custom vibeguard command."""
    console.print("[dim]Tip: Type command without 'vibeguard' prefix (e.g., 'scan . --badge badge.svg')[/dim]")
    console.print("[dim]     Right-click or Ctrl+V to paste[/dim]")

    cmd_input = questionary.text(
        "vibeguard",
        style=custom_style,
    ).ask()

    if cmd_input is None or not cmd_input.strip():
        return

    # Parse the command into argv
    import shlex
    try:
        args = shlex.split(cmd_input.strip())
    except ValueError:
        args = cmd_input.strip().split()

    # Strip leading "vibeguard" prefix if the user typed the full command
    # (e.g., "vibeguard auth logout" -> "auth logout")
    if args and args[0].lower() == "vibeguard":
        args = args[1:]

    if args:
        run_command(["vibeguard"] + args)


def show_interactive_menu() -> None:
    """Show interactive command selection menu."""
    while True:
        is_pro = is_pro_licensed()
        choices = []
        for cmd in COMMANDS:
            tier = cmd.get("tier", "free")
            if tier == "pro" and not is_pro:
                emoji = "\U0001f512"  # lock
            else:
                emoji = "\U0001f7e2"  # green circle
            choices.append(
                questionary.Choice(
                    title=f"{emoji} {cmd['name']:10} - {cmd['description']}",
                    value=cmd['name']
                )
            )
        choices.append(questionary.Choice(title="► Run command - Type a custom command with options", value="custom"))
        choices.append(questionary.Choice(title="Exit", value="exit"))

        selected = questionary.select(
            "What would you like to do?",
            choices=choices,
            style=custom_style,
        ).ask()

        if selected is None or selected == "exit":
            raise typer.Exit()

        # Handle custom command input
        if selected == "custom":
            run_custom_command()
            console.print()
            continue

        # Handle commands with subcommands
        if selected == "keys":
            argv = show_keys_submenu()
            if not argv:
                # User went back, show main menu again
                continue
            run_command(argv)
            console.print()  # Add spacing before next menu
            continue

        if selected == "config":
            argv = show_config_submenu()
            if not argv:
                # User went back, show main menu again
                continue
            run_command(argv)
            console.print()
            continue

        if selected == "baseline":
            argv = show_baseline_submenu()
            if not argv:
                # User went back, show main menu again
                continue
            run_command(argv)
            console.print()
            continue

        if selected == "import":
            argv = show_import_submenu()
            if not argv:
                # User went back, show main menu again
                continue
            run_command(argv)
            console.print()
            continue

        if selected == "auth":
            argv = show_auth_submenu()
            if not argv:
                # User went back, show main menu again
                continue
            run_command(argv)
            console.print()
            continue

        # Handle scan - default to current directory
        if selected == "scan":
            path = questionary.path(
                "Path to scan (Enter for current directory):",
                default=".",
                style=custom_style,
            ).ask()

            if path is None:
                continue

            run_command(["vibeguard", "scan", path])
            console.print()
            continue

        # Handle live - DAST scanning
        if selected == "live":
            url = questionary.text(
                "Target URL (e.g., http://localhost:8080):",
                style=custom_style,
            ).ask()

            if url is None or not url.strip():
                continue

            # Check if non-localhost and prompt for --i-own-this
            from vibeguard.core.url_validator import validate_url
            validation = validate_url(url)

            cmd = ["vibeguard", "live", url.strip()]
            if not validation.is_localhost:
                console.print()
                console.print("[yellow]This is a non-localhost target.[/yellow]")
                console.print("[yellow]Unauthorized scanning may be illegal.[/yellow]")
                confirm = questionary.confirm(
                    "Do you own this target and have permission to scan it?",
                    default=False,
                    style=custom_style,
                ).ask()
                if confirm:
                    cmd.append("--i-own-this")
                else:
                    console.print("[dim]Scan cancelled.[/dim]")
                    continue

            run_command(cmd)
            console.print()
            continue

        # Handle apply - needs patch file path
        if selected == "apply":
            # Check for available patches
            from pathlib import Path
            patches_dir = Path(".vibeguard/patches")
            patches = []
            if patches_dir.exists():
                patches = list(patches_dir.glob("*.patch"))

            if patches:
                # Let user select from available patches
                choices = [
                    questionary.Choice(title=p.name, value=str(p))
                    for p in patches[:10]
                ]
                choices.append(questionary.Choice(title="Enter path manually...", value="manual"))
                choices.append(questionary.Choice(title="← Back", value="back"))

                selected_patch = questionary.select(
                    "Select patch to apply:",
                    choices=choices,
                    style=custom_style,
                ).ask()

                if selected_patch is None or selected_patch == "back":
                    continue

                if selected_patch == "manual":
                    patch_path = questionary.path(
                        "Path to patch file:",
                        style=custom_style,
                    ).ask()
                    if patch_path is None or not patch_path.strip():
                        continue
                    selected_patch = patch_path
            else:
                # No patches found, ask for manual path
                patch_path = questionary.path(
                    "Path to patch file:",
                    style=custom_style,
                ).ask()
                if patch_path is None or not patch_path.strip():
                    continue
                selected_patch = patch_path

            # Ask about dry run
            dry_run = questionary.confirm(
                "Dry run? (check without applying)",
                default=False,
                style=custom_style,
            ).ask()

            cmd = ["vibeguard", "apply", selected_patch]
            if dry_run:
                cmd.append("--dry-run")

            run_command(cmd)
            console.print()
            continue

        # Simple commands without arguments
        run_command(["vibeguard", selected])
        console.print()
        # Loop continues - show menu again


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        None,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit",
    ),
) -> None:
    """VibeGuard CLI - Unified Security Scanner Orchestrator"""
    if ctx.invoked_subcommand is None:
        # No command provided - show logo + interactive menu
        print_banner(get_console(), is_pro=is_pro_licensed())
        show_interactive_menu()


if __name__ == "__main__":
    app()
