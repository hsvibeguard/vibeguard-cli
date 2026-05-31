"""Auth command - manage Pro license authentication."""

from __future__ import annotations

import asyncio
import threading

import typer
from rich.live import Live
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from vibeguard.cli.display import BRAND_COLOR, VIBEGUARD_SPINNER_NAME, get_console
from vibeguard.core.auth import (
    LicenseError,
    NetworkError,
    activate_license,
    clear_auth_cache,
    get_cached_token,
    get_or_create_machine_id,
    get_token_time_remaining,
    mask_license_key,
    save_token_to_cache,
    should_refresh_token,
)
from vibeguard.core.exit_codes import ExitCode
from vibeguard.core.keyring import get_configured_providers

app = typer.Typer(
    name="auth",
    help="Manage Pro license authentication.",
    invoke_without_command=True,
    no_args_is_help=True,
)

console = get_console()


@app.callback(invoke_without_command=True)
def auth_callback(ctx: typer.Context) -> None:
    """Manage Pro license authentication.

    Activate your Pro license to unlock premium features like
    automated patch generation and application.

    Examples:
        vibeguard auth login VGPRO-XXXX-XXXX-XXXX   # Activate license
        vibeguard auth status                        # Check license status
        vibeguard auth logout                        # Deactivate this machine
    """
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


def _activate_with_spinner(license_key: str) -> tuple[bool, str, object | None]:
    """Run activation in background thread with spinner.

    Returns:
        Tuple of (success, message, response_or_error)
    """
    result: tuple[bool, str, object | None] = (False, "Activation failed", None)
    done = threading.Event()

    def do_activate() -> None:
        nonlocal result
        try:
            response = asyncio.run(activate_license(license_key))
            result = (True, "License activated successfully!", response)
        except LicenseError as e:
            result = (False, str(e), e)
        except NetworkError as e:
            result = (False, str(e), e)
        except Exception as e:
            result = (False, f"Unexpected error: {e}", e)
        finally:
            done.set()

    thread = threading.Thread(target=do_activate, daemon=True)
    thread.start()

    spinner = Spinner(VIBEGUARD_SPINNER_NAME, text=Text(" Activating license...", style=BRAND_COLOR))
    with Live(spinner, console=console, transient=True):
        done.wait(timeout=45)

    if not done.is_set():
        return (False, "Activation timed out. Please try again.", None)

    return result


@app.command("login")
def login(
    license_key: str | None = typer.Argument(
        None,
        help="Your VibeGuard Pro license key (e.g., VGPRO-XXXX-XXXX-XXXX)",
    ),
) -> None:
    """Activate Pro license for this machine.

    Your license key can be found in your account at https://vibeguard.co/account

    Example:
        vibeguard auth login VGPRO-XXXX-XXXX-XXXX
    """
    # Handle missing argument
    if license_key is None:
        console.print("[red]Error:[/red] Missing license key.\n")
        console.print("[bold]Usage:[/bold] vibeguard auth login <license-key>\n")
        console.print("[bold]Example:[/bold] vibeguard auth login VGPRO-XXXX-XXXX-XXXX\n")
        console.print("Get your license key at: [link=https://vibeguard.co/pricing]https://vibeguard.co/pricing[/link]")
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    # Check if already logged in
    existing_token = get_cached_token()
    if existing_token is not None:
        # If user provided a different license key, clear old token and re-activate
        if license_key and existing_token.license_id and license_key != existing_token.license_id:
            # Proceed with new activation (clear old cache first)
            console.print("[yellow]Switching license — clearing previous activation...[/yellow]\n")
            clear_auth_cache()
        else:
            console.print("[yellow]You are already logged in.[/yellow]")
            console.print(f"Current plan: [bold]{existing_token.plan or 'Pro'}[/bold]")
            remaining = get_token_time_remaining(existing_token)
            if remaining.total_seconds() > 0:
                days = remaining.days
                hours = remaining.seconds // 3600
                console.print(f"Token expires in: {days} days, {hours} hours")
            console.print("\nTo switch licenses, run [bold]vibeguard auth login <new-key>[/bold].")
            raise typer.Exit(ExitCode.SUCCESS)

    # Activate
    console.print(f"Activating license: [dim]{mask_license_key(license_key)}[/dim]\n")

    success, message, response = _activate_with_spinner(license_key)

    if success and response is not None:
        # Save token to cache
        token = save_token_to_cache(response)

        console.print(f"[green]{message}[/green]\n")

        # Show details
        table = Table(show_header=False, box=None)
        table.add_column("Field", style="dim")
        table.add_column("Value")

        table.add_row("Plan", token.plan or "Pro")
        table.add_row("Machine ID", get_or_create_machine_id()[:8] + "...")

        remaining = get_token_time_remaining(token)
        days = remaining.days
        hours = remaining.seconds // 3600
        table.add_row("Token expires", f"in {days} days, {hours} hours")

        if token.entitlements:
            table.add_row("Entitlements", ", ".join(token.entitlements))

        console.print(table)
        console.print()

        # Check if LLM key is configured
        providers = get_configured_providers()
        if not providers:
            console.print(
                Panel(
                    "[yellow]Pro license activated![/yellow]\n\n"
                    "To use patch generation, configure an LLM API key:\n"
                    "  [bold]vibeguard keys set openai <your-api-key>[/bold]\n"
                    "  [bold]vibeguard keys set anthropic <your-api-key>[/bold]",
                    title="Next Step",
                    border_style="yellow",
                )
            )
        else:
            console.print("[green]You're all set![/green] Try [bold]vibeguard patch[/bold] to generate fixes.")

    else:
        console.print(f"[red]Activation failed:[/red] {message}")

        # Provide helpful suggestions
        if isinstance(response, NetworkError):
            console.print("\n[dim]Tips:[/dim]")
            console.print("  - Check your internet connection")
            console.print("  - Try again in a few moments")
            console.print("  - Contact support@vibeguard.co if the issue persists")
        elif isinstance(response, LicenseError):
            console.print("\n[dim]Tips:[/dim]")
            console.print("  - Verify your license key is correct")
            console.print("  - Check your account at https://vibeguard.co/account")
            console.print("  - Contact support@vibeguard.co for help")

        raise typer.Exit(ExitCode.CONFIG_ERROR)


@app.command("status")
def status() -> None:
    """Show current license status.

    Displays:
    - License activation status
    - Token expiry
    - Current plan
    - Available entitlements
    - Configured LLM providers

    Example:
        vibeguard auth status
    """
    token = get_cached_token()
    providers = get_configured_providers()
    machine_id = get_or_create_machine_id()

    # Build status table
    table = Table(title="VibeGuard License Status", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    if token is not None:
        table.add_row("Status", "[green]Licensed (Pro)[/green]")
        table.add_row("Plan", token.plan or "Pro")

        # Token expiry
        remaining = get_token_time_remaining(token)
        if remaining.total_seconds() > 0:
            days = remaining.days
            hours = remaining.seconds // 3600
            if days > 1:
                expiry_str = f"in {days} days, {hours} hours"
            elif days == 1:
                expiry_str = f"in 1 day, {hours} hours"
            else:
                expiry_str = f"in {hours} hours"

            if should_refresh_token(token):
                expiry_str += " [yellow](refresh pending)[/yellow]"

            table.add_row("Token expires", expiry_str)
        else:
            table.add_row("Token expires", "[red]Expired[/red]")

        # Entitlements
        if token.entitlements:
            table.add_row("Entitlements", ", ".join(token.entitlements))
        else:
            table.add_row("Entitlements", "[dim]None[/dim]")

        # Last refresh
        if token.last_refresh:
            refresh_str = token.last_refresh.strftime("%Y-%m-%d %H:%M UTC")
            table.add_row("Last refresh", refresh_str)

    else:
        table.add_row("Status", "[yellow]Not licensed (Free tier)[/yellow]")
        table.add_row("Plan", "Free")

    # Machine ID
    table.add_row("Machine ID", machine_id[:12] + "...")

    # LLM providers
    if providers:
        table.add_row("LLM providers", ", ".join(providers))
    else:
        table.add_row("LLM providers", "[dim]None configured[/dim]")

    console.print(table)
    console.print()

    # Actionable guidance
    if token is None:
        console.print(
            Panel(
                "Activate your Pro license to unlock patch generation:\n"
                "  [bold]vibeguard auth login <your-license-key>[/bold]\n\n"
                "Get a license at: [link=https://vibeguard.co/pricing]https://vibeguard.co/pricing[/link]",
                title="Upgrade to Pro",
                border_style="yellow",
            )
        )
    elif not providers:
        console.print(
            Panel(
                "Configure an LLM API key to use patch generation:\n"
                "  [bold]vibeguard keys set openai <your-api-key>[/bold]\n"
                "  [bold]vibeguard keys set anthropic <your-api-key>[/bold]",
                title="Configure LLM",
                border_style="yellow",
            )
        )
    else:
        console.print("[green]Ready to use Pro features![/green] Try [bold]vibeguard patch[/bold]")


@app.command("logout")
def logout() -> None:
    """Deactivate license and clear cached token.

    Your license key remains valid and can be activated
    on another machine.

    Example:
        vibeguard auth logout
    """
    token = get_cached_token()

    if token is None:
        console.print("[yellow]You are not currently logged in.[/yellow]")
        raise typer.Exit(ExitCode.SUCCESS)

    # Confirm logout
    console.print(f"Current plan: [bold]{token.plan or 'Pro'}[/bold]")
    console.print()

    if clear_auth_cache():
        console.print("[green]Logged out successfully.[/green]")
        console.print()
        console.print("[dim]Your license key is still valid.[/dim]")
        console.print("[dim]You can reactivate on this or another machine.[/dim]")
    else:
        console.print("[yellow]No active session to clear.[/yellow]")
