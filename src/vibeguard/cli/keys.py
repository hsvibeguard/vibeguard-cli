"""Keys command - manage BYOK LLM API keys."""

from __future__ import annotations

import typer
from rich.table import Table

from vibeguard.cli.display import get_console
from vibeguard.core.exit_codes import ExitCode
from vibeguard.core.keyring import (
    delete_key,
    get_configured_providers,
    list_providers,
    load_key,
    save_key,
)

app = typer.Typer(
    name="keys",
    help="Manage LLM API keys for patch generation.",
    invoke_without_command=True,
    no_args_is_help=True,
)

console = get_console()


@app.callback(invoke_without_command=True)
def keys_callback(ctx: typer.Context) -> None:
    """Manage LLM API keys for patch generation.

    Keys are encrypted and stored locally in ~/.vibeguard/keys/.
    They never leave your machine.

    Examples:
        vibeguard keys list                    # Show all providers
        vibeguard keys set openai sk-...       # Store OpenAI key
        vibeguard keys set anthropic sk-ant-...  # Store Anthropic key
        vibeguard keys get openai              # Check if key exists
        vibeguard keys delete openai           # Remove a key
    """
    if ctx.invoked_subcommand is None:
        # Show help when no subcommand given
        console.print(ctx.get_help())


@app.command("set")
def set_key_cmd(
    provider: str | None = typer.Argument(
        None,
        help="Provider name (openai, anthropic, google, azure_openai, mistral, groq)",
    ),
    api_key: str | None = typer.Argument(
        None,
        help="API key for the provider",
    ),
) -> None:
    """Store an API key for an LLM provider.

    Keys are encrypted and stored locally in ~/.vibeguard/keys/.
    They never leave your machine.

    Example:
        vibeguard keys set openai sk-...
        vibeguard keys set anthropic sk-ant-...
    """
    # Handle missing arguments with helpful message
    if provider is None or api_key is None:
        console.print("[red]Error:[/red] Missing required arguments.\n")
        console.print("[bold]Usage:[/bold] vibeguard keys set <provider> <api-key>\n")
        console.print("[bold]Supported providers:[/bold]")
        for p in list_providers():
            console.print(f"  - {p}")
        console.print("\n[bold]Example:[/bold] vibeguard keys set openai sk-proj-abc123...")
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    try:
        save_key(provider, api_key)
        console.print(f"[green]API key saved for {provider}[/green]")
        console.print("[dim]Keys are encrypted and stored locally.[/dim]")
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        console.print("\nSupported providers:")
        for p in list_providers():
            console.print(f"  - {p}")
        raise typer.Exit(ExitCode.CONFIG_ERROR)


@app.command("get")
def get_key_cmd(
    provider: str | None = typer.Argument(
        None,
        help="Provider name",
    ),
    show: bool = typer.Option(
        False,
        "--show",
        help="Show the actual key (hidden by default)",
    ),
) -> None:
    """Check if an API key is configured for a provider.

    Example:
        vibeguard keys get openai
        vibeguard keys get openai --show
    """
    # Handle missing argument with helpful message
    if provider is None:
        console.print("[red]Error:[/red] Missing provider name.\n")
        console.print("[bold]Usage:[/bold] vibeguard keys get <provider>\n")
        console.print("[bold]Supported providers:[/bold]")
        for p in list_providers():
            console.print(f"  - {p}")
        console.print("\n[bold]Example:[/bold] vibeguard keys get openai")
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    if provider not in list_providers():
        console.print(f"[red]Error:[/red] Unknown provider: {provider}")
        console.print("\nSupported providers:")
        for p in list_providers():
            console.print(f"  - {p}")
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    key = load_key(provider)
    if key:
        if show:
            console.print(f"[green]{provider}:[/green] {key}")
        else:
            # Mask the key
            if len(key) > 12:
                masked = key[:8] + "..." + key[-4:]
            else:
                masked = "****"
            console.print(f"[green]{provider}:[/green] {masked}")
    else:
        console.print(f"[yellow]{provider}:[/yellow] Not configured")


@app.command("delete")
def delete_key_cmd(
    provider: str | None = typer.Argument(
        None,
        help="Provider name",
    ),
) -> None:
    """Delete an API key for a provider.

    Example:
        vibeguard keys delete openai
    """
    # Handle missing argument with helpful message
    if provider is None:
        console.print("[red]Error:[/red] Missing provider name.\n")
        console.print("[bold]Usage:[/bold] vibeguard keys delete <provider>\n")
        console.print("[bold]Supported providers:[/bold]")
        for p in list_providers():
            console.print(f"  - {p}")
        console.print("\n[bold]Example:[/bold] vibeguard keys delete openai")
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    try:
        if delete_key(provider):
            console.print(f"[green]API key deleted for {provider}[/green]")
        else:
            console.print(f"[yellow]No key configured for {provider}[/yellow]")
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(ExitCode.CONFIG_ERROR)


@app.command("list")
def list_keys_cmd() -> None:
    """List all configured API keys.

    Example:
        vibeguard keys list
    """
    configured = get_configured_providers()
    all_providers = list_providers()

    table = Table(title="LLM Provider Keys")
    table.add_column("Provider", style="cyan")
    table.add_column("Status")

    for provider in all_providers:
        if provider in configured:
            table.add_row(provider, "[green]Configured[/green]")
        else:
            table.add_row(provider, "[dim]Not set[/dim]")

    console.print(table)
    console.print()
    console.print("[dim]Keys are stored encrypted in ~/.vibeguard/keys/[/dim]")
