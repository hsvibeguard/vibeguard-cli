"""Expiry and grace period banners for CLI commands.

Displays warning banners based on license/token status to alert users
about upcoming expiration or grace period status.
"""

from __future__ import annotations

from typing import Any

from rich.panel import Panel

from vibeguard.cli.display import get_console

console = get_console()

# Banner thresholds
CRITICAL_HOURS = 24  # Red banner when < 24 hours
APPROACHING_DAYS = 7  # Yellow banner when < 7 days


def show_expiry_banner(license_status: dict[str, Any]) -> None:
    """Show warning banner based on license/token status.

    Banner zones (in priority order):
    1. Grace period (license expired, in 48h grace): Yellow urgent
    2. Critical (< 24 hours until expiry): Red
    3. Approaching (< 7 days until expiry): Yellow notice

    Args:
        license_status: Dictionary from get_license_status_with_grace() with:
            - valid: bool - whether license is currently valid
            - in_grace: bool - whether in grace period
            - hours_left: int - hours remaining (if in grace)
            - days_left: int - days remaining (if not in grace)
    """
    if not license_status.get("valid"):
        # Don't show banner if fully expired (auth will fail anyway)
        return

    in_grace = license_status.get("in_grace", False)
    hours_left = license_status.get("hours_left", 0)
    days_left = license_status.get("days_left", 999)

    if in_grace:
        # Grace period - yellow/urgent messaging
        _show_grace_period_banner(hours_left)
    elif days_left * 24 + hours_left <= CRITICAL_HOURS:
        # Critical - less than 24 hours
        total_hours = days_left * 24 + hours_left
        _show_critical_banner(total_hours)
    elif days_left <= APPROACHING_DAYS:
        # Approaching - 1-7 days remaining
        _show_approaching_banner(days_left)
    # else: No banner for healthy licenses (> 7 days remaining)


def _show_grace_period_banner(hours_left: int) -> None:
    """Show grace period warning banner (yellow, urgent)."""
    console.print(
        Panel(
            f"[yellow bold]Your license expired. "
            f"Grace period: {hours_left} hours remaining.[/yellow bold]\n"
            "Renew now to avoid service interruption.\n"
            "[dim]https://app.vibeguard.co/billing[/dim]",
            title="[yellow]Grace Period Active[/yellow]",
            border_style="yellow",
        )
    )
    console.print()  # Add spacing after banner


def _show_critical_banner(hours_left: int) -> None:
    """Show critical expiry warning banner (red)."""
    time_str = f"{hours_left} hour{'s' if hours_left != 1 else ''}"
    console.print(
        Panel(
            f"[red bold]Your license expires in {time_str}![/red bold]\n"
            "Renew at: [dim]https://app.vibeguard.co/billing[/dim]",
            title="[red]License Expiring Soon[/red]",
            border_style="red",
        )
    )
    console.print()


def _show_approaching_banner(days_left: int) -> None:
    """Show approaching expiry notice banner (yellow, informational)."""
    day_str = f"{days_left} day{'s' if days_left != 1 else ''}"
    console.print(
        Panel(
            f"[yellow]Your license expires in {day_str}.[/yellow]\n"
            "Renew at: [dim]https://app.vibeguard.co/billing[/dim]",
            title="Renewal Reminder",
            border_style="yellow",
        )
    )
    console.print()
