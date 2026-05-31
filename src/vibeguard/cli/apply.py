"""Apply command - safely apply patches with git checks (PRO tier)."""

from __future__ import annotations

import json
import subprocess  # nosec B404  # noqa: S404  # needed for git operations
from pathlib import Path
from typing import Any

import typer
from rich.panel import Panel
from rich.syntax import Syntax

from vibeguard.cli.banners import show_expiry_banner
from vibeguard.cli.display import get_console
from vibeguard.core.exit_codes import ExitCode
from vibeguard.core.license import (
    ProFeatureError,
    get_license_status_with_grace,
    require_pro_license,
)
from vibeguard.models.patch import validate_unified_diff

console = get_console()

# Default patches directory
PATCHES_DIR = ".vibeguard/patches"


def apply(
    patch_file: Path | None = typer.Argument(
        None,
        help="Path to the .patch file to apply",
        exists=True,
        file_okay=True,
        dir_okay=False,
        resolve_path=True,
    ),
    path: Path = typer.Option(
        Path("."),
        "--path",
        "-p",
        help="Path to the git repository",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Check if patch applies cleanly without actually applying",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Apply even if working directory has uncommitted changes",
    ),
    reverse: bool = typer.Option(
        False,
        "--reverse",
        "-R",
        help="Reverse/unapply the patch",
    ),
) -> None:
    """Apply a generated patch to fix a security finding.

    This is a PRO feature that requires an active Pro license.
    Run 'vibeguard auth login <license-key>' to activate.

    Safety checks performed:
    - Verifies patch file is valid unified diff
    - Checks repository is a git repo
    - Warns if working directory has uncommitted changes
    - Uses 'git apply --check' to verify patch applies cleanly
    - Creates backup information before applying

    Example:
        vibeguard apply .vibeguard/patches/abc123.patch
        vibeguard apply my-fix.patch --dry-run
        vibeguard apply .vibeguard/patches/abc123.patch --reverse
    """
    target = path.resolve()

    # Handle missing patch_file with helpful message
    if patch_file is None:
        _show_missing_patch_help(target)
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    # Check Pro license
    try:
        require_pro_license("Patch application")
    except ProFeatureError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    # Show expiry/grace period banner if license is expiring soon
    license_status = get_license_status_with_grace()
    if license_status.get("valid"):
        show_expiry_banner(license_status)

    # Verify patch file exists and is readable
    patch_content = _read_patch_file(patch_file)
    if patch_content is None:
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    # Validate patch format
    is_valid, error = validate_unified_diff(patch_content)
    if not is_valid:
        console.print(f"[red]Error:[/red] Invalid patch file: {error}")
        console.print(f"\n[dim]File: {patch_file}[/dim]")
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    # Check if target is a git repository
    if not _is_git_repo(target):
        console.print(f"[red]Error:[/red] Not a git repository: {target}")
        console.print("\nVibeGuard apply requires a git repository for safety checks.")
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    # Load patch metadata if available
    metadata = _load_patch_metadata(patch_file)

    # Show patch info
    _show_patch_info(patch_file, patch_content, metadata, reverse)

    # Check working directory status
    if not force:
        has_changes, status_output = _check_working_directory(target)
        if has_changes:
            console.print("[yellow]Warning:[/yellow] Working directory has uncommitted changes.\n")
            console.print("[dim]Uncommitted files:[/dim]")
            console.print(status_output[:500])
            console.print()
            console.print(
                "Use [cyan]--force[/cyan] to apply anyway, or commit/stash changes first."
            )
            raise typer.Exit(ExitCode.CONFIG_ERROR)

    # Verify patch applies cleanly with git apply --check
    console.print("[dim]Checking if patch applies cleanly...[/dim]")
    can_apply, check_error = _git_apply_check(target, patch_file, reverse)

    if not can_apply:
        console.print("[red]Error:[/red] Patch cannot be applied cleanly.\n")
        console.print("[bold]Git apply check output:[/bold]")
        console.print(check_error)
        console.print()
        console.print("[dim]Tips:[/dim]")
        console.print("  - The file may have been modified since the patch was generated")
        console.print(
            "  - Try running [cyan]vibeguard scan[/cyan] and [cyan]vibeguard patch[/cyan] again"
        )
        console.print("  - Check if the patch was already applied")
        raise typer.Exit(ExitCode.SCAN_ERROR)

    console.print("[green]Patch applies cleanly![/green]\n")

    # Dry run - stop here
    if dry_run:
        console.print("[dim]Dry run - patch not applied[/dim]")
        console.print(f"\nTo apply: [cyan]vibeguard apply {patch_file}[/cyan]")
        raise typer.Exit(ExitCode.SUCCESS)

    # Get current HEAD for reference
    head_before = _get_git_head(target)

    # Apply the patch
    action = "Reversing" if reverse else "Applying"
    console.print(f"[dim]{action} patch...[/dim]")

    success, apply_output = _git_apply(target, patch_file, reverse)

    if not success:
        console.print("[red]Error:[/red] Failed to apply patch.\n")
        console.print(apply_output)
        raise typer.Exit(ExitCode.SCAN_ERROR)

    # Success!
    action_past = "reversed" if reverse else "applied"
    console.print(f"[green]Patch {action_past} successfully![/green]\n")

    # Show what changed
    console.print("[dim]Modified files:[/dim]")
    modified = _get_modified_files_from_patch(patch_content)
    for f in modified:
        console.print(f"  {f}")

    console.print()
    console.print("[dim]Next steps:[/dim]")
    console.print("  1. Review the changes: [cyan]git diff[/cyan]")
    console.print("  2. Run tests to verify the fix")
    console.print("  3. Commit when satisfied: [cyan]git commit -am 'Fix security finding'[/cyan]")

    if head_before:
        console.print(f"\n[dim]To undo: git checkout {head_before[:8]} -- <files>[/dim]")

    raise typer.Exit(ExitCode.SUCCESS)


def _show_missing_patch_help(target: Path) -> None:
    """Show helpful error when patch file is missing."""
    console.print("[red]Error:[/red] Missing patch file.\n")
    console.print("[bold]Usage:[/bold] vibeguard apply <patch-file>\n")

    # Check for available patches
    patches_dir = target / PATCHES_DIR
    if patches_dir.exists():
        patches = list(patches_dir.glob("*.patch"))
        if patches:
            console.print("[bold]Available patches:[/bold]")
            for p in patches[:10]:
                # Try to load metadata for context
                meta = _load_patch_metadata(p)
                if meta:
                    console.print(
                        f"  [green]{p.name}[/green]  {meta.get('file_path', '')[:40]}"
                    )
                else:
                    console.print(f"  [green]{p.name}[/green]")
            if len(patches) > 10:
                console.print(f"  [dim]... and {len(patches) - 10} more[/dim]")
            console.print(f"\n[bold]Example:[/bold] vibeguard apply {patches[0]}")
            return

    console.print("Generate a patch first using:")
    console.print("  1. [cyan]vibeguard scan[/cyan]  (find security issues)")
    console.print("  2. [cyan]vibeguard patch <finding-id>[/cyan]  (generate fix)")
    console.print("  3. [cyan]vibeguard apply <patch-file>[/cyan]  (apply fix)")


def _read_patch_file(patch_file: Path) -> str | None:
    """Read patch file content."""
    try:
        return patch_file.read_text(encoding="utf-8")
    except OSError as e:
        console.print(f"[red]Error:[/red] Cannot read patch file: {e}")
        return None


def _is_git_repo(path: Path) -> bool:
    """Check if path is inside a git repository."""
    git_dir = path / ".git"
    if git_dir.exists():
        return True

    # Check parent directories
    try:
        result = subprocess.run(  # nosec B603 B607
            ["git", "rev-parse", "--git-dir"],
            cwd=path,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def _check_working_directory(path: Path) -> tuple[bool, str]:
    """Check if working directory has uncommitted changes.

    Returns:
        Tuple of (has_changes, status_output)
    """
    try:
        result = subprocess.run(  # nosec B603 B607
            ["git", "status", "--porcelain"],
            cwd=path,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout.strip()
        return bool(output), output
    except (subprocess.SubprocessError, OSError):
        return False, ""


def _git_apply_check(
    path: Path, patch_file: Path, reverse: bool = False
) -> tuple[bool, str]:
    """Run git apply --check to verify patch.

    Returns:
        Tuple of (can_apply, error_output)
    """
    cmd = ["git", "apply", "--check"]
    if reverse:
        cmd.append("--reverse")
    cmd.append(str(patch_file))

    try:
        result = subprocess.run(  # nosec B603
            cmd,
            cwd=path,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            return True, ""
        return False, result.stderr or result.stdout
    except subprocess.TimeoutExpired:
        return False, "Git apply check timed out"
    except (subprocess.SubprocessError, OSError) as e:
        return False, str(e)


def _git_apply(
    path: Path, patch_file: Path, reverse: bool = False
) -> tuple[bool, str]:
    """Apply patch using git apply.

    Returns:
        Tuple of (success, output)
    """
    cmd = ["git", "apply"]
    if reverse:
        cmd.append("--reverse")
    cmd.append(str(patch_file))

    try:
        result = subprocess.run(  # nosec B603
            cmd,
            cwd=path,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            return True, result.stdout
        return False, result.stderr or result.stdout
    except subprocess.TimeoutExpired:
        return False, "Git apply timed out"
    except (subprocess.SubprocessError, OSError) as e:
        return False, str(e)


def _get_git_head(path: Path) -> str | None:
    """Get current HEAD commit hash."""
    try:
        result = subprocess.run(  # nosec B603 B607
            ["git", "rev-parse", "HEAD"],
            cwd=path,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.SubprocessError, OSError):
        pass
    return None


def _load_patch_metadata(patch_file: Path) -> dict[str, Any] | None:
    """Load patch metadata JSON if available."""
    meta_path = patch_file.with_suffix(".json")
    if not meta_path.exists():
        return None

    try:
        content = meta_path.read_text(encoding="utf-8")
        data: dict[str, Any] = json.loads(content)
        return data
    except (OSError, json.JSONDecodeError):
        return None


def _show_patch_info(
    patch_file: Path,
    patch_content: str,
    metadata: dict[str, Any] | None,
    reverse: bool,
) -> None:
    """Display patch information."""
    action = "Reversing" if reverse else "Applying"
    title = f"{action} Patch"

    info_lines = [f"[bold]File:[/bold] {patch_file.name}"]

    if metadata:
        if "file_path" in metadata:
            info_lines.append(f"[bold]Target:[/bold] {metadata['file_path']}")
        if "finding_id" in metadata:
            info_lines.append(f"[bold]Finding:[/bold] {metadata['finding_id'][:12]}")
        if "provider" in metadata and "model" in metadata:
            info_lines.append(
                f"[bold]Generated by:[/bold] {metadata['provider']}/{metadata['model']}"
            )
        if metadata.get("manual_review_required"):
            info_lines.append("[yellow]Note: Manual review markers present[/yellow]")

    console.print(Panel("\n".join(info_lines), title=title))
    console.print()

    # Show diff preview (first 30 lines)
    lines = patch_content.split("\n")
    preview = "\n".join(lines[:30])
    if len(lines) > 30:
        preview += f"\n... ({len(lines) - 30} more lines)"

    syntax = Syntax(preview, "diff", theme="monokai", line_numbers=False)
    console.print(Panel(syntax, title="Patch Preview"))
    console.print()


def _get_modified_files_from_patch(patch_content: str) -> list[str]:
    """Extract list of files modified by the patch."""
    files = []
    for line in patch_content.split("\n"):
        if line.startswith("+++ "):
            # Extract file path, removing a/ or b/ prefix
            file_path = line[4:].strip()
            if file_path.startswith("b/"):
                file_path = file_path[2:]
            elif file_path.startswith("a/"):
                file_path = file_path[2:]
            if file_path and file_path != "/dev/null":
                files.append(file_path)
    return files
