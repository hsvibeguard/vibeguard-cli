"""Binary auto-download framework for VibeGuard scanners."""

import platform
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import NamedTuple

import httpx
from pydantic import BaseModel

VIBEGUARD_BIN_DIR = Path.home() / ".vibeguard" / "bin"


def _is_safe_path(base_dir: Path, member_path: str) -> bool:
    """Check if extracted path is safe (no path traversal).

    Prevents Zip Slip vulnerability by ensuring extracted files
    stay within the target directory.
    """
    # Resolve the full path and check it's within base_dir
    try:
        target_path = (base_dir / member_path).resolve()
        base_resolved = base_dir.resolve()
        # Check the path is within the base directory
        return str(target_path).startswith(str(base_resolved))
    except (ValueError, OSError):
        return False


def _safe_tar_extract(tar: tarfile.TarFile, dest_dir: Path) -> None:
    """Safely extract tar archive, filtering dangerous members.

    Skips files with:
    - Absolute paths
    - Path traversal sequences (..)
    - Paths that escape the destination directory
    """
    for member in tar.getmembers():
        # Skip absolute paths
        if member.name.startswith("/") or member.name.startswith("\\"):
            continue
        # Skip path traversal attempts
        if ".." in member.name:
            continue
        # Final safety check
        if not _is_safe_path(dest_dir, member.name):
            continue
        # Extract safely
        tar.extract(member, dest_dir)


def _safe_zip_extract(zip_ref: zipfile.ZipFile, dest_dir: Path) -> None:
    """Safely extract zip archive, filtering dangerous members.

    Skips files with:
    - Absolute paths
    - Path traversal sequences (..)
    - Paths that escape the destination directory
    """
    for member in zip_ref.namelist():
        # Skip absolute paths
        if member.startswith("/") or member.startswith("\\"):
            continue
        # Skip path traversal attempts
        if ".." in member:
            continue
        # Final safety check
        if not _is_safe_path(dest_dir, member):
            continue
        # Extract safely
        zip_ref.extract(member, dest_dir)


class DownloadConfig(BaseModel):
    """Download configuration for a scanner binary."""

    version: str
    url_template: str
    binary_name: str
    archive_type: str = "tar.gz"
    windows_archive_type: str | None = None  # Override for Windows
    windows_arch: str | None = None  # Override arch for Windows (e.g., "x64" instead of "amd64")
    os_map: dict[str, str] | None = None  # Custom OS name mapping (e.g., {"darwin": "macOS"})
    arch_map: dict[str, str] | None = None  # Custom arch name mapping (e.g., {"amd64": "64bit"})


class PlatformInfo(NamedTuple):
    """Platform information."""

    os: str
    arch: str


def get_platform() -> PlatformInfo:
    """Detect current platform."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    os_map = {"linux": "linux", "darwin": "darwin", "windows": "windows"}
    # Most tools use amd64 for x86_64/AMD64
    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "arm64": "arm64",
        "aarch64": "arm64",
    }

    return PlatformInfo(
        os=os_map.get(system, system),
        arch=arch_map.get(machine, machine),
    )


def get_cached_binary(name: str, version: str) -> Path | None:
    """Check if binary is already cached."""
    version_dir = VIBEGUARD_BIN_DIR / f"{name}-{version}"
    binary_name = name
    if platform.system() == "Windows":
        binary_name = f"{name}.exe"

    binary_path = version_dir / binary_name
    if binary_path.exists():
        return binary_path

    # Also check for binary directly in version dir (some archives extract differently)
    for path in version_dir.glob("*"):
        if path.is_file() and path.stem == name:
            return path

    return None


async def download_binary(config: DownloadConfig) -> Path | None:
    """Download and extract scanner binary.

    Returns path to binary or None on failure.
    """
    VIBEGUARD_BIN_DIR.mkdir(parents=True, exist_ok=True)

    platform_info = get_platform()
    version_dir = VIBEGUARD_BIN_DIR / f"{config.binary_name}-{config.version}"

    # Check if already downloaded
    cached = get_cached_binary(config.binary_name, config.version)
    if cached:
        return cached

    # Determine archive type and arch (Windows may use different values)
    archive_type = config.archive_type
    arch = platform_info.arch
    os_name = platform_info.os

    # Apply custom OS/arch mappings if provided (e.g., Trivy uses "macOS" not "darwin")
    if config.os_map:
        os_name = config.os_map.get(os_name, os_name)
    if config.arch_map:
        arch = config.arch_map.get(arch, arch)

    if platform_info.os == "windows":
        if config.windows_archive_type:
            archive_type = config.windows_archive_type
        if config.windows_arch:
            arch = config.windows_arch

    # Build download URL
    url = config.url_template.format(
        version=config.version,
        os=os_name,
        arch=arch,
    )
    # Handle Windows archive type in URL if different from default
    if platform_info.os == "windows" and config.windows_archive_type:
        url = url.replace(f".{config.archive_type}", f".{archive_type}")

    # For raw binary downloads on Windows, append .exe to the URL
    if archive_type == "none" and platform_info.os == "windows":
        url = url + ".exe"

    try:
        # Download archive or raw binary
        async with httpx.AsyncClient(follow_redirects=True, timeout=120.0) as client:
            response = await client.get(url)
            if response.status_code != 200:
                return None

            download_data = response.content

        version_dir.mkdir(parents=True, exist_ok=True)

        if archive_type == "none":
            # Raw binary download (no archive extraction)
            binary_suffix = ".exe" if platform_info.os == "windows" else ""
            binary_path = version_dir / f"{config.binary_name}{binary_suffix}"
            binary_path.write_bytes(download_data)
            if platform_info.os != "windows":
                binary_path.chmod(0o755)
            return binary_path

        # Archive download - extract binary
        archive_path = version_dir / f"archive.{archive_type}"
        archive_path.write_bytes(download_data)

        if archive_type == "tar.gz":
            with tarfile.open(archive_path, "r:gz") as tar:
                _safe_tar_extract(tar, version_dir)
        elif archive_type == "zip":
            with zipfile.ZipFile(archive_path, "r") as zip_ref:
                _safe_zip_extract(zip_ref, version_dir)

        archive_path.unlink()  # Clean up archive

        # Find and make binary executable
        binary_path = _find_binary(version_dir, config.binary_name)
        if binary_path and platform_info.os != "windows":
            binary_path.chmod(0o755)

        return binary_path

    except Exception:
        # Clean up on failure
        if version_dir.exists():
            shutil.rmtree(version_dir, ignore_errors=True)
        return None


def _find_binary(directory: Path, name: str) -> Path | None:
    """Find binary in extracted directory."""
    # Check direct path
    for ext in ("", ".exe"):
        direct = directory / f"{name}{ext}"
        if direct.exists() and direct.is_file():
            return direct

    # Search recursively (some archives have nested structure)
    for path in directory.rglob("*"):
        if path.is_file() and path.stem == name:
            # Move to version dir root for easier access
            target = directory / path.name
            if target != path:
                shutil.move(str(path), str(target))
                return target
            return path

    return None
