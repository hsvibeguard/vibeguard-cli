"""Bootstrap module for auto-installing missing scanners before scan."""

import asyncio
import platform
import shutil
import subprocess  # nosec B404  # noqa: S404  # needed for pip install
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from vibeguard.core.downloader import DownloadConfig, download_binary, get_cached_binary
from vibeguard.scanners import ScannerManifest, load_manifest


class ScannerStatus(str, Enum):
    """Status of a scanner after bootstrap check."""

    READY = "ready"  # Scanner is available and ready to use
    DOWNLOADED = "downloaded"  # Scanner was downloaded during bootstrap
    INSTALLED = "installed"  # Scanner was pip-installed during bootstrap
    DOCKER_ONLY = "docker_only"  # Scanner only available via Docker
    UNAVAILABLE = "unavailable"  # Scanner cannot be made available


@dataclass
class BootstrapResult:
    """Result of bootstrap for a single scanner."""

    name: str
    display_name: str
    status: ScannerStatus
    message: str = ""


@dataclass
class BootstrapSummary:
    """Summary of bootstrap process."""

    results: list[BootstrapResult]
    ready_count: int = 0
    downloaded_count: int = 0
    installed_count: int = 0
    docker_only_count: int = 0
    unavailable_count: int = 0

    def __post_init__(self) -> None:
        """Calculate counts from results."""
        for r in self.results:
            if r.status == ScannerStatus.READY:
                self.ready_count += 1
            elif r.status == ScannerStatus.DOWNLOADED:
                self.downloaded_count += 1
            elif r.status == ScannerStatus.INSTALLED:
                self.installed_count += 1
            elif r.status == ScannerStatus.DOCKER_ONLY:
                self.docker_only_count += 1
            elif r.status == ScannerStatus.UNAVAILABLE:
                self.unavailable_count += 1

    @property
    def total_available(self) -> int:
        """Total scanners available (ready, downloaded, installed, or docker-only)."""
        return (
            self.ready_count
            + self.downloaded_count
            + self.installed_count
            + self.docker_only_count
        )


def _is_binary_available(binary_name: str) -> bool:
    """Check if a binary is available in PATH or the current venv's bin directory."""
    if shutil.which(binary_name) is not None:
        return True

    # Check current Python environment's bin directory (handles pipx installs)
    prefix = Path(sys.prefix)
    bin_dir = prefix / ("Scripts" if sys.platform == "win32" else "bin")
    if bin_dir.is_dir():
        for ext in ("", ".exe"):
            if (bin_dir / f"{binary_name}{ext}").is_file():
                return True

    return False


def _is_docker_available() -> bool:
    """Check if Docker is available and running."""
    if not shutil.which("docker"):
        return False
    try:
        result = subprocess.run(  # nosec B603 B607
            ["docker", "info"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
        return False


async def _try_download(manifest: ScannerManifest) -> bool:
    """Try to download scanner binary.

    Returns True if download succeeded.
    """
    if not manifest.download_config:
        return False

    dl_config = DownloadConfig(
        version=manifest.version,
        url_template=manifest.download_config.url_template,
        binary_name=manifest.download_config.binary_name,
        archive_type=manifest.download_config.archive_type,
        windows_archive_type=manifest.download_config.windows_archive_type,
        windows_arch=manifest.download_config.windows_arch,
        os_map=manifest.download_config.os_map,
        arch_map=manifest.download_config.arch_map,
    )

    binary_path = await download_binary(dl_config)
    return binary_path is not None


def _try_pip_install(manifest: ScannerManifest) -> bool:
    """Try to install scanner via pip.

    Returns True if install succeeded.
    """
    if not manifest.pip_config:
        return False

    package = manifest.pip_config.package_name
    version = manifest.pip_config.version

    # Build pip install command
    if version:
        package_spec = f"{package}=={version}"
    else:
        package_spec = package

    try:
        result = subprocess.run(  # nosec B603
            [sys.executable, "-m", "pip", "install", package_spec, "-q"],
            capture_output=True,
            timeout=120,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
        return False


async def _bootstrap_scanner(
    manifest: ScannerManifest,
    *,
    no_download: bool = False,
    no_pip_install: bool = False,
) -> BootstrapResult:
    """Bootstrap a single scanner.

    Tries strategies in order defined in manifest:
    1. local - check if already available
    2. download - download binary (if allowed)
    3. pip - install via pip (if allowed)
    4. docker - check if Docker is available

    Args:
        manifest: Scanner manifest
        no_download: Skip download attempts
        no_pip_install: Skip pip install attempts

    Returns:
        BootstrapResult with status and message
    """
    # Check OS compatibility before trying any strategy
    if manifest.supported_os:
        current_os = platform.system().lower()
        os_name_map = {"windows": "windows", "linux": "linux", "darwin": "darwin"}
        current_os_normalized = os_name_map.get(current_os, current_os)
        if current_os_normalized not in manifest.supported_os:
            return BootstrapResult(
                name=manifest.name,
                display_name=manifest.display_name,
                status=ScannerStatus.UNAVAILABLE,
                message=f"Not available on {platform.system()}",
            )

    # Get binary name for checks
    binary_name = manifest.name
    if manifest.local_config and manifest.local_config.binary_name:
        binary_name = manifest.local_config.binary_name
    elif manifest.download_config:
        binary_name = manifest.download_config.binary_name

    for strategy in manifest.install_strategies:
        if strategy == "local":
            # Check if already available in PATH
            if _is_binary_available(binary_name):
                return BootstrapResult(
                    name=manifest.name,
                    display_name=manifest.display_name,
                    status=ScannerStatus.READY,
                    message="Available in PATH",
                )

            # Check if already downloaded
            if manifest.download_config:
                cached = get_cached_binary(
                    manifest.download_config.binary_name,
                    manifest.version,
                )
                if cached:
                    return BootstrapResult(
                        name=manifest.name,
                        display_name=manifest.display_name,
                        status=ScannerStatus.READY,
                        message=f"Cached at {cached}",
                    )

        elif strategy == "download":
            if no_download:
                continue

            # Check if already cached first
            if manifest.download_config:
                cached = get_cached_binary(
                    manifest.download_config.binary_name,
                    manifest.version,
                )
                if cached:
                    return BootstrapResult(
                        name=manifest.name,
                        display_name=manifest.display_name,
                        status=ScannerStatus.READY,
                        message=f"Cached at {cached}",
                    )

            # Try to download
            if await _try_download(manifest):
                return BootstrapResult(
                    name=manifest.name,
                    display_name=manifest.display_name,
                    status=ScannerStatus.DOWNLOADED,
                    message="Downloaded successfully",
                )

        elif strategy == "pip":
            if no_pip_install:
                continue

            if _try_pip_install(manifest):
                return BootstrapResult(
                    name=manifest.name,
                    display_name=manifest.display_name,
                    status=ScannerStatus.INSTALLED,
                    message="Installed via pip",
                )

        elif strategy == "docker":
            if _is_docker_available():
                return BootstrapResult(
                    name=manifest.name,
                    display_name=manifest.display_name,
                    status=ScannerStatus.DOCKER_ONLY,
                    message="Available via Docker",
                )

    # No strategy worked
    return BootstrapResult(
        name=manifest.name,
        display_name=manifest.display_name,
        status=ScannerStatus.UNAVAILABLE,
        message="No installation method available",
    )


async def bootstrap_scanners(
    scanner_names: list[str],
    *,
    no_download: bool = False,
    no_pip_install: bool = False,
) -> BootstrapSummary:
    """Bootstrap multiple scanners.

    Args:
        scanner_names: List of scanner names to bootstrap
        no_download: Skip binary downloads
        no_pip_install: Skip pip installs

    Returns:
        BootstrapSummary with results for all scanners
    """
    results: list[BootstrapResult] = []

    for name in scanner_names:
        try:
            manifest = load_manifest(name)
            result = await _bootstrap_scanner(
                manifest,
                no_download=no_download,
                no_pip_install=no_pip_install,
            )
            results.append(result)
        except FileNotFoundError:
            results.append(
                BootstrapResult(
                    name=name,
                    display_name=name.capitalize(),
                    status=ScannerStatus.UNAVAILABLE,
                    message="Manifest not found",
                )
            )

    return BootstrapSummary(results=results)


def bootstrap_scanners_sync(
    scanner_names: list[str],
    *,
    no_download: bool = False,
    no_pip_install: bool = False,
) -> BootstrapSummary:
    """Synchronous wrapper for bootstrap_scanners."""
    return asyncio.run(
        bootstrap_scanners(
            scanner_names,
            no_download=no_download,
            no_pip_install=no_pip_install,
        )
    )
