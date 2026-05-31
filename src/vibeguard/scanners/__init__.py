"""Scanner infrastructure for VibeGuard."""

from typing import Literal

import toml
from pydantic import BaseModel

from vibeguard.core.resources import get_manifests_dir


class InstallStrategy(BaseModel):
    """Installation strategy configuration."""

    check_command: str | None = None
    binary_name: str | None = None
    image: str | None = None
    mount_mode: str = "ro"


class DownloadConfig(BaseModel):
    """Download configuration for auto-downloading scanner binaries."""

    url_template: str
    binary_name: str
    archive_type: str = "tar.gz"
    windows_archive_type: str | None = None  # Override for Windows
    windows_arch: str | None = None  # Override arch for Windows (e.g., "x64")
    os_map: dict[str, str] | None = None  # Custom OS name mapping (e.g., darwin → macOS)
    arch_map: dict[str, str] | None = None  # Custom arch name mapping (e.g., amd64 → 64bit)


class PipConfig(BaseModel):
    """Pip package configuration for auto-installing scanner packages."""

    package_name: str
    version: str | None = None  # If None, install latest


class ExecutionConfig(BaseModel):
    """Execution configuration."""

    command: str
    timeout: int = 300
    output_format: str = "json"
    workdir: str | None = None


class ScannerManifest(BaseModel):
    """Parsed scanner manifest."""

    name: str
    display_name: str
    version: str
    tier: Literal["core", "ecosystem", "differentiation"]
    categories: list[str]
    languages: list[str]
    supported_os: list[str] | None = None  # e.g., ["linux", "darwin"] — None means all OS
    install_strategies: list[str]
    local_config: InstallStrategy | None = None
    download_config: DownloadConfig | None = None
    pip_config: PipConfig | None = None
    docker_config: InstallStrategy | None = None
    execution: ExecutionConfig
    docker_execution: ExecutionConfig | None = None
    output_format: str
    parser_module: str
    parser_function: str


def load_manifest(name: str) -> ScannerManifest:
    """Load a scanner manifest by name."""
    manifest_dir = get_manifests_dir()
    manifest_path = manifest_dir / f"{name}.toml"

    if not manifest_path.exists():
        raise FileNotFoundError(f"Scanner manifest not found: {name}")

    data = toml.load(manifest_path)

    # Parse nested structure into flat model
    scanner = data["scanner"]
    install = data.get("install", {})
    execution = data.get("execution", {})
    output = data.get("output", {})

    # Parse download config if present
    download_config = None
    if "download" in install:
        download_data = install["download"]
        download_config = DownloadConfig(
            url_template=download_data["url_template"],
            binary_name=download_data.get("binary_name", scanner["name"]),
            archive_type=download_data.get("archive_type", "tar.gz"),
            windows_archive_type=download_data.get("windows_archive_type"),
            windows_arch=download_data.get("windows_arch"),
            os_map=download_data.get("os_map"),
            arch_map=download_data.get("arch_map"),
        )

    # Parse pip config if present
    pip_config = None
    if "pip" in install:
        pip_data = install["pip"]
        pip_config = PipConfig(
            package_name=pip_data["package_name"],
            version=pip_data.get("version"),
        )

    return ScannerManifest(
        name=scanner["name"],
        display_name=scanner["display_name"],
        version=scanner["version"],
        tier=scanner["tier"],
        categories=scanner["categories"],
        languages=scanner["languages"],
        supported_os=scanner.get("supported_os"),
        install_strategies=install.get("strategies", ["local"]),
        local_config=InstallStrategy(**install.get("local", {})) if "local" in install else None,
        download_config=download_config,
        pip_config=pip_config,
        docker_config=InstallStrategy(**install.get("docker", {})) if "docker" in install else None,
        execution=ExecutionConfig(**{k: v for k, v in execution.items() if k != "docker"}),
        docker_execution=(
            ExecutionConfig(**execution.get("docker", {})) if "docker" in execution else None
        ),
        output_format=output.get("format", "json"),
        parser_module=output["parser_module"],
        parser_function=output["parser_function"],
    )


def list_available_scanners() -> list[str]:
    """List all available scanner manifests."""
    manifest_dir = get_manifests_dir()
    if not manifest_dir.exists():
        return []
    return [p.stem for p in manifest_dir.glob("*.toml")]
