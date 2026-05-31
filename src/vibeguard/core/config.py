"""Configuration management for VibeGuard."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import toml
from pydantic import BaseModel, Field


class ScanConfig(BaseModel):
    """Scan configuration settings."""

    pack: Literal["core", "ecosystem", "full"] = "core"
    timeout: int = 300
    min_severity: Literal["critical", "high", "medium", "low", "info"] = "low"


class OutputConfig(BaseModel):
    """Output configuration settings."""

    format: Literal["terminal", "json", "sarif", "html"] = "terminal"


class ReportConfig(BaseModel):
    """Auto-report generation settings."""

    auto_generate: bool = Field(default=True, description="Auto-generate report after scan")
    format: Literal["html", "json", "sarif"] = Field(
        default="html", description="Report format"
    )
    output_dir: str = Field(default=".", description="Directory for generated reports")
    filename_template: str = Field(
        default="vibeguard-report-{datetime}",
        description="Report filename template ({datetime} will be replaced)",
    )


class ScoringConfig(BaseModel):
    """Scoring configuration settings."""

    enabled: bool = True


class VibeGuardConfig(BaseModel):
    """Main configuration model."""

    scan: ScanConfig = Field(default_factory=ScanConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)


def find_config_file(start_path: Path | None = None) -> Path | None:
    """Find the config file by walking up the directory tree."""
    if start_path is None:
        start_path = Path.cwd()

    current = start_path.resolve()

    while current != current.parent:
        config_path = current / ".vibeguard" / "config.toml"
        if config_path.exists():
            return config_path
        current = current.parent

    return None


def load_config(path: Path | None = None) -> VibeGuardConfig:
    """Load configuration from file or return defaults.

    Args:
        path: Path to config file. If None, searches for config.toml.

    Returns:
        VibeGuardConfig with loaded or default values.
    """
    if path is None:
        path = find_config_file()

    if path is None or not path.exists():
        return VibeGuardConfig()

    try:
        data = toml.load(path)
        return VibeGuardConfig(**data)
    except Exception:
        # Return defaults if config is invalid
        return VibeGuardConfig()


def save_config(config: VibeGuardConfig, path: Path) -> None:
    """Save configuration to file."""
    data = config.model_dump()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        toml.dump(data, f)
