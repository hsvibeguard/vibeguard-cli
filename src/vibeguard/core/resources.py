"""Resource path resolution for both installed and frozen (PyInstaller) modes."""

import sys
from pathlib import Path


def _is_frozen() -> bool:
    """Check if running as a PyInstaller frozen executable."""
    return getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")


def _package_dir() -> Path:
    """Get the base directory for the vibeguard package.

    When frozen, data files live under sys._MEIPASS/vibeguard/.
    When running normally, they are relative to this file's parent's parent.
    """
    if _is_frozen():
        return Path(sys._MEIPASS) / "vibeguard"  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent.parent


def get_manifests_dir() -> Path:
    """Get the directory containing scanner manifest TOML files."""
    return _package_dir() / "scanners" / "manifests"


def get_templates_dir() -> Path:
    """Get the directory containing template files."""
    return _package_dir() / "templates"
