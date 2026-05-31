"""JSON cache management for scan results."""

import json
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ValidationError

from vibeguard import __version__
from vibeguard.models.scan_result import ScanResult

CACHE_DIR = ".vibeguard/cache"
CACHE_SCHEMA_VERSION = 1


class CachedScan(BaseModel):
    """Wrapper for cached scan result with metadata."""

    model_config = {"extra": "ignore"}  # Allow extra fields for forward compatibility

    schema_version: int = CACHE_SCHEMA_VERSION
    vibeguard_version: str = __version__
    scan_result: ScanResult


def save_scan(result: ScanResult, repo_root: Path) -> Path:
    """Save scan result to cache.

    Returns path to cache file.
    """
    cache_dir = repo_root / CACHE_DIR
    cache_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    cache_file = cache_dir / f"scan_{timestamp}.json"

    cached = CachedScan(scan_result=result)
    cache_file.write_text(cached.model_dump_json(indent=2), encoding="utf-8")

    return cache_file


def load_latest_scan(repo_root: Path) -> ScanResult | None:
    """Load the most recent scan from cache."""
    cache_dir = repo_root / CACHE_DIR
    if not cache_dir.exists():
        return None

    cache_files = sorted(cache_dir.glob("scan_*.json"), reverse=True)
    if not cache_files:
        return None

    try:
        data = json.loads(cache_files[0].read_text(encoding="utf-8"))
        cached = CachedScan.model_validate(data)
        return cached.scan_result
    except (json.JSONDecodeError, ValidationError):
        return None


def list_cached_scans(repo_root: Path) -> list[Path]:
    """List all cached scan files, newest first."""
    cache_dir = repo_root / CACHE_DIR
    if not cache_dir.exists():
        return []
    return sorted(cache_dir.glob("scan_*.json"), reverse=True)


def clear_cache(repo_root: Path) -> int:
    """Clear all cached scans.

    Returns number of files deleted.
    """
    cache_files = list_cached_scans(repo_root)
    for f in cache_files:
        f.unlink()
    return len(cache_files)
