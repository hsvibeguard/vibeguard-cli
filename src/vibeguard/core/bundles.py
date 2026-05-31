"""Policy bundle fetching, caching, and loading.

Bundles contain server-managed prompts, patch rules, and defaults
that can be updated without releasing a new CLI version.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from vibeguard.core.auth import API_BASE_URL, API_TIMEOUT
from vibeguard.models.auth import Bundle, BundleMetadata

# Storage locations
BUNDLES_DIR = Path.home() / ".vibeguard" / "bundles"
BUNDLE_FILE = BUNDLES_DIR / "current.json"
BUNDLE_META_FILE = BUNDLES_DIR / "meta.json"


class BundleError(Exception):
    """Raised when bundle operations fail."""


# ---------------------------------------------------------------------------
# Hardcoded fallback (mirrors fix.py FIX_PROMPT_TEMPLATE)
# ---------------------------------------------------------------------------

_DEFAULT_FIX_PROMPT = """\
You are a security expert helping fix a vulnerability in code.

## Finding Details
- **Scanner**: {scanner}
- **Rule**: {rule_id}
- **Severity**: {severity}
- **File**: {file_path}
- **Line**: {line_start}{line_end_str}
{cwe_section}
## Issue Description
{message}

## Affected Code
```
{code_snippet}
```

## Your Task
Generate a minimal, safe fix for this security issue. Follow these rules:

### Patch Safety Rules
1. Make minimal changes only - fix the vulnerability, nothing else
2. Do not add new dependencies unless absolutely required
3. Do not include any secrets, tokens, or credentials in your response
4. Preserve the existing code style and formatting
5. Output ONLY a valid unified diff (starting with --- and +++)
6. If you are uncertain about the fix, include a comment: # MANUAL_REVIEW_REQUIRED

### Expected Output Format
```diff
--- a/{file_path}
+++ b/{file_path}
@@ -line,count +line,count @@
 context line
-removed line
+added line
 context line
```

Generate the patch now:
"""


def _ensure_bundles_dir() -> None:
    """Ensure the bundles directory exists."""
    BUNDLES_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Load / Save
# ---------------------------------------------------------------------------


def load_cached_bundle() -> Bundle | None:
    """Load bundle from local cache (~/.vibeguard/bundles/current.json).

    Returns:
        Bundle if cached and valid, None otherwise.
    """
    if not BUNDLE_FILE.exists():
        return None
    try:
        data = json.loads(BUNDLE_FILE.read_text(encoding="utf-8"))
        return Bundle(**data)
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None


def load_bundle_metadata() -> BundleMetadata | None:
    """Load bundle metadata from local cache.

    Returns:
        BundleMetadata if exists, None otherwise.
    """
    if not BUNDLE_META_FILE.exists():
        return None
    try:
        data = json.loads(BUNDLE_META_FILE.read_text(encoding="utf-8"))
        return BundleMetadata(**data)
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None


def save_bundle(bundle: Bundle, sha256: str | None = None) -> None:
    """Save bundle and metadata to local cache.

    Args:
        bundle: The Bundle object to cache.
        sha256: Optional SHA-256 hash for integrity verification.
    """
    _ensure_bundles_dir()

    # Write bundle content
    content = bundle.model_dump_json(indent=2)
    BUNDLE_FILE.write_text(content, encoding="utf-8")

    # Write metadata
    meta = BundleMetadata(
        version=bundle.version,
        downloaded_at=datetime.now(UTC),
        sha256=sha256,
        is_current=True,
    )
    BUNDLE_META_FILE.write_text(meta.model_dump_json(indent=2), encoding="utf-8")


def get_cached_version() -> str | None:
    """Get version of the currently cached bundle.

    Returns:
        Version string or None if no bundle cached.
    """
    meta = load_bundle_metadata()
    return meta.version if meta else None


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------


async def fetch_bundle(token: str) -> Bundle | None:
    """Fetch latest bundle from API server.

    Uses conditional fetching: sends cached version as
    If-None-Match header. If server returns 304 (Not Modified),
    returns None (no update needed).

    Args:
        token: Auth token for the API.

    Returns:
        New Bundle if updated, None if already current.

    Raises:
        BundleError: If fetch fails (caller should fall back to cache).
    """
    headers: dict[str, str] = {"Authorization": f"Bearer {token}"}

    cached_version = get_cached_version()
    if cached_version:
        headers["If-None-Match"] = cached_version

    try:
        async with httpx.AsyncClient(timeout=API_TIMEOUT) as client:
            resp = await client.get(
                f"{API_BASE_URL}/v1/bundles/latest",
                headers=headers,
            )

        if resp.status_code == 304:
            return None  # Already up to date

        if resp.status_code == 401:
            raise BundleError("Unauthorized: invalid or expired token")

        if resp.status_code != 200:
            raise BundleError(f"Unexpected status {resp.status_code}")

        data = resp.json()
        bundle = Bundle(**data)

        # Compute SHA-256 of the raw response body
        sha256 = hashlib.sha256(resp.content).hexdigest()

        # Cache the new bundle
        save_bundle(bundle, sha256=sha256)

        return bundle

    except httpx.HTTPError as exc:
        raise BundleError(f"Network error fetching bundle: {exc}") from exc
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise BundleError(f"Invalid bundle response: {exc}") from exc


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def ensure_bundle(token: str | None = None) -> Bundle:
    """Get the current bundle, fetching if needed.

    Priority order:
    1. If online + token: Try fetch (with version check)
    2. If cached bundle exists: Use it
    3. Fall back to hardcoded defaults

    This is the main entry point that other modules should call.
    Never raises -- always returns a usable Bundle.

    Args:
        token: Optional auth token (skips fetch if None).

    Returns:
        Bundle (from server, cache, or hardcoded fallback).
    """
    # Try fetching from server if we have a token
    if token:
        try:
            fetched = await fetch_bundle(token)
            if fetched is not None:
                return fetched
        except BundleError:
            pass  # Fall through to cache

    # Try cached bundle
    cached = load_cached_bundle()
    if cached is not None:
        return cached

    # Final fallback: hardcoded defaults
    return get_hardcoded_fallback()


# ---------------------------------------------------------------------------
# Fallback & helpers
# ---------------------------------------------------------------------------


def get_hardcoded_fallback() -> Bundle:
    """Get the hardcoded fallback bundle.

    This contains the same prompts/rules that are currently
    hardcoded in fix.py, ensuring backwards compatibility.

    Returns:
        Bundle with hardcoded defaults.
    """
    return Bundle(
        version="0.0.0-builtin",
        prompts={
            "fix_prompt": _DEFAULT_FIX_PROMPT,
        },
        patch_rules={
            "max_tokens": 4096,
            "temperature": 0.2,
        },
        defaults={},
    )


def get_prompt(bundle: Bundle, key: str, fallback: str) -> str:
    """Get a prompt template from bundle with fallback.

    Args:
        bundle: The bundle to look up.
        key: Prompt key (e.g., "fix_prompt", "patch_system").
        fallback: Default template if key not in bundle.

    Returns:
        Prompt template string.
    """
    return bundle.prompts.get(key, fallback)


def get_patch_rule(bundle: Bundle, key: str, fallback: Any = None) -> Any:
    """Get a patch rule from bundle with fallback.

    Args:
        bundle: The bundle to look up.
        key: Rule key (e.g., "max_tokens", "temperature").
        fallback: Default value if key not in bundle.

    Returns:
        Rule value.
    """
    return bundle.patch_rules.get(key, fallback)
