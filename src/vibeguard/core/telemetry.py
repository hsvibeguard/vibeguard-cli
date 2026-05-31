"""Scan telemetry submission.

Fire-and-forget scan metadata submission to the API for Pro users.
Only sends aggregated counts, never individual findings.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import httpx

from vibeguard.core.auth import API_BASE_URL, API_TIMEOUT

if TYPE_CHECKING:
    from vibeguard.models.scan_result import ScanResult

logger = logging.getLogger(__name__)


def submit_scan(result: ScanResult, repo_name: str | None = None) -> None:
    """Fire-and-forget scan submission. Never raises, never blocks the user.

    Only submits if the user has a valid Pro token cached.
    Uses synchronous httpx to avoid event loop conflicts.

    Args:
        result: The completed scan result.
        repo_name: Optional repo name (only if user opted in via settings).
    """
    try:
        from vibeguard.core.auth import get_cached_token

        token_obj = get_cached_token()
        if not token_obj:
            return  # No Pro license, skip

        token_str = token_obj.token

        # Calculate duration in milliseconds
        duration_ms = None
        if result.started_at and result.finished_at:
            delta = result.finished_at - result.started_at
            duration_ms = int(delta.total_seconds() * 1000)

        payload = {
            "score": result.score,
            "grade": result.grade,
            "critical_count": result.counts.critical,
            "high_count": result.counts.high,
            "medium_count": result.counts.medium,
            "low_count": result.counts.low,
            "total_findings": len(result.findings),
            "scanners_run": result.scanners_run,
            "scan_duration_ms": duration_ms,
            "partial": result.partial,
            "repo_name": repo_name,
            "scanned_at": (result.finished_at or datetime.now(UTC)).isoformat(),
        }

        # Use sync client to avoid event loop conflicts in test/async contexts
        with httpx.Client(timeout=API_TIMEOUT) as client:
            resp = client.post(
                f"{API_BASE_URL}/v1/scans",
                json=payload,
                headers={"Authorization": f"Bearer {token_str}"},
            )
            resp.raise_for_status()
    except Exception:
        # Never block user flow on telemetry failure
        logger.debug("Scan submission failed (ignored)", exc_info=True)
