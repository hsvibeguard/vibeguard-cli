"""URL validation and safety checks for DAST scanning.

Ensures localhost-only scanning by default, with explicit consent
required for external targets. This is the critical safety layer
that prevents VibeGuard from becoming a hacking tool.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import NamedTuple
from urllib.parse import urlparse


class URLValidationResult(NamedTuple):
    """Result of URL validation."""

    is_valid: bool
    is_localhost: bool
    host: str
    port: int | None
    scheme: str
    error: str | None


# Localhost patterns that are considered safe (no --i-own-this needed)
LOCALHOST_HOSTS = frozenset([
    "localhost",
    "127.0.0.1",
    "::1",
    "[::1]",
])


def validate_url(url: str) -> URLValidationResult:
    """Validate a URL and determine if it's localhost.

    Args:
        url: The target URL to validate

    Returns:
        URLValidationResult with validation details

    Examples:
        >>> result = validate_url("http://localhost:8080")
        >>> result.is_valid
        True
        >>> result.is_localhost
        True

        >>> result = validate_url("https://example.com")
        >>> result.is_localhost
        False
    """
    if not url or not url.strip():
        return URLValidationResult(
            is_valid=False,
            is_localhost=False,
            host="",
            port=None,
            scheme="",
            error="URL cannot be empty",
        )

    url = url.strip()

    # Ensure URL has a scheme
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    try:
        parsed = urlparse(url)
    except Exception as e:
        return URLValidationResult(
            is_valid=False,
            is_localhost=False,
            host="",
            port=None,
            scheme="",
            error=f"Invalid URL format: {e}",
        )

    if not parsed.hostname:
        return URLValidationResult(
            is_valid=False,
            is_localhost=False,
            host="",
            port=None,
            scheme=parsed.scheme or "",
            error="URL must have a hostname",
        )

    host = parsed.hostname.lower()
    port = parsed.port
    scheme = parsed.scheme or "http"

    # Check if localhost
    is_localhost = _is_localhost(host)

    return URLValidationResult(
        is_valid=True,
        is_localhost=is_localhost,
        host=host,
        port=port,
        scheme=scheme,
        error=None,
    )


def _is_localhost(host: str) -> bool:
    """Check if a host resolves to localhost.

    SECURITY: This function is critical for the safety gate that prevents
    scanning external targets without explicit consent. We must verify
    that hostnames actually resolve to loopback, not just trust patterns.

    Args:
        host: Hostname or IP address

    Returns:
        True if the host verifiably resolves to localhost only
    """
    # Direct localhost patterns (trusted)
    if host in LOCALHOST_HOSTS:
        return True

    # Check if it's a loopback IP address (trusted)
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback
    except ValueError:
        pass

    # For all other hostnames (including .localhost), we MUST verify DNS resolution
    # This prevents bypassing the safety gate with crafted hostnames
    return _verify_resolves_to_loopback_only(host)


def _verify_resolves_to_loopback_only(host: str) -> bool:
    """Verify that a hostname resolves EXCLUSIVELY to loopback addresses.

    SECURITY: This is used for .localhost domains and other hostnames.
    We must ensure ALL resolved IPs are loopback, not just some.
    If any resolved IP is not loopback, or if resolution fails, return False.

    Args:
        host: Hostname to verify

    Returns:
        True only if ALL resolved addresses are loopback
    """
    try:
        addrs = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addrs:
            # No addresses resolved - not safe
            return False

        # Check that ALL resolved addresses are loopback
        for addr in addrs:
            ip_str = addr[4][0]
            try:
                ip = ipaddress.ip_address(ip_str)
                if not ip.is_loopback:
                    # Found a non-loopback IP - not safe to trust
                    return False
            except ValueError:
                # Invalid IP format - not safe
                return False

        # All addresses are loopback - this is safe
        return True

    except (socket.gaierror, OSError):
        # DNS resolution failed - not safe to assume localhost
        return False


def is_private_ip(host: str) -> bool:
    """Check if a host is a private IP address.

    Private IPs (10.x, 172.16-31.x, 192.168.x) are not localhost
    but are internal network addresses that still require authorization.

    Args:
        host: Hostname or IP address

    Returns:
        True if the host is a private (non-loopback) IP
    """
    # Try to parse as IP address directly
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private and not ip.is_loopback
    except ValueError:
        pass

    # Try to resolve hostname
    try:
        addrs = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for addr in addrs:
            ip_str = addr[4][0]
            try:
                ip = ipaddress.ip_address(ip_str)
                if ip.is_private and not ip.is_loopback:
                    return True
            except ValueError:
                continue
    except (socket.gaierror, OSError):
        pass

    return False


def get_safety_warning(url: str, is_localhost: bool) -> str | None:
    """Get safety warning message for a URL.

    Args:
        url: The target URL
        is_localhost: Whether URL is localhost

    Returns:
        Warning message or None if safe (localhost)
    """
    if is_localhost:
        return None

    result = validate_url(url)
    if not result.is_valid:
        return None

    if is_private_ip(result.host):
        return (
            f"WARNING: {result.host} is a private network address.\n"
            "Scanning internal network targets requires explicit authorization.\n"
            "Use --i-own-this to confirm you have permission to scan this target."
        )

    return (
        f"WARNING: {result.host} is an external target.\n"
        "Unauthorized security scanning may be illegal.\n"
        "Only scan targets you own or have explicit permission to test.\n"
        "Use --i-own-this to confirm you have permission to scan this target."
    )


def normalize_url(url: str) -> str:
    """Normalize a URL by adding scheme if missing.

    Args:
        url: The URL to normalize

    Returns:
        Normalized URL with scheme
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return f"http://{url}"
    return url
