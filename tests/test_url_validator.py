"""Tests for URL validator module - critical safety component."""

from unittest.mock import patch

from vibeguard.core.url_validator import (
    _verify_resolves_to_loopback_only,
    get_safety_warning,
    is_private_ip,
    normalize_url,
    validate_url,
)


class TestValidateUrl:
    """Test URL validation."""

    def test_valid_localhost_url(self) -> None:
        """Test that localhost URL is valid and marked as localhost."""
        result = validate_url("http://localhost:8080")
        assert result.is_valid is True
        assert result.is_localhost is True
        assert result.host == "localhost"
        assert result.port == 8080
        assert result.scheme == "http"
        assert result.error is None

    def test_valid_localhost_no_port(self) -> None:
        """Test localhost without port."""
        result = validate_url("http://localhost")
        assert result.is_valid is True
        assert result.is_localhost is True
        assert result.host == "localhost"
        assert result.port is None

    def test_valid_127_0_0_1(self) -> None:
        """Test 127.0.0.1 is recognized as localhost."""
        result = validate_url("http://127.0.0.1:3000")
        assert result.is_valid is True
        assert result.is_localhost is True
        assert result.host == "127.0.0.1"
        assert result.port == 3000

    def test_valid_ipv6_localhost(self) -> None:
        """Test IPv6 localhost is recognized."""
        result = validate_url("http://[::1]:8080")
        assert result.is_valid is True
        assert result.is_localhost is True

    def test_valid_external_url(self) -> None:
        """Test external URL is valid but not localhost."""
        result = validate_url("https://example.com")
        assert result.is_valid is True
        assert result.is_localhost is False
        assert result.host == "example.com"
        assert result.scheme == "https"

    def test_external_with_port(self) -> None:
        """Test external URL with port."""
        result = validate_url("https://api.example.com:443/path")
        assert result.is_valid is True
        assert result.is_localhost is False
        assert result.host == "api.example.com"
        assert result.port == 443

    def test_missing_scheme_adds_http(self) -> None:
        """Test that missing scheme defaults to http."""
        result = validate_url("localhost:8080")
        assert result.is_valid is True
        assert result.is_localhost is True
        assert result.scheme == "http"

    def test_missing_scheme_external(self) -> None:
        """Test external URL without scheme."""
        result = validate_url("example.com")
        assert result.is_valid is True
        assert result.is_localhost is False
        assert result.scheme == "http"

    def test_empty_url_invalid(self) -> None:
        """Test that empty URL is invalid."""
        result = validate_url("")
        assert result.is_valid is False
        assert result.error is not None
        assert "empty" in result.error.lower()

    def test_whitespace_only_invalid(self) -> None:
        """Test that whitespace-only URL is invalid."""
        result = validate_url("   ")
        assert result.is_valid is False
        assert result.error is not None

    def test_url_with_path(self) -> None:
        """Test URL with path component."""
        result = validate_url("http://localhost:8080/api/v1/users")
        assert result.is_valid is True
        assert result.is_localhost is True
        assert result.host == "localhost"
        assert result.port == 8080

    def test_localhost_subdomain_requires_dns_verification(self) -> None:
        """Test that subdomain.localhost requires DNS verification to be localhost.

        SECURITY: .localhost domains are no longer blindly trusted.
        They must resolve to loopback to be considered localhost.
        """
        # Without mocking DNS, app.localhost may not resolve on Windows
        result = validate_url("http://app.localhost:3000")
        assert result.is_valid is True
        assert result.host == "app.localhost"
        # is_localhost depends on actual DNS resolution

    def test_localhost_subdomain_trusted_with_loopback_dns(self) -> None:
        """Test subdomain.localhost is trusted when DNS resolves to loopback."""
        with patch("vibeguard.core.url_validator.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(2, 1, 0, "", ("127.0.0.1", 0))]
            result = validate_url("http://app.localhost:3000")
            assert result.is_valid is True
            assert result.is_localhost is True
            assert result.host == "app.localhost"

    def test_deep_localhost_subdomain_trusted_with_loopback_dns(self) -> None:
        """Test deep subdomain of localhost is trusted when DNS verifies."""
        with patch("vibeguard.core.url_validator.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(2, 1, 0, "", ("127.0.0.1", 0))]
            result = validate_url("http://api.v1.localhost:8080")
            assert result.is_valid is True
            assert result.is_localhost is True

    def test_https_localhost(self) -> None:
        """Test HTTPS localhost."""
        result = validate_url("https://localhost:8443")
        assert result.is_valid is True
        assert result.is_localhost is True
        assert result.scheme == "https"

    def test_case_insensitive_localhost(self) -> None:
        """Test that localhost matching is case-insensitive."""
        result = validate_url("http://LOCALHOST:8080")
        assert result.is_valid is True
        assert result.is_localhost is True
        assert result.host == "localhost"  # Normalized to lowercase


class TestIsPrivateIp:
    """Test private IP detection."""

    def test_10_x_private(self) -> None:
        """Test 10.x.x.x range is private."""
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("10.255.255.255") is True
        assert is_private_ip("10.100.50.25") is True

    def test_172_16_private(self) -> None:
        """Test 172.16-31.x.x range is private."""
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("172.31.255.255") is True
        assert is_private_ip("172.20.10.5") is True

    def test_172_outside_range_not_private(self) -> None:
        """Test 172.x outside 16-31 is not private."""
        assert is_private_ip("172.15.0.1") is False
        assert is_private_ip("172.32.0.1") is False

    def test_192_168_private(self) -> None:
        """Test 192.168.x.x range is private."""
        assert is_private_ip("192.168.0.1") is True
        assert is_private_ip("192.168.1.100") is True
        assert is_private_ip("192.168.255.255") is True

    def test_public_ip_not_private(self) -> None:
        """Test public IPs are not private."""
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.1.1.1") is False
        assert is_private_ip("93.184.216.34") is False  # example.com

    def test_localhost_not_private(self) -> None:
        """Test localhost is not considered private (it's loopback)."""
        assert is_private_ip("127.0.0.1") is False
        assert is_private_ip("::1") is False

    def test_non_ip_hostname(self) -> None:
        """Test that non-IP hostname returns False if can't resolve."""
        # This should not raise, just return False
        result = is_private_ip("nonexistent.invalid.hostname.test")
        assert result is False


class TestGetSafetyWarning:
    """Test safety warning generation."""

    def test_localhost_no_warning(self) -> None:
        """Test that localhost returns no warning."""
        warning = get_safety_warning("http://localhost:8080", is_localhost=True)
        assert warning is None

    def test_localhost_ip_no_warning(self) -> None:
        """Test that 127.0.0.1 returns no warning."""
        warning = get_safety_warning("http://127.0.0.1:3000", is_localhost=True)
        assert warning is None

    def test_external_host_warning(self) -> None:
        """Test that external host returns warning."""
        warning = get_safety_warning("https://example.com", is_localhost=False)
        assert warning is not None
        assert "external" in warning.lower()
        assert "--i-own-this" in warning

    def test_warning_mentions_host(self) -> None:
        """Test that warning mentions the host."""
        warning = get_safety_warning("https://api.example.com", is_localhost=False)
        assert warning is not None
        assert "api.example.com" in warning

    def test_warning_mentions_legal(self) -> None:
        """Test that warning mentions legal implications."""
        warning = get_safety_warning("https://example.com", is_localhost=False)
        assert warning is not None
        assert "illegal" in warning.lower() or "unauthorized" in warning.lower()


class TestNormalizeUrl:
    """Test URL normalization."""

    def test_adds_http_scheme(self) -> None:
        """Test that http:// is added if no scheme."""
        assert normalize_url("localhost:8080") == "http://localhost:8080"

    def test_preserves_http_scheme(self) -> None:
        """Test that existing http:// is preserved."""
        assert normalize_url("http://localhost:8080") == "http://localhost:8080"

    def test_preserves_https_scheme(self) -> None:
        """Test that existing https:// is preserved."""
        assert normalize_url("https://example.com") == "https://example.com"

    def test_strips_whitespace(self) -> None:
        """Test that whitespace is stripped."""
        assert normalize_url("  http://localhost  ") == "http://localhost"

    def test_external_no_scheme(self) -> None:
        """Test external URL without scheme."""
        assert normalize_url("example.com/path") == "http://example.com/path"


class TestLocalhostVerificationSecurity:
    """Security regression tests for localhost verification.

    These tests ensure that .localhost domains cannot be used to bypass
    the safety gate without proper DNS resolution verification.
    """

    def test_dotlocalhost_not_trusted_without_dns(self) -> None:
        """Test that .localhost domains are NOT trusted if DNS resolution fails.

        SECURITY: On Windows, names like foo.localhost don't automatically
        resolve to loopback. We must verify resolution, not just trust patterns.
        """
        # Mock DNS resolution failure
        with patch("vibeguard.core.url_validator.socket.getaddrinfo") as mock_dns:
            mock_dns.side_effect = OSError("Name resolution failed")
            result = validate_url("http://malicious.localhost:8080")
            # Should NOT be marked as localhost without verified resolution
            assert result.is_valid is True
            assert result.is_localhost is False

    def test_dotlocalhost_trusted_when_resolves_loopback(self) -> None:
        """Test that .localhost is trusted when it resolves to loopback."""
        with patch("vibeguard.core.url_validator.socket.getaddrinfo") as mock_dns:
            # Mock resolution to 127.0.0.1
            mock_dns.return_value = [
                (2, 1, 0, "", ("127.0.0.1", 0)),
            ]
            result = validate_url("http://app.localhost:3000")
            assert result.is_valid is True
            assert result.is_localhost is True

    def test_dotlocalhost_not_trusted_when_resolves_external(self) -> None:
        """Test that .localhost is NOT trusted if it resolves to external IP.

        SECURITY: A malicious actor could add an entry like
        'prod.localhost -> 93.184.216.34' in hosts file and bypass the gate.
        """
        with patch("vibeguard.core.url_validator.socket.getaddrinfo") as mock_dns:
            # Mock resolution to external IP (example.com)
            mock_dns.return_value = [
                (2, 1, 0, "", ("93.184.216.34", 0)),
            ]
            result = validate_url("http://evil.localhost:8080")
            # Should NOT be marked as localhost
            assert result.is_valid is True
            assert result.is_localhost is False

    def test_dotlocalhost_mixed_resolution_not_trusted(self) -> None:
        """Test that .localhost is NOT trusted if ANY resolved IP is external.

        SECURITY: If a hostname resolves to both loopback AND external IPs,
        it should not be trusted as localhost.
        """
        with patch("vibeguard.core.url_validator.socket.getaddrinfo") as mock_dns:
            # Mock resolution to both loopback and external
            mock_dns.return_value = [
                (2, 1, 0, "", ("127.0.0.1", 0)),
                (2, 1, 0, "", ("8.8.8.8", 0)),  # External!
            ]
            result = validate_url("http://suspicious.localhost:8080")
            # Should NOT be marked as localhost
            assert result.is_valid is True
            assert result.is_localhost is False

    def test_verify_resolves_loopback_only_all_loopback(self) -> None:
        """Test _verify_resolves_to_loopback_only with all loopback IPs."""
        with patch("vibeguard.core.url_validator.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (2, 1, 0, "", ("127.0.0.1", 0)),
                (10, 1, 0, "", ("::1", 0)),  # IPv6 loopback
            ]
            assert _verify_resolves_to_loopback_only("test.localhost") is True

    def test_verify_resolves_loopback_only_empty_result(self) -> None:
        """Test _verify_resolves_to_loopback_only with empty DNS result."""
        with patch("vibeguard.core.url_validator.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = []
            assert _verify_resolves_to_loopback_only("test.localhost") is False

    def test_direct_localhost_still_trusted(self) -> None:
        """Test that direct 'localhost' is still trusted without DNS check."""
        # 'localhost' is in LOCALHOST_HOSTS and bypasses DNS check
        result = validate_url("http://localhost:8080")
        assert result.is_localhost is True

    def test_direct_127_0_0_1_still_trusted(self) -> None:
        """Test that 127.0.0.1 is still trusted without DNS check."""
        result = validate_url("http://127.0.0.1:8080")
        assert result.is_localhost is True

    def test_ipv6_loopback_still_trusted(self) -> None:
        """Test that ::1 is still trusted without DNS check."""
        result = validate_url("http://[::1]:8080")
        assert result.is_localhost is True
