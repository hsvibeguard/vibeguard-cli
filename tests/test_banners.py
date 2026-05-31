"""Tests for CLI expiry banners and grace period status."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from vibeguard.cli.banners import (
    APPROACHING_DAYS,
    CRITICAL_HOURS,
    _show_approaching_banner,
    _show_critical_banner,
    _show_grace_period_banner,
    show_expiry_banner,
)
from vibeguard.core.license import get_license_status_with_grace
from vibeguard.models.auth import AuthToken


class TestShowExpiryBanner:
    """Tests for show_expiry_banner() function."""

    def test_no_banner_when_invalid(self, capsys):
        """No banner should be shown when license is invalid."""
        status = {"valid": False, "in_grace": False, "days_left": 0}
        show_expiry_banner(status)
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_no_banner_when_healthy(self, capsys):
        """No banner for licenses with > 7 days remaining."""
        status = {"valid": True, "in_grace": False, "days_left": 30, "hours_left": 0}
        show_expiry_banner(status)
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_grace_period_banner_shown(self, capsys):
        """Grace period banner should be shown when in_grace=True."""
        status = {"valid": True, "in_grace": True, "hours_left": 24, "days_left": 0}
        show_expiry_banner(status)
        captured = capsys.readouterr()
        assert "Grace Period Active" in captured.out
        assert "24 hours remaining" in captured.out

    def test_critical_banner_when_less_than_24_hours(self, capsys):
        """Critical banner shown when < 24 hours remaining."""
        status = {"valid": True, "in_grace": False, "days_left": 0, "hours_left": 12}
        show_expiry_banner(status)
        captured = capsys.readouterr()
        assert "License Expiring Soon" in captured.out
        assert "12 hour" in captured.out

    def test_approaching_banner_when_less_than_7_days(self, capsys):
        """Approaching banner shown when 1-7 days remaining."""
        status = {"valid": True, "in_grace": False, "days_left": 5, "hours_left": 0}
        show_expiry_banner(status)
        captured = capsys.readouterr()
        assert "Renewal Reminder" in captured.out
        assert "5 days" in captured.out

    def test_approaching_banner_singular_day(self, capsys):
        """Approaching banner uses singular 'day' for 1 day."""
        status = {"valid": True, "in_grace": False, "days_left": 1, "hours_left": 12}
        show_expiry_banner(status)
        captured = capsys.readouterr()
        # With 1 day and 12 hours = 36 hours > 24, so approaching banner
        assert "Renewal Reminder" in captured.out
        assert "1 day" in captured.out

    def test_critical_takes_priority_over_approaching(self, capsys):
        """Critical banner when days_left=0 even if hours > 0."""
        status = {"valid": True, "in_grace": False, "days_left": 0, "hours_left": 23}
        show_expiry_banner(status)
        captured = capsys.readouterr()
        assert "License Expiring Soon" in captured.out
        assert "Renewal Reminder" not in captured.out

    def test_grace_takes_priority_over_critical(self, capsys):
        """Grace period banner takes priority over critical."""
        status = {"valid": True, "in_grace": True, "hours_left": 5, "days_left": 0}
        show_expiry_banner(status)
        captured = capsys.readouterr()
        assert "Grace Period Active" in captured.out
        assert "License Expiring Soon" not in captured.out


class TestGracePeriodBanner:
    """Tests for _show_grace_period_banner()."""

    def test_shows_hours_remaining(self, capsys):
        """Banner shows hours remaining."""
        _show_grace_period_banner(36)
        captured = capsys.readouterr()
        assert "36 hours remaining" in captured.out
        assert "Grace Period Active" in captured.out
        assert "app.vibeguard.co/billing" in captured.out

    def test_shows_single_hour(self, capsys):
        """Banner handles single hour properly."""
        _show_grace_period_banner(1)
        captured = capsys.readouterr()
        assert "1 hours remaining" in captured.out


class TestCriticalBanner:
    """Tests for _show_critical_banner()."""

    def test_shows_hours_remaining(self, capsys):
        """Banner shows hours remaining."""
        _show_critical_banner(12)
        captured = capsys.readouterr()
        assert "12 hours" in captured.out
        assert "License Expiring Soon" in captured.out

    def test_singular_hour(self, capsys):
        """Banner uses singular 'hour' for 1 hour."""
        _show_critical_banner(1)
        captured = capsys.readouterr()
        assert "1 hour!" in captured.out


class TestApproachingBanner:
    """Tests for _show_approaching_banner()."""

    def test_shows_days_remaining(self, capsys):
        """Banner shows days remaining."""
        _show_approaching_banner(5)
        captured = capsys.readouterr()
        assert "5 days" in captured.out
        assert "Renewal Reminder" in captured.out

    def test_singular_day(self, capsys):
        """Banner uses singular 'day' for 1 day."""
        _show_approaching_banner(1)
        captured = capsys.readouterr()
        assert "1 day." in captured.out


class TestGetLicenseStatusWithGrace:
    """Tests for get_license_status_with_grace()."""

    def test_returns_invalid_when_no_token(self):
        """Returns invalid status when no token cached."""
        with patch("vibeguard.core.auth.get_cached_token", return_value=None):
            status = get_license_status_with_grace()

        assert status["valid"] is False
        assert status["in_grace"] is False
        assert status["days_left"] == 0
        assert status["hours_left"] == 0

    def test_returns_invalid_when_token_expired(self):
        """Returns invalid status when token is fully expired."""
        expired_token = AuthToken(
            token="test-token",
            expires_at=datetime.now(UTC) - timedelta(hours=1),
            entitlements=["pro.patch"],
        )

        with patch("vibeguard.core.auth.get_cached_token", return_value=expired_token):
            with patch(
                "vibeguard.core.auth.get_token_time_remaining",
                return_value=timedelta(seconds=-3600),
            ):
                status = get_license_status_with_grace()

        assert status["valid"] is False

    def test_returns_valid_with_days_remaining(self):
        """Returns valid status with days remaining."""
        future_token = AuthToken(
            token="test-token",
            expires_at=datetime.now(UTC) + timedelta(days=10),
            entitlements=["pro.patch"],
        )

        with patch("vibeguard.core.auth.get_cached_token", return_value=future_token):
            with patch(
                "vibeguard.core.auth.get_token_time_remaining",
                return_value=timedelta(days=10, hours=5),
            ):
                status = get_license_status_with_grace()

        assert status["valid"] is True
        assert status["in_grace"] is False
        assert status["days_left"] == 10

    def test_detects_grace_period_via_entitlement(self):
        """Detects grace period when 'grace.active' entitlement present."""
        grace_token = AuthToken(
            token="test-token",
            expires_at=datetime.now(UTC) + timedelta(hours=24),
            entitlements=["pro.patch", "grace.active"],
        )

        with patch("vibeguard.core.auth.get_cached_token", return_value=grace_token):
            with patch(
                "vibeguard.core.auth.get_token_time_remaining",
                return_value=timedelta(hours=24),
            ):
                status = get_license_status_with_grace()

        assert status["valid"] is True
        assert status["in_grace"] is True

    def test_returns_license_expires_at(self):
        """Returns license_expires_at from token."""
        expires = datetime.now(UTC) + timedelta(days=5)
        token = AuthToken(
            token="test-token",
            expires_at=expires,
            entitlements=["pro.patch"],
        )

        with patch("vibeguard.core.auth.get_cached_token", return_value=token):
            with patch(
                "vibeguard.core.auth.get_token_time_remaining",
                return_value=timedelta(days=5),
            ):
                status = get_license_status_with_grace()

        assert status["license_expires_at"] == expires


class TestBannerConstants:
    """Tests for banner threshold constants."""

    def test_critical_hours_is_24(self):
        """Critical threshold is 24 hours."""
        assert CRITICAL_HOURS == 24

    def test_approaching_days_is_7(self):
        """Approaching threshold is 7 days."""
        assert APPROACHING_DAYS == 7
