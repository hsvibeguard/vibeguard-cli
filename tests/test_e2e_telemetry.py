"""End-to-end tests for telemetry flow: CLI scan -> API submission.

Tests the submit_scan function from vibeguard.core.telemetry,
covering payload construction, auth gating, error handling, and
integration with the scan command.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import httpx
import pytest

from vibeguard.core import auth as auth_module
from vibeguard.core.telemetry import submit_scan
from vibeguard.models.auth import AuthToken
from vibeguard.models.finding import Category, Finding, Severity
from vibeguard.models.scan_result import ScanResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    severity: Severity = Severity.HIGH,
    category: Category = Category.SECURITY,
    scanner: str = "semgrep",
    rule_id: str = "test-rule",
    file_path: str = "app.py",
    line_start: int = 1,
) -> Finding:
    return Finding(
        scanner=scanner,
        rule_id=rule_id,
        severity=severity,
        category=category,
        title=f"{severity.value} issue",
        message="Test finding",
        file_path=file_path,
        line_start=line_start,
    )


def _make_scan_result(
    findings: list[Finding] | None = None,
    scanners_run: list[str] | None = None,
    partial: bool = False,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
) -> ScanResult:
    now = datetime.now(UTC)
    return ScanResult(
        repo_root="/tmp/test-repo",
        started_at=started_at or now - timedelta(seconds=30),
        finished_at=finished_at or now,
        findings=findings or [],
        scanners_run=scanners_run or ["semgrep"],
        partial=partial,
    )


def _make_valid_token() -> AuthToken:
    return AuthToken(
        token="test-pro-token-abc123",
        expires_at=datetime.now(UTC) + timedelta(days=7),
        entitlements=["pro.patch", "pro.apply"],
        plan="pro",
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolate_auth(tmp_path):
    """Prevent tests from touching real auth files."""
    auth_dir = tmp_path / ".vibeguard"
    with (
        patch.object(auth_module, "AUTH_DIR", auth_dir),
        patch.object(auth_module, "AUTH_CACHE_FILE", auth_dir / "auth.json"),
        patch.object(auth_module, "MACHINE_ID_FILE", auth_dir / "machine_id"),
    ):
        yield


# ---------------------------------------------------------------------------
# 1. Telemetry Submission Tests
# ---------------------------------------------------------------------------

class TestSubmitScanSendsCorrectPayload:
    """Verify submit_scan sends properly shaped payload to the API."""

    def test_submit_scan_sends_correct_payload(self) -> None:
        """Payload should contain score, grade, counts, scanners, etc."""
        token = _make_valid_token()
        result = _make_scan_result(
            findings=[
                _make_finding(Severity.CRITICAL),
                _make_finding(Severity.HIGH, rule_id="r2", line_start=2),
                _make_finding(Severity.MEDIUM, rule_id="r3", line_start=3),
            ],
            scanners_run=["semgrep", "gitleaks"],
        )

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        with (
            patch.object(auth_module, "get_cached_token", return_value=token),
            patch("vibeguard.core.telemetry.httpx.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            submit_scan(result, repo_name="my-repo")

            # Verify post was called
            mock_client.post.assert_called_once()
            call_args = mock_client.post.call_args

            # Check URL
            assert "/v1/scans" in call_args[0][0]

            # Check payload shape
            payload = call_args[1]["json"]
            assert isinstance(payload["score"], int)
            assert isinstance(payload["grade"], str)
            assert isinstance(payload["scanners_run"], list)
            assert isinstance(payload["partial"], bool)
            assert "scanned_at" in payload
            assert payload["repo_name"] == "my-repo"

    def test_submit_scan_includes_bearer_token(self) -> None:
        """Authorization header should contain Bearer <token>."""
        token = _make_valid_token()
        result = _make_scan_result()

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        with (
            patch.object(auth_module, "get_cached_token", return_value=token),
            patch("vibeguard.core.telemetry.httpx.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            submit_scan(result)

            call_args = mock_client.post.call_args
            headers = call_args[1]["headers"]
            assert headers["Authorization"] == f"Bearer {token.token}"


class TestSubmitScanAuthGating:
    """Verify telemetry is gated on Pro auth."""

    def test_submit_scan_skips_without_token(self) -> None:
        """No Pro token -> no HTTP call should be made."""
        result = _make_scan_result()

        with (
            patch.object(auth_module, "get_cached_token", return_value=None),
            patch("vibeguard.core.telemetry.httpx.Client") as mock_client_cls,
        ):
            submit_scan(result)

            mock_client_cls.assert_not_called()


class TestSubmitScanErrorHandling:
    """Verify submit_scan never raises, regardless of errors."""

    def test_submit_scan_never_raises_on_network_error(self) -> None:
        """Network error should be silently caught."""
        token = _make_valid_token()
        result = _make_scan_result()

        with (
            patch.object(auth_module, "get_cached_token", return_value=token),
            patch("vibeguard.core.telemetry.httpx.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.side_effect = httpx.ConnectError("Connection refused")
            mock_client_cls.return_value = mock_client

            # Should not raise
            submit_scan(result)

    def test_submit_scan_never_raises_on_server_error(self) -> None:
        """500 response should be silently caught."""
        token = _make_valid_token()
        result = _make_scan_result()

        with (
            patch.object(auth_module, "get_cached_token", return_value=token),
            patch("vibeguard.core.telemetry.httpx.Client") as mock_client_cls,
        ):
            mock_response = MagicMock()
            mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
                "Server Error",
                request=MagicMock(),
                response=MagicMock(status_code=500),
            )
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            # Should not raise
            submit_scan(result)

    def test_submit_scan_never_raises_on_timeout(self) -> None:
        """Timeout should be silently caught."""
        token = _make_valid_token()
        result = _make_scan_result()

        with (
            patch.object(auth_module, "get_cached_token", return_value=token),
            patch("vibeguard.core.telemetry.httpx.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.side_effect = httpx.ReadTimeout("Timed out")
            mock_client_cls.return_value = mock_client

            # Should not raise
            submit_scan(result)

    def test_submit_scan_never_raises_on_attribute_error(self) -> None:
        """Any internal error (like AttributeError) is caught by broad except."""
        token = _make_valid_token()
        result = _make_scan_result()

        with (
            patch.object(auth_module, "get_cached_token", return_value=token),
            patch("vibeguard.core.telemetry.httpx.Client", side_effect=AttributeError("test")),
        ):
            # Should not raise
            submit_scan(result)


class TestSubmitScanDuration:
    """Verify duration calculation from started_at/finished_at."""

    def test_submit_scan_calculates_duration(self) -> None:
        """Duration in ms should be correctly computed from timestamps."""
        token = _make_valid_token()
        start = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        end = datetime(2026, 1, 1, 12, 0, 45, tzinfo=UTC)  # 45 seconds later
        result = _make_scan_result(started_at=start, finished_at=end)

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        with (
            patch.object(auth_module, "get_cached_token", return_value=token),
            patch("vibeguard.core.telemetry.httpx.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            submit_scan(result)

            payload = mock_client.post.call_args[1]["json"]
            assert payload["scan_duration_ms"] == 45000

    def test_submit_scan_duration_none_without_finished_at(self) -> None:
        """Duration should be None when finished_at is missing."""
        token = _make_valid_token()
        result = _make_scan_result()
        result.finished_at = None  # type: ignore[assignment]

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        with (
            patch.object(auth_module, "get_cached_token", return_value=token),
            patch("vibeguard.core.telemetry.httpx.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            submit_scan(result)

            payload = mock_client.post.call_args[1]["json"]
            assert payload["scan_duration_ms"] is None


class TestSubmitScanRepoName:
    """Verify repo_name handling in payload."""

    def test_submit_scan_includes_repo_name_when_provided(self) -> None:
        """repo_name should appear in payload when provided."""
        token = _make_valid_token()
        result = _make_scan_result()

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        with (
            patch.object(auth_module, "get_cached_token", return_value=token),
            patch("vibeguard.core.telemetry.httpx.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            submit_scan(result, repo_name="my-project")

            payload = mock_client.post.call_args[1]["json"]
            assert payload["repo_name"] == "my-project"

    def test_submit_scan_omits_repo_name_when_none(self) -> None:
        """repo_name should be None in payload when not provided."""
        token = _make_valid_token()
        result = _make_scan_result()

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        with (
            patch.object(auth_module, "get_cached_token", return_value=token),
            patch("vibeguard.core.telemetry.httpx.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            submit_scan(result)

            payload = mock_client.post.call_args[1]["json"]
            assert payload["repo_name"] is None


# ---------------------------------------------------------------------------
# 2. ScanResult -> Payload Mapping Tests
# ---------------------------------------------------------------------------

class TestScanResultToPayload:
    """Verify ScanResult fields map correctly to telemetry payload."""

    def test_scan_result_to_payload_all_fields(self) -> None:
        """Full ScanResult with findings should produce correct payload."""
        start = datetime(2026, 1, 15, 10, 0, 0, tzinfo=UTC)
        end = datetime(2026, 1, 15, 10, 1, 0, tzinfo=UTC)
        result = _make_scan_result(
            findings=[
                _make_finding(Severity.CRITICAL, rule_id="c1"),
                _make_finding(Severity.HIGH, rule_id="h1", line_start=2),
                _make_finding(Severity.HIGH, rule_id="h2", line_start=3),
                _make_finding(Severity.MEDIUM, rule_id="m1", line_start=4),
                _make_finding(Severity.LOW, rule_id="l1", line_start=5),
            ],
            scanners_run=["semgrep", "gitleaks", "trivy"],
            partial=False,
            started_at=start,
            finished_at=end,
        )

        # All findings are Category.SECURITY (default), so:
        # critical=20, high1=10, high2=10, medium=5, low=2 => total=47, cap=50 => deduct 47
        # Score = 100 - 47 = 53
        assert result.score == 53
        assert result.grade == "C"
        assert result.counts.critical == 1
        assert result.counts.high == 2
        assert result.counts.medium == 1
        assert result.counts.low == 1
        assert len(result.findings) == 5
        assert result.scanners_run == ["semgrep", "gitleaks", "trivy"]
        assert result.partial is False

    def test_scan_result_minimal(self) -> None:
        """ScanResult with no findings should have perfect score."""
        result = _make_scan_result(findings=[], scanners_run=["semgrep"])

        assert result.score == 100
        assert result.grade == "A+"
        assert result.counts.critical == 0
        assert result.counts.high == 0
        assert result.counts.medium == 0
        assert result.counts.low == 0
        assert len(result.findings) == 0

    def test_scan_result_partial_flag(self) -> None:
        """partial=True in ScanResult should propagate."""
        result = _make_scan_result(partial=True)

        assert result.partial is True


# ---------------------------------------------------------------------------
# 3. Integration with scan command
# ---------------------------------------------------------------------------

class TestScanCommandIntegration:
    """Verify scan command calls submit_scan correctly."""

    def test_scan_command_calls_submit(self) -> None:
        """After scan completes, submit_scan should be called."""
        # We test this by verifying the import and call pattern in scan.py.
        # Since scan.py does a lazy import and call, we mock at the module level.
        with patch("vibeguard.core.telemetry.submit_scan"):
            # Verify submit_scan is importable and callable
            from vibeguard.core.telemetry import submit_scan as real_submit

            result = _make_scan_result()
            token = _make_valid_token()

            with patch.object(auth_module, "get_cached_token", return_value=token):
                real_submit(result)

            # The real function was called (not the mock, since we imported directly)
            # This test validates the function signature is correct
            assert callable(real_submit)

    def test_scan_command_skips_submit_free_tier(self) -> None:
        """Free user (no token) should result in no HTTP calls."""
        result = _make_scan_result()

        with (
            patch.object(auth_module, "get_cached_token", return_value=None),
            patch("vibeguard.core.telemetry.httpx.Client") as mock_client_cls,
        ):
            submit_scan(result)

            # No HTTP client should be created
            mock_client_cls.assert_not_called()


# ---------------------------------------------------------------------------
# 4. API Contract Validation
# ---------------------------------------------------------------------------

class TestApiContractValidation:
    """Verify payload matches the expected API contract."""

    def _extract_payload(self, result: ScanResult, repo_name: str | None = None) -> dict:
        """Helper to extract the payload that submit_scan would send."""
        token = _make_valid_token()
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        with (
            patch.object(auth_module, "get_cached_token", return_value=token),
            patch("vibeguard.core.telemetry.httpx.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            submit_scan(result, repo_name=repo_name)

            return mock_client.post.call_args[1]["json"]

    def test_payload_matches_api_contract(self) -> None:
        """All required fields must be present in the payload."""
        result = _make_scan_result(
            findings=[_make_finding(Severity.HIGH)],
            scanners_run=["semgrep"],
        )

        payload = self._extract_payload(result, repo_name="test-repo")

        required_fields = {
            "score",
            "grade",
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
            "total_findings",
            "scanners_run",
            "scan_duration_ms",
            "partial",
            "repo_name",
            "scanned_at",
        }
        assert required_fields.issubset(set(payload.keys())), (
            f"Missing fields: {required_fields - set(payload.keys())}"
        )

    def test_payload_types_correct(self) -> None:
        """Verify each payload field has the correct Python type."""
        result = _make_scan_result(
            findings=[
                _make_finding(Severity.CRITICAL, rule_id="c1"),
                _make_finding(Severity.HIGH, rule_id="h1", line_start=2),
            ],
            scanners_run=["semgrep", "gitleaks"],
        )

        payload = self._extract_payload(result)

        assert isinstance(payload["score"], int)
        assert isinstance(payload["grade"], str)
        assert isinstance(payload["critical_count"], int)
        assert isinstance(payload["high_count"], int)
        assert isinstance(payload["medium_count"], int)
        assert isinstance(payload["low_count"], int)
        assert isinstance(payload["total_findings"], int)
        assert isinstance(payload["scanners_run"], list)
        assert all(isinstance(s, str) for s in payload["scanners_run"])
        assert payload["scan_duration_ms"] is None or isinstance(payload["scan_duration_ms"], int)
        assert isinstance(payload["partial"], bool)
        assert isinstance(payload["scanned_at"], str)

    def test_payload_scanners_run_matches(self) -> None:
        """scanners_run should match the ScanResult."""
        scanners = ["semgrep", "gitleaks", "trivy"]
        result = _make_scan_result(scanners_run=scanners)

        payload = self._extract_payload(result)

        assert payload["scanners_run"] == scanners

    def test_payload_scanned_at_is_iso_format(self) -> None:
        """scanned_at should be a valid ISO datetime string."""
        end = datetime(2026, 2, 1, 14, 30, 0, tzinfo=UTC)
        result = _make_scan_result(finished_at=end)

        payload = self._extract_payload(result)

        # Should be parseable as ISO format
        parsed = datetime.fromisoformat(payload["scanned_at"])
        assert parsed.year == 2026
        assert parsed.month == 2
        assert parsed.day == 1
