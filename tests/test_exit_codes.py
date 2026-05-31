"""Tests for exit codes."""


from vibeguard.core.exit_codes import ExitCode


class TestExitCodeValues:
    """Test exit code values are correct."""

    def test_success_is_zero(self) -> None:
        """SUCCESS should be 0."""
        assert ExitCode.SUCCESS == 0

    def test_findings_is_one(self) -> None:
        """FINDINGS should be 1."""
        assert ExitCode.FINDINGS == 1

    def test_scan_error_is_two(self) -> None:
        """SCAN_ERROR should be 2."""
        assert ExitCode.SCAN_ERROR == 2

    def test_no_cache_is_three(self) -> None:
        """NO_CACHE should be 3."""
        assert ExitCode.NO_CACHE == 3

    def test_config_error_is_four(self) -> None:
        """CONFIG_ERROR should be 4."""
        assert ExitCode.CONFIG_ERROR == 4

    def test_invalid_path_is_five(self) -> None:
        """INVALID_PATH should be 5."""
        assert ExitCode.INVALID_PATH == 5

    def test_threshold_exceeded_is_ten(self) -> None:
        """THRESHOLD_EXCEEDED should be 10."""
        assert ExitCode.THRESHOLD_EXCEEDED == 10


class TestExitCodeUniqueness:
    """Test exit codes are unique."""

    def test_all_codes_unique(self) -> None:
        """All exit codes should have unique values."""
        codes = [code.value for code in ExitCode]
        assert len(codes) == len(set(codes)), "Duplicate exit codes found"


class TestExitCodeIntEnum:
    """Test ExitCode is usable as integer."""

    def test_can_use_in_comparisons(self) -> None:
        """Exit codes should work in integer comparisons."""
        assert ExitCode.SUCCESS < ExitCode.FINDINGS
        assert ExitCode.FINDINGS < ExitCode.SCAN_ERROR

    def test_can_cast_to_int(self) -> None:
        """Exit codes should be castable to int."""
        assert int(ExitCode.SUCCESS) == 0
        assert int(ExitCode.THRESHOLD_EXCEEDED) == 10
