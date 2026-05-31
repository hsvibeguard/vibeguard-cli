"""Tests for patch CLI command."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from vibeguard.cli.main import app
from vibeguard.core import auth as auth_module
from vibeguard.core import keyring
from vibeguard.core.llm import LLMResponse
from vibeguard.models.finding import Category, Finding, Severity
from vibeguard.models.scan_result import ScanResult

runner = CliRunner()

SAMPLE_DIFF = """\
--- a/app/utils.py
+++ b/app/utils.py
@@ -40,5 +40,5 @@ def process_input(user_input):
     # Process the input
-    exec(user_input)
+    result = safe_eval(user_input)
     return True
"""


@pytest.fixture
def sample_finding() -> Finding:
    """Create a sample finding for testing."""
    return Finding(
        scanner="semgrep",
        rule_id="python.security.audit.exec-detected",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        title="Use of exec() detected",
        message="The exec() function can execute arbitrary code.",
        file_path="app/utils.py",
        line_start=42,
        line_end=42,
        cwe="CWE-78",
        code_snippet="exec(user_input)",
    )


@pytest.fixture
def sample_scan_result(sample_finding: Finding) -> ScanResult:
    """Create a sample scan result."""
    return ScanResult(
        repo_root="/test/repo",
        started_at=datetime.now(),
        finished_at=datetime.now(),
        findings=[sample_finding],
        scanners_run=["semgrep"],
    )


@pytest.fixture(autouse=True)
def mock_keys_storage(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Mock the keys directory to use temp path."""
    keys_dir = tmp_path / ".vibeguard" / "keys"
    master_key = keys_dir / "master.key"
    providers_file = keys_dir / "providers.enc"

    with (
        patch.object(keyring, "KEYS_DIR", keys_dir),
        patch.object(keyring, "MASTER_KEY_FILE", master_key),
        patch.object(keyring, "PROVIDERS_FILE", providers_file),
    ):
        yield


@pytest.fixture
def mock_pro_license():
    """Mock a valid Pro license token for tests that need Pro access."""
    from datetime import UTC, timedelta

    from vibeguard.models.auth import AuthToken

    mock_token = AuthToken(
        token="test-token",
        expires_at=datetime.now(UTC) + timedelta(days=7),
        entitlements=["pro.patch", "pro.apply"],
        plan="pro",
    )

    with patch.object(auth_module, "get_cached_token", return_value=mock_token):
        yield mock_token


class TestPatchCommand:
    """Tests for 'vibeguard patch' CLI command."""

    def test_requires_pro_license(self, tmp_path: Path) -> None:
        """Should error if no LLM key configured (not Pro)."""
        result = runner.invoke(app, ["patch", "abc123", "--path", str(tmp_path)])

        assert result.exit_code != 0
        assert "pro license" in result.output.lower() or "requires" in result.output.lower()

    def test_requires_cached_scan(self, tmp_path: Path, mock_pro_license) -> None:
        """Should error if no cached scan exists."""
        keyring.save_key("openai", "test-key")  # Need BYOK key for patch
        with patch("vibeguard.cli.patch.load_latest_scan", return_value=None):
            result = runner.invoke(app, ["patch", "abc123", "--path", str(tmp_path)])

        assert result.exit_code != 0
        assert "no cached scan" in result.output.lower()

    def test_shows_error_for_invalid_finding(
        self, tmp_path: Path, sample_scan_result: ScanResult, mock_pro_license
    ) -> None:
        """Should error if finding not found."""
        keyring.save_key("openai", "test-key")  # Need BYOK key for patch
        with patch("vibeguard.cli.patch.load_latest_scan", return_value=sample_scan_result):
            result = runner.invoke(app, ["patch", "nonexistent", "--path", str(tmp_path)])

        assert result.exit_code != 0
        assert "not found" in result.output.lower()

    def test_requires_llm_key(
        self, tmp_path: Path, sample_scan_result: ScanResult, sample_finding: Finding, mock_pro_license
    ) -> None:
        """Should error if no LLM key configured (even with Pro license)."""
        # Don't set up BYOK key - should fail with LLM key error
        with patch("vibeguard.cli.patch.load_latest_scan", return_value=sample_scan_result):
            result = runner.invoke(
                app, ["patch", sample_finding.id, "--path", str(tmp_path)]
            )

        assert result.exit_code != 0
        assert "llm" in result.output.lower() or "api key" in result.output.lower()

    def test_generates_patch_successfully(
        self, tmp_path: Path, sample_scan_result: ScanResult, sample_finding: Finding, mock_pro_license
    ) -> None:
        """Should generate patch with valid Pro license and LLM key."""
        # Set up BYOK key
        keyring.save_key("openai", "test-key")

        # Mock LLM response
        mock_response = LLMResponse(
            content=f"```diff\n{SAMPLE_DIFF}\n```",
            model="gpt-4",
            provider="openai",
            tokens_used=100,
        )

        with (
            patch("vibeguard.cli.patch.load_latest_scan", return_value=sample_scan_result),
            patch("vibeguard.cli.patch.generate", new_callable=AsyncMock) as mock_gen,
        ):
            mock_gen.return_value = mock_response

            result = runner.invoke(
                app,
                ["patch", sample_finding.id, "--path", str(tmp_path), "--dry-run"],
            )

        assert result.exit_code == 0
        assert "generated successfully" in result.output.lower()
        assert "--- a/app/utils.py" in result.output

    def test_saves_patch_file(
        self, tmp_path: Path, sample_scan_result: ScanResult, sample_finding: Finding, mock_pro_license
    ) -> None:
        """Should save patch file to .vibeguard/patches/."""
        keyring.save_key("openai", "test-key")

        mock_response = LLMResponse(
            content=f"```diff\n{SAMPLE_DIFF}\n```",
            model="gpt-4",
            provider="openai",
        )

        with (
            patch("vibeguard.cli.patch.load_latest_scan", return_value=sample_scan_result),
            patch("vibeguard.cli.patch.generate", new_callable=AsyncMock) as mock_gen,
            patch("vibeguard.cli.patch._prompt_apply_patch", return_value="skip"),
        ):
            mock_gen.return_value = mock_response

            result = runner.invoke(
                app, ["patch", sample_finding.id, "--path", str(tmp_path)]
            )

        assert result.exit_code == 0

        # Check patch file exists
        patches_dir = tmp_path / ".vibeguard" / "patches"
        patch_files = list(patches_dir.glob("*.patch"))
        assert len(patch_files) == 1

        # Check metadata file exists
        meta_files = list(patches_dir.glob("*.json"))
        assert len(meta_files) == 1

    def test_saves_to_custom_output(
        self, tmp_path: Path, sample_scan_result: ScanResult, sample_finding: Finding, mock_pro_license
    ) -> None:
        """Should save to custom output path."""
        keyring.save_key("openai", "test-key")

        mock_response = LLMResponse(
            content=f"```diff\n{SAMPLE_DIFF}\n```",
            model="gpt-4",
            provider="openai",
        )

        custom_output = tmp_path / "my-patch.patch"

        with (
            patch("vibeguard.cli.patch.load_latest_scan", return_value=sample_scan_result),
            patch("vibeguard.cli.patch.generate", new_callable=AsyncMock) as mock_gen,
            patch("vibeguard.cli.patch._prompt_apply_patch", return_value="skip"),
        ):
            mock_gen.return_value = mock_response

            result = runner.invoke(
                app,
                [
                    "patch",
                    sample_finding.id,
                    "--path",
                    str(tmp_path),
                    "--output",
                    str(custom_output),
                ],
            )

        assert result.exit_code == 0
        assert custom_output.exists()

    def test_dry_run_does_not_save(
        self, tmp_path: Path, sample_scan_result: ScanResult, sample_finding: Finding, mock_pro_license
    ) -> None:
        """Should not save files in dry-run mode."""
        keyring.save_key("openai", "test-key")

        mock_response = LLMResponse(
            content=f"```diff\n{SAMPLE_DIFF}\n```",
            model="gpt-4",
            provider="openai",
        )

        with (
            patch("vibeguard.cli.patch.load_latest_scan", return_value=sample_scan_result),
            patch("vibeguard.cli.patch.generate", new_callable=AsyncMock) as mock_gen,
        ):
            mock_gen.return_value = mock_response

            result = runner.invoke(
                app,
                ["patch", sample_finding.id, "--path", str(tmp_path), "--dry-run"],
            )

        assert result.exit_code == 0
        assert "dry run" in result.output.lower()

        # No files should be saved
        patches_dir = tmp_path / ".vibeguard" / "patches"
        if patches_dir.exists():
            assert list(patches_dir.glob("*")) == []

    def test_handles_invalid_diff_response(
        self, tmp_path: Path, sample_scan_result: ScanResult, sample_finding: Finding, mock_pro_license
    ) -> None:
        """Should error if LLM returns invalid diff."""
        keyring.save_key("openai", "test-key")

        mock_response = LLMResponse(
            content="Here's a fix: just remove the exec() call.",
            model="gpt-4",
            provider="openai",
        )

        with (
            patch("vibeguard.cli.patch.load_latest_scan", return_value=sample_scan_result),
            patch("vibeguard.cli.patch.generate", new_callable=AsyncMock) as mock_gen,
        ):
            mock_gen.return_value = mock_response

            result = runner.invoke(
                app, ["patch", sample_finding.id, "--path", str(tmp_path)]
            )

        assert result.exit_code != 0
        assert "could not extract diff" in result.output.lower()

    def test_uses_specified_provider(
        self, tmp_path: Path, sample_scan_result: ScanResult, sample_finding: Finding, mock_pro_license
    ) -> None:
        """Should use specified provider."""
        keyring.save_key("anthropic", "ant-key")

        mock_response = LLMResponse(
            content=f"```diff\n{SAMPLE_DIFF}\n```",
            model="claude-3-opus",
            provider="anthropic",
        )

        with (
            patch("vibeguard.cli.patch.load_latest_scan", return_value=sample_scan_result),
            patch("vibeguard.cli.patch.generate", new_callable=AsyncMock) as mock_gen,
        ):
            mock_gen.return_value = mock_response

            result = runner.invoke(
                app,
                [
                    "patch",
                    sample_finding.id,
                    "--path",
                    str(tmp_path),
                    "--provider",
                    "anthropic",
                    "--dry-run",
                ],
            )

        assert result.exit_code == 0
        mock_gen.assert_called_once()
        call_kwargs = mock_gen.call_args.kwargs
        assert call_kwargs["provider"] == "anthropic"

    def test_shows_manual_review_warning(
        self, tmp_path: Path, sample_scan_result: ScanResult, sample_finding: Finding, mock_pro_license
    ) -> None:
        """Should warn if patch contains MANUAL_REVIEW_REQUIRED."""
        keyring.save_key("openai", "test-key")

        diff_with_review = """\
--- a/app/utils.py
+++ b/app/utils.py
@@ -40,5 +40,5 @@ def process_input(user_input):
     # Process the input
-    exec(user_input)
+    result = safe_eval(user_input)  # MANUAL_REVIEW_REQUIRED
     return True
"""

        mock_response = LLMResponse(
            content=f"```diff\n{diff_with_review}\n```",
            model="gpt-4",
            provider="openai",
        )

        with (
            patch("vibeguard.cli.patch.load_latest_scan", return_value=sample_scan_result),
            patch("vibeguard.cli.patch.generate", new_callable=AsyncMock) as mock_gen,
        ):
            mock_gen.return_value = mock_response

            result = runner.invoke(
                app,
                ["patch", sample_finding.id, "--path", str(tmp_path), "--dry-run"],
            )

        assert result.exit_code == 0
        assert "MANUAL_REVIEW_REQUIRED" in result.output
