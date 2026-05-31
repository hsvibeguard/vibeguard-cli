"""Tests for apply CLI command."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from vibeguard.cli.main import app
from vibeguard.core import auth as auth_module
from vibeguard.core import keyring

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

SAMPLE_METADATA = """\
{
    "finding_id": "abc123def456",
    "file_path": "app/utils.py",
    "unified_diff": "--- a/app/utils.py\\n+++ b/app/utils.py\\n@@ -40,5 +40,5 @@",
    "provider": "openai",
    "model": "gpt-4",
    "generated_at": "2026-01-31T10:00:00",
    "manual_review_required": false
}
"""


@pytest.fixture(autouse=True)
def mock_keys_storage(tmp_path):  # type: ignore[no-untyped-def]
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
    from datetime import UTC, datetime, timedelta

    from vibeguard.models.auth import AuthToken

    mock_token = AuthToken(
        token="test-token",
        expires_at=datetime.now(UTC) + timedelta(days=7),
        entitlements=["pro.patch", "pro.apply"],
        plan="pro",
    )

    with patch.object(auth_module, "get_cached_token", return_value=mock_token):
        yield mock_token


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """Create a temporary git repository."""
    repo_path = tmp_path / "test_repo"
    repo_path.mkdir()

    # Initialize git repo
    subprocess.run(["git", "init"], cwd=repo_path, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repo_path,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=repo_path,
        capture_output=True,
    )

    # Create a file to patch
    app_dir = repo_path / "app"
    app_dir.mkdir()
    utils_file = app_dir / "utils.py"
    utils_file.write_text(
        """\
def process_input(user_input):
    # Process the input
    exec(user_input)
    return True
""",
        encoding="utf-8",
    )

    # Commit the file
    subprocess.run(["git", "add", "."], cwd=repo_path, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "Initial commit"],
        cwd=repo_path,
        capture_output=True,
    )

    return repo_path


@pytest.fixture
def patch_file(tmp_path: Path) -> Path:
    """Create a sample patch file."""
    patch_path = tmp_path / "fix.patch"
    patch_path.write_text(SAMPLE_DIFF, encoding="utf-8")
    return patch_path


@pytest.fixture
def patch_file_with_metadata(tmp_path: Path) -> Path:
    """Create a patch file with metadata JSON."""
    patch_path = tmp_path / "fix.patch"
    patch_path.write_text(SAMPLE_DIFF, encoding="utf-8")

    meta_path = tmp_path / "fix.json"
    meta_path.write_text(SAMPLE_METADATA, encoding="utf-8")

    return patch_path


class TestApplyCommand:
    """Tests for 'vibeguard apply' CLI command."""

    def test_requires_pro_license(self, tmp_path: Path, patch_file: Path) -> None:
        """Should error if no LLM key configured (not Pro)."""
        # Mock git repo check
        with patch("vibeguard.cli.apply._is_git_repo", return_value=True):
            result = runner.invoke(
                app, ["apply", str(patch_file), "--path", str(tmp_path)]
            )

        assert result.exit_code != 0
        assert "requires a Pro license" in result.output or "Pro" in result.output

    def test_shows_error_for_missing_patch_file(self, tmp_path: Path) -> None:
        """Should error when patch file is missing."""
        keyring.save_key("openai", "test-key")

        result = runner.invoke(app, ["apply", "--path", str(tmp_path)])

        assert result.exit_code != 0
        assert "missing patch file" in result.output.lower() or "usage" in result.output.lower()

    def test_shows_available_patches_in_help(self, tmp_path: Path) -> None:
        """Should show available patches when patch file is missing."""
        keyring.save_key("openai", "test-key")

        # Create patches directory with a patch
        patches_dir = tmp_path / ".vibeguard" / "patches"
        patches_dir.mkdir(parents=True)
        (patches_dir / "abc123.patch").write_text(SAMPLE_DIFF, encoding="utf-8")

        result = runner.invoke(app, ["apply", "--path", str(tmp_path)])

        assert result.exit_code != 0
        assert "abc123.patch" in result.output

    def test_validates_patch_format(self, tmp_path: Path, mock_pro_license) -> None:
        """Should error if patch file has invalid format."""
        # Create invalid patch file
        invalid_patch = tmp_path / "invalid.patch"
        invalid_patch.write_text("This is not a valid diff", encoding="utf-8")

        with patch("vibeguard.cli.apply._is_git_repo", return_value=True):
            result = runner.invoke(
                app, ["apply", str(invalid_patch), "--path", str(tmp_path)]
            )

        assert result.exit_code != 0
        assert "invalid patch file" in result.output.lower()

    def test_requires_git_repo(self, tmp_path: Path, patch_file: Path, mock_pro_license) -> None:
        """Should error if target is not a git repository."""

        # tmp_path is not a git repo
        result = runner.invoke(
            app, ["apply", str(patch_file), "--path", str(tmp_path)]
        )

        assert result.exit_code != 0
        assert "not a git repository" in result.output.lower()

    def test_warns_about_uncommitted_changes(
        self, git_repo: Path, patch_file: Path, mock_pro_license
    ) -> None:
        """Should warn if working directory has uncommitted changes."""

        # Create uncommitted change
        (git_repo / "new_file.py").write_text("# new file", encoding="utf-8")

        result = runner.invoke(
            app, ["apply", str(patch_file), "--path", str(git_repo)]
        )

        assert result.exit_code != 0
        assert "uncommitted changes" in result.output.lower()

    def test_force_flag_ignores_uncommitted_changes(
        self, git_repo: Path, tmp_path: Path, mock_pro_license
    ) -> None:
        """Should proceed with --force despite uncommitted changes."""

        # Create a patch that will apply cleanly
        simple_patch = tmp_path / "simple.patch"
        simple_patch.write_text(
            """\
--- a/test.txt
+++ b/test.txt
@@ -0,0 +1 @@
+new line
""",
            encoding="utf-8",
        )

        # Create uncommitted change
        (git_repo / "new_file.py").write_text("# new file", encoding="utf-8")

        # Mock git apply commands
        with (
            patch("vibeguard.cli.apply._git_apply_check") as mock_check,
            patch("vibeguard.cli.apply._git_apply") as mock_apply,
        ):
            mock_check.return_value = (True, "")
            mock_apply.return_value = (True, "")

            runner.invoke(
                app,
                ["apply", str(simple_patch), "--path", str(git_repo), "--force"],
            )

        # Should proceed with apply
        mock_apply.assert_called_once()

    def test_dry_run_does_not_apply(
        self, git_repo: Path, patch_file: Path, mock_pro_license
    ) -> None:
        """Should not apply patch in dry-run mode."""

        with (
            patch("vibeguard.cli.apply._git_apply_check") as mock_check,
            patch("vibeguard.cli.apply._git_apply") as mock_apply,
        ):
            mock_check.return_value = (True, "")

            result = runner.invoke(
                app,
                ["apply", str(patch_file), "--path", str(git_repo), "--dry-run"],
            )

        assert result.exit_code == 0
        assert "dry run" in result.output.lower()
        mock_apply.assert_not_called()

    def test_checks_patch_applies_cleanly(
        self, git_repo: Path, patch_file: Path, mock_pro_license
    ) -> None:
        """Should run git apply --check before applying."""

        with patch("vibeguard.cli.apply._git_apply_check") as mock_check:
            mock_check.return_value = (False, "error: patch does not apply")

            result = runner.invoke(
                app, ["apply", str(patch_file), "--path", str(git_repo)]
            )

        assert result.exit_code != 0
        assert "cannot be applied" in result.output.lower() or "patch does not apply" in result.output.lower()

    def test_applies_patch_successfully(
        self, git_repo: Path, patch_file: Path, mock_pro_license
    ) -> None:
        """Should apply patch when all checks pass."""

        with (
            patch("vibeguard.cli.apply._git_apply_check") as mock_check,
            patch("vibeguard.cli.apply._git_apply") as mock_apply,
            patch("vibeguard.cli.apply._get_git_head") as mock_head,
        ):
            mock_check.return_value = (True, "")
            mock_apply.return_value = (True, "")
            mock_head.return_value = "abc123def"

            result = runner.invoke(
                app, ["apply", str(patch_file), "--path", str(git_repo)]
            )

        assert result.exit_code == 0
        assert "successfully" in result.output.lower()
        mock_apply.assert_called_once()

    def test_shows_modified_files(
        self, git_repo: Path, patch_file: Path, mock_pro_license
    ) -> None:
        """Should show files modified by the patch."""

        with (
            patch("vibeguard.cli.apply._git_apply_check") as mock_check,
            patch("vibeguard.cli.apply._git_apply") as mock_apply,
        ):
            mock_check.return_value = (True, "")
            mock_apply.return_value = (True, "")

            result = runner.invoke(
                app, ["apply", str(patch_file), "--path", str(git_repo)]
            )

        assert result.exit_code == 0
        assert "app/utils.py" in result.output

    def test_reverse_flag_reverses_patch(
        self, git_repo: Path, patch_file: Path, mock_pro_license
    ) -> None:
        """Should pass --reverse flag to git apply."""

        with (
            patch("vibeguard.cli.apply._git_apply_check") as mock_check,
            patch("vibeguard.cli.apply._git_apply") as mock_apply,
        ):
            mock_check.return_value = (True, "")
            mock_apply.return_value = (True, "")

            result = runner.invoke(
                app,
                ["apply", str(patch_file), "--path", str(git_repo), "--reverse"],
            )

        assert result.exit_code == 0
        assert "reversed" in result.output.lower()
        # Check that reverse=True was passed
        mock_apply.assert_called_once()
        call_args = mock_apply.call_args
        assert call_args[1].get("reverse") is True or call_args[0][2] is True

    def test_shows_patch_info_with_metadata(
        self, git_repo: Path, patch_file_with_metadata: Path, mock_pro_license
    ) -> None:
        """Should display metadata when available."""

        with (
            patch("vibeguard.cli.apply._git_apply_check") as mock_check,
            patch("vibeguard.cli.apply._git_apply") as mock_apply,
        ):
            mock_check.return_value = (True, "")
            mock_apply.return_value = (True, "")

            result = runner.invoke(
                app,
                ["apply", str(patch_file_with_metadata), "--path", str(git_repo)],
            )

        assert result.exit_code == 0
        # Should show provider/model info
        assert "openai" in result.output or "gpt-4" in result.output

    def test_handles_git_apply_failure(
        self, git_repo: Path, patch_file: Path, mock_pro_license
    ) -> None:
        """Should handle git apply failure gracefully."""

        with (
            patch("vibeguard.cli.apply._git_apply_check") as mock_check,
            patch("vibeguard.cli.apply._git_apply") as mock_apply,
        ):
            mock_check.return_value = (True, "")
            mock_apply.return_value = (False, "error: patch failed")

            result = runner.invoke(
                app, ["apply", str(patch_file), "--path", str(git_repo)]
            )

        assert result.exit_code != 0
        assert "failed" in result.output.lower() or "error" in result.output.lower()

    def test_shows_next_steps_after_success(
        self, git_repo: Path, patch_file: Path, mock_pro_license
    ) -> None:
        """Should show helpful next steps after successful apply."""

        with (
            patch("vibeguard.cli.apply._git_apply_check") as mock_check,
            patch("vibeguard.cli.apply._git_apply") as mock_apply,
        ):
            mock_check.return_value = (True, "")
            mock_apply.return_value = (True, "")

            result = runner.invoke(
                app, ["apply", str(patch_file), "--path", str(git_repo)]
            )

        assert result.exit_code == 0
        assert "git diff" in result.output or "review" in result.output.lower()
        assert "commit" in result.output.lower()


class TestApplyHelperFunctions:
    """Tests for apply command helper functions."""

    def test_is_git_repo_returns_true_for_repo(self, git_repo: Path) -> None:
        """Should return True for valid git repo."""
        from vibeguard.cli.apply import _is_git_repo

        assert _is_git_repo(git_repo) is True

    def test_is_git_repo_returns_false_for_non_repo(self, tmp_path: Path) -> None:
        """Should return False for non-git directory."""
        from vibeguard.cli.apply import _is_git_repo

        assert _is_git_repo(tmp_path) is False

    def test_get_modified_files_extracts_paths(self) -> None:
        """Should extract file paths from patch content."""
        from vibeguard.cli.apply import _get_modified_files_from_patch

        files = _get_modified_files_from_patch(SAMPLE_DIFF)
        assert "app/utils.py" in files

    def test_get_modified_files_handles_b_prefix(self) -> None:
        """Should strip b/ prefix from file paths."""
        from vibeguard.cli.apply import _get_modified_files_from_patch

        diff = """\
--- a/src/file.py
+++ b/src/file.py
@@ -1 +1 @@
-old
+new
"""
        files = _get_modified_files_from_patch(diff)
        assert files == ["src/file.py"]

    def test_get_modified_files_handles_multiple_files(self) -> None:
        """Should extract all modified files."""
        from vibeguard.cli.apply import _get_modified_files_from_patch

        diff = """\
--- a/file1.py
+++ b/file1.py
@@ -1 +1 @@
-old
+new
--- a/file2.py
+++ b/file2.py
@@ -1 +1 @@
-old
+new
"""
        files = _get_modified_files_from_patch(diff)
        assert "file1.py" in files
        assert "file2.py" in files
