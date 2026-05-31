"""Local runner for executing scanners via local binaries."""

import asyncio
import os
import shutil
import sys
from pathlib import Path

from vibeguard.core.downloader import VIBEGUARD_BIN_DIR
from vibeguard.scanners.runners.base import BaseRunner, RunResult


def _get_venv_bin_dir() -> Path | None:
    """Get the bin/Scripts directory of the current Python environment.

    This handles pipx installs where pip-installed tools end up in the
    isolated venv's bin directory, not on the system PATH.
    """
    prefix = Path(sys.prefix)
    if sys.platform == "win32":
        bin_dir = prefix / "Scripts"
    else:
        bin_dir = prefix / "bin"
    if bin_dir.is_dir():
        return bin_dir
    return None


class LocalRunner(BaseRunner):
    """Run scanners using locally installed binaries."""

    def __init__(
        self,
        binary_name: str,
        check_command: str | None = None,
        version: str | None = None,
    ):
        self.binary_name = binary_name
        self.check_command = check_command or f"{binary_name} --version"
        self.version = version
        self._binary_path: str | None = None

    @property
    def name(self) -> str:
        return "local"

    def is_available(self) -> bool:
        """Check if binary is available in PATH, venv bin, or downloaded cache."""
        # First check system PATH
        self._binary_path = shutil.which(self.binary_name)
        if self._binary_path:
            return True

        # Check current Python environment's bin directory (handles pipx installs)
        venv_bin = _get_venv_bin_dir()
        if venv_bin:
            for ext in ("", ".exe"):
                candidate = venv_bin / f"{self.binary_name}{ext}"
                if candidate.is_file():
                    self._binary_path = str(candidate)
                    return True

        # Check downloaded binaries in ~/.vibeguard/bin/
        if self.version:
            downloaded = self._find_downloaded_binary()
            if downloaded:
                self._binary_path = str(downloaded)
                return True

        return False

    def _find_downloaded_binary(self) -> Path | None:
        """Find binary in downloaded cache."""
        if not self.version:
            return None

        version_dir = VIBEGUARD_BIN_DIR / f"{self.binary_name}-{self.version}"
        if not version_dir.exists():
            return None

        # Check for binary with common extensions
        for ext in ("", ".exe"):
            binary = version_dir / f"{self.binary_name}{ext}"
            if binary.exists() and binary.is_file():
                return binary

        # Search in subdirectories (some archives have nested structure)
        for path in version_dir.rglob("*"):
            if path.is_file() and path.stem == self.binary_name:
                return path

        return None

    def get_binary_path(self) -> str:
        """Get the resolved binary path.

        Returns the full path to the binary if found in cache,
        otherwise returns just the binary name (for PATH lookup).

        Returns:
            Binary path as a string
        """
        # Ensure is_available has been called to populate _binary_path
        if self._binary_path is None:
            self.is_available()

        return self._binary_path if self._binary_path else self.binary_name

    async def run(
        self,
        command: str,
        target: Path,
        timeout: int = 300,
    ) -> RunResult:
        """Execute command locally."""
        # Replace {target} placeholder
        full_command = command.replace("{target}", str(target))

        # Use absolute binary path if running from downloaded cache
        if self._binary_path and not shutil.which(self.binary_name):
            # Replace the binary name at the start of the command with full path
            full_command = full_command.replace(
                self.binary_name, f'"{self._binary_path}"', 1
            )

        try:
            # Build environment with UTF-8 encoding on Windows
            # This fixes encoding issues with tools like semgrep
            env = os.environ.copy()
            if sys.platform == "win32":
                env["PYTHONUTF8"] = "1"
                env["PYTHONIOENCODING"] = "utf-8"

            process = await asyncio.create_subprocess_shell(
                full_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(target),
                env=env,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )

            return RunResult(
                success=process.returncode == 0,
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
                exit_code=process.returncode or 0,
            )

        except TimeoutError:
            return RunResult(
                success=False,
                stdout="",
                stderr="",
                exit_code=-1,
                error_message=f"Command timed out after {timeout}s",
            )
        except Exception as e:
            return RunResult(
                success=False,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                error_message=str(e),
            )
