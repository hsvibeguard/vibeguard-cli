"""Docker runner for executing scanners in containers."""

import asyncio
import shutil
from pathlib import Path

from vibeguard.scanners.runners.base import BaseRunner, RunResult


class DockerRunner(BaseRunner):
    """Run scanners in Docker containers."""

    def __init__(
        self,
        image: str,
        mount_mode: str = "ro",
        workdir: str = "/src",
    ):
        self.image = image
        self.mount_mode = mount_mode
        self.workdir = workdir

    @property
    def name(self) -> str:
        return "docker"

    def is_available(self) -> bool:
        """Check if Docker is available."""
        return shutil.which("docker") is not None

    async def run(
        self,
        command: str,
        target: Path,
        timeout: int = 300,
    ) -> RunResult:
        """Execute command in Docker container."""
        abs_target = target.resolve()

        docker_cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{abs_target}:{self.workdir}:{self.mount_mode}",
            "-w",
            self.workdir,
            self.image,
            *command.split(),
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
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
                error_message=f"Docker command timed out after {timeout}s",
            )
        except Exception as e:
            return RunResult(
                success=False,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                error_message=str(e),
            )
