"""Base runner interface for scanner execution."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RunResult:
    """Result from running a scanner."""

    success: bool
    stdout: str
    stderr: str
    exit_code: int
    error_message: str | None = None


class BaseRunner(ABC):
    """Abstract base class for scanner runners."""

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this runner can execute."""
        pass

    @abstractmethod
    async def run(
        self,
        command: str,
        target: Path,
        timeout: int = 300,
    ) -> RunResult:
        """Execute a scanner command."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Runner identifier."""
        pass
