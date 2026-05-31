"""Finding model for normalized security findings."""

import hashlib
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, computed_field

from vibeguard.models.triage import PathClass, TriageReason, TriageStatus


class Severity(str, Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    """Categories for findings."""

    SECURITY = "security"
    SECRETS = "secrets"
    VULNERABILITY = "vulnerability"
    BEST_PRACTICE = "best-practice"
    MISCONFIGURATION = "misconfiguration"


class Finding(BaseModel):
    """Normalized security finding from any scanner."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="ignore",  # Allow computed fields during deserialization
    )

    scanner: str = Field(..., description="Name of the scanner that found this issue")
    rule_id: str = Field(..., description="Original rule ID from scanner")
    severity: Severity = Field(..., description="Severity level")
    category: Category = Field(default=Category.SECURITY)
    title: str = Field(..., description="Short title of the finding")
    message: str = Field(..., description="Detailed description")
    file_path: str = Field(..., description="Path to affected file")
    line_start: int = Field(..., ge=1, description="Starting line number")
    line_end: int | None = Field(None, ge=1, description="Ending line number")
    cwe: str | None = Field(None, description="CWE identifier if available")
    references: list[str] = Field(default_factory=list, description="Reference URLs")
    code_snippet: str | None = Field(None, description="Affected code snippet")
    fingerprint: str | None = Field(None, description="Scanner-provided fingerprint")

    # Triage fields (optional for backward compatibility)
    triage_status: TriageStatus = Field(
        default=TriageStatus.ACTIONABLE,
        description="Triage classification after analysis",
    )
    triage_reason: TriageReason = Field(
        default=TriageReason.NONE,
        description="Reason for triage classification",
    )
    path_class: PathClass = Field(
        default=PathClass.SOURCE,
        description="Classification of the file path",
    )
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Confidence score (0.0-1.0)",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def id(self) -> str:
        """Generate stable hash ID for deduplication."""
        content = f"{self.scanner}:{self.rule_id}:{self.file_path}:{self.line_start}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
