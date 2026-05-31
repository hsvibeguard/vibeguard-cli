"""Repository ecosystem detection for auto-enabling scanners."""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Ecosystem(str, Enum):
    """Detected ecosystems in repository."""

    JAVASCRIPT = "javascript"
    PYTHON = "python"
    RUST = "rust"
    GO = "go"
    IAC = "iac"  # Infrastructure as Code (Terraform, K8s, CloudFormation, etc.)


@dataclass
class EcosystemDetection:
    """Result of ecosystem detection."""

    ecosystem: Ecosystem
    scanner_name: str
    detection_file: str
    confidence: float  # 0.0-1.0 (1.0 = definite match)


# Mapping of ecosystems to their scanner names
ECOSYSTEM_SCANNERS: dict[Ecosystem, str] = {
    Ecosystem.JAVASCRIPT: "npm_audit",
    Ecosystem.PYTHON: "pip_audit",
    Ecosystem.RUST: "cargo_audit",
    Ecosystem.GO: "gosec",
    Ecosystem.IAC: "checkov",
}

# Detection files for each ecosystem (ordered by confidence)
DETECTION_FILES: dict[Ecosystem, list[tuple[str, float]]] = {
    Ecosystem.JAVASCRIPT: [
        ("package-lock.json", 1.0),  # Definite Node.js project
        ("yarn.lock", 1.0),  # Definite Yarn project
        ("pnpm-lock.yaml", 1.0),  # Definite pnpm project
        ("package.json", 0.9),  # Likely Node.js (could be frontend-only)
    ],
    Ecosystem.PYTHON: [
        ("requirements.txt", 1.0),  # Classic Python deps
        ("pyproject.toml", 1.0),  # Modern Python project
        ("Pipfile", 1.0),  # Pipenv project
        ("Pipfile.lock", 1.0),  # Pipenv with lock
        ("setup.py", 0.9),  # Legacy but still valid
        ("setup.cfg", 0.8),  # Older setuptools config
        ("poetry.lock", 1.0),  # Poetry project
    ],
    Ecosystem.RUST: [
        ("Cargo.lock", 1.0),  # Definite Rust project with deps
        ("Cargo.toml", 0.9),  # Rust project (might have no deps)
    ],
    Ecosystem.GO: [
        ("go.sum", 1.0),  # Definite Go module with deps
        ("go.mod", 0.9),  # Go module (might have no deps)
    ],
    Ecosystem.IAC: [
        ("main.tf", 1.0),  # Terraform main file
        ("terraform.tf", 1.0),  # Terraform config
        ("variables.tf", 1.0),  # Terraform variables
        ("Dockerfile", 0.9),  # Docker container definition
        ("docker-compose.yml", 0.9),  # Docker Compose
        ("docker-compose.yaml", 0.9),  # Docker Compose (yaml extension)
        ("kustomization.yaml", 1.0),  # Kubernetes Kustomize
        ("kustomization.yml", 1.0),  # Kubernetes Kustomize
        ("Chart.yaml", 1.0),  # Helm chart
        ("serverless.yml", 1.0),  # Serverless Framework
        ("serverless.yaml", 1.0),  # Serverless Framework
        ("template.yaml", 0.8),  # CloudFormation/SAM template
        ("template.yml", 0.8),  # CloudFormation/SAM template
        ("cloudformation.yaml", 1.0),  # CloudFormation
        ("cloudformation.yml", 1.0),  # CloudFormation
        ("cloudformation.json", 1.0),  # CloudFormation JSON
        ("bicep.config.json", 1.0),  # Azure Bicep
    ],
}


def detect_ecosystems(target: Path) -> list[EcosystemDetection]:
    """Detect ecosystems present in a repository.

    Scans for indicator files and returns list of detected ecosystems
    with their associated scanners.

    Args:
        target: Path to the repository root

    Returns:
        List of EcosystemDetection objects for detected ecosystems
    """
    detections: list[EcosystemDetection] = []

    for ecosystem, files in DETECTION_FILES.items():
        for filename, confidence in files:
            file_path = target / filename
            if file_path.exists() and file_path.is_file():
                detections.append(
                    EcosystemDetection(
                        ecosystem=ecosystem,
                        scanner_name=ECOSYSTEM_SCANNERS[ecosystem],
                        detection_file=filename,
                        confidence=confidence,
                    )
                )
                # Found one file for this ecosystem, don't check others
                break

    return detections


def get_ecosystem_scanners(target: Path) -> list[str]:
    """Get list of ecosystem scanner names to run.

    Convenience function that returns just the scanner names
    for detected ecosystems.

    Args:
        target: Path to the repository root

    Returns:
        List of scanner names (e.g., ["npm_audit", "pip_audit"])
    """
    detections = detect_ecosystems(target)
    return [d.scanner_name for d in detections]


def get_detection_summary(target: Path) -> dict[str, str]:
    """Get a summary of detected ecosystems for display.

    Returns a dict mapping ecosystem names to their detection files.

    Args:
        target: Path to the repository root

    Returns:
        Dict like {"JavaScript": "package.json", "Python": "pyproject.toml"}
    """
    detections = detect_ecosystems(target)
    summary: dict[str, str] = {}
    for d in detections:
        # Capitalize ecosystem name for display
        display_name = d.ecosystem.value.capitalize()
        summary[display_name] = d.detection_file
    return summary
