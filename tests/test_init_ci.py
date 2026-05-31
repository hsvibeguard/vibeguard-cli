"""Tests for vibeguard init --ci flag."""

from pathlib import Path

import yaml
from typer.testing import CliRunner

from vibeguard.cli.main import app

runner = CliRunner()


def test_ci_flag_creates_workflow(tmp_path: Path) -> None:
    """--ci should create .github/workflows/vibeguard.yml."""
    result = runner.invoke(app, ["init", str(tmp_path), "--ci"])
    assert result.exit_code == 0

    workflow = tmp_path / ".github" / "workflows" / "vibeguard.yml"
    assert workflow.exists()
    assert "VibeGuard Security Scan" in workflow.read_text()


def test_ci_flag_skips_existing_workflow(tmp_path: Path) -> None:
    """Existing workflow should not be overwritten without --force."""
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    workflow = workflow_dir / "vibeguard.yml"
    workflow.write_text("# custom workflow")

    result = runner.invoke(app, ["init", str(tmp_path), "--ci"])
    assert result.exit_code == 0

    # Content should be unchanged
    assert workflow.read_text() == "# custom workflow"
    assert "already exists" in result.output


def test_ci_flag_force_overwrites_workflow(tmp_path: Path) -> None:
    """--force should overwrite existing workflow."""
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    workflow = workflow_dir / "vibeguard.yml"
    workflow.write_text("# custom workflow")

    result = runner.invoke(app, ["init", str(tmp_path), "--ci", "--force"])
    assert result.exit_code == 0

    # Content should now be the template
    assert "VibeGuard Security Scan" in workflow.read_text()


def test_workflow_yaml_is_valid(tmp_path: Path) -> None:
    """Generated workflow YAML should be parseable."""
    runner.invoke(app, ["init", str(tmp_path), "--ci"])

    workflow = tmp_path / ".github" / "workflows" / "vibeguard.yml"
    content = yaml.safe_load(workflow.read_text())

    assert content["name"] == "VibeGuard Security Scan"
    assert "security-scan" in content["jobs"]
    assert content["permissions"]["security-events"] == "write"


def test_init_without_ci_skips_workflow(tmp_path: Path) -> None:
    """Without --ci, no workflow should be created."""
    result = runner.invoke(app, ["init", str(tmp_path)])
    assert result.exit_code == 0

    workflow = tmp_path / ".github" / "workflows" / "vibeguard.yml"
    assert not workflow.exists()
