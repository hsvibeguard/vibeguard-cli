"""Tests for repository ecosystem detection."""

from pathlib import Path

from vibeguard.core.repo_detector import (
    ECOSYSTEM_SCANNERS,
    Ecosystem,
    detect_ecosystems,
    get_detection_summary,
    get_ecosystem_scanners,
)


class TestDetectEcosystems:
    """Tests for detect_ecosystems function."""

    def test_detect_javascript_package_json(self, tmp_path: Path) -> None:
        """Test detection of JavaScript via package.json."""
        (tmp_path / "package.json").write_text('{"name": "test"}')

        detections = detect_ecosystems(tmp_path)

        assert len(detections) == 1
        assert detections[0].ecosystem == Ecosystem.JAVASCRIPT
        assert detections[0].scanner_name == "npm_audit"
        assert detections[0].detection_file == "package.json"

    def test_detect_javascript_package_lock(self, tmp_path: Path) -> None:
        """Test detection of JavaScript via package-lock.json."""
        (tmp_path / "package-lock.json").write_text("{}")

        detections = detect_ecosystems(tmp_path)

        assert len(detections) == 1
        assert detections[0].ecosystem == Ecosystem.JAVASCRIPT
        assert detections[0].detection_file == "package-lock.json"

    def test_detect_javascript_yarn_lock(self, tmp_path: Path) -> None:
        """Test detection of JavaScript via yarn.lock."""
        (tmp_path / "yarn.lock").write_text("")

        detections = detect_ecosystems(tmp_path)

        assert len(detections) == 1
        assert detections[0].ecosystem == Ecosystem.JAVASCRIPT

    def test_detect_python_requirements(self, tmp_path: Path) -> None:
        """Test detection of Python via requirements.txt."""
        (tmp_path / "requirements.txt").write_text("flask==2.0.0")

        detections = detect_ecosystems(tmp_path)

        assert len(detections) == 1
        assert detections[0].ecosystem == Ecosystem.PYTHON
        assert detections[0].scanner_name == "pip_audit"

    def test_detect_python_pyproject(self, tmp_path: Path) -> None:
        """Test detection of Python via pyproject.toml."""
        (tmp_path / "pyproject.toml").write_text('[project]\nname = "test"')

        detections = detect_ecosystems(tmp_path)

        assert len(detections) == 1
        assert detections[0].ecosystem == Ecosystem.PYTHON

    def test_detect_python_pipfile(self, tmp_path: Path) -> None:
        """Test detection of Python via Pipfile."""
        (tmp_path / "Pipfile").write_text("[packages]")

        detections = detect_ecosystems(tmp_path)

        assert len(detections) == 1
        assert detections[0].ecosystem == Ecosystem.PYTHON

    def test_detect_rust_cargo_toml(self, tmp_path: Path) -> None:
        """Test detection of Rust via Cargo.toml."""
        (tmp_path / "Cargo.toml").write_text('[package]\nname = "test"')

        detections = detect_ecosystems(tmp_path)

        assert len(detections) == 1
        assert detections[0].ecosystem == Ecosystem.RUST
        assert detections[0].scanner_name == "cargo_audit"

    def test_detect_rust_cargo_lock(self, tmp_path: Path) -> None:
        """Test detection of Rust via Cargo.lock."""
        (tmp_path / "Cargo.lock").write_text("")

        detections = detect_ecosystems(tmp_path)

        assert len(detections) == 1
        assert detections[0].ecosystem == Ecosystem.RUST

    def test_detect_multiple_ecosystems(self, tmp_path: Path) -> None:
        """Test detection of multiple ecosystems."""
        (tmp_path / "package.json").write_text("{}")
        (tmp_path / "requirements.txt").write_text("")
        (tmp_path / "Cargo.toml").write_text("")

        detections = detect_ecosystems(tmp_path)

        assert len(detections) == 3
        ecosystems = {d.ecosystem for d in detections}
        assert Ecosystem.JAVASCRIPT in ecosystems
        assert Ecosystem.PYTHON in ecosystems
        assert Ecosystem.RUST in ecosystems

    def test_detect_no_ecosystems(self, tmp_path: Path) -> None:
        """Test empty result for repo without ecosystem files."""
        (tmp_path / "README.md").write_text("# Test")

        detections = detect_ecosystems(tmp_path)

        assert detections == []

    def test_prioritizes_lock_files(self, tmp_path: Path) -> None:
        """Test that lock files are found first due to higher confidence."""
        (tmp_path / "package-lock.json").write_text("{}")
        (tmp_path / "package.json").write_text("{}")

        detections = detect_ecosystems(tmp_path)

        # Should only have one detection (stops after first match)
        assert len(detections) == 1
        assert detections[0].detection_file == "package-lock.json"
        assert detections[0].confidence == 1.0


class TestGetEcosystemScanners:
    """Tests for get_ecosystem_scanners function."""

    def test_returns_scanner_names(self, tmp_path: Path) -> None:
        """Test that function returns scanner names."""
        (tmp_path / "package.json").write_text("{}")
        (tmp_path / "requirements.txt").write_text("")

        scanners = get_ecosystem_scanners(tmp_path)

        assert "npm_audit" in scanners
        assert "pip_audit" in scanners

    def test_returns_empty_list_no_detection(self, tmp_path: Path) -> None:
        """Test empty list when no ecosystems detected."""
        scanners = get_ecosystem_scanners(tmp_path)
        assert scanners == []


class TestGetDetectionSummary:
    """Tests for get_detection_summary function."""

    def test_returns_summary_dict(self, tmp_path: Path) -> None:
        """Test that function returns summary dict."""
        (tmp_path / "package.json").write_text("{}")

        summary = get_detection_summary(tmp_path)

        assert "Javascript" in summary
        assert summary["Javascript"] == "package.json"

    def test_returns_empty_dict_no_detection(self, tmp_path: Path) -> None:
        """Test empty dict when no ecosystems detected."""
        summary = get_detection_summary(tmp_path)
        assert summary == {}

    def test_multiple_ecosystems_summary(self, tmp_path: Path) -> None:
        """Test summary with multiple ecosystems."""
        (tmp_path / "requirements.txt").write_text("")
        (tmp_path / "Cargo.lock").write_text("")

        summary = get_detection_summary(tmp_path)

        assert len(summary) == 2
        assert "Python" in summary
        assert "Rust" in summary


class TestEcosystemMapping:
    """Tests for ecosystem to scanner mapping."""

    def test_all_ecosystems_have_scanners(self) -> None:
        """Test that all ecosystems map to scanners."""
        for ecosystem in Ecosystem:
            assert ecosystem in ECOSYSTEM_SCANNERS
            assert ECOSYSTEM_SCANNERS[ecosystem] is not None

    def test_scanner_names_are_valid(self) -> None:
        """Test that scanner names follow expected format."""
        for scanner_name in ECOSYSTEM_SCANNERS.values():
            assert "_" in scanner_name or scanner_name.isalpha()
            assert scanner_name.islower() or "_" in scanner_name
