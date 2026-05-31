"""Tests for SARIF reporter."""

from datetime import datetime

from vibeguard.models.finding import Finding, Severity
from vibeguard.models.scan_result import ScanResult
from vibeguard.reporters.sarif import (
    SEVERITY_TO_LEVEL,
    SEVERITY_TO_SCORE,
    to_sarif,
)


class TestSarifSchema:
    """Test SARIF schema compliance."""

    def test_sarif_schema_version(self, sample_scan_result: ScanResult) -> None:
        """SARIF should have correct schema version."""
        sarif = to_sarif(sample_scan_result)
        assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
        assert sarif["version"] == "2.1.0"

    def test_sarif_has_single_run(self, sample_scan_result: ScanResult) -> None:
        """SARIF should have exactly one run."""
        sarif = to_sarif(sample_scan_result)
        assert len(sarif["runs"]) == 1

    def test_sarif_tool_info(self, sample_scan_result: ScanResult) -> None:
        """SARIF tool info should be correct."""
        sarif = to_sarif(sample_scan_result)
        tool = sarif["runs"][0]["tool"]["driver"]
        assert tool["name"] == "VibeGuard"
        assert "semanticVersion" in tool
        assert "informationUri" in tool

    def test_sarif_has_invocations(self, sample_scan_result: ScanResult) -> None:
        """SARIF should have invocation info."""
        sarif = to_sarif(sample_scan_result)
        invocations = sarif["runs"][0]["invocations"]
        assert len(invocations) == 1
        assert "executionSuccessful" in invocations[0]
        assert "startTimeUtc" in invocations[0]


class TestSarifRules:
    """Test SARIF rule generation."""

    def test_rules_generated_from_findings(
        self, sample_scan_result: ScanResult
    ) -> None:
        """Rules should be generated from findings."""
        sarif = to_sarif(sample_scan_result)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) > 0

    def test_rule_has_required_fields(self, sample_scan_result: ScanResult) -> None:
        """Each rule should have required SARIF fields."""
        sarif = to_sarif(sample_scan_result)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        for rule in rules:
            assert "id" in rule
            assert "name" in rule
            assert "shortDescription" in rule
            assert "fullDescription" in rule
            assert "defaultConfiguration" in rule
            assert "properties" in rule

    def test_rule_security_severity(self, sample_scan_result: ScanResult) -> None:
        """Rules should have security-severity property."""
        sarif = to_sarif(sample_scan_result)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        for rule in rules:
            assert "security-severity" in rule["properties"]


class TestSarifResults:
    """Test SARIF result generation."""

    def test_results_match_findings_count(
        self, sample_scan_result: ScanResult
    ) -> None:
        """Results count should match findings count."""
        sarif = to_sarif(sample_scan_result)
        results = sarif["runs"][0]["results"]
        assert len(results) == len(sample_scan_result.findings)

    def test_result_has_required_fields(self, sample_scan_result: ScanResult) -> None:
        """Each result should have required SARIF fields."""
        sarif = to_sarif(sample_scan_result)
        results = sarif["runs"][0]["results"]
        for result in results:
            assert "ruleId" in result
            assert "ruleIndex" in result
            assert "level" in result
            assert "message" in result
            assert "locations" in result

    def test_result_has_partial_fingerprints(
        self, sample_scan_result: ScanResult
    ) -> None:
        """Results should have partial fingerprints for dedup."""
        sarif = to_sarif(sample_scan_result)
        results = sarif["runs"][0]["results"]
        for result in results:
            assert "partialFingerprints" in result
            assert "primaryLocationLineHash" in result["partialFingerprints"]

    def test_result_location_has_artifact_location(
        self, sample_scan_result: ScanResult
    ) -> None:
        """Result locations should have artifact location with URI."""
        sarif = to_sarif(sample_scan_result)
        results = sarif["runs"][0]["results"]
        for result in results:
            location = result["locations"][0]["physicalLocation"]
            assert "artifactLocation" in location
            assert "uri" in location["artifactLocation"]
            assert "region" in location
            assert "startLine" in location["region"]


class TestSarifSeverityMapping:
    """Test severity to SARIF level mapping."""

    def test_critical_maps_to_error(self) -> None:
        """Critical severity should map to error level."""
        assert SEVERITY_TO_LEVEL[Severity.CRITICAL] == "error"

    def test_high_maps_to_error(self) -> None:
        """High severity should map to error level."""
        assert SEVERITY_TO_LEVEL[Severity.HIGH] == "error"

    def test_medium_maps_to_warning(self) -> None:
        """Medium severity should map to warning level."""
        assert SEVERITY_TO_LEVEL[Severity.MEDIUM] == "warning"

    def test_low_maps_to_warning(self) -> None:
        """Low severity should map to warning level."""
        assert SEVERITY_TO_LEVEL[Severity.LOW] == "warning"

    def test_info_maps_to_note(self) -> None:
        """Info severity should map to note level."""
        assert SEVERITY_TO_LEVEL[Severity.INFO] == "note"


class TestSarifSecuritySeverity:
    """Test security-severity score mapping."""

    def test_critical_has_high_score(self) -> None:
        """Critical severity should have high security score."""
        assert SEVERITY_TO_SCORE[Severity.CRITICAL] == "9.0"

    def test_info_has_low_score(self) -> None:
        """Info severity should have low security score."""
        assert SEVERITY_TO_SCORE[Severity.INFO] == "1.0"


class TestEmptyScanResult:
    """Test SARIF generation with empty scan result."""

    def test_empty_scan_produces_valid_sarif(self) -> None:
        """Empty scan should still produce valid SARIF."""
        result = ScanResult(
            repo_root="/empty/repo",
            started_at=datetime.now(),
            finished_at=datetime.now(),
            findings=[],
            scanners_run=["semgrep"],
        )
        sarif = to_sarif(result)
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


class TestPartialScan:
    """Test SARIF generation for partial scans."""

    def test_partial_scan_invocation_success(self) -> None:
        """Partial scan should set executionSuccessful to False."""
        result = ScanResult(
            repo_root="/repo",
            started_at=datetime.now(),
            finished_at=datetime.now(),
            findings=[],
            scanners_run=["semgrep"],
            scanners_skipped=["trivy"],
            partial=True,
        )
        sarif = to_sarif(result)
        assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is False


class TestSarifExtensions:
    """Test SARIF scanner extensions."""

    def test_scanners_listed_as_extensions(
        self, sample_scan_result: ScanResult
    ) -> None:
        """Scanners run should be listed as extensions."""
        sarif = to_sarif(sample_scan_result)
        extensions = sarif["runs"][0]["tool"]["extensions"]
        scanner_names = [ext["name"] for ext in extensions]
        for scanner in sample_scan_result.scanners_run:
            assert scanner in scanner_names


class TestMultipleFindingsSameRule:
    """Test SARIF handling of multiple findings with same rule."""

    def test_deduplicates_rules(self) -> None:
        """Multiple findings with same rule should share one rule entry."""
        finding1 = Finding(
            scanner="semgrep",
            rule_id="same-rule",
            severity=Severity.HIGH,
            title="Same Rule",
            message="First occurrence",
            file_path="file1.py",
            line_start=10,
        )
        finding2 = Finding(
            scanner="semgrep",
            rule_id="same-rule",
            severity=Severity.HIGH,
            title="Same Rule",
            message="Second occurrence",
            file_path="file2.py",
            line_start=20,
        )
        result = ScanResult(
            repo_root="/repo",
            started_at=datetime.now(),
            findings=[finding1, finding2],
            scanners_run=["semgrep"],
        )
        sarif = to_sarif(result)

        # Should have 1 rule but 2 results
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1
        assert len(sarif["runs"][0]["results"]) == 2

        # Both results should reference the same rule index
        results = sarif["runs"][0]["results"]
        assert results[0]["ruleIndex"] == results[1]["ruleIndex"]
