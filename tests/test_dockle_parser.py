"""Tests for Dockle output parser."""

import json

import pytest

from vibeguard.models.finding import Category, Severity
from vibeguard.scanners.parsers.dockle import parse_output


class TestParseOutput:
    """Tests for parse_output function."""

    def test_empty_output_returns_empty_list(self) -> None:
        """Empty output should return empty list."""
        assert parse_output("") == []
        assert parse_output("   ") == []

    def test_invalid_json_raises_value_error(self) -> None:
        """Invalid JSON should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid Dockle JSON"):
            parse_output("not valid json")

    def test_empty_details_returns_empty_list(self) -> None:
        """Output with no details returns empty list."""
        output = json.dumps({
            "summary": {"fatal": 0, "warn": 0, "info": 0},
            "details": [],
        })
        assert parse_output(output) == []

    def test_single_finding(self) -> None:
        """Parse a single Dockle finding."""
        output = json.dumps({
            "summary": {"fatal": 0, "warn": 1, "info": 0},
            "details": [
                {
                    "code": "CIS-DI-0001",
                    "title": "Create a user for the container",
                    "level": "WARN",
                    "alerts": ["Last user should not be root"],
                }
            ],
        })

        findings = parse_output(output)
        assert len(findings) == 1

        f = findings[0]
        assert f.scanner == "dockle"
        assert f.rule_id == "CIS-DI-0001"
        assert f.severity == Severity.HIGH  # WARN maps to HIGH
        assert "CIS-DI-0001" in f.title
        assert "Last user should not be root" in f.message
        assert f.file_path == "Dockerfile"
        assert f.line_start == 1

    def test_multiple_findings(self) -> None:
        """Parse multiple Dockle findings."""
        output = json.dumps({
            "details": [
                {
                    "code": "CIS-DI-0001",
                    "title": "Check 1",
                    "level": "WARN",
                    "alerts": ["Alert 1"],
                },
                {
                    "code": "CIS-DI-0006",
                    "title": "Check 2",
                    "level": "INFO",
                    "alerts": ["Alert 2"],
                },
                {
                    "code": "DKL-DI-0001",
                    "title": "Check 3",
                    "level": "FATAL",
                    "alerts": ["Alert 3"],
                },
            ],
        })

        findings = parse_output(output)
        assert len(findings) == 3

        assert findings[0].rule_id == "CIS-DI-0001"
        assert findings[0].severity == Severity.HIGH
        assert findings[1].rule_id == "CIS-DI-0006"
        assert findings[1].severity == Severity.MEDIUM
        assert findings[2].rule_id == "DKL-DI-0001"
        assert findings[2].severity == Severity.CRITICAL


class TestLevelMapping:
    """Tests for severity level mapping."""

    @pytest.mark.parametrize(
        "dockle_level,expected",
        [
            ("FATAL", Severity.CRITICAL),
            ("WARN", Severity.HIGH),
            ("INFO", Severity.MEDIUM),
        ],
    )
    def test_level_mapping(self, dockle_level: str, expected: Severity) -> None:
        """Test level mapping from Dockle to VibeGuard severity."""
        output = json.dumps({
            "details": [
                {
                    "code": "TEST-001",
                    "title": "Test Check",
                    "level": dockle_level,
                    "alerts": [],
                }
            ]
        })

        findings = parse_output(output)
        assert len(findings) == 1
        assert findings[0].severity == expected

    def test_pass_level_skipped(self) -> None:
        """PASS level should be skipped (not a finding)."""
        output = json.dumps({
            "details": [
                {
                    "code": "CIS-DI-0001",
                    "title": "Passed Check",
                    "level": "PASS",
                    "alerts": [],
                }
            ]
        })

        findings = parse_output(output)
        assert len(findings) == 0

    def test_skip_level_skipped(self) -> None:
        """SKIP level should be skipped (not a finding)."""
        output = json.dumps({
            "details": [
                {
                    "code": "CIS-DI-0001",
                    "title": "Skipped Check",
                    "level": "SKIP",
                    "alerts": [],
                }
            ]
        })

        findings = parse_output(output)
        assert len(findings) == 0

    def test_mixed_levels_filters_correctly(self) -> None:
        """Only FATAL, WARN, INFO levels should produce findings."""
        output = json.dumps({
            "details": [
                {"code": "CHECK-1", "title": "Fatal", "level": "FATAL", "alerts": []},
                {"code": "CHECK-2", "title": "Pass", "level": "PASS", "alerts": []},
                {"code": "CHECK-3", "title": "Warn", "level": "WARN", "alerts": []},
                {"code": "CHECK-4", "title": "Skip", "level": "SKIP", "alerts": []},
                {"code": "CHECK-5", "title": "Info", "level": "INFO", "alerts": []},
            ]
        })

        findings = parse_output(output)
        assert len(findings) == 3

        codes = [f.rule_id for f in findings]
        assert "CHECK-1" in codes  # FATAL
        assert "CHECK-3" in codes  # WARN
        assert "CHECK-5" in codes  # INFO
        assert "CHECK-2" not in codes  # PASS - skipped
        assert "CHECK-4" not in codes  # SKIP - skipped


class TestAlerts:
    """Tests for alert message extraction."""

    def test_multiple_alerts_in_message(self) -> None:
        """Multiple alerts should be listed in the message."""
        output = json.dumps({
            "details": [
                {
                    "code": "CIS-DI-0001",
                    "title": "Container user check",
                    "level": "WARN",
                    "alerts": [
                        "User root found",
                        "No USER instruction",
                        "Running as privileged",
                    ],
                }
            ]
        })

        findings = parse_output(output)
        assert len(findings) == 1

        msg = findings[0].message
        assert "User root found" in msg
        assert "No USER instruction" in msg
        assert "Running as privileged" in msg

    def test_empty_alerts(self) -> None:
        """Empty alerts array should use title as message."""
        output = json.dumps({
            "details": [
                {
                    "code": "CIS-DI-0001",
                    "title": "Just a title",
                    "level": "WARN",
                    "alerts": [],
                }
            ]
        })

        findings = parse_output(output)
        assert len(findings) == 1
        assert findings[0].message == "Just a title"

    def test_missing_alerts(self) -> None:
        """Missing alerts key should use title as message."""
        output = json.dumps({
            "details": [
                {
                    "code": "CIS-DI-0001",
                    "title": "Just a title",
                    "level": "WARN",
                    # No alerts key
                }
            ]
        })

        findings = parse_output(output)
        assert len(findings) == 1
        assert findings[0].message == "Just a title"


class TestCategory:
    """Tests for category determination."""

    def test_security_category_checks(self) -> None:
        """Security-critical checks should have SECURITY category."""
        security_codes = [
            "CIS-DI-0001",  # Run as non-root
            "CIS-DI-0010",  # No secrets in ENV
            "DKL-DI-0001",  # Avoid sudo
            "DKL-LI-0001",  # Avoid empty password
        ]

        for code in security_codes:
            output = json.dumps({
                "details": [
                    {"code": code, "title": "Test", "level": "WARN", "alerts": []}
                ]
            })
            findings = parse_output(output)
            assert findings[0].category == Category.SECURITY, f"Expected SECURITY for {code}"

    def test_best_practice_category_default(self) -> None:
        """Non-security checks should default to BEST_PRACTICE."""
        output = json.dumps({
            "details": [
                {
                    "code": "CIS-DI-0006",  # HEALTHCHECK instruction
                    "title": "Add HEALTHCHECK",
                    "level": "INFO",
                    "alerts": [],
                }
            ]
        })

        findings = parse_output(output)
        assert findings[0].category == Category.BEST_PRACTICE


class TestReferences:
    """Tests for reference URL generation."""

    def test_cis_check_has_benchmark_reference(self) -> None:
        """CIS checks should include CIS benchmark reference."""
        output = json.dumps({
            "details": [
                {
                    "code": "CIS-DI-0001",
                    "title": "CIS Check",
                    "level": "WARN",
                    "alerts": [],
                }
            ]
        })

        findings = parse_output(output)
        refs = findings[0].references
        assert any("cisecurity.org" in ref for ref in refs)

    def test_dockle_check_has_github_reference(self) -> None:
        """All checks should include Dockle GitHub reference."""
        output = json.dumps({
            "details": [
                {
                    "code": "DKL-DI-0001",
                    "title": "Dockle Check",
                    "level": "WARN",
                    "alerts": [],
                }
            ]
        })

        findings = parse_output(output)
        refs = findings[0].references
        assert any("github.com/goodwithtech/dockle" in ref for ref in refs)


class TestFingerprint:
    """Tests for fingerprint generation."""

    def test_fingerprint_format(self) -> None:
        """Fingerprint should be dockle:{code}."""
        output = json.dumps({
            "details": [
                {
                    "code": "CIS-DI-0001",
                    "title": "Test",
                    "level": "WARN",
                    "alerts": [],
                }
            ]
        })

        findings = parse_output(output)
        assert findings[0].fingerprint == "dockle:CIS-DI-0001"


class TestFilePath:
    """Tests for file path handling."""

    def test_file_path_is_dockerfile(self) -> None:
        """File path should be 'Dockerfile' since Dockle scans images."""
        output = json.dumps({
            "details": [
                {
                    "code": "CIS-DI-0001",
                    "title": "Test",
                    "level": "WARN",
                    "alerts": [],
                }
            ]
        })

        findings = parse_output(output)
        assert findings[0].file_path == "Dockerfile"


class TestMalformedData:
    """Tests for handling malformed data."""

    def test_missing_details_key(self) -> None:
        """Missing details key should return empty list."""
        output = json.dumps({
            "summary": {"fatal": 0},
            # No details key
        })

        findings = parse_output(output)
        assert findings == []

    def test_non_list_details(self) -> None:
        """Non-list details should return empty list."""
        output = json.dumps({
            "details": "not a list",
        })

        findings = parse_output(output)
        assert findings == []

    def test_malformed_detail_skipped(self) -> None:
        """Malformed detail entries should be skipped gracefully."""
        output = json.dumps({
            "details": [
                # Valid entry
                {"code": "CIS-DI-0001", "title": "Valid", "level": "WARN", "alerts": []},
                # Missing level (will default)
                {"code": "CIS-DI-0002", "title": "No level"},
                # Valid entry
                {"code": "CIS-DI-0003", "title": "Also Valid", "level": "INFO", "alerts": []},
            ]
        })

        findings = parse_output(output)
        # Missing level defaults to empty string which is skipped
        assert len(findings) == 2
        assert findings[0].rule_id == "CIS-DI-0001"
        assert findings[1].rule_id == "CIS-DI-0003"
