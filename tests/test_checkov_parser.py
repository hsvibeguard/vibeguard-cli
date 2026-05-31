"""Tests for Checkov output parser."""

import json

import pytest

from vibeguard.models.finding import Category, Severity
from vibeguard.scanners.parsers.checkov import parse_output


class TestParseOutput:
    """Tests for parse_output function."""

    def test_empty_output_returns_empty_list(self) -> None:
        """Empty output should return empty list."""
        assert parse_output("") == []
        assert parse_output("   ") == []

    def test_invalid_json_raises_value_error(self) -> None:
        """Invalid JSON should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid Checkov JSON"):
            parse_output("not valid json")

    def test_empty_failed_checks_returns_empty_list(self) -> None:
        """Output with no failed checks returns empty list."""
        output = json.dumps({
            "passed_checks": [{"check": {"id": "CKV_AWS_1"}}],
            "failed_checks": [],
            "skipped_checks": [],
        })
        assert parse_output(output) == []

    def test_single_failed_check(self) -> None:
        """Parse a single failed check."""
        output = json.dumps({
            "failed_checks": [
                {
                    "check": {
                        "id": "CKV_AWS_21",
                        "name": "Ensure S3 bucket has versioning enabled",
                        "guideline": "https://docs.checkov.io/docs/aws/CKV_AWS_21",
                    },
                    "check_result": {"result": "FAILED"},
                    "file_path": "/terraform/s3.tf",
                    "file_line_range": [10, 15],
                    "resource": "aws_s3_bucket.my_bucket",
                    "severity": "MEDIUM",
                }
            ]
        })

        findings = parse_output(output)
        assert len(findings) == 1

        f = findings[0]
        assert f.scanner == "checkov"
        assert f.rule_id == "CKV_AWS_21"
        assert f.severity == Severity.MEDIUM
        assert f.category == Category.MISCONFIGURATION
        assert "CKV_AWS_21" in f.title
        assert "S3 bucket has versioning enabled" in f.title
        assert f.file_path == "terraform/s3.tf"  # Leading slash removed
        assert f.line_start == 10
        assert f.line_end == 15
        assert "https://docs.checkov.io" in f.references[0]

    def test_multiple_failed_checks(self) -> None:
        """Parse multiple failed checks."""
        output = json.dumps({
            "failed_checks": [
                {
                    "check": {"id": "CKV_AWS_1", "name": "Check 1"},
                    "file_path": "/file1.tf",
                    "file_line_range": [1, 5],
                    "severity": "HIGH",
                },
                {
                    "check": {"id": "CKV_AWS_2", "name": "Check 2"},
                    "file_path": "/file2.tf",
                    "file_line_range": [10, 20],
                    "severity": "LOW",
                },
                {
                    "check": {"id": "CKV_AWS_3", "name": "Check 3"},
                    "file_path": "/file3.tf",
                    "file_line_range": [100, 110],
                    "severity": "CRITICAL",
                },
            ]
        })

        findings = parse_output(output)
        assert len(findings) == 3

        assert findings[0].rule_id == "CKV_AWS_1"
        assert findings[0].severity == Severity.HIGH
        assert findings[1].rule_id == "CKV_AWS_2"
        assert findings[1].severity == Severity.LOW
        assert findings[2].rule_id == "CKV_AWS_3"
        assert findings[2].severity == Severity.CRITICAL


class TestSeverityMapping:
    """Tests for severity mapping."""

    @pytest.mark.parametrize(
        "checkov_severity,expected",
        [
            ("CRITICAL", Severity.CRITICAL),
            ("HIGH", Severity.HIGH),
            ("MEDIUM", Severity.MEDIUM),
            ("LOW", Severity.LOW),
            ("INFO", Severity.INFO),
            ("UNKNOWN", Severity.MEDIUM),  # Default
        ],
    )
    def test_severity_mapping(self, checkov_severity: str, expected: Severity) -> None:
        """Test severity mapping from Checkov to VibeGuard."""
        output = json.dumps({
            "failed_checks": [
                {
                    "check": {"id": "CKV_TEST_1", "name": "Test Check"},
                    "file_path": "/test.tf",
                    "file_line_range": [1, 1],
                    "severity": checkov_severity,
                }
            ]
        })

        findings = parse_output(output)
        assert len(findings) == 1
        assert findings[0].severity == expected

    def test_missing_severity_defaults_to_medium(self) -> None:
        """Missing severity should default to MEDIUM."""
        output = json.dumps({
            "failed_checks": [
                {
                    "check": {"id": "CKV_TEST_1", "name": "Test Check"},
                    "file_path": "/test.tf",
                    "file_line_range": [1, 1],
                    # No severity field
                }
            ]
        })

        findings = parse_output(output)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_null_severity_defaults_to_medium(self) -> None:
        """Null severity should default to MEDIUM."""
        output = json.dumps({
            "failed_checks": [
                {
                    "check": {"id": "CKV_TEST_1", "name": "Test Check"},
                    "file_path": "/test.tf",
                    "file_line_range": [1, 1],
                    "severity": None,
                }
            ]
        })

        findings = parse_output(output)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM


class TestLineRanges:
    """Tests for line range parsing."""

    def test_line_range_parsed_correctly(self) -> None:
        """Line range should be parsed into line_start and line_end."""
        output = json.dumps({
            "failed_checks": [
                {
                    "check": {"id": "CKV_TEST_1", "name": "Test"},
                    "file_path": "/test.tf",
                    "file_line_range": [42, 55],
                    "severity": "HIGH",
                }
            ]
        })

        findings = parse_output(output)
        assert findings[0].line_start == 42
        assert findings[0].line_end == 55

    def test_single_line_range(self) -> None:
        """Single line range where start == end."""
        output = json.dumps({
            "failed_checks": [
                {
                    "check": {"id": "CKV_TEST_1", "name": "Test"},
                    "file_path": "/test.tf",
                    "file_line_range": [10, 10],
                    "severity": "HIGH",
                }
            ]
        })

        findings = parse_output(output)
        assert findings[0].line_start == 10
        assert findings[0].line_end == 10

    def test_empty_line_range_defaults(self) -> None:
        """Empty line range should default to line 1."""
        output = json.dumps({
            "failed_checks": [
                {
                    "check": {"id": "CKV_TEST_1", "name": "Test"},
                    "file_path": "/test.tf",
                    "file_line_range": [],
                    "severity": "HIGH",
                }
            ]
        })

        findings = parse_output(output)
        assert findings[0].line_start == 1
        assert findings[0].line_end == 1

    def test_missing_line_range_defaults(self) -> None:
        """Missing line range should default to line 1."""
        output = json.dumps({
            "failed_checks": [
                {
                    "check": {"id": "CKV_TEST_1", "name": "Test"},
                    "file_path": "/test.tf",
                    "severity": "HIGH",
                    # No file_line_range
                }
            ]
        })

        findings = parse_output(output)
        assert findings[0].line_start == 1


class TestMultiCheckTypeFormat:
    """Tests for multi-check-type output format (list of results)."""

    def test_multi_check_type_format(self) -> None:
        """Parse multi-check-type format with list of results."""
        output = json.dumps([
            {
                "check_type": "terraform",
                "results": {
                    "failed_checks": [
                        {
                            "check": {"id": "CKV_AWS_1", "name": "TF Check"},
                            "file_path": "/main.tf",
                            "file_line_range": [1, 5],
                            "severity": "HIGH",
                        }
                    ]
                },
            },
            {
                "check_type": "dockerfile",
                "results": {
                    "failed_checks": [
                        {
                            "check": {"id": "CKV_DOCKER_1", "name": "Docker Check"},
                            "file_path": "/Dockerfile",
                            "file_line_range": [10, 12],
                            "severity": "MEDIUM",
                        }
                    ]
                },
            },
        ])

        findings = parse_output(output)
        assert len(findings) == 2

        assert findings[0].rule_id == "CKV_AWS_1"
        assert findings[0].file_path == "main.tf"
        assert findings[1].rule_id == "CKV_DOCKER_1"
        assert findings[1].file_path == "Dockerfile"

    def test_multi_check_type_with_empty_results(self) -> None:
        """Multi-check-type format with some empty results."""
        output = json.dumps([
            {
                "check_type": "terraform",
                "results": {
                    "failed_checks": [],
                },
            },
            {
                "check_type": "dockerfile",
                "results": {
                    "failed_checks": [
                        {
                            "check": {"id": "CKV_DOCKER_1", "name": "Docker Check"},
                            "file_path": "/Dockerfile",
                            "file_line_range": [1, 1],
                            "severity": "HIGH",
                        }
                    ]
                },
            },
        ])

        findings = parse_output(output)
        assert len(findings) == 1
        assert findings[0].rule_id == "CKV_DOCKER_1"


class TestWrappedFormat:
    """Tests for wrapped results format."""

    def test_wrapped_results_format(self) -> None:
        """Parse wrapped format with results key."""
        output = json.dumps({
            "results": {
                "passed_checks": [],
                "failed_checks": [
                    {
                        "check": {"id": "CKV_K8S_1", "name": "K8s Check"},
                        "file_path": "/deployment.yaml",
                        "file_line_range": [5, 15],
                        "severity": "CRITICAL",
                    }
                ],
                "skipped_checks": [],
            }
        })

        findings = parse_output(output)
        assert len(findings) == 1
        assert findings[0].rule_id == "CKV_K8S_1"
        assert findings[0].severity == Severity.CRITICAL


class TestResourceInfo:
    """Tests for resource info extraction."""

    def test_resource_in_message(self) -> None:
        """Resource info should be included in message."""
        output = json.dumps({
            "failed_checks": [
                {
                    "check": {"id": "CKV_AWS_1", "name": "Security Check"},
                    "file_path": "/main.tf",
                    "file_line_range": [1, 1],
                    "resource": "aws_s3_bucket.data",
                    "resource_address": "module.storage.aws_s3_bucket.data",
                    "severity": "HIGH",
                }
            ]
        })

        findings = parse_output(output)
        assert "module.storage.aws_s3_bucket.data" in findings[0].message

    def test_resource_without_address(self) -> None:
        """Resource without resource_address uses resource field."""
        output = json.dumps({
            "failed_checks": [
                {
                    "check": {"id": "CKV_AWS_1", "name": "Security Check"},
                    "file_path": "/main.tf",
                    "file_line_range": [1, 1],
                    "resource": "aws_instance.web",
                    "severity": "HIGH",
                }
            ]
        })

        findings = parse_output(output)
        assert "aws_instance.web" in findings[0].message


class TestGuideline:
    """Tests for guideline/references extraction."""

    def test_guideline_in_references(self) -> None:
        """Guideline URL should be in references."""
        output = json.dumps({
            "failed_checks": [
                {
                    "check": {
                        "id": "CKV_AWS_1",
                        "name": "Security Check",
                        "guideline": "https://docs.checkov.io/docs/aws/CKV_AWS_1",
                    },
                    "file_path": "/main.tf",
                    "file_line_range": [1, 1],
                    "severity": "HIGH",
                }
            ]
        })

        findings = parse_output(output)
        assert len(findings[0].references) == 1
        assert "https://docs.checkov.io" in findings[0].references[0]

    def test_no_guideline_empty_references(self) -> None:
        """Missing guideline results in empty references."""
        output = json.dumps({
            "failed_checks": [
                {
                    "check": {"id": "CKV_AWS_1", "name": "Security Check"},
                    "file_path": "/main.tf",
                    "file_line_range": [1, 1],
                    "severity": "HIGH",
                }
            ]
        })

        findings = parse_output(output)
        assert findings[0].references == []


class TestFingerprint:
    """Tests for fingerprint generation."""

    def test_fingerprint_format(self) -> None:
        """Fingerprint should be check_id:file_path:line_start."""
        output = json.dumps({
            "failed_checks": [
                {
                    "check": {"id": "CKV_AWS_21", "name": "Test"},
                    "file_path": "/terraform/main.tf",
                    "file_line_range": [42, 50],
                    "severity": "HIGH",
                }
            ]
        })

        findings = parse_output(output)
        assert findings[0].fingerprint == "CKV_AWS_21:terraform/main.tf:42"


class TestFilePath:
    """Tests for file path handling."""

    def test_leading_slash_removed(self) -> None:
        """Leading slash should be removed from file path."""
        output = json.dumps({
            "failed_checks": [
                {
                    "check": {"id": "CKV_TEST_1", "name": "Test"},
                    "file_path": "/path/to/file.tf",
                    "file_line_range": [1, 1],
                    "severity": "HIGH",
                }
            ]
        })

        findings = parse_output(output)
        assert findings[0].file_path == "path/to/file.tf"

    def test_no_leading_slash_unchanged(self) -> None:
        """File path without leading slash should be unchanged."""
        output = json.dumps({
            "failed_checks": [
                {
                    "check": {"id": "CKV_TEST_1", "name": "Test"},
                    "file_path": "path/to/file.tf",
                    "file_line_range": [1, 1],
                    "severity": "HIGH",
                }
            ]
        })

        findings = parse_output(output)
        assert findings[0].file_path == "path/to/file.tf"


class TestMalformedChecks:
    """Tests for handling malformed check entries."""

    def test_missing_check_uses_defaults(self) -> None:
        """Missing check dict uses default values (graceful degradation)."""
        output = json.dumps({
            "failed_checks": [
                # Valid check
                {
                    "check": {"id": "CKV_AWS_1", "name": "Valid Check"},
                    "file_path": "/main.tf",
                    "file_line_range": [1, 1],
                    "severity": "HIGH",
                },
                # Missing check dict - uses defaults
                {
                    "file_path": "/other.tf",
                },
                # Another valid check
                {
                    "check": {"id": "CKV_AWS_2", "name": "Another Valid"},
                    "file_path": "/second.tf",
                    "file_line_range": [5, 10],
                    "severity": "LOW",
                },
            ]
        })

        findings = parse_output(output)
        # Parser uses defaults for missing fields (graceful)
        assert len(findings) == 3
        assert findings[0].rule_id == "CKV_AWS_1"
        assert findings[1].rule_id == "UNKNOWN"  # Default when check.id missing
        assert findings[2].rule_id == "CKV_AWS_2"

    def test_empty_check_dict(self) -> None:
        """Empty check dict uses default values."""
        output = json.dumps({
            "failed_checks": [
                {
                    "check": {},
                    "file_path": "/test.tf",
                    "file_line_range": [1, 1],
                    "severity": "HIGH",
                }
            ]
        })

        findings = parse_output(output)
        assert len(findings) == 1
        assert findings[0].rule_id == "UNKNOWN"
        assert "Security misconfiguration detected" in findings[0].title
