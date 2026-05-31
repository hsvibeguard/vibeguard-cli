"""Tests for SARIF import module."""

import json

import pytest

from vibeguard.core.sarif_import import parse_sarif
from vibeguard.models.finding import Category, Severity


class TestParseSarif:
    """Tests for parse_sarif function."""

    def test_empty_string_returns_empty_list(self) -> None:
        """Empty string should return empty list."""
        assert parse_sarif("") == []
        assert parse_sarif("   ") == []

    def test_invalid_json_raises_value_error(self) -> None:
        """Invalid JSON should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_sarif("not valid json")

    def test_invalid_sarif_structure_raises_error(self) -> None:
        """Non-object SARIF should raise ValueError."""
        with pytest.raises(ValueError, match="must be a JSON object"):
            parse_sarif("[]")

    def test_unsupported_version_raises_error(self) -> None:
        """SARIF 1.x should raise ValueError."""
        sarif = json.dumps({"version": "1.0.0", "runs": []})
        with pytest.raises(ValueError, match="Unsupported SARIF version"):
            parse_sarif(sarif)

    def test_empty_runs_returns_empty_list(self) -> None:
        """SARIF with empty runs array returns empty list."""
        sarif = json.dumps({"version": "2.1.0", "runs": []})
        assert parse_sarif(sarif) == []

    def test_basic_sarif_parsing(self) -> None:
        """Parse a basic SARIF file with one result."""
        sarif = json.dumps({
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CodeQL",
                            "rules": [
                                {
                                    "id": "js/sql-injection",
                                    "name": "SQL Injection",
                                    "shortDescription": {"text": "SQL injection vulnerability"},
                                    "fullDescription": {"text": "User input flows into SQL query"},
                                    "defaultConfiguration": {"level": "error"},
                                    "properties": {
                                        "security-severity": "8.5",
                                        "tags": ["security", "external/cwe/cwe-89"],
                                    },
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "js/sql-injection",
                            "level": "error",
                            "message": {"text": "SQL injection detected"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/db.js"},
                                        "region": {
                                            "startLine": 42,
                                            "endLine": 45,
                                            "snippet": {"text": "db.query(input)"},
                                        },
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        })

        findings = parse_sarif(sarif)
        assert len(findings) == 1

        f = findings[0]
        assert f.scanner == "codeql"
        assert f.rule_id == "js/sql-injection"
        assert f.severity == Severity.HIGH  # 8.5 score
        assert f.title == "SQL Injection"
        assert f.message == "SQL injection detected"
        assert f.file_path == "src/db.js"
        assert f.line_start == 42
        assert f.line_end == 45
        assert f.code_snippet == "db.query(input)"
        assert f.cwe == "CWE-89"

    def test_multiple_runs(self) -> None:
        """Parse SARIF with multiple runs from different tools."""
        sarif = json.dumps({
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Tool1", "rules": []}},
                    "results": [
                        {
                            "ruleId": "rule1",
                            "level": "error",
                            "message": {"text": "Finding 1"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "file1.js"},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                },
                {
                    "tool": {"driver": {"name": "Tool2", "rules": []}},
                    "results": [
                        {
                            "ruleId": "rule2",
                            "level": "warning",
                            "message": {"text": "Finding 2"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "file2.js"},
                                        "region": {"startLine": 10},
                                    }
                                }
                            ],
                        }
                    ],
                },
            ],
        })

        findings = parse_sarif(sarif)
        assert len(findings) == 2

        assert findings[0].scanner == "tool1"
        assert findings[0].rule_id == "rule1"
        assert findings[1].scanner == "tool2"
        assert findings[1].rule_id == "rule2"


class TestSeverityMapping:
    """Tests for severity determination from SARIF."""

    @pytest.mark.parametrize(
        "score,expected",
        [
            ("9.5", Severity.CRITICAL),
            ("9.0", Severity.CRITICAL),
            ("8.0", Severity.HIGH),
            ("7.0", Severity.HIGH),
            ("6.0", Severity.MEDIUM),
            ("4.0", Severity.MEDIUM),
            ("3.0", Severity.LOW),
            ("1.0", Severity.LOW),
        ],
    )
    def test_security_severity_score(self, score: str, expected: Severity) -> None:
        """Test severity mapping from security-severity score."""
        sarif = json.dumps({
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Test",
                            "rules": [
                                {
                                    "id": "test-rule",
                                    "properties": {"security-severity": score},
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "test-rule",
                            "message": {"text": "Test"},
                            "locations": [{
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "test.js"},
                                    "region": {"startLine": 1},
                                }
                            }],
                        }
                    ],
                }
            ],
        })

        findings = parse_sarif(sarif)
        assert findings[0].severity == expected

    @pytest.mark.parametrize(
        "level,expected",
        [
            ("error", Severity.HIGH),
            ("warning", Severity.MEDIUM),
            ("note", Severity.LOW),
            ("none", Severity.INFO),
        ],
    )
    def test_level_fallback(self, level: str, expected: Severity) -> None:
        """Test severity mapping from SARIF level when no score available."""
        sarif = json.dumps({
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Test", "rules": []}},
                    "results": [
                        {
                            "ruleId": "test-rule",
                            "level": level,
                            "message": {"text": "Test"},
                            "locations": [{
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "test.js"},
                                    "region": {"startLine": 1},
                                }
                            }],
                        }
                    ],
                }
            ],
        })

        findings = parse_sarif(sarif)
        assert findings[0].severity == expected


class TestCategoryExtraction:
    """Tests for category extraction from SARIF tags."""

    def test_secrets_category(self) -> None:
        """Tags with 'secrets' should set SECRETS category."""
        sarif = _create_sarif_with_tags(["security", "secrets"])
        findings = parse_sarif(sarif)
        assert findings[0].category == Category.SECRETS

    def test_vulnerability_category(self) -> None:
        """Tags with 'vulnerability' should set VULNERABILITY category."""
        sarif = _create_sarif_with_tags(["security", "vulnerability"])
        findings = parse_sarif(sarif)
        assert findings[0].category == Category.VULNERABILITY

    def test_misconfiguration_category(self) -> None:
        """Tags with 'misconfiguration' should set MISCONFIGURATION category."""
        sarif = _create_sarif_with_tags(["iac", "misconfiguration"])
        findings = parse_sarif(sarif)
        assert findings[0].category == Category.MISCONFIGURATION

    def test_default_security_category(self) -> None:
        """Unknown tags should default to SECURITY category."""
        sarif = _create_sarif_with_tags(["something", "else"])
        findings = parse_sarif(sarif)
        assert findings[0].category == Category.SECURITY


class TestCweExtraction:
    """Tests for CWE extraction from SARIF tags."""

    def test_cwe_from_external_tag(self) -> None:
        """Extract CWE from external/cwe/cwe-XXX format."""
        sarif = _create_sarif_with_tags(["external/cwe/cwe-89"])
        findings = parse_sarif(sarif)
        assert findings[0].cwe == "CWE-89"

    def test_cwe_from_simple_tag(self) -> None:
        """Extract CWE from CWE-XXX format."""
        sarif = _create_sarif_with_tags(["CWE-79"])
        findings = parse_sarif(sarif)
        assert findings[0].cwe == "CWE-79"

    def test_no_cwe_when_missing(self) -> None:
        """CWE should be None when not in tags."""
        sarif = _create_sarif_with_tags(["security"])
        findings = parse_sarif(sarif)
        assert findings[0].cwe is None


class TestFilePathHandling:
    """Tests for file path handling."""

    def test_simple_path(self) -> None:
        """Simple relative path should be preserved."""
        sarif = _create_sarif_with_location("src/app.js", 1)
        findings = parse_sarif(sarif)
        assert findings[0].file_path == "src/app.js"

    def test_file_uri_prefix_removed(self) -> None:
        """file:// prefix should be removed."""
        sarif = _create_sarif_with_location("file:///home/user/src/app.js", 1)
        findings = parse_sarif(sarif)
        assert findings[0].file_path == "/home/user/src/app.js"

    def test_windows_path_handling(self) -> None:
        """Windows paths like /C:/... should have leading slash removed."""
        sarif = _create_sarif_with_location("file:///C:/Users/test/app.js", 1)
        findings = parse_sarif(sarif)
        assert findings[0].file_path == "C:/Users/test/app.js"


class TestCustomScannerName:
    """Tests for custom scanner name parameter."""

    def test_custom_scanner_name(self) -> None:
        """Custom scanner name should override tool name."""
        sarif = json.dumps({
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "OriginalTool", "rules": []}},
                    "results": [
                        {
                            "ruleId": "rule1",
                            "message": {"text": "Test"},
                            "locations": [{
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "test.js"},
                                    "region": {"startLine": 1},
                                }
                            }],
                        }
                    ],
                }
            ],
        })

        findings = parse_sarif(sarif, scanner_name="custom_scanner")
        # User-provided scanner_name overrides SARIF tool name
        assert findings[0].scanner == "custom_scanner"

    def test_default_scanner_name_when_no_tool(self) -> None:
        """Default scanner name used when tool has no name."""
        sarif = json.dumps({
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {}},
                    "results": [
                        {
                            "ruleId": "rule1",
                            "message": {"text": "Test"},
                            "locations": [{
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "test.js"},
                                    "region": {"startLine": 1},
                                }
                            }],
                        }
                    ],
                }
            ],
        })

        findings = parse_sarif(sarif, scanner_name="my_scanner")
        assert findings[0].scanner == "my_scanner"

    def test_sarif_tool_name_used_when_no_override(self) -> None:
        """SARIF tool name used when scanner_name is not provided."""
        sarif = json.dumps({
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "CodeQL", "rules": []}},
                    "results": [
                        {
                            "ruleId": "rule1",
                            "message": {"text": "Test"},
                            "locations": [{
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "test.js"},
                                    "region": {"startLine": 1}
                                }
                            }],
                        }
                    ],
                }
            ],
        })

        # No scanner_name provided - should use SARIF tool name
        findings = parse_sarif(sarif)
        assert findings[0].scanner == "codeql"


class TestFingerprint:
    """Tests for fingerprint extraction and generation."""

    def test_fingerprint_from_sarif(self) -> None:
        """Fingerprint should be extracted from partialFingerprints."""
        sarif = json.dumps({
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Test", "rules": []}},
                    "results": [
                        {
                            "ruleId": "rule1",
                            "message": {"text": "Test"},
                            "locations": [{
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "test.js"},
                                    "region": {"startLine": 1},
                                }
                            }],
                            "partialFingerprints": {"primaryLocationLineHash": "abc123"},
                        }
                    ],
                }
            ],
        })

        findings = parse_sarif(sarif)
        assert findings[0].fingerprint == "abc123"

    def test_generated_fingerprint_when_missing(self) -> None:
        """Fingerprint should be generated when not in SARIF."""
        sarif = json.dumps({
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "TestTool", "rules": []}},
                    "results": [
                        {
                            "ruleId": "rule1",
                            "message": {"text": "Test"},
                            "locations": [{
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "test.js"},
                                    "region": {"startLine": 42},
                                }
                            }],
                        }
                    ],
                }
            ],
        })

        findings = parse_sarif(sarif)
        # Format: tool_name:rule_id:file_path:line_start
        # Tool name is used as-is in fingerprint (before lowercase for scanner field)
        assert findings[0].fingerprint == "TestTool:rule1:test.js:42"


# Helper functions for creating test SARIF data
def _create_sarif_with_tags(tags: list[str]) -> str:
    """Create SARIF with specific rule tags."""
    return json.dumps({
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Test",
                        "rules": [
                            {
                                "id": "test-rule",
                                "properties": {"tags": tags},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "test-rule",
                        "message": {"text": "Test"},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "test.js"},
                                "region": {"startLine": 1},
                            }
                        }],
                    }
                ],
            }
        ],
    })


def _create_sarif_with_location(uri: str, line: int) -> str:
    """Create SARIF with specific file location."""
    return json.dumps({
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Test", "rules": []}},
                "results": [
                    {
                        "ruleId": "test-rule",
                        "message": {"text": "Test"},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": uri},
                                "region": {"startLine": line},
                            }
                        }],
                    }
                ],
            }
        ],
    })
