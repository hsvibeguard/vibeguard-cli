"""Tests for Semgrep parser."""

import json

import pytest

from vibeguard.models.finding import Category, Severity
from vibeguard.scanners.parsers.semgrep import parse_output

SAMPLE_OUTPUT = {
    "results": [
        {
            "check_id": "python.security.audit.dangerous-eval-use",
            "path": "app/utils.py",
            "start": {"line": 42, "col": 5, "offset": 1234},
            "end": {"line": 42, "col": 25, "offset": 1254},
            "extra": {
                "message": "Detected the use of eval(). This can be dangerous.",
                "severity": "WARNING",
                "lines": "    result = eval(user_input)",
                "fingerprint": "abc123",
                "metadata": {
                    "cwe": ["CWE-95: Improper Neutralization of Directives"],
                    "references": ["https://owasp.org/eval"],
                },
            },
        }
    ],
    "errors": [],
}


class TestSemgrepParser:
    def test_parse_valid_output(self) -> None:
        findings = parse_output(json.dumps(SAMPLE_OUTPUT))
        assert len(findings) == 1

        finding = findings[0]
        assert finding.scanner == "semgrep"
        assert finding.rule_id == "python.security.audit.dangerous-eval-use"
        assert finding.file_path == "app/utils.py"
        assert finding.line_start == 42
        assert finding.severity == Severity.HIGH  # WARNING maps to HIGH
        assert "eval" in finding.message.lower()
        assert finding.fingerprint == "abc123"

    def test_parse_empty_results(self) -> None:
        output = {"results": [], "errors": []}
        findings = parse_output(json.dumps(output))
        assert findings == []

    def test_parse_invalid_json(self) -> None:
        with pytest.raises(ValueError, match="Invalid Semgrep JSON"):
            parse_output("not json")

    def test_severity_mapping(self) -> None:
        severities_expected = [
            ("ERROR", Severity.CRITICAL),
            ("WARNING", Severity.HIGH),
            ("INFO", Severity.MEDIUM),
            ("CRITICAL", Severity.CRITICAL),
            ("HIGH", Severity.HIGH),
            ("MEDIUM", Severity.MEDIUM),
            ("LOW", Severity.LOW),
        ]

        for sev, expected_sev in severities_expected:
            output = {
                "results": [
                    {
                        "check_id": "test",
                        "path": "test.py",
                        "start": {"line": 1},
                        "end": {"line": 1},
                        "extra": {
                            "message": "test",
                            "severity": sev,
                        },
                    }
                ],
            }
            findings = parse_output(json.dumps(output))
            assert findings[0].severity == expected_sev, f"Failed for severity {sev}"

    def test_extract_cwe(self) -> None:
        findings = parse_output(json.dumps(SAMPLE_OUTPUT))
        assert findings[0].cwe == "CWE-95: Improper Neutralization of Directives"

    def test_extract_references(self) -> None:
        findings = parse_output(json.dumps(SAMPLE_OUTPUT))
        assert "https://owasp.org/eval" in findings[0].references

    def test_category_detection_secrets(self) -> None:
        output = {
            "results": [
                {
                    "check_id": "generic.secrets.hardcoded-password",
                    "path": "config.py",
                    "start": {"line": 5},
                    "end": {"line": 5},
                    "extra": {
                        "message": "Hardcoded password detected",
                        "severity": "ERROR",
                    },
                }
            ],
        }
        findings = parse_output(json.dumps(output))
        assert findings[0].category == Category.SECRETS

    def test_category_detection_security(self) -> None:
        output = {
            "results": [
                {
                    "check_id": "python.security.injection.sql-injection",
                    "path": "db.py",
                    "start": {"line": 10},
                    "end": {"line": 10},
                    "extra": {
                        "message": "SQL injection detected",
                        "severity": "ERROR",
                    },
                }
            ],
        }
        findings = parse_output(json.dumps(output))
        assert findings[0].category == Category.SECURITY

    def test_parse_multiple_results(self) -> None:
        output = {
            "results": [
                {
                    "check_id": "rule1",
                    "path": "file1.py",
                    "start": {"line": 1},
                    "end": {"line": 1},
                    "extra": {"message": "Issue 1", "severity": "WARNING"},
                },
                {
                    "check_id": "rule2",
                    "path": "file2.py",
                    "start": {"line": 5},
                    "end": {"line": 5},
                    "extra": {"message": "Issue 2", "severity": "ERROR"},
                },
            ],
        }
        findings = parse_output(json.dumps(output))
        assert len(findings) == 2
        assert findings[0].rule_id == "rule1"
        assert findings[1].rule_id == "rule2"

    def test_title_extraction(self) -> None:
        findings = parse_output(json.dumps(SAMPLE_OUTPUT))
        # "python.security.audit.dangerous-eval-use" -> "Dangerous Eval Use"
        assert findings[0].title == "Dangerous Eval Use"
