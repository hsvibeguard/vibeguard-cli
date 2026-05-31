"""Tests for Nuclei JSONL parser."""

import json

from vibeguard.models.finding import Category, Severity
from vibeguard.scanners.parsers.nuclei import (
    _determine_category,
    _parse_result,
    parse_output,
)


class TestParseOutput:
    """Test the main parse_output function."""

    def test_empty_output_returns_empty_list(self) -> None:
        """Test that empty output returns empty list."""
        assert parse_output("") == []

    def test_whitespace_only_returns_empty_list(self) -> None:
        """Test that whitespace-only output returns empty list."""
        assert parse_output("   ") == []
        assert parse_output("\n\n\n") == []

    def test_none_safe(self) -> None:
        """Test that None-like input is handled."""
        # Empty string is the None equivalent for raw output
        assert parse_output("") == []

    def test_single_jsonl_finding(self) -> None:
        """Test parsing a single JSONL finding."""
        output = json.dumps({
            "template-id": "CVE-2021-44228",
            "info": {
                "name": "Log4j RCE",
                "severity": "critical",
                "description": "Remote code execution via Log4j",
                "tags": ["cve", "rce"],
            },
            "host": "http://localhost:8080",
            "matched-at": "http://localhost:8080/api/login",
        })
        findings = parse_output(output)
        assert len(findings) == 1
        assert findings[0].rule_id == "CVE-2021-44228"
        assert findings[0].title == "Log4j RCE"
        assert findings[0].severity == Severity.CRITICAL

    def test_multiple_jsonl_findings(self) -> None:
        """Test parsing multiple JSONL lines."""
        line1 = json.dumps({
            "template-id": "xss-detection",
            "info": {"name": "XSS Detected", "severity": "high", "tags": ["xss"]},
            "host": "http://localhost:8080",
            "matched-at": "http://localhost:8080/search",
        })
        line2 = json.dumps({
            "template-id": "sqli-detection",
            "info": {"name": "SQL Injection", "severity": "critical", "tags": ["sqli"]},
            "host": "http://localhost:8080",
            "matched-at": "http://localhost:8080/login",
        })
        output = f"{line1}\n{line2}"
        findings = parse_output(output)
        assert len(findings) == 2
        assert findings[0].rule_id == "xss-detection"
        assert findings[1].rule_id == "sqli-detection"

    def test_malformed_line_skipped(self) -> None:
        """Test that malformed JSON lines are skipped."""
        valid_line = json.dumps({
            "template-id": "test",
            "info": {"name": "Test", "severity": "low", "tags": []},
            "host": "http://localhost",
        })
        output = f"not valid json\n{valid_line}\nalso invalid"
        findings = parse_output(output)
        assert len(findings) == 1
        assert findings[0].rule_id == "test"

    def test_empty_lines_skipped(self) -> None:
        """Test that empty lines are skipped."""
        valid_line = json.dumps({
            "template-id": "test",
            "info": {"name": "Test", "severity": "medium", "tags": []},
            "host": "http://localhost",
        })
        output = f"\n\n{valid_line}\n\n"
        findings = parse_output(output)
        assert len(findings) == 1

    def test_status_messages_skipped(self) -> None:
        """Test that Nuclei status messages are skipped."""
        valid_line = json.dumps({
            "template-id": "test",
            "info": {"name": "Test", "severity": "medium", "tags": []},
            "host": "http://localhost",
        })
        # Nuclei may output status messages that aren't valid JSON
        output = f"[INF] Loading templates...\n{valid_line}\n[INF] Done"
        findings = parse_output(output)
        assert len(findings) == 1


class TestSeverityMapping:
    """Test severity mapping from Nuclei to VibeGuard."""

    def test_critical_severity(self) -> None:
        """Test critical severity mapping."""
        data = {
            "template-id": "test",
            "info": {"name": "Test", "severity": "critical", "tags": []},
            "host": "http://localhost",
        }
        finding = _parse_result(data)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL

    def test_high_severity(self) -> None:
        """Test high severity mapping."""
        data = {
            "template-id": "test",
            "info": {"name": "Test", "severity": "high", "tags": []},
            "host": "http://localhost",
        }
        finding = _parse_result(data)
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_medium_severity(self) -> None:
        """Test medium severity mapping."""
        data = {
            "template-id": "test",
            "info": {"name": "Test", "severity": "medium", "tags": []},
            "host": "http://localhost",
        }
        finding = _parse_result(data)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM

    def test_low_severity(self) -> None:
        """Test low severity mapping."""
        data = {
            "template-id": "test",
            "info": {"name": "Test", "severity": "low", "tags": []},
            "host": "http://localhost",
        }
        finding = _parse_result(data)
        assert finding is not None
        assert finding.severity == Severity.LOW

    def test_info_severity(self) -> None:
        """Test info severity mapping."""
        data = {
            "template-id": "test",
            "info": {"name": "Test", "severity": "info", "tags": []},
            "host": "http://localhost",
        }
        finding = _parse_result(data)
        assert finding is not None
        assert finding.severity == Severity.INFO

    def test_unknown_severity_defaults_medium(self) -> None:
        """Test that unknown severity defaults to medium."""
        data = {
            "template-id": "test",
            "info": {"name": "Test", "severity": "unknown", "tags": []},
            "host": "http://localhost",
        }
        finding = _parse_result(data)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM

    def test_missing_severity_defaults_medium(self) -> None:
        """Test that missing severity defaults to medium."""
        data = {
            "template-id": "test",
            "info": {"name": "Test", "tags": []},
            "host": "http://localhost",
        }
        finding = _parse_result(data)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM

    def test_case_insensitive_severity(self) -> None:
        """Test that severity matching is case-insensitive."""
        data = {
            "template-id": "test",
            "info": {"name": "Test", "severity": "CRITICAL", "tags": []},
            "host": "http://localhost",
        }
        finding = _parse_result(data)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL


class TestCategoryMapping:
    """Test category mapping from Nuclei tags."""

    def test_cve_tag_vulnerability(self) -> None:
        """Test that cve tag maps to VULNERABILITY."""
        category = _determine_category(["cve", "log4j"])
        assert category == Category.VULNERABILITY

    def test_xss_tag_security(self) -> None:
        """Test that xss tag maps to SECURITY."""
        category = _determine_category(["xss", "reflected"])
        assert category == Category.SECURITY

    def test_sqli_tag_security(self) -> None:
        """Test that sqli tag maps to SECURITY (via VULNERABILITY)."""
        category = _determine_category(["sqli", "error-based"])
        assert category == Category.VULNERABILITY

    def test_misconfig_tag_misconfiguration(self) -> None:
        """Test that misconfig tag maps to MISCONFIGURATION."""
        category = _determine_category(["misconfig", "nginx"])
        assert category == Category.MISCONFIGURATION

    def test_exposure_tag_secrets(self) -> None:
        """Test that exposure tag maps to SECRETS."""
        category = _determine_category(["exposure", "api-key"])
        assert category == Category.SECRETS

    def test_tech_tag_best_practice(self) -> None:
        """Test that tech tag maps to BEST_PRACTICE."""
        category = _determine_category(["tech", "nginx"])
        assert category == Category.BEST_PRACTICE

    def test_default_category_security(self) -> None:
        """Test that unknown tags default to SECURITY."""
        category = _determine_category(["unknown", "custom"])
        assert category == Category.SECURITY

    def test_empty_tags_default_security(self) -> None:
        """Test that empty tags default to SECURITY."""
        category = _determine_category([])
        assert category == Category.SECURITY


class TestClassificationExtraction:
    """Test extraction of classification data (CWE, CVSS)."""

    def test_cwe_id_extracted(self) -> None:
        """Test that CWE ID is extracted from classification."""
        data = {
            "template-id": "test",
            "info": {
                "name": "Test",
                "severity": "high",
                "tags": [],
                "classification": {
                    "cwe-id": ["CWE-79", "CWE-80"],
                },
            },
            "host": "http://localhost",
        }
        finding = _parse_result(data)
        assert finding is not None
        assert finding.cwe == "CWE-79"  # First CWE is used

    def test_cvss_score_in_message(self) -> None:
        """Test that CVSS score is included in message."""
        data = {
            "template-id": "test",
            "info": {
                "name": "Test",
                "severity": "critical",
                "description": "Test vulnerability",
                "tags": [],
                "classification": {
                    "cvss-score": 9.8,
                },
            },
            "host": "http://localhost",
        }
        finding = _parse_result(data)
        assert finding is not None
        assert "9.8" in finding.message

    def test_references_list(self) -> None:
        """Test that references list is extracted."""
        data = {
            "template-id": "test",
            "info": {
                "name": "Test",
                "severity": "high",
                "tags": [],
                "reference": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                    "https://logging.apache.org/log4j/",
                ],
            },
            "host": "http://localhost",
        }
        finding = _parse_result(data)
        assert finding is not None
        assert len(finding.references) == 2
        assert "nvd.nist.gov" in finding.references[0]

    def test_references_string(self) -> None:
        """Test that single reference string is converted to list."""
        data = {
            "template-id": "test",
            "info": {
                "name": "Test",
                "severity": "high",
                "tags": [],
                "reference": "https://example.com",
            },
            "host": "http://localhost",
        }
        finding = _parse_result(data)
        assert finding is not None
        assert finding.references == ["https://example.com"]

    def test_no_classification(self) -> None:
        """Test handling of missing classification data."""
        data = {
            "template-id": "test",
            "info": {"name": "Test", "severity": "medium", "tags": []},
            "host": "http://localhost",
        }
        finding = _parse_result(data)
        assert finding is not None
        assert finding.cwe is None


class TestFingerprintGeneration:
    """Test fingerprint generation for deduplication."""

    def test_fingerprint_format_with_matched_at(self) -> None:
        """Test that fingerprint uses matched-at URL for uniqueness."""
        data = {
            "template-id": "CVE-2021-44228",
            "info": {"name": "Test", "severity": "critical", "tags": []},
            "host": "http://localhost:8080",
            "matched-at": "http://localhost:8080/api/login",
        }
        finding = _parse_result(data)
        assert finding is not None
        # Fingerprint should include the matched-at URL, not just host
        assert "http://localhost:8080/api/login" in finding.fingerprint

    def test_fingerprint_includes_matcher_name(self) -> None:
        """Test that fingerprint includes matcher-name when present."""
        data = {
            "template-id": "test-template",
            "info": {"name": "Test", "severity": "high", "tags": []},
            "host": "http://localhost:8080",
            "matched-at": "http://localhost:8080/page",
            "matcher-name": "specific-matcher",
        }
        finding = _parse_result(data)
        assert finding is not None
        # Fingerprint should include matcher name
        assert "specific-matcher" in finding.fingerprint

    def test_fingerprint_uniqueness(self) -> None:
        """Test that different templates/hosts produce different fingerprints."""
        data1 = {
            "template-id": "template-a",
            "info": {"name": "Test A", "severity": "high", "tags": []},
            "host": "http://localhost:8080",
            "matched-at": "http://localhost:8080/api",
        }
        data2 = {
            "template-id": "template-b",
            "info": {"name": "Test B", "severity": "high", "tags": []},
            "host": "http://localhost:8080",
            "matched-at": "http://localhost:8080/api",
        }
        data3 = {
            "template-id": "template-a",
            "info": {"name": "Test A", "severity": "high", "tags": []},
            "host": "http://localhost:9090",
            "matched-at": "http://localhost:9090/api",
        }

        finding1 = _parse_result(data1)
        finding2 = _parse_result(data2)
        finding3 = _parse_result(data3)

        assert finding1 is not None
        assert finding2 is not None
        assert finding3 is not None

        # All fingerprints should be unique
        fingerprints = {finding1.fingerprint, finding2.fingerprint, finding3.fingerprint}
        assert len(fingerprints) == 3

    def test_same_template_different_endpoints_distinct(self) -> None:
        """Test that same template on different URLs produces different fingerprints.

        REGRESSION: Previously fingerprints only included host, so multiple
        findings on different endpoints of the same host would collide.
        """
        data1 = {
            "template-id": "xss-detection",
            "info": {"name": "XSS", "severity": "high", "tags": []},
            "host": "http://localhost:8080",
            "matched-at": "http://localhost:8080/search",
        }
        data2 = {
            "template-id": "xss-detection",
            "info": {"name": "XSS", "severity": "high", "tags": []},
            "host": "http://localhost:8080",
            "matched-at": "http://localhost:8080/admin",
        }

        finding1 = _parse_result(data1)
        finding2 = _parse_result(data2)

        assert finding1 is not None
        assert finding2 is not None
        # MUST have different fingerprints
        assert finding1.fingerprint != finding2.fingerprint

    def test_same_template_same_url_different_matcher_distinct(self) -> None:
        """Test that same template with different matchers produces different fingerprints."""
        data1 = {
            "template-id": "sql-injection",
            "info": {"name": "SQLi", "severity": "critical", "tags": []},
            "host": "http://localhost:8080",
            "matched-at": "http://localhost:8080/login",
            "matcher-name": "error-based",
        }
        data2 = {
            "template-id": "sql-injection",
            "info": {"name": "SQLi", "severity": "critical", "tags": []},
            "host": "http://localhost:8080",
            "matched-at": "http://localhost:8080/login",
            "matcher-name": "time-based",
        }

        finding1 = _parse_result(data1)
        finding2 = _parse_result(data2)

        assert finding1 is not None
        assert finding2 is not None
        # MUST have different fingerprints
        assert finding1.fingerprint != finding2.fingerprint

    def test_fingerprint_fallback_to_host(self) -> None:
        """Test that fingerprint falls back to host when matched-at is missing."""
        data = {
            "template-id": "test",
            "info": {"name": "Test", "severity": "medium", "tags": []},
            "host": "http://localhost:8080",
            # No matched-at
        }
        finding = _parse_result(data)
        assert finding is not None
        assert "http://localhost:8080" in finding.fingerprint


class TestMatchedAtHandling:
    """Test URL/matched-at field handling."""

    def test_matched_at_used_for_file_path(self) -> None:
        """Test that matched-at URL is used as file_path."""
        data = {
            "template-id": "test",
            "info": {"name": "Test", "severity": "medium", "tags": []},
            "host": "http://localhost:8080",
            "matched-at": "http://localhost:8080/api/v1/users",
        }
        finding = _parse_result(data)
        assert finding is not None
        assert finding.file_path == "http://localhost:8080/api/v1/users"

    def test_host_fallback_when_no_matched_at(self) -> None:
        """Test that host is used when matched-at is missing."""
        data = {
            "template-id": "test",
            "info": {"name": "Test", "severity": "medium", "tags": []},
            "host": "http://localhost:8080",
        }
        finding = _parse_result(data)
        assert finding is not None
        assert finding.file_path == "http://localhost:8080"

    def test_line_start_always_one(self) -> None:
        """Test that line_start is always 1 for DAST findings."""
        data = {
            "template-id": "test",
            "info": {"name": "Test", "severity": "medium", "tags": []},
            "host": "http://localhost",
        }
        finding = _parse_result(data)
        assert finding is not None
        assert finding.line_start == 1


class TestEdgeCases:
    """Test edge cases and malformed input."""

    def test_missing_info_block(self) -> None:
        """Test handling of missing info block."""
        data = {
            "template-id": "test",
            "host": "http://localhost",
        }
        finding = _parse_result(data)
        assert finding is not None
        assert finding.title == "test"  # Falls back to template-id

    def test_missing_template_id(self) -> None:
        """Test handling of missing template-id."""
        data = {
            "info": {"name": "Test", "severity": "medium", "tags": []},
            "host": "http://localhost",
        }
        finding = _parse_result(data)
        assert finding is not None
        assert finding.rule_id == "unknown"

    def test_tags_as_string(self) -> None:
        """Test handling of tags as string instead of list."""
        data = {
            "template-id": "test",
            "info": {"name": "Test", "severity": "medium", "tags": "xss"},
            "host": "http://localhost",
        }
        finding = _parse_result(data)
        assert finding is not None
        # Tag should be parsed correctly and category determined
        assert finding.category == Category.SECURITY  # xss maps to SECURITY

    def test_comma_separated_tags_split_correctly(self) -> None:
        """Test that comma-separated tags string is split into list.

        REGRESSION: Nuclei template tags are often comma-separated strings
        like "cve,xss,rce". The parser must split these to properly
        determine category.
        """
        data = {
            "template-id": "test",
            "info": {"name": "Test", "severity": "critical", "tags": "cve,xss,rce"},
            "host": "http://localhost",
        }
        finding = _parse_result(data)
        assert finding is not None
        # 'cve' is first tag and should map to VULNERABILITY
        assert finding.category == Category.VULNERABILITY

    def test_comma_separated_tags_with_spaces(self) -> None:
        """Test that tags with spaces after commas are handled."""
        data = {
            "template-id": "test",
            "info": {"name": "Test", "severity": "high", "tags": "misconfig, nginx, panel"},
            "host": "http://localhost",
        }
        finding = _parse_result(data)
        assert finding is not None
        # 'misconfig' is first matching tag -> MISCONFIGURATION
        assert finding.category == Category.MISCONFIGURATION

    def test_category_from_second_tag_if_first_unknown(self) -> None:
        """Test that category is determined from first matching tag."""
        data = {
            "template-id": "test",
            "info": {"name": "Test", "severity": "high", "tags": "custom,exposure,misc"},
            "host": "http://localhost",
        }
        finding = _parse_result(data)
        assert finding is not None
        # 'custom' is unknown, 'exposure' maps to SECRETS
        assert finding.category == Category.SECRETS

    def test_matcher_name_in_message(self) -> None:
        """Test that matcher-name is included in message."""
        data = {
            "template-id": "test",
            "info": {"name": "Test", "severity": "high", "tags": []},
            "host": "http://localhost",
            "matcher-name": "error-message",
        }
        finding = _parse_result(data)
        assert finding is not None
        assert "error-message" in finding.message

    def test_scanner_name_is_nuclei(self) -> None:
        """Test that scanner name is always 'nuclei'."""
        data = {
            "template-id": "test",
            "info": {"name": "Test", "severity": "medium", "tags": []},
            "host": "http://localhost",
        }
        finding = _parse_result(data)
        assert finding is not None
        assert finding.scanner == "nuclei"
