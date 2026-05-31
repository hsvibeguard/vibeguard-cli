"""Tests for HTML reporter."""

from datetime import datetime

from vibeguard.models.finding import Finding, Severity
from vibeguard.models.scan_result import ScanResult
from vibeguard.reporters.html import to_html


class TestHtmlStructure:
    """Test HTML document structure."""

    def test_html_is_valid_document(self, sample_scan_result: ScanResult) -> None:
        """HTML should be a valid document with proper structure."""
        html = to_html(sample_scan_result)
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html
        assert "<head>" in html
        assert "</head>" in html
        assert "<body>" in html
        assert "</body>" in html

    def test_html_has_meta_charset(self, sample_scan_result: ScanResult) -> None:
        """HTML should have UTF-8 charset declaration."""
        html = to_html(sample_scan_result)
        assert 'charset="UTF-8"' in html or "charset=UTF-8" in html

    def test_html_has_viewport_meta(self, sample_scan_result: ScanResult) -> None:
        """HTML should have viewport meta for responsive design."""
        html = to_html(sample_scan_result)
        assert "viewport" in html

    def test_html_has_title(self, sample_scan_result: ScanResult) -> None:
        """HTML should have a title."""
        html = to_html(sample_scan_result)
        assert "<title>" in html
        assert "VibeGuard" in html


class TestHtmlEmbeddedCss:
    """Test embedded CSS in HTML."""

    def test_html_contains_embedded_css(self, sample_scan_result: ScanResult) -> None:
        """HTML should have embedded CSS styles."""
        html = to_html(sample_scan_result)
        assert "<style>" in html
        assert "</style>" in html

    def test_css_has_root_variables(self, sample_scan_result: ScanResult) -> None:
        """CSS should have CSS custom properties (variables)."""
        html = to_html(sample_scan_result)
        assert ":root" in html
        assert "--bg-primary" in html


class TestHtmlContent:
    """Test HTML content generation."""

    def test_html_contains_score(self, sample_scan_result: ScanResult) -> None:
        """HTML should contain the security score."""
        html = to_html(sample_scan_result)
        assert str(sample_scan_result.score) in html

    def test_html_contains_grade(self, sample_scan_result: ScanResult) -> None:
        """HTML should contain the grade."""
        html = to_html(sample_scan_result)
        assert sample_scan_result.grade in html

    def test_html_contains_repo_path(self, sample_scan_result: ScanResult) -> None:
        """HTML should contain the repo path."""
        html = to_html(sample_scan_result)
        # Path is escaped, so check for escaped version or original
        assert sample_scan_result.repo_root in html or "/path/to/repo" in html

    def test_html_contains_scanners_run(self, sample_scan_result: ScanResult) -> None:
        """HTML should list scanners that were run."""
        html = to_html(sample_scan_result)
        for scanner in sample_scan_result.scanners_run:
            assert scanner in html


class TestHtmlFindings:
    """Test HTML findings table."""

    def test_html_contains_findings_count(
        self, sample_scan_result: ScanResult
    ) -> None:
        """HTML should show findings count."""
        html = to_html(sample_scan_result)
        assert f"Findings ({len(sample_scan_result.findings)})" in html

    def test_html_contains_finding_details(
        self, sample_scan_result: ScanResult
    ) -> None:
        """HTML should contain finding details."""
        html = to_html(sample_scan_result)
        finding = sample_scan_result.findings[0]
        assert finding.scanner in html
        assert finding.file_path in html
        assert str(finding.line_start) in html


class TestHtmlXssPrevention:
    """Test XSS prevention in HTML output."""

    def test_html_escapes_script_tags(self) -> None:
        """HTML should escape script tags to prevent XSS."""
        malicious_finding = Finding(
            scanner="test",
            rule_id="xss-test",
            severity=Severity.HIGH,
            title="<script>alert('xss')</script>",
            message="Test <script>alert('xss')</script> message",
            file_path="<script>alert('xss')</script>.py",
            line_start=1,
        )
        result = ScanResult(
            repo_root="/path/to/repo",
            started_at=datetime.now(),
            findings=[malicious_finding],
            scanners_run=["test"],
        )
        html = to_html(result)

        # Should NOT contain unescaped script tags
        assert "<script>alert" not in html
        # Should contain escaped versions
        assert "&lt;script&gt;" in html or "\\u003c" in html

    def test_html_escapes_html_entities(self) -> None:
        """HTML should escape HTML entities in user content."""
        finding = Finding(
            scanner="test",
            rule_id="entity-test",
            severity=Severity.MEDIUM,
            title="Test & <special> \"chars\"",
            message="Message with <b>html</b> & entities",
            file_path="test.py",
            line_start=1,
        )
        result = ScanResult(
            repo_root="/path",
            started_at=datetime.now(),
            findings=[finding],
            scanners_run=["test"],
        )
        html = to_html(result)

        # Ampersands should be escaped
        assert "&amp;" in html
        # Angle brackets should be escaped in content
        assert "&lt;special&gt;" in html or "&lt;b&gt;" in html


class TestHtmlEmptyScan:
    """Test HTML generation with no findings."""

    def test_empty_scan_shows_success_message(self) -> None:
        """Empty scan should show success message."""
        result = ScanResult(
            repo_root="/clean/repo",
            started_at=datetime.now(),
            finished_at=datetime.now(),
            findings=[],
            scanners_run=["semgrep"],
        )
        html = to_html(result)
        assert "No security findings" in html or "Great job" in html


class TestHtmlPartialScan:
    """Test HTML generation for partial scans."""

    def test_partial_scan_shows_warning(self) -> None:
        """Partial scan should show warning message."""
        result = ScanResult(
            repo_root="/repo",
            started_at=datetime.now(),
            finished_at=datetime.now(),
            findings=[],
            scanners_run=["semgrep"],
            scanners_skipped=["trivy"],
            partial=True,
        )
        html = to_html(result)
        assert "partial" in html.lower() or "warning" in html.lower()


class TestHtmlSeverityColors:
    """Test severity color coding in HTML."""

    def test_different_severities_have_colors(self) -> None:
        """Each severity should have a distinct color style."""
        findings = [
            Finding(
                scanner="test",
                rule_id=f"rule-{sev.value}",
                severity=sev,
                title=f"{sev.value} finding",
                message="Test",
                file_path="test.py",
                line_start=i + 1,
            )
            for i, sev in enumerate(
                [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
            )
        ]
        result = ScanResult(
            repo_root="/repo",
            started_at=datetime.now(),
            findings=findings,
            scanners_run=["test"],
        )
        html = to_html(result)

        # Each severity should appear in the output
        for sev in ["critical", "high", "medium", "low"]:
            assert sev in html.lower()


class TestHtmlFindingsLimit:
    """Test findings display limit."""

    def test_limits_displayed_findings(self) -> None:
        """HTML should limit displayed findings to prevent huge pages."""
        # Create 250 findings
        findings = [
            Finding(
                scanner="test",
                rule_id=f"rule-{i}",
                severity=Severity.LOW,
                title=f"Finding {i}",
                message=f"Message {i}",
                file_path=f"file{i}.py",
                line_start=i + 1,
            )
            for i in range(250)
        ]
        result = ScanResult(
            repo_root="/repo",
            started_at=datetime.now(),
            findings=findings,
            scanners_run=["test"],
        )
        html = to_html(result)

        # Should mention the limit
        assert "250" in html  # Total count shown in header
        # HTML size should be reasonable (not explode with all 250)
        # Just check it doesn't contain all 250 rule IDs
        rule_count = sum(1 for i in range(250) if f"rule-{i}" in html)
        assert rule_count <= 200  # Limit is 200
