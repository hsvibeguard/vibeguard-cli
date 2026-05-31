"""Tests for PDF reporter."""

from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vibeguard.models.finding import Finding, Severity
from vibeguard.models.scan_result import ScanResult


@pytest.fixture
def simple_scan_result() -> ScanResult:
    """Create a simple scan result for PDF testing."""
    finding = Finding(
        scanner="semgrep",
        rule_id="python.security.eval",
        severity=Severity.HIGH,
        title="Use of eval",
        message="Avoid using eval()",
        file_path="app.py",
        line_start=10,
    )
    return ScanResult(
        repo_root="/path/to/repo",
        started_at=datetime.now(),
        finished_at=datetime.now(),
        findings=[finding],
        scanners_run=["semgrep"],
        scanners_skipped=[],
        partial=False,
    )


class TestPdfGeneration:
    """Test PDF report generation."""

    def test_to_pdf_raises_without_weasyprint(self, simple_scan_result: ScanResult) -> None:
        """to_pdf should raise RuntimeError when weasyprint is not installed."""
        with patch.dict("sys.modules", {"weasyprint": None}):
            from vibeguard.reporters.pdf import to_pdf

            # Force re-import by clearing cached module
            import importlib
            import vibeguard.reporters.pdf as pdf_mod
            importlib.reload(pdf_mod)

            with pytest.raises(RuntimeError, match="weasyprint"):
                pdf_mod.to_pdf(simple_scan_result)

    def test_to_pdf_error_message_content(self, simple_scan_result: ScanResult) -> None:
        """Error message should include install instructions."""
        with patch.dict("sys.modules", {"weasyprint": None}):
            import importlib
            import vibeguard.reporters.pdf as pdf_mod
            importlib.reload(pdf_mod)

            with pytest.raises(RuntimeError, match="pip install vibeguard-cli"):
                pdf_mod.to_pdf(simple_scan_result)

    def test_to_pdf_calls_weasyprint(self, simple_scan_result: ScanResult, tmp_path: Path) -> None:
        """to_pdf should generate HTML and pass to weasyprint."""
        mock_weasyprint = MagicMock()
        mock_html_instance = MagicMock()
        mock_weasyprint.HTML.return_value = mock_html_instance
        mock_weasyprint.CSS.return_value = MagicMock()

        with patch.dict("sys.modules", {"weasyprint": mock_weasyprint}):
            import importlib
            import vibeguard.reporters.pdf as pdf_mod
            importlib.reload(pdf_mod)

            output_path = tmp_path / "report.pdf"
            result = pdf_mod.to_pdf(simple_scan_result, output_path=output_path)

            assert result == output_path
            mock_weasyprint.HTML.assert_called_once()
            # Verify HTML string was passed
            call_kwargs = mock_weasyprint.HTML.call_args
            assert "string" in call_kwargs.kwargs or len(call_kwargs.args) == 0
            mock_html_instance.write_pdf.assert_called_once()

    def test_to_pdf_default_filename(self, simple_scan_result: ScanResult) -> None:
        """to_pdf should generate a default filename when none is provided."""
        mock_weasyprint = MagicMock()
        mock_html_instance = MagicMock()
        mock_weasyprint.HTML.return_value = mock_html_instance
        mock_weasyprint.CSS.return_value = MagicMock()

        with patch.dict("sys.modules", {"weasyprint": mock_weasyprint}):
            import importlib
            import vibeguard.reporters.pdf as pdf_mod
            importlib.reload(pdf_mod)

            result = pdf_mod.to_pdf(simple_scan_result)

            assert str(result).startswith("vibeguard-report-")
            assert str(result).endswith(".pdf")

    def test_to_pdf_uses_landscape_a4(self, simple_scan_result: ScanResult, tmp_path: Path) -> None:
        """PDF should use A4 landscape layout."""
        mock_weasyprint = MagicMock()
        mock_html_instance = MagicMock()
        mock_weasyprint.HTML.return_value = mock_html_instance
        mock_css_instance = MagicMock()
        mock_weasyprint.CSS.return_value = mock_css_instance

        with patch.dict("sys.modules", {"weasyprint": mock_weasyprint}):
            import importlib
            import vibeguard.reporters.pdf as pdf_mod
            importlib.reload(pdf_mod)

            pdf_mod.to_pdf(simple_scan_result, output_path=tmp_path / "report.pdf")

            # Verify CSS was created with landscape A4
            css_call = mock_weasyprint.CSS.call_args
            css_string = css_call.kwargs.get("string", "")
            assert "A4 landscape" in css_string

    def test_to_pdf_empty_scan(self, tmp_path: Path) -> None:
        """PDF should generate even with no findings."""
        result = ScanResult(
            repo_root="/clean/repo",
            started_at=datetime.now(),
            finished_at=datetime.now(),
            findings=[],
            scanners_run=["semgrep"],
        )

        mock_weasyprint = MagicMock()
        mock_html_instance = MagicMock()
        mock_weasyprint.HTML.return_value = mock_html_instance
        mock_weasyprint.CSS.return_value = MagicMock()

        with patch.dict("sys.modules", {"weasyprint": mock_weasyprint}):
            import importlib
            import vibeguard.reporters.pdf as pdf_mod
            importlib.reload(pdf_mod)

            output_path = tmp_path / "empty.pdf"
            pdf_mod.to_pdf(result, output_path=output_path)

            mock_weasyprint.HTML.assert_called_once()
            mock_html_instance.write_pdf.assert_called_once()
