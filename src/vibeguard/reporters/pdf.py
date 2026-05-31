"""PDF report generator (requires weasyprint)."""

from datetime import datetime
from pathlib import Path

from vibeguard.models.scan_result import ScanResult


def to_pdf(result: ScanResult, output_path: Path | None = None) -> Path:
    """Generate PDF report from scan result.

    Uses the existing HTML reporter and converts to PDF via weasyprint.
    weasyprint is an optional dependency; install with:
        pip install vibeguard-cli[pdf]

    Args:
        result: The scan result to convert
        output_path: Optional output path (default: auto-generated filename)

    Returns:
        Path to the generated PDF file

    Raises:
        RuntimeError: If weasyprint is not installed
    """
    try:
        import weasyprint
    except ImportError:
        raise RuntimeError(
            "PDF export requires weasyprint. Install with:\n"
            "  pip install vibeguard-cli[pdf]\n"
            "Note: weasyprint requires system dependencies. "
            "See: https://doc.courtbouillon.org/weasyprint/stable/first_steps.html"
        )

    from vibeguard.reporters.html import to_html

    # Generate HTML content
    html_content = to_html(result)

    # Determine output path
    if output_path is None:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        output_path = Path(f"vibeguard-report-{timestamp}.pdf")

    # PDF-specific CSS for pagination and print layout
    pdf_css = "@page { size: A4 landscape; margin: 1.5cm; }"

    doc = weasyprint.HTML(string=html_content)
    doc.write_pdf(str(output_path), stylesheets=[weasyprint.CSS(string=pdf_css)])

    return output_path
