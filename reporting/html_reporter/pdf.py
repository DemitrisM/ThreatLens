"""PDF Indicator rows for the HTML template.

Reuses the pure terminal builder rather than re-implementing it — see
``web.py`` in this package for the rationale.
"""

from reporting.terminal_reporter.pdf import pdf_rows

_HTML_DETAIL = 2


def pdf_indicators(module_results: list[dict]) -> list:
    """Rows for the PDF Indicators table."""
    result = next(
        (r for r in module_results if r.get("module") == "pdf_analysis"), None
    )
    if not result or result.get("status") != "success":
        return []
    return pdf_rows(result.get("data") or {}, _HTML_DETAIL)
