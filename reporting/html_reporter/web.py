"""HTML Smuggling Indicator rows for the HTML template.

Unlike the older ``pe.py``/``doc.py`` here, this does **not** re-implement
the row logic. Pass 2 made the terminal builders pure functions returning
``Row(label, value, severity)`` namedtuples, and Jinja reaches those by
attribute exactly as it does a dict — so both reporters share one source
and cannot drift apart.

HTML is the archival format with no verbosity axis, so it renders at the
highest detail level: everything, nothing truncated.
"""

from reporting.terminal_reporter.web import html_rows

_HTML_DETAIL = 2


def html_indicators(module_results: list[dict]) -> list:
    """Rows for the HTML Smuggling Indicators table."""
    result = next(
        (r for r in module_results if r.get("module") == "html_analysis"), None
    )
    if not result or result.get("status") != "success":
        return []
    return html_rows(result.get("data") or {}, _HTML_DETAIL)
