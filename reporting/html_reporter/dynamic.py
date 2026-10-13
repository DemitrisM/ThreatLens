"""Dynamic Analysis rows for the HTML template.

Reuses the pure terminal builder rather than re-implementing it — see
``web.py`` in this package for the rationale, and the recommendation
drift fixed in `8669435` for what happens when a mirror is written
twice instead.

The HTML report has no truncation, so it always builds at detail 2 and
the blocked-destination list arrives whole.
"""

from reporting.terminal_reporter.dynamic import dynamic_rows

_HTML_DETAIL = 2


def dynamic_indicators(dynamic: dict | None) -> list:
    """Rows for the Dynamic Analysis table.

    Args:
        dynamic: ``report["dynamic"]``, or None when no provider ran.

    Returns:
        Rows, or empty so the template omits the section. A failed
        detonation returns rows deliberately — that is the disclosure
        D-3 exists for, and dropping it here would reintroduce in HTML
        exactly what the terminal section was built to prevent.
    """
    return dynamic_rows(dynamic, _HTML_DETAIL)
