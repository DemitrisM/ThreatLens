"""Windows Shortcut Indicator rows for the HTML template.

Follows the newer of the two patterns in this package (as ``web.py`` and
``pdf.py`` do): the terminal builder is already a pure function returning
``Row`` namedtuples, which Jinja reaches by attribute exactly as it would
a dict — so both reporters share one source and cannot drift apart.

HTML is the archival format with no verbosity axis, so it renders at the
highest detail level: shell items, property store, structural flags and
all.
"""

from reporting.terminal_reporter.lnk import lnk_rows

_HTML_DETAIL = 2


def lnk_indicators(module_results: list[dict]) -> list:
    """Rows for the Windows Shortcut Indicators table."""
    result = next(
        (r for r in module_results if r.get("module") == "lnk_analysis"), None
    )
    if not result or result.get("status") != "success":
        return []
    return lnk_rows(result.get("data") or {}, _HTML_DETAIL)


def lnk_shell_items(module_results: list[dict]) -> list[dict]:
    """Decoded IDList entries, including the NTFS file references."""
    result = next(
        (r for r in module_results if r.get("module") == "lnk_analysis"), None
    )
    if not result or result.get("status") != "success":
        return []
    return (result.get("data") or {}).get("shell_items") or []


def lnk_property_store(module_results: list[dict]) -> list[dict]:
    """Decoded PropertyStoreDataBlock properties, empty values dropped."""
    result = next(
        (r for r in module_results if r.get("module") == "lnk_analysis"), None
    )
    if not result or result.get("status") != "success":
        return []
    properties = (result.get("data") or {}).get("property_store") or []
    return [p for p in properties if p.get("value")]
