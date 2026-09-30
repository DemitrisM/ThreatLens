"""Handler failures must reach the report, in both renderers.

`archive_analysis` records every handler failure — a missing backend, a
`BadRarFile`, a `NeedFirstVolume`, an extraction error — into
`meta.handler_errors`, and publishes them as `data["errors"]`.

Neither reporter showed them. The terminal row builder read
`data.get("handler_errors")`, a key the module has never written, so the
`Row("Handler error", …)` branch had never executed for any failure at all.
The HTML builder had no error handling whatsoever.

The consequence is the failure mode this project keeps paying for: measured
with `rarfile` masked, a real RAR scored **8 -> 0** with `status: "success"`
and the reason "No archive indicators fired", while the payload underneath
said `{'stage': 'enumerate_rar', 'error': 'rarfile not installed'}`. The scan
reported a clean archive it had never opened.

Worth noting where this came from. The comment above the module's
`data["errors"] = list(meta.handler_errors)` records an *earlier* fix, for
handler errors being dropped before the caller saw them — "extraction failures
reported as a clean scan". That fix corrected the producer and wrote to a key
no consumer read, so the symptom survived the fix.
"""

from reporting.html_reporter.archive import archive_indicators
from reporting.terminal_reporter.archive import archive_rows

#: The exact shape the module publishes: a list of dicts, not of strings.
_ERRORS = [{"stage": "enumerate_rar", "error": "rarfile not installed"}]


def _data(**over) -> dict:
    base = {
        "detected_format": "rar",
        "classification": "CLEAN",
        "errors": list(_ERRORS),
    }
    base.update(over)
    return base


def test_terminal_rows_show_a_handler_error():
    rows = archive_rows(_data())
    rendered = " ".join(f"{r.label} {r.value}" for r in rows)

    assert "rarfile not installed" in rendered, (
        "the archive handler failed and the terminal report does not say so — "
        f"rows were: {[(r.label, r.value) for r in rows]}"
    )
    assert "enumerate_rar" in rendered, "the failing stage must be named"


def test_the_handler_error_is_readable_not_a_python_literal():
    """A dict rendered with `str()` reaches the analyst as `{'stage': ...}`.

    The branch had never run, so nothing had ever checked what it did with the
    dicts the module actually publishes.
    """
    rows = archive_rows(_data())
    errs = [r for r in rows if "rarfile not installed" in str(r.value)]

    assert errs, "no handler-error row was produced"
    for row in errs:
        assert "{" not in str(row.value) and "'" not in str(row.value), (
            f"the error renders as a raw Python literal: {row.value!r}"
        )


def test_handler_errors_are_shown_at_default_verbosity():
    """Not gated behind -v.

    An analyst reading a default report is the one most likely to mistake a
    degraded scan for a clean one, so this is precisely the audience that
    needs it.
    """
    rendered = " ".join(str(r.value) for r in archive_rows(_data(), detail_level=0))
    assert "rarfile not installed" in rendered


def test_html_report_shows_a_handler_error():
    """The HTML builder is not the terminal one.

    `html_reporter/archive.py` imports only `nested_member_label` from the
    terminal module and builds its own rows, so fixing one does not fix the
    other.
    """
    module_results = [{
        "module": "archive_analysis",
        "status": "success",
        "score_delta": 0,
        "data": _data(),
    }]

    out = archive_indicators(module_results)
    assert out is not None, "the HTML builder produced nothing for a real archive"
    assert "rarfile not installed" in str(out), (
        f"the HTML report omits the handler error: {out}"
    )


def test_no_error_rows_when_nothing_failed():
    """The clean path stays clean — no empty 'Handler error' row."""
    rows = archive_rows(_data(errors=[]))
    assert not [r for r in rows if "handler error" in r.label.lower()]
