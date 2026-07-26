"""The shared indicator renderer replaces four copy-pasted dialects."""

import io

from reporting.terminal_reporter._render import (
    Row,
    filter_rows,
    more_hint,
    render_indicators,
)
from tests.conftest import make_console


def render(rows, detail_level=0, width=100, **kwargs):
    buf = io.StringIO()
    render_indicators(
        "INDICATORS",
        rows,
        detail_level,
        console=make_console(width, file=buf),
        **kwargs,
    )
    return buf.getvalue()


def test_info_rows_drop_at_detail_zero_when_signal_exists():
    rows = [Row("Quiet", "nothing", "info"), Row("Loud", "danger", "bad")]
    assert filter_rows(rows, 0) == [Row("Loud", "danger", "bad")]


def test_info_rows_survive_when_nothing_else_fired():
    """A section of only info rows must not render empty."""
    rows = [Row("Quiet", "nothing", "info"), Row("Also quiet", "x", "info")]
    assert filter_rows(rows, 0) == rows


def test_info_rows_return_at_detail_one():
    rows = [Row("Quiet", "nothing", "info"), Row("Loud", "danger", "bad")]
    assert filter_rows(rows, 1) == rows


def test_always_show_labels_survive_filtering():
    rows = [Row("Format", "RAR", "info"), Row("Loud", "danger", "bad")]
    kept = filter_rows(rows, 0, always_show=frozenset({"Format"}))
    assert kept == rows


def test_order_is_preserved():
    """pe.py appended its whitelist rows and doc.py inserted at index 0;
    both reordered relative to the source list. This must not."""
    rows = [
        Row("First", "1", "bad"),
        Row("Second", "2", "info"),
        Row("Third", "3", "bad"),
    ]
    kept = filter_rows(rows, 0, always_show=frozenset({"Second"}))
    assert [r.label for r in kept] == ["First", "Second", "Third"]


def test_warn_rows_are_never_dropped():
    rows = [Row("Warn", "careful", "warn"), Row("Bad", "danger", "bad")]
    assert filter_rows(rows, 0) == rows


def test_row_defaults_to_info():
    assert Row("Label", "value").severity == "info"


def test_empty_rows_render_nothing():
    assert render([]) == ""


def test_title_and_values_appear():
    output = render([Row("Imphash", "f34d5f2d", "info")])
    assert "INDICATORS" in output
    assert "Imphash" in output
    assert "f34d5f2d" in output


def test_long_values_fold_rather_than_truncate():
    long_value = "x" * 300
    output = render([Row("Long", long_value, "bad")])
    assert "…" not in output
    assert output.count("x") == 300


def test_more_hint_wording_is_uniform():
    assert more_hint(7) == "(+7 more — use -v to show all)"


def test_more_hint_is_empty_when_nothing_hidden():
    assert more_hint(0) == ""
    assert more_hint(-1) == ""
