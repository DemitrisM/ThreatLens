"""Golden-snapshot tests for the terminal reporter.

Characterization tests: they pin what the reporter renders *today* so the
Pass 2 refactor underneath them is provably output-preserving. When a
change to the output is intended, review the diff and regenerate with:

    THREATLENS_UPDATE_SNAPSHOTS=1 .venv/bin/python -m pytest tests/test_report_snapshots.py
"""

import os

import pytest

from tests.conftest import SNAPSHOT_DIR, load_report, render_report

FIXTURES = [
    "redline",
    "netsupport_rar",
    "onenote",
    "giftedcrook_xlsm",
    "clickfix_html",
    "booking_pdf",
]


def assert_snapshot(name: str, actual: str) -> None:
    """Compare against a golden file, or write it when updating."""
    SNAPSHOT_DIR.mkdir(exist_ok=True)
    path = SNAPSHOT_DIR / f"{name}.txt"

    if os.environ.get("THREATLENS_UPDATE_SNAPSHOTS"):
        path.write_text(actual)
        pytest.skip(f"snapshot {name} rewritten")

    assert path.exists(), (
        f"missing snapshot {path} — create it with "
        f"THREATLENS_UPDATE_SNAPSHOTS=1 pytest {__file__}"
    )
    assert actual == path.read_text(), (
        f"render changed for {name}. Review the diff; if the change is "
        f"intended, rerun with THREATLENS_UPDATE_SNAPSHOTS=1"
    )


def test_render_accepts_an_injected_console(report_redline):
    output = render_report(report_redline)
    assert "RedLineStealer.exe" in output
    assert output.count("\n") > 20


def test_render_is_deterministic(report_redline):
    """Same input, same bytes — otherwise snapshots are worthless."""
    assert render_report(report_redline) == render_report(report_redline)


@pytest.mark.parametrize("detail", [0, 1, 2])
@pytest.mark.parametrize("fixture_name", FIXTURES)
def test_snapshot(fixture_name, detail):
    assert_snapshot(
        f"{fixture_name}_detail{detail}",
        render_report(load_report(fixture_name), detail_level=detail),
    )


def test_verbose_levels_differ(report_redline):
    """Before Pass 2b every detail_level site tested >= 1 and none tested
    >= 2, so -vv was byte-identical to -v apart from the logging level."""
    assert render_report(report_redline, 1) != render_report(report_redline, 2)


def test_detail_levels_are_strictly_increasing(report_redline):
    zero, one, two = (render_report(report_redline, d) for d in (0, 1, 2))
    assert len(zero) < len(one) < len(two)


def test_raw_module_data_only_at_detail_two(report_redline):
    assert "RAW MODULE DATA" not in render_report(report_redline, 0)
    assert "RAW MODULE DATA" not in render_report(report_redline, 1)
    assert "RAW MODULE DATA" in render_report(report_redline, 2)


def test_skipped_modules_collapse_to_a_strip_at_detail_zero(report_redline):
    """Six 'Not applicable' rows became one line."""
    zero = render_report(report_redline, 0)
    assert "modules" in zero
    assert zero.count("Not applicable") == 0


def test_full_module_table_returns_at_detail_one(report_redline):
    assert "Module Results" in render_report(report_redline, 1)


def test_score_breakdown_is_not_rendered_twice(report_redline):
    """print_module_table and print_score_breakdown restated the same
    module/delta/reason back to back in two different box styles."""
    zero = render_report(report_redline, 0)
    assert "FINDINGS" in zero
    assert "Score Breakdown" not in zero


def test_no_credential_appears_at_any_detail_level(report_redline):
    for detail in (0, 1, 2):
        assert "api_key" not in render_report(report_redline, detail)
