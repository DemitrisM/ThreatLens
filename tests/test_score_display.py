"""Score bar, module status strip, and the merged FINDINGS table."""

import io

import pytest

from reporting.terminal_reporter._render import module_strip, score_bar
from tests.conftest import make_console

BAR_WIDTH = 22


def plain(text: str) -> str:
    """Strip rich markup so assertions read the glyphs, not the styling."""
    import re

    return re.sub(r"\[/?[a-z0-9 _#]+\]", "", text)


# ------------------------------------------------------------------ score bar


def test_score_bar_is_empty_at_zero():
    assert plain(score_bar(0, "LOW", width=BAR_WIDTH)).count("█") == 0


def test_score_bar_is_full_at_one_hundred():
    assert plain(score_bar(100, "CRITICAL", width=BAR_WIDTH)).count("█") == BAR_WIDTH


def test_score_bar_length_is_constant():
    """Otherwise bars at different scores do not line up when stacked."""
    for score in (0, 7, 31, 68, 99, 100):
        bar = plain(score_bar(score, "LOW", width=BAR_WIDTH))
        assert bar.count("█") + bar.count("░") == BAR_WIDTH


def test_score_bar_is_monotonic():
    """A higher score can never draw fewer filled cells."""
    filled = [plain(score_bar(s, "LOW", width=BAR_WIDTH)).count("█") for s in range(101)]
    assert filled == sorted(filled)


def test_score_bar_distinguishes_low_from_high():
    """The whole point — 12 and 98 used to render identically."""
    assert plain(score_bar(12, "LOW", width=BAR_WIDTH)) != plain(
        score_bar(98, "CRITICAL", width=BAR_WIDTH)
    )


def test_score_bar_clamps_out_of_range_scores():
    assert plain(score_bar(-5, "LOW", width=BAR_WIDTH)).count("█") == 0
    assert plain(score_bar(150, "CRITICAL", width=BAR_WIDTH)).count("█") == BAR_WIDTH


def test_score_bar_carries_the_band_colour():
    assert "red" in score_bar(90, "CRITICAL", width=BAR_WIDTH)


# --------------------------------------------------------------- module strip


def results(*specs):
    return [{"module": m, "status": s, "score_delta": 0} for m, s in specs]


def test_module_strip_counts_ran_and_not_applicable():
    strip = plain(
        module_strip(results(("a", "success"), ("b", "success"), ("c", "skipped")))
    )
    assert "2 ran" in strip
    assert "1 n/a" in strip


def test_module_strip_uses_one_glyph_per_module():
    strip = plain(module_strip(results(("a", "success"), ("b", "skipped"))))
    assert strip.count("✓") == 1
    assert strip.count("○") == 1


def test_module_strip_marks_errors_distinctly():
    strip = plain(module_strip(results(("a", "success"), ("b", "error"))))
    assert "✗" in strip
    assert "1 error" in strip


def test_module_strip_is_empty_without_results():
    assert module_strip([]) == ""


def test_module_strip_replaces_six_not_applicable_rows(report_redline):
    """The RedLine baseline spent 6 of 116 lines on 'Not applicable'."""
    strip = plain(module_strip(report_redline["module_results"]))
    assert "n/a" in strip
    assert strip.count("\n") == 0


# ------------------------------------------------------------------- findings


def test_findings_shows_only_scoring_modules(report_redline):
    from reporting.terminal_reporter.score import print_findings

    buf = io.StringIO()
    print_findings(
        report_redline["scoring"],
        report_redline["module_results"],
        0,
        console=make_console(file=buf),
    )
    output = buf.getvalue()
    assert "FINDINGS" in output
    assert "Not applicable" not in output
    for entry in report_redline["scoring"]["breakdown"]:
        assert entry["module"] in output


def test_findings_renders_nothing_when_no_module_scored():
    from reporting.terminal_reporter.score import print_findings

    buf = io.StringIO()
    print_findings(
        {"breakdown": [], "total_score": 0, "risk_band": "LOW"},
        [],
        0,
        console=make_console(file=buf),
    )
    assert buf.getvalue().strip() == ""


def test_findings_reason_is_untruncated_at_detail_two(report_redline):
    """-vv exists to show the whole reason; detail 0 caps it at 120."""
    from reporting.terminal_reporter._common import LIMITS
    from reporting.terminal_reporter.score import print_findings

    long_reason = "R" * 400
    scoring = {
        "total_score": 50,
        "risk_band": "MEDIUM",
        "breakdown": [
            {"module": "string_analysis", "score_delta": 50, "reason": long_reason}
        ],
    }

    def render(detail):
        buf = io.StringIO()
        print_findings(scoring, [], detail, console=make_console(200, file=buf))
        return buf.getvalue()

    assert render(2).count("R") > LIMITS["reason_chars"]
    assert render(0).count("R") <= LIMITS["reason_chars"]
