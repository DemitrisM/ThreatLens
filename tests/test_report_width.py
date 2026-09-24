"""A SHA256 must survive as one unbroken, copy-pasteable run.

Verified empirically before Pass 2a on the real NetSupport RAR sample: a
boxed layout splits a 64-char hash at 80 columns, which breaks
double-click copy-paste into VirusTotal. The flat layout holds down to 66
columns. This is the regression guard for that decision.
"""

import io
import re

import pytest

from reporting.terminal_reporter._render import render_hash_list
from tests.conftest import make_console

SHA = "2cc8ebea55c06981625397b04575ed0eaad9bb9f9dc896355c011a62febe49b5"
ENTRY = ("kqgWNAYv/AudioCapture.dll", "PE32  87.3 KiB", SHA)


def render(width, entries=None, **kwargs):
    buf = io.StringIO()
    render_hash_list(
        "Embedded Executables",
        entries if entries is not None else [ENTRY],
        console=make_console(width, file=buf),
        **kwargs,
    )
    return buf.getvalue()


def test_sha_is_exactly_64_chars():
    """Guard the guard — a typo here would make every assertion vacuous."""
    assert len(SHA) == 64


@pytest.mark.parametrize("width", [66, 80, 100, 120])
def test_sha256_is_never_split(width):
    assert SHA in render(width), f"hash was broken at width {width}"


@pytest.mark.parametrize("width", [66, 80, 100, 120])
def test_sha256_occupies_its_own_line(width):
    """Selecting the line must yield the hash and nothing else."""
    lines = [line.strip() for line in render(width).splitlines()]
    assert SHA in lines, f"hash shares its line at width {width}"


def test_no_ellipsis_in_hash_output():
    output = render(100)
    assert "…" not in output
    assert not re.search(r"\.\.\.", output)


def test_every_hash_survives_when_many_entries():
    entries = [(f"member_{i}.dll", "PE32  1.0 KiB", f"{i:064x}") for i in range(12)]
    output = render(80, entries)
    for _, _, sha in entries:
        assert sha in output


def test_truncation_always_announces_itself():
    """Today's archive caps drop rows with no hint at all."""
    entries = [(f"f{i}.dll", "PE32  1 KiB", f"{i:064x}") for i in range(60)]
    output = render(100, entries, limit=50)
    assert "(+10 more — use -v to show all)" in output


def test_no_truncation_no_hint():
    entries = [(f"f{i}.dll", "PE32  1 KiB", f"{i:064x}") for i in range(3)]
    assert "more" not in render(100, entries, limit=50)


def test_empty_entries_render_nothing():
    assert render(100, []) == ""


# ── wrapped blocks keep their indent ────────────────────────────────


@pytest.mark.parametrize("width", [66, 80, 100, 120])
def test_the_verdict_keeps_its_indent_when_it_wraps(width):
    """The indent was two spaces inside the string, so rich dropped it.

    A wrapped verdict restarted at column 0 while every other block in
    the report stays at column 2, which reads as a stray paragraph
    rather than the continuation of the sentence above it. Measured on
    Grandoreiro.lnk at 100 columns, whose verdict names four findings
    and needs two lines to do it.
    """
    from reporting.terminal_reporter.score import print_score_banner

    scoring = {"total_score": 60, "risk_band": "HIGH", "breakdown": []}
    module_results = [
        {
            "module": "lnk_analysis",
            "status": "success",
            "score_delta": 60,
            "data": {
                "classification": "MALICIOUS",
                "lolbin_target": "powershell.exe",
                "indicator_flags": {
                    "encoded_powershell": True,
                    "icon_masquerade": True,
                    "known_bad_infrastructure": True,
                },
                "tracker": {"machine_id": "laptop-pp7fvpth"},
            },
        }
    ]

    buf = io.StringIO()
    print_score_banner(scoring, module_results, console=make_console(width, file=buf))

    lines = [line for line in buf.getvalue().splitlines() if line.strip()]
    score_line = max(i for i, ln in enumerate(lines) if "/100" in ln)
    verdict_lines = lines[score_line + 1 :]
    assert verdict_lines, "no verdict rendered"
    for line in verdict_lines:
        assert line.startswith("  "), f"width {width}: {line!r} lost the indent"


@pytest.mark.parametrize("width", [66, 80, 100])
def test_the_verdict_carries_no_trailing_whitespace(width):
    """`rich.padding.Padding` fixes the indent and pads to full width.

    That puts trailing spaces on the one line of the report a reader is
    most likely to select and copy, so the wrapping is done here instead.
    """
    from reporting.terminal_reporter.score import print_score_banner

    scoring = {"total_score": 60, "risk_band": "HIGH", "breakdown": []}
    module_results = [
        {
            "module": "lnk_analysis",
            "status": "success",
            "score_delta": 60,
            "data": {
                "classification": "MALICIOUS",
                "lolbin_target": "powershell.exe",
                "indicator_flags": {
                    "encoded_powershell": True,
                    "icon_masquerade": True,
                    "known_bad_infrastructure": True,
                },
                "tracker": {"machine_id": "laptop-pp7fvpth"},
            },
        }
    ]

    buf = io.StringIO()
    print_score_banner(scoring, module_results, console=make_console(width, file=buf))

    for line in buf.getvalue().splitlines():
        assert line == line.rstrip(), f"width {width}: trailing space in {line!r}"


@pytest.mark.parametrize("width", [20, 21, 22, 40])
def test_the_verdict_survives_a_narrow_console(width):
    """A floor above the indent hands the wrapping back to rich.

    `max(20, width - 2)` meant that at any width under 22 the wrapped
    line plus its indent overran the console, rich re-wrapped it, and
    the overflow restarted at column 0 — recreating the bug the manual
    wrapping exists to fix.

    66 columns is the width the report is actually supported at; these
    are the band where that floor misbehaved, not a claim that the rest
    of the layout holds here. Below about 20 the score bar itself wraps
    onto three lines, which this assertion cannot tell from a verdict.
    """
    from reporting.terminal_reporter.score import print_score_banner

    scoring = {"total_score": 60, "risk_band": "HIGH", "breakdown": []}
    module_results = [
        {
            "module": "lnk_analysis",
            "status": "success",
            "score_delta": 60,
            "data": {
                "classification": "MALICIOUS",
                "lolbin_target": "powershell.exe",
                "indicator_flags": {"encoded_powershell": True},
            },
        }
    ]

    buf = io.StringIO()
    print_score_banner(scoring, module_results, console=make_console(width, file=buf))

    # Everything after the score line. Sliced this way rather than by
    # index because the bar itself wraps below about forty columns, and
    # its continuation is not a verdict line.
    lines = [ln for ln in buf.getvalue().splitlines() if ln.strip()]
    score_line = max(i for i, ln in enumerate(lines) if "/100" in ln)
    verdict_lines = lines[score_line + 1 :]

    assert verdict_lines
    for line in verdict_lines:
        assert line.startswith("  "), f"width {width}: {line!r} lost the indent"


@pytest.mark.parametrize("width", [66, 80, 100, 120])
def test_a_narrow_ioc_table_does_not_wrap_its_own_title(width):
    """rich centres a table title inside the table, then wraps it.

    "Indicators of Compromise (IOCs)" is 31 characters, and a scan whose
    only IOC is a short domain builds a table narrower than that — so
    the heading broke across two lines and read as a layout fault.
    Measured on AgentTesla.html, whose single IOC is "link.click".
    """
    from reporting.terminal_reporter._common import use_console
    from reporting.terminal_reporter.tables import print_ioc_table

    module_results = [
        {
            "module": "ioc_extractor",
            "status": "success",
            "data": {"iocs": {"domain": ["link.click"]}, "total_iocs": 1},
            # The full module contract, not only the keys this reader
            # touches — a mock that drops them stops being a check that
            # the reporter handles what a module really returns.
            "score_delta": 5,
            "reason": "Domains: link.click",
            "elapsed_seconds": 0.01,
        }
    ]

    buf = io.StringIO()
    with use_console(make_console(width, file=buf)):
        print_ioc_table(module_results, 0)
    output = buf.getvalue()

    assert "Indicators of Compromise (IOCs)" in output, output
