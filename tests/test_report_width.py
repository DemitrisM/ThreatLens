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
