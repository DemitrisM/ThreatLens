"""Reason truncation on the FINDINGS table."""

import pytest

from reporting.terminal_reporter._render import truncate_reason


def test_a_short_reason_is_untouched():
    assert truncate_reason("Nothing to see", 120) == "Nothing to see"


def test_a_reason_is_cut_on_a_clause_boundary():
    """Cutting at a character offset landed mid-word.

    Measured on ACRStealer.exe, whose pe_analysis reason is 404
    characters over six clauses: the old `reason[:cap - 3] + "..."`
    rendered `LoadLibraryW (+1 mor...`, which reads as a mangled count
    rather than a truncation, and dropped five findings — including "No
    digital signature found" — with nothing to say they existed.
    """
    reason = (
        "Suspicious imports (several): GetProcAddress, IsDebuggerPresent, "
        "LoadLibraryExA, LoadLibraryExW, LoadLibraryW (+1 more); "
        "Spans 3 suspicious API categories: antidebug, injection, loader; "
        "No digital signature found; Unusual section count (8)"
    )

    out = truncate_reason(reason, 120)

    assert out.startswith("Suspicious imports (several): GetProcAddress")
    assert "mor..." not in out
    assert not out.split("…")[0].rstrip().endswith((",", ";"))


def test_the_dropped_clauses_are_counted_and_the_flag_named():
    reason = "; ".join(f"Finding number {n} with some words" for n in range(8))

    out = truncate_reason(reason, 120)

    assert "more findings" in out
    assert "-vv" in out, "the reader has to be told how to see the rest"
    # Not the `(+N more)` shape: the modules already use it inside a
    # clause for an elided import or domain, and two of them side by
    # side read as one count continuing.
    assert "(+" not in out.split("…")[-1]


def test_truncation_never_makes_the_line_longer():
    """A 125-character reason lost a complete clause to save five chars.

    Adding the hint costs more than the tail it removed, so the whole
    string is shorter than the truncated one. Print it whole.
    """
    reason = (
        "PE with archive payload in overlay (+10); "
        "Embedded executable + risky extension (+5); "
        "Dangerous extension inside archive (+3)"
    )
    assert len(reason) > 120

    assert truncate_reason(reason, 120) == reason


def test_a_single_long_clause_is_cut_on_a_word_boundary():
    """There is no clause boundary to use, so fall back to a space."""
    reason = "One enormous clause with no semicolons " + "padding " * 40

    out = truncate_reason(reason, 120)

    assert len(out) <= 140
    assert "…" in out
    assert not out.replace("…", "").rstrip().endswith("paddin")


@pytest.mark.parametrize("cap", [40, 80, 120, 200])
def test_the_result_is_never_empty(cap):
    reason = "; ".join(f"Clause {n}" for n in range(30))

    assert truncate_reason(reason, cap).strip()


def test_a_single_dropped_clause_is_not_plural():
    """"1 more findings" is the kind of wart a reader notices first."""
    reason = "; ".join(["A" * 110, "B" * 200])

    out = truncate_reason(reason, 120)

    assert "1 more finding —" in out
    assert "findings" not in out


def test_a_long_first_clause_does_not_escape_the_budget():
    """The loop takes the first clause unconditionally.

    So a reason whose opening clause alone overran the budget printed in
    full whenever a second clause existed — dropping the second one to
    make room for a first that was three times the cap.
    """
    reason = "word " * 60 + "first clause; second clause; third clause"

    out = truncate_reason(reason, 120)

    assert len(out) < len(reason)
    assert len(out) <= 120 + 40, f"{len(out)} characters: {out!r}"


def test_a_reason_just_over_the_cap_is_left_whole():
    """Cutting costs a finding; overrunning costs one wrapped line.

    Four real reasons sit between the cap and half again as much — 125,
    138, 161 and 165 characters against a cap of 120. Cutting them
    dropped "Dangerous extension inside archive", "PowerShell
    download/exec, Base64 reference", the social-engineering alert text
    a PDF shows its victim, and two oleid findings, to save between five
    and forty characters each.
    """
    for length in (125, 138, 161, 165):
        reason = "; ".join(["word " * 8] * 4)[:length]
        assert truncate_reason(reason, 120) == reason, length


def test_a_single_clause_well_past_the_tolerance_is_cut():
    """No clause boundary to use, so the cut falls back to a word one."""
    reason = "alpha bravo charlie delta echo foxtrot golf hotel india " * 6

    out = truncate_reason(reason, 120)

    assert out.endswith("…")
    assert len(out) < len(reason)
    assert "findings" not in out, "nothing was dropped — there was one clause"
