"""D-3 and D-4 — the Dynamic Analysis section.

D-3: a failed detonation renders as a visible notice.
D-4: denied egress appears in the report, not only in the command.

Both exist because a dynamic report's silence is ambiguous. A run that
observed nothing and a run that never happened produce the same empty
payload; a sample that contacted no C2 and a harness that blocked the
network produce the same empty connection log. In each pair one is a
finding and the other is an artefact of the setup, and only an explicit
statement tells them apart.

Asserted against rendered text wherever the claim is about what a reader
sees. The row list is an intermediate: the project's standing lesson is
that eight reporting defects survived a thousand green tests because the
tests checked structures instead of output.
"""

import io

import pytest
from rich.console import Console

from core import detonation as det
from reporting.html_reporter.dynamic import dynamic_indicators
from reporting.terminal_reporter.dynamic import dynamic_rows, print_dynamic_section
from reporting.terminal_reporter._common import use_console


def _provider(state=det.OBSERVED, reason="ran", egress_state=None,
              blocked=None, module="dynamic_speakeasy", status="success"):
    """A provider result.

    `status` is a parameter, not a constant, and that matters: hardcoding
    "success" meant the test claiming this section renders a NON-success
    result never passed one, so an early-return guard on status would
    have gone undetected. Raised in review.
    """
    data = {"detonation": det.build(state, reason)}
    if egress_state is not None:
        data["egress"] = det.egress(egress_state, blocked)
    return {"module": module, "status": status, "data": data,
            "score_delta": 0, "reason": ""}


def _render(dynamic, detail_level=0, width=100) -> str:
    """Render the section the way a user sees it, not as a row list."""
    buf = io.StringIO()
    console = Console(file=buf, width=width, no_color=True, highlight=False)
    with use_console(console):
        print_dynamic_section(dynamic, detail_level)
    return buf.getvalue()


# ----------------------------------------------------------------------
# D-3 — the failed detonation is visible
# ----------------------------------------------------------------------

@pytest.mark.parametrize("status", ["success", "error", "skipped"])
def test_a_failed_detonation_is_rendered_whatever_the_status(status):
    """Every other section returns early on a non-success result. This
    one must not: a failure is the thing D-3 exists to disclose, and an
    errored provider is exactly the case where a reader would otherwise
    see a report that looks complete.

    Parametrised over the status because an earlier version only ever
    passed "success" while claiming to prove the opposite."""
    out = _render(_provider(det.FAILED, "emulator aborted", status=status))
    assert "Dynamic Analysis" in out, status
    assert "FAILED" in out, status
    assert "emulator aborted" in out, status


def test_the_failure_says_the_report_is_static_only():
    """The sentence a reader needs. "Detonation failed" alone invites
    them to read the rest as though dynamic analysis had happened."""
    out = _render(_provider(det.FAILED, "emulator aborted"))
    assert "static only" in out


def test_the_reason_reaches_the_reader():
    """A denied network and a crashed emulator lead to opposite next
    steps, so the cause cannot stay in the log."""
    out = _render(_provider(det.FAILED, "egress denied by policy"))
    assert "egress denied by policy" in out


def test_the_notice_survives_the_default_detail_level():
    """Not gated on -v. The reader most likely to mistake a partial
    analysis for a complete one is the one reading a default report."""
    assert "FAILED" in _render(_provider(det.FAILED, "x"), detail_level=0)


def test_the_detonation_row_comes_first():
    """Prepended, never appended — a notice at the end of a section is
    the first thing truncation eats. The doc_analysis `Pass unavailable`
    rows earned this lesson."""
    rows = dynamic_rows(_provider(det.FAILED, "x", det.EGRESS_DENIED, ["a"]))
    assert rows[0].label == "Detonation"


def test_a_failed_detonation_is_not_coloured_as_a_threat():
    """It is a gap in the analysis, not evidence against the sample.
    Rendering it as `bad` would be its own kind of lie — and it would
    rank above real findings in a severity-sorted table."""
    rows = dynamic_rows(_provider(det.FAILED, "x"))
    assert rows[0].severity == "warn"


def test_not_attempted_is_quieter_than_failed():
    """No provider armed is the default posture, not a shortcoming."""
    rows = dynamic_rows(_provider(det.NOT_ATTEMPTED, "no provider"))
    assert rows[0].severity == "info"
    assert "not attempted" in rows[0].value


def test_no_provider_renders_no_section_at_all():
    """`report["dynamic"]` is None on every static scan. A section
    saying "not attempted" on all of them would be true, useless, and
    present on every report this tool has ever produced."""
    assert _render(None) == ""
    assert dynamic_rows(None) == []


def test_an_observed_detonation_says_so_plainly():
    out = _render(_provider(det.OBSERVED, "ran"))
    assert "observed" in out
    assert "FAILED" not in out


# ----------------------------------------------------------------------
# D-4 — egress is stated, not implied
# ----------------------------------------------------------------------

def test_denied_egress_says_absence_is_not_evidence():
    """The whole rule in one assertion. Without this line a reader sees
    an empty connection list and concludes the sample has no C2."""
    out = _render(_provider(egress_state=det.EGRESS_DENIED))
    assert "DENIED" in out
    assert "not evidence" in out


def test_allowed_egress_says_absence_is_meaningful():
    """The converse matters too: if the network was open and nothing was
    contacted, that IS a finding and the reader should know it counts."""
    out = _render(_provider(egress_state=det.EGRESS_ALLOWED))
    assert "allowed" in out
    assert "meaningful" in out


def test_unknown_egress_makes_no_claim():
    """An emulator with no network model has no honest answer. Printing
    "allowed" there would fabricate the exact reassurance D-4 forbids."""
    out = _render(_provider(egress_state=det.EGRESS_UNKNOWN))
    assert "egress" not in out.lower()


def test_egress_is_absent_when_the_provider_never_said():
    out = _render(_provider())
    assert "egress" not in out.lower()


def test_blocked_destinations_are_named_with_a_count():
    """Count in the value, names in rows — the doc_analysis lesson. The
    reader sees the scale even when the list is cut."""
    out = _render(_provider(egress_state=det.EGRESS_DENIED,
                            blocked=["http://a.example", "http://b.example"]))
    assert "2 reached for" in out
    assert "a.example" in out


def test_a_long_blocked_list_is_capped_and_says_so():
    """Truncation must announce itself — every cap in this reporter
    does, because a silently shortened list reads as a complete one."""
    blocked = [f"http://host{i}.example" for i in range(12)]
    out = _render(_provider(egress_state=det.EGRESS_DENIED, blocked=blocked),
                  detail_level=0)
    assert "12 reached for" in out
    assert "more" in out and "-v" in out


def test_verbose_lifts_the_blocked_cap():
    blocked = [f"http://host{i}.example" for i in range(12)]
    out = _render(_provider(egress_state=det.EGRESS_DENIED, blocked=blocked),
                  detail_level=1)
    assert "host11.example" in out
    assert "more — use -v" not in out


def test_the_disclosures_survive_every_guarded_width():
    """Wrapping is fine for a reader; losing the claim is not.

    The first draft of the egress line ran long enough that "not
    evidence" landed split across the wrap, and at narrow widths it
    still wraps — so this normalises whitespace and asserts the sentence
    is READABLE rather than asserting where rich chose to break it. The
    widths are the ones `test_report_width.py` already guards.

    This is the defect class that cost eight reporting fixes: a row list
    that looks right and rendered output that does not."""
    import re

    dynamic = _provider(det.FAILED, "emulator aborted",
                        det.EGRESS_DENIED, ["http://a.example"])
    for width in (66, 80, 100, 120):
        flat = re.sub(r"\s+", " ", _render(dynamic, width=width))
        assert "FAILED" in flat, width
        assert "static only" in flat, width
        assert "absence of C2 contact is not evidence" in flat, width
        assert "emulator aborted" in flat, width


def test_the_truncation_notice_is_not_filtered_away():
    """It was. The overflow row was `info`, and detail 0 hides info rows
    whenever something louder fired — which is precisely when a blocked
    list is long enough to need cutting. The cap announced itself only
    on reports where nothing had been truncated.

    Every cap in this reporter announces itself; a silently shortened
    list reads as a complete one."""
    blocked = [f"http://host{i}.example" for i in range(12)]
    out = _render(_provider(det.OBSERVED, "ran",
                            det.EGRESS_DENIED, blocked))
    assert "+7 more" in out


def test_blocked_destinations_need_an_observed_detonation():
    """A blocked destination says the SAMPLE reached for that host —
    a behavioural finding, which D-2 permits only on `observed`.

    This cuts against the project's standing preference for noise over
    a missed IOC, and the trade is deliberate: a destination recovered
    from a run that did not complete is exactly the half-observed
    evidence D-2 exists to keep out, and nothing on the page would tell
    an analyst it was unverified. Raised in review."""
    blocked = ["http://a.example", "http://b.example"]
    out = _render(_provider(det.FAILED, "aborted", det.EGRESS_DENIED, blocked))
    assert "a.example" not in out
    assert "reached for" not in out


def test_the_egress_policy_is_stated_even_when_detonation_failed():
    """The other half of the same rule. The policy is a fact about the
    HARNESS and is true whether or not the sample ran, so suppressing it
    would hide the very disclosure D-4 requires — and a failed run with
    a denied network is precisely when a reader is most likely to draw
    the wrong conclusion from silence."""
    out = _render(_provider(det.FAILED, "aborted", det.EGRESS_DENIED,
                            ["http://a.example"]))
    assert "DENIED" in out
    assert "not evidence" in out


def test_the_provider_is_named_even_without_the_orchestrator_prefix():
    """The orchestrator labels a provider with
    `setdefault("module", f"dynamic_{name}")`, so one that names itself
    keeps its own name and never gains the prefix. Gating the row on
    that prefix dropped it silently for exactly those providers."""
    out = _render(_provider(module="speakeasy"))
    assert "speakeasy" in out
    prefixed = _render(_provider(module="dynamic_speakeasy"))
    assert "dynamic_speakeasy" not in prefixed
    assert "speakeasy" in prefixed


def test_a_top_level_reason_is_used_when_there_is_no_detonation_block():
    """Design rule 2's graceful-skip shape has `data: {}` and puts the
    explanation at the top level. Reading only the detonation block lost
    the one sentence explaining the gap."""
    skipped = {
        "module": "dynamic_speakeasy", "status": "skipped", "data": {},
        "score_delta": 0, "reason": "speakeasy is not installed",
    }
    rows = dynamic_rows(skipped)
    assert any("not installed" in r.value for r in rows)
    # And at the rendered level, which is this file's stated discipline
    # and was missing here. Whether the row survives the severity filter
    # on the way to the page is a separate question from whether it was
    # built. Raised in review.
    assert "not installed" in _render(skipped)


# ----------------------------------------------------------------------
# Robustness — a provider result is not trusted input
# ----------------------------------------------------------------------

@pytest.mark.parametrize("bad", [None, "string", 42, [], {"data": "not a dict"}])
def test_malformed_input_never_raises(bad):
    """Design rule 2 reaches the reporters too: a broken provider must
    not take down the report that would have explained it."""
    dynamic_rows(bad)
    _render(bad)


def test_a_result_with_no_detonation_block_still_renders_the_state():
    """state_of resolves it rather than leaving the section blank —
    a provider that said nothing must not read as one that ran fine."""
    rows = dynamic_rows({"module": "dynamic_x", "status": "success", "data": {}})
    assert rows[0].label == "Detonation"
    assert rows[0].value != _STATE_OBSERVED_TEXT


_STATE_OBSERVED_TEXT = "observed — the sample ran and its behaviour was recorded"


# ----------------------------------------------------------------------
# The HTML mirror
#
# Written as a reuse of the terminal builder on purpose. The
# recommendations pair drifted precisely because the advice was written
# twice, and that cost three defects.
# ----------------------------------------------------------------------

@pytest.mark.parametrize("state", [det.OBSERVED, det.FAILED, det.NOT_ATTEMPTED])
def test_the_html_mirror_reuses_the_terminal_rows(state):
    """Parity across every state, with blocked destinations present.

    The first version passed FAILED with a blocked list — which D-2
    suppresses — so the argument exercised nothing and parity on the
    blocked rows went untested. Raised in review, and the same dead-
    parameter shape that cost several rounds today."""
    dynamic = _provider(state, "x", det.EGRESS_DENIED,
                        ["http://a.example", "http://b.example"])
    assert dynamic_indicators(dynamic) == dynamic_rows(dynamic, 2)


def test_the_html_mirror_also_renders_a_failed_detonation():
    """Dropping it here would reintroduce in HTML exactly what the
    terminal section was built to prevent."""
    rows = dynamic_indicators(_provider(det.FAILED, "aborted"))
    assert any("FAILED" in r.value for r in rows)


def test_the_html_mirror_shows_every_blocked_destination():
    """No truncation in HTML, so the cap must not follow it there."""
    blocked = [f"http://host{i}.example" for i in range(12)]
    rows = dynamic_indicators(_provider(egress_state=det.EGRESS_DENIED,
                                        blocked=blocked))
    assert sum(1 for r in rows if r.label == "Blocked") == 12
