"""D-2 — the three-valued detonation state.

The rule: "did it detonate" is a reported fact with three values, not
two, and no reporter may render a behavioural finding unless the value is
``observed``.

What these tests are really defending is the distinction between *we
looked and saw nothing* and *we never got to look*. Those produce an
identical empty payload, so nothing but an explicit state keeps them
apart — and scoring them the same way turns "we did not see it" into "it
is not there".
"""

import copy
import logging

import pytest

from core import detonation as det


# ----------------------------------------------------------------------
# build() — the provider-side constructor
# ----------------------------------------------------------------------

def test_build_returns_the_block_shape_normalise_expects():
    block = det.build(det.OBSERVED, "emulated 412 API calls")
    assert block == {"state": "observed", "reason": "emulated 412 API calls"}


def test_build_rejects_an_unknown_state():
    """The one place in the dynamic path that raises, deliberately.

    build() is called by provider code at construction time, not by the
    orchestrator on untrusted input, so a typo is a bug to surface rather
    than a hostile value to absorb."""
    with pytest.raises(ValueError, match="unknown detonation state"):
        det.build("detonated", "typo for observed")


def test_build_allows_an_observed_state_with_no_reason():
    """An observed detonation is self-explanatory — the findings are the
    reason. The two non-observed states are the ones that owe an
    explanation."""
    assert det.build(det.OBSERVED)["reason"] == ""


# ----------------------------------------------------------------------
# normalise() — the orchestrator-side enforcement
#
# Every test here builds the result the way _run_dynamic_provider hands it
# over: data/status/score_delta already defaulted.
# ----------------------------------------------------------------------

def _result(delta=0, status="success", data=None):
    return {
        "module": "dynamic_speakeasy",
        "status": status,
        "data": {} if data is None else data,
        "score_delta": delta,
        "reason": "",
    }


def test_a_missing_state_becomes_failed_not_observed(caplog):
    """The direction matters more than the value.

    A provider that does not report its state has told us nothing, and
    the only state that can move a score is `observed` — so defaulting
    anywhere near it would let a silent provider score."""
    result = _result()
    with caplog.at_level(logging.WARNING, logger="core.detonation"):
        det.normalise(result, "speakeasy")
    assert result["data"]["detonation"]["state"] == det.FAILED
    assert "no detonation state" in caplog.text


def test_a_missing_state_is_failed_rather_than_not_attempted():
    """It was attempted — the provider ran and returned a dict. `failed`
    is also what D-5 counts toward INDETERMINATE, which is the honest
    band for "we cannot tell"."""
    result = _result()
    det.normalise(result, "speakeasy")
    assert result["data"]["detonation"]["state"] != det.NOT_ATTEMPTED


def test_an_unknown_state_string_becomes_failed(caplog):
    result = _result(data={"detonation": {"state": "ran_ok", "reason": ""}})
    with caplog.at_level(logging.WARNING, logger="core.detonation"):
        det.normalise(result, "speakeasy")
    assert result["data"]["detonation"]["state"] == det.FAILED
    assert "ran_ok" in caplog.text


def test_a_malformed_detonation_block_becomes_failed():
    """A provider returning a bare string where a dict belongs."""
    result = _result(data={"detonation": "observed"})
    det.normalise(result, "speakeasy")
    assert result["data"]["detonation"]["state"] == det.FAILED


def test_non_dict_data_is_replaced_rather_than_crashing():
    """The caller's setdefault only fills a *missing* key, so a provider
    returning data as a list still reaches here. Design rule 2 — never
    take the scan down."""
    result = _result()
    result["data"] = ["not", "a", "dict"]
    det.normalise(result, "speakeasy")
    assert isinstance(result["data"], dict)
    assert result["data"]["detonation"]["state"] == det.FAILED


def test_a_valid_observed_state_survives_untouched():
    """The rule must not become "nothing is ever observed", which would
    pass most of this file while deleting the feature."""
    result = _result(delta=25,
                     data={"detonation": det.build(det.OBSERVED, "ran")})
    det.normalise(result, "speakeasy")
    assert result["data"]["detonation"]["state"] == det.OBSERVED
    assert result["score_delta"] == 25


def test_not_attempted_survives_as_itself():
    """Distinct from `failed`, and D-5 depends on the difference: an
    inapplicable provider must not push a benign file toward
    INDETERMINATE."""
    result = _result(data={"detonation":
                           det.build(det.NOT_ATTEMPTED, "sample is not a PE")})
    det.normalise(result, "speakeasy")
    assert result["data"]["detonation"]["state"] == det.NOT_ATTEMPTED
    assert result["data"]["detonation"]["reason"] == "sample is not a PE"


def test_a_gracefully_skipped_provider_reads_as_not_attempted(caplog):
    """Design rule 2's prescribed shape, and it must not read as failure.

    A provider whose backend is not configured logs, sets status
    "skipped" and returns empty data. Nothing was attempted, so nothing
    failed — and the difference is load-bearing: D-5 counts FAILED
    toward INDETERMINATE, so branding every unconfigured provider a
    failure would push ordinary static scans toward "could not
    determine". Raised in review 2026-10-13."""
    result = _result(status="skipped")
    result["reason"] = "speakeasy is not installed"
    with caplog.at_level(logging.WARNING, logger="core.detonation"):
        det.normalise(result, "speakeasy")
    assert result["data"]["detonation"]["state"] == det.NOT_ATTEMPTED
    assert caplog.text == "", "warned about a provider behaving correctly"


def test_a_skipped_provider_keeps_its_own_reason():
    """The provider already said why it could not run; repeating a
    generic string over the top of it loses the only useful detail."""
    result = _result(status="skipped")
    result["reason"] = "speakeasy is not installed"
    det.normalise(result, "speakeasy")
    assert result["data"]["detonation"]["reason"] == "speakeasy is not installed"


def test_a_skipped_provider_with_no_reason_still_gets_one():
    result = _result(status="skipped")
    det.normalise(result, "speakeasy")
    assert result["data"]["detonation"]["reason"].strip()


def test_an_errored_provider_with_no_block_is_failed_not_skipped():
    """The other side of the same rule: it tried and broke."""
    result = _result(status="error")
    det.normalise(result, "speakeasy")
    assert result["data"]["detonation"]["state"] == det.FAILED


# ----------------------------------------------------------------------
# The reason requirement
# ----------------------------------------------------------------------

def test_a_non_observed_state_without_a_reason_gets_one(caplog):
    """"Detonation failed" with no reason leaves an analyst unable to
    tell a denied network from a crashed emulator — which is the
    distinction this whole rule exists to preserve."""
    result = _result(data={"detonation": {"state": det.FAILED, "reason": ""}})
    with caplog.at_level(logging.WARNING, logger="core.detonation"):
        det.normalise(result, "speakeasy")
    assert result["data"]["detonation"]["reason"]
    assert "no reason" in caplog.text


def test_a_whitespace_reason_counts_as_missing():
    result = _result(data={"detonation": {"state": det.FAILED, "reason": "   "}})
    det.normalise(result, "speakeasy")
    assert result["data"]["detonation"]["reason"].strip()


def test_a_non_string_reason_does_not_crash_the_strip():
    """`None.strip()` would raise, inside the one path design rule 2 says
    must never raise."""
    result = _result(data={"detonation": {"state": det.FAILED, "reason": None}})
    det.normalise(result, "speakeasy")
    assert isinstance(result["data"]["detonation"]["reason"], str)


def test_an_observed_state_needs_no_reason():
    result = _result(data={"detonation": {"state": det.OBSERVED, "reason": ""}})
    det.normalise(result, "speakeasy")
    assert result["data"]["detonation"]["reason"] == ""


# ----------------------------------------------------------------------
# Nothing observed, nothing scored
#
# A dynamic score_delta IS a behavioural finding, expressed as a number —
# and a number that moves a verdict is the loudest rendering there is.
# ----------------------------------------------------------------------

def test_a_failed_detonation_cannot_score(caplog):
    result = _result(delta=40,
                     data={"detonation": det.build(det.FAILED, "emulator aborted")})
    with caplog.at_level(logging.WARNING, logger="core.detonation"):
        det.normalise(result, "speakeasy")
    assert result["score_delta"] == 0
    assert "zeroed" in caplog.text


def test_a_not_attempted_detonation_cannot_score():
    result = _result(delta=40,
                     data={"detonation": det.build(det.NOT_ATTEMPTED, "no PE")})
    det.normalise(result, "speakeasy")
    assert result["score_delta"] == 0


def test_a_skipped_status_demotes_an_observed_state(caplog):
    """Raised by the review gate on the D-1 commit: nothing zeroed a
    delta on a non-success status, because core/scoring never reads
    `status`. A provider claiming both "skipped" and "observed" is
    self-contradictory, and the orchestrator believes neither."""
    result = _result(delta=40, status="skipped",
                     data={"detonation": det.build(det.OBSERVED, "ran")})
    with caplog.at_level(logging.WARNING, logger="core.detonation"):
        det.normalise(result, "speakeasy")
    assert result["data"]["detonation"]["state"] == det.FAILED
    assert result["score_delta"] == 0
    assert "demoted" in caplog.text


def test_an_error_status_demotes_an_observed_state():
    result = _result(delta=40, status="error",
                     data={"detonation": det.build(det.OBSERVED, "ran")})
    det.normalise(result, "speakeasy")
    assert result["data"]["detonation"]["state"] == det.FAILED
    assert result["score_delta"] == 0


def test_the_demotion_happens_even_when_nothing_was_scored():
    """Zeroing the score is not enough and was the defect.

    The STATE is what the rest of the system reads — observed() gates
    whether a reporter renders behaviour, and D-5 counts FAILED toward
    INDETERMINATE. With delta already 0 there is nothing to zero, so a
    fix that only touched the score left `observed` standing: an errored
    provider still rendered its findings and still read as a completed
    detonation. Raised in review 2026-10-12."""
    result = _result(delta=0, status="error",
                     data={"detonation": det.build(det.OBSERVED, "ran")})
    det.normalise(result, "speakeasy")
    assert result["data"]["detonation"]["state"] == det.FAILED
    assert det.observed(result) is False
    assert det.state_of(result) == det.FAILED


def test_the_demotion_reason_names_the_contradiction():
    """An analyst reading "failed" needs to know the provider contradicted
    itself, not that the emulator crashed."""
    result = _result(status="error",
                     data={"detonation": det.build(det.OBSERVED, "ran")})
    det.normalise(result, "speakeasy")
    assert "status" in result["data"]["detonation"]["reason"]


def test_a_consistent_skip_is_not_warned_about(caplog):
    """status=skipped with state=not_attempted is a provider behaving
    correctly. Warning on it would bury the real contradictions."""
    result = _result(delta=0, status="skipped",
                     data={"detonation":
                           det.build(det.NOT_ATTEMPTED, "no provider armed")})
    with caplog.at_level(logging.WARNING, logger="core.detonation"):
        det.normalise(result, "speakeasy")
    assert caplog.text == ""


def test_an_observed_success_keeps_its_score():
    """The one combination that may score. Without this the rule
    degenerates into "dynamic analysis cannot contribute"."""
    result = _result(delta=40, status="success",
                     data={"detonation": det.build(det.OBSERVED, "ran")})
    det.normalise(result, "speakeasy")
    assert result["score_delta"] == 40


def test_a_zero_delta_on_a_failed_state_logs_nothing(caplog):
    """The ordinary failure. Warning on it would make the log noisy for
    the most common non-observed case and bury the real provider bugs."""
    result = _result(delta=0,
                     data={"detonation": det.build(det.FAILED, "timed out")})
    with caplog.at_level(logging.WARNING, logger="core.detonation"):
        det.normalise(result, "speakeasy")
    assert "zeroed" not in caplog.text


def test_normalise_is_idempotent():
    """It runs once today, but a second call must not turn a valid state
    into FAILED or re-warn."""
    result = _result(delta=25,
                     data={"detonation": det.build(det.OBSERVED, "ran")})
    det.normalise(result, "speakeasy")
    first = dict(result["data"]["detonation"])
    det.normalise(result, "speakeasy")
    assert result["data"]["detonation"] == first
    assert result["score_delta"] == 25


# ----------------------------------------------------------------------
# observed() and state_of() — the reporter-facing predicates
# ----------------------------------------------------------------------

def test_observed_is_true_only_for_the_observed_state():
    for state in (det.FAILED, det.NOT_ATTEMPTED):
        assert det.observed(_result(data={"detonation": det.build(state, "x")})) is False
    assert det.observed(_result(data={"detonation": det.build(det.OBSERVED)})) is True


def test_observed_is_false_when_no_state_was_reported():
    """Narrower than it first read.

    An earlier docstring claimed this proved "a result that never went
    through normalise renders nothing", which the implementation does
    not enforce: observed() reads the state and cannot tell whether
    normalisation ran. What it does guarantee is that a result carrying
    no state is never rendered as behaviour. Raised in review
    2026-10-13."""
    assert det.observed(_result()) is False
    assert det.observed({}) is False


def test_observed_handles_the_absent_provider_without_crashing():
    """`report["dynamic"]` is None on every scan that armed no provider,
    which is the overwhelmingly common case — `dynamic_provider` defaults
    to "none". A reporter asking this question unconditionally must not
    have to guard the call, and an AttributeError here would break design
    rule 2 on ordinary static scans. Raised in review 2026-10-12."""
    assert det.observed(None) is False
    assert det.observed("not a result") is False
    assert det.observed([]) is False


def test_state_of_reads_true_absence_as_not_attempted():
    """`report["dynamic"]` is None on every scan that armed no provider."""
    assert det.state_of(None) == det.NOT_ATTEMPTED
    assert det.state_of("nonsense") == det.NOT_ATTEMPTED


def test_state_of_and_normalise_never_disagree_on_any_result():
    """The module's core invariant, enforced exhaustively rather than
    asserted in prose.

    It has now been broken twice. First the two functions each decided
    for themselves, so a missing block read NOT_ATTEMPTED through one and
    FAILED through the other. Then only the missing-block case was
    shared, which left an unknown state, a malformed block and a
    status/state contradiction still resolving differently — and a
    documented invariant that holds in *some* cases is worse than none,
    because callers rely on it. Both reviews caught a case this test
    would have caught first, which is why it is a product now and not a
    pair of examples.

    The cross-product below is every shape a provider can hand over,
    against every status the contract allows."""
    blocks = [
        None,                                        # key absent
        "observed",                                  # present, not a dict
        42,                                          # present, not a dict
        [],                                          # present, not a dict
        {},                                          # dict, no state
        {"state": None},
        {"state": "ran_ok"},                         # unknown string
        {"state": ["observed"]},                     # unhashable
        {"state": {"name": "observed"}},             # unhashable
        {"state": 7},                                # wrong type, hashable
        {"state": det.OBSERVED, "reason": "ran"},
        {"state": det.FAILED, "reason": "aborted"},
        {"state": det.NOT_ATTEMPTED, "reason": "no PE"},
    ]
    statuses = ["success", "skipped", "error", None, "weird"]

    # deepcopy per arm, and it is not belt-and-braces — without it this
    # test proves nothing, which is how it was first written.
    #
    # `dict(data)` copies only the outer mapping, so before["data"]
    # ["detonation"] and after["data"]["detonation"] were the SAME object:
    # normalise(after) mutated `before` in place, and state_of then read
    # an already-normalised result. It compared normalised against
    # normalised and passed unconditionally. Worse, `blocks` is built once
    # outside the loop, so each arm permanently demoted the shared fixture
    # — by the second status every OBSERVED block had already become
    # FAILED, and the contradiction case was never exercised again.
    # Found by the review gate 2026-10-13.
    for status in statuses:
        for block in blocks:
            data = {} if block is None else {"detonation": copy.deepcopy(block)}
            before = _result(status=status, data=copy.deepcopy(data))
            after = _result(status=status, data=copy.deepcopy(data))
            assert before["data"] is not after["data"]
            det.normalise(after, "speakeasy")

            read = det.state_of(before)
            written = after["data"]["detonation"]["state"]
            assert read == written, (
                f"state_of said {read!r} but normalise wrote {written!r} "
                f"for status={status!r} block={block!r}"
            )
            # And reading it again after normalisation must not move it.
            assert det.state_of(after) == written, "normalise is not a fixpoint"


def test_an_unhashable_state_does_not_crash_the_scan():
    """`x not in frozenset` HASHES x, so an unhashable value raises
    TypeError rather than answering False.

    A provider returning {"state": ["observed"]} therefore took the whole
    scan down from inside the one function whose docstring promises it
    never raises — design rule 2, broken by a membership test that looks
    total. Found by the review gate 2026-10-13 and reproduced before
    fixing."""
    for bad in (["observed"], {"name": "observed"}, {"a": 1}, set()):
        result = _result(data={"detonation": {"state": bad}})
        det.normalise(result, "speakeasy")  # must not raise
        assert result["data"]["detonation"]["state"] == det.FAILED


def test_an_unhashable_state_is_safe_to_read_too():
    """state_of() shares the resolver, so it shares the crash if the
    guard is ever removed from only one side."""
    result = _result(data={"detonation": {"state": ["observed"]}})
    assert det.state_of(result) == det.FAILED
    assert det.observed(result) is False


def test_the_malformed_warning_names_the_type_the_provider_sent(caplog):
    """It named the replacement, not the offence.

    The block is overwritten with {} before the message is built, and the
    message read the type back out of the dict afterwards — so it printed
    "dict" for every malformed value, which is both wrong and the exact
    opposite of what a reader needs. Found by the review gate
    2026-10-13."""
    for value, expected in ((["x"], "list"), ("observed", "str"), (42, "int")):
        caplog.clear()
        result = _result(data={"detonation": value})
        with caplog.at_level(logging.WARNING, logger="core.detonation"):
            det.normalise(result, "speakeasy")
        assert f"({expected})" in caplog.text, (
            f"expected the warning to name {expected}, got: {caplog.text}"
        )


def test_a_malformed_block_is_failed_even_on_a_skipped_status():
    """An absent block on a skipped provider is design rule 2's correct
    shape. A block that is *present* and malformed is a provider bug, and
    a bug resolves to FAILED whatever the status claims. The two were
    conflated when `_state_for_missing_block` was applied to both."""
    result = _result(status="skipped", data={"detonation": "observed"})
    det.normalise(result, "speakeasy")
    assert result["data"]["detonation"]["state"] == det.FAILED


def test_an_unknown_state_is_failed_even_on_a_skipped_status():
    result = _result(status="skipped", data={"detonation": {"state": "corrupt"}})
    det.normalise(result, "speakeasy")
    assert result["data"]["detonation"]["state"] == det.FAILED


def test_state_of_returns_a_valid_state_verbatim():
    for state in (det.OBSERVED, det.FAILED, det.NOT_ATTEMPTED):
        result = _result(data={"detonation": det.build(state, "x")})
        assert det.state_of(result) == state


def test_state_of_never_returns_an_unknown_value():
    """A reporter switching on this must not meet a string the palette
    has no entry for."""
    result = _result(data={"detonation": {"state": "weird", "reason": ""}})
    assert det.state_of(result) in det.STATES


# ----------------------------------------------------------------------
# The vocabulary itself
# ----------------------------------------------------------------------

def test_the_three_states_are_distinct_and_complete():
    assert det.STATES == {"observed", "not_attempted", "failed"}
    assert len({det.OBSERVED, det.NOT_ATTEMPTED, det.FAILED}) == 3
