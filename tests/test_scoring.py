"""Tests for the confidence scoring engine.

`compute_score` is the last thing to run before a verdict is shown, so every
number a user sees passes through it. It is pure and takes plain dicts, which
makes the whole contract cheap to pin down exactly.
"""

import logging

import pytest

from core.scoring import _clamp, _risk_band, compute_score


def _result(module, delta, reason="because"):
    """Build a minimal module result dict."""
    return {"module": module, "status": "success", "data": {},
            "score_delta": delta, "reason": reason}


# ----------------------------------------------------------------------
# Summing and clamping
# ----------------------------------------------------------------------

def test_empty_input_scores_zero_and_bands_low():
    out = compute_score([])
    assert out["total_score"] == 0
    assert out["risk_band"] == "LOW"
    assert out["breakdown"] == []


def test_deltas_are_summed():
    out = compute_score([_result("a", 10), _result("b", 15), _result("c", 5)])
    assert out["total_score"] == 30


def test_clamp_is_applied_after_summing_not_per_module():
    """The clamp must run once on the total.

    Clamping each contribution first would let one large module hide
    every other signal, and would make the breakdown fail to add up to
    the total the user is shown.
    """
    out = compute_score([_result("a", 80), _result("b", 80), _result("c", 80)])
    assert out["total_score"] == 100
    # The breakdown keeps the true, unclamped contributions.
    assert [row["score_delta"] for row in out["breakdown"]] == [80, 80, 80]


def test_negative_total_is_clamped_to_zero():
    out = compute_score([_result("a", -50), _result("b", 10)])
    assert out["total_score"] == 0
    assert out["risk_band"] == "LOW"


def test_float_deltas_are_accepted_and_truncated():
    """Nested archive scores are damped by 0.5/0.25/0.125 before arriving."""
    out = compute_score([_result("a", 10.9), _result("b", 0.5)])
    assert out["total_score"] == 11
    assert isinstance(out["total_score"], int)


# ----------------------------------------------------------------------
# Band boundaries — exact, on both sides
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "score, band",
    [
        (0, "LOW"), (30, "LOW"),
        (31, "MEDIUM"), (55, "MEDIUM"),
        (56, "HIGH"), (75, "HIGH"),
        (76, "CRITICAL"), (100, "CRITICAL"),
    ],
)
def test_band_boundaries(score, band):
    assert _risk_band(score) == band


def test_band_matches_the_documented_thresholds_end_to_end():
    """The band in the returned dict follows the clamped total."""
    assert compute_score([_result("a", 76)])["risk_band"] == "CRITICAL"
    assert compute_score([_result("a", 75)])["risk_band"] == "HIGH"
    assert compute_score([_result("a", 999)])["risk_band"] == "CRITICAL"


# ----------------------------------------------------------------------
# Breakdown
# ----------------------------------------------------------------------

def test_zero_delta_modules_are_excluded_from_the_breakdown():
    """file_intake always scores 0; a table of "+0" rows buries findings."""
    out = compute_score([_result("file_intake", 0), _result("pe_analysis", 20)])
    assert [row["module"] for row in out["breakdown"]] == ["pe_analysis"]


def test_negative_deltas_appear_in_the_breakdown():
    """Non-zero means non-zero, in either direction."""
    out = compute_score([_result("a", -5), _result("b", 40)])
    assert [row["module"] for row in out["breakdown"]] == ["a", "b"]


def test_breakdown_carries_module_reason_and_delta():
    out = compute_score([_result("yara_scanner", 25, "matched Neo23x0 rule")])
    row = out["breakdown"][0]
    assert row == {"module": "yara_scanner", "score_delta": 25,
                   "reason": "matched Neo23x0 rule"}


def test_breakdown_preserves_input_order():
    out = compute_score([_result("c", 1), _result("a", 2), _result("b", 3)])
    assert [row["module"] for row in out["breakdown"]] == ["c", "a", "b"]


# ----------------------------------------------------------------------
# Malformed input — design rule 2: never kill the pipeline
# ----------------------------------------------------------------------

def test_non_numeric_delta_is_skipped_not_raised(caplog):
    """One malformed module must not discard eleven good ones."""
    with caplog.at_level(logging.WARNING):
        out = compute_score([
            _result("good", 20),
            _result("broken", "not-a-number"),
            _result("also_good", 10),
        ])
    assert out["total_score"] == 30
    assert "broken" in caplog.text


def test_none_delta_is_skipped():
    out = compute_score([_result("a", None), _result("b", 15)])
    assert out["total_score"] == 15


def test_boolean_delta_is_treated_as_a_number():
    """bool is a subclass of int, so True counts as 1 rather than raising."""
    out = compute_score([_result("a", True), _result("b", 4)])
    assert out["total_score"] == 5


def test_missing_score_delta_key_defaults_to_zero():
    out = compute_score([{"module": "sparse", "status": "success"}])
    assert out["total_score"] == 0
    assert out["breakdown"] == []


def test_missing_module_name_is_labelled_unknown():
    out = compute_score([{"score_delta": 12, "reason": "r"}])
    assert out["breakdown"][0]["module"] == "unknown"


def test_missing_reason_becomes_empty_string():
    out = compute_score([{"module": "m", "score_delta": 12}])
    assert out["breakdown"][0]["reason"] == ""


# ----------------------------------------------------------------------
# _clamp
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "value, expected",
    [(-10, 0), (0, 0), (55, 55), (100, 100), (250, 100), (7.9, 7)],
)
def test_clamp(value, expected):
    assert _clamp(value, 0, 100) == expected
