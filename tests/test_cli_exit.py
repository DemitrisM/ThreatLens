"""Tests for the CLI exit-code contract (``cli/_exit.py``).

The contract Pass 1 locks in:

    0  clean, or below ``--fail-on``
    1  threat at or above ``--fail-on``
    2  usage error (Click's own)
    3  runtime error
"""

import pytest

from cli._exit import (
    EXIT_OK,
    EXIT_RUNTIME,
    EXIT_THREAT,
    EXIT_USAGE,
    FAIL_ON_CHOICES,
    RuntimeFailure,
    meets_threshold,
)


def test_exit_codes_are_the_documented_constants():
    assert (EXIT_OK, EXIT_THREAT, EXIT_USAGE, EXIT_RUNTIME) == (0, 1, 2, 3)


def test_runtime_failure_exits_three():
    assert RuntimeFailure("boom").exit_code == EXIT_RUNTIME


def test_no_fail_on_never_meets_threshold():
    for band in FAIL_ON_CHOICES:
        assert meets_threshold(band, None) is False
    assert meets_threshold("CRITICAL", "") is False


@pytest.mark.parametrize(
    ("band", "fail_on", "expected"),
    [
        ("LOW", "LOW", True),
        ("LOW", "MEDIUM", False),
        ("MEDIUM", "MEDIUM", True),
        ("HIGH", "MEDIUM", True),
        ("HIGH", "CRITICAL", False),
        ("CRITICAL", "CRITICAL", True),
        ("CRITICAL", "LOW", True),
    ],
)
def test_threshold_is_inclusive_and_ordered(band, fail_on, expected):
    assert meets_threshold(band, fail_on) is expected


def test_threshold_is_case_insensitive():
    assert meets_threshold("high", "medium") is True
    assert meets_threshold("HIGH", "critical") is False


def test_unknown_or_missing_band_is_treated_as_lowest():
    # A report with no scoring band must not be able to trip --fail-on MEDIUM.
    assert meets_threshold(None, "MEDIUM") is False
    assert meets_threshold("UNRATED", "MEDIUM") is False
    # ...but --fail-on LOW is a floor everything satisfies.
    assert meets_threshold(None, "LOW") is True


def test_unknown_fail_on_band_is_a_programming_error():
    with pytest.raises(ValueError, match="Unknown --fail-on band"):
        meets_threshold("HIGH", "SEVERE")
