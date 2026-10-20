"""Tests for the YARA scanning module's setup-state reporting.

An empty rules directory is a deliberate skip rather than an error — a
fresh clone or a freshly rebuilt image has no rules until
``threatlens rules update`` runs. These pin that the *reason* says so,
because a reason string is advice: an analyst reading "no rule files" has
to already know what populates them, and one detection technique is
silently absent from the scan until they do.
"""

from pathlib import Path

import pytest

from modules.static.yara_scanner import run

# yara-python is an optional dependency, and `run` returns before it looks
# at the rules directory when the import fails. Without this, a machine
# that legitimately does not have it would see these fail rather than skip
# — turning supported graceful degradation into a broken suite.
pytest.importorskip("yara", reason="yara-python is an optional dependency")


def test_empty_rules_directory_names_the_command_that_fixes_it(tmp_path):
    """Must fail against a reason that states the condition only.

    The scan is a technique short and nothing in the report says how to
    change that, which is exactly the state a first scan after a container
    rebuild is in.
    """
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x90\x00")
    empty = tmp_path / "rules"
    empty.mkdir()

    out = run(sample, {"yara_rules_dir": str(empty)})

    assert out["status"] == "skipped"
    assert out["score_delta"] == 0
    assert "rules update" in out["reason"], out["reason"]


def test_a_missing_rules_directory_also_says_what_to_run(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x90\x00")

    out = run(sample, {"yara_rules_dir": str(tmp_path / "nope")})

    assert out["status"] == "skipped"
    assert "rules update" in out["reason"], out["reason"]


def test_an_empty_directory_is_not_reported_as_an_error(tmp_path):
    """Setup state, not failure. `error` would put it in the FINDINGS
    table and imply something went wrong."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x90\x00")
    empty = tmp_path / "rules"
    empty.mkdir()

    assert run(sample, {"yara_rules_dir": str(empty)})["status"] != "error"
