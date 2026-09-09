"""Tests for the VirusTotal enrichment module.

Focused on the paths that must never raise. This module reaches the network
and parses third-party JSON, so it sits behind design rule 2 more exposed
than anything else in the tool: a blank config value, a hostile header or an
unexpected response shape must degrade the lookup, not kill the scan.

No test here performs a real request.
"""

import time

import pytest

from modules.enrichment import virustotal
from modules.enrichment.virustotal import (
    _compute_score,
    _parse_response,
    _sha256,
    run,
)


@pytest.fixture
def sample(tmp_path):
    p = tmp_path / "sample.bin"
    p.write_bytes(b"MZ" + b"\x00" * 32)
    return p


# ----------------------------------------------------------------------
# Config handling — must never raise
# ----------------------------------------------------------------------

def test_null_api_key_is_a_skip_not_a_crash(sample):
    """`virustotal_api_key:` with no value parses to None, not "".

    dict.get returns its default only when the key is ABSENT. config_loader
    guarantees the key is always present, so a bare YAML entry puts None
    there and `.strip()` on it raised AttributeError — killing the whole
    pipeline over an empty config field.
    """
    out = run(sample, {"virustotal_api_key": None})
    assert out["status"] == "skipped"
    assert out["score_delta"] == 0


def test_empty_api_key_is_a_skip(sample):
    out = run(sample, {"virustotal_api_key": ""})
    assert out["status"] == "skipped"


def test_whitespace_api_key_is_a_skip(sample):
    out = run(sample, {"virustotal_api_key": "   "})
    assert out["status"] == "skipped"


def test_absent_api_key_is_a_skip(sample):
    out = run(sample, {})
    assert out["status"] == "skipped"


# ----------------------------------------------------------------------
# Response parsing — third-party JSON of any shape
# ----------------------------------------------------------------------

def test_explicit_null_data_does_not_crash():
    """`{"data": null}` is valid JSON and must degrade, not raise.

    `body.get("data", {})` returns None when the key is present and null,
    so the chained .get raised AttributeError.
    """
    out = _parse_response({"data": None}, "a" * 64)
    assert out["module"] == "virustotal"
    assert out["data"]["sha256"] == "a" * 64


def test_null_attributes_does_not_crash():
    out = _parse_response({"data": {"attributes": None}}, "b" * 64)
    assert out["status"] == "success"


def test_empty_body_does_not_crash():
    out = _parse_response({}, "c" * 64)
    assert out["data"]["detection_ratio"] == "0/0"


def test_detection_stats_are_parsed():
    body = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 40, "suspicious": 2,
                                "undetected": 20, "harmless": 0},
        "popular_threat_classification": {"suggested_threat_label": "trojan.agent"},
    }}}
    out = _parse_response(body, "d" * 64)
    assert out["data"]["detection_ratio"] == "42/62"
    assert out["data"]["threat_label"] == "trojan.agent"
    assert out["score_delta"] == 25


def test_permalink_is_built_from_the_hash():
    out = _parse_response({}, "e" * 64)
    assert out["data"]["permalink"].endswith("e" * 64)


# ----------------------------------------------------------------------
# Retry-After handling
# ----------------------------------------------------------------------

class _Resp429:
    status_code = 429

    def __init__(self, retry_after):
        self.headers = {"Retry-After": retry_after} if retry_after is not None else {}


def _drive_retry(monkeypatch, retry_after):
    """Run one 429 retry cycle, capturing what time.sleep was asked for."""
    slept = []
    monkeypatch.setattr(time, "sleep", lambda s: slept.append(s))
    monkeypatch.setattr(virustotal, "requests", _FakeRequests(_Resp429(retry_after)))
    virustotal._request_with_retry("f" * 64, "key", 10, 1)
    return slept


class _FakeRequests:
    """Minimal stand-in for the requests module."""

    class exceptions:
        class Timeout(Exception): pass
        class ConnectionError(Exception): pass
        class RequestException(Exception): pass

    def __init__(self, response):
        self._response = response

    def get(self, url, headers=None, timeout=None):
        return self._response


@pytest.mark.parametrize("header", ["-10", "-1"])
def test_negative_retry_after_does_not_crash(monkeypatch, header):
    """A negative Retry-After must not reach time.sleep.

    int("-10") parses fine and min(-10, 120) is still -10;
    time.sleep(-10) raises ValueError and kills the pipeline.
    """
    slept = _drive_retry(monkeypatch, header)
    assert all(s >= 0 for s in slept), slept


def test_retry_after_is_capped(monkeypatch):
    """A huge Retry-After must not park the scan for hours."""
    slept = _drive_retry(monkeypatch, "99999")
    assert all(s <= 120 for s in slept), slept


def test_absent_retry_after_defaults(monkeypatch):
    slept = _drive_retry(monkeypatch, None)
    assert slept and 0 <= slept[0] <= 120


def test_garbage_retry_after_defaults(monkeypatch):
    slept = _drive_retry(monkeypatch, "soon-ish")
    assert slept and 0 <= slept[0] <= 120


# ----------------------------------------------------------------------
# Scoring
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "detections, expected",
    [(50, 25), (11, 25), (10, 10), (1, 10), (0, -5)],
)
def test_score_thresholds(detections, expected):
    score, _reason = _compute_score(detections, 70, None)
    assert score == expected


def test_clean_but_seen_is_only_mildly_reassuring():
    """Absence of detections is weak evidence; signatures lag new builds."""
    score, reason = _compute_score(0, 70, None)
    assert score == -5
    assert "no engines flagged" in reason


def test_threat_label_appears_in_the_reason():
    _score, reason = _compute_score(30, 70, "stealer.redline")
    assert "stealer.redline" in reason


# ----------------------------------------------------------------------
# Hashing
# ----------------------------------------------------------------------

def test_sha256_matches_hashlib(sample):
    import hashlib
    assert _sha256(sample) == hashlib.sha256(sample.read_bytes()).hexdigest()


def test_sha256_returns_none_on_unreadable_file(tmp_path):
    assert _sha256(tmp_path / "nope.bin") is None
