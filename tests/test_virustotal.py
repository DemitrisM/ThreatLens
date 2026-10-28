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


# ----------------------------------------------------------------------
# An unobserved hash must not reduce the score
#
# A 404 means the hash was never submitted, which is the EXPECTED state
# for a targeted or freshly built sample — precisely the case this tool
# exists for. Subtracting for it turns absence of observation into
# evidence of safety, the error rule D-1 exists to prevent on the
# dynamic side.
# ----------------------------------------------------------------------

class _RespStatus:
    """Minimal stand-in carrying only a status code and a JSON body."""

    def __init__(self, status_code, body=None):
        self.status_code = status_code
        self.headers = {}
        self._body = body if body is not None else {}

    def json(self):
        return self._body


def _run_against(monkeypatch, sample, response, config=None):
    """Drive run() with every request answered by one canned response."""
    monkeypatch.setattr(virustotal, "requests", _FakeRequests(response))
    cfg = {"virustotal_api_key": "k"}
    cfg.update(config or {})
    return run(sample, cfg)


def test_an_unseen_hash_does_not_reduce_the_score(monkeypatch, sample):
    """A 404 is "nobody looked", not "nothing was found".

    Asserted on the delta rather than the reason string: the wording may
    be rephrased, but the number is the contract.
    """
    out = _run_against(monkeypatch, sample, _RespStatus(404))
    assert out["status"] == "success"
    assert out["score_delta"] == 0


def test_a_queued_file_with_no_verdicts_does_not_reduce_the_score():
    """All-zero stats mean the file is queued — no engine has reported."""
    body = {"data": {"attributes": {"last_analysis_stats": {
        "malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0,
    }}}}
    out = _parse_response(body, "a" * 64)
    assert out["score_delta"] == 0


def test_an_unsupported_file_does_not_reduce_the_score():
    """`type-unsupported` engines are not engines that cleared the file.

    total_engines sums type-unsupported and failure alongside the real
    verdicts, so an unsupported file reports ~70 "engines" with zero
    verdicts and used to take the full -5 for it. The guard has to count
    verdict-bearing engines, and the ratio must not read 0/70 — that is
    indistinguishable from seventy engines examining it and finding
    nothing.
    """
    body = {"data": {"attributes": {"last_analysis_stats": {
        "malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0,
        "type-unsupported": 68, "failure": 2,
    }}}}
    out = _parse_response(body, "b" * 64)
    assert out["score_delta"] == 0
    assert out["data"]["detection_ratio"] != "0/70"


def test_a_seen_and_clean_file_still_scores_minus_five():
    """The paired case. Seventy engines looked; that is weak reassurance.

    This is the asymmetry _compute_score argues for deliberately, and the
    fix above must not reach it.
    """
    body = {"data": {"attributes": {"last_analysis_stats": {
        "malicious": 0, "suspicious": 0, "undetected": 68, "harmless": 2,
    }}}}
    out = _parse_response(body, "c" * 64)
    assert out["score_delta"] == -5


def test_a_detected_file_is_unaffected():
    """The other paired case — the guard must not swallow a real hit."""
    body = {"data": {"attributes": {"last_analysis_stats": {
        "malicious": 12, "suspicious": 0, "undetected": 58, "harmless": 0,
    }}}}
    out = _parse_response(body, "d" * 64)
    assert out["score_delta"] == 25


class _FakeRequestsByHash:
    """Answers each request according to the hash in its URL.

    The embedded-hash cases need the outer lookup and the inner lookup to
    return different things, which the single-response stand-in cannot do.
    """

    exceptions = _FakeRequests.exceptions

    def __init__(self, default, by_hash):
        self._default = default
        self._by_hash = by_hash
        self.urls = []

    def get(self, url, headers=None, timeout=None):
        self.urls.append(url)
        for sha, response in self._by_hash.items():
            if sha in url:
                return response
        return self._default


def _flagged_body(detections):
    return {"data": {"attributes": {"last_analysis_stats": {
        "malicious": detections, "suspicious": 0, "undetected": 60,
        "harmless": 0,
    }}}}


def test_an_unseen_embedded_hash_contributes_nothing(monkeypatch, sample):
    """An unseen payload inside an unseen container lands on 0.

    _lookup_embedded_hashes was already correct on its own terms: it
    scores min(hits * 2, 10) and a 404 never increments hits. What this
    pins is the pair — the outer 404 no longer passes -5 through for the
    inner lookup to add to.

    The inner request is asserted to have been issued. Without that the
    test passes just as well when the embedded hashes are never looked up
    at all, which would make it prove nothing.
    """
    inner = "e" * 64
    prior = [{"module": "archive_analysis", "status": "success",
              "data": {"embedded_executables": [
                  {"name": "payload.exe", "sha256": inner,
                   "size": 1024, "type": "PE"}]}}]
    fake = _FakeRequestsByHash(_RespStatus(404), {})
    monkeypatch.setattr(virustotal, "requests", fake)

    out = run(sample, {"virustotal_api_key": "k",
                       "_module_results_so_far": prior})

    assert out["status"] == "success"
    assert out["score_delta"] == 0
    assert any(inner in url for url in fake.urls), fake.urls
    assert out["data"]["embedded_hash_lookups"]


def test_a_flagged_embedded_hash_still_raises_an_unseen_container(
        monkeypatch, sample):
    """The paired case, and the one that proves the fix is not a blanket 0.

    An archive nobody has submitted carrying a payload ninety engines
    have flagged used to net -5 + 2 = -3 — a negative score for a
    container with known malware inside it. It must now be the embedded
    contribution alone, and positive.
    """
    inner = "f" * 64
    prior = [{"module": "archive_analysis", "status": "success",
              "data": {"embedded_executables": [
                  {"name": "payload.exe", "sha256": inner,
                   "size": 1024, "type": "PE"}]}}]
    fake = _FakeRequestsByHash(
        _RespStatus(404),
        {inner: _RespStatus(200, _flagged_body(40))},
    )
    monkeypatch.setattr(virustotal, "requests", fake)

    out = run(sample, {"virustotal_api_key": "k",
                       "_module_results_so_far": prior})

    assert out["status"] == "success"
    assert out["score_delta"] == 2


def test_a_thin_verdict_count_is_reported_honestly():
    """One engine evaluating and sixty-nine failing is not "0/70".

    The guard above only fires at zero verdicts, so this is the case one
    engine away from it: the denominator has to be the engines that
    actually reached a conclusion, or the ratio reads as a seventy-engine
    all-clear.

    NOTE the -5 still stands here on the word of a single engine. That is
    weak evidence treated as strong, it predates this change, and
    correcting it needs a minimum-coverage threshold chosen against the
    corpus rather than invented — so it is left for the calibration pass
    and recorded, not guessed at here.
    """
    body = {"data": {"attributes": {"last_analysis_stats": {
        "malicious": 0, "suspicious": 0, "undetected": 1, "harmless": 0,
        "type-unsupported": 67, "failure": 2,
    }}}}
    out = _parse_response(body, "g" * 64)
    assert out["data"]["detection_ratio"] == "0/1"
    assert out["data"]["verdict_engines"] == 1
    assert out["data"]["total_engines"] == 70


def test_a_queued_file_reason_does_not_blame_unsupported_engines():
    """A queued file has no engines that failed — it has none that ran."""
    body = {"data": {"attributes": {"last_analysis_stats": {
        "malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0,
    }}}}
    out = _parse_response(body, "h" * 64)
    assert "queued" in out["reason"]
    assert "0 unsupported" not in out["reason"]


def test_a_detection_is_scored_on_the_count_not_the_ratio():
    """Switching the denominator must not change what a detection scores.

    _compute_score tiers on the raw detection count and uses its second
    argument only in the reason text, so narrowing that argument from all
    responding engines to verdict-bearing ones cannot move a score. This
    pins it: one engine flagging the file while sixty-nine cannot read it
    is still the 1-10 tier (+10), not the >10 consensus tier, even though
    the ratio is now 1/1 rather than 1/70.
    """
    body = {"data": {"attributes": {"last_analysis_stats": {
        "malicious": 1, "suspicious": 0, "undetected": 0, "harmless": 0,
        "type-unsupported": 67, "failure": 2,
    }}}}
    out = _parse_response(body, "i" * 64)
    assert out["score_delta"] == 10
    assert out["data"]["detection_ratio"] == "1/1"


def test_both_success_paths_publish_the_same_keys(monkeypatch, sample):
    """A 404 and a 200 both report success, so both must carry one shape.

    A reporter reading data["verdict_engines"] should not have to branch
    on data["found"] first.
    """
    body = {"data": {"attributes": {"last_analysis_stats": {
        "malicious": 0, "suspicious": 0, "undetected": 70, "harmless": 0,
    }}}}
    seen = _run_against(monkeypatch, sample, _RespStatus(200, body))
    unseen = _run_against(monkeypatch, sample, _RespStatus(404))
    assert seen["status"] == unseen["status"] == "success"
    # Compared both ways, and both driven through run() rather than one
    # through run() and one through _parse_response: a one-way check
    # passes when the NEXT key is added to the path it treats as the
    # reference.
    assert set(seen["data"]) == set(unseen["data"]), (
        f"only on 200: {sorted(set(seen['data']) - set(unseen['data']))}; "
        f"only on 404: {sorted(set(unseen['data']) - set(seen['data']))}"
    )


def test_an_unsupported_container_reason_does_not_overclaim(monkeypatch, sample):
    """"Nothing was learned" must be scoped to the file, not to the score.

    An unsupported container can still carry a payload the embedded
    lookup flags, which adds to the delta and appends to this same
    reason string. An unscoped "nothing was learned" would then sit next
    to a positive score and a flagged payload.
    """
    inner = "k" * 64
    prior = [{"module": "archive_analysis", "status": "success",
              "data": {"embedded_executables": [
                  {"name": "payload.exe", "sha256": inner,
                   "size": 1024, "type": "PE"}]}}]
    unsupported = _RespStatus(200, {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 0, "suspicious": 0,
                                "undetected": 0, "harmless": 0,
                                "type-unsupported": 70}}}})
    fake = _FakeRequestsByHash(unsupported,
                              {inner: _RespStatus(200, _flagged_body(40))})
    monkeypatch.setattr(virustotal, "requests", fake)

    out = run(sample, {"virustotal_api_key": "k",
                       "_module_results_so_far": prior})

    assert out["score_delta"] == 2
    assert "about this file" in out["reason"]


def test_an_unsupported_embedded_payload_is_not_reported_as_cleared():
    """The embedded rows carried the same inflated denominator.

    _lookup_embedded_hashes built its ratio from every responding engine,
    so an unsupported payload read as "0/70" — seventy engines clearing
    a file none of them could open.
    """
    inner = "m" * 64
    prior = [{"module": "archive_analysis", "status": "success",
              "data": {"embedded_executables": [
                  {"name": "payload.bin", "sha256": inner,
                   "size": 10, "type": "PE"}]}}]
    unsupported = _RespStatus(200, {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 0, "suspicious": 0,
                                "undetected": 0, "harmless": 0,
                                "type-unsupported": 70}}}})

    fake = _FakeRequestsByHash(unsupported, {})
    saved = virustotal.requests
    virustotal.requests = fake
    try:
        rows, delta, _reason = virustotal._lookup_embedded_hashes(
            {"_module_results_so_far": prior}, "k", 10, 0,
        )
    finally:
        virustotal.requests = saved

    assert delta == 0
    assert rows[0]["detection_ratio"] == "0/0"


def test_an_all_timeout_response_is_not_reported_as_queued():
    """Engines that timed out tried and failed; they are not absent.

    total_engines omitted timeout and confirmed-timeout, so a response
    where every engine timed out summed to zero and the zero-verdict
    branch described it as queued — reporting "nobody has looked yet"
    about a file seventy engines had just given up on.
    """
    body = {"data": {"attributes": {"last_analysis_stats": {
        "malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0,
        "timeout": 68, "confirmed-timeout": 2,
    }}}}
    out = _parse_response(body, "n" * 64)
    assert out["score_delta"] == 0
    assert "queued" not in out["reason"]
    assert "70 could not evaluate" in out["reason"]
