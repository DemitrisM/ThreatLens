"""Tests for the capa capability-detection module.

capa is an external binary whose JSON schema has already changed once (v6 to
v7), so the parsing here is defensive by necessity: every failure it can have —
absent, timing out, exiting non-zero, printing nothing, printing something that
is not JSON, printing JSON of an unexpected shape — has to degrade to a skip
rather than an exception (design rule 2). These tests exercise that, plus the
category-based scoring that keeps capa from dominating the pipeline.
"""

from pathlib import Path

from modules.static.capa_analysis import (
    _MAX_SCORE,
    _parse_capa_output,
    _score_capabilities,
    run,
)


def _doc(rules: dict) -> dict:
    return {"rules": rules}


def _rule(meta: dict | None = None) -> dict:
    return {"meta": meta or {}}


# ----------------------------------------------------------------------
# Module contract
# ----------------------------------------------------------------------

def test_missing_binary_is_a_skip(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x90\x00")
    out = run(sample, {"capa_binary": str(tmp_path / "no_such_capa")})
    assert out["module"] == "capa_analysis"
    assert out["status"] == "skipped"
    assert out["score_delta"] == 0
    assert isinstance(out["reason"], str)


def test_unsupported_format_says_so_rather_than_blaming_the_install(tmp_path,
                                                                   monkeypatch):
    """Must fail against collapsing "capa declined" into "capa failed".

    Measured: the bundled capa exits **16** with "Input file does not
    appear to be a supported file" for a RAR and for a PDF — a dedicated
    code for a format it does not handle. Reporting that as "capa analysis
    failed" sends the analyst to check an installation that is fine, and
    the source comment says that is exactly what the phrasing is for. A
    RAR is not a PE; nothing failed.
    """
    import subprocess

    from modules.static import capa_analysis

    sample = tmp_path / "archive.rar"
    sample.write_bytes(b"Rar!\x1a\x07\x01\x00")
    capa = tmp_path / "capa"
    capa.write_text("#!/bin/true\n")
    capa.chmod(0o755)

    def _fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, returncode=16, stdout=b"", stderr=b"")

    monkeypatch.setattr(capa_analysis, "run_contained", _fake_run)
    out = capa_analysis.run(sample, {"capa_binary": str(capa)})

    assert out["status"] == "skipped"
    assert out["score_delta"] == 0
    assert "fail" not in out["reason"].lower(), out["reason"]
    assert "not applicable" in out["reason"].lower(), out["reason"]


def test_unparseable_output_reports_the_failed_outcome(tmp_path, monkeypatch):
    """Must fail against the one return path left on the old boolean.

    Every other branch moved from `False` to `_FAILED` when the contract
    became four-valued; this one did not, so the declared return type was
    a lie and anything comparing `outcome == _FAILED` would miss it. The
    reason string happened to stay right by falling through a `.get`
    default, which is what made it easy to miss.
    """
    import subprocess

    from modules.static import capa_analysis

    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x90\x00")
    capa = tmp_path / "capa"
    capa.write_text("#!/bin/true\n")
    capa.chmod(0o755)

    def _fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, returncode=0,
                                           stdout=b"not json at all", stderr=b"")

    monkeypatch.setattr(capa_analysis, "run_contained", _fake_run)
    parsed, outcome = capa_analysis._run_capa(sample, capa, timeout=5)
    assert parsed is None
    assert outcome == capa_analysis._FAILED


def test_a_refusal_does_not_log_that_a_parse_will_be_attempted(tmp_path, monkeypatch,
                                                               caplog):
    """Must fail against checking the refusal AFTER the non-zero-exit log.

    Exit 16 is non-zero, so it fell into the branch that logs "will still
    attempt JSON parse" — which is untrue: the refusal returns before any
    parse. Every archive and document scanned produced that line.
    """
    import logging
    import subprocess

    from modules.static import capa_analysis

    sample = tmp_path / "archive.rar"
    sample.write_bytes(b"Rar!\x1a\x07\x01\x00")
    capa = tmp_path / "capa"
    capa.write_text("#!/bin/true\n")
    capa.chmod(0o755)

    def _fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(
            cmd, returncode=16, stdout=b"",
            stderr=b"ERROR capa: Input file does not appear to be a supported file")

    monkeypatch.setattr(capa_analysis, "run_contained", _fake_run)
    with caplog.at_level(logging.INFO, logger="modules.static.capa_analysis"):
        _, outcome = capa_analysis._run_capa(sample, capa, timeout=5)

    assert outcome == capa_analysis._UNSUPPORTED
    assert not any("attempt JSON parse" in r.message for r in caplog.records), \
        [r.message for r in caplog.records]


def test_a_real_failure_still_says_failed(tmp_path, monkeypatch):
    """The other half: a genuine error must keep pointing at the install."""
    import subprocess

    from modules.static import capa_analysis

    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x90\x00")
    capa = tmp_path / "capa"
    capa.write_text("#!/bin/true\n")
    capa.chmod(0o755)

    def _fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, returncode=250, stdout=b"",
                                           stderr=b"segfault")

    monkeypatch.setattr(capa_analysis, "run_contained", _fake_run)
    out = capa_analysis.run(sample, {"capa_binary": str(capa)})
    assert out["status"] == "skipped"
    assert "failed" in out["reason"].lower(), out["reason"]


# ----------------------------------------------------------------------
# Parsing
# ----------------------------------------------------------------------

def test_library_and_subscope_rules_are_not_capabilities():
    """Those describe capa's own plumbing, not the sample's behaviour."""
    doc = _doc({
        "inject APC": _rule(),
        "contains PE file": _rule({"lib": True}),
        "anonymous subscope": _rule({"is_subscope_rule": True}),
    })
    capabilities, _ = _parse_capa_output(doc)
    assert capabilities == ["inject APC"]


def test_attack_mapping_is_extracted_with_its_subtechnique():
    doc = _doc({"inject APC": _rule({"attack": [{
        "id": "T1055.004", "tactic": "Defense Evasion",
        "technique": "Process Injection", "subtechnique": "APC Injection",
    }]})})
    _, mappings = _parse_capa_output(doc)
    assert mappings == [{
        "capability": "inject APC",
        "tactic": "Defense Evasion",
        "technique_id": "T1055.004",
        "technique_name": "Process Injection: APC Injection",
    }]


def test_the_same_technique_from_two_rules_is_kept():
    """Two capabilities mapping to T1055 are two findings."""
    entry = {"id": "T1055", "tactic": "Defense Evasion", "technique": "Process Injection"}
    doc = _doc({"inject APC": _rule({"attack": [entry]}),
                "hollow process": _rule({"attack": [entry]})})
    _, mappings = _parse_capa_output(doc)
    assert len(mappings) == 2


def test_a_technique_repeated_within_one_rule_is_deduplicated():
    entry = {"id": "T1055", "tactic": "Defense Evasion", "technique": "Process Injection"}
    doc = _doc({"inject APC": _rule({"attack": [entry, dict(entry)]})})
    _, mappings = _parse_capa_output(doc)
    assert len(mappings) == 1


def test_null_attack_metadata_does_not_raise():
    """A JSON null is not a missing key — .get()'s default never fires.

    capa emits its ATT&CK block optionally, and a null field must degrade
    to an empty string rather than an AttributeError that costs the whole
    module its result.
    """
    doc = _doc({"inject APC": _rule({"attack": [{
        "id": None, "tactic": None, "technique": None, "subtechnique": None,
    }]})})
    capabilities, mappings = _parse_capa_output(doc)
    assert capabilities == ["inject APC"]
    assert mappings[0]["technique_id"] == ""
    assert mappings[0]["tactic"] == ""


def test_malformed_rules_field_degrades_to_nothing():
    capabilities, mappings = _parse_capa_output({"rules": ["not", "a", "dict"]})
    assert capabilities == []
    assert mappings == []


def test_non_dict_rule_entry_is_skipped():
    doc = _doc({"good": _rule(), "bad": "not a dict"})
    capabilities, _ = _parse_capa_output(doc)
    assert capabilities == ["good"]


# ----------------------------------------------------------------------
# Scoring
# ----------------------------------------------------------------------

def test_a_category_is_counted_once_however_many_capabilities_match():
    one, _, _ = _score_capabilities(["inject APC"])
    many, _, cats = _score_capabilities(
        ["inject APC", "inject DLL", "inject shellcode", "process hollowing"]
    )
    assert one == many
    assert [c["category"] for c in cats] == ["Process injection"]


def test_one_capability_may_feed_several_categories():
    """The match loop deliberately does not break on its first hit."""
    _, _, cats = _score_capabilities(["anti-debug via inject"])
    assert {c["category"] for c in cats} == {"Process injection", "Anti-analysis / anti-debug"}


def test_total_is_capped():
    caps = ["inject APC", "check for debugger", "steal credentials", "persist via run key",
            "connect to server", "take screenshot", "bypass UAC", "encrypt data"]
    delta, _, _ = _score_capabilities(caps)
    assert delta == _MAX_SCORE


def test_categories_are_reported_highest_first():
    _, _, cats = _score_capabilities(["encrypt data using AES", "inject APC"])
    assert [c["score"] for c in cats] == sorted((c["score"] for c in cats), reverse=True)


def test_no_capabilities_scores_nothing():
    assert _score_capabilities([]) == (0, [], [])
