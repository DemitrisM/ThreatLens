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
