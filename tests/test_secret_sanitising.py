"""Credentials must not survive into any rendered or written report.

The strip used to apply only to the top level of each module's ``data``,
so a nested ``{"request": {"api_key": ...}}`` went straight through. Pass
2b wires raw module data into the terminal at ``-vv``, which widens the
blast radius, so the strip is recursive from here on.
"""

import json

from reporting.shared import SECRET_KEYS, sanitise_secrets

SECRET = "a" * 64


def test_top_level_key_is_removed():
    assert sanitise_secrets({"api_key": SECRET, "keep": 1}) == {"keep": 1}


def test_nested_dict_key_is_removed():
    dirty = {"request": {"api_key": SECRET, "url": "https://vt/api"}}
    clean = sanitise_secrets(dirty)
    assert clean == {"request": {"url": "https://vt/api"}}


def test_deeply_nested_key_is_removed():
    dirty = {"a": {"b": {"c": {"virustotal_api_key": SECRET, "ok": True}}}}
    assert SECRET not in json.dumps(sanitise_secrets(dirty))


def test_key_inside_a_list_of_dicts_is_removed():
    dirty = {"calls": [{"api_key": SECRET}, {"api_key": SECRET, "n": 2}]}
    clean = sanitise_secrets(dirty)
    assert clean == {"calls": [{}, {"n": 2}]}


def test_key_matching_is_case_insensitive():
    assert sanitise_secrets({"API_KEY": SECRET}) == {}
    assert sanitise_secrets({"Virustotal_Api_Key": SECRET}) == {}


def test_every_known_secret_key_is_stripped():
    dirty = {k: SECRET for k in SECRET_KEYS}
    assert sanitise_secrets(dirty) == {}


def test_the_input_is_not_mutated():
    dirty = {"request": {"api_key": SECRET}}
    sanitise_secrets(dirty)
    assert dirty == {"request": {"api_key": SECRET}}


def test_non_dict_values_pass_through():
    assert sanitise_secrets("plain") == "plain"
    assert sanitise_secrets([1, 2]) == [1, 2]
    assert sanitise_secrets(None) is None


def test_tuples_are_preserved_as_lists_or_tuples():
    result = sanitise_secrets({"t": ({"api_key": SECRET}, 2)})
    assert SECRET not in json.dumps(result, default=str)


def test_html_raw_modules_uses_the_recursive_strip():
    from reporting.html_reporter.debug import raw_modules

    rows = raw_modules(
        [
            {
                "module": "virustotal",
                "status": "success",
                "data": {"request": {"api_key": SECRET}},
            }
        ]
    )
    assert SECRET not in rows[0]["json"]


def test_json_report_uses_the_recursive_strip():
    from reporting.json_reporter import build_json_report

    report = {
        "file": "/samples/x.exe",
        "module_results": [
            {
                "module": "virustotal",
                "status": "success",
                "data": {"request": {"api_key": SECRET}},
                "score_delta": 0,
                "reason": "",
            }
        ],
        "scoring": {"total_score": 0, "risk_band": "LOW", "breakdown": []},
        "timing": {},
        "dynamic": None,
    }
    assert SECRET not in json.dumps(build_json_report(report), default=str)
