"""The one-line verdict sentence, shared by both reporters.

Before Pass 4 it branched on 5 of 12 modules with no else, so a ClickFix
HTML page, a malicious PDF, a path-traversal RAR and a YARA hit all
produced an empty string. Both callers render nothing when it is empty,
and Pass 2's layout leans on that line.
"""

import inspect

import reporting.shared as shared
from core.pipeline import _MODULE_REGISTRY
from reporting.shared import build_verdict

HIGH = {"risk_band": "HIGH"}
MEDIUM = {"risk_band": "MEDIUM"}


def result(module, data, delta=10, status="success"):
    return {
        "module": module,
        "status": status,
        "data": data,
        "score_delta": delta,
        "reason": "",
    }


# ------------------------------------------------------------------- coverage


def test_every_scoring_module_is_covered():
    """file_intake is the one exemption — it never scores."""
    source = inspect.getsource(shared.build_verdict)
    missing = [
        m for m in _MODULE_REGISTRY if m not in source and m != "file_intake"
    ]
    assert missing == [], f"uncovered modules: {missing}"


def test_yara_match_reaches_the_verdict():
    verdict = build_verdict(
        [result("yara_scanner", {"matches": [{"rule": "SUSP_RTF_MalVer"}]})], HIGH
    )
    assert "SUSP_RTF_MalVer" in verdict


def test_multiple_yara_matches_are_counted():
    matches = [{"rule": f"RULE_{i}"} for i in range(4)]
    verdict = build_verdict([result("yara_scanner", {"matches": matches})], HIGH)
    assert "RULE_0" in verdict and "+3" in verdict


def test_doc_autoexec_macro_reaches_the_verdict():
    data = {"macros": {"vba": {"present": True, "auto_exec_keywords": ["AutoOpen"]}}}
    assert "auto-executing macro" in build_verdict([result("doc_analysis", data)], HIGH)


def test_doc_stomping_reaches_the_verdict():
    data = {"macros": {"vba": {"present": True, "stomping_detected": True}}}
    assert "VBA stomping" in build_verdict([result("doc_analysis", data)], HIGH)


def test_doc_template_injection_reaches_the_verdict():
    data = {"template_injection": {"ooxml": [{"severity": "high"}]}}
    assert "template injection" in build_verdict([result("doc_analysis", data)], HIGH)


def test_pdf_autoexec_reaches_the_verdict():
    data = {"raw_keyword_hits": {"/OpenAction": 1}, "has_javascript": True}
    verdict = build_verdict([result("pdf_analysis", data)], HIGH)
    assert "auto-action" in verdict or "JavaScript" in verdict


def test_pdf_header_mismatch_reaches_the_verdict():
    data = {"header_mismatch": True}
    assert "not a PDF" in build_verdict([result("pdf_analysis", data)], HIGH)


def test_html_smuggling_reaches_the_verdict():
    data = {"base64_blobs": [{"size": 1000}], "embedded_payload_types": ["PE"]}
    assert "smuggled" in build_verdict([result("html_analysis", data)], HIGH).lower()


def test_html_clickfix_reaches_the_verdict():
    data = {"has_clipboard_write": True, "clipboard_contains_lolbin": True}
    assert "ClickFix" in build_verdict([result("html_analysis", data)], HIGH)


def test_archive_traversal_reaches_the_verdict():
    data = {"detected_format": "rar", "indicator_flags": ["path_traversal"]}
    assert "traversal" in build_verdict([result("archive_analysis", data)], HIGH)


def test_archive_embedded_executable_reaches_the_verdict():
    data = {"detected_format": "zip", "embedded_executables": [{"name": "a.exe"}]}
    assert "executable" in build_verdict([result("archive_analysis", data)], HIGH)


def test_onenote_embedded_payload_reaches_the_verdict():
    data = {"blob_count": 3, "indicator_flags": ["contains_embedded_hta"]}
    assert "OneNote" in build_verdict([result("onenote_analysis", data)], HIGH)


def test_lnk_padding_evasion_leads_the_verdict():
    """The one finding an analyst cannot see in Explorer's own UI."""
    data = {
        "indicator_flags": ["args_padding_zdi", "lolbin_target"],
        "target_basename": "cmd.exe",
        "is_lolbin": True,
    }
    verdict = build_verdict([result("lnk_analysis", data)], HIGH)
    assert "ZDI-CAN-25373" in verdict


def test_real_samples_all_produce_a_verdict(
    report_redline, report_rar, report_xlsm, report_onenote, report_html,
    report_pdf, report_lnk,
):
    """No scoring sample may render a blank verdict line."""
    for report in (
        report_redline,
        report_rar,
        report_xlsm,
        report_onenote,
        report_html,
        report_pdf,
        report_lnk,
    ):
        verdict = build_verdict(report["module_results"], report["scoring"])
        assert verdict, f"empty verdict for {report['file']}"


# -------------------------------------------------------------------- ranking


def test_unsigned_binary_does_not_lead():
    """It fires for every unsigned PE and consumed the first of four slots
    on the RedLine baseline, ahead of the .NET stealer strings."""
    data = {
        "has_signature": False,
        "packers_detected": ["UPX"],
        "rwx_sections": [".text"],
    }
    verdict = build_verdict([result("pe_analysis", data)], HIGH)
    assert "unsigned" in verdict
    assert not verdict.split("with ")[1].startswith("unsigned")


def test_virustotal_outranks_everything():
    results = [
        result("pe_analysis", {"has_signature": False}),
        result("virustotal", {"found": True, "malicious": 60}),
    ]
    body = build_verdict(results, HIGH).split("with ")[1]
    assert body.startswith("VirusTotal")


def test_yara_outranks_a_packer():
    results = [
        result("pe_analysis", {"packers_detected": ["UPX"]}),
        result("yara_scanner", {"matches": [{"rule": "X"}]}),
    ]
    body = build_verdict(results, HIGH).split("with ")[1]
    assert body.startswith("YARA")


def test_redline_verdict_leads_with_real_signal(report_redline):
    verdict = build_verdict(report_redline["module_results"], report_redline["scoring"])
    assert not verdict.split("with ")[1].startswith("unsigned")


# --------------------------------------------------------------------- format


def test_empty_when_nothing_fired():
    assert build_verdict([], {"risk_band": "LOW"}) == ""


def test_zero_delta_modules_are_ignored():
    assert build_verdict([result("pe_analysis", {"has_signature": False}, 0)], HIGH) == ""


def test_failed_modules_are_ignored():
    bad = result("pe_analysis", {"has_signature": False}, 10, status="error")
    assert build_verdict([bad], HIGH) == ""


def test_band_prefix_is_not_binary_specific_for_documents():
    """'Suspicious binary' on a .docx reads wrong now that doc/pdf/html
    findings reach the verdict."""
    data = {"macros": {"vba": {"present": True, "auto_exec_keywords": ["AutoOpen"]}}}
    verdict = build_verdict([result("doc_analysis", data)], MEDIUM)
    assert "binary" not in verdict


def test_at_most_four_indicators_are_listed():
    data = {
        "has_signature": False,
        "packers_detected": ["UPX"],
        "rwx_sections": [".text"],
        "embedded_pe": {"where": "overlay"},
        "hollowing_apis": ["a", "b"],
        "dynamic_api_resolution": {"count": 9},
    }
    verdict = build_verdict([result("pe_analysis", data)], HIGH)
    assert "more)" in verdict
