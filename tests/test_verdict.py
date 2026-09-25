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


# ------------------------------------------------ coverage of scored findings
#
# Measured over the 311-sample corpus: 23 files scored above zero and
# rendered no verdict line at all, and six modules had scored results the
# sentence never mentioned. Each test below is one of those gaps.


def test_doc_altchunk_reaches_the_verdict():
    """Eleven corpus .docx — Formbook x5, RemcosRAT x2 — score +12 for this
    and rendered a blank verdict. The branch read template_injection["ooxml"]
    while an altChunk lands in template_injection["alt_chunks"]."""
    data = {"indicator_flags": ["altchunk", "altchunk_absolute_path"],
            "template_injection": {"ooxml": [], "alt_chunks": ["/word/lset.rtf"]}}
    assert "altChunk" in build_verdict([result("doc_analysis", data)], HIGH)


def test_doc_shell_explorer_reaches_the_verdict():
    """UKR2.rtf, +5 for an embedded WebBrowser control, blank verdict."""
    data = {"indicator_flags": ["shell_explorer"]}
    assert "remote content" in build_verdict([result("doc_analysis", data)], HIGH)


def test_doc_dangerous_embedded_file_reaches_the_verdict():
    data = {"indicator_flags": ["dangerous_embedded_file"]}
    verdict = build_verdict([result("doc_analysis", data)], HIGH)
    assert "dangerous file extension" in verdict


def test_doc_rtf_objupdate_reaches_the_verdict():
    """Formbook.rtf and unknown7.rtf, +4 each, blank verdict."""
    data = {"indicator_flags": ["rtf_objupdate"]}
    assert "open" in build_verdict([result("doc_analysis", data)], HIGH)


def test_every_scored_doc_flag_reaches_the_verdict():
    """A flag the scoring rules pay for must reach the sentence.

    The mirror of ``test_every_emitted_flag_is_scored`` one layer up. That
    test exists because five flags were emitted and never scored; this one
    exists because eleven were scored and never narrated. Both failure
    modes are invisible without a mechanical check, because the list on
    each side is hand-written.

    Sourced from COMBO_RULES rather than from a literal list here, so a
    new rule cannot be added without either narrating its flags or saying
    in ``_VERDICT_EXEMPT_DOC_FLAGS`` why it is not worth narrating.
    """
    from modules.static.doc_analysis.scoring import COMBO_RULES

    scored = {flag for flags, _, _ in COMBO_RULES for flag in flags}
    missing = []
    for flag in sorted(scored):
        if flag in shared._VERDICT_EXEMPT_DOC_FLAGS:
            continue
        data = {"indicator_flags": [flag]}
        if not build_verdict([result("doc_analysis", data)], HIGH):
            missing.append(flag)
    assert missing == [], f"scored doc flags absent from the verdict: {missing}"


def test_pdf_raw_javascript_reaches_the_verdict_without_peepdf():
    """pdf-zeroday.pdf, +20, blank verdict: peepdf reported parse errors so
    has_javascript was False while the raw sweep held /JavaScript and /JS.
    Same shape as the `encrypted: false` defect fixed in 0.5.x."""
    data = {"has_javascript": False,
            "raw_keyword_hits": {"/JavaScript": 2, "/JS": 1}}
    assert "JavaScript" in build_verdict([result("pdf_analysis", data)], HIGH)


def test_pdf_embedded_files_name_tree_alone_is_not_an_attachment():
    """The plural key is the name tree. Reporting an attachment from it is
    the false positive pdf_analysis had removed; the verdict must not
    reintroduce it."""
    data = {"raw_keyword_hits": {"/EmbeddedFiles": 1}}
    assert "embedded file" not in build_verdict([result("pdf_analysis", data)], HIGH)


def test_html_clickfix_lure_reaches_the_verdict_without_a_lolbin():
    """ClickFix2/3 and unknown.html score +15..+30 for a clipboard write plus
    a paste lure. The copied text is a template literal at parse time, so
    requiring a LOLBin inside it requires the one thing not yet there."""
    data = {"has_clipboard_write": True,
            "clipboard_contains_lolbin": False,
            "social_eng_patterns": ["Paste instruction (Ctrl+V)"]}
    assert "ClickFix" in build_verdict([result("html_analysis", data)], HIGH)


def test_ioc_domain_reaches_the_verdict():
    """DonutLoader.lnk, +5 for the typosquat amazom.my, blank verdict."""
    data = {"iocs": {"domain": ["amazom.my"]}}
    assert build_verdict([result("ioc_extractor", data)], HIGH)


def test_ioc_registry_key_and_email_reach_the_verdict():
    reg = {"iocs": {"registry_key": [r"HKCU\Software\Microsoft\Windows\Run"]}}
    assert build_verdict([result("ioc_extractor", reg)], HIGH)
    mail = {"iocs": {"email": ["a@b.com"]}}
    assert build_verdict([result("ioc_extractor", mail)], HIGH)


def test_string_high_severity_category_reaches_the_verdict():
    """AgentTesla.exe scores +10 for these two and said nothing."""
    data = {"suspicious_categories": ["Anti-debug API reference",
                                      "Code injection API string"],
            "suspicious_matches": [
                {"category": "Anti-debug API reference", "severity": "high"},
                {"category": "Code injection API string", "severity": "high"}]}
    verdict = build_verdict([result("string_analysis", data)], HIGH)
    assert "Anti-debug API reference" in verdict


def test_string_low_severity_alone_does_not_reach_the_verdict():
    """'Crypto algorithm reference' fires on 60 of 311 corpus samples — any
    binary that speaks TLS — and scores nothing. It must not take a slot."""
    data = {"suspicious_categories": ["Crypto algorithm reference"],
            "suspicious_matches": [
                {"category": "Crypto algorithm reference", "severity": "low"}]}
    assert build_verdict([result("string_analysis", data, delta=0)], HIGH) == ""


def test_string_credential_category_still_reaches_the_verdict():
    """Regression guard: the categories the old substring map covered must
    survive the move to severity tiers."""
    data = {"suspicious_categories": ["Password/credential assignment"],
            "suspicious_matches": [
                {"category": "Password/credential assignment",
                 "severity": "medium"}]}
    assert build_verdict([result("string_analysis", data)], HIGH)


def test_floss_obfuscation_bonus_reaches_the_verdict():
    """A flat +10 for stack-built or runtime-decoded strings — the module's
    whole argument for carrying the FLOSS dependency, and the one signal no
    regex can produce. Unobservable from this corpus: bin/floss is absent,
    so the sweep that found the other gaps could not see this one."""
    data = {"suspicious_categories": [], "suspicious_matches": [],
            "floss_decoded_strings": 12, "floss_stack_strings": 3}
    assert "decoded" in build_verdict([result("string_analysis", data)], HIGH)


def test_virustotal_embedded_payload_reaches_the_verdict_when_container_is_unknown():
    """The container hash is new to VirusTotal, so `found` is False and the
    primary starts at -5 — but _lookup_embedded_hashes adds the payload's
    detections onto that same result. Gating the branch on `found` hid the
    one thing VirusTotal did know: an archive nobody has submitted, carrying
    a payload fifty engines flag."""
    data = {"found": False, "malicious": 0,
            "embedded_hash_lookups": [
                {"name": "invoice.exe", "found": True, "malicious": 52,
                 "suspicious": 2, "threat_label": "trojan.formbook"}]}
    verdict = build_verdict([result("virustotal", data, delta=15)], HIGH)
    # 54, not 52: malicious + suspicious, the same sum the primary hash
    # branch reports, so the two cannot read as different scales.
    assert "VirusTotal" in verdict and "54" in verdict


# ----------------------------------------------------------------- invariant


def test_a_module_that_scored_always_yields_a_sentence():
    """Design rule 1 makes every module return a human-readable `reason` for
    its score. So a scoring module can always be narrated, and a blank
    verdict under a non-zero score is never correct — it only means this
    function did not recognise the shape. The fallback is the module's own
    reason rather than a second vocabulary maintained here."""
    data = {"indicator_flags": ["bulk_packed_timestamps"],
            "detected_format": "rar"}
    verdict = build_verdict(
        [{"module": "archive_analysis", "status": "success", "data": data,
          "score_delta": 2,
          "reason": "Bulk-packed timestamps (+1); Nested archive layer (+1)"}],
        {"risk_band": "LOW"},
    )
    assert verdict, "a scoring module rendered no verdict at all"
    assert "(+1)" not in verdict, "scoring noise leaked into the sentence"
    assert "bulk-packed timestamps" in verdict


def test_fallback_keeps_an_acronym_or_camelcase_lead_word():
    """The clause follows "… file with ", so it is folded to lower case —
    but only when the first word is ordinary prose. Modules open reasons
    with "RTF uses", "VBA stomping" and "AutoExec + Shell call"."""
    for reason, expected in (
        ("RTF uses \\objupdate (+4)", "RTF uses"),
        ("VBA stomping detected (+8)", "VBA stomping"),
        ("AutoExec + Shell call (+10)", "AutoExec + Shell"),
        ("Bulk-packed timestamps (+1)", "bulk-packed timestamps"),
    ):
        verdict = build_verdict(
            [{"module": "doc_analysis", "status": "success", "data": {},
              "score_delta": 4, "reason": reason}], {"risk_band": "LOW"})
        assert expected in verdict, f"{reason!r} -> {verdict!r}"


def test_fallback_does_not_fire_when_a_branch_matched():
    """The fallback is a floor, not a supplement — a recognised finding must
    not be followed by a restatement of the same module's reason."""
    data = {"indicator_flags": ["path_traversal"], "detected_format": "rar"}
    verdict = build_verdict(
        [{"module": "archive_analysis", "status": "success", "data": data,
          "score_delta": 10, "reason": "Path traversal member (+10)"}], HIGH)
    assert "traversal" in verdict
    assert "Path traversal member" not in verdict


def test_fallback_survives_a_module_with_no_reason():
    """`reason` is guaranteed by design rule 1, but a module returning an
    empty one must not produce 'Low-risk file with ' trailing a preposition."""
    bare = {"module": "archive_analysis", "status": "success",
            "data": {}, "score_delta": 3, "reason": ""}
    verdict = build_verdict([bare], {"risk_band": "LOW"})
    assert not verdict.rstrip().endswith("with")


def test_doc_flag_order_is_reproducible():
    """The sentence must not depend on set-iteration order.

    The first version of the flag loop iterated the set directly. Measured
    across five PYTHONHASHSEED values it produced five different sentences
    for one document, and the four-item cut hid a different finding each
    time — so which finding an analyst saw was decided by hash
    randomisation.
    """
    import subprocess
    import sys

    script = (
        "import sys; sys.path.insert(0, '.');"
        "from reporting.shared import build_verdict;"
        "d={'indicator_flags':['altchunk','altchunk_absolute_path',"
        "'dangerous_embedded_file','shell_explorer','htmlfile']};"
        "print(build_verdict([{'module':'doc_analysis','status':'success',"
        "'data':d,'score_delta':12,'reason':''}],{'risk_band':'HIGH'}))"
    )
    seen = {
        subprocess.run([sys.executable, "-c", script], capture_output=True,
                       text=True, env={"PYTHONHASHSEED": str(seed), "PATH": "/usr/bin"},
                       cwd=".").stdout.strip()
        for seed in range(1, 6)
    }
    assert len(seen) == 1, f"verdict varies with hash seed: {seen}"


def test_a_qualifier_does_not_outrank_the_finding_it_qualifies():
    """altchunk_absolute_path scores +2 and describes where the altChunk
    from the +6 altchunk flag points. Ranking it first read backwards."""
    data = {"indicator_flags": ["altchunk", "altchunk_absolute_path"]}
    body = build_verdict([result("doc_analysis", data)], HIGH).split("with ")[1]
    assert body.startswith("altChunk import")


def test_floss_bonus_reads_whatever_shape_the_module_reports():
    """The two FLOSS keys are counts, set from len() in string_analysis.

    Pinned because the verdict branch reads them and a reviewer read them
    as lists. Either shape must work, and neither may raise: this runs
    inside a reporter, where design rule 2 forbids an exception.
    """
    for decoded, stack in ((12, 0), (0, 3), ([], ["a"]), (["x"], []), (0, 0)):
        data = {"suspicious_matches": [],
                "floss_decoded_strings": decoded, "floss_stack_strings": stack}
        verdict = build_verdict([result("string_analysis", data)], HIGH)
        assert bool(verdict) == bool(decoded or stack), (decoded, stack, verdict)
