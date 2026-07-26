"""Triage flag derivation and the adaptive legend."""

import io

from reporting.triage_reporter import (
    FLAGS,
    derive_flags,
    format_flags,
    print_triage_table,
)
from tests.conftest import make_console


def ok(module: str, data: dict | None = None, delta: int = 0) -> dict:
    return {
        "module": module,
        "status": "success",
        "data": data or {},
        "score_delta": delta,
    }


# ------------------------------------------------------------------ derivation


def test_no_results_gives_no_flags():
    assert derive_flags([]) == set()


def test_strings_flag_needs_a_positive_delta():
    assert derive_flags([ok("string_analysis", delta=10)]) == {"S"}
    assert derive_flags([ok("string_analysis", delta=0)]) == set()


def test_ioc_flag_fires_on_url_or_ip_only():
    assert derive_flags([ok("ioc_extractor", {"iocs": {"url": ["http://x"]}})]) == {"I"}
    assert derive_flags([ok("ioc_extractor", {"iocs": {"ipv4": ["1.2.3.4"]}})]) == {"I"}
    assert derive_flags([ok("ioc_extractor", {"iocs": {"email": ["a@b.c"]}})]) == set()


def test_yara_flag():
    assert derive_flags([ok("yara_scanner", {"matches": [{"rule": "X"}]})]) == {"Y"}
    assert derive_flags([ok("yara_scanner", {"matches": []})]) == set()


def test_macro_and_autoexec_flags():
    data = {"macros": {"vba": {"present": True, "auto_exec_keywords": ["AutoOpen"]}}}
    assert derive_flags([ok("doc_analysis", data)]) == {"M", "A"}


def test_macro_without_autoexec_does_not_set_a():
    data = {"macros": {"vba": {"present": True}}}
    assert derive_flags([ok("doc_analysis", data)]) == {"M"}


def test_pdf_openaction_sets_autoexec():
    """Regression: this branch checked has_openaction/has_launch, keys
    pdf_analysis does not emit. It reports them in raw_keyword_hits, so
    booking.pdf carried /OpenAction plus JS and earned no flag at all."""
    assert derive_flags(
        [ok("pdf_analysis", {"raw_keyword_hits": {"/OpenAction": 1}})]
    ) == {"A"}
    assert derive_flags([ok("pdf_analysis", {"raw_keyword_hits": {"/AA": 2}})]) == {"A"}
    assert derive_flags(
        [ok("pdf_analysis", {"raw_keyword_hits": {"/Launch": 1}})]
    ) == {"A"}


def test_pdf_javascript_alone_is_not_autoexec():
    """/JS can sit in a form field and never fire."""
    assert derive_flags(
        [ok("pdf_analysis", {"has_javascript": True, "raw_keyword_hits": {"/JS": 1}})]
    ) == set()


def test_pdf_without_triggers_earns_no_flag():
    assert derive_flags([ok("pdf_analysis", {"raw_keyword_hits": {}})]) == set()


def test_real_pdf_sample_is_flagged(report_pdf):
    """booking.pdf — /OpenAction + embedded JS."""
    assert "A" in derive_flags(report_pdf["module_results"])


def test_packer_flag():
    assert derive_flags([ok("pe_analysis", {"packers_detected": ["UPX"]})]) == {"P"}


def test_virustotal_flag_requires_a_detection():
    assert derive_flags([ok("virustotal", {"found": True, "malicious": 3})]) == {"V"}
    assert derive_flags([ok("virustotal", {"found": True, "malicious": 0})]) == set()
    assert derive_flags([ok("virustotal", {"found": False, "malicious": 9})]) == set()


def test_embedded_executable_flag_from_either_container():
    exe = {"embedded_executables": [{"name": "a.exe"}]}
    assert derive_flags([ok("archive_analysis", exe)]) == {"E"}
    assert derive_flags([ok("onenote_analysis", exe)]) == {"E"}


def test_embedded_flag_fires_on_a_non_pe_dropper():
    """Regression: an IcedID OneNote carries HTA blobs, not PEs, so
    embedded_executables is empty and the file used to triage with no
    flags at all despite its own rule naming an embedded HTA dropper."""
    data = {"embedded_executables": [], "blobs": [{"kind": "hta"}, {"kind": "image"}]}
    assert derive_flags([ok("onenote_analysis", data)]) == {"E"}


def test_embedded_flag_fires_on_a_contains_embedded_indicator():
    data = {"embedded_executables": [], "indicator_flags": ["contains_embedded_lnk"]}
    assert derive_flags([ok("onenote_analysis", data)]) == {"E"}


def test_image_only_container_earns_no_embedded_flag():
    """An ordinary OneNote page of screenshots is not a dropper."""
    data = {"embedded_executables": [], "blobs": [{"kind": "image"}, {"kind": "other"}]}
    assert derive_flags([ok("onenote_analysis", data)]) == set()


def test_real_onenote_sample_is_flagged(report_onenote):
    """IcedID + Qakbot.one — two HTA droppers."""
    assert "E" in derive_flags(report_onenote["module_results"])


def test_failed_modules_contribute_no_flags():
    assert derive_flags([{"module": "yara_scanner", "status": "error", "data": {}}]) == set()


def test_flags_are_ordered_canonically():
    assert format_flags({"E", "S", "A"}) == "S A E"


def test_real_sample_earns_expected_flags(report_rar):
    """NetSupport RAR carries nine embedded PE32 members."""
    assert "E" in derive_flags(report_rar["module_results"])


# ---------------------------------------------------------------------- table


def render(reports, failures=None, width=100):
    buf = io.StringIO()
    print_triage_table(
        reports, failures, elapsed=14.2, console=make_console(width, file=buf)
    )
    return buf.getvalue()


def report(name, score, band, results=None):
    return {
        "file_name": name,
        "scoring": {"total_score": score, "risk_band": band},
        "module_results": results or [],
    }


def test_rows_sort_by_score_descending():
    output = render(
        [
            report("low.exe", 12, "LOW"),
            report("critical.exe", 87, "CRITICAL"),
            report("high.exe", 68, "HIGH"),
        ]
    )
    positions = [output.index(n) for n in ("critical.exe", "high.exe", "low.exe")]
    assert positions == sorted(positions)


def test_legend_lists_only_letters_that_fired():
    output = render(
        [report("a.exe", 50, "MEDIUM", [ok("string_analysis", delta=5)])]
    )
    assert "suspicious strings" in output
    assert "YARA rule hit" not in output
    assert "macro present" not in output


def test_no_legend_when_nothing_fired():
    assert "FLAGS SEEN" not in render([report("clean.exe", 0, "LOW")])


def test_summary_counts_high_and_above():
    output = render(
        [
            report("a.exe", 87, "CRITICAL"),
            report("b.exe", 68, "HIGH"),
            report("c.exe", 10, "LOW"),
        ]
    )
    assert "3 files" in output
    assert "2 at HIGH+" in output


def test_failures_are_listed_and_counted():
    output = render([report("a.exe", 10, "LOW")], [("broken.exe", "boom")])
    assert "broken.exe" in output
    assert "ERR" in output
    assert "1 failed" in output


def test_empty_sweep_says_so():
    assert "No files analysed" in render([])


def test_every_flag_letter_has_a_description():
    for letter, flag in FLAGS.items():
        assert flag.letter == letter
        assert flag.description


# ------------------------------------------------------------------ TYPE column


def intake(description: str, file_name: str = "sample.bin") -> list[dict]:
    return [
        ok(
            "file_intake",
            {"file_name": file_name, "file_type": {"description": description}},
        )
    ]


def type_of(description, file_name="sample.bin"):
    from reporting.triage_reporter import _file_type

    return _file_type(intake(description, file_name))


def test_pe_variants_are_distinguished():
    assert type_of("PE32 executable (console) Intel 80386", "a.exe") == "PE32"
    assert type_of("PE32+ executable (GUI) x86-64", "a.exe") == "PE32+"


def test_ooxml_formats_use_the_extension_to_disambiguate():
    """libmagic calls every macro workbook 'Microsoft Excel 2007+', so the
    description alone cannot tell XLSM from XLSX."""
    assert type_of("Microsoft Excel 2007+", "GiftedCrook.xlsm") == "XLSM"
    assert type_of("Microsoft Excel 2007+", "benign.xlsx") == "XLSX"
    assert type_of("Microsoft Word 2007+", "lure.docm") == "DOCM"


def test_onenote_is_not_truncated_to_microsoft():
    """Regression: 'Microsoft OneNote' and 'Microsoft Excel 2007+' both
    rendered as 'MICROS', making two different formats indistinguishable."""
    assert type_of("Microsoft OneNote", "IcedID.one") == "ONE"
    assert type_of("Microsoft OneNote", "x.one") != type_of(
        "Microsoft Excel 2007+", "x.xlsm"
    )


def test_no_label_is_a_truncated_word():
    for desc, name in [
        ("Microsoft OneNote", "a.one"),
        ("Microsoft Excel 2007+", "a.xlsm"),
        ("Composite Document File V2 Document", "a.doc"),
        ("RAR archive data, v5", "a.rar"),
    ]:
        assert type_of(desc, name) != "MICROS"


def test_archive_and_document_formats():
    assert type_of("RAR archive data, v5", "a.rar") == "RAR"
    assert type_of("PDF document, version 1.7", "a.pdf") == "PDF"
    assert type_of("Rich Text Format data", "a.rtf") == "RTF"
    assert type_of("7-zip archive data", "a.7z") == "7Z"
    assert type_of("Composite Document File V2 Document", "a.doc") == "OLE"


def test_real_type_beats_a_lying_extension():
    """gamaredon.pdf in the corpus is actually HTML — the mismatch is a
    finding, so the TYPE column must report what the bytes say."""
    assert type_of("HTML document, ASCII text", "gamaredon.pdf") == "HTML"


def test_missing_intake_is_safe():
    from reporting.triage_reporter import _file_type

    assert _file_type([]) == "?"


def test_unknown_description_falls_back_to_the_extension():
    assert type_of("some exotic container", "thing.xyz") == "XYZ"


def test_every_fixture_gets_a_distinct_sensible_type(
    report_redline, report_rar, report_xlsm, report_onenote
):
    from reporting.triage_reporter import _file_type

    labels = [
        _file_type(r["module_results"])
        for r in (report_redline, report_rar, report_xlsm, report_onenote)
    ]
    assert labels == ["PE32", "RAR", "XLSM", "ONE"]
    assert len(set(labels)) == 4
