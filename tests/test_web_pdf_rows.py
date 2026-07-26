"""html_analysis and pdf_analysis indicator rows.

Before Pass 4 neither module rendered anything: a ClickFix sample scoring
50 produced one FINDINGS line and no indicators at all. Field names below
were catalogued from real module output, not inferred.
"""

import copy

from reporting.terminal_reporter._render import Row
from reporting.terminal_reporter.pdf import pdf_rows
from reporting.terminal_reporter.web import html_rows

VALID = {"bad", "warn", "info"}


def module_data(report: dict, module: str) -> dict:
    return next(r for r in report["module_results"] if r["module"] == module)["data"]


# ------------------------------------------------------------------ html rows


def test_html_rows_from_real_sample(report_html):
    rows = html_rows(module_data(report_html, "html_analysis"), 1)
    assert rows and all(isinstance(r, Row) for r in rows)
    assert all(r.severity in VALID for r in rows)


def test_html_rows_is_pure(report_html):
    data = module_data(report_html, "html_analysis")
    before = copy.deepcopy(data)
    html_rows(data, 0)
    html_rows(data, 1)
    assert data == before


def test_html_rows_empty_data_is_safe():
    assert html_rows({}, 0) == []


def test_html_rows_surface_the_clickfix_signal(report_html):
    """ClickFix.html: Blob chain, junk comments, obfuscated varnames,
    and C2 random-path scripts."""
    rows = html_rows(module_data(report_html, "html_analysis"), 1)
    labels = {r.label for r in rows}
    assert "Obfuscation" in labels
    assert "External scripts" in labels


def test_html_smuggled_payload_is_reported():
    data = {
        "base64_blobs": [{"size": 163840}],
        "embedded_payload_types": ["PE"],
        "has_blob_creation": True,
    }
    rows = html_rows(data, 0)
    payload = next(r for r in rows if r.label == "Smuggled payload")
    assert "PE" in payload.value
    assert payload.severity == "bad"


def test_html_clipboard_poisoning_is_reported():
    data = {
        "has_clipboard_write": True,
        "clipboard_contains_lolbin": True,
        "clipboard_lolbins_found": ["powershell.exe"],
    }
    rows = html_rows(data, 0)
    row = next(r for r in rows if r.label == "ClickFix clipboard")
    assert "powershell.exe" in row.value
    assert row.severity == "bad"


def test_html_delivery_chain_lists_mechanisms():
    data = {"has_atob": True, "has_blob_url": True, "has_onload_trigger": True}
    rows = html_rows(data, 0)
    chain = next(r for r in rows if r.label == "Delivery chain")
    for mechanism in ("atob", "Blob URL", "onload"):
        assert mechanism in chain.value


def test_html_benign_page_yields_no_bad_rows():
    data = {"num_script_blocks": 1, "encoding": "utf-8", "file_size_bytes": 900}
    assert all(r.severity == "info" for r in html_rows(data, 1))


# ------------------------------------------------------------------- pdf rows


def test_pdf_rows_from_real_sample(report_pdf):
    rows = pdf_rows(module_data(report_pdf, "pdf_analysis"), 1)
    assert rows and all(isinstance(r, Row) for r in rows)
    assert all(r.severity in VALID for r in rows)


def test_pdf_rows_is_pure(report_pdf):
    data = module_data(report_pdf, "pdf_analysis")
    before = copy.deepcopy(data)
    pdf_rows(data, 0)
    pdf_rows(data, 1)
    assert data == before


def test_pdf_rows_empty_data_is_safe():
    assert pdf_rows({}, 0) == []


def test_pdf_autoexec_comes_from_raw_keyword_hits(report_pdf):
    """The trigger lives in raw_keyword_hits, not a top-level boolean —
    the same mistake that made the triage A flag dead code."""
    rows = pdf_rows(module_data(report_pdf, "pdf_analysis"), 0)
    auto = next(r for r in rows if r.label == "Auto-execute")
    assert "/OpenAction" in auto.value
    assert auto.severity == "bad"


def test_pdf_javascript_row_shows_a_snippet(report_pdf):
    rows = pdf_rows(module_data(report_pdf, "pdf_analysis"), 0)
    js = next(r for r in rows if r.label == "JavaScript")
    assert "app.alert" in js.value


def test_pdf_encryption_is_reported():
    rows = pdf_rows({"encrypted": True, "parsed": True}, 0)
    assert any(r.label == "Encryption" and r.severity == "warn" for r in rows)


def test_pdf_header_mismatch_is_bad():
    """gamaredon.pdf is HTML wearing a .pdf extension."""
    rows = pdf_rows({"header_mismatch": True, "parsed": True}, 0)
    row = next(r for r in rows if r.label == "Header mismatch")
    assert row.severity == "bad"


def test_pdf_unparseable_file_says_so():
    rows = pdf_rows({"parsed": False, "peepdf_errors": ["broken xref"]}, 0)
    assert any(r.label == "Parse" for r in rows)


def test_pdf_uris_are_listed(report_pdf):
    rows = pdf_rows(module_data(report_pdf, "pdf_analysis"), 1)
    assert any("bociking.netlify.app" in r.value for r in rows)
