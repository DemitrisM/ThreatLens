"""Tests for the PDF analysis module.

The module is two independent passes: a raw byte keyword sweep that always
runs, and a peepdf structural parse that runs only on files with a real %PDF
header. These tests concentrate on the raw sweep, because it is the pass that
has to stand on its own — peepdf is unmaintained, absent on some installs, and
skipped entirely for the header-mismatched files this module most wants to
catch.
"""

from modules.static.pdf_analysis import (
    _KEYWORD_WEIGHTS,
    _PDF_SCORE_CAP,
    _analyse,
    _raw_keyword_scan,
    run,
)


def _pdf(tmp_path, body: bytes, name: str = "sample.pdf"):
    """Write a minimal header-valid PDF containing *body*."""
    p = tmp_path / name
    p.write_bytes(b"%PDF-1.7\n" + body + b"\ntrailer\n%%EOF\n")
    return p


# ----------------------------------------------------------------------
# Module contract
# ----------------------------------------------------------------------

def test_returns_the_standard_module_result_dict(tmp_path):
    out = run(_pdf(tmp_path, b"1 0 obj\n<< /Type /Catalog >>\nendobj"), {})
    assert out["module"] == "pdf_analysis"
    assert out["status"] in {"success", "skipped", "error"}
    assert isinstance(out["data"], dict)
    assert isinstance(out["score_delta"], (int, float))
    assert isinstance(out["reason"], str)


def test_non_pdf_is_skipped(tmp_path):
    p = tmp_path / "sample.bin"
    p.write_bytes(b"MZ\x90\x00" + b"\x00" * 64)
    out = run(p, {})
    assert out["status"] == "skipped"
    assert out["score_delta"] == 0


def test_missing_file_does_not_raise(tmp_path):
    """Design rule 2 — a bad path degrades, it does not explode."""
    out = run(tmp_path / "does_not_exist.pdf", {})
    assert out["score_delta"] == 0
    assert out["status"] in {"skipped", "error"}


# ----------------------------------------------------------------------
# Raw keyword sweep
# ----------------------------------------------------------------------

def test_openaction_is_scored(tmp_path):
    delta, _, hits = _raw_keyword_scan(_pdf(tmp_path, b"<< /OpenAction 4 0 R >>"), 0)
    assert hits.get("/OpenAction") == 1
    assert delta >= _KEYWORD_WEIGHTS[b"/OpenAction"][0]


def test_embedded_files_name_tree_is_not_counted_twice(tmp_path):
    """"/EmbeddedFile" is a prefix of "/EmbeddedFiles".

    Matching is raw byte containment, so a document carrying only the
    /EmbeddedFiles name tree also matches /EmbeddedFile and was scored for
    both — 20 points for one construct that appears once.
    """
    path = _pdf(tmp_path, b"<< /Names << /EmbeddedFiles 3 0 R >> >>")
    delta, _, hits = _raw_keyword_scan(path, 0)
    assert hits.get("/EmbeddedFiles") == 1
    assert "/EmbeddedFile" not in hits
    assert delta == _KEYWORD_WEIGHTS[b"/EmbeddedFiles"][0]


def test_a_real_embedded_file_still_scores_its_full_weight(tmp_path):
    path = _pdf(tmp_path, b"<< /Type /EmbeddedFile /Length 10 >>")
    delta, _, hits = _raw_keyword_scan(path, 0)
    assert hits.get("/EmbeddedFile") == 1
    assert delta == _KEYWORD_WEIGHTS[b"/EmbeddedFile"][0]


def test_both_markers_together_score_both(tmp_path):
    """A name tree plus an actual attachment is two distinct findings."""
    path = _pdf(tmp_path, b"/Names << /EmbeddedFiles 3 0 R >>\n/Type /EmbeddedFile")
    delta, _, hits = _raw_keyword_scan(path, 0)
    assert hits.get("/EmbeddedFile") == 1
    assert hits.get("/EmbeddedFiles") == 1
    assert delta == (_KEYWORD_WEIGHTS[b"/EmbeddedFile"][0]
                     + _KEYWORD_WEIGHTS[b"/EmbeddedFiles"][0])


def test_prefix_correction_handles_a_chain_of_three(tmp_path, monkeypatch):
    """Correcting with raw counts would subtract the same bytes twice.

    With keywords A, AB and ABC, one "/ABC" contributes a match to all
    three raw counts. Subtracting both longer raw counts from A drives a
    genuine standalone "/A" to zero and loses it. The correction therefore
    runs longest-first over already-corrected counts. The table has no such
    chain today; this pins the behaviour for when one is added.
    """
    from modules.static import pdf_analysis

    monkeypatch.setattr(
        pdf_analysis, "_KEYWORD_WEIGHTS", {b"/A": (1, 1), b"/AB": (2, 1), b"/ABC": (4, 1)}
    )
    path = _pdf(tmp_path, b"/ABC and a standalone /A here")
    delta, _, hits = pdf_analysis._raw_keyword_scan(path, 0)
    assert hits == {"/A": 1, "/ABC": 1}
    assert delta == 5


# ----------------------------------------------------------------------
# Encryption
# ----------------------------------------------------------------------

def test_raw_encrypt_marker_sets_the_encrypted_flag(tmp_path):
    """The report must not contradict its own reason string.

    The raw sweep scores +10 and says "PDF is encrypted", so data must say
    so too — peepdf may be absent, may have been skipped, or may fail to
    read the encryption dictionary of a hostile file.
    """
    path = _pdf(tmp_path, b"<< /Encrypt 9 0 R /Filter /Standard >>")
    data = _analyse(path, path.stat().st_size)["data"]
    assert data["encrypted"] is True


def test_password_hint_in_filename_adds_to_the_encrypted_score(tmp_path):
    plain = _pdf(tmp_path, b"<< /Encrypt 9 0 R >>", name="invoice.pdf")
    hinted = _pdf(tmp_path, b"<< /Encrypt 9 0 R >>", name="invoice_pwd=1234.pdf")
    assert _raw_keyword_scan(hinted, 0)[0] > _raw_keyword_scan(plain, 0)[0]


# ----------------------------------------------------------------------
# Header handling
# ----------------------------------------------------------------------

def test_html_in_a_pdf_extension_is_flagged(tmp_path):
    p = tmp_path / "invoice.pdf"
    p.write_bytes(b"<!DOCTYPE html>\n<html><body>click</body></html>")
    out = run(p, {})
    assert out["data"]["header_mismatch"] is True
    assert out["score_delta"] >= 40
    assert "smuggling" in out["reason"].lower()


def test_score_is_capped(tmp_path):
    body = (b"/OpenAction /Launch /JavaScript /JS /EmbeddedFile /SubmitForm "
            b"/RichMedia /AA /XFA /GoToR /GoToE /ImportData /Encrypt "
            + b"/URI " * 40 + b"/Action " * 30)
    out = run(_pdf(tmp_path, body, name="pwd=1.pdf"), {})
    assert out["score_delta"] == _PDF_SCORE_CAP
