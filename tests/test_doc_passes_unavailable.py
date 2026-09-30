"""doc_analysis must say which passes did not run.

Measured in the graceful-degradation audit with `oletools` masked:
`APT28.docx` scored **25 -> 9** and `AgentTesla.xlsm` **27 -> 2**, both
`status: "success"`, and with no indicator firing the reason reads
*"No suspicious OLE/VBA content detected"* — a positive claim about a document
whose macros were never opened.

The existing decision not to raise a *flag* for a missing library is correct
and is kept: an install problem must not move a score in either direction.
What it had become was "must not be mentioned", which is a different thing.
These tests pin the separation — disclose in the report, score nothing.
"""

import shutil

import pytest

from modules.static import doc_analysis
from modules.static.doc_analysis import oleid_indicators, vba_macros

#: OLE compound file magic. Enough for the router to call it `ole`; the body
#: is inert, which is all these tests need.
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


@pytest.fixture
def docx(tmp_path):
    """A minimal OOXML container — routes to `openxml`."""
    import zipfile

    p = tmp_path / "sample.docx"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document/>")
    return p


@pytest.fixture
def ole_doc(tmp_path):
    p = tmp_path / "sample.doc"
    p.write_bytes(_OLE_MAGIC + b"\x00" * 1024)
    return p


def test_a_missing_olevba_is_disclosed(docx, monkeypatch):
    """The measured defect.

    The name lives in `passes_unavailable` and in the report row; the reason
    carries the count. That split is deliberate — see
    `test_the_report_names_the_missing_pass` — because naming every pass in a
    reason truncated at ~120 characters pushed the findings that identify the
    document off the line.
    """
    monkeypatch.setattr(vba_macros, "_HAS_OLEVBA", False)

    result = doc_analysis.run(docx, {})
    data = result["data"] or {}

    assert "olevba" in str(data.get("passes_unavailable")), (
        f"the unavailable pass is not recorded: {data.get('passes_unavailable')!r}"
    )
    assert "incomplete" in result["reason"].lower(), (
        f"the report does not say the analysis was partial: {result['reason']!r}"
    )


def test_the_clean_sentence_is_replaced_not_decorated(docx, monkeypatch):
    """"No suspicious OLE/VBA content detected" must not sit beside a gap.

    Asserting safety and withdrawing it in the same line is worse than either
    half alone.
    """
    monkeypatch.setattr(vba_macros, "_HAS_OLEVBA", False)

    reason = doc_analysis.run(docx, {})["reason"]
    assert "No suspicious OLE/VBA content detected" not in reason, (
        f"the module asserted a clean document it did not fully examine: "
        f"{reason!r}"
    )


def test_the_disclosure_comes_first_so_truncation_cannot_drop_it(docx, monkeypatch):
    """`truncate_reason` cuts the tail at default verbosity.

    A notice appended after several fired indicators would be the first thing
    dropped — invisible on exactly the busy reports where it matters most.
    """
    monkeypatch.setattr(vba_macros, "_HAS_OLEVBA", False)

    reason = doc_analysis.run(docx, {})["reason"]
    head = reason.split(";")[0]
    assert "unavailable" in head.lower() or "olevba" in head, (
        f"the disclosure is not at the front of the reason: {reason!r}"
    )


def test_disclosure_does_not_move_the_score(docx, monkeypatch):
    """The existing decision, kept: an install problem scores nothing."""
    monkeypatch.setattr(vba_macros, "_HAS_OLEVBA", False)

    result = doc_analysis.run(docx, {})
    data = result["data"] or {}

    assert result["score_delta"] == 0, (
        f"a missing library moved the score to {result['score_delta']}"
    )
    flags = " ".join(str(f) for f in (data.get("indicator_flags") or []))
    assert "unavail" not in flags.lower() and "missing" not in flags.lower(), (
        f"the disclosure leaked into the scoring flags: {flags!r}"
    )


def test_a_fully_analysed_document_is_unchanged(docx):
    """No note when every applicable pass ran."""
    result = doc_analysis.run(docx, {})
    data = result["data"] or {}

    assert not data.get("passes_unavailable"), (
        f"a fully analysed document reported gaps: {data.get('passes_unavailable')!r}"
    )
    assert "unavailable" not in result["reason"].lower()


def test_a_pass_irrelevant_to_the_format_is_not_named(docx, monkeypatch):
    """`rtfobj` means nothing to a .docx.

    A warning that fires on files it cannot apply to is one analysts learn to
    ignore, which costs more than it buys.
    """
    from modules.static.doc_analysis import ole_objects

    monkeypatch.setattr(ole_objects, "_HAS_RTFOBJ", False)

    result = doc_analysis.run(docx, {})
    assert "rtfobj" not in str((result["data"] or {}).get("passes_unavailable")), (
        "an RTF-only pass was reported missing for an OOXML document"
    )


def test_an_ole_document_with_nothing_available_is_a_skip(ole_doc, monkeypatch):
    """Every applicable pass dead means no analysis happened at all.

    Consistent with fix 2 and design rule 2: a classic OLE .doc has only the
    VBA and oleid passes, both from oletools. With neither, the module has
    examined nothing and must not return success.
    """
    monkeypatch.setattr(vba_macros, "_HAS_OLEVBA", False)
    monkeypatch.setattr(vba_macros, "_HAS_MRAPTOR", False)
    monkeypatch.setattr(oleid_indicators, "_HAS_OLEID", False)

    result = doc_analysis.run(ole_doc, {})
    assert result["status"] == "skipped", (
        f"nothing was analysed and the module reported {result['status']!r}: "
        f"{result['reason']!r}"
    )
    assert result["score_delta"] == 0


@pytest.mark.skipif(shutil.which("pcodedmp") is None,
                    reason="pcodedmp present, so its absence cannot be observed here")
def test_pcodedmp_is_not_reported_missing_on_a_macro_free_document(docx):
    """The proxy trap.

    `stomping_check_performed` is false both when pcodedmp is missing and
    when there are simply no macros to check, so using it as an availability
    signal would print "pcodedmp unavailable" on every clean document.
    """
    result = doc_analysis.run(docx, {})
    assert "pcodedmp" not in str((result["data"] or {}).get("passes_unavailable"))


def test_the_report_names_the_missing_pass():
    """The reason says how many; the report says which.

    The reason line is truncated at ~120 characters, and naming every missing
    pass there pushed the findings that identify the document off the line —
    measured on APT28.docx, the analyst saw the notice instead of the AutoExec
    and Shell indicators. So the count goes in the reason and the names go in
    a row, which is not truncated.
    """
    from reporting.terminal_reporter.doc import doc_rows

    rows = doc_rows({
        "format": "openxml",
        "classification": "MALICIOUS",
        "passes_unavailable": ["VBA stomping check (pcodedmp)"],
    })
    rendered = " ".join(f"{r.label} {r.value}" for r in rows)

    assert "pcodedmp" in rendered, (
        f"the report does not name the pass that did not run: "
        f"{[(r.label, r.value) for r in rows]}"
    )


def test_no_unavailable_row_when_everything_ran():
    """The clean path gains no warning row."""
    from reporting.terminal_reporter.doc import doc_rows

    rows = doc_rows({"format": "openxml", "classification": "CLEAN",
                     "passes_unavailable": []})
    assert not [r for r in rows if "unavailable" in r.label.lower()]


def test_mraptor_is_not_reported_missing_on_a_macro_free_document(docx, monkeypatch):
    """mraptor triages macros, so its absence costs a macro-free file nothing.

    The same cry-wolf trap guarded for pcodedmp: a notice that fires on clean
    documents trains analysts to ignore it, which costs more than it buys.
    """
    monkeypatch.setattr(vba_macros, "_HAS_MRAPTOR", False)

    result = doc_analysis.run(docx, {})
    assert "mraptor" not in str((result["data"] or {}).get("passes_unavailable")), (
        "a macro-free document was told its macro triage was unavailable"
    )
