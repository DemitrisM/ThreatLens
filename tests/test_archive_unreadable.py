"""An archive that was never opened must not be reported as clean.

Measured during the graceful-degradation audit, with `rarfile` masked against
a real RAR:

    status = "success", score_delta = 0, reason = "No archive indicators fired"

The container was never enumerated, and the module asserted the opposite on
the line that drives the verdict — the same shape as `pdf_analysis` losing
JavaScript to a read-only working directory in 0.5.15 and still reporting
success.

The two causes are deliberately not treated alike, per the archive design
notes in CLAUDE.md: *"Missing optional libraries (rarfile, py7zr, pycdlib) are
graceful skips, not errors."* An absent library says nothing about the sample;
a file that a handler reached and rejected says a great deal.

No corpus is needed here: a RAR signature followed by junk routes to the RAR
handler, which is enough to exercise the paths under test. Note it does not
*fail* there — `rarfile` parses such a file as a valid archive with no
members — so the parse-failure case makes the library raise instead, and the
empty-but-valid case is pinned as its own boundary.
"""

import sys

import pytest

from modules.static import archive_analysis

#: RAR5 signature. Enough for format detection to route to the RAR handler.
#: The body is inert: `rarfile` reads it as a valid archive containing
#: nothing, which is why it serves both the missing-library case and the
#: empty-but-valid boundary.
_RAR5_MAGIC = b"Rar!\x1a\x07\x01\x00"


@pytest.fixture
def fake_rar(tmp_path):
    p = tmp_path / "sample.rar"
    p.write_bytes(_RAR5_MAGIC + b"\x00" * 512)
    return p


@pytest.fixture
def no_rarfile(monkeypatch):
    """Make `import rarfile` raise, the way an uninstalled library does.

    The handler imports it inside the function, so masking the entry in
    `sys.modules` is enough and nothing needs reloading.
    """
    monkeypatch.setitem(sys.modules, "rarfile", None)


def test_a_missing_library_is_a_skip_not_a_clean_result(fake_rar, no_rarfile):
    """The measured defect, and the headline of this fix."""
    result = archive_analysis.run(fake_rar, {})

    assert result["status"] == "skipped", (
        f"an archive that was never opened reported {result['status']!r} "
        f"with reason {result['reason']!r}"
    )
    assert "No archive indicators fired" not in result["reason"], (
        "the module asserted a clean archive it never read"
    )
    assert "rarfile" in result["reason"], (
        f"the reason must name the missing library: {result['reason']!r}"
    )
    assert result["score_delta"] == 0


def test_an_unreadable_archive_is_an_error_and_keeps_its_data(fake_rar, monkeypatch):
    """`rarfile` present, and the file rejected by it.

    The question applied and could not be answered, which is `_error` by the
    module's own definition. The payload is kept so the format and the handler
    errors survive for the report — a skip carries no data by design rule 2,
    but an error about a real file has something to say.

    The library is made to raise rather than crafting bytes that provoke it:
    `rarfile` proved tolerant of every malformed RAR tried here — a signature
    followed by junk, by zeros, by random bytes, truncated — parsing each as a
    valid archive with no members. That is correct of it, and it means a real
    parse failure cannot be produced from a fixture. The handler's own
    `except rarfile.BadRarFile` path is what runs, so this still exercises the
    real code between the library and the verdict.
    """
    rarfile = pytest.importorskip("rarfile")

    def _reject(*a, **kw):
        raise rarfile.BadRarFile("corrupt header")

    monkeypatch.setattr(rarfile, "RarFile", _reject)
    result = archive_analysis.run(fake_rar, {})

    assert result["status"] == "error", (
        f"a file the handler rejected reported {result['status']!r}: "
        f"{result['reason']!r}"
    )
    assert "No archive indicators fired" not in result["reason"]
    assert "BadRarFile" in result["reason"] or "corrupt header" in result["reason"]

    data = result["data"] or {}
    assert data.get("detected_format") == "rar", (
        "the detected format was discarded, so the report cannot say what "
        "failed"
    )
    assert data.get("errors"), "the handler errors were discarded"


def test_an_empty_but_valid_archive_is_still_a_clean_success(fake_rar):
    """The boundary this fix must not cross.

    `rarfile` parses a RAR signature followed by junk as a valid archive with
    no members, recording no error. Nothing failed, so "No archive indicators
    fired" is the truth and must survive — the fix targets containers that
    were never read, not containers that were read and found empty.
    """
    pytest.importorskip("rarfile")
    result = archive_analysis.run(fake_rar, {})

    assert result["status"] == "success"
    assert (result["data"] or {}).get("entry_count") == 0
    assert not (result["data"] or {}).get("errors")


def test_the_import_guards_mark_the_cause_explicitly():
    """The classifier must not depend on the wording of a message.

    Matching on "not installed" would be a string contract nobody declared,
    and the next author to reword a message would silently turn a skip into
    an error.
    """
    import inspect

    from modules.static.archive_analysis import (
        other_handlers,
        rar_handler,
        sevenzip_handler,
    )

    for mod in (rar_handler, sevenzip_handler, other_handlers):
        src = inspect.getsource(mod)
        assert "missing_dependency" in src, (
            f"{mod.__name__} does not mark its ImportError path, so the "
            f"cause can only be recovered by reading the message text"
        )


def test_a_clean_archive_is_untouched(tmp_path):
    """The ordinary path keeps its wording — no incompleteness note."""
    import zipfile

    p = tmp_path / "ordinary.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("notes.txt", "nothing interesting here")

    result = archive_analysis.run(p, {})

    assert result["status"] == "success"
    assert "analysis incomplete" not in result["reason"].lower(), (
        f"a clean archive was described as incomplete: {result['reason']!r}"
    )


def test_a_nested_failure_reaches_the_parents_reason(tmp_path, no_rarfile):
    """The blind spot one level down.

    The parent merges only `indicator_flags` from its children, so a child's
    handler errors never reach the parent's own list. A RAR inside a ZIP with
    `rarfile` absent therefore enumerated the ZIP, scored `success` and said
    nothing — the audited defect, one level deeper.
    """
    import zipfile

    inner = tmp_path / "inner.rar"
    inner.write_bytes(_RAR5_MAGIC + b"\x00" * 512)

    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as zf:
        zf.write(inner, "inner.rar")

    result = archive_analysis.run(outer, {"archive_full_recursion": False})

    assert result["status"] == "success", "the outer archive was readable"
    assert "incomplete" in result["reason"].lower(), (
        "a nested archive could not be read and the parent's reason does not "
        f"admit it: {result['reason']!r}"
    )


# ---------------------------------------------------------------------------
# Regressions from the review of this fix.
# ---------------------------------------------------------------------------

def test_a_nameless_missing_dependency_does_not_crash():
    """`"".split()[0]` raises IndexError, from inside the graceful path.

    A handler that records a missing dependency without naming it is
    malformed, not fatal — and killing the pipeline from within the code
    written to keep it alive would be the worst possible place for it.
    """
    from modules.static.archive_analysis import _missing_libraries

    for bad in ({"kind": "missing_dependency"},
                {"kind": "missing_dependency", "error": ""},
                {"kind": "missing_dependency", "error": "   "}):
        assert _missing_libraries([bad]) == []


def test_a_deliberate_nested_skip_is_not_called_incomplete():
    """Only failures count, never a child that declined on purpose.

    `_analyse_archive` skips for perfectly ordinary reasons — "not an
    archive", "handled by doc_analysis". Counting those would describe an
    ordinary nested document as an incomplete analysis and put a warning on
    a clean report.
    """
    from modules.static.archive_analysis import _count_incomplete

    benign = {
        "errors": [],
        "nested": [
            {"status": "skipped", "reason": "OOXML container — handled by doc_analysis",
             "data": {}},
            {"status": "skipped", "reason": "Not applicable — not an archive", "data": {}},
            {"status": "success", "reason": "Bulk-packed timestamps (+1)", "data": {}},
        ],
    }
    assert _count_incomplete(benign) == 0


def test_a_nested_container_that_went_unread_does_count():
    """The other side of the same boundary."""
    from modules.static.archive_analysis import _UNREAD_MARKER, _count_incomplete

    unread = {
        "errors": [],
        "nested": [
            {"status": "skipped",
             "reason": f"rarfile not installed — {_UNREAD_MARKER}",
             "data": {}},
        ],
    }
    assert _count_incomplete(unread) == 1


def test_a_malformed_handler_error_still_reads_as_a_sentence():
    """A bare string in the error list must not leave a dangling reason.

    Handlers append dicts, but nothing enforces it, and "Archive could not be
    read — " trailing into nothing is a worse report than saying how many.
    """
    from modules.static.archive_analysis import _error

    result = _error("Archive could not be read — 1 handler error(s)", {"detected_format": "rar"})
    assert result["status"] == "error"
    assert not result["reason"].rstrip().endswith("—")
