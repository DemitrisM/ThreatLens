"""The OOXML hand-off between archive_analysis and doc_analysis.

An Office document is a ZIP, so exactly one of the two modules must own it.
archive_analysis defers by looking inside; doc_analysis accepts on its own,
stricter terms. Anything that satisfies the first test and fails the second
is analysed by nothing at all, which is the worst outcome the pipeline can
produce — a clean report for a file nobody opened.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from modules.static.archive_analysis import run as archive_run
from modules.static.archive_analysis.routing import is_office_ooxml_zip

_PE = b"MZ" + b"\x90\x00" * 20 + b"PE\x00\x00" + b"\x00" * 2000


def _write(path: Path, members: dict[str, bytes | str]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, body in members.items():
            archive.writestr(name, body)
    return path


_PACKAGE = {
    "[Content_Types].xml": '<?xml version="1.0"?><Types/>',
    "_rels/.rels": '<?xml version="1.0"?><Relationships/>',
    "docProps/app.xml": "<Properties/>",
    "word/document.xml": "<w:document/>",
}


def test_a_genuine_package_is_still_deferred_to_doc_analysis(tmp_path):
    """The ordinary case must not change: doc_analysis keeps owning documents."""
    target = _write(tmp_path / "real.docx", dict(_PACKAGE))

    assert is_office_ooxml_zip(target) is True
    assert archive_run(target, {})["status"] == "skipped"


def test_a_zip_wearing_an_ooxml_costume_is_analysed_as_an_archive(tmp_path):
    """Two dummy parts used to make a ZIP invisible to the whole pipeline.

    Deferring on the presence of ``[Content_Types].xml`` plus a package root
    meant an attacker could add both to an ordinary ZIP. archive_analysis
    then skipped it as a document while doc_analysis skipped it as "not an
    Office document" — verified: both returned skipped and the file scored
    nothing. The payload beside them was never examined by anything.

    A real package contains only package components, so carrying a member
    outside that set is what separates the costume from the document.
    """
    target = _write(
        tmp_path / "costume.zip",
        dict(_PACKAGE, **{"payload.exe": _PE}),
    )

    assert is_office_ooxml_zip(target) is False

    result = archive_run(target, {})

    assert result["status"] == "success"
    assert "dangerous_member" in result["data"]["indicator_flags"]
    assert any(
        d["name"] == "payload.exe" for d in result["data"]["dangerous_members"]
    )


def test_a_foreign_component_is_what_disqualifies_it_not_the_payload(tmp_path):
    """The test is structural, so a harmless foreign member disqualifies too.

    Deliberate: the rule cannot depend on recognising the payload, or an
    unrecognised one would walk straight back through the gap.
    """
    target = _write(
        tmp_path / "odd.docx",
        dict(_PACKAGE, **{"notes/readme.txt": "hello"}),
    )

    assert is_office_ooxml_zip(target) is False


def test_backslash_separated_parts_are_recognised(tmp_path):
    """Real documents in the corpus store parts with backslashes.

    ``word\\embeddings\\oleObject1.bin`` appears in the sample set. Splitting
    on forward slashes alone would read the whole string as one top-level
    component, see it is not in the allowed set, and stop deferring every
    document that embeds an object.
    """
    target = _write(
        tmp_path / "embedded.docx",
        dict(_PACKAGE, **{"word\\embeddings\\oleObject1.bin": b"\xd0\xcf\x11\xe0"}),
    )

    assert is_office_ooxml_zip(target) is True


def test_a_package_without_content_types_is_not_deferred(tmp_path):
    """Both original conditions still hold — this only adds a third."""
    members = {k: v for k, v in _PACKAGE.items() if k != "[Content_Types].xml"}
    target = _write(tmp_path / "nocontent.zip", members)

    assert is_office_ooxml_zip(target) is False


def test_a_payload_inside_a_package_directory_is_not_deferred(tmp_path):
    """Checking only the top-level component left the pockets open.

    Requiring every first path component to be a package name blocked a
    payload at the root and nothing else: `word/malware.exe` satisfies it
    perfectly. doc_analysis then ignores the unreferenced part, so the
    executable is missed exactly as before — the costume still worked, the
    payload just moved inside it.

    Measured across the corpus: none of 57 real OOXML packages contains a
    member with a dangerous extension, so refusing to defer on one costs
    nothing.
    """
    target = _write(
        tmp_path / "pocket.docx",
        dict(_PACKAGE, **{"word/malware.exe": _PE}),
    )

    assert is_office_ooxml_zip(target) is False


def test_a_package_part_that_is_not_xml_is_not_deferred(tmp_path):
    """Renaming the payload to a required part name was the other way in.

    `[Content_Types].xml` holding a PE satisfies every name-based test:
    the part is present, a package root is present, and every component is
    allowed. doc_analysis then fails to parse it and skips. All 57 real
    packages in the corpus begin that part with `<?xml `, so requiring it
    to open as XML is free.
    """
    target = _write(
        tmp_path / "notxml.docx",
        dict(_PACKAGE, **{"[Content_Types].xml": _PE}),
    )

    assert is_office_ooxml_zip(target) is False


def test_binary_package_parts_are_still_allowed(tmp_path):
    """Documents legitimately carry .bin parts — 162 of them in the corpus.

    vbaProject.bin and embedded OLE objects are binary by nature. The rule
    is about dangerous extensions and the content-types part specifically,
    not about binary content, or every macro-enabled document would stop
    reaching doc_analysis — the one module that can read its macros.
    """
    target = _write(
        tmp_path / "macro.docm",
        dict(_PACKAGE, **{"word/vbaProject.bin": b"\xd0\xcf\x11\xe0" + b"\x00" * 64}),
    )

    assert is_office_ooxml_zip(target) is True


@pytest.mark.parametrize(
    "member",
    [
        "word/.exe",            # pathlib reads no suffix at all
        "word/malware.exe ",    # pathlib reads ".exe " — Windows strips it
        "word/malware.exe.",    # pathlib reads no suffix; Windows strips it
    ],
)
def test_extension_tricks_do_not_slip_a_payload_through(tmp_path, member):
    """pathlib.suffix is the wrong tool for a security blocklist.

    ``PurePosixPath("word/.exe").suffix`` is the empty string, and a
    trailing space or dot gives ".exe " or "" — none of which match the
    blocklist. Windows strips trailing spaces and dots on extraction and
    treats a bare ``.exe`` as executable, so all three run. Matching the
    stripped name's ending is what closes it.
    """
    target = _write(tmp_path / "trick.docx", dict(_PACKAGE, **{member: _PE}))

    assert is_office_ooxml_zip(target) is False


def test_the_content_types_part_is_not_read_whole(tmp_path, monkeypatch):
    """Routing runs before the bomb guard, so it must never read a member.

    ``ZipFile.read`` decompresses the entire member before anything can
    slice it, and this check happens during routing — before the
    decompression-bomb guard has seen a single number. A
    ``[Content_Types].xml`` that inflates to gigabytes would therefore
    exhaust memory while the tool was still deciding which module owns the
    file. Only the first few bytes are ever needed.
    """
    target = _write(tmp_path / "real.docx", dict(_PACKAGE))

    def forbidden(self, *args, **kwargs):
        raise AssertionError("whole-member read during routing")

    monkeypatch.setattr(zipfile.ZipFile, "read", forbidden)

    assert is_office_ooxml_zip(target) is True


def test_declining_to_defer_does_not_cost_the_document_its_macro_analysis():
    """The predicate adds archive analysis; it never removes doc analysis.

    archive_analysis and doc_analysis are separate pipeline entries and
    doc_analysis applies its own test, so this function only decides
    whether a second module also looks at the file. Verified against a
    real macro-bearing sample: adding a foreign top-level folder makes
    is_office_ooxml_zip return False and archive_analysis run, while
    doc_analysis still succeeds with exactly the same score it gave the
    untouched document.

    This is pinned because the opposite is an easy and dangerous thing to
    assume — it would make every condition above a macro-evasion path
    rather than a hardening.
    """
    sample = next(
        (p for p in Path("/home/pmafma/Documents/Malware").rglob("*.docm")),
        None,
    )
    if sample is None:
        pytest.skip("no macro-bearing sample available on this machine")

    from core.pipeline import run_pipeline

    def deltas(path):
        report = run_pipeline(
            path,
            {"enabled_modules": ["file_intake", "archive_analysis", "doc_analysis"]},
        )
        return {
            m["module"]: (m["status"], m["score_delta"])
            for m in report["module_results"]
        }

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        altered = Path(tmp) / "altered.docm"
        with zipfile.ZipFile(sample) as src, zipfile.ZipFile(altered, "w") as dst:
            for info in src.infolist():
                dst.writestr(info, src.read(info.filename))
            dst.writestr("bypass/readme.txt", "hello")

        assert is_office_ooxml_zip(sample) is True
        assert is_office_ooxml_zip(altered) is False

        before = deltas(sample)
        after = deltas(altered)

    assert before["doc_analysis"][0] == "success"
    assert after["doc_analysis"] == before["doc_analysis"], (
        "doc_analysis must be unaffected by archive_analysis's routing"
    )
    assert after["archive_analysis"][0] == "success"


def test_an_unreadable_content_types_part_does_not_escape(tmp_path):
    """A narrow except around zf.open() was itself an evasion primitive.

    zipfile raises NotImplementedError for an unsupported compression
    method, which is not an OSError and was not caught. The exception
    escaped is_office_ooxml_zip, and although run()'s last-resort handler
    turned it into status="error", the archive was then never analysed —
    a crafted compression method on one part disabled the module for the
    whole file. Design rule 2 wants a decision here, not an exception.
    """
    target = tmp_path / "badmethod.docx"
    with zipfile.ZipFile(target, "w") as archive:
        for name, body in _PACKAGE.items():
            archive.writestr(name, body)

    # The method must be patched in the central directory, not the local
    # header: zipfile reads it from the CD, so patching the LFH alone
    # changes nothing it will ever look at.
    data = bytearray(target.read_bytes())
    cd = data.find(b"PK\x01\x02")
    assert cd > 0, "no central directory found in the fixture"
    while cd > 0:
        name_len = int.from_bytes(data[cd + 28:cd + 30], "little")
        extra_len = int.from_bytes(data[cd + 30:cd + 32], "little")
        comment_len = int.from_bytes(data[cd + 32:cd + 34], "little")
        name = bytes(data[cd + 46:cd + 46 + name_len])
        if name == b"[Content_Types].xml":
            data[cd + 10:cd + 12] = (99).to_bytes(2, "little")  # unsupported
            break
        cd = data.find(b"PK\x01\x02", cd + 46 + name_len + extra_len + comment_len)
    target.write_bytes(bytes(data))

    # The fixture really does produce the exception the code must survive.
    with zipfile.ZipFile(target) as handle:
        with pytest.raises(NotImplementedError):
            handle.open("[Content_Types].xml")

    assert is_office_ooxml_zip(target) is False


def test_an_archive_payload_inside_a_package_is_not_deferred(tmp_path):
    """Blocking only executable extensions left nested containers through.

    doc_analysis ignores an unreferenced part, so a `word/payload.rar`
    would have been deferred to it and then skipped — the same bypass as
    before, needing only an extension the executable blocklist does not
    name. Measured: none of the 57 real OOXML packages in the corpus
    contains a member with an archive extension, so refusing these is
    free.
    """
    target = _write(
        tmp_path / "nested.docx",
        dict(_PACKAGE, **{"word/payload.rar": b"Rar!\x1a\x07\x01\x00" + b"\x00" * 64}),
    )

    assert is_office_ooxml_zip(target) is False


def test_an_extensionless_payload_is_not_deferred(tmp_path):
    """A blocklist of extensions cannot be made complete.

    Naming the payload `word/payload` with no extension at all passed
    every blocked-extension test, so the package deferred and
    doc_analysis ignored the unreferenced part. The rule is an allow-list
    now: a part type the corpus does not show is a reason to analyse the
    file, not to defer it, because failing that way only means a second
    module also looks.
    """
    target = _write(tmp_path / "bare.docx", dict(_PACKAGE, **{"word/payload": _PE}))

    assert is_office_ooxml_zip(target) is False


def test_the_rels_dotfile_is_still_allowed(tmp_path):
    """`_rels/.rels` has no suffix by pathlib's reckoning but is required.

    Every one of the 57 corpus packages contains it, and it is the only
    legitimate extensionless *file* among them — the other empty-suffix
    entries are directories. An allow-list that missed this would stop
    deferring every Office document in existence.
    """
    target = _write(tmp_path / "rels.docx", dict(_PACKAGE))

    assert "_rels/.rels" in _PACKAGE
    assert is_office_ooxml_zip(target) is True


def test_directory_entries_are_allowed(tmp_path):
    """Explicit directory records carry no extension and are ordinary."""
    target = tmp_path / "withdirs.docx"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("word/", "")
        for name, body in _PACKAGE.items():
            archive.writestr(name, body)

    assert is_office_ooxml_zip(target) is True


def test_an_embedded_office_document_stops_the_deferral(tmp_path):
    """Macro-capable part types must not sit on the allow-list.

    An unreferenced `word/payload.xls` passes a list that permits Office
    formats, so the package defers, doc_analysis ignores the unreferenced
    part, and a user who unpacks the ZIP can open and run it. The
    allow-list therefore holds only part types that cannot themselves
    execute.

    Measured on the corpus: 13 of the 57 real packages carry an embedded
    .rtf, .xls or .xlsx, and every one of those 13 is a malware sample —
    the embedded-object delivery shape. They now get archive analysis as
    well as doc_analysis, which still runs on them unchanged.
    """
    for part in ("word/payload.xls", "word/payload.rtf", "word/payload.html"):
        target = _write(tmp_path / f"{part.replace('/', '_')}.docx",
                        dict(_PACKAGE, **{part: b"\xd0\xcf\x11\xe0" + b"\x00" * 64}))
        assert is_office_ooxml_zip(target) is False, part


def test_the_content_types_part_is_matched_case_insensitively(tmp_path):
    """ECMA-376 part names are case-insensitive; the lookup was not.

    A document spelling it `[content_types].xml` failed the presence test,
    and zipfile's open() is case-sensitive too, so the hardcoded spelling
    would raise KeyError and the file would be treated as not-a-document.
    Harmless in direction — it is analysed twice — but it made the
    case-insensitivity applied to the package roots meaningless for the
    one part every document must contain.
    """
    members = {
        k if k != "[Content_Types].xml" else "[content_types].xml": v
        for k, v in _PACKAGE.items()
    }
    target = _write(tmp_path / "lowercase.docx", members)

    assert is_office_ooxml_zip(target) is True


def test_a_null_byte_in_a_part_name_stops_the_deferral(tmp_path):
    """A NUL truncates the name for the consumer that extracts it.

    `word/payload.exe\\x00.png` ends with an allowed extension, so the
    allow-list passed it and the package deferred. Windows truncates at
    the NUL when writing the file out, leaving `payload.exe` on disk. No
    legitimate part name contains one, so presence alone disqualifies.
    """
    target = _write(
        tmp_path / "nul.docx",
        dict(_PACKAGE, **{"word/payload.exe\x00.png": _PE}),
    )

    assert is_office_ooxml_zip(target) is False
