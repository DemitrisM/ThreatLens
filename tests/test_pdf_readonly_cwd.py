"""`pdf_analysis` must not depend on the working directory being writable.

Found by containerising. The shipped `docker compose` configuration sets the
working directory to the samples mount, which is deliberately read-only — a
static scan never writes to a sample. peepdf, however, writes scratch files
into the current directory while parsing, and when it cannot it abandons an
object instead of failing.

The damage is entirely silent. On `booking.pdf` the module still returned
`status: "success"`, but extracted **0 JavaScript blocks instead of 1**,
missed the social-engineering lure, and the file scored **45/MEDIUM in the
container against 65/HIGH on the host** — a band change, with nothing in the
report saying the environment had degraded the analysis.

That is the same defect class as the FLOSS degraded-run bug in 0.5.13 and the
lnk/onenote size-cap bypasses: an environmental failure rendering as a
finding about the sample.
"""

import os
import stat
from pathlib import Path

import pytest


def _minimal_pdf_with_javascript() -> bytes:
    """A valid 5-object PDF whose OpenAction runs JavaScript.

    Built byte by byte rather than taken from the corpus so the test runs on
    any machine — the corpus is not in the repository.
    """
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
        b"<< /Type /Action /S /JavaScript /JS 5 0 R >>",
        b"<< /Length 46 >>\nstream\napp.alert('open me in your browser');\nendstream",
    ]
    out = bytearray(b"%PDF-1.5\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n" % (len(objs) + 1)
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objs) + 1, xref
    )
    return bytes(out)


@pytest.fixture
def js_pdf(tmp_path) -> Path:
    p = tmp_path / "sample.pdf"
    p.write_bytes(_minimal_pdf_with_javascript())
    return p


def _js_count(path: Path) -> int:
    from modules.static.pdf_analysis import run
    return run(path, {})["data"].get("javascript_count") or 0


def test_javascript_is_found_with_a_writable_cwd(js_pdf, tmp_path, monkeypatch):
    """The control. If this fails the fixture is wrong, not the module."""
    workdir = tmp_path / "writable"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    assert _js_count(js_pdf) == 1


@pytest.mark.skipif(os.geteuid() == 0,
                    reason="root ignores directory permissions, so the premise cannot hold")
def test_javascript_is_still_found_with_a_read_only_cwd(js_pdf, tmp_path, monkeypatch):
    """The real case: the container's working directory is the :ro mount."""
    workdir = tmp_path / "readonly"
    workdir.mkdir()
    workdir.chmod(stat.S_IRUSR | stat.S_IXUSR)      # r-x------, no write
    monkeypatch.chdir(workdir)
    try:
        assert _js_count(js_pdf) == 1, (
            "peepdf lost the JavaScript because it could not write to the "
            "working directory — the analysis must not depend on that"
        )
    finally:
        workdir.chmod(stat.S_IRWXU)                  # so tmp_path cleanup works


def test_the_module_does_not_leave_scratch_files_in_the_cwd(js_pdf, tmp_path, monkeypatch):
    """Whatever peepdf writes must land somewhere the module owns.

    Deliberately **not** skipped for root, unlike the two tests above. Those
    need an unwritable directory, which root ignores, so their premise
    cannot hold. This one uses an ordinary writable directory and asserts
    nothing is left in it — valid for any user, and the check that would
    have caught the 30 stray `-peepdf-jserrors.txt` files that had
    accumulated in the repository root.
    """
    workdir = tmp_path / "clean"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    _js_count(js_pdf)
    assert list(workdir.iterdir()) == [], (
        f"scratch left in the working directory: {[p.name for p in workdir.iterdir()]}"
    )


def test_the_parse_runs_in_a_directory_the_module_owns(js_pdf, tmp_path, monkeypatch):
    """Pin the mechanism, not just the symptom.

    The two tests above only fail on a peepdf version that actually writes
    to the working directory — 5.4.1 does, 5.3.0 does not — so on a machine
    with the older one they pass whether or not the fix is present. This one
    fails on any version if the fix is removed, by checking that the parse
    happens somewhere other than where the caller was standing, and that the
    caller's directory is restored afterwards.
    """
    from modules.static import pdf_analysis

    workdir = tmp_path / "caller"
    workdir.mkdir()
    monkeypatch.chdir(workdir)

    seen = {}
    real_parse = pdf_analysis.PDFParser.parse

    def _spy(self, path, *a, **kw):
        seen["cwd"] = os.getcwd()
        seen["path"] = path
        return real_parse(self, path, *a, **kw)

    monkeypatch.setattr(pdf_analysis.PDFParser, "parse", _spy)
    pdf_analysis.run(js_pdf, {})

    assert seen, "peepdf was never invoked"
    assert seen["cwd"] != str(workdir), (
        "the parse ran in the caller's directory, so it still depends on "
        "that directory being writable"
    )
    assert Path(seen["path"]).is_absolute(), (
        "the sample path must be absolute before the directory changes, or "
        "it stops pointing at the sample"
    )
    assert os.getcwd() == str(workdir), "the caller's directory was not restored"


def test_a_symlink_loop_does_not_kill_the_pipeline(tmp_path):
    """Design rule 2, on input this tool is actually pointed at.

    The parse runs from a scratch directory, so the sample path must be made
    absolute first — and `Path.resolve()` touches the filesystem. A looping
    symlink makes it raise **RuntimeError**, which is not an OSError, so it
    would escape a narrow handler and take the whole scan down. A symlink
    loop named `.pdf` is ordinary hostile input, not an exotic case.
    """
    from modules.static.pdf_analysis import run

    a = tmp_path / "a.pdf"
    b = tmp_path / "b.pdf"
    a.symlink_to(b)
    b.symlink_to(a)

    result = run(a, {})
    assert result["module"] == "pdf_analysis"
    assert result["status"] in ("skipped", "error", "success")
    assert isinstance(result["score_delta"], int)
