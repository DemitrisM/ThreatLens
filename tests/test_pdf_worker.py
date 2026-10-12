"""The peepdf worker boundary: every way it can fail must degrade, not raise.

The parse runs in a child process so that `os.chdir` cannot reach this one —
see `test_pdf_readonly_cwd.py` for that property. This file covers what the
separation costs: a process boundary has failure modes an in-process call does
not, and design rule 2 says every one of them ends in a degraded module rather
than a dead pipeline.

The raw keyword sweep runs regardless, so a failed structural parse still
leaves a usable result. That is the behaviour these tests pin: `status`
stays "success", the reason says what went wrong, and nothing propagates.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from modules.static import pdf_analysis


def _minimal_pdf() -> bytes:
    """A syntactically valid PDF carrying one /JavaScript action."""
    return (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction 4 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R>>endobj\n"
        b"4 0 obj<</Type/Action/S/JavaScript/JS(app.alert\\(1\\);)>>endobj\n"
        b"trailer<</Root 1 0 R>>\n%%EOF\n"
    )


@pytest.fixture
def sample(tmp_path) -> Path:
    p = tmp_path / "sample.pdf"
    p.write_bytes(_minimal_pdf())
    return p


def _assert_degraded_not_dead(result, expect_in_reason: str):
    """The module survived, said why, and scored nothing for the parse."""
    assert result["module"] == "pdf_analysis"
    assert result["status"] == "success", (
        "a failed structural parse must not fail the module — the raw keyword "
        "sweep still ran and its findings are still valid"
    )
    assert isinstance(result["score_delta"], int)
    assert expect_in_reason in result["reason"].lower(), result["reason"]


def test_a_timed_out_parse_degrades(sample, monkeypatch):
    """peepdf has never had a timeout. Now it does, and it is survivable."""
    def _boom(cmd, *a, **kw):
        raise subprocess.TimeoutExpired(cmd, kw.get("timeout", 60))

    monkeypatch.setattr(pdf_analysis, "run_contained", _boom)
    _assert_degraded_not_dead(pdf_analysis.run(sample, {}), "timed out")


def test_a_missing_worker_degrades(sample, monkeypatch):
    """The worker file absent — a broken install, or a partial copy."""
    monkeypatch.setattr(pdf_analysis, "_WORKER", Path("/nonexistent/_pdf_worker.py"))
    _assert_degraded_not_dead(pdf_analysis.run(sample, {}), "worker missing")


def test_a_crashing_worker_degrades(sample, monkeypatch):
    """A non-zero exit, which is what a segfaulting parser looks like.

    This is the case that used to take the whole scan down: peepdf is
    unmaintained and reaches C code, and an in-process crash is not catchable.
    """
    real_run = pdf_analysis.subprocess.run

    def _fail(cmd, *a, **kw):
        # Run something that exits non-zero and writes nothing, keeping the
        # real call shape so cwd and the redirections are still exercised.
        return real_run([sys.executable, "-c", "import sys; sys.exit(9)"], *a, **kw)

    monkeypatch.setattr(pdf_analysis, "run_contained", _fail)
    _assert_degraded_not_dead(pdf_analysis.run(sample, {}), "exited 9")


def test_unreadable_worker_output_degrades(sample, monkeypatch):
    """Exit 0 but the JSON is truncated or corrupt — a half-written file."""
    real_run = pdf_analysis.subprocess.run

    def _garbage(cmd, *a, **kw):
        Path(cmd[3]).write_text("{not json")
        return real_run([sys.executable, "-c", ""], *a, **kw)

    monkeypatch.setattr(pdf_analysis, "run_contained", _garbage)
    _assert_degraded_not_dead(pdf_analysis.run(sample, {}), "unreadable")


def test_the_scratch_directory_is_removed_even_when_the_child_is_killed(sample, monkeypatch, tmp_path):
    """A timeout must not leak the directory the child was parsing in.

    Extracted PDF scratch accumulating once per timed-out sample would be a
    slow disk leak on exactly the files most likely to time out.
    """
    made = []
    real_mkdtemp = pdf_analysis.tempfile.mkdtemp

    def _track(*a, **kw):
        path = real_mkdtemp(*a, **kw)
        made.append(Path(path))
        return path

    monkeypatch.setattr(pdf_analysis.tempfile, "mkdtemp", _track)
    monkeypatch.setattr(
        pdf_analysis, "run_contained",
        lambda cmd, *a, **kw: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(cmd, 1)
        ),
    )

    pdf_analysis.run(sample, {})

    assert made, "no scratch directory was created"
    assert not any(p.exists() for p in made), (
        f"scratch left behind after a killed child: "
        f"{[str(p) for p in made if p.exists()]}"
    )


def test_the_configured_timeout_reaches_the_child(sample, monkeypatch):
    """module_timeout_seconds is honoured here.

    `config_loader` has always validated this key and nothing has ever read
    it — the orchestrator still does not. This module is the first to make it
    true, so the wiring is pinned rather than assumed.
    """
    seen = {}
    real_run = pdf_analysis.subprocess.run

    def _spy(cmd, *a, **kw):
        seen["timeout"] = kw.get("timeout")
        return real_run(cmd, *a, **kw)

    monkeypatch.setattr(pdf_analysis, "run_contained", _spy)
    pdf_analysis.run(sample, {"module_timeout_seconds": 17})
    assert seen["timeout"] == 17.0


@pytest.mark.parametrize("bad", [0, -5, "banana", None])
def test_a_nonsense_timeout_falls_back_to_the_default(sample, monkeypatch, bad):
    """A config that cannot mean a duration must not disable the bound."""
    seen = {}
    real_run = pdf_analysis.subprocess.run

    def _spy(cmd, *a, **kw):
        seen["timeout"] = kw.get("timeout")
        return real_run(cmd, *a, **kw)

    monkeypatch.setattr(pdf_analysis, "run_contained", _spy)
    pdf_analysis.run(sample, {"module_timeout_seconds": bad})
    assert seen["timeout"] == float(pdf_analysis._DEFAULT_TIMEOUT)


def test_the_worker_runs_standalone_and_emits_json(sample, tmp_path):
    """The worker must not depend on the project being importable.

    It is launched by absolute path with the repository nowhere on sys.path,
    so a project import inside it would work on a developer machine — where
    the cwd happens to be the repo — and fail in the container.
    """
    out = tmp_path / "result.json"
    completed = subprocess.run(
        [sys.executable, str(pdf_analysis._WORKER), str(sample), str(out)],
        cwd=tmp_path,          # NOT the repository
        capture_output=True,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr.decode()[:300]

    payload = json.loads(out.read_text())
    assert payload["parsed"] is True
    assert payload["javascript"], "the /JavaScript action was not extracted"


def test_the_worker_rejects_wrong_arguments(tmp_path):
    """A usage error exits non-zero rather than writing an empty result."""
    completed = subprocess.run(
        [sys.executable, str(pdf_analysis._WORKER)],
        cwd=tmp_path, capture_output=True, timeout=60,
    )
    assert completed.returncode != 0


# ---------------------------------------------------------------------------
# Regressions from the review of this change. Each of these was a real defect
# in the first implementation, so each gets a test rather than a promise.
# ---------------------------------------------------------------------------

def test_an_oversized_javascript_block_still_registers(sample, monkeypatch):
    """A detection bypass, and the reason the payload cap is not a gate.

    The worker caps how many bytes of JavaScript it ships back. The first
    implementation *dropped* any block that would exceed the cap and the parent
    gated its whole JavaScript branch on the payload being non-empty — so a
    single block padded past the cap arrived as an empty list, set no
    `has_javascript`, scored nothing, and matched no patterns. One oversized
    comment would have bought an attacker silence from this module.
    """
    real_run = pdf_analysis.subprocess.run

    def _oversized(cmd, *a, **kw):
        # A worker that found one block far larger than the cap: payload
        # truncated, count still honest.
        Path(cmd[3]).write_text(json.dumps({
            "parsed": True,
            "javascript": [],          # nothing survived the cap
            "javascript_total": 1,     # but the file carries a block
            "js_truncated": True,
        }))
        return real_run([sys.executable, "-c", ""], *a, **kw)

    monkeypatch.setattr(pdf_analysis, "run_contained", _oversized)
    result = pdf_analysis.run(sample, {})

    assert result["data"]["has_javascript"] is True, (
        "a file whose JavaScript was too large to ship back still contains "
        "JavaScript, and the report must say so"
    )
    assert result["data"]["javascript_count"] == 1
    assert "javascript block" in result["reason"].lower()
    assert "truncated" in result["reason"].lower(), (
        "partial matching must be admitted, not hidden — a non-match against "
        "a shortened haystack is weaker evidence than a real one"
    )


def test_the_worker_truncates_an_oversized_block_rather_than_dropping_it(monkeypatch):
    """The other half of the same defect, on the worker's side.

    Truncating keeps a prefix the parent can still match patterns against;
    dropping leaves it nothing. This drives the real `_extract` against a
    stand-in document, rather than re-running the loop inside the test — a
    test that reimplements the code it is checking passes even when that code
    is deleted.
    """
    import peepdf.PDFCore

    from modules.static import _pdf_worker

    monkeypatch.setattr(_pdf_worker, "MAX_JS_PAYLOAD_BYTES", 100)

    class _FakeDoc:
        def getVersion(self): return "1.4"
        def isEncrypted(self): return False
        def getStats(self): return {}
        def getErrors(self): return []
        def getURIs(self): return []
        def getURLs(self): return []
        def getSuspiciousComponents(self): return []
        def getJavascriptCode(self):
            return [["app.alert(1);" + "A" * 5000]]

    class _FakeParser:
        def parse(self, target, forceMode=False, looseMode=False, **kwargs):
            return 0, _FakeDoc()

    monkeypatch.setattr(peepdf.PDFCore, "PDFParser", _FakeParser)

    found = _pdf_worker._extract("/irrelevant.pdf")

    assert found["parsed"] is True
    assert found["javascript"], (
        "an oversized block must leave a prefix behind, not an empty list — "
        "an empty list is the detection bypass this test exists for"
    )
    assert found["js_truncated"] is True
    assert found["javascript"][0].startswith("app.alert(1);"), (
        "the prefix must come from the start of the block, where the "
        "interesting calls are"
    )
    assert len(found["javascript"][0]) <= 100
    assert found["javascript_total"] == 1


def test_the_stderr_excerpt_is_read_with_a_bounded_call(sample, monkeypatch):
    """The diagnostic read must be bounded at the handle, not after the fact.

    `read_text()[:400]` pulls the entire file into memory before slicing, so a
    child that wrote gigabytes to stderr before dying would exhaust the
    orchestrator — reintroducing, at the diagnostic step, exactly what the
    DEVNULL redirection exists to prevent. The slice looks identical in the
    output either way, so the assertion is on HOW the read happens.
    """
    real_run = pdf_analysis.subprocess.run

    def _fail(cmd, *a, **kw):
        err = kw.get("stderr")
        if err is not None and hasattr(err, "write"):
            err.write(b"E" * 100_000)
            err.flush()
        return real_run([sys.executable, "-c", "import sys; sys.exit(4)"], *a, **kw)

    monkeypatch.setattr(pdf_analysis, "run_contained", _fail)

    reads: list = []
    real_open = open

    class _SpyHandle:
        def __init__(self, handle): self._handle = handle
        def read(self, size=-1):
            reads.append(size)
            return self._handle.read(size)
        def __enter__(self): return self
        def __exit__(self, *exc): self._handle.close(); return False

    def _spy_open(file, mode="r", *a, **kw):
        handle = real_open(file, mode, *a, **kw)
        if "r" in mode and str(file).endswith("stderr.log"):
            return _SpyHandle(handle)
        return handle

    monkeypatch.setattr("builtins.open", _spy_open)
    result = pdf_analysis.run(sample, {})

    assert reads, "the stderr excerpt was not read through an open handle"
    assert all(size is not None and size > 0 for size in reads), (
        f"stderr was read unbounded ({reads}) — a gigabyte of child chatter "
        f"would land in this process's memory"
    )
    assert "exited 4" in result["reason"]


def test_the_worker_survives_a_platform_without_resource(monkeypatch):
    """Losing the memory bound must not lose the module.

    `resource` is Unix-only. The project targets Linux, so this should never
    fire — but an ImportError at module scope would kill the worker, which the
    parent reports as a generic crash, silently disabling structural PDF
    analysis while looking like a parser failure.
    """
    from modules.static import _pdf_worker

    monkeypatch.setattr(_pdf_worker, "resource", None)
    _pdf_worker._limit_memory()   # must simply return


def test_an_unusable_temp_directory_degrades_without_losing_the_raw_sweep(sample, monkeypatch):
    """A full /tmp must not throw away findings that already succeeded.

    By the time the worker is launched, `_raw_keyword_scan` has run and its
    results are valid. An environmental failure in the handoff — no space, no
    inodes — must degrade the structural half and keep the rest, which is what
    the in-process version did. Letting it escape turns the whole module to
    `status: "error"` and discards work that was never in question.
    """
    def _no_space(*a, **kw):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(pdf_analysis.tempfile, "mkdtemp", _no_space)

    result = pdf_analysis.run(sample, {})
    assert result["status"] == "success", (
        "an unusable temp directory took the whole module down with it"
    )
    assert "scratch directory" in result["reason"].lower()
    # The raw sweep's own finding survives: this PDF carries /JavaScript and
    # /OpenAction, which the byte-level pass sees without peepdf.
    assert result["score_delta"] > 0, "the raw keyword sweep's findings were lost"


# ------------------------------------------------- JavaScript execution gate
#
# peepdf EXECUTES the JavaScript it recovers; it does not merely read it.
# These tests pin the three things that follow from that: the engine state is
# always reported, the switch that disables execution is actually honoured,
# and a mistyped switch is refused rather than silently leaving V8 armed.


class _RecordingParser:
    """A fake PDFParser that records how it was called and returns nothing."""

    calls: list = []

    # `manualAnalysis` defaults to None, NOT False. peepdf's real default is
    # False, so a fake that copied it would record False when the worker
    # omitted the argument entirely — and the assertion below would pass for
    # the very regression it exists to catch. None is a value the worker can
    # never pass, so omission is detectable. Raised in review.
    def parse(self, target, forceMode=False, looseMode=False, manualAnalysis=None):
        type(self).calls.append(
            {"target": target, "forceMode": forceMode,
             "looseMode": looseMode, "manualAnalysis": manualAnalysis}
        )
        return 1, None          # a refused parse — the call shape is the point


def _patch_parser(monkeypatch, parser_cls):
    """Install `parser_cls` as the PDFParser the worker imports."""
    import sys
    import types
    from modules.static import _pdf_worker

    module = types.ModuleType("peepdf.PDFCore")
    module.PDFParser = parser_cls
    monkeypatch.setitem(sys.modules, "peepdf.PDFCore", module)
    return _pdf_worker


def test_execution_is_on_by_default_and_peepdfs_flag_is_passed_explicitly(monkeypatch):
    """Default is execute, and `manualAnalysis` is never left to peepdf.

    peepdf's own default for `manualAnalysis` is False — i.e. run the script.
    Relying on that default is what made the execution undisclosed, so the
    worker must pass it explicitly even when the value agrees.
    """
    _RecordingParser.calls = []
    worker = _patch_parser(monkeypatch, _RecordingParser)

    worker._extract("/sample.pdf")

    assert len(_RecordingParser.calls) == 1
    # `is False`, not falsy: the fake records None when the argument is
    # omitted, and None is falsy too.
    assert _RecordingParser.calls[0]["manualAnalysis"] is False, \
        "manualAnalysis must be passed explicitly, not left to peepdf's default"


def test_disabling_execution_inverts_peepdfs_manual_analysis_flag(monkeypatch):
    """`execute_js=False` must become `manualAnalysis=True`, not False.

    The two names are opposites, which is exactly the kind of inversion that
    gets implemented backwards once and then ships.
    """
    _RecordingParser.calls = []
    worker = _patch_parser(monkeypatch, _RecordingParser)

    worker._extract("/sample.pdf", execute_js=False)

    assert _RecordingParser.calls[0]["manualAnalysis"] is True


def test_engine_state_is_reported_even_when_the_parse_fails(monkeypatch):
    """A failed parse must still disclose whether a JS engine ran.

    A reader needs to know the tool handed this file's script to V8 whatever
    the structural outcome was, so the disclosure cannot live only on the
    success path.
    """
    _RecordingParser.calls = []
    worker = _patch_parser(monkeypatch, _RecordingParser)

    result = worker._extract("/sample.pdf")

    assert result["parsed"] is False
    assert set(result["js_engine"]) == {
        "available", "enabled", "executed", "peepdf_version"
    }


def test_execution_cannot_be_reported_without_an_engine(monkeypatch):
    """Asking for execution on a build with no V8 binding runs nothing.

    `executed` is **False** here, not None: the parse completed and found
    script, so the question was answered — the engine simply was not there to
    run it. (`_engine_facts` alone returns None, because before the parse it
    genuinely does not know. This test deliberately goes past that point.)
    An earlier docstring here described the pre-review version of the test and
    contradicted its own assertion. Raised in review.
    """
    _force_js_module(monkeypatch, False)

    # Drive the real extraction with script PRESENT, so the only thing that
    # can keep `executed` False is the missing engine. Asserting against
    # `_engine_facts` alone proved nothing: it hardcodes None. Raised in
    # review, along with a monkeypatch that had set the function to itself.
    worker = _patch_parser(monkeypatch, _parser_returning(_doc([["app.alert(1)"]])))
    result = worker._extract("/js.pdf", execute_js=True)

    engine = result["js_engine"]
    assert engine["available"] is False
    assert engine["enabled"] is True
    assert result["javascript_total"] == 1, "script was present"
    assert engine["executed"] is False, "no engine means nothing ran"


def test_javascript_errors_are_separated_from_structural_errors(monkeypatch):
    """A script that threw must not read as a quiet file.

    peepdf routes JS failures into the same error list as malformed-xref
    complaints, so without the split "the script threw on line 1" and "bad
    PDF header" are the same finding.
    """
    class _ErrorParser:
        def parse(self, target, **kwargs):
            return 0, _ErrorDoc()

    class _ErrorDoc:
        def getVersion(self): return "1.7"
        def getEncryptionAlgorithms(self): return []
        def isEncrypted(self): return False
        def getStats(self): return {}
        def getErrors(self):
            return ["Bad PDF header",
                    "Error analysing Javascript: ReferenceError: app is not defined"]
        def getJavascriptCode(self): return []
        def getURIs(self): return []
        def getURLs(self): return []
        def getSuspiciousComponents(self): return []

    worker = _patch_parser(monkeypatch, _ErrorParser)
    result = worker._extract("/sample.pdf")

    assert result["errors"] == ["Bad PDF header"]
    assert len(result["js_errors"]) == 1
    assert "ReferenceError" in result["js_errors"][0]


def test_a_mistyped_switch_is_refused_rather_than_ignored(tmp_path):
    """An unknown third argument must not leave execution armed silently.

    The PDF is created, so a missing input cannot be the reason for the exit
    code — the mistyped switch has to be. Argument validation happens before
    the file is touched, so the original version passed for the right reason,
    but it would not have survived a reordering. Raised in review.
    """
    from modules.static import _pdf_worker

    pdf = tmp_path / "x.pdf"
    pdf.write_bytes(b"%PDF-1.7\n%%EOF\n")
    out = tmp_path / "out.json"

    code = _pdf_worker.main(["worker", str(pdf), str(out), "no-js"])

    assert code == 2
    assert not out.exists(), "a refused switch must not produce a result file"


# ------------------------------------------- `executed` means executed
#
# The first draft of the disclosure computed `executed` before parsing, from
# `enabled and available` alone, so a clean PDF carrying no script at all
# reported that its script had been executed. Raised in review. A disclosure
# that overclaims in the alarming direction is as wrong as one that hides.


def _doc(js):
    class _Doc:
        def getVersion(self): return "1.7"
        def isEncrypted(self): return False
        def getStats(self): return {}
        def getErrors(self): return []
        def getJavascriptCode(self): return js
        def getURIs(self): return []
        def getURLs(self): return []
        def getSuspiciousComponents(self): return []
    return _Doc()


def _parser_returning(doc):
    class _P:
        def parse(self, target, **kwargs): return 0, doc
    return _P


def _force_js_module(monkeypatch, present):
    """Pin `peepdf.JSAnalysis.JS_MODULE` so a test does not inherit the host's.

    This matters more than it looks. On this development host `JS_MODULE` is
    False, because the virtualenv resolves the old `peepdf` package ahead of
    `peepdf-3`; in the shipped image it is True. A test that does not pin it
    asserts something different in the two places — and `executed` is a
    conjunction including `available`, so on the host it is False whatever
    else is true. Two of these tests passed vacuously for exactly that
    reason and would have kept passing if the defect were reintroduced.
    Raised in review.
    """
    import sys
    import types
    stub = types.ModuleType("peepdf.JSAnalysis")
    stub.JS_MODULE = present
    monkeypatch.setitem(sys.modules, "peepdf.JSAnalysis", stub)


def test_a_pdf_with_no_javascript_did_not_execute_anything(monkeypatch):
    """Armed AND importable, but nothing to run — `executed` must be False.

    `available` is pinned True deliberately: without it the host's own False
    satisfies the assertion on its own and the test proves nothing.
    """
    _force_js_module(monkeypatch, True)
    worker = _patch_parser(monkeypatch, _parser_returning(_doc([])))
    result = worker._extract("/clean.pdf", execute_js=True)

    engine = result["js_engine"]
    assert engine["enabled"] is True
    assert engine["available"] is True, "the point of this test needs an engine"
    assert engine["executed"] is False, "a PDF with no script executed nothing"


def test_a_pdf_with_javascript_did_execute(monkeypatch):
    """Armed, importable, and script present — `executed` is True."""
    _force_js_module(monkeypatch, True)
    worker = _patch_parser(monkeypatch, _parser_returning(_doc([["app.alert(1)"]])))
    result = worker._extract("/js.pdf", execute_js=True)

    assert result["js_engine"]["executed"] is True


def test_disabling_execution_means_nothing_ran_even_with_script_present(monkeypatch):
    """Script present but the engine disarmed — `executed` must be False.

    `available` is pinned True so that disarming is the ONLY thing that can
    keep `executed` False. Without the pin this passed on the host for the
    same vacuous reason `_force_js_module` was written to prevent — and I had
    not applied it here. Raised in review.
    """
    _force_js_module(monkeypatch, True)
    worker = _patch_parser(monkeypatch, _parser_returning(_doc([["app.alert(1)"]])))
    result = worker._extract("/js.pdf", execute_js=False)

    engine = result["js_engine"]
    assert engine["available"] is True, "disarming must be the only cause"
    assert engine["enabled"] is False
    assert engine["executed"] is False


def test_the_disclosure_survives_a_worker_that_never_reported(monkeypatch, tmp_path):
    """A timeout or crash must not silently drop the disclosure.

    Those are the failures a hostile script is most likely to cause, so the
    keys must still be there — with `None` meaning "not known" rather than a
    confident False, and without handing a consumer a KeyError. Driven
    through the real module rather than asserted against its source.
    Raised in review.
    """
    from modules.static import pdf_analysis

    pdf = tmp_path / "s.pdf"
    pdf.write_bytes(b"%PDF-1.7\n%%EOF\n")

    # The worker dying before it writes anything — exactly what a timeout
    # looks like to the parent.
    monkeypatch.setattr(
        pdf_analysis, "_run_worker",
        lambda *a, **k: {"parsed": False, "failure": "peepdf timed out after 60s"},
    )

    result = pdf_analysis.run(pdf, {"pdf_javascript_execution": True})
    engine = result["data"]["javascript_engine"]

    assert set(engine) == {"available", "enabled", "executed", "peepdf_version"}
    # Known from our own config even though the child never answered.
    assert engine["enabled"] is True
    # Never found out — and "not known" must not be reported as False.
    assert engine["available"] is None
    assert engine["executed"] is None
