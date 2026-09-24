"""End-to-end scans of the real malware corpus, checked as rendered text.

Every other test in this suite feeds the reporters a frozen fixture. That
is what makes them fast and reproducible, and it is also why six defects
survived them: a fixture cannot notice that a reason was cut mid-word,
that a wrapped verdict restarted at column 0, that a row of three flags
was reading the wrong keys, or that the one URL in the report meant to be
clicked had been folded in half. Snapshots could not either — they are
captured with ``no_color=True`` and store wrapped text as a single string,
so they recorded the broken layout as correct.

So this module runs the pipeline over real samples and asserts against
what a person would actually see. It is the cheap half of "run the tool
against the malware": not a replacement for looking at the output, but a
guard that stops the specific faults already found from coming back.

Design notes
------------
**Skipped whole when the corpus is absent.** The samples are live malware
and are not in the repository, so a clean checkout and CI both skip this
file rather than fail. `CORPUS_ROOT` points at the directory the project
notes record.

**One sample per format, not the whole corpus.** These are real scans, so
the cost is real. One file from each format directory covers every row
builder in the tree, which is what the invariants below are about; the
per-module detection work is covered by that module's own tests.

**`virustotal` and `capa_analysis` are excluded by default.** The first
needs the network and a key and sleeps on the free tier's rate limit; the
second takes up to 120 seconds on a large sample and times out on some of
them. Both are exercised by ``-m corpus_slow``, which is deselected in
the default run.

**The assertions are about rendering, not verdicts.** Scores move
whenever a weight is tuned, and a test that pins them would fail on every
calibration change for no benefit. What is pinned is that the report is
readable: hashes and links survive whole, blocks keep their indentation,
truncation announces itself, and nothing renders a placeholder where a
value should be.
"""

from __future__ import annotations

import copy
import io
import os
import re
from pathlib import Path

import pytest

from core.config_loader import DEFAULTS
from core.pipeline import run_pipeline
from reporting.terminal_reporter import print_terminal_report
from reporting.terminal_reporter._common import use_console
from tests.conftest import make_console

#: Where the samples live. Overridable so another machine can point at
#: its own copy without editing the file.
CORPUS_ROOT = Path(
    os.environ.get("THREATLENS_CORPUS", "/home/pmafma/Documents/Malware")
)

#: The format directories, and the modules each one is there to exercise.
_FORMATS = (
    "exe test malware",
    "doc and docx test malware",
    "xlsm test malware",
    "rtf test malware",
    "pdf test malware",
    "html smuggling test malware",
    "onenote test malware",
    "lnk test malware",
    "zip test malware",
    "rar test malware",
)

#: Excluded from the default run. `virustotal` needs the network and a
#: key; `capa_analysis` can spend two minutes on one sample.
_SLOW_MODULES = ("virustotal", "capa_analysis")

#: Width the report is rendered at for these checks. 100 is the CLI's own
#: `max_content_width`, so it is the width most people see.
_WIDTH = 100

pytestmark = pytest.mark.skipif(
    not CORPUS_ROOT.is_dir(),
    reason=f"malware corpus not present at {CORPUS_ROOT}",
)


def _first_sample(directory: str) -> Path | None:
    """The first real sample in a format directory, or None.

    Sorted so the choice is the same on every run — an arbitrary sample
    that changes between runs makes a failure impossible to reproduce.
    Dotfiles and the corpus's own README are skipped.
    """
    folder = CORPUS_ROOT / directory
    if not folder.is_dir():
        return None
    for path in sorted(folder.iterdir()):
        if path.is_file() and not path.name.startswith(".") and path.suffix != ".txt":
            return path
    return None


def _scan(path: Path, *, slow: bool = False) -> dict:
    """Scan *path* with the default module set.

    Built from ``DEFAULTS`` rather than ``get_config`` on purpose: the
    result must not depend on whether this machine has a config.yaml, or
    on what someone has tuned in it. The point of comparison is the
    shipped configuration.
    """
    config = copy.deepcopy(DEFAULTS)
    if not slow:
        config["enabled_modules"] = [
            m for m in config["enabled_modules"] if m not in _SLOW_MODULES
        ]
    return run_pipeline(path, config)


def _render(report: dict, detail_level: int = 0) -> str:
    buf = io.StringIO()
    with use_console(make_console(_WIDTH, file=buf)):
        print_terminal_report(report, detail_level=detail_level)
    return buf.getvalue()


@pytest.fixture(scope="module")
def scanned() -> dict[str, tuple[dict, str]]:
    """One ``(report, rendered text)`` pair per format, scanned once.

    Module-scoped because these are real scans: repeating them per
    assertion would turn a twenty-second suite into a minutes-long one
    for no extra coverage. The report is kept alongside the text so an
    assertion can compare what was rendered against what was found,
    rather than guessing at the output with a regex.
    """
    out: dict[str, tuple[dict, str]] = {}
    for directory in _FORMATS:
        sample = _first_sample(directory)
        if sample is None:
            continue
        report = _scan(sample)
        out[sample.name] = (report, _render(report))
    if not out:
        pytest.skip("corpus directory present but holds no samples")
    return out


@pytest.fixture(scope="module")
def rendered(scanned) -> dict[str, str]:
    """Just the text, for the assertions that do not need the report."""
    return {name: text for name, (_report, text) in scanned.items()}


# ── the report is produced at all ───────────────────────────────────


def test_every_format_produces_a_report(rendered):
    """A format directory that renders nothing is the loudest failure."""
    assert rendered, "no samples rendered"
    for name, text in rendered.items():
        assert text.strip(), f"{name} rendered an empty report"
        assert "Traceback" not in text, f"{name} leaked a traceback into the report"


# ── nothing overflows the terminal ──────────────────────────────────


def test_no_line_overflows_the_console(rendered):
    """A line past the width wraps where the terminal chooses, not here.

    Box borders then fail to line up and a table looks broken. The
    permalink is the deliberate exception: it is printed with
    ``soft_wrap`` precisely so it stays one logical line and survives a
    copy, so it is expected to run past the edge.
    """
    for name, text in rendered.items():
        for line in text.splitlines():
            if "virustotal.com/gui/file/" in line:
                continue
            assert len(line) <= _WIDTH, (
                f"{name}: {len(line)}-column line at width {_WIDTH}: {line!r}"
            )


# ── identifiers survive whole ───────────────────────────────────────


def _sha256_values(report: dict) -> set[str]:
    """Every 64-hex string anywhere in the report's own data.

    Taken from the report rather than matched out of the text, because a
    regex over the rendering cannot tell a folded SHA256 from an intact
    MD5 or imphash — both are runs of lowercase hex, and the first
    version of this test failed on ACRStealer.exe's MD5 for exactly that
    reason.
    """
    found: set[str] = set()

    def walk(node):
        if isinstance(node, str):
            if len(node) == 64 and all(c in "0123456789abcdef" for c in node):
                found.add(node)
        elif isinstance(node, dict):
            for value in node.values():
                walk(value)
        elif isinstance(node, (list, tuple)):
            for value in node:
                walk(value)

    walk(report.get("module_results"))
    return found


def test_every_sha256_renders_unbroken(scanned):
    """The report's contract: a hash can be pasted straight into VT.

    Asserted against the hashes the scan actually produced, so a hash
    that reaches the page has to arrive on one line. A hash the report
    chose not to print is not this test's business — only a printed one
    that arrives in two halves.
    """
    for name, (report, text) in scanned.items():
        for digest in _sha256_values(report):
            halves = digest[:20], digest[-20:]
            if not any(half in text for half in halves):
                continue  # not rendered at this detail level
            assert digest in text, (
                f"{name}: SHA256 {digest[:16]}… reached the report folded"
            )


# ── truncation announces itself ─────────────────────────────────────


def _findings_block(text: str) -> list[str]:
    """The lines of the FINDINGS table, which is where reasons render."""
    lines = text.splitlines()
    try:
        start = next(i for i, ln in enumerate(lines) if ln.strip() == "FINDINGS")
    except StopIteration:
        return []
    # The table is box.SIMPLE, so there are no borders to look for and
    # the boundary has to come from the indentation. A row opens with one
    # space, a section heading such as "  PE Structural Indicators" with
    # exactly two, and a wrapped reason's continuation with the full
    # width of the Module and delta columns — around twenty-five.
    #
    # Testing only for "starts with two spaces" therefore ended the block
    # at the first wrapped line, which is precisely where a truncation
    # mark lands. The heading is identified by *exactly* two.
    block: list[str] = []
    for line in lines[start + 1 :]:
        if not line.strip():
            block.append(line)
            continue
        is_heading = line.startswith("  ") and not line.startswith("   ")
        if not line.startswith(" ") or is_heading:
            break
        block.append(line)
    return block


def test_a_truncated_reason_says_what_it_dropped(rendered):
    """`...` mid-sentence with no hint is how findings went missing.

    The FINDINGS table used to cut a reason at a character offset and
    append a bare `...`, which reads as a mangled word rather than a
    truncation and named none of the findings it dropped.

    Scoped to that table on purpose. Elsewhere a bare ellipsis is
    correct: the HTML and PDF panels preview a base64 blob and a
    JavaScript snippet, where there are no findings to count and the cut
    is self-evidently a cut.
    """
    for name, text in rendered.items():
        for line in _findings_block(text):
            stripped = line.rstrip()
            # The cut is at the end of the rendered reason, so that is
            # where the check has to be. Asserting only that the report
            # contains a hint somewhere would pass on a report that
            # truncated one reason silently and announced another.
            assert not stripped.endswith("..."), (
                f"{name}: reason truncated with a bare ellipsis: {line!r}"
            )


# ── no placeholder stands in for a value ────────────────────────────


def test_no_row_renders_a_bare_placeholder(rendered):
    """"?" in a value column reads as a parse failure.

    It was the fallback for a nested archive with no member name, which
    is the ordinary shape of an SFX payload rather than an error.
    """
    for name, text in rendered.items():
        for line in text.splitlines():
            cells = [cell.strip() for cell in line.split("│")]
            assert "?" not in cells, f"{name}: bare '?' in a table cell: {line!r}"


#: The shape the MacroRaptor row used to render. Matched precisely
#: rather than searching for "=False" anywhere, because these reports
#: carry strings pulled out of real malware and a payload is perfectly
#: entitled to contain "debug=False".
_FLAG_EQUALS_FALSE_RE = re.compile(r"\b[A-Z]=False\b")


def test_no_row_renders_every_flag_false(rendered):
    """Three Falses in a row is what reading the wrong keys looks like.

    The MacroRaptor row rendered "A=False, W=False, X=False" on
    documents flagged for all three, because it read the attribute names
    off MacroRaptor's own object rather than the keys the module stores.
    """
    for name, text in rendered.items():
        hit = _FLAG_EQUALS_FALSE_RE.search(text)
        assert hit is None, (
            f"{name}: a row rendered {hit.group()!r} — check the flag key names"
        )


# ── wrapped prose keeps its shape ───────────────────────────────────


def test_the_verdict_block_keeps_its_indent(rendered):
    """A verdict that wraps must not restart at column 0.

    The indent used to be two spaces inside the string, so rich applied
    it to the first line only and the rest read as a stray paragraph.
    """
    for name, text in rendered.items():
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if "/100" not in line or "█" not in line:
                continue
            for following in lines[index + 1 :]:
                if not following.strip():
                    continue
                # The verdict is the only prose between the score bar and
                # the FINDINGS heading; anything else ends the block.
                if following.strip() == "FINDINGS" or following.lstrip().startswith(
                    ("╭", "│", "╰", "─")
                ):
                    break
                assert following.startswith("  "), (
                    f"{name}: verdict line lost its indent: {following!r}"
                )
            break


# ── the slow modules, on request ────────────────────────────────────


@pytest.mark.corpus_slow
def test_a_scan_with_every_module_enabled_still_renders():
    """`-m corpus_slow`: the default run excludes capa and VirusTotal.

    Both were skipped for every sample report during the reporting pass,
    which is exactly why the folded VirusTotal permalink went unseen —
    no rendered report had ever contained that table.
    """
    sample = _first_sample("exe test malware")
    if sample is None:
        pytest.skip("no PE sample in the corpus")

    text = _render(_scan(sample, slow=True))

    assert text.strip()
    assert "Traceback" not in text
