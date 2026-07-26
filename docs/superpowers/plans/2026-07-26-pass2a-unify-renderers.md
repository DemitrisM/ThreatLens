# Pass 2a — Unify Renderers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse five severity colour maps into one `theme.py`, and four copy-pasted indicator dialects into one `render_indicators()`, without losing any information the report prints today.

**Architecture:** Characterization tests first — pin today's rendered output as golden snapshots, then refactor underneath them. A refactor that changes output is caught immediately, and the two intended output changes (archive/onenote `Panel` → table) are reviewed as an explicit snapshot diff. Section modules become pure `*_rows(data, detail_level) -> list[Row]` builders; a single renderer owns all presentation.

**Tech Stack:** Python 3.12, `rich`, `pytest`, `jinja2`.

**Design doc:** `docs/superpowers/specs/2026-07-26-pass2-report-redesign-design.md`

---

## File Structure

| File | Responsibility |
|---|---|
| `reporting/theme.py` | **Create.** `TOKENS` — the single palette, rich + CSS. `rich_style()`, `css_root()`. |
| `reporting/console.py` | **Create.** `out`/`err` `Console` singletons. |
| `reporting/terminal_reporter/_render.py` | **Create.** `Row`, `Severity`, `render_indicators()`, `render_hash_list()`, `more_hint()`. |
| `reporting/terminal_reporter/_common.py` | **Modify.** Re-export console; `LIMITS`; derive colour maps from `theme`. |
| `reporting/terminal_reporter/pe.py` | **Modify.** `print_pe_indicators` → `pe_rows()`. |
| `reporting/terminal_reporter/doc.py` | **Modify.** `print_doc_indicators` → `doc_rows()`. |
| `reporting/terminal_reporter/archive.py` | **Modify.** `archive_rows()`; flat hash list; cap+hint fix. |
| `reporting/terminal_reporter/onenote.py` | **Modify.** `onenote_rows()`; two bug fixes. |
| `reporting/terminal_reporter/__init__.py` | **Modify.** Accept injected console; call row builders. |
| `reporting/templates/report.html.j2` | **Modify.** `:root` → `{{ theme_css }}`. |
| `tests/conftest.py` | **Create.** Fixture loading, pinned console. |
| `tests/fixtures/*.json` | **Create.** Frozen real pipeline output. |
| `tests/test_report_snapshots.py` | **Create.** Golden renders. |
| `tests/test_theme.py` | **Create.** Palette contract. |
| `tests/test_render_indicators.py` | **Create.** Renderer contract. |
| `tests/test_report_width.py` | **Create.** SHA256 unbroken at 80/100 cols. |

---

## Task 1: Capture fixtures and pin the console

Snapshots are only stable if timing, timestamps and width are fixed. This task makes that possible and changes no rendering logic.

**Files:**
- Create: `tests/fixtures/redline.json`, `tests/fixtures/netsupport_rar.json`, `tests/fixtures/onenote.json`
- Create: `tests/conftest.py`
- Modify: `reporting/terminal_reporter/__init__.py`
- Modify: `reporting/terminal_reporter/header.py`

- [ ] **Step 1: Capture the three fixtures from real samples**

```bash
cd /home/pmafma/Documents/Uni/FinalProject
mkdir -p tests/fixtures
M=/home/pmafma/Documents/Malware

.venv/bin/threatlens scan "$M/exe test malware/RedLineStealer.exe" \
  --skip virustotal,capa_analysis -f json -o tests/fixtures/redline.json

.venv/bin/threatlens scan "$M/rar test malware/ NetSupport + booking + ini.rar" \
  --modules file_intake,archive_analysis -f json -o tests/fixtures/netsupport_rar.json

.venv/bin/threatlens scan "$M/onenote test malware/IcedID + Qakbot.one" \
  --modules file_intake,onenote_analysis -f json -o tests/fixtures/onenote.json
```

Expected: three files written, exit 0 each.

Do **not** use `CVE-2025-8088 + UKR,.rar` — it hangs >110s (logged in the design doc as a separate bug).

- [ ] **Step 2: Strip volatile fields so snapshots are reproducible**

```bash
.venv/bin/python - <<'EOF'
import json, pathlib
for p in pathlib.Path("tests/fixtures").glob("*.json"):
    d = json.loads(p.read_text())
    d.get("meta", {}).pop("generated_utc", None)
    for m in d.get("module_results", []):
        m.pop("elapsed_seconds", None)
    d["timing"] = {"total_seconds": 1.0}
    # Absolute sample paths must not leak into a committed fixture.
    name = pathlib.Path(d.get("file", "sample")).name
    d["file"] = f"/samples/{name}"
    p.write_text(json.dumps(d, indent=2, sort_keys=True))
    print("normalised", p)
EOF
```

Expected: `normalised tests/fixtures/<name>.json` ×3.

- [ ] **Step 3: Verify no credential leaked into the fixtures**

```bash
grep -ric "api_key\|virustotal_api_key" tests/fixtures/ ; echo "hits above must be 0"
```

Expected: `0` for every file. If not, stop — the sanitiser is broken and that is a Pass 5 blocker, not something to commit around.

- [ ] **Step 4: Write `tests/conftest.py`**

```python
"""Shared fixtures for report-rendering tests.

Rendered rich output is only deterministic when width, colour and clock
are pinned, so every rendering test uses the console built here.
"""

import json
from pathlib import Path

import pytest
from rich.console import Console

FIXTURE_DIR = Path(__file__).parent / "fixtures"
SNAPSHOT_DIR = Path(__file__).parent / "snapshots"


def load_report(name: str) -> dict:
    """Return a frozen pipeline report dict by fixture stem."""
    return json.loads((FIXTURE_DIR / f"{name}.json").read_text())


@pytest.fixture
def report_redline() -> dict:
    return load_report("redline")


@pytest.fixture
def report_rar() -> dict:
    return load_report("netsupport_rar")


@pytest.fixture
def report_onenote() -> dict:
    return load_report("onenote")


def make_console(width: int = 100) -> Console:
    """A console that renders identically on every machine and in CI."""
    return Console(
        width=width,
        no_color=True,
        highlight=False,
        soft_wrap=False,
        force_terminal=False,
        legacy_windows=False,
    )


@pytest.fixture
def console() -> Console:
    return make_console()
```

- [ ] **Step 5: Write the failing test for console injection**

Create `tests/test_report_snapshots.py`:

```python
"""Golden-snapshot tests for the terminal reporter."""

import io

from rich.console import Console

from reporting.terminal_reporter import print_terminal_report


def render(report: dict, detail_level: int = 0, width: int = 100) -> str:
    """Render a report to a string using a pinned console."""
    buf = io.StringIO()
    console = Console(
        file=buf,
        width=width,
        no_color=True,
        highlight=False,
        force_terminal=False,
        legacy_windows=False,
    )
    print_terminal_report(report, detail_level=detail_level, console=console)
    return buf.getvalue()


def test_render_accepts_an_injected_console(report_redline):
    output = render(report_redline)
    assert "RedLineStealer.exe" in output
    assert output.count("\n") > 20
```

- [ ] **Step 6: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_report_snapshots.py -v`
Expected: FAIL — `print_terminal_report() got an unexpected keyword argument 'console'`.

- [ ] **Step 7: Thread the console through the reporter**

In `reporting/terminal_reporter/__init__.py`, change the signature and pass the console to every section. Replace the body of `print_terminal_report`:

```python
def print_terminal_report(
    report: dict,
    *,
    detail_level: int = 0,
    console: Console | None = None,
) -> None:
    """Render a complete threat report to the terminal using rich.

    Args:
        report:       Complete report dict returned by ``run_pipeline()``.
        detail_level: 0 = summary, 1 = expanded (-v), 2 = full (-vv).
        console:      Console to render to. Defaults to the stdout singleton;
                      tests inject a pinned one for reproducible output.
    """
    con = console or default_console
    scoring = report.get("scoring", {})
    module_results = report.get("module_results", [])
    timing = report.get("timing", {})
    file_path = report.get("file", "unknown")

    print_header(con)
    print_file_info(module_results, file_path, con)
    print_score_banner(scoring, module_results, con)
    print_module_table(module_results, con)

    if scoring.get("breakdown"):
        print_score_breakdown(scoring["breakdown"], con)

    print_pe_indicators(module_results, detail_level, con)
    print_doc_indicators(module_results, detail_level, con)
    print_archive_indicators(module_results, detail_level, con)
    print_onenote_indicators(module_results, detail_level, con)
    print_attack_table(module_results, detail_level, con)
    print_ioc_table(module_results, detail_level, con)
    print_suspicious_strings(module_results, detail_level, con)
    print_capabilities(module_results, detail_level, con)
    print_virustotal(module_results, detail_level, con)

    if detail_level >= 1:
        print_timing_table(module_results, timing, con)

    print_recommendations(module_results, scoring, file_path, con)
    print_footer(timing, con)
```

Add to the imports at the top of that file:

```python
from rich.console import Console

from ._common import console as default_console
```

Note `print_module_table` and `print_recommendations` lose their `file_path` argument — it is passed today and never read in either body. Drop the parameter from both definitions in `score.py` and `recommendations.py`.

Every section function in `header.py`, `score.py`, `pe.py`, `doc.py`, `archive.py`, `onenote.py`, `tables.py`, `findings.py`, `recommendations.py` gains a trailing `con: Console` parameter and uses `con.print(...)` in place of the module-level `console.print(...)`. Do not delete the module-level `console` import yet — Task 3 replaces it.

- [ ] **Step 8: Make the footer clock injectable**

In `reporting/terminal_reporter/header.py`, change `print_footer` so the timestamp can be frozen:

```python
def print_footer(timing: dict, con: Console, *, now: datetime | None = None) -> None:
    """Closing line: completion timestamp and total elapsed time."""
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M:%S UTC")
    total = timing.get("total_seconds", 0)
    con.print()
    con.print(f"[dim]Analysis complete  {stamp}  ({total:.2f}s)[/dim]")
```

Ensure `from datetime import datetime, timezone` is imported there.

- [ ] **Step 9: Run the test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_report_snapshots.py -v`
Expected: PASS.

- [ ] **Step 10: Run the whole suite — Pass 1 must stay green**

Run: `.venv/bin/python -m pytest tests/ -q`
Expected: 54 passed.

- [ ] **Step 11: Commit**

```bash
git add tests/ reporting/terminal_reporter/
git commit -m "test(report): pin console and capture fixtures for snapshots

Thread an injectable Console through print_terminal_report and make the
footer clock injectable, so rendered output is reproducible. Drop the
file_path parameter from print_module_table and print_recommendations —
it was passed and never read in either body."
```

---

## Task 2: Golden snapshots of today's output

Characterization tests. These capture **current** behaviour so the refactor that follows is provably output-preserving.

**Files:**
- Modify: `tests/test_report_snapshots.py`
- Create: `tests/snapshots/*.txt` (generated)

- [ ] **Step 1: Add the snapshot harness and tests**

Append to `tests/test_report_snapshots.py`:

```python
import os
from pathlib import Path

import pytest

SNAPSHOT_DIR = Path(__file__).parent / "snapshots"


def assert_snapshot(name: str, actual: str) -> None:
    """Compare against a golden file, or write it when updating.

    Regenerate deliberately with:
        THREATLENS_UPDATE_SNAPSHOTS=1 pytest tests/test_report_snapshots.py
    """
    SNAPSHOT_DIR.mkdir(exist_ok=True)
    path = SNAPSHOT_DIR / f"{name}.txt"

    if os.environ.get("THREATLENS_UPDATE_SNAPSHOTS"):
        path.write_text(actual)
        pytest.skip(f"snapshot {name} rewritten")

    assert path.exists(), (
        f"missing snapshot {path}. Create it with "
        f"THREATLENS_UPDATE_SNAPSHOTS=1 pytest {__file__}"
    )
    assert actual == path.read_text(), (
        f"render changed for {name}. Review the diff; if intended, rerun with "
        f"THREATLENS_UPDATE_SNAPSHOTS=1"
    )


@pytest.mark.parametrize("detail", [0, 1, 2])
@pytest.mark.parametrize(
    "fixture_name", ["redline", "netsupport_rar", "onenote"]
)
def test_snapshot(fixture_name, detail):
    from tests.conftest import load_report

    assert_snapshot(
        f"{fixture_name}_detail{detail}",
        render(load_report(fixture_name), detail_level=detail),
    )
```

- [ ] **Step 2: Generate the golden files**

Run: `THREATLENS_UPDATE_SNAPSHOTS=1 .venv/bin/python -m pytest tests/test_report_snapshots.py -q`
Expected: 9 skipped (one per fixture × detail level), 9 files in `tests/snapshots/`.

- [ ] **Step 3: Verify they now pass without the env var**

Run: `.venv/bin/python -m pytest tests/test_report_snapshots.py -q`
Expected: 10 passed.

- [ ] **Step 4: Record the `-v` ≡ `-vv` bug as a failing test**

This is the defect Pass 2b fixes. Add it now, marked expected-fail, so it flips to passing when 2b lands:

```python
@pytest.mark.xfail(
    reason="detail 1 and 2 are identical until Pass 2b adds raw module data",
    strict=True,
)
def test_verbose_levels_differ(report_redline):
    assert render(report_redline, 1) != render(report_redline, 2)
```

- [ ] **Step 5: Run and confirm it xfails**

Run: `.venv/bin/python -m pytest tests/test_report_snapshots.py -q`
Expected: 10 passed, 1 xfailed. A `strict=True` xfail that unexpectedly *passes* fails the suite, which is what we want when 2b lands.

- [ ] **Step 6: Commit**

```bash
git add tests/
git commit -m "test(report): golden snapshots of current render

Characterization tests taken before the Pass 2a refactor, so any
unintended output change is caught. Records the -v == -vv defect as a
strict xfail that will flip when Pass 2b adds raw module data."
```

---

## Task 3: `reporting/theme.py` — one palette

**Files:**
- Create: `reporting/theme.py`
- Create: `tests/test_theme.py`

- [ ] **Step 1: Write the failing test**

```python
"""The palette is the single source of colour for both reporters."""

import re

from reporting.theme import TOKENS, css_root, rich_style


def test_every_token_has_both_representations():
    for name, token in TOKENS.items():
        assert token["rich"], f"{name} has no rich style"
        assert re.fullmatch(r"#[0-9a-f]{6}", token["css"]), (
            f"{name} css value {token['css']!r} is not a 6-digit hex colour"
        )


def test_rich_style_returns_the_token_value():
    assert rich_style("critical") == TOKENS["critical"]["rich"]


def test_rich_style_falls_back_for_unknown_names():
    assert rich_style("no_such_token") == ""


def test_css_root_emits_a_variable_per_token():
    css = css_root()
    assert css.startswith(":root {")
    assert css.rstrip().endswith("}")
    for name, token in TOKENS.items():
        assert f"--{name.replace('_', '-')}:" in css
        assert token["css"] in css


def test_css_root_preserves_the_shipped_palette():
    """These values ship in report.html.j2 today and must not drift."""
    css = css_root()
    for expected in (
        "--critical:     #ff4d4f",
        "--high:         #ff8c1a",
        "--medium:       #ffd93d",
        "--low:          #5cb85c",
        "--bg:           #0f1115",
        "--accent:       #4cc9f0",
    ):
        assert expected in css, f"missing {expected!r}"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_theme.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'reporting.theme'`.

- [ ] **Step 3: Write `reporting/theme.py`**

CSS values are copied verbatim from `reporting/templates/report.html.j2` lines 8–25 so the rendered HTML does not change. Rich values are copied from the five maps this file replaces.

```python
"""The single source of colour for both reporters.

Before this module the tree held five separate severity maps: ``_SEV_STYLES``
in ``pe.py`` and ``doc.py`` (byte-identical), ``_CLASS_COLOURS`` in
``archive.py`` and ``onenote.py`` (byte-identical), ``BAND_COLOURS`` and
``STATUS_COLOURS`` in ``_common.py``, ``_IOC_TYPE_STYLES`` in ``tables.py``,
and the CSS ``:root`` block in ``report.html.j2``. Each token below carries
both representations so terminal and HTML cannot drift apart.
"""

from typing import Final, TypedDict


class Token(TypedDict):
    rich: str
    css: str


TOKENS: Final[dict[str, Token]] = {
    # Risk bands — core.scoring._BANDS
    "critical": {"rich": "bold red", "css": "#ff4d4f"},
    "high": {"rich": "bold orange1", "css": "#ff8c1a"},
    "medium": {"rich": "bold yellow", "css": "#ffd93d"},
    "low": {"rich": "bold green", "css": "#5cb85c"},
    # Indicator severities
    "bad": {"rich": "red", "css": "#ff4d4f"},
    "warn": {"rich": "yellow", "css": "#ffd93d"},
    "info": {"rich": "dim", "css": "#6b7280"},
    # Module statuses
    "success": {"rich": "green", "css": "#5cb85c"},
    "skipped": {"rich": "dim yellow", "css": "#d4a017"},
    "error": {"rich": "red", "css": "#ff4d4f"},
    # Per-module classification bands
    "malicious": {"rich": "bold red", "css": "#ff4d4f"},
    "suspicious": {"rich": "bold yellow", "css": "#ffd93d"},
    "informational": {"rich": "cyan", "css": "#4cc9f0"},
    "clean": {"rich": "green", "css": "#5cb85c"},
    # Chrome
    "bg": {"rich": "", "css": "#0f1115"},
    "bg_panel": {"rich": "", "css": "#181b22"},
    "bg_panel_2": {"rich": "", "css": "#1f232c"},
    "border": {"rich": "", "css": "#2a2f3a"},
    "text": {"rich": "", "css": "#e6e8ee"},
    "text_dim": {"rich": "dim", "css": "#9aa3b2"},
    "text_faint": {"rich": "dim", "css": "#6b7280"},
    "accent": {"rich": "cyan", "css": "#4cc9f0"},
    "code_bg": {"rich": "", "css": "#0b0d12"},
}

#: Maps a module's ``data["classification"]`` to an indicator severity.
CLASS_SEVERITY: Final[dict[str, str]] = {
    "MALICIOUS": "bad",
    "SUSPICIOUS": "warn",
    "INFORMATIONAL": "info",
    "CLEAN": "info",
}


def rich_style(name: str) -> str:
    """Rich style string for a token, or "" when the name is unknown.

    Returning "" rather than raising keeps a typo in a colour name from
    killing a report that has already completed its analysis.
    """
    token = TOKENS.get(name)
    return token["rich"] if token else ""


def css_root() -> str:
    """The ``:root`` block for the HTML template.

    Column alignment matches the block it replaces so a rendered report
    diffs cleanly against one produced before this module existed.
    """
    lines = [":root {"]
    for name, token in TOKENS.items():
        var = f"--{name.replace('_', '-')}:"
        lines.append(f"        {var:<15} {token['css']};")
    lines.append("    }")
    return "\n".join(lines)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_theme.py -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add reporting/theme.py tests/test_theme.py
git commit -m "feat(reporting): add theme.py as the single colour source

Holds every severity, band, status and chrome colour in both rich and
CSS form. CSS values are copied verbatim from report.html.j2 so the
rendered HTML is unchanged."
```

---

## Task 4: `reporting/console.py` — one pair of streams

**Files:**
- Create: `reporting/console.py`
- Modify: `cli/_console.py`
- Modify: `reporting/terminal_reporter/_common.py`
- Create: `tests/test_console_streams.py`

- [ ] **Step 1: Write the failing test**

```python
"""stdout carries results, stderr carries everything else — CLAUDE.md rule 8."""

import sys

from reporting.console import err, out


def test_out_writes_to_stdout():
    assert out.file is sys.stdout


def test_err_writes_to_stderr():
    assert err.file is sys.stderr


def test_cli_reexports_the_same_objects():
    """One stdout Console in the tree, not two competing ones."""
    from cli import _console

    assert _console.out is out
    assert _console.err is err


def test_terminal_reporter_uses_the_same_console():
    from reporting.terminal_reporter import _common

    assert _common.console is out
```

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_console_streams.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'reporting.console'`.

- [ ] **Step 3: Create `reporting/console.py`**

```python
"""The two output streams, created once.

``reporting`` is the lower layer — ``cli`` imports it, never the reverse —
so the singletons live here and ``cli/_console.py`` re-exports them. This
keeps exactly one stdout ``Console`` in the tree, which is what makes
``threatlens scan f.exe -f json | jq`` safe.
"""

from rich.console import Console

#: Results only. Anything written here is part of the report.
out = Console()

#: Progress, warnings, log lines, saved-path notices.
err = Console(stderr=True)

__all__ = ["err", "out"]
```

- [ ] **Step 4: Re-export from `cli/_console.py`**

Replace the whole file with:

```python
"""Re-export of the shared console singletons.

The objects live in ``reporting.console`` because ``reporting`` is the
lower layer. Importing them here keeps existing ``from cli._console
import out, err`` call sites working.
"""

from reporting.console import err, out

__all__ = ["err", "out"]
```

- [ ] **Step 5: Point `_common.py` at the shared console and the theme**

Replace `reporting/terminal_reporter/_common.py` with:

```python
"""Shared rich objects, colour maps and display limits.

Colour values are derived from ``reporting.theme`` — this module holds no
literals of its own. Kept separate from ``__init__.py`` so section
submodules can import without a circular import through the orchestrator.
"""

from typing import Final

from reporting.console import out as console
from reporting.theme import rich_style

BAND_COLOURS: Final[dict[str, str]] = {
    "CRITICAL": rich_style("critical"),
    "HIGH": rich_style("high"),
    "MEDIUM": rich_style("medium"),
    "LOW": rich_style("low"),
}

STATUS_COLOURS: Final[dict[str, str]] = {
    "success": rich_style("success"),
    "skipped": rich_style("skipped"),
    "error": rich_style("error"),
}

#: Row caps per section. Every one of these was an unnamed literal at its
#: use site before Pass 2a. ``None`` means uncapped.
LIMITS: Final[dict[str, int]] = {
    "attack_mappings": 10,
    "iocs_per_type": 5,
    "suspicious_strings": 10,
    "capabilities": 10,
    "onenote_blobs": 20,
    "archive_members": 50,
    "archive_execs": 50,
    "html_members": 50,
    "reason_chars": 120,
    "pdb_chars": 90,
}

__all__ = ["BAND_COLOURS", "LIMITS", "STATUS_COLOURS", "console"]
```

`archive_members` and `archive_execs` rise from today's silent `20` and `10` to `50`, and Task 7 makes truncation always announce itself.

- [ ] **Step 6: Run the test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_console_streams.py -v`
Expected: 4 passed.

- [ ] **Step 7: Confirm the render is unchanged**

Run: `.venv/bin/python -m pytest tests/ -q`
Expected: all passed, snapshots still matching. If a snapshot fails here, a colour value drifted — fix the token, do not rewrite the snapshot.

- [ ] **Step 8: Commit**

```bash
git add reporting/console.py cli/_console.py reporting/terminal_reporter/_common.py tests/test_console_streams.py
git commit -m "refactor(reporting): own the console singletons, derive colours from theme

reporting is the lower layer, so it owns out/err and cli/_console.py
re-exports them — one stdout Console in the tree. _common.py now derives
its colour maps from theme.py and names the display limits that were
inline literals."
```

---

## Task 5: `render_indicators()` — one dialect

**Files:**
- Create: `reporting/terminal_reporter/_render.py`
- Create: `tests/test_render_indicators.py`

- [ ] **Step 1: Write the failing test**

```python
"""The shared indicator renderer replaces four copy-pasted dialects."""

import io

from rich.console import Console

from reporting.terminal_reporter._render import (
    Row,
    filter_rows,
    more_hint,
    render_indicators,
)


def render(rows, detail_level=0, width=100, **kwargs):
    buf = io.StringIO()
    console = Console(file=buf, width=width, no_color=True, highlight=False)
    render_indicators("INDICATORS", rows, detail_level, console=console, **kwargs)
    return buf.getvalue()


def test_info_rows_drop_at_detail_zero_when_signal_exists():
    rows = [Row("Quiet", "nothing", "info"), Row("Loud", "danger", "bad")]
    assert filter_rows(rows, 0) == [Row("Loud", "danger", "bad")]


def test_info_rows_survive_when_nothing_else_fired():
    """A report of only info rows must not render an empty section."""
    rows = [Row("Quiet", "nothing", "info")]
    assert filter_rows(rows, 0) == rows


def test_info_rows_return_at_detail_one():
    rows = [Row("Quiet", "nothing", "info"), Row("Loud", "danger", "bad")]
    assert filter_rows(rows, 1) == rows


def test_always_show_labels_survive_filtering():
    rows = [Row("Format", "RAR", "info"), Row("Loud", "danger", "bad")]
    kept = filter_rows(rows, 0, always_show=frozenset({"Format"}))
    assert kept == [Row("Format", "RAR", "info"), Row("Loud", "danger", "bad")]


def test_order_is_preserved():
    """pe.py appended its whitelist rows and doc.py inserted at index 0;
    both reordered relative to the source list. The shared filter must not."""
    rows = [
        Row("First", "1", "bad"),
        Row("Second", "2", "info"),
        Row("Third", "3", "bad"),
    ]
    kept = filter_rows(rows, 0, always_show=frozenset({"Second"}))
    assert [r.label for r in kept] == ["First", "Second", "Third"]


def test_empty_rows_render_nothing():
    assert render([]) == ""


def test_rows_that_filter_to_empty_render_nothing():
    assert render([Row("Quiet", "x", "info")], 0, always_show=frozenset()) != ""


def test_title_and_values_appear():
    output = render([Row("Imphash", "f34d5f2d", "info")])
    assert "INDICATORS" in output
    assert "Imphash" in output
    assert "f34d5f2d" in output


def test_more_hint_wording_is_uniform():
    assert more_hint(7) == "(+7 more — use -v to show all)"


def test_more_hint_is_empty_when_nothing_hidden():
    assert more_hint(0) == ""
```

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_render_indicators.py -v`
Expected: FAIL — no module `reporting.terminal_reporter._render`.

- [ ] **Step 3: Write `reporting/terminal_reporter/_render.py`**

```python
"""Shared rendering primitives for the terminal report.

Replaces four hand-written indicator dialects: ``pe.py``/``doc.py`` built a
2-column table from ``(label, value, severity)`` tuples, while
``archive.py``/``onenote.py`` baked rich markup into hand-space-padded
strings inside a Panel. Everything now flows through ``render_indicators``.
"""

from typing import Final, Literal, NamedTuple

from rich import box
from rich.console import Console
from rich.table import Table

from reporting.theme import rich_style

from ._common import console as default_console

Severity = Literal["bad", "warn", "info"]


class Row(NamedTuple):
    """One indicator: what it is, what it says, how much it matters."""

    label: str
    value: str
    severity: Severity = "info"


_SEVERITY_RANK: Final[dict[str, int]] = {"bad": 0, "warn": 1, "info": 2}


def filter_rows(
    rows: list[Row],
    detail_level: int,
    *,
    always_show: frozenset[str] = frozenset(),
) -> list[Row]:
    """Drop ``info`` rows at detail 0 when something louder fired.

    Order is always preserved — callers used to append or insert their
    whitelist rows, which reordered them relative to the source list.
    When every row is ``info`` nothing is dropped, so a quiet section
    still renders rather than vanishing.
    """
    if detail_level >= 1:
        return list(rows)
    if not any(r.severity != "info" for r in rows):
        return list(rows)
    return [r for r in rows if r.severity != "info" or r.label in always_show]


def more_hint(hidden: int) -> str:
    """Uniform 'there is more' wording.

    Three spellings existed before this: two in ``tables.py``/``findings.py``
    as a standalone dim line, one in ``onenote.py`` as a table row.
    """
    return f"(+{hidden} more — use -v to show all)" if hidden > 0 else ""


def render_indicators(
    title: str,
    rows: list[Row],
    detail_level: int = 0,
    *,
    always_show: frozenset[str] = frozenset(),
    console: Console | None = None,
) -> None:
    """Render a severity-ranked 2-column indicator table."""
    con = console or default_console
    kept = filter_rows(rows, detail_level, always_show=always_show)
    if not kept:
        return

    table = Table(
        box=box.SIMPLE,
        padding=(0, 1),
        show_header=False,
        pad_edge=False,
    )
    table.add_column("Indicator", style="bold", no_wrap=True)
    table.add_column("Detail", overflow="fold")

    for row in kept:
        style = rich_style(row.severity)
        value = f"[{style}]{row.value}[/{style}]" if style else row.value
        table.add_row(row.label, value)

    con.print()
    con.print(f"  [bold]{title}[/bold]")
    con.print(table)


def render_hash_list(
    title: str,
    entries: list[tuple[str, str, str]],
    *,
    limit: int | None = None,
    console: Console | None = None,
) -> None:
    """Render name/meta/SHA256 triples with each hash on its own line.

    Flat rather than boxed on purpose. A SHA256 is 64 characters; box
    borders and cell padding consume 6+ columns, so at an 80-column
    terminal a boxed layout must break the hash mid-string, which
    defeats double-click copy-paste into VirusTotal. Flat layout keeps
    the hash intact down to 66 columns.
    """
    if not entries:
        return
    con = console or default_console
    shown = entries if limit is None else entries[:limit]
    hidden = len(entries) - len(shown)

    con.print()
    con.print(f"  [bold]{title}[/bold]")
    con.print()
    for name, meta, sha in shown:
        con.print(f"  [bold]{name}[/bold]  [dim]{meta}[/dim]")
        if sha:
            con.print(f"  [cyan]{sha}[/cyan]")
        con.print()
    if hidden:
        con.print(f"  [dim]{more_hint(hidden)}[/dim]")


__all__ = [
    "Row",
    "Severity",
    "filter_rows",
    "more_hint",
    "render_hash_list",
    "render_indicators",
]
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_render_indicators.py -v`
Expected: 10 passed.

- [ ] **Step 5: Commit**

```bash
git add reporting/terminal_reporter/_render.py tests/test_render_indicators.py
git commit -m "feat(reporting): add the shared indicator renderer

Row/Severity types plus render_indicators, render_hash_list and
more_hint. filter_rows preserves source order, which the four dialects
it replaces did not, and keeps info rows when nothing louder fired so a
quiet section cannot render empty."
```

---

## Task 6: Width guard for SHA256

Written before the archive conversion so the constraint is enforced, not assumed.

**Files:**
- Create: `tests/test_report_width.py`

- [ ] **Step 1: Write the test**

```python
"""A SHA256 must survive as one unbroken, copy-pasteable run.

Verified empirically at two widths before Pass 2a: a boxed layout splits a
64-char hash at 80 columns, which breaks double-click copy-paste into
VirusTotal. The flat layout holds down to 66 columns.
"""

import io
import re

import pytest
from rich.console import Console

from reporting.terminal_reporter._render import render_hash_list

SHA = "2cc8ebea55c06981625397b04575ed0eaad9bb9f9dc896355c011a62febe49b5"


def render(width):
    buf = io.StringIO()
    console = Console(file=buf, width=width, no_color=True, highlight=False)
    render_hash_list(
        "Embedded Executables",
        [("kqgWNAYv/AudioCapture.dll", "PE32  87.3 KiB", SHA)],
        console=console,
    )
    return buf.getvalue()


@pytest.mark.parametrize("width", [66, 80, 100, 120])
def test_sha256_is_never_split(width):
    assert SHA in render(width), f"hash was broken at width {width}"


@pytest.mark.parametrize("width", [80, 100])
def test_sha256_occupies_its_own_line(width):
    """Selecting the line must yield the hash and nothing else."""
    lines = [line.strip() for line in render(width).splitlines()]
    assert SHA in lines


def test_no_ellipsis_in_hash_output():
    assert "…" not in render(100)
    assert not re.search(r"\.\.\.", render(100))
```

- [ ] **Step 2: Run it**

Run: `.venv/bin/python -m pytest tests/test_report_width.py -v`
Expected: 7 passed — `render_hash_list` already satisfies this by design.

- [ ] **Step 3: Commit**

```bash
git add tests/test_report_width.py
git commit -m "test(report): guard SHA256 against being split by layout

Renders at 66/80/100/120 columns and asserts the hash appears as one
unbroken run on its own line. Stops a future refactor from silently
reintroducing the boxed layout that splits it at 80 columns."
```

---

## Task 7: Convert `pe.py` to a row builder

**Files:**
- Modify: `reporting/terminal_reporter/pe.py`
- Create: `tests/test_report_rows.py`

- [ ] **Step 1: Read the current implementation**

Run: `sed -n '1,279p' reporting/terminal_reporter/pe.py`

Note every `(label, value, severity)` tuple it appends, and the whitelist at
lines 262–269 that appends `Imphash` and `Compiled language` after filtering.
The conversion must preserve every row and its severity, changing only *where*
filtering happens.

- [ ] **Step 2: Write the failing test**

```python
"""Section modules expose pure row builders."""

from reporting.terminal_reporter._render import Row
from reporting.terminal_reporter.pe import pe_rows


def test_pe_rows_returns_rows(report_redline):
    data = next(
        r for r in report_redline["module_results"] if r["module"] == "pe_analysis"
    )["data"]
    rows = pe_rows(data, 0)
    assert rows and all(isinstance(r, Row) for r in rows)


def test_pe_rows_is_pure(report_redline):
    """Calling it twice must not mutate the module data."""
    data = next(
        r for r in report_redline["module_results"] if r["module"] == "pe_analysis"
    )["data"]
    import copy

    before = copy.deepcopy(data)
    pe_rows(data, 0)
    pe_rows(data, 1)
    assert data == before


def test_pe_rows_severities_are_valid(report_redline):
    data = next(
        r for r in report_redline["module_results"] if r["module"] == "pe_analysis"
    )["data"]
    assert all(r.severity in {"bad", "warn", "info"} for r in pe_rows(data, 1))


def test_pe_rows_empty_data_is_safe():
    assert pe_rows({}, 0) == []
```

- [ ] **Step 3: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_report_rows.py -v`
Expected: FAIL — `cannot import name 'pe_rows'`.

- [ ] **Step 4: Convert `pe.py`**

Rename the accumulator function to `pe_rows(data: dict, detail_level: int) -> list[Row]`,
returning `Row(...)` objects instead of bare tuples. Delete `_SEV_STYLES` (now
`theme.rich_style`). Delete the manual filtering and whitelist-appending block at
lines 262–269 — `filter_rows` handles it via `always_show`. Keep
`print_pe_indicators` as a thin wrapper:

```python
_PE_ALWAYS_SHOW = frozenset({"Imphash", "Compiled language"})


def print_pe_indicators(
    module_results: list[dict], detail_level: int, con: Console
) -> None:
    """PE Structural Indicators section."""
    result = next(
        (r for r in module_results if r.get("module") == "pe_analysis"), None
    )
    if not result or result.get("status") != "success":
        return
    render_indicators(
        "PE Structural Indicators",
        pe_rows(result.get("data") or {}, detail_level),
        detail_level,
        always_show=_PE_ALWAYS_SHOW,
        console=con,
    )
```

- [ ] **Step 5: Run the row tests**

Run: `.venv/bin/python -m pytest tests/test_report_rows.py -v`
Expected: 4 passed.

- [ ] **Step 6: Review the snapshot diff**

Run: `.venv/bin/python -m pytest tests/test_report_snapshots.py -q`

The PE section moves from a boxed `Table` to the shared `SIMPLE` table, so
snapshots **will** differ. Inspect the diff and confirm only styling changed
and no indicator row was lost:

```bash
git stash && .venv/bin/python -m pytest tests/test_report_snapshots.py -q ; git stash pop
diff <(sed -n '/PE Structural/,/^$/p' tests/snapshots/redline_detail1.txt) /dev/null
```

Every label present before must be present after. If a row vanished, the
conversion dropped it — fix `pe_rows`, do not rewrite the snapshot.

- [ ] **Step 7: Accept the intended snapshot change**

Run: `THREATLENS_UPDATE_SNAPSHOTS=1 .venv/bin/python -m pytest tests/test_report_snapshots.py -q`
Then: `git diff tests/snapshots/` and read it before committing.

- [ ] **Step 8: Commit**

```bash
git add reporting/terminal_reporter/pe.py tests/test_report_rows.py tests/snapshots/
git commit -m "refactor(reporting): pe.py exposes a pure row builder

pe_rows() returns Row objects; presentation moves to render_indicators.
Drops the local _SEV_STYLES copy and the whitelist-append block, which
reordered Imphash and Compiled language relative to the source list."
```

---

## Task 8: Convert `doc.py` to a row builder

**Files:**
- Modify: `reporting/terminal_reporter/doc.py`
- Modify: `tests/test_report_rows.py`

- [ ] **Step 1: Read the current implementation**

Run: `sed -n '1,195p' reporting/terminal_reporter/doc.py`

Note the six `detail_level` sites (lines 63, 86, 155, 160, 167, 179) and the
whitelist row inserted at index 0 (line 178–185).

- [ ] **Step 2: Add the failing test**

```python
def test_doc_rows_returns_rows():
    data = {
        "format": "OOXML",
        "classification": "MALICIOUS",
        "vba": {"macros_present": True, "auto_exec": ["Workbook_Open"]},
    }
    from reporting.terminal_reporter.doc import doc_rows

    rows = doc_rows(data, 0)
    assert any(r.label.startswith("Format") for r in rows)
    assert all(r.severity in {"bad", "warn", "info"} for r in rows)


def test_doc_rows_empty_data_is_safe():
    from reporting.terminal_reporter.doc import doc_rows

    assert doc_rows({}, 0) == []
```

- [ ] **Step 3: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_report_rows.py -v`
Expected: FAIL — `cannot import name 'doc_rows'`.

- [ ] **Step 4: Convert `doc.py`**

Same shape as Task 7. Delete the second `_SEV_STYLES` copy and the local
classification map at lines 27–32 (use `theme.CLASS_SEVERITY`). Replace the
index-0 insert with `always_show`:

```python
_DOC_ALWAYS_SHOW = frozenset({"Format", "Classification"})
```

Keep the `detail_level >= 1` conditions that decide whether a row is *built*
(the "checked, none detected" rows at lines 63 and 86) — those are content
decisions, not filtering, and belong in the builder.

- [ ] **Step 5: Run the tests**

Run: `.venv/bin/python -m pytest tests/test_report_rows.py -v`
Expected: 6 passed.

- [ ] **Step 6: Review and accept the snapshot diff**

Run: `.venv/bin/python -m pytest tests/test_report_snapshots.py -q`, inspect,
then `THREATLENS_UPDATE_SNAPSHOTS=1 .venv/bin/python -m pytest tests/test_report_snapshots.py -q`
and `git diff tests/snapshots/`.

- [ ] **Step 7: Commit**

```bash
git add reporting/terminal_reporter/doc.py tests/
git commit -m "refactor(reporting): doc.py exposes a pure row builder

Removes the second byte-identical _SEV_STYLES copy and the local
classification map, and replaces the index-0 whitelist insert with
always_show so source order is preserved."
```

---

## Task 9: Convert `archive.py` — rows, flat hashes, honest truncation

**Files:**
- Modify: `reporting/terminal_reporter/archive.py`
- Modify: `tests/test_report_rows.py`

- [ ] **Step 1: Write the failing tests**

```python
def test_archive_rows_from_real_sample(report_rar):
    from reporting.terminal_reporter.archive import archive_rows

    data = next(
        r
        for r in report_rar["module_results"]
        if r["module"] == "archive_analysis"
    )["data"]
    rows = archive_rows(data, 1)
    labels = [r.label for r in rows]
    assert "Format" in labels
    assert "Classification" in labels
    assert any(r.value == "MALICIOUS" and r.severity == "bad" for r in rows)


def test_archive_fired_rules_become_rows(report_rar):
    from reporting.terminal_reporter.archive import archive_rows

    data = next(
        r
        for r in report_rar["module_results"]
        if r["module"] == "archive_analysis"
    )["data"]
    rows = archive_rows(data, 1)
    assert sum(1 for r in rows if r.label == "Fired rule") == len(
        data.get("fired_rules") or []
    )


def test_truncation_always_announces_itself():
    """Today's [:20]/[:10] caps drop rows with no hint at all."""
    import io

    from rich.console import Console

    from reporting.terminal_reporter._render import render_hash_list

    buf = io.StringIO()
    console = Console(file=buf, width=100, no_color=True, highlight=False)
    entries = [(f"f{i}.dll", "PE32  1 KiB", "a" * 64) for i in range(60)]
    render_hash_list("Embedded Executables", entries, limit=50, console=console)
    assert "(+10 more — use -v to show all)" in buf.getvalue()
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_report_rows.py -v`
Expected: FAIL — `cannot import name 'archive_rows'`.

- [ ] **Step 3: Convert `archive.py`**

Replace `_summary_panel` and `_flags_table` with:

```python
def archive_rows(data: dict, detail_level: int) -> list[Row]:
    """Indicator rows for one archive container."""
    if not data or not data.get("detected_format"):
        return []

    rows: list[Row] = []
    classification = data.get("classification") or "CLEAN"
    rows.append(Row("Format", (data.get("detected_format") or "?").upper(), "info"))
    rows.append(
        Row(
            "Classification",
            classification,
            CLASS_SEVERITY.get(classification, "info"),
        )
    )
    rows.append(Row("Entries", str(data.get("entry_count", 0)), "info"))
    rows.append(
        Row("Total size", human_size(data.get("total_uncompressed_size", 0)), "info")
    )

    enc = data.get("encryption") or {}
    if enc.get("header_encrypted"):
        rows.append(Row("Encryption", "header-encrypted", "bad"))
    elif enc.get("is_encrypted"):
        rows.append(Row("Encryption", "per-file encrypted", "warn"))

    bomb = data.get("bomb_guard") or {}
    if bomb.get("triggered"):
        reasons = ", ".join(bomb.get("reasons") or [])
        rows.append(Row("Bomb guard", f"TRIGGERED — {reasons}", "bad"))

    sfx = data.get("sfx") or {}
    if sfx.get("is_sfx"):
        rows.append(
            Row(
                "SFX payload",
                f"{sfx.get('embedded_format')} @ offset {sfx.get('offset')}",
                "bad",
            )
        )
    if data.get("ace_detected"):
        rows.append(Row("ACE archive", "detected — extraction refused", "bad"))
    if data.get("recursion_depth_reached"):
        rows.append(Row("Recursion", "depth cap hit", "warn"))

    for rule in data.get("fired_rules") or []:
        rows.append(Row("Fired rule", rule, "bad"))

    if detail_level >= 1:
        for flag in data.get("indicator_flags") or []:
            rows.append(Row("Flag", flag, "info"))

    return rows
```

Keep `_dangerous_members_table` as a boxed table (no hashes in it) but change
its cap from the literal `[:20]` to `LIMITS["archive_members"]` and append
`more_hint()` when rows are dropped.

Replace `_embedded_execs_table` with a `render_hash_list` call so every SHA256
prints in full:

```python
def _embedded_execs(data: dict, detail_level: int, con: Console) -> None:
    execs = data.get("embedded_executables") or []
    entries = [
        (
            str(e.get("name", "")),
            f"{e.get('type', '')}  {human_size(e.get('size') or 0)}",
            e.get("sha256") or "",
        )
        for e in execs
    ]
    render_hash_list(
        "Embedded Executables",
        entries,
        limit=None if detail_level >= 1 else LIMITS["archive_execs"],
        console=con,
    )
```

Delete the local `_CLASS_COLOURS`; import `CLASS_SEVERITY` from `reporting.theme`.

- [ ] **Step 4: Run the tests**

Run: `.venv/bin/python -m pytest tests/test_report_rows.py tests/test_report_width.py -v`
Expected: all passed.

- [ ] **Step 5: Confirm every hash from the real sample renders in full**

```bash
.venv/bin/python - <<'EOF'
import io, json
from rich.console import Console
from tests.conftest import load_report
from reporting.terminal_reporter import print_terminal_report

report = load_report("netsupport_rar")
buf = io.StringIO()
print_terminal_report(report, detail_level=0,
                      console=Console(file=buf, width=80, no_color=True))
out = buf.getvalue()
data = next(r for r in report["module_results"]
            if r["module"] == "archive_analysis")["data"]
missing = [e["sha256"] for e in data["embedded_executables"]
           if e["sha256"] not in out]
print("hashes:", len(data["embedded_executables"]), "missing:", missing)
assert not missing, missing
EOF
```

Expected: `hashes: 9 missing: []`.

- [ ] **Step 6: Review and accept the snapshot diff**

Run: `.venv/bin/python -m pytest tests/test_report_snapshots.py -q`, read the
diff, then update with `THREATLENS_UPDATE_SNAPSHOTS=1`.

- [ ] **Step 7: Commit**

```bash
git add reporting/terminal_reporter/archive.py tests/
git commit -m "refactor(reporting): archive rows, full SHA256, honest truncation

archive_rows() replaces the hand-padded Panel. Embedded executables now
render flat so each 64-char SHA256 stays on one unbroken line at 80
columns. Caps rise from a silent [:20]/[:10] to a named 50 that always
prints a '+N more' hint."
```

---

## Task 10: Convert `onenote.py` and fix two bugs

**Files:**
- Modify: `reporting/terminal_reporter/onenote.py`
- Modify: `tests/test_report_rows.py`

- [ ] **Step 1: Write the failing tests for the two bugs**

```python
def test_nested_band_colour_is_not_always_white():
    """onenote.py looked up a risk_band (LOW/HIGH/...) in a map keyed by
    MALICIOUS/SUSPICIOUS/..., so it could never match and always fell
    back to white."""
    from reporting.theme import CLASS_SEVERITY

    assert CLASS_SEVERITY.get("MALICIOUS") == "bad"
    assert "HIGH" not in CLASS_SEVERITY


def test_nested_score_reads_total_score():
    """onenote.py read scoring['final_score']; the pipeline emits
    'total_score'."""
    from reporting.terminal_reporter.onenote import nested_score

    assert nested_score({"scoring": {"total_score": 42}}) == 42
    assert nested_score({"scoring": {}}) is None


def test_onenote_rows_empty_data_is_safe():
    from reporting.terminal_reporter.onenote import onenote_rows

    assert onenote_rows({}, 0) == []
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_report_rows.py -v`
Expected: FAIL — `cannot import name 'nested_score'`.

- [ ] **Step 3: Convert `onenote.py`**

Mirror Task 9: `onenote_rows(data, detail_level) -> list[Row]` from the
hand-padded lines (labels padded to columns 17 and 19 today), delete the local
`_CLASS_COLOURS`, and render blobs through `render_hash_list` so blob SHA256s
print in full. Add the helper the tests require:

```python
def nested_score(child: dict) -> int | None:
    """Score of a nested pipeline result.

    Reads ``total_score`` — the key ``core/scoring.py`` actually emits.
    This used to read ``final_score`` and always rendered ``None``.
    """
    return (child.get("scoring") or {}).get("total_score")
```

In the nested tree, colour the child by its `classification` through
`CLASS_SEVERITY`, not by its `risk_band`.

- [ ] **Step 4: Run the tests**

Run: `.venv/bin/python -m pytest tests/test_report_rows.py -v`
Expected: all passed.

- [ ] **Step 5: Review and accept the snapshot diff, then commit**

```bash
git add reporting/terminal_reporter/onenote.py tests/
git commit -m "fix(reporting): onenote nested score and classification colour

nested_score reads total_score, the key the pipeline emits — final_score
never existed, so the column always rendered None. Nested children are
now coloured by classification rather than by risk_band, which could
never match the MALICIOUS/SUSPICIOUS keys and always fell back to white.
Converts the section to a pure row builder."
```

---

## Task 11: Wire the theme into the HTML template

**Files:**
- Modify: `reporting/templates/report.html.j2:8-25`
- Modify: `reporting/html_reporter/__init__.py`
- Create: `tests/test_html_theme.py`

- [ ] **Step 1: Write the failing test**

```python
"""HTML keeps its exact palette while sourcing it from theme.py."""

from reporting.theme import TOKENS


def test_template_has_no_hardcoded_root_block():
    from pathlib import Path

    tpl = Path("reporting/templates/report.html.j2").read_text()
    assert "{{ theme_css }}" in tpl
    assert "--critical:" not in tpl, "palette literal still in the template"


def test_rendered_html_carries_every_token(tmp_path):
    import json

    from reporting.html_reporter import write_html_report
    from tests.conftest import load_report

    path = write_html_report(load_report("redline"), tmp_path)
    html = path.read_text()
    for name, token in TOKENS.items():
        assert token["css"] in html, f"{name} missing from rendered HTML"
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_html_theme.py -v`
Expected: FAIL — `{{ theme_css }}` not in the template.

- [ ] **Step 3: Replace the literal block**

In `reporting/templates/report.html.j2`, replace lines 8–25 (the whole `:root {
... }` block) with:

```
    {{ theme_css }}
```

In `reporting/html_reporter/__init__.py`, add `css_root` to the template
context where the other context keys are built:

```python
from reporting.theme import css_root

# ... inside the context dict:
    "theme_css": css_root(),
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_html_theme.py -v`
Expected: 2 passed.

- [ ] **Step 5: Prove the rendered HTML did not change**

```bash
git stash
.venv/bin/threatlens scan "/home/pmafma/Documents/Malware/exe test malware/RedLineStealer.exe" \
  --skip virustotal,capa_analysis -f html -o /tmp/before.html
git stash pop
.venv/bin/threatlens scan "/home/pmafma/Documents/Malware/exe test malware/RedLineStealer.exe" \
  --skip virustotal,capa_analysis -f html -o /tmp/after.html
diff <(grep -A30 ':root' /tmp/before.html) <(grep -A30 ':root' /tmp/after.html) \
  && echo "PALETTE IDENTICAL"
```

Expected: `PALETTE IDENTICAL`. Whitespace-only differences are acceptable;
any changed hex value is a bug in `css_root()`.

- [ ] **Step 6: Commit**

```bash
git add reporting/templates/report.html.j2 reporting/html_reporter/__init__.py tests/test_html_theme.py
git commit -m "refactor(reporting): source the HTML palette from theme.py

The :root block is now generated from TOKENS. Values are unchanged —
verified by diffing a rendered report against one produced before."
```

---

## Task 12: Verify the stage and update the docs

**Files:**
- Modify: `CLAUDE.md`
- Modify: `docs/cli_redesign_plan.md`

- [ ] **Step 1: Confirm exactly one severity colour map remains**

```bash
grep -rn "_SEV_STYLES\|_CLASS_COLOURS\|BAND_COLOURS\s*=\|STATUS_COLOURS\s*=" \
  reporting/ --include=*.py
```

Expected: only the derived definitions in `_common.py`. No `_SEV_STYLES` or
`_CLASS_COLOURS` anywhere.

- [ ] **Step 2: Confirm no information was lost**

```bash
.venv/bin/python -m pytest tests/ -q
```

Expected: all passed, 1 xfailed (the `-v` ≡ `-vv` marker, which Pass 2b flips).

- [ ] **Step 3: Check the CLI still behaves**

```bash
R="/home/pmafma/Documents/Malware/exe test malware/RedLineStealer.exe"
.venv/bin/threatlens scan "$R" --skip virustotal,capa_analysis -f json | jq -e .scoring.total_score
.venv/bin/threatlens scan "$R" --skip virustotal,capa_analysis 2>/dev/null | head -1
COLUMNS=80 .venv/bin/threatlens scan "$R" --skip virustotal,capa_analysis | awk '{ if (length($0) > 80) { print "OVERFLOW:", length($0); exit 1 } }'
```

Expected: a score on stdout; the first stdout line is report chrome, not a
warning; no line exceeds 80 columns.

- [ ] **Step 4: Update the trackers**

In `CLAUDE.md`, under "CLI / report redesign passes", change the Pass 2 line to:

```
  [~] Pass 2 — Report redesign. 2a (unify renderers) done: theme.py is the
      single palette, render_indicators() replaces four dialects, SHA256s
      render in full. 2b (scan layout) and 2c (triage table) pending.
```

In `docs/cli_redesign_plan.md`, update the Status table row for Pass 2 to
`🟡 2a shipped` and add a pointer to the design doc noting that §2.2's
~40-line target was dropped in favour of removing duplication only.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md docs/cli_redesign_plan.md
git commit -m "docs: record Pass 2a as shipped

Notes that the ~40-line default target from the original plan was
dropped after review — full detail stays at detail 0 and only genuine
duplication is removed."
```

---

## Self-review

**Spec coverage.** Design doc → tasks: `theme.py` → 3; `console.py` → 4;
`_render.py` → 5; `LIMITS` → 4; `Row`/`Severity` → 5; four dialects converge →
7, 8, 9, 10; flat hash layout → 5, 6, 9; silent-truncation fix → 4, 9; two
onenote bugs → 10; `theme_css` wiring → 11; fixtures/injection/snapshots → 1, 2;
width guard → 6. The design doc's `shared.py` recursive sanitiser and
`triage_reporter.py` are **not** here — they belong to 2b and 2c respectively,
which get their own plans.

**Type consistency.** `Row(label, value, severity)` is used identically in
tasks 5, 7, 8, 9, 10. `filter_rows(rows, detail_level, *, always_show)` and
`render_indicators(title, rows, detail_level, *, always_show, console)` match
between definition (5) and every call. `render_hash_list(title, entries, *,
limit, console)` matches between 5, 6 and 9. `nested_score(child)` is defined
and tested in 10. Section printers take a trailing `con: Console` from Task 1
onward, consistently.

**Known ordering constraint.** Task 1 touches every section module's signature;
tasks 7–10 then rewrite four of those bodies. This is deliberate — the console
must be injectable before any snapshot can be taken, and snapshots must exist
before any refactor.
