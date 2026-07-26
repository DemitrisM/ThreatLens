"""Shared rendering primitives for the terminal report.

Replaces four hand-written indicator dialects. ``pe.py`` and ``doc.py``
built a 2-column table from ``(label, value, severity)`` tuples, while
``archive.py`` and ``onenote.py`` baked rich markup into hand-space-padded
strings inside a ``Panel`` — labels padded to column 17, and to 19 in two
OneNote rows. Everything now flows through :func:`render_indicators`.
"""

from typing import Literal, NamedTuple

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


def filter_rows(
    rows: list[Row],
    detail_level: int,
    *,
    always_show: frozenset[str] = frozenset(),
) -> list[Row]:
    """Drop ``info`` rows at detail 0 when something louder fired.

    Source order is always preserved. The callers this replaces did not:
    ``pe.py`` appended its whitelist rows (``Imphash``, ``Compiled
    language``) to the end, and ``doc.py`` inserted its whitelist row at
    index 0 — both reordering relative to the list they were built from.

    When every row is ``info`` nothing is dropped, so a section with only
    quiet findings still renders instead of vanishing entirely.
    """
    if detail_level >= 1:
        return list(rows)
    if not any(r.severity != "info" for r in rows):
        return list(rows)
    return [r for r in rows if r.severity != "info" or r.label in always_show]


def more_hint(hidden: int) -> str:
    """Uniform 'there is more' wording.

    Three spellings existed before this: a standalone dim line in
    ``tables.py`` and ``findings.py``, and a table row in ``onenote.py``.
    """
    return f"(+{hidden} more — use -v to show all)" if hidden > 0 else ""


def score_bar(score: int, band: str, *, width: int = 22) -> str:
    """A filled/empty bar for a 0-100 score, coloured by risk band.

    The score was a text chip before this, so 12 and 98 rendered
    identically except in hue — unreadable at a glance.
    """
    clamped = max(0, min(100, int(score)))
    filled = round(clamped * width / 100)
    style = rich_style(band.lower()) or "white"
    return f"[{style}]{'█' * filled}[/{style}][dim]{'░' * (width - filled)}[/dim]"


#: status -> (glyph, tally label)
_STATUS_GLYPHS = {
    "success": ("✓", "ran"),
    "skipped": ("○", "n/a"),
    "error": ("✗", "error"),
}


def module_strip(module_results: list[dict]) -> str:
    """One-line summary of which modules ran.

    Replaces a block of per-module "Not applicable" rows — the RedLine
    baseline spent six of its 116 lines on them.
    """
    if not module_results:
        return ""

    glyphs: list[str] = []
    tally: dict[str, int] = {}
    for result in module_results:
        status = result.get("status", "error")
        glyph, label = _STATUS_GLYPHS.get(status, ("✗", "error"))
        style = rich_style(status) or "white"
        glyphs.append(f"[{style}]{glyph}[/{style}]")
        tally[label] = tally.get(label, 0) + 1

    counts = ", ".join(f"{n} {label}" for label, n in tally.items())
    return f"  [dim]modules[/dim]  {''.join(glyphs)}   [dim]{counts}[/dim]"


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
    """Render ``(name, meta, sha256)`` triples, each hash on its own line.

    Flat rather than boxed, deliberately. A SHA256 is 64 characters; box
    borders and cell padding consume 6 or more columns, so at an 80-column
    terminal a boxed layout must break the hash mid-string. That defeats
    double-click copy-paste into VirusTotal, which is the only reason to
    print a full hash. Flat layout keeps it intact down to 66 columns.

    Verified by ``tests/test_report_width.py`` at 66/80/100/120 columns.
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
    "module_strip",
    "more_hint",
    "render_hash_list",
    "render_indicators",
    "score_bar",
]
