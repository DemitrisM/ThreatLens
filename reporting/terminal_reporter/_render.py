"""Shared rendering primitives for the terminal report.

Replaces four hand-written indicator dialects. ``pe.py`` and ``doc.py``
built a 2-column table from ``(label, value, severity)`` tuples, while
``archive.py`` and ``onenote.py`` baked rich markup into hand-space-padded
strings inside a ``Panel`` — labels padded to column 17, and to 19 in two
OneNote rows. Everything now flows through :func:`render_indicators`.

Design notes
------------
Every primitive here takes an optional ``console`` and falls back to the
context-local proxy from ``_common``. That is what lets a test render to a
pinned console without threading a parameter through all nine section
modules, and why none of them holds a ``Console`` of its own.

Two things are rendered *outside* a bordered table on purpose, and both
were defects first. A SHA256 is 64 characters and box borders plus cell
padding cost six or more columns, so a boxed hash must break mid-string at
80 columns — which defeats the double-click copy that is the only reason
to print one; :func:`render_hash_list` is flat for that reason, guarded at
66/80/100/120 columns by ``tests/test_report_width.py``. The VirusTotal
permalink lost the same argument in a cell with ``overflow="fold"`` and now
prints below its table.

The value column here keeps ``overflow="fold"`` deliberately: an indicator
value is prose or a short token, and folding is right for it. It is only
wrong for a string whose whole purpose is to be copied in one piece.

Severity is a closed set of three, not a free string, because
:func:`render_indicators` looks it up as a palette token — design rule 8
means a typo would render as a literal ``[typo]`` tag rather than fail.
"""

from typing import Literal, NamedTuple

from rich import box
from rich.console import Console
from rich.table import Table

from reporting.theme import NEUTRAL, rich_style

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


#: Appended to a reason that lost whole clauses. ``-vv`` rather than
#: ``-v``, because only detail level 2 prints a reason in full.
#:
#: Deliberately *not* the ``(+N more)`` shape :func:`more_hint` uses. The
#: scoring modules already end a clause with their own ``(+1 more)`` for
#: an elided API or domain, and the two parentheticals rendered side by
#: side — ``LoadLibraryW (+1 more) (+5 more — use -vv)`` — where the
#: first counts imports and the second counts findings. The ellipsis and
#: the noun keep them apart.
_MORE_CLAUSES = "… {n} more finding{s} — use -vv"

#: Separator the scoring modules join their clauses with. Every module
#: builds its reason this way, so cutting here keeps whole findings
#: rather than whole words.
_CLAUSE_SEP = "; "

#: How far past the cap a reason may run before it is worth cutting.
#:
#: The cap exists to stop a long reason dominating the table, and a
#: reason half again as long as the cap costs one extra wrapped line.
#: Cutting it costs a finding, which is the thing the table is for. Two
#: real reasons sit in this band — 125 and 138 characters against a cap
#: of 120 — and cutting them dropped "Dangerous extension inside
#: archive" and "PowerShell download/exec, Base64 reference" to save
#: five and thirty-one characters. The reason that motivated the cap is
#: 404 characters, comfortably past it.
_OVERFLOW_TOLERANCE = 1.5


def _cut_on_word(text: str, cap: int) -> str:
    """Cut *text* at the last space at or before *cap*.

    Falls back to a hard slice when there is no space to cut at — a
    single unbroken token, such as a base64 blob or a very long path.
    """
    head = text[:cap].rsplit(" ", 1)[0]
    return head or text[:cap]


def truncate_reason(reason: str, cap: int) -> str:
    """Shorten a module reason without lying about what it contained.

    Args:
        reason: The module's ``reason`` string, clauses joined by ``"; "``.
        cap:    Soft character budget. Soft because the announcement is
                allowed past it, and because a reason is left whole when
                cutting it would not pay for itself.

    Returns:
        *reason* unchanged when it fits or when cutting would not pay,
        otherwise whole clauses, a word-boundary cut, or both, followed by
        a count of the findings that were dropped.

    A reason is a list of findings, not prose, so it is cut at clause
    boundaries. Cutting at a character offset landed mid-word —
    ACRStealer.exe rendered ``LoadLibraryW (+1 mor...``, which reads as a
    mangled count rather than a truncation, and silently dropped five
    findings including "No digital signature found" while the verdict
    line above still named them.

    The first clause is kept even when it alone overruns the budget,
    because returning nothing would be worse; it is then cut on a word
    boundary, so one enormous clause cannot push the line out on its own.

    Whether to cut at all is a judgement about value, not arithmetic. A
    reason within :data:`_OVERFLOW_TOLERANCE` of the cap costs at most
    one extra wrapped line, while cutting it costs a finding — so it is
    left whole. Past that the reason is dominating the table and the
    trade reverses. The finished string still has to be shorter than the
    original by more than the announcement costs, which is a floor, not
    the decision.
    """
    if len(reason) <= cap * _OVERFLOW_TOLERANCE:
        return reason

    # ── Take whole clauses while they fit ───────────────────────────────
    clauses = reason.split(_CLAUSE_SEP)
    kept: list[str] = []
    for clause in clauses:
        candidate = _CLAUSE_SEP.join([*kept, clause])
        if kept and len(candidate) > cap:
            break
        kept.append(clause)

    dropped = len(clauses) - len(kept)
    head = _CLAUSE_SEP.join(kept)

    # ── A single clause can still overrun on its own ────────────────────
    # The loop takes the first clause unconditionally, so `head` is not
    # bounded by `cap` yet. Without this a 300-character opening clause
    # would print in full whenever a second clause existed, which is the
    # opposite of what dropping the second one was for.
    elided = len(head) > cap
    if elided:
        head = _cut_on_word(head, cap)

    # ── Say what went missing ───────────────────────────────────────────
    # The clause hint opens with its own ellipsis, so a reason that was
    # both shortened and truncated needs only one mark.
    if dropped:
        suffix = " " + _MORE_CLAUSES.format(n=dropped, s="" if dropped == 1 else "s")
    elif elided:
        suffix = "…"
    else:
        return reason

    out = head + suffix
    return out if len(reason) - len(out) > len(suffix) else reason


def score_bar(score: int, band: str, *, width: int = 22) -> str:
    """A filled/empty bar for a 0-100 score, coloured by risk band.

    Args:
        score: 0-100. Clamped rather than trusted: the pipeline clamps
               once after summing, but this also renders a triage row and
               a compare column, and a bar that overruns its own width
               would corrupt the line.
        band:  Risk band name, used as a palette token once lowercased.
               An unknown band falls back to :data:`theme.NEUTRAL`, which
               is the terminal's own foreground rather than a hue that
               would imply a severity nobody computed.
        width: Cells in the bar, not characters of score.

    Returns:
        Rich markup, not plain text — the caller prints it, it does not
        print itself.

    The score was a text chip before this, so 12 and 98 rendered
    identically except in hue — unreadable at a glance.
    """
    clamped = max(0, min(100, int(score)))
    filled = round(clamped * width / 100)
    style = rich_style(band.lower()) or NEUTRAL
    return f"[{style}]{'█' * filled}[/{style}][dim]{'░' * (width - filled)}[/dim]"


#: status -> (glyph, tally label)
_STATUS_GLYPHS = {
    "success": ("✓", "ran"),
    "skipped": ("○", "n/a"),
    "error": ("✗", "error"),
}


def module_strip(module_results: list[dict]) -> str:
    """One-line summary of which modules ran.

    Args:
        module_results: The pipeline's per-module results, in execution
                        order. The glyph order follows it, so the strip
                        doubles as a reading of where a scan spent itself.

    Returns:
        Rich markup, or ``""`` for an empty list so the caller prints
        nothing rather than a bare label with no glyphs after it.

    A status this function has never heard of counts as an error rather
    than being dropped. Silently ignoring it would shorten the strip and
    make a module that returned something malformed indistinguishable
    from one that never ran.

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
        style = rich_style(status) or NEUTRAL
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
    """Render a severity-ranked 2-column indicator table.

    Args:
        title:        Section heading, printed above the table.
        rows:         Indicators in the order the section built them.
                      Source order is preserved; only filtering removes
                      rows, never reordering.
        detail_level: 0 hides ``info`` rows when anything louder fired,
                      1 and above show everything. See :func:`filter_rows`.
        always_show:  Labels exempt from that filter — the whitelist rows
                      (``Imphash``, ``Compiled language``) that are quiet
                      by nature but wanted even in a noisy report.
        console:      Target console; the context-local one when omitted.

    Returns:
        None. Nothing is printed at all when every row is filtered out, so
        a section with no surviving indicators leaves no empty heading
        behind.
    """
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

    Args:
        title:   Section heading, printed above the entries.
        entries: ``(name, meta, sha256)`` per row — what it is, a dim
                 qualifier such as a size or an offset, and the digest. An
                 empty ``sha`` prints the entry without a hash line rather
                 than an empty one, since a member can be listed from a
                 central directory without ever being read.
        limit:   Rows to show; ``None`` shows all. The count of what was
                 dropped is printed through :func:`more_hint`, because a
                 truncation that does not announce itself reads as a
                 complete list.
        console: Target console; the context-local one when omitted.

    Returns:
        None, and prints nothing at all for an empty list.

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
            con.print(f"  [accent]{sha}[/accent]")
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
