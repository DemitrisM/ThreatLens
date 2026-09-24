"""Score banner and the merged FINDINGS table.

``print_module_table`` and ``print_score_breakdown`` used to restate the
same module / Δ / reason back to back in two different box styles — one
truncated at 120 chars, one not. They are now one table built from
``scoring["breakdown"]``, which ``core/scoring.py`` already filters to
non-zero deltas. Modules that scored nothing are summarised by the
one-line module strip instead of a block of "Not applicable" rows.
"""

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from reporting.shared import build_verdict

from reporting.theme import NEUTRAL, rich_style

from ._common import LIMITS, BAND_COLOURS
from ._common import console as default_console
from ._render import module_strip, score_bar, truncate_reason


def print_score_banner(
    scoring: dict, module_results: list[dict], *, console: Console | None = None
) -> None:
    """Score bar, numeric score, risk band, and the verdict sentence."""
    con = console or default_console
    score = scoring.get("total_score", 0)
    band = scoring.get("risk_band", "LOW")
    colour = BAND_COLOURS.get(band, NEUTRAL)

    con.print()
    con.print(f"  {score_bar(score, band)}  [{colour}]{score}/100  {band}[/{colour}]")

    verdict = build_verdict(module_results, scoring)
    if verdict:
        con.print()
        # Wrapped here rather than left to rich. Two spaces inside the
        # string indent only the first line: rich wraps on the console
        # width and restarts at column 0, so any verdict naming more than
        # two findings read as a stray paragraph rather than the rest of
        # the sentence above it. `rich.padding.Padding` fixes the indent
        # but pads every line out to the full width, putting trailing
        # whitespace on the line a reader is most likely to select.
        #
        # `Text.wrap` rather than `textwrap.wrap` because the measurement
        # has to be in terminal cells, not characters: the verdict quotes
        # the LNK TrackerDataBlock's build-host name, which is
        # attacker-controlled and may be full-width, and a character
        # count would under-wrap it and hand the overflow back to rich.
        #
        # The width floor only guards against zero. Nothing preserves a
        # two-space indent on a console three columns wide, and a larger
        # floor would break the indent at widths where it still fits.
        body = Text(verdict, style="dim italic")
        for line in body.wrap(con, max(1, con.width - 2)):
            # Wrapping keeps the separator space at the fold. `rstrip`
            # on a Text edits in place and returns None, so it cannot be
            # chained the way the str method can.
            line.rstrip()
            con.print(Text("  ") + line)


def print_findings(
    scoring: dict,
    module_results: list[dict],
    detail_level: int = 0,
    *,
    console: Console | None = None,
) -> None:
    """The modules that actually moved the score, and why."""
    con = console or default_console
    breakdown = scoring.get("breakdown") or []
    if not breakdown:
        return

    table = Table(
        box=box.SIMPLE,
        padding=(0, 1),
        show_header=True,
        header_style="dim",
        pad_edge=False,
    )
    table.add_column("Module", style="bold", no_wrap=True)
    table.add_column("Δ", justify="right", no_wrap=True)
    table.add_column("Reason", overflow="fold")

    cap = LIMITS["reason_chars"]
    for item in breakdown:
        delta = item.get("score_delta", 0)
        sign = "+" if delta > 0 else ""
        # From the palette, not spelled here: design rule 8, and these
        # two are the only colours on the report's headline table.
        colour = rich_style("bad") if delta > 0 else rich_style("success")
        reason = item.get("reason", "")
        # -vv exists to show the whole thing; below that, cap it.
        if detail_level < 2:
            reason = truncate_reason(reason, cap)
        table.add_row(
            item.get("module", "unknown"),
            f"[{colour}]{sign}{delta}[/{colour}]",
            reason,
        )

    con.print()
    con.print("  [bold]FINDINGS[/bold]")
    con.print(table)


def print_module_strip(
    module_results: list[dict], *, console: Console | None = None
) -> None:
    """One line saying which modules ran, replacing the skip rows."""
    con = console or default_console
    strip = module_strip(module_results)
    if not strip:
        return
    con.print()
    con.print(strip)


def print_module_errors(
    module_results: list[dict], *, console: Console | None = None
) -> None:
    """Modules that failed. Never hidden — a failure is not a clean result."""
    con = console or default_console
    errors = [r for r in module_results if r.get("status") == "error"]
    if not errors:
        return
    con.print()
    for result in errors:
        con.print(
            f"  [red]![/red] {result.get('module', 'unknown')}: "
            f"[dim]{result.get('reason', 'failed')}[/dim]"
        )


def print_module_table(
    module_results: list[dict], detail_level: int = 1, *, console: Console | None = None
) -> None:
    """Full per-module table, including skipped modules. ``-v`` and above."""
    con = console or default_console
    if not module_results:
        return

    from ._common import STATUS_COLOURS

    table = Table(
        title="[bold]Module Results[/bold]",
        box=box.ROUNDED,
        show_lines=False,
        padding=(0, 1),
    )
    table.add_column("Module", style="bold", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Score Δ", justify="right", no_wrap=True)
    table.add_column("Reason", overflow="fold")

    cap = LIMITS["reason_chars"]
    for result in module_results:
        status = result.get("status", "unknown")
        delta = result.get("score_delta", 0)
        reason = result.get("reason", "")
        status_colour = STATUS_COLOURS.get(status, NEUTRAL)

        if isinstance(delta, (int, float)) and delta != 0:
            sign = "+" if delta > 0 else ""
            cell_colour = rich_style("bad") if delta > 0 else rich_style("success")
            delta_cell = f"[{cell_colour}]{sign}{delta}[/]"
        else:
            delta_cell = "[dim]—[/dim]"

        if detail_level < 2:
            reason = truncate_reason(reason, cap)

        table.add_row(
            result.get("module", "unknown"),
            f"[{status_colour}]{status}[/{status_colour}]",
            delta_cell,
            f"[dim]{reason}[/dim]",
        )

    con.print()
    con.print(table)
