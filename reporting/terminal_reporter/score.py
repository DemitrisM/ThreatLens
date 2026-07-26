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

from ._common import LIMITS, BAND_COLOURS
from ._common import console as default_console
from ._render import module_strip, score_bar


def print_score_banner(
    scoring: dict, module_results: list[dict], *, console: Console | None = None
) -> None:
    """Score bar, numeric score, risk band, and the verdict sentence."""
    con = console or default_console
    score = scoring.get("total_score", 0)
    band = scoring.get("risk_band", "LOW")
    colour = BAND_COLOURS.get(band, "white")

    con.print()
    con.print(f"  {score_bar(score, band)}  [{colour}]{score}/100  {band}[/{colour}]")

    verdict = build_verdict(module_results, scoring)
    if verdict:
        con.print()
        con.print(Text(f"  {verdict}", style="dim italic"))


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
        colour = "red" if delta > 0 else "green"
        reason = item.get("reason", "")
        # -vv exists to show the whole thing; below that, cap it.
        if detail_level < 2 and len(reason) > cap:
            reason = reason[: cap - 3] + "..."
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
        status_colour = STATUS_COLOURS.get(status, "white")

        if isinstance(delta, (int, float)) and delta != 0:
            sign = "+" if delta > 0 else ""
            delta_cell = f"[{'red' if delta > 0 else 'green'}]{sign}{delta}[/]"
        else:
            delta_cell = "[dim]—[/dim]"

        if detail_level < 2 and len(reason) > cap:
            reason = reason[: cap - 3] + "..."

        table.add_row(
            result.get("module", "unknown"),
            f"[{status_colour}]{status}[/{status_colour}]",
            delta_cell,
            f"[dim]{reason}[/dim]",
        )

    con.print()
    con.print(table)
