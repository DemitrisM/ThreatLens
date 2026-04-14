"""Score banner, module-results table, and score-breakdown table."""

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from reporting.shared import build_verdict

from ._common import BAND_COLOURS, STATUS_COLOURS, console


def print_score_banner(scoring: dict, module_results: list[dict]) -> None:
    """Large coloured score panel + auto-generated verdict sentence."""
    score = scoring.get("total_score", 0)
    band = scoring.get("risk_band", "LOW")
    colour = BAND_COLOURS.get(band, "white")

    score_text = Text(f"  {score} / 100  ", style=f"bold {colour} on grey15")
    band_text = Text(f"  {band}  ", style=f"bold {colour}")

    content = Text.assemble(score_text, "   ", band_text)

    verdict = build_verdict(module_results, scoring)
    if verdict:
        content = Text.assemble(content, "\n\n", Text(verdict, style="dim italic"))

    panel = Panel(
        content,
        title="[bold]Threat Score[/bold]",
        style=colour.replace("bold ", ""),
        padding=(1, 4),
    )
    console.print()
    console.print(panel)


def print_module_table(module_results: list[dict], file_path: str) -> None:
    """Table of all module results with status + score delta + reason."""
    if not module_results:
        console.print("\n[dim]No module results.[/dim]")
        return

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

    for result in module_results:
        name = result.get("module", "unknown")
        status = result.get("status", "unknown")
        delta = result.get("score_delta", 0)
        reason = result.get("reason", "")

        status_colour = STATUS_COLOURS.get(status, "white")
        status_cell = f"[{status_colour}]{status}[/{status_colour}]"

        if isinstance(delta, (int, float)) and delta != 0:
            sign = "+" if delta > 0 else ""
            delta_cell = f"[{'red' if delta > 0 else 'green'}]{sign}{delta}[/]"
        else:
            delta_cell = "[dim]—[/dim]"

        reason_display = reason if len(reason) <= 120 else reason[:117] + "..."
        table.add_row(name, status_cell, delta_cell, f"[dim]{reason_display}[/dim]")

    console.print()
    console.print(table)


def print_score_breakdown(breakdown: list[dict]) -> None:
    """Score-contributor table (only shown when there are non-zero deltas)."""
    table = Table(
        title="[bold]Score Breakdown[/bold]",
        box=box.SIMPLE_HEAVY,
        padding=(0, 1),
    )
    table.add_column("Module", style="bold", no_wrap=True)
    table.add_column("Δ", justify="right", no_wrap=True)
    table.add_column("Reason", overflow="fold")

    for item in breakdown:
        delta = item.get("score_delta", 0)
        sign = "+" if delta > 0 else ""
        colour = "red" if delta > 0 else "green"
        table.add_row(
            item.get("module", "unknown"),
            f"[{colour}]{sign}{delta}[/{colour}]",
            item.get("reason", ""),
        )

    console.print()
    console.print(table)
