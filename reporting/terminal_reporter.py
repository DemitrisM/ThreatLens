"""Terminal report generator using rich.

Displays colour-coded threat scores, formatted tables for IOCs and
MITRE ATT&CK mappings, progress bars during analysis, and a
human-readable score breakdown in the terminal.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

logger = logging.getLogger(__name__)

console = Console()

# Risk band → rich colour name
_BAND_COLOURS = {
    "CRITICAL": "bold red",
    "HIGH": "bold orange1",
    "MEDIUM": "bold yellow",
    "LOW": "bold green",
}

# Module status → colour
_STATUS_COLOURS = {
    "success": "green",
    "skipped": "dim yellow",
    "error": "red",
}


def print_terminal_report(report: dict) -> None:
    """Render a complete threat report to the terminal using rich.

    Args:
        report: Complete report dict returned by ``run_pipeline()``.
    """
    scoring = report.get("scoring", {})
    module_results = report.get("module_results", [])
    timing = report.get("timing", {})
    file_path = report.get("file", "unknown")

    _print_header()
    _print_file_info(module_results, file_path)
    _print_score_banner(scoring)
    _print_module_table(module_results)

    if scoring.get("breakdown"):
        _print_score_breakdown(scoring["breakdown"])

    _print_footer(timing)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _print_header() -> None:
    title = Text("ThreatLens", style="bold cyan")
    subtitle = Text("  Static Malware Analysis  ", style="dim")
    console.print()
    console.print(Panel(title + subtitle, style="cyan", padding=(0, 2)))


def _print_file_info(module_results: list[dict], file_path: str) -> None:
    """Print file metadata from the file_intake module result."""
    intake = next(
        (r for r in module_results if r.get("module") == "file_intake"), None
    )

    table = Table(
        title="[bold]File Information[/bold]",
        box=box.ROUNDED,
        show_header=False,
        padding=(0, 1),
    )
    table.add_column("Key", style="bold dim", no_wrap=True)
    table.add_column("Value", overflow="fold")

    if intake and intake.get("status") == "success":
        data = intake.get("data", {})
        hashes = data.get("hashes", {})
        ft = data.get("file_type", {})

        table.add_row("File", data.get("file_name", Path(file_path).name))
        table.add_row("Path", data.get("file_path", file_path))
        table.add_row("Size", _human_size(data.get("file_size", 0)))
        table.add_row("Type", ft.get("description", "Unknown"))
        table.add_row("MIME", ft.get("mime_type", "Unknown"))
        table.add_row("MD5", hashes.get("md5") or "N/A")
        table.add_row("SHA256", hashes.get("sha256") or "N/A")
        if hashes.get("tlsh"):
            table.add_row("TLSH", hashes["tlsh"])
        if hashes.get("ssdeep"):
            table.add_row("ssdeep", hashes["ssdeep"])
    else:
        table.add_row("File", Path(file_path).name)
        table.add_row("Path", str(file_path))
        if intake and intake.get("status") == "error":
            table.add_row("[red]Error[/red]", intake.get("reason", "File intake failed"))

    console.print()
    console.print(table)


def _print_score_banner(scoring: dict) -> None:
    """Print a large coloured score panel."""
    score = scoring.get("total_score", 0)
    band = scoring.get("risk_band", "LOW")
    colour = _BAND_COLOURS.get(band, "white")

    score_text = Text(f"  {score} / 100  ", style=f"bold {colour} on grey15")
    band_text = Text(f"  {band}  ", style=f"bold {colour}")

    content = Text.assemble(score_text, "   ", band_text)
    panel = Panel(
        content,
        title="[bold]Threat Score[/bold]",
        style=colour.replace("bold ", ""),
        padding=(1, 4),
    )
    console.print()
    console.print(panel)


def _print_module_table(module_results: list[dict]) -> None:
    """Print a table of all module results."""
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

        status_colour = _STATUS_COLOURS.get(status, "white")
        status_cell = f"[{status_colour}]{status}[/{status_colour}]"

        if isinstance(delta, (int, float)) and delta != 0:
            sign = "+" if delta > 0 else ""
            delta_cell = f"[{'red' if delta > 0 else 'green'}]{sign}{delta}[/]"
        else:
            delta_cell = "[dim]—[/dim]"

        # Truncate long reason text for table display
        reason_display = reason if len(reason) <= 80 else reason[:77] + "..."

        table.add_row(name, status_cell, delta_cell, f"[dim]{reason_display}[/dim]")

    console.print()
    console.print(table)


def _print_score_breakdown(breakdown: list[dict]) -> None:
    """Print score contributors (only shown when there are non-zero deltas)."""
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


def _print_footer(timing: dict) -> None:
    elapsed = timing.get("elapsed_seconds")
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    parts = [f"[dim]Analysis complete[/dim]  [dim]{ts}[/dim]"]
    if elapsed is not None:
        parts.append(f"  [dim]({elapsed:.2f}s)[/dim]")
    console.print()
    console.print("".join(parts))
    console.print()


def _human_size(nbytes: int) -> str:
    """Format byte count as a human-readable string."""
    for unit in ("B", "KiB", "MiB", "GiB"):
        if nbytes < 1024:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024
    return f"{nbytes:.1f} TiB"
