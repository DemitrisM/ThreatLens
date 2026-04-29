"""``compare`` CLI command — side-by-side analysis of two files."""

from pathlib import Path

import click

from core.config_loader import get_config
from core.pipeline import run_pipeline

from ._helpers import _setup_logging


@click.command()
@click.argument("file1", type=click.Path(exists=True, path_type=Path))
@click.argument("file2", type=click.Path(exists=True, path_type=Path))
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=None)
@click.option("--verbose", "-v", is_flag=True)
@click.option("--debug", is_flag=True)
@click.option("--recurse-archives", is_flag=True,
              help="Feed nested archive members back through the full pipeline.")
@click.option("--max-archive-depth", type=int, default=None,
              help="Override max archive recursion depth (default: 3).")
@click.option("--no-archive", is_flag=True, help="Disable archive_analysis.")
@click.option("--recurse-onenote", is_flag=True,
              help="Feed embedded OneNote payloads back through the full pipeline.")
def compare(
    file1: Path,
    file2: Path,
    config_path: Path | None,
    verbose: bool,
    debug: bool,
    recurse_archives: bool,
    max_archive_depth: int | None,
    no_archive: bool,
    recurse_onenote: bool,
) -> None:
    """Compare analysis results of two files side-by-side."""
    from rich.console import Console  # noqa: PLC0415
    from rich.table import Table  # noqa: PLC0415
    from rich.panel import Panel  # noqa: PLC0415
    from rich.text import Text  # noqa: PLC0415
    from rich import box  # noqa: PLC0415

    from reporting.terminal_reporter._common import BAND_COLOURS  # noqa: PLC0415

    config = get_config(config_path)
    _setup_logging(config["log_level"], verbose, debug)

    if no_archive:
        config["enabled_modules"] = [
            m for m in config.get("enabled_modules", []) if m != "archive_analysis"
        ]
    if recurse_archives:
        config["archive_full_recursion"] = True
    if max_archive_depth is not None:
        config["max_archive_recursion_depth"] = int(max_archive_depth)
    if recurse_onenote:
        config["onenote_full_recursion"] = True

    console = Console()

    console.print("\n[bold cyan]ThreatLens[/bold cyan]  [dim]Compare Mode[/dim]\n")

    # Run both analyses
    console.print(f"[dim]Analysing {file1.name}…[/dim]")
    report1 = run_pipeline(file1, config)
    console.print(f"[dim]Analysing {file2.name}…[/dim]")
    report2 = run_pipeline(file2, config)

    scoring1 = report1["scoring"]
    scoring2 = report2["scoring"]

    # ── Comparison table ──
    table = Table(
        title="[bold]Comparison[/bold]",
        box=box.ROUNDED,
        padding=(0, 1),
    )
    table.add_column("", style="bold dim", no_wrap=True)
    table.add_column(file1.name, overflow="fold")
    table.add_column(file2.name, overflow="fold")

    # Score row
    c1 = BAND_COLOURS.get(scoring1["risk_band"], "white")
    c2 = BAND_COLOURS.get(scoring2["risk_band"], "white")
    table.add_row(
        "Score",
        f"[{c1}]{scoring1['total_score']} / 100  {scoring1['risk_band']}[/{c1}]",
        f"[{c2}]{scoring2['total_score']} / 100  {scoring2['risk_band']}[/{c2}]",
    )

    # Hashes
    def _get_hashes(report):
        intake = next(
            (r for r in report["module_results"] if r.get("module") == "file_intake"), None
        )
        if intake and intake.get("status") == "success":
            return intake["data"].get("hashes", {})
        return {}

    h1, h2 = _get_hashes(report1), _get_hashes(report2)
    table.add_row("SHA256", h1.get("sha256", "N/A")[:16] + "…", h2.get("sha256", "N/A")[:16] + "…")

    # TLSH similarity
    if h1.get("tlsh") and h2.get("tlsh"):
        try:
            import tlsh  # noqa: PLC0415
            diff = tlsh.diff(h1["tlsh"], h2["tlsh"])
            similarity = "Identical" if diff == 0 else f"Distance: {diff} {'(similar)' if diff < 100 else '(different)'}"
            table.add_row("TLSH similarity", similarity, "")
        except ImportError:
            pass

    # Per-module score comparison
    table.add_section()
    all_modules = set()
    def _mod_scores(report):
        return {r["module"]: r.get("score_delta", 0) for r in report["module_results"]}
    s1, s2 = _mod_scores(report1), _mod_scores(report2)
    all_modules = sorted(set(s1) | set(s2))
    for mod in all_modules:
        d1 = s1.get(mod, 0)
        d2 = s2.get(mod, 0)
        d1_str = f"+{d1}" if d1 > 0 else ("—" if d1 == 0 else str(d1))
        d2_str = f"+{d2}" if d2 > 0 else ("—" if d2 == 0 else str(d2))
        table.add_row(mod, d1_str, d2_str)

    # Timing
    table.add_section()
    t1 = report1["timing"]["elapsed_seconds"]
    t2 = report2["timing"]["elapsed_seconds"]
    table.add_row("Elapsed", f"{t1:.1f}s", f"{t2:.1f}s")

    console.print()
    console.print(table)
    console.print()
