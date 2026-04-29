"""``analyse`` CLI command — single-file, batch, and hash-only modes."""

import logging
import sys
import webbrowser
from pathlib import Path

import click

from core.config_loader import get_config
from core.pipeline import run_pipeline
from reporting.json_reporter import write_json_report
from reporting.terminal_reporter import print_terminal_report

from ._helpers import (
    _apply_module_overrides,
    _apply_scan_profile,
    _detail_level,
    _resolve_profile,
    _setup_logging,
)
from ._progress import _make_progress_cb


@click.command()
@click.argument("file", type=click.Path(path_type=Path))
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to config.yaml (default: ./config.yaml).",
)
@click.option(
    "--output",
    type=click.Choice(["terminal", "json", "html", "all"], case_sensitive=False),
    default="terminal",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Directory for saved reports (overrides config).",
)
@click.option(
    "--dynamic",
    type=click.Choice(["none", "speakeasy", "vm_worker", "cape"], case_sensitive=False),
    default=None,
    help="Dynamic analysis provider (overrides config).",
)
@click.option("--verbose", "-v", is_flag=True, help="Expanded output — IOCs, ATT&CK table, strings, timing.")
@click.option("--debug", is_flag=True, help="Full output + DEBUG logging (equivalent to -vv).")
# ── Scan profiles ──
@click.option("--quick", "-q", is_flag=True, help="Quick scan — file_intake + PE analysis only.")
@click.option("--deep", "-D", is_flag=True, help="Deep scan — extended timeouts, all modules.")
@click.option("--full", "-A", is_flag=True, help="Full analysis — deep + all output formats saved.")
# ── Module selection ──
@click.option("--modules", type=str, default=None, help="Comma-separated list of modules to run (e.g. pe,capa,yara).")
@click.option("--skip", type=str, default=None, help="Comma-separated list of modules to skip.")
# ── Extra features ──
@click.option("--save", is_flag=True, help="Also save JSON report alongside terminal output.")
@click.option("--open", "open_report", is_flag=True, help="Open HTML report in default browser.")
@click.option("--hash-only", is_flag=True, help="Print file hashes only (no full analysis).")
# ── Archive-analysis controls ──
@click.option("--recurse-archives", is_flag=True,
              help="Feed nested archive members back through the full pipeline (default: archive-only recursion).")
@click.option("--max-archive-depth", type=int, default=None,
              help="Override max archive recursion depth (default: 3).")
@click.option("--no-archive", is_flag=True, help="Disable archive_analysis (shorthand for --skip archive_analysis).")
# ── OneNote-analysis controls ──
@click.option("--recurse-onenote", is_flag=True,
              help="Feed embedded OneNote payloads back through the full pipeline (default: hash-only for VT forward-lookup).")
def analyse(
    file: Path,
    config_path: Path | None,
    output: str,
    output_dir: Path | None,
    dynamic: str | None,
    verbose: bool,
    debug: bool,
    quick: bool,
    deep: bool,
    full: bool,
    modules: str | None,
    skip: str | None,
    save: bool,
    open_report: bool,
    hash_only: bool,
    recurse_archives: bool,
    max_archive_depth: int | None,
    no_archive: bool,
    recurse_onenote: bool,
) -> None:
    """Analyse FILE and produce a threat report with confidence scoring.

    FILE can be a single file path or a directory (batch mode).
    """
    config = get_config(config_path)
    _setup_logging(config["log_level"], verbose, debug)
    logger = logging.getLogger(__name__)

    # Resolve scan profile
    try:
        profile = _resolve_profile(quick, deep, full)
    except click.UsageError as exc:
        click.echo(str(exc), err=True)
        sys.exit(1)

    config = _apply_scan_profile(config, profile)

    # --no-archive is sugar for --skip archive_analysis
    effective_skip = skip
    if no_archive:
        effective_skip = (
            f"{skip},archive_analysis" if skip else "archive_analysis"
        )

    config = _apply_module_overrides(config, modules, effective_skip)

    if recurse_archives:
        config["archive_full_recursion"] = True
    if max_archive_depth is not None:
        config["max_archive_recursion_depth"] = int(max_archive_depth)
    if recurse_onenote:
        config["onenote_full_recursion"] = True

    if output_dir is not None:
        config["output_dir"] = str(output_dir)
    if dynamic is not None:
        config["dynamic_provider"] = dynamic.lower()

    # Full profile forces all outputs
    if profile == "full":
        output = "all"
        save = True

    detail = _detail_level(verbose, debug)

    # ── Batch mode (directory) ──
    if file.is_dir():
        _run_batch(file, config, output, detail, save, open_report, logger)
        return

    # Validate file exists (for single file mode)
    if not file.exists():
        click.echo(f"Error: Path '{file}' does not exist.", err=True)
        sys.exit(2)

    # ── Hash-only mode ──
    if hash_only:
        _run_hash_only(file, config, logger)
        return

    # ── Single file analysis ──
    _run_single(file, config, output, detail, save, open_report, logger)


def _run_hash_only(file: Path, config: dict, logger: logging.Logger) -> None:
    """Print hashes in copy-paste-friendly format."""
    config["enabled_modules"] = ["file_intake"]

    report = run_pipeline(file, config)
    intake = next(
        (r for r in report["module_results"] if r.get("module") == "file_intake"), None
    )
    if intake is None or intake.get("status") != "success":
        click.echo("Error: file_intake failed", err=True)
        sys.exit(1)

    hashes = intake["data"].get("hashes", {})
    click.echo(f"MD5:    {hashes.get('md5', 'N/A')}")
    click.echo(f"SHA256: {hashes.get('sha256', 'N/A')}")
    if hashes.get("tlsh"):
        click.echo(f"TLSH:   {hashes['tlsh']}")
    if hashes.get("ssdeep"):
        click.echo(f"ssdeep: {hashes['ssdeep']}")


def _run_single(
    file: Path,
    config: dict,
    output: str,
    detail: int,
    save: bool,
    open_report: bool,
    logger: logging.Logger,
) -> None:
    """Run analysis on a single file and produce output."""
    output_lower = output.lower()
    show_progress = output_lower in ("terminal", "all") or save

    progress_cb, progress_fin = _make_progress_cb(show_progress)

    try:
        report = run_pipeline(file, config, progress_cb=progress_cb)
    except Exception as exc:  # noqa: BLE001
        progress_fin()
        logger.error("Pipeline failed: %s", exc)
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    finally:
        progress_fin()

    # ── Output routing ──
    if output_lower in ("terminal", "all"):
        print_terminal_report(report, detail_level=detail)

    json_path = None
    if output_lower in ("json", "all") or save:
        out_dir = Path(config["output_dir"])
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = write_json_report(report, out_dir)
        logger.info("JSON report written to %s", json_path)
        if output_lower == "json":
            click.echo(f"Report saved: {json_path}")

    html_path = None
    if output_lower in ("html", "all"):
        try:
            from reporting.html_reporter import write_html_report  # noqa: PLC0415

            out_dir = Path(config["output_dir"])
            out_dir.mkdir(parents=True, exist_ok=True)
            html_path = write_html_report(report, out_dir)
            logger.info("HTML report written to %s", html_path)
            if output_lower == "html":
                click.echo(f"Report saved: {html_path}")
        except Exception as exc:  # noqa: BLE001
            logger.warning("HTML report generation failed: %s", exc)

    # Show save path if --save was used alongside terminal output
    if save and json_path and output_lower not in ("json", "all"):
        click.echo(f"\nReport saved: {json_path}")

    # Open HTML in browser if requested
    if open_report and html_path:
        webbrowser.open(html_path.as_uri() if hasattr(html_path, "as_uri") else f"file://{html_path}")


def _run_batch(
    directory: Path,
    config: dict,
    output: str,
    detail: int,
    save: bool,
    open_report: bool,
    logger: logging.Logger,
) -> None:
    """Run analysis on all files in a directory."""
    from rich.console import Console  # noqa: PLC0415
    from rich.table import Table  # noqa: PLC0415
    from rich import box  # noqa: PLC0415

    from reporting.terminal_reporter._common import BAND_COLOURS  # noqa: PLC0415

    console = Console()

    files = sorted(
        f for f in directory.iterdir()
        if f.is_file() and not f.name.startswith(".")
    )
    if not files:
        click.echo(f"No files found in {directory}", err=True)
        sys.exit(1)

    console.print(f"\n[bold cyan]Batch analysis:[/bold cyan] {len(files)} file(s) in {directory}\n")

    summary_rows: list[dict] = []
    for file in files:
        output_lower = output.lower()
        show_progress = output_lower in ("terminal", "all") or save
        progress_cb, progress_fin = _make_progress_cb(show_progress)

        try:
            report = run_pipeline(file, config.copy(), progress_cb=progress_cb)
        except Exception as exc:  # noqa: BLE001
            logger.error("Pipeline failed for %s: %s", file.name, exc)
            summary_rows.append({
                "name": file.name,
                "score": "ERR",
                "band": "ERROR",
                "elapsed": 0,
            })
            continue
        finally:
            progress_fin()

        scoring = report["scoring"]
        elapsed = report["timing"]["elapsed_seconds"]
        summary_rows.append({
            "name": file.name,
            "score": scoring["total_score"],
            "band": scoring["risk_band"],
            "elapsed": elapsed,
        })

        # Per-file output
        if output_lower in ("terminal", "all"):
            print_terminal_report(report, detail_level=detail)

        if output_lower in ("json", "all") or save:
            out_dir = Path(config["output_dir"])
            out_dir.mkdir(parents=True, exist_ok=True)
            json_path = write_json_report(report, out_dir)
            logger.info("JSON report written to %s", json_path)

        console.print("[dim]" + "─" * 60 + "[/dim]\n")

    # ── Batch summary table ──
    table = Table(
        title="[bold]Batch Summary[/bold]",
        box=box.ROUNDED,
        padding=(0, 1),
    )
    table.add_column("File", style="bold", no_wrap=True)
    table.add_column("Score", justify="right", no_wrap=True)
    table.add_column("Risk Band", no_wrap=True)
    table.add_column("Elapsed", justify="right", no_wrap=True)

    for row in summary_rows:
        if row["band"] == "ERROR":
            table.add_row(row["name"], "[red]ERR[/red]", "[red]ERROR[/red]", "—")
        else:
            colour = BAND_COLOURS.get(row["band"], "white")
            table.add_row(
                row["name"],
                f"[{colour}]{row['score']}[/{colour}]",
                f"[{colour}]{row['band']}[/{colour}]",
                f"{row['elapsed']:.1f}s",
            )

    console.print()
    console.print(table)
    console.print()
