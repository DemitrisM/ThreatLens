"""Malware Triage Tool — Entry point and CLI argument parsing.

Accepts a suspicious file path from the user, orchestrates the analysis
pipeline, and outputs a structured threat report with confidence scoring.
"""

import logging
import sys
import webbrowser
from pathlib import Path

import click

from core.config_loader import get_config
from core.pipeline import run_pipeline
from reporting.json_reporter import write_json_report
from reporting.terminal_reporter import print_terminal_report


# ── Scan profile presets ────────────────────────────────────────────

_QUICK_MODULES = ["file_intake", "pe_analysis"]

_STANDARD_MODULES = [
    "file_intake",
    "pe_analysis",
    "string_analysis",
    "ioc_extractor",
    "capa_analysis",
    "yara_scanner",
    "doc_analysis",
    "pdf_analysis",
    "virustotal",
]

_DEEP_OVERRIDES = {
    "capa_timeout_seconds": 180,
}


def _apply_scan_profile(config: dict, profile: str) -> dict:
    """Override config values based on the selected scan profile."""
    if profile == "quick":
        config["enabled_modules"] = list(_QUICK_MODULES)
    elif profile == "deep":
        for k, v in _DEEP_OVERRIDES.items():
            config[k] = v
    elif profile == "full":
        for k, v in _DEEP_OVERRIDES.items():
            config[k] = v
        # Full implies all output formats are saved (handled in analyse)
    return config


def _apply_module_overrides(
    config: dict, modules: str | None, skip: str | None
) -> dict:
    """Apply --modules and --skip overrides to enabled_modules."""
    if modules is not None:
        # Explicit module list — always include file_intake
        names = [m.strip() for m in modules.split(",") if m.strip()]
        if "file_intake" not in names:
            names.insert(0, "file_intake")
        config["enabled_modules"] = names

    if skip is not None:
        to_skip = {m.strip() for m in skip.split(",") if m.strip()}
        config["enabled_modules"] = [
            m for m in config["enabled_modules"] if m not in to_skip
        ]

    return config


def _setup_logging(log_level: str, verbose: bool, debug: bool) -> None:
    """Configure the root logger based on CLI flags and config."""
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = getattr(logging, log_level, logging.WARNING)

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _resolve_profile(quick: bool, deep: bool, full: bool) -> str:
    """Return the active scan profile name, enforcing mutual exclusion."""
    selected = [p for p, flag in [("quick", quick), ("deep", deep), ("full", full)] if flag]
    if len(selected) > 1:
        raise click.UsageError(
            f"Scan profiles are mutually exclusive — got: {', '.join(selected)}"
        )
    return selected[0] if selected else "standard"


def _detail_level(verbose: bool, debug: bool) -> int:
    """Map verbosity flags to a detail level for the terminal reporter.

    0 = default summary, 1 = expanded (-v), 2 = full (--debug / -vv).
    """
    if debug:
        return 2
    if verbose:
        return 1
    return 0


# ── Progress display (rich spinner) ────────────────────────────────

def _make_progress_cb(show: bool):
    """Return a (progress_cb, finalise) pair.

    ``progress_cb`` is passed to the pipeline; ``finalise()`` must be
    called after the pipeline returns to stop the spinner.
    """
    if not show:
        return None, lambda: None

    from rich.console import Console  # noqa: PLC0415
    from rich.live import Live  # noqa: PLC0415
    from rich.spinner import Spinner  # noqa: PLC0415
    from rich.text import Text  # noqa: PLC0415

    console = Console(stderr=True)
    spinner = Spinner("dots", text="Initialising…", style="cyan")
    live = Live(spinner, console=console, refresh_per_second=10, transient=True)
    live.start()

    import time as _time  # noqa: PLC0415
    _start = _time.time()

    def _cb(idx: int, total: int, name: str, event: str) -> None:
        if event == "start":
            elapsed = _time.time() - _start
            txt = Text.assemble(
                (f"[{idx + 1}/{total}] ", "bold cyan"),
                ("Running ", "dim"),
                (name, "bold"),
                (f"  ({elapsed:.0f}s elapsed)", "dim"),
            )
            spinner.update(text=txt)

    def _fin() -> None:
        live.stop()

    return _cb, _fin


# ── CLI ─────────────────────────────────────────────────────────────

@click.group()
@click.version_option(version="0.2.0", prog_name="ThreatLens")
def cli() -> None:
    """ThreatLens — static malware analysis with transparent confidence scoring."""


@cli.command()
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
    config = _apply_module_overrides(config, modules, skip)

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

    console = Console()

    files = sorted(
        f for f in directory.iterdir()
        if f.is_file() and not f.name.startswith(".")
    )
    if not files:
        click.echo(f"No files found in {directory}", err=True)
        sys.exit(1)

    console.print(f"\n[bold cyan]Batch analysis:[/bold cyan] {len(files)} file(s) in {directory}\n")

    _BAND_COLOURS = {
        "CRITICAL": "bold red",
        "HIGH": "bold orange1",
        "MEDIUM": "bold yellow",
        "LOW": "bold green",
    }

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
            colour = _BAND_COLOURS.get(row["band"], "white")
            table.add_row(
                row["name"],
                f"[{colour}]{row['score']}[/{colour}]",
                f"[{colour}]{row['band']}[/{colour}]",
                f"{row['elapsed']:.1f}s",
            )

    console.print()
    console.print(table)
    console.print()


@cli.command()
@click.argument("file1", type=click.Path(exists=True, path_type=Path))
@click.argument("file2", type=click.Path(exists=True, path_type=Path))
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=None)
@click.option("--verbose", "-v", is_flag=True)
@click.option("--debug", is_flag=True)
def compare(
    file1: Path,
    file2: Path,
    config_path: Path | None,
    verbose: bool,
    debug: bool,
) -> None:
    """Compare analysis results of two files side-by-side."""
    from rich.console import Console  # noqa: PLC0415
    from rich.table import Table  # noqa: PLC0415
    from rich.panel import Panel  # noqa: PLC0415
    from rich.text import Text  # noqa: PLC0415
    from rich import box  # noqa: PLC0415

    config = get_config(config_path)
    _setup_logging(config["log_level"], verbose, debug)

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
    _BAND_COLOURS = {
        "CRITICAL": "bold red",
        "HIGH": "bold orange1",
        "MEDIUM": "bold yellow",
        "LOW": "bold green",
    }
    c1 = _BAND_COLOURS.get(scoring1["risk_band"], "white")
    c2 = _BAND_COLOURS.get(scoring2["risk_band"], "white")
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


if __name__ == "__main__":
    cli()
