"""``triage`` CLI command — sweep a directory of files.

``triage`` is the batch counterpart to ``scan``: same two axes, but the
default profile is ``quick`` because a sweep is meant to be cheap. Under a
machine format every piece of chrome (banner, separators, summary table) is
suppressed or routed to stderr, so ``-f jsonl`` yields exactly one parseable
line per analysed file.
"""

import copy
import logging
from pathlib import Path

import click

from core.config_loader import get_config
from core.pipeline import run_pipeline

from ._console import err, out
from ._exit import EXIT_THREAT, FAIL_ON_CHOICES, RuntimeFailure, meets_threshold
from ._helpers import PROFILES, _apply_module_overrides, _apply_scan_profile, _detail_level, _setup_logging
from ._progress import _make_progress_cb

logger = logging.getLogger(__name__)

#: Formats that write machine-readable data rather than a rendered report.
_MACHINE_FORMATS = frozenset({"json", "jsonl"})


@click.command("triage")
@click.argument("directory", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-p",
    "--profile",
    type=click.Choice(PROFILES, case_sensitive=False),
    default="quick",
    show_default=True,
    help="Which modules run: quick (intake + PE), standard (all), deep (extended timeouts).",
)
@click.option(
    "-v",
    "--verbose",
    "verbosity",
    count=True,
    help="How much prints: -v expands every section, -vv adds raw module data and DEBUG logs.",
)
@click.option(
    "-f",
    "--format",
    "fmt",
    type=click.Choice(["text", "jsonl", "json"], case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format. jsonl emits one report per line; json emits one array.",
)
@click.option(
    "--min-score",
    type=click.IntRange(0, 100),
    default=None,
    help="Hide files scoring below this threshold.",
)
@click.option(
    "-r",
    "--recursive",
    is_flag=True,
    help="Descend into subdirectories.",
)
@click.option(
    "--fail-on",
    type=click.Choice(FAIL_ON_CHOICES, case_sensitive=False),
    default=None,
    help="Exit 1 when any file reaches this risk band. Default: never fail.",
)
@click.option(
    "--modules",
    default=None,
    help="Comma-separated list of modules to run, by their registry names "
    "(e.g. pe_analysis,capa_analysis,yara_scanner).",
)
@click.option("--skip", default=None, help="Comma-separated list of modules to skip.")
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to config.yaml (default: ./config.yaml).",
)
@click.pass_context
def triage(
    ctx: click.Context,
    directory: Path,
    profile: str,
    verbosity: int,
    fmt: str,
    min_score: int | None,
    recursive: bool,
    fail_on: str | None,
    modules: str | None,
    skip: str | None,
    config_path: Path | None,
) -> None:
    """Analyse every file in DIRECTORY and summarise the results."""
    fmt = fmt.lower()
    profile = profile.lower()

    if directory.is_file():
        raise click.UsageError(
            "triage takes a directory; use 'threatlens scan' for a single file"
        )

    # Logging first, so config-loading warnings reach the configured handler.
    _setup_logging(verbosity=verbosity)
    config = get_config(config_path)
    _setup_logging(config["log_level"], verbosity)

    config = _apply_scan_profile(config, profile)
    config = _apply_module_overrides(config, modules, skip)

    files = _collect_files(directory, recursive=recursive)
    if not files:
        err.print(f"[yellow]No files found in {directory}[/yellow]")
        return

    machine = fmt in _MACHINE_FORMATS
    if not machine:
        err.print(
            f"\n[bold cyan]Triage:[/bold cyan] {len(files)} file(s) in {directory}\n"
        )

    reports, failures = _analyse_all(
        files,
        config,
        machine=machine,
        min_score=min_score,
        detail_level=_detail_level(verbosity),
    )

    if machine:
        _emit_machine(reports, fmt)
    else:
        _print_summary(reports, failures)

    # Runtime failure outranks a threat verdict.
    if failures:
        raise RuntimeFailure(
            f"{len(failures)} of {len(files)} file(s) failed to analyse: "
            + ", ".join(name for name, _ in failures[:5])
        )
    if any(meets_threshold(r["scoring"]["risk_band"], fail_on) for r in reports):
        ctx.exit(EXIT_THREAT)


def _collect_files(directory: Path, *, recursive: bool) -> list[Path]:
    """Return the files to analyse, dotfiles excluded, deterministically ordered.

    With ``recursive`` a dot-prefixed *directory* is skipped too — walking
    into ``.git`` or ``.venv`` is never what a triage sweep wants.
    """
    candidates = directory.rglob("*") if recursive else directory.iterdir()
    return sorted(
        f
        for f in candidates
        if f.is_file()
        and not any(part.startswith(".") for part in f.relative_to(directory).parts)
    )


def _analyse_all(
    files: list[Path],
    config: dict,
    *,
    machine: bool,
    min_score: int | None,
    detail_level: int,
) -> tuple[list[dict], list[tuple[str, str]]]:
    """Run the pipeline over every file.

    Returns:
        ``(reports, failures)`` where *reports* holds the reports that passed
        the ``--min-score`` filter and *failures* holds ``(name, error)``
        pairs for files whose pipeline raised.
    """
    reports: list[dict] = []
    failures: list[tuple[str, str]] = []

    for index, file in enumerate(files, start=1):
        err.print(f"[dim]({index}/{len(files)}) {file.name}[/dim]")
        progress_cb, progress_fin = _make_progress_cb(err.is_terminal and not machine)
        try:
            # Each file gets its own config copy — modules mutate it
            # (`_module_results_so_far`) and must not leak across files.
            report = run_pipeline(file, copy.deepcopy(config), progress_cb=progress_cb)
        except Exception as exc:  # noqa: BLE001 — the pipeline is the boundary
            # One line at default verbosity; the traceback is a -vv concern.
            logger.error("Pipeline failed for %s: %s", file.name, exc)
            logger.debug("Pipeline traceback", exc_info=True)
            failures.append((file.name, str(exc)))
            err.print(f"[red]  failed: {exc}[/red]")
            continue
        finally:
            progress_fin()

        if min_score is not None and report["scoring"]["total_score"] < min_score:
            logger.info(
                "%s below --min-score %d — hidden", file.name, min_score
            )
            continue

        reports.append(report)

        if not machine:
            from reporting.terminal_reporter import print_terminal_report  # noqa: PLC0415

            print_terminal_report(report, detail_level=detail_level)
            err.print("[dim]" + "─" * 60 + "[/dim]\n")

    return reports, failures


def _emit_machine(reports: list[dict], fmt: str) -> None:
    """Serialise *reports* to stdout as JSON or JSON Lines.

    There is no ``-o`` here on purpose: under a machine format nothing else
    writes to stdout, so ``> out.jsonl`` is enough and cannot interleave.
    """
    from reporting.json_reporter import build_json_report, dumps_json_report  # noqa: PLC0415

    if fmt == "jsonl":
        payload = "\n".join(dumps_json_report(r, compact=True) for r in reports)
    else:
        import json  # noqa: PLC0415

        payload = json.dumps(
            [build_json_report(r) for r in reports], indent=2, default=str
        )

    click.echo(payload)


def _print_summary(reports: list[dict], failures: list[tuple[str, str]]) -> None:
    """Print the per-file summary table to stdout."""
    from rich import box  # noqa: PLC0415
    from rich.table import Table  # noqa: PLC0415

    from reporting.terminal_reporter._common import BAND_COLOURS  # noqa: PLC0415

    table = Table(title="[bold]Triage Summary[/bold]", box=box.ROUNDED, padding=(0, 1))
    table.add_column("File", style="bold", no_wrap=True)
    table.add_column("Score", justify="right", no_wrap=True)
    table.add_column("Risk Band", no_wrap=True)
    table.add_column("Elapsed", justify="right", no_wrap=True)

    for report in reports:
        scoring = report["scoring"]
        band = scoring["risk_band"]
        colour = BAND_COLOURS.get(band, "white")
        table.add_row(
            Path(report["file"]).name,
            f"[{colour}]{scoring['total_score']}[/{colour}]",
            f"[{colour}]{band}[/{colour}]",
            f"{report['timing']['elapsed_seconds']:.1f}s",
        )

    for name, _error in failures:
        table.add_row(name, "[red]ERR[/red]", "[red]ERROR[/red]", "—")

    out.print()
    out.print(table)
    out.print()
