"""``triage`` CLI command — sweep a directory of files.

``triage`` is the batch counterpart to ``scan``: same two axes, but the
default profile is ``quick`` because a sweep is meant to be cheap. Under a
machine format every piece of chrome (banner, separators, summary table) is
suppressed or routed to stderr, so ``-f jsonl`` yields exactly one parseable
line per analysed file.

Design notes
------------
**``--min-score`` hides rows; it does not decide the exit code.**
:func:`_analyse_all` returns two lists for that reason — one filtered for
display, one holding every report produced. Grading ``--fail-on`` against
the filtered list made ``--min-score 90 --fail-on HIGH`` exit 0 on a
directory full of HIGH files, which is the one invocation a CI gate would
use to catch them.

**A runtime failure outranks a threat verdict.** Exit 1 asserts the sweep
was complete and the answer is "threat"; a sweep that could not read part
of the directory cannot make that claim, so any failure produces exit 3 —
after the reports are emitted, so the results of the files that did work
are not lost.

**Every file gets its own config copy.** Modules write into the config
(``_module_results_so_far``), so a shared dict would carry one file's
module results into the next file's VirusTotal lookups.

**Chrome is conditional on the format, not on verbosity.** Under ``-f
json``/``jsonl`` the banner, the separators and the summary table are
suppressed or sent to stderr, so stdout holds exactly the parseable
payload. The per-file progress lines are on stderr either way.
"""

import copy
import logging
from pathlib import Path

import click

from core.config_loader import ConfigNotFound, get_config
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
    # click.Choice(case_sensitive=False) matches case-insensitively but hands
    # back what the user typed, so downstream comparisons need the fold.
    fmt = fmt.lower()
    profile = profile.lower()

    # ── Usage error, before any work ────────────────────────────────────
    if directory.is_file():
        raise click.UsageError(
            "triage takes a directory; use 'threatlens scan' for a single file"
        )

    # Logging first, so config-loading warnings reach the configured handler.
    _setup_logging(verbosity=verbosity)
    try:
        config = get_config(config_path)
    except ConfigNotFound as exc:
        raise click.UsageError(
            f"Config file not found: {exc}"
        ) from exc
    _setup_logging(config["log_level"], verbosity)

    # Profile before overrides: the profile rewrites `enabled_modules`
    # wholesale, so applying it second would reinstate what --skip removed.
    # `quick` is the default here rather than `standard` — a sweep is meant
    # to be cheap, and `scan -v` investigates whatever it points at.
    config = _apply_scan_profile(config, profile)
    config = _apply_module_overrides(config, modules, skip)

    files = _collect_files(directory, recursive=recursive)
    if not files:
        err.print(f"[yellow]No files found in {directory}[/yellow]")
        return

    # An empty directory is not an error: a sweep that finds nothing to
    # analyse has still run, and exit 0 with a stderr notice says so
    # without a CI job treating it as a failure.
    machine = fmt in _MACHINE_FORMATS
    if not machine:
        err.print(
            f"\n[bold cyan]Triage:[/bold cyan] {len(files)} file(s) in {directory}\n"
        )

    reports, analysed, failures = _analyse_all(
        files,
        config,
        machine=machine,
        min_score=min_score,
        detail_level=_detail_level(verbosity),
    )

    if machine:
        _emit_machine(reports, fmt)
    else:
        _print_summary(reports, failures, analysed)

    # Runtime failure outranks a threat verdict.
    if failures:
        raise RuntimeFailure(
            f"{len(failures)} of {len(files)} file(s) failed to analyse: "
            + ", ".join(name for name, _ in failures[:5])
        )
    # Graded over every file that was analysed, not over the ones that were
    # printed. `--min-score` hides rows; letting it also decide the exit code
    # would mean `--min-score 90 --fail-on HIGH` reporting success on a
    # directory full of HIGH files — the one invocation a CI gate would use.
    if any(meets_threshold(r["scoring"]["risk_band"], fail_on) for r in analysed):
        ctx.exit(EXIT_THREAT)


def _collect_files(directory: Path, *, recursive: bool) -> list[Path]:
    """Return the files to analyse, dotfiles excluded, deterministically ordered.

    Args:
        directory: The sweep root. Already known to be a directory.
        recursive: True descends into subdirectories.

    Returns:
        Sorted paths. Sorted rather than left in filesystem order so that
        two sweeps of the same directory produce the same ``-f jsonl``
        output, which is what makes the format diffable between runs.

    With ``recursive`` a dot-prefixed *directory* is skipped too — walking
    into ``.git`` or ``.venv`` is never what a triage sweep wants. The same
    rule excludes a dot-prefixed *file*, which is collateral rather than
    the intent, and is pinned by a test; see the project notes for why it
    has been left as a decision rather than changed.
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
) -> tuple[list[dict], list[dict], list[tuple[str, str]]]:
    """Run the pipeline over every file.

    Args:
        files:        Paths to analyse, in the order they will be reported.
        config:       Loaded config. Deep-copied per file rather than shared.
        machine:      True under ``-f json``/``jsonl``, which suppresses the
                      per-file terminal report and the spinner.
        min_score:    Display filter, or None. Never affects *analysed*.
        detail_level: Clamped ``-v`` count; 1 or more prints a full report
                      per file between the sweep rows.

    Returns:
        ``(shown, analysed, failures)``. *shown* holds the reports that
        passed ``--min-score`` and is what gets printed or serialised;
        *analysed* holds every report the pipeline produced, and is what
        ``--fail-on`` is graded against; *failures* holds ``(name, error)``
        pairs for files whose pipeline raised.
    """
    shown: list[dict] = []
    analysed: list[dict] = []
    failures: list[tuple[str, str]] = []

    for index, file in enumerate(files, start=1):
        # On stderr even under a machine format: it is progress, not
        # output, and stdout has to stay parseable (design rule 7).
        err.print(f"[dim]({index}/{len(files)}) {file.name}[/dim]")
        progress_cb, progress_fin = _make_progress_cb(err.is_terminal and not machine)
        try:
            # Each file gets its own config copy — modules mutate it
            # (`_module_results_so_far`) and must not leak across files.
            report = run_pipeline(file, copy.deepcopy(config), progress_cb=progress_cb)
        # One bad file must not end the sweep — the remaining files are
        # still analysed and the failure is carried to the exit code.
        except Exception as exc:  # noqa: BLE001 — the pipeline is the boundary
            # One line at default verbosity; the traceback is a -vv concern.
            logger.error("Pipeline failed for %s: %s", file.name, exc)
            logger.debug("Pipeline traceback", exc_info=True)
            failures.append((file.name, str(exc)))
            err.print(f"[red]  failed: {exc}[/red]")
            continue
        finally:
            progress_fin()

        analysed.append(report)

        # ── Display filter ──────────────────────────────────────────────
        # Recorded above first, so a hidden file still reaches --fail-on.
        if min_score is not None and report["scoring"]["total_score"] < min_score:
            logger.info(
                "%s below --min-score %d — hidden", file.name, min_score
            )
            continue

        shown.append(report)

        # Triage is a different output *shape*, not a quieter scan: at
        # default verbosity only the score table prints, and `scan -v`
        # investigates whatever it points at. -v restores per-file reports.
        if not machine and detail_level >= 1:
            from reporting.terminal_reporter import print_terminal_report  # noqa: PLC0415

            print_terminal_report(report, detail_level=detail_level)
            err.print("[dim]" + "─" * 60 + "[/dim]\n")

    return shown, analysed, failures


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


def _print_summary(
    reports: list[dict],
    failures: list[tuple[str, str]],
    analysed: list[dict] | None = None,
) -> None:
    """Print the sweep score table to stdout, highest score first.

    Args:
        reports:  The reports that passed ``--min-score`` — the rows.
        failures: ``(name, error)`` pairs, rendered as their own section so
                  a file that could not be read is visible rather than
                  merely absent from the table.
        analysed: Every report the sweep produced, used only for the total
                  time. Defaults to *reports* for a caller that does not
                  filter. Timed over all of them because the work was done
                  either way: summing the rows instead would report a
                  fraction of the real cost under ``--min-score``, which is
                  the number a user reads to decide whether the sweep is
                  affordable.

    The total is summed from the per-file pipeline timings rather than
    measured around the loop, so it reports time spent analysing and not
    time spent rendering the reports between files at ``-v``.
    """
    from reporting.triage_reporter import print_triage_table  # noqa: PLC0415

    elapsed = sum(
        (r.get("timing") or {}).get("elapsed_seconds") or 0.0
        for r in (reports if analysed is None else analysed)
    )
    print_triage_table(reports, failures, elapsed=elapsed, console=out)
