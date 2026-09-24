"""``compare`` CLI command — side-by-side analysis of two files.

Shares the two-axis flag surface with ``scan``: ``-p`` picks what runs, ``-v``
picks what prints. Both files are analysed under an independent copy of the
config so neither run can contaminate the other's module state.

Design notes
------------
**``-v`` means something narrower here.** In ``scan`` and ``triage`` it
selects report detail; this command renders one fixed table, so verbosity
only raises the log level. The help text says so rather than implying a
detail axis that does not exist.

**No ``--fail-on`` and no machine format, by design.** Comparison answers
"how do these two relate", which is a question a person asks; a caller that
wants both reports as data runs ``scan -f json`` twice and diffs them. That
also means every line here may use rich markup freely — there is no
parseable stdout to protect.

**The table is the result, so it goes to ``out``**; the banner and the
per-file progress lines are chrome and go to ``err`` (design rule 7).

**Both files are analysed before anything is rendered**, so a failure on
the second file produces exit 3 with no half-drawn table. Each gets its own
deep copy of the config because modules write into it —
``_module_results_so_far`` from the first file would otherwise be read as
the second file's own prior results.
"""

import copy
import logging
from pathlib import Path

import click

from core.config_loader import ConfigNotFound, get_config
from core.pipeline import run_pipeline

from ._console import err, out
from ._exit import RuntimeFailure
from ._helpers import PROFILES, _apply_module_overrides, _apply_scan_profile, _setup_logging
from ._progress import _make_progress_cb

logger = logging.getLogger(__name__)


@click.command("compare")
@click.argument("file1", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("file2", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "-p",
    "--profile",
    type=click.Choice(PROFILES, case_sensitive=False),
    default="standard",
    show_default=True,
    help="Which modules run: quick (intake + PE), standard (all), deep (extended timeouts).",
)
@click.option(
    "-v",
    "--verbose",
    "verbosity",
    count=True,
    help="How much prints: -v adds INFO logs, -vv adds DEBUG logs.",
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
def compare(
    file1: Path,
    file2: Path,
    profile: str,
    verbosity: int,
    modules: str | None,
    skip: str | None,
    config_path: Path | None,
) -> None:
    """Analyse FILE1 and FILE2 and show their scores side by side."""
    # Imported here rather than at module scope: rich and the reporter
    # package cost tens of milliseconds, and `cli/__init__` imports this
    # module on every invocation, including `scan -f jsonl`.
    from rich import box  # noqa: PLC0415
    from rich.table import Table  # noqa: PLC0415

    from reporting.terminal_reporter._common import BAND_COLOURS  # noqa: PLC0415

    _setup_logging(verbosity=verbosity)
    try:
        config = get_config(config_path)
    except ConfigNotFound as exc:
        raise click.UsageError(
            f"Config file not found: {exc}"
        ) from exc
    _setup_logging(config["log_level"], verbosity)

    config = _apply_scan_profile(config, profile.lower())
    config = _apply_module_overrides(config, modules, skip)

    err.print("\n[bold cyan]ThreatLens[/bold cyan]  [dim]Compare Mode[/dim]\n")

    report1 = _analyse(file1, config)
    report2 = _analyse(file2, config)

    scoring1 = report1["scoring"]
    scoring2 = report2["scoring"]

    table = Table(title="[bold]Comparison[/bold]", box=box.ROUNDED, padding=(0, 1))
    table.add_column("", style="bold dim", no_wrap=True)
    table.add_column(file1.name, overflow="fold")
    table.add_column(file2.name, overflow="fold")

    # The fallback repeats `terminal_reporter/score.py` verbatim so the two
    # renderings of a band cannot drift. Note that rich reads "white" as
    # ANSI colour 7, not as the terminal default, so it is a real colour
    # and not a neutral one — unreachable in practice, since every band
    # comes from `core.scoring`'s fixed set and is therefore in the table.
    # Recorded in the project notes: the literal belongs in the palette.
    c1 = BAND_COLOURS.get(scoring1["risk_band"], "white")
    c2 = BAND_COLOURS.get(scoring2["risk_band"], "white")
    table.add_row(
        "Score",
        f"[{c1}]{scoring1['total_score']} / 100  {scoring1['risk_band']}[/{c1}]",
        f"[{c2}]{scoring2['total_score']} / 100  {scoring2['risk_band']}[/{c2}]",
    )

    # ── Identity ────────────────────────────────────────────────────────
    # Truncated, unlike every other SHA256 the tool prints: two 64-character
    # columns plus a label do not fit the 100-column help width, and this
    # row answers "are these the same file", which the first 16 characters
    # settle. `scan` is where a hash is read to be pasted somewhere.
    h1, h2 = _get_hashes(report1), _get_hashes(report2)
    table.add_row(
        "SHA256",
        h1.get("sha256", "N/A")[:16] + "…",
        h2.get("sha256", "N/A")[:16] + "…",
    )

    # One value describing a relationship, so it spans from the first
    # column and the second is left empty rather than repeating it.
    similarity = _tlsh_similarity(h1.get("tlsh"), h2.get("tlsh"))
    if similarity:
        table.add_row("TLSH similarity", similarity, "")

    # ── Per-module score comparison ─────────────────────────────────────
    # Union rather than intersection, and sorted: a module that ran for one
    # file and not the other is the interesting case, and it must still get
    # a row. Sorting keeps the two halves of a comparison aligned even when
    # the files enabled different module sets.
    table.add_section()
    s1, s2 = _module_scores(report1), _module_scores(report2)
    for module in sorted(set(s1) | set(s2)):
        table.add_row(module, _fmt_delta(s1.get(module, 0)), _fmt_delta(s2.get(module, 0)))

    table.add_section()
    table.add_row(
        "Elapsed",
        f"{report1['timing']['elapsed_seconds']:.1f}s",
        f"{report2['timing']['elapsed_seconds']:.1f}s",
    )

    out.print()
    out.print(table)
    out.print()


def _analyse(file: Path, config: dict) -> dict:
    """Run the pipeline on *file* against an isolated copy of *config*.

    Raises:
        RuntimeFailure: On any pipeline exception — exit 3, not a traceback.
    """
    err.print(f"[dim]Analysing {file.name}…[/dim]")
    progress_cb, progress_fin = _make_progress_cb(err.is_terminal)
    try:
        return run_pipeline(file, copy.deepcopy(config), progress_cb=progress_cb)
    except Exception as exc:  # noqa: BLE001 — the pipeline is the boundary
        # One line at default verbosity; the traceback is a -vv concern.
        logger.error("Pipeline failed for %s: %s", file.name, exc)
        logger.debug("Pipeline traceback", exc_info=True)
        raise RuntimeFailure(f"analysis of {file.name} failed: {exc}") from exc
    finally:
        progress_fin()


def _get_hashes(report: dict) -> dict:
    """Return file_intake's hash dict, or empty if the module did not succeed.

    Args:
        report: A finished pipeline report.

    Returns:
        The ``hashes`` sub-dict, or ``{}``. Empty rather than raising: a
        comparison whose hashes are missing still has scores and per-module
        deltas worth showing, and the callers render "N/A".
    """
    intake = next(
        (r for r in report["module_results"] if r.get("module") == "file_intake"), None
    )
    if intake and intake.get("status") == "success":
        return intake["data"].get("hashes", {})
    return {}


def _tlsh_similarity(tlsh1: str | None, tlsh2: str | None) -> str:
    """Describe the TLSH distance between two digests, or "" if unavailable.

    Args:
        tlsh1: First digest, or None when the file was too small (TLSH
               needs roughly 50 bytes of varied input) or the library is
               absent.
        tlsh2: Second digest, same.

    Returns:
        A rendered description, or "" — which the caller treats as "omit
        the row" rather than printing an empty measurement.

    The library is imported lazily and its absence is an ``info`` line, not
    a warning: TLSH is optional, and ``file_intake`` has already said so
    once for the scan itself.

    ``tlsh.diff`` raises ``ValueError`` on a malformed digest, which is not
    guarded because ``file_intake`` yields either a valid hexdigest or
    None — it catches that same ``ValueError`` from ``final()`` and stores
    nothing. Recorded in the project notes rather than defended here, so
    the assumption is written down where it can be rechecked.
    """
    if not (tlsh1 and tlsh2):
        return ""
    try:
        import tlsh  # noqa: PLC0415
    except ImportError:
        logger.info("tlsh not installed — skipping similarity comparison")
        return ""

    diff = tlsh.diff(tlsh1, tlsh2)
    if diff == 0:
        return "Identical"
    return f"Distance: {diff} {'(similar)' if diff < 100 else '(different)'}"


def _module_scores(report: dict) -> dict[str, int]:
    """Map module name → score_delta for one report.

    Zero-delta modules are kept, unlike the scoring breakdown, which drops
    them: "ran and found nothing" and "did not run" are different answers
    and this table exists to show the difference between two files.
    """
    return {r["module"]: r.get("score_delta", 0) for r in report["module_results"]}


def _fmt_delta(delta: int) -> str:
    """Render a score delta: ``+15``, ``—`` for zero, plain for negative.

    An em dash rather than ``0`` so a column of inert modules reads as
    background and the modules that scored stand out. Negative deltas have
    no sign added — the minus is already there, and ``+-5`` would be worse
    than useless.
    """
    if delta > 0:
        return f"+{delta}"
    return "—" if delta == 0 else str(delta)
