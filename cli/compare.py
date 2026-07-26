"""``compare`` CLI command — side-by-side analysis of two files.

Shares the two-axis flag surface with ``scan``: ``-p`` picks what runs, ``-v``
picks what prints. Both files are analysed under an independent copy of the
config so neither run can contaminate the other's module state.
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

    c1 = BAND_COLOURS.get(scoring1["risk_band"], "white")
    c2 = BAND_COLOURS.get(scoring2["risk_band"], "white")
    table.add_row(
        "Score",
        f"[{c1}]{scoring1['total_score']} / 100  {scoring1['risk_band']}[/{c1}]",
        f"[{c2}]{scoring2['total_score']} / 100  {scoring2['risk_band']}[/{c2}]",
    )

    h1, h2 = _get_hashes(report1), _get_hashes(report2)
    table.add_row(
        "SHA256",
        h1.get("sha256", "N/A")[:16] + "…",
        h2.get("sha256", "N/A")[:16] + "…",
    )

    similarity = _tlsh_similarity(h1.get("tlsh"), h2.get("tlsh"))
    if similarity:
        table.add_row("TLSH similarity", similarity, "")

    # Per-module score comparison.
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
    """Return file_intake's hash dict, or empty if the module did not succeed."""
    intake = next(
        (r for r in report["module_results"] if r.get("module") == "file_intake"), None
    )
    if intake and intake.get("status") == "success":
        return intake["data"].get("hashes", {})
    return {}


def _tlsh_similarity(tlsh1: str | None, tlsh2: str | None) -> str:
    """Describe the TLSH distance between two digests, or "" if unavailable."""
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
    """Map module name → score_delta for one report."""
    return {r["module"]: r.get("score_delta", 0) for r in report["module_results"]}


def _fmt_delta(delta: int) -> str:
    """Render a score delta: ``+15``, ``—`` for zero, plain for negative."""
    if delta > 0:
        return f"+{delta}"
    return "—" if delta == 0 else str(delta)
