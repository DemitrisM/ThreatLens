"""``scan`` CLI command — analyse a single file.

Two axes, no third: ``--profile`` selects which modules run, ``-v``/``-vv``
select how much prints. Machine formats go to stdout (or to ``-o FILE``),
diagnostics go to stderr, and the exit status reflects the risk band when
``--fail-on`` is given.
"""

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


@click.command("scan")
@click.argument("file", type=click.Path(exists=True, path_type=Path))
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
    help="How much prints: -v expands every section, -vv adds raw module data and DEBUG logs.",
)
@click.option(
    "-f",
    "--format",
    "fmt",
    type=click.Choice(["text", "json", "jsonl", "html"], case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format. json/jsonl go to stdout unless -o is given.",
)
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="Write the report to this file instead of stdout.",
)
@click.option(
    "--fail-on",
    type=click.Choice(FAIL_ON_CHOICES, case_sensitive=False),
    default=None,
    help="Exit 1 when the risk band reaches this level. Default: never fail.",
)
@click.option(
    "--modules",
    default=None,
    help="Comma-separated list of modules to run, by their registry names "
    "(e.g. pe_analysis,capa_analysis,yara_scanner).",
)
@click.option("--skip", default=None, help="Comma-separated list of modules to skip.")
@click.option("--hash-only", is_flag=True, help="Print file hashes only — no analysis.")
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to config.yaml (default: ./config.yaml).",
)
@click.pass_context
def scan(
    ctx: click.Context,
    file: Path,
    profile: str,
    verbosity: int,
    fmt: str,
    output_path: Path | None,
    fail_on: str | None,
    modules: str | None,
    skip: str | None,
    hash_only: bool,
    config_path: Path | None,
) -> None:
    """Analyse FILE and report a threat score with transparent scoring."""
    fmt = fmt.lower()
    profile = profile.lower()

    if file.is_dir():
        raise click.UsageError(
            "scan takes a single file; use 'threatlens triage' for a directory"
        )
    if fmt == "text" and output_path is not None:
        raise click.UsageError(
            "-o/--output needs a machine format; use -f json, -f jsonl, or -f html"
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

    config = _apply_scan_profile(config, profile)
    config = _apply_module_overrides(config, modules, skip)

    if hash_only:
        _run_hash_only(file, config, fmt)
        return

    report = _run_pipeline(file, config)

    _emit(report, fmt, output_path, config, detail_level=_detail_level(verbosity))

    if meets_threshold(report["scoring"]["risk_band"], fail_on):
        ctx.exit(EXIT_THREAT)


def _run_pipeline(file: Path, config: dict) -> dict:
    """Run the pipeline with a stderr progress spinner.

    Raises:
        RuntimeFailure: On any pipeline exception — exit 3, not a traceback.
    """
    progress_cb, progress_fin = _make_progress_cb(err.is_terminal)
    try:
        return run_pipeline(file, config, progress_cb=progress_cb)
    except Exception as exc:  # noqa: BLE001 — the pipeline is the boundary
        # One line at default verbosity; the traceback is a -vv concern.
        logger.error("Pipeline failed: %s", exc)
        logger.debug("Pipeline traceback", exc_info=True)
        raise RuntimeFailure(f"analysis failed: {exc}") from exc
    finally:
        progress_fin()


def _run_hash_only(file: Path, config: dict, fmt: str) -> None:
    """Print hashes only, in text or machine form."""
    config["enabled_modules"] = ["file_intake"]
    report = _run_pipeline(file, config)

    intake = next(
        (r for r in report["module_results"] if r.get("module") == "file_intake"), None
    )
    if intake is None or intake.get("status") != "success":
        raise RuntimeFailure("file_intake failed — cannot compute hashes")

    hashes = intake["data"].get("hashes", {})

    if fmt in _MACHINE_FORMATS:
        import json  # noqa: PLC0415

        payload = {"file": str(file), "hashes": hashes}
        separators = (",", ":") if fmt == "jsonl" else None
        click.echo(json.dumps(payload, indent=None if fmt == "jsonl" else 2,
                              separators=separators, default=str))
        return

    if fmt == "html":
        raise click.UsageError("--hash-only supports -f text, json, or jsonl")

    click.echo(f"MD5:    {hashes.get('md5', 'N/A')}")
    click.echo(f"SHA256: {hashes.get('sha256', 'N/A')}")
    if hashes.get("tlsh"):
        click.echo(f"TLSH:   {hashes['tlsh']}")
    if hashes.get("ssdeep"):
        click.echo(f"ssdeep: {hashes['ssdeep']}")


def _emit(
    report: dict,
    fmt: str,
    output_path: Path | None,
    config: dict,
    *,
    detail_level: int,
) -> None:
    """Route the finished report to the requested destination."""
    if fmt == "text":
        from reporting.terminal_reporter import print_terminal_report  # noqa: PLC0415

        print_terminal_report(report, detail_level=detail_level)
        return

    if fmt in _MACHINE_FORMATS:
        from reporting.json_reporter import dumps_json_report  # noqa: PLC0415

        payload = dumps_json_report(report, compact=fmt == "jsonl")
        if output_path is None:
            click.echo(payload)
        else:
            _write_text(output_path, payload)
            err.print(f"[dim]Report written to {output_path}[/dim]")
        return

    # fmt == "html"
    from reporting.html_reporter import write_html_report  # noqa: PLC0415

    try:
        if output_path is None:
            out_dir = Path(config["output_dir"])
            out_dir.mkdir(parents=True, exist_ok=True)
            written = write_html_report(report, out_dir)
        else:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            written = write_html_report(report, output_path.parent)
            written = written.replace(output_path)
    except OSError as exc:
        raise RuntimeFailure(f"cannot write HTML report: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 — template/render errors
        raise RuntimeFailure(f"HTML report generation failed: {exc}") from exc

    err.print(f"[dim]Report written to {written}[/dim]")


def _write_text(path: Path, payload: str) -> None:
    """Write *payload* to *path*, translating OS errors into exit code 3."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload + "\n", encoding="utf-8")
    except OSError as exc:
        raise RuntimeFailure(f"cannot write {path}: {exc}") from exc
