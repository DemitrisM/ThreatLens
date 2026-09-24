"""``scan`` CLI command — analyse a single file.

Two axes, no third: ``--profile`` selects which modules run, ``-v``/``-vv``
select how much prints. Machine formats go to stdout (or to ``-o FILE``),
diagnostics go to stderr, and the exit status reflects the risk band when
``--fail-on`` is given.

Design notes
------------
**The docstrings here are user-facing.** Click builds every ``--help`` string
from the docstring of the function it decorates, so the one-line summary on
:func:`scan` is what a user reads, not an internal note. That also defeats
the AST proof used to verify a comment pass, since it strips docstrings
before comparing — a rewritten help text is invisible to it. Diff the
rendered help instead.

**Validation order is deliberate.** The two usage errors are raised before
the config is read and before any module runs, so a wrong invocation costs
nothing. Everything after that point can fail only at runtime, which is
exit 3. The one exception is ``--hash-only -f html``, which is refused
after hashing — the check sits with the other format branches rather than
beside the argument checks, and hashing is the cheapest thing the tool does.

**``--hash-only`` is not a scan.** It replaces ``enabled_modules``
wholesale, so ``--modules`` and ``--skip`` are accepted and then ignored,
and it returns before ``--fail-on`` is evaluated — nothing was analysed, so
there is no risk band to grade.

**Stream discipline (design rules 6 and 7).** Results reach stdout through
``print_machine``, which writes the payload byte for byte — unwrapped,
unstyled and with markup off, so a JSON document longer than the terminal
survives ``-f json | jq`` and a ``[`` inside a string is not read as a
style tag. Every notice, including "Report written to …", goes to ``err``:
a saved-path line on stdout would corrupt the same pipeline.
"""

import logging
from pathlib import Path

import click

from core.config_loader import ConfigNotFound, get_config
from core.pipeline import run_pipeline

from ._console import err, out, print_machine
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
    # click.Choice(case_sensitive=False) matches case-insensitively but hands
    # back what the user typed, so downstream comparisons need the fold.
    fmt = fmt.lower()
    profile = profile.lower()

    # ── Usage errors, before any work ───────────────────────────────────
    # `exists=True` has already confirmed the path; this separates the two
    # verbs rather than letting a directory reach the pipeline.
    if file.is_dir():
        raise click.UsageError(
            "scan takes a single file; use 'threatlens triage' for a directory"
        )
    if fmt == "text" and output_path is not None:
        raise click.UsageError(
            "-o/--output needs a machine format; use -f json, -f jsonl, or -f html"
        )
    # Refused here rather than where the hashes are formatted, so a
    # known-invalid invocation does not hash the file first.
    if hash_only and fmt == "html":
        raise click.UsageError("--hash-only supports -f text, json, or jsonl")

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
    config = _apply_scan_profile(config, profile)
    config = _apply_module_overrides(config, modules, skip)

    if hash_only:
        _run_hash_only(file, config, fmt, output_path)
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


def _run_hash_only(
    file: Path, config: dict, fmt: str, output_path: Path | None = None
) -> None:
    """Print hashes only, in text or machine form.

    Args:
        file:        The file to hash. Already known to exist and not be a
                     directory.
        config:      Loaded config. Both ``enabled_modules`` and
                     ``dynamic_provider`` are replaced here.
        fmt:         Output format. ``html`` has already been refused by
                     the caller — there is no report to render, only four
                     lines of text.
        output_path: Destination for a machine format, or None for stdout.
                     ``-f text`` with a path is a usage error the caller
                     has already rejected.

    Raises:
        RuntimeFailure: When ``file_intake`` did not succeed, since the
            hashes are the entire output and an empty result is not one,
            or when the output path cannot be written.

    The pipeline is still used rather than hashing inline, so that the type
    detection, the size guards and the ssdeep backend selection behave
    identically to a real scan — ``--hash-only`` is meant to answer "what
    would that scan call this file", not to be a second implementation.
    """
    # Both keys, because they are separate gates. The dynamic provider is
    # selected by `dynamic_provider` alone and is not listed in
    # `enabled_modules`, so restricting the module list does not restrict
    # detonation — a request for four hashes would have run a sandbox.
    config["enabled_modules"] = ["file_intake"]
    config["dynamic_provider"] = "none"
    report = _run_pipeline(file, config)

    intake = next(
        (r for r in report["module_results"] if r.get("module") == "file_intake"), None
    )
    if intake is None or intake.get("status") != "success":
        raise RuntimeFailure("file_intake failed — cannot compute hashes")

    hashes = intake["data"].get("hashes", {})

    # ── Machine formats ─────────────────────────────────────────────────
    # jsonl is one line, so it takes the compact separators and no indent;
    # json is read by a person as often as by a program and stays indented.
    if fmt in _MACHINE_FORMATS:
        import json  # noqa: PLC0415

        payload = {"file": str(file), "hashes": hashes}
        separators = (",", ":") if fmt == "jsonl" else None
        rendered = json.dumps(payload, indent=None if fmt == "jsonl" else 2,
                              separators=separators, default=str)
        if output_path is None:
            print_machine(rendered)
        else:
            _write_text(output_path, rendered)
            err.print(f"[dim]Hashes written to {output_path}[/dim]")
        return

    # TLSH and ssdeep are conditional: both have minimum-size and backend
    # requirements, and a line reading "ssdeep: N/A" invites the reader to
    # think the file has no fuzzy hash rather than that none was computed.
    print_machine(f"MD5:    {hashes.get('md5', 'N/A')}")
    print_machine(f"SHA256: {hashes.get('sha256', 'N/A')}")
    if hashes.get("tlsh"):
        print_machine(f"TLSH:   {hashes['tlsh']}")
    if hashes.get("ssdeep"):
        print_machine(f"ssdeep: {hashes['ssdeep']}")


def _emit(
    report: dict,
    fmt: str,
    output_path: Path | None,
    config: dict,
    *,
    detail_level: int,
) -> None:
    """Route the finished report to the requested destination.

    Args:
        report:       The pipeline's result dict.
        fmt:          ``text``, ``json``, ``jsonl`` or ``html``.
        output_path:  Destination file, or None for stdout. Already refused
                      for ``-f text`` by the caller.
        config:       Read only for ``output_dir``, the default HTML
                      destination.
        detail_level: Clamped ``-v`` count, used by the terminal reporter.

    Raises:
        RuntimeFailure: On any failure to write or render — exit 3.

    Reporters are imported inside the branch that uses them. Each pulls in
    rich or jinja2, and a ``-f jsonl`` sweep over a directory should not pay
    for a template engine it never renders with.
    """
    if fmt == "text":
        from reporting.terminal_reporter import print_terminal_report  # noqa: PLC0415

        print_terminal_report(report, detail_level=detail_level)
        return

    if fmt in _MACHINE_FORMATS:
        from reporting.json_reporter import dumps_json_report  # noqa: PLC0415

        payload = dumps_json_report(report, compact=fmt == "jsonl")
        if output_path is None:
            print_machine(payload)
        else:
            _write_text(output_path, payload)
            err.print(f"[dim]Report written to {output_path}[/dim]")
        return

    # ── HTML ────────────────────────────────────────────────────────────
    # `write_html_report` names the file itself, from a timestamp, so that
    # two scans of the same sample cannot overwrite each other. With `-o`
    # the caller has named it instead: it is written into the destination's
    # own directory first and then renamed onto the requested path, which
    # keeps the rename within one filesystem and therefore atomic.
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
