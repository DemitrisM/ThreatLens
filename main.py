"""Malware Triage Tool — Entry point and CLI argument parsing.

Accepts a suspicious file path from the user, orchestrates the analysis
pipeline, and outputs a structured threat report with confidence scoring.
"""

import logging
import sys
from pathlib import Path

import click

from core.config_loader import get_config
from core.pipeline import run_pipeline
from reporting.json_reporter import write_json_report
from reporting.terminal_reporter import print_terminal_report


def _setup_logging(log_level: str, verbose: bool, debug: bool) -> None:
    """Configure the root logger based on CLI flags and config."""
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = getattr(logging, log_level, logging.INFO)

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@click.group()
@click.version_option(version="0.1.0", prog_name="malware-triage")
def cli() -> None:
    """Malware Triage Tool — static analysis with transparent confidence scoring."""


@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
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
@click.option("--verbose", "-v", is_flag=True, help="Enable INFO-level logging.")
@click.option("--debug", is_flag=True, help="Enable DEBUG-level logging.")
def analyse(
    file: Path,
    config_path: Path | None,
    output: str,
    output_dir: Path | None,
    dynamic: str | None,
    verbose: bool,
    debug: bool,
) -> None:
    """Analyse FILE and produce a threat report with confidence scoring."""
    config = get_config(config_path)

    _setup_logging(config["log_level"], verbose, debug)
    logger = logging.getLogger(__name__)

    if output_dir is not None:
        config["output_dir"] = str(output_dir)

    if dynamic is not None:
        config["dynamic_provider"] = dynamic.lower()

    logger.info("Starting analysis of %s", file)

    try:
        report = run_pipeline(file, config)
    except Exception as exc:  # noqa: BLE001
        logger.error("Pipeline failed: %s", exc)
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    output_lower = output.lower()

    if output_lower in ("terminal", "all"):
        print_terminal_report(report)

    if output_lower in ("json", "all"):
        out_dir = Path(config["output_dir"])
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = write_json_report(report, out_dir)
        logger.info("JSON report written to %s", json_path)
        if output_lower == "json":
            click.echo(f"Report saved: {json_path}")

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


if __name__ == "__main__":
    cli()
