"""``rules`` CLI command group — YARA rule source management.

A group rather than a single verb so later passes can add ``rules list`` /
``rules validate`` without another top-level command. Rendered results go to
stdout; failures go to stderr and exit 3.
"""

import logging
from pathlib import Path

import click

from core.config_loader import get_config

from ._console import err, out
from ._exit import RuntimeFailure
from ._helpers import _setup_logging

logger = logging.getLogger(__name__)


@click.group("rules")
def rules() -> None:
    """Manage the YARA rule sources used by yara_scanner."""


@rules.command("update")
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to config.yaml (default: ./config.yaml).",
)
@click.option("--force", is_flag=True, help="Delete and re-clone all rule sources from scratch.")
@click.option("--check", is_flag=True, help="Check for available updates without applying them.")
@click.option("--validate-only", is_flag=True, help="Only validate existing rules (no network access).")
@click.option(
    "-v",
    "--verbose",
    "verbosity",
    count=True,
    help="How much prints: -v lists broken rules, -vv adds DEBUG logs.",
)
def update(
    config_path: Path | None,
    force: bool,
    check: bool,
    validate_only: bool,
    verbosity: int,
) -> None:
    """Clone or pull the configured rule repositories, then compile-check them.

    Sources are read from ``rule_sources`` in config.yaml. Missing repos are
    cloned, existing ones are pulled, and every ``.yar``/``.yara`` file is
    compiled afterwards so a bad upstream commit cannot silently break
    scanning.
    """
    from core.rule_updater import (  # noqa: PLC0415
        check_git_available,
        update_all_sources,
        validate_rules,
    )

    if check and force:
        raise click.UsageError(
            "--check and --force are mutually exclusive: --check applies nothing"
        )

    _setup_logging(verbosity=verbosity)
    config = get_config(config_path)
    _setup_logging(config["log_level"], verbosity)

    out.print("\n[bold cyan]ThreatLens[/bold cyan]  [dim]Rule Update[/dim]\n")

    rules_dir = Path(config.get("yara_rules_dir", "./rules/yara"))

    # --validate-only: compile-check rules, no network.
    if validate_only:
        err.print("[dim]Validating existing rules…[/dim]")
        vr = validate_rules(rules_dir)
        if vr.get("skipped_reason"):
            err.print(f"[yellow]Validation skipped: {vr['skipped_reason']}[/yellow]")
        else:
            _print_validation(vr, verbosity > 0)
        return

    if not check_git_available():
        raise RuntimeFailure("git is required for rule updates — install git and retry")

    report = update_all_sources(config, force=force, check_only=check)

    if check:
        _print_check_results(report)
    else:
        _print_update_results(report, verbosity > 0)

    out.print()


def _print_validation(vr: dict, verbose: bool) -> None:
    """Display rule validation results."""
    total = vr["total_files"]
    valid = vr["valid_count"]
    broken = vr["broken_count"]

    if broken == 0:
        out.print(
            f"[bold green]Validation:[/bold green] {valid}/{total} rules compile successfully"
        )
    else:
        out.print(
            f"[bold yellow]Validation:[/bold yellow] {valid}/{total} rules compile "
            f"successfully ({broken} broken)"
        )
        if verbose and vr["broken_files"]:
            for bf in vr["broken_files"]:
                out.print(f"  [dim red]{bf['file']}:[/dim red] {bf['error']}")


def _print_check_results(report: dict) -> None:
    """Display ``--check`` results."""
    for src in report["sources"]:
        name = src["name"]
        if not src["exists"]:
            out.print(
                f"  [bold]{name}:[/bold] not cloned yet "
                "(will be cloned on next update)"
            )
        elif src.get("error"):
            out.print(f"  [bold]{name}:[/bold] [red]error — {src['error']}[/red]")
        elif src["has_updates"]:
            behind = src["commits_behind"]
            local = src.get("local_commit", "?")
            remote = src.get("remote_commit", "?")
            out.print(
                f"  [bold]{name}:[/bold] [cyan]{behind} new commit(s) available[/cyan] "
                f"(local: {local}, remote: {remote})"
            )
        else:
            out.print(f"  [bold]{name}:[/bold] [green]up to date[/green]")


def _print_update_results(report: dict, verbose: bool) -> None:
    """Display update results per source, then validation."""
    from rich.panel import Panel  # noqa: PLC0415

    action_style = {
        "cloned": ("Cloned", "bold green"),
        "pulled": ("Updated", "bold cyan"),
        "up_to_date": ("Up to date", "bold green"),
        "error": ("Error", "bold red"),
        "skipped": ("Skipped", "bold yellow"),
    }

    for src in report["sources"]:
        action = src.get("action", "skipped")
        label, style = action_style.get(action, ("Unknown", "dim"))

        lines: list[str] = [f"[{style}]{label}[/{style}]"]

        if action == "error" and src.get("error"):
            lines.append(f"[red]{src['error']}[/red]")
        elif action == "cloned":
            lines.append(f"Commit: {src.get('new_commit', '?')}")
            lines.append(f"Rules:  {src.get('rule_count', 0)} files")
        elif action == "pulled":
            old = src.get("old_commit", "?")
            new = src.get("new_commit", "?")
            changes = src.get("changes", {})
            lines.append(f"Commit: {old} → {new}")
            parts = []
            if changes.get("new"):
                parts.append(f"{changes['new']} new")
            if changes.get("modified"):
                parts.append(f"{changes['modified']} modified")
            if changes.get("deleted"):
                parts.append(f"{changes['deleted']} deleted")
            if parts:
                lines.append(f"Changes: {', '.join(parts)}")
            lines.append(f"Rules:  {src.get('rule_count', 0)} files")
        elif action == "up_to_date":
            lines.append(f"Commit: {src.get('new_commit') or src.get('old_commit', '?')}")
            lines.append(f"Rules:  {src.get('rule_count', 0)} files")

        out.print(Panel(
            "\n".join(lines),
            title=f"[bold]{src['name']}[/bold]",
            expand=False,
            padding=(0, 2),
        ))

    vr = report.get("validation")
    if vr:
        if vr.get("skipped_reason"):
            err.print(f"\n[yellow]Validation skipped: {vr['skipped_reason']}[/yellow]")
        else:
            _print_validation(vr, verbose)
