"""``update-rules`` CLI command — YARA rule source management."""

import sys
from pathlib import Path

import click

from core.config_loader import get_config

from ._helpers import _setup_logging


@click.command("update-rules")
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
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output.")
@click.option("--debug", is_flag=True, help="Show debug logging.")
def update_rules(
    config_path: Path | None,
    force: bool,
    check: bool,
    validate_only: bool,
    verbose: bool,
    debug: bool,
) -> None:
    """Update YARA rule sets from configured sources.

    Clones rule repositories if not present, pulls updates if already
    cloned, validates all rules compile correctly, and reports changes.
    """
    from core.rule_updater import (  # noqa: PLC0415
        check_git_available,
        update_all_sources,
        validate_rules,
    )
    from rich.console import Console  # noqa: PLC0415
    from rich.panel import Panel  # noqa: PLC0415
    from rich.table import Table  # noqa: PLC0415
    from rich import box  # noqa: PLC0415

    config = get_config(config_path)
    _setup_logging(config["log_level"], verbose, debug)

    console = Console()
    console.print("\n[bold cyan]ThreatLens[/bold cyan]  [dim]Rule Update[/dim]\n")

    rules_dir = Path(config.get("yara_rules_dir", "./rules/yara"))

    # --validate-only: compile-check rules, no network
    if validate_only:
        console.print("[dim]Validating existing rules…[/dim]")
        vr = validate_rules(rules_dir)
        if vr.get("skipped_reason"):
            console.print(f"[yellow]Validation skipped: {vr['skipped_reason']}[/yellow]")
        else:
            _print_validation(console, vr, verbose)
        return

    if not check_git_available():
        console.print("[bold red]Error:[/bold red] git is required for rule updates — install git and retry.")
        sys.exit(1)

    report = update_all_sources(config, force=force, check_only=check)

    if check:
        _print_check_results(console, report)
    else:
        _print_update_results(console, report, verbose)

    console.print()


def _print_validation(console, vr: dict, verbose: bool) -> None:
    """Display rule validation results."""
    total = vr["total_files"]
    valid = vr["valid_count"]
    broken = vr["broken_count"]

    if broken == 0:
        console.print(
            f"[bold green]Validation:[/bold green] {valid}/{total} rules compile successfully"
        )
    else:
        console.print(
            f"[bold yellow]Validation:[/bold yellow] {valid}/{total} rules compile "
            f"successfully ({broken} broken)"
        )
        if verbose and vr["broken_files"]:
            for bf in vr["broken_files"]:
                console.print(f"  [dim red]{bf['file']}:[/dim red] {bf['error']}")


def _print_check_results(console, report: dict) -> None:
    """Display --check results."""
    for src in report["sources"]:
        name = src["name"]
        if not src["exists"]:
            console.print(
                f"  [bold]{name}:[/bold] not cloned yet "
                "(will be cloned on next update)"
            )
        elif src.get("error"):
            console.print(
                f"  [bold]{name}:[/bold] [red]error — {src['error']}[/red]"
            )
        elif src["has_updates"]:
            behind = src["commits_behind"]
            local = src.get("local_commit", "?")
            remote = src.get("remote_commit", "?")
            console.print(
                f"  [bold]{name}:[/bold] [cyan]{behind} new commit(s) available[/cyan] "
                f"(local: {local}, remote: {remote})"
            )
        else:
            console.print(f"  [bold]{name}:[/bold] [green]up to date[/green]")


def _print_update_results(console, report: dict, verbose: bool) -> None:
    """Display update results per source and validation."""
    from rich.panel import Panel  # noqa: PLC0415

    _ACTION_STYLE = {
        "cloned": ("Cloned", "bold green"),
        "pulled": ("Updated", "bold cyan"),
        "up_to_date": ("Up to date", "bold green"),
        "error": ("Error", "bold red"),
        "skipped": ("Skipped", "bold yellow"),
    }

    for src in report["sources"]:
        action = src.get("action", "skipped")
        label, style = _ACTION_STYLE.get(action, ("Unknown", "dim"))

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

        console.print(Panel(
            "\n".join(lines),
            title=f"[bold]{src['name']}[/bold]",
            expand=False,
            padding=(0, 2),
        ))

    vr = report.get("validation")
    if vr:
        if vr.get("skipped_reason"):
            console.print(f"\n[yellow]Validation skipped: {vr['skipped_reason']}[/yellow]")
        else:
            _print_validation(console, vr, verbose)
