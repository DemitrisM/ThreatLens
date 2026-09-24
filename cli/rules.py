"""``rules`` CLI command group — YARA rule source management.

A group rather than a single verb so later passes can add ``rules list`` /
``rules validate`` without another top-level command. Rendered results go to
stdout; failures go to stderr and exit 3.

Design notes
------------
**The three modes are mutually exclusive and refused, not resolved.**
``--check`` reports without applying, ``--force`` re-clones, and
``--validate-only`` runs offline and applies nothing. Picking a winner by
precedence would mean accepting a flag and silently not honouring it,
which leaves the user believing the run did what they asked.

**A source that errored is exit 3, a rule that will not compile is not.**
The first means the rules on disk are not the ones the config asks for, so
the next scan runs against something else — a scheduled job has to be able
to see that. The second means the fetch worked and an upstream rule is
broken; ``yara_scanner`` compiles per-file and isolates it by design, so
it is a finding rather than a failure to run.

**Nothing here writes a machine format**, so the renderers use rich markup
throughout. Results go to ``out``; progress and skip notices go to ``err``.

``core.rule_updater`` returns an aggregate dict and raises nothing — the
formatting, and the decision about the exit status, both live here.
"""

import logging
from pathlib import Path

import click

from core.config_loader import ConfigNotFound, get_config

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

    # ── Mutually exclusive modes ────────────────────────────────────────
    # Refused rather than resolved by precedence: a flag that is accepted
    # and then silently ignored is worse than one that is rejected, because
    # the user believes the run did what they asked.
    if check and force:
        raise click.UsageError(
            "--check and --force are mutually exclusive: --check applies nothing"
        )
    if validate_only and (force or check):
        raise click.UsageError(
            "--validate-only runs offline and applies nothing, so it cannot be "
            "combined with --force or --check"
        )

    _setup_logging(verbosity=verbosity)
    try:
        config = get_config(config_path)
    except ConfigNotFound as exc:
        raise click.UsageError(
            f"Config file not found: {exc}"
        ) from exc
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

    # ── Exit code ───────────────────────────────────────────────────────
    # Reported after the results, so a source that did work is still shown.
    # A source that errored means the rule set on disk is not the one the
    # config asks for, and the next scan runs against whatever is there —
    # which a scheduled job must be able to detect. Broken *rules* are not
    # counted: they were fetched correctly and `yara_scanner` isolates them
    # by design, so that is a report, not a failure to run.
    failed = [s["name"] for s in report["sources"] if s.get("error")]
    if failed:
        raise RuntimeFailure(
            f"{len(failed)} of {len(report['sources'])} rule source(s) failed: "
            + ", ".join(failed)
        )


def _print_validation(vr: dict, verbose: bool) -> None:
    """Display rule validation results.

    Args:
        vr:      A ``validate_rules`` result. The caller has already
                 handled ``skipped_reason``, so the counts are present.
        verbose: True at ``-v``, which lists each broken file and its
                 compiler error. Off by default because a signature-base
                 clone routinely carries a handful of rules that need a
                 YARA module this build lacks, and a wall of them would
                 bury the counts that matter.

    Yellow rather than red for broken rules: the scan still runs, with the
    rules that did compile.
    """
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
    """Display ``--check`` results, one line per source.

    Args:
        report: The ``update_all_sources`` aggregate, gathered in check
                mode so nothing on disk has changed.

    The four states are distinguished deliberately — not cloned, errored,
    behind, up to date. "Not cloned" is the first-run case and says what
    will happen rather than reading as a fault; the commit pair is printed
    for a source that is behind so the change can be inspected upstream
    before it is pulled.
    """
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
    """Display update results per source, then validation.

    Args:
        report:  The ``update_all_sources`` aggregate.
        verbose: Passed through to :func:`_print_validation`.

    One panel per source rather than a table: the fields differ by action —
    a clone has no previous commit, a pull has a change breakdown, an error
    has neither — and a table would need a column for every field and leave
    most of them empty.

    ``action`` is read with a default and an unknown value renders as
    "Unknown" rather than raising, so a newer ``rule_updater`` reporting an
    action this renderer has not been taught cannot break the command.
    """
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
