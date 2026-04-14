"""MITRE ATT&CK, IOC, and per-module timing tables."""

from rich import box
from rich.table import Table

from ._common import STATUS_COLOURS, console


_IOC_TYPE_STYLES = {
    "ipv4":         ("IP Address",   "red"),
    "url":          ("URL",          "yellow"),
    "domain":       ("Domain",       "cyan"),
    "registry_key": ("Registry Key", "magenta"),
    "email":        ("Email",        "blue"),
    "windows_path": ("File Path",    "dim"),
}


def print_attack_table(module_results: list[dict], detail_level: int) -> None:
    """MITRE ATT&CK mappings from capa analysis."""
    capa = next(
        (r for r in module_results if r.get("module") == "capa_analysis"), None
    )
    if not capa or capa.get("status") != "success":
        return

    mappings = capa.get("data", {}).get("attack_mappings", [])
    if not mappings:
        return

    mappings_sorted = sorted(
        mappings, key=lambda m: (m.get("tactic", ""), m.get("technique_id", ""))
    )

    limit = len(mappings_sorted) if detail_level >= 1 else 10
    shown = mappings_sorted[:limit]
    remaining = len(mappings_sorted) - limit

    table = Table(
        title="[bold]MITRE ATT&CK Mappings[/bold]",
        box=box.ROUNDED,
        padding=(0, 1),
    )
    table.add_column("Technique", style="bold cyan", no_wrap=True)
    table.add_column("Name", overflow="fold")
    table.add_column("Tactic", style="dim", overflow="fold")
    table.add_column("Capability", overflow="fold")

    current_tactic = None
    for m in shown:
        tactic = m.get("tactic", "Unknown")
        tactic_display = tactic if tactic != current_tactic else ""
        current_tactic = tactic

        table.add_row(
            m.get("technique_id", ""),
            m.get("technique_name", ""),
            tactic_display,
            f"[dim]{m.get('capability', '')}[/dim]",
        )

    console.print()
    console.print(table)

    if remaining > 0:
        console.print(f"  [dim](+{remaining} more — use -v to show all)[/dim]")


def print_ioc_table(module_results: list[dict], detail_level: int) -> None:
    """Extracted IOCs grouped by type."""
    ioc_result = next(
        (r for r in module_results if r.get("module") == "ioc_extractor"), None
    )
    if not ioc_result or ioc_result.get("status") != "success":
        return

    iocs = ioc_result.get("data", {}).get("iocs", {})
    total = ioc_result.get("data", {}).get("total_iocs", 0)
    if total == 0:
        return

    table = Table(
        title="[bold]Indicators of Compromise (IOCs)[/bold]",
        box=box.ROUNDED,
        padding=(0, 1),
    )
    table.add_column("Type", style="bold", no_wrap=True)
    table.add_column("Value", overflow="fold")

    limit = None if detail_level >= 1 else 5

    for ioc_type, values in iocs.items():
        if not values:
            continue

        label, colour = _IOC_TYPE_STYLES.get(ioc_type, (ioc_type, "white"))
        shown = values if limit is None else values[:limit]
        remaining = len(values) - len(shown)

        for val in shown:
            table.add_row(f"[{colour}]{label}[/{colour}]", val)
        if remaining > 0:
            table.add_row("", f"[dim](+{remaining} more — use -v to show all)[/dim]")

    console.print()
    console.print(table)


def print_timing_table(module_results: list[dict], timing: dict) -> None:
    """Per-module timing breakdown (shown at -v and above)."""
    timed = [r for r in module_results if "elapsed_seconds" in r]
    if not timed:
        return

    timed.sort(key=lambda r: r.get("elapsed_seconds", 0), reverse=True)

    table = Table(
        title="[bold]Module Timing[/bold]",
        box=box.SIMPLE,
        padding=(0, 1),
    )
    table.add_column("Module", style="bold", no_wrap=True)
    table.add_column("Elapsed", justify="right", no_wrap=True)
    table.add_column("Status", no_wrap=True)

    for r in timed:
        elapsed = r.get("elapsed_seconds", 0)
        status = r.get("status", "unknown")
        name = r.get("module", "unknown")

        if elapsed > 60:
            time_str = f"[red]{elapsed:.1f}s[/red]"
        elif elapsed > 10:
            time_str = f"[yellow]{elapsed:.1f}s[/yellow]"
        else:
            time_str = f"[dim]{elapsed:.1f}s[/dim]"

        status_colour = STATUS_COLOURS.get(status, "white")
        table.add_row(name, time_str, f"[{status_colour}]{status}[/{status_colour}]")

    total = timing.get("elapsed_seconds", 0)
    table.add_section()
    table.add_row("[bold]Total[/bold]", f"[bold]{total:.1f}s[/bold]", "")

    console.print()
    console.print(table)
