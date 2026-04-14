"""Suspicious strings, capa capabilities, VirusTotal results."""

from datetime import datetime, timezone

from rich import box
from rich.table import Table

from ._common import console


def print_suspicious_strings(module_results: list[dict], detail_level: int) -> None:
    str_result = next(
        (r for r in module_results if r.get("module") == "string_analysis"), None
    )
    if not str_result or str_result.get("status") != "success":
        return

    matches = str_result.get("data", {}).get("suspicious_matches", [])
    if not matches:
        return

    limit = len(matches) if detail_level >= 1 else 10
    shown = matches[:limit]
    remaining = len(matches) - limit

    table = Table(
        title="[bold]Suspicious Strings[/bold]",
        box=box.ROUNDED,
        padding=(0, 1),
    )
    table.add_column("Category", style="bold yellow", no_wrap=True)
    table.add_column("String", overflow="fold")

    for m in shown:
        table.add_row(m.get("category", ""), f"[dim]{m.get('string', '')}[/dim]")

    console.print()
    console.print(table)

    if remaining > 0:
        console.print(f"  [dim](+{remaining} more — use -v to show all)[/dim]")


def print_capabilities(module_results: list[dict], detail_level: int) -> None:
    capa = next(
        (r for r in module_results if r.get("module") == "capa_analysis"), None
    )
    if not capa or capa.get("status") != "success":
        return

    capabilities = capa.get("data", {}).get("capabilities", [])
    scored = capa.get("data", {}).get("scored_categories", [])

    if not capabilities:
        return

    limit = len(capabilities) if detail_level >= 1 else 10
    shown = capabilities[:limit]
    remaining = len(capabilities) - limit

    if scored:
        cats = ", ".join(
            f"{c['category']} [red](+{c['score']})[/red]"
            for c in scored
        )
        console.print(f"\n[bold]Scored Categories:[/bold] {cats}")

    table = Table(
        title=f"[bold]Detected Capabilities[/bold] [dim]({len(capabilities)} total)[/dim]",
        box=box.SIMPLE,
        padding=(0, 1),
        show_header=False,
    )
    table.add_column("Capability", overflow="fold")

    for cap in shown:
        table.add_row(f"  {cap}")

    console.print()
    console.print(table)

    if remaining > 0:
        console.print(f"  [dim](+{remaining} more — use -v to show all)[/dim]")


def print_virustotal(module_results: list[dict], detail_level: int) -> None:
    vt = next(
        (r for r in module_results if r.get("module") == "virustotal"), None
    )
    if not vt or vt.get("status") != "success":
        return

    data = vt.get("data", {})

    table = Table(
        title="[bold]VirusTotal Results[/bold]",
        box=box.ROUNDED,
        show_header=False,
        padding=(0, 1),
    )
    table.add_column("Key", style="bold dim", no_wrap=True)
    table.add_column("Value", overflow="fold")

    if not data.get("found"):
        table.add_row("Status", "[yellow]Hash not found in VirusTotal database[/yellow]")
        table.add_row("SHA256", data.get("sha256", "N/A"))
        table.add_row("Link", data.get("permalink", ""))
        console.print()
        console.print(table)
        return

    detections = data.get("malicious", 0) + data.get("suspicious", 0)
    total = data.get("total_engines", 0)
    ratio = data.get("detection_ratio", f"{detections}/{total}")

    if detections > 10:
        ratio_style = "bold red"
    elif detections >= 1:
        ratio_style = "yellow"
    else:
        ratio_style = "green"

    table.add_row("Detection", f"[{ratio_style}]{ratio} engines[/{ratio_style}]")

    if data.get("threat_label"):
        table.add_row("Threat Label", f"[bold red]{data['threat_label']}[/bold red]")

    if detail_level >= 1:
        table.add_row("Malicious", str(data.get("malicious", 0)))
        if data.get("suspicious", 0) > 0:
            table.add_row("Suspicious", str(data["suspicious"]))
        table.add_row("Undetected", str(data.get("undetected", 0)))

    if data.get("first_seen"):
        first_seen = data["first_seen"]
        if isinstance(first_seen, (int, float)):
            try:
                first_seen = datetime.fromtimestamp(
                    first_seen, tz=timezone.utc
                ).strftime("%Y-%m-%d %H:%M UTC")
            except (OSError, ValueError):
                first_seen = str(first_seen)
        table.add_row("First Seen", str(first_seen))

    if data.get("community_score") is not None and detail_level >= 1:
        cs = data["community_score"]
        cs_style = "red" if cs > 0 else "green" if cs < 0 else "dim"
        table.add_row("Community Score", f"[{cs_style}]{cs}[/{cs_style}]")

    table.add_row("Link", data.get("permalink", ""))

    console.print()
    console.print(table)
