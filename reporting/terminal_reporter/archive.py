"""Archive Indicators panels — summary, flags, dangerous members,
embedded executables, and nested-archive tree."""

from rich import box
from rich.panel import Panel
from rich.table import Table

from reporting.shared import human_size

from ._common import console


_CLASS_COLOURS = {
    "MALICIOUS": "bold red",
    "SUSPICIOUS": "bold yellow",
    "INFORMATIONAL": "cyan",
    "CLEAN": "green",
}


def print_archive_indicators(module_results: list[dict], detail_level: int = 0) -> None:
    arc = next(
        (r for r in module_results if r.get("module") == "archive_analysis"),
        None,
    )
    if not arc or arc.get("status") != "success":
        return
    data = arc.get("data") or {}
    if not data or not data.get("detected_format"):
        return

    _summary_panel(data)
    _flags_table(data, detail_level)
    _dangerous_members_table(data)
    _embedded_execs_table(data)
    _nested_tree(data)


def _summary_panel(data: dict) -> None:
    fmt = (data.get("detected_format") or "?").upper()
    classification = data.get("classification") or "CLEAN"
    colour = _CLASS_COLOURS.get(classification, "white")

    lines: list[str] = []
    lines.append(f"Format:          [bold]{fmt}[/bold]")
    lines.append(f"Classification:  [{colour}]{classification}[/{colour}]")
    lines.append(f"Entries:         {data.get('entry_count', 0)}")
    lines.append(
        f"Total size:      {human_size(data.get('total_uncompressed_size', 0))}"
    )
    enc = data.get("encryption") or {}
    if enc.get("header_encrypted"):
        lines.append("Encryption:      [red]header-encrypted[/red]")
    elif enc.get("is_encrypted"):
        lines.append("Encryption:      [yellow]per-file encrypted[/yellow]")
    bomb = data.get("bomb_guard") or {}
    if bomb.get("triggered"):
        reasons = ", ".join(bomb.get("reasons") or [])
        lines.append(f"Bomb guard:      [red]TRIGGERED[/red] ({reasons})")
    sfx = data.get("sfx") or {}
    if sfx.get("is_sfx"):
        lines.append(
            f"SFX payload:     [red]{sfx.get('embedded_format')} @ offset {sfx.get('offset')}[/red]"
        )
    if data.get("ace_detected"):
        lines.append("ACE archive:     [red]detected — extraction refused[/red]")
    if data.get("recursion_depth_reached"):
        lines.append("Recursion:       depth cap hit")

    console.print()
    console.print(
        Panel(
            "\n".join(lines),
            title="[bold]Archive Indicators[/bold]",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(0, 1),
        )
    )


def _flags_table(data: dict, detail_level: int) -> None:
    fired = data.get("fired_rules") or []
    flags = data.get("indicator_flags") or []
    if not fired and not flags:
        return

    table = Table(
        title="[bold]Archive Fired Rules[/bold]",
        box=box.ROUNDED,
        padding=(0, 1),
    )
    table.add_column("Rule", overflow="fold")

    if fired:
        for rule in fired:
            table.add_row(rule)
    if detail_level >= 1 and flags:
        table.add_section()
        table.add_row(f"[dim]Flags: {', '.join(flags)}[/dim]")

    console.print()
    console.print(table)


def _dangerous_members_table(data: dict) -> None:
    members = data.get("dangerous_members") or []
    if not members:
        return
    table = Table(
        title="[bold]Dangerous Members[/bold]",
        box=box.ROUNDED,
        padding=(0, 1),
    )
    table.add_column("Name", overflow="fold")
    table.add_column("Ext", no_wrap=True)
    table.add_column("Size", justify="right", no_wrap=True)
    for m in members[:20]:
        table.add_row(
            str(m.get("name", "")),
            str(m.get("extension", "")),
            human_size(m.get("size") or 0),
        )
    console.print()
    console.print(table)


def _embedded_execs_table(data: dict) -> None:
    execs = data.get("embedded_executables") or []
    if not execs:
        return
    table = Table(
        title="[bold]Embedded Executables[/bold]",
        box=box.ROUNDED,
        padding=(0, 1),
    )
    table.add_column("Name", overflow="fold")
    table.add_column("Type", no_wrap=True)
    table.add_column("Size", justify="right", no_wrap=True)
    table.add_column("SHA256", overflow="fold")
    for e in execs[:10]:
        sha = e.get("sha256") or ""
        sha_display = f"{sha[:16]}…" if sha else ""
        table.add_row(
            str(e.get("name", "")),
            str(e.get("type", "")),
            human_size(e.get("size") or 0),
            sha_display,
        )
    console.print()
    console.print(table)


def _nested_tree(data: dict) -> None:
    nested = data.get("nested") or []
    if not nested:
        return

    table = Table(
        title="[bold]Nested Archives[/bold]",
        box=box.ROUNDED,
        padding=(0, 1),
    )
    table.add_column("Member", overflow="fold")
    table.add_column("Format", no_wrap=True)
    table.add_column("Classification", no_wrap=True)
    table.add_column("Score", justify="right", no_wrap=True)

    for child in nested:
        name = child.get("nested_member_name") or child.get("name") or "?"
        cdata = child.get("data") or child.get("report") or {}
        fmt = (cdata.get("detected_format") or "").upper()
        classification = cdata.get("classification") or "-"
        colour = _CLASS_COLOURS.get(classification, "white")
        score = child.get("score_delta")
        table.add_row(
            str(name),
            fmt,
            f"[{colour}]{classification}[/{colour}]",
            str(score) if score is not None else "-",
        )

    console.print()
    console.print(table)
