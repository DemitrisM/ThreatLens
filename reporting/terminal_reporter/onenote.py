"""OneNote Indicators panels — summary, fired rules, embedded blobs,
and nested-pipeline results when ``--recurse-onenote`` is on."""

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

_KIND_COLOURS = {
    "pe": "red",
    "elf": "red",
    "macho": "red",
    "msi": "red",
    "lnk": "yellow",
    "hta": "red",
    "script": "yellow",
    "chm": "yellow",
    "ole": "cyan",
    "image": "dim",
    "other": "dim",
}


def print_onenote_indicators(module_results: list[dict], detail_level: int = 0) -> None:
    on = next(
        (r for r in module_results if r.get("module") == "onenote_analysis"),
        None,
    )
    if not on or on.get("status") != "success":
        return
    data = on.get("data") or {}
    if not data or data.get("blob_count") is None:
        return

    _summary_panel(data)
    _fired_rules_table(data, detail_level)
    _blobs_table(data, detail_level)
    _nested_tree(data)


def _summary_panel(data: dict) -> None:
    classification = data.get("classification") or "CLEAN"
    colour = _CLASS_COLOURS.get(classification, "white")

    lines: list[str] = []
    lines.append(f"Classification:  [{colour}]{classification}[/{colour}]")
    lines.append(f"Blob count:      {data.get('blob_count', 0)}")

    execs = data.get("embedded_executables") or []
    if execs:
        lines.append(
            f"VT forward-lookup: {len(execs)} embedded executable(s) queued"
        )

    if data.get("encrypted_section"):
        lines.append(
            "Encrypted section: [yellow]password-protected — content hidden[/yellow]"
        )

    if not data.get("onestore_header_present"):
        lines.append(
            "Header:          [yellow]ONESTORE GUID absent — parsed by extension[/yellow]"
        )

    console.print()
    console.print(
        Panel(
            "\n".join(lines),
            title="[bold]OneNote Indicators[/bold]",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(0, 1),
        )
    )


def _fired_rules_table(data: dict, detail_level: int) -> None:
    fired = data.get("fired_rules") or []
    flags = data.get("indicator_flags") or []
    if not fired and not flags:
        return

    table = Table(
        title="[bold]OneNote Fired Rules[/bold]",
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


def _blobs_table(data: dict, detail_level: int) -> None:
    blobs = data.get("blobs") or []
    if not blobs:
        return

    interesting = [b for b in blobs if b.get("kind") not in {"image", "other"}]
    rows = interesting if (interesting and detail_level < 1) else blobs
    limit = 20 if detail_level < 1 else len(rows)

    table = Table(
        title="[bold]Embedded Blobs[/bold]",
        box=box.ROUNDED,
        padding=(0, 1),
    )
    table.add_column("Offset", no_wrap=True)
    table.add_column("Kind", no_wrap=True)
    table.add_column("Size", justify="right", no_wrap=True)
    table.add_column("Label", overflow="fold")
    table.add_column("SHA256", overflow="fold")

    for b in rows[:limit]:
        kind = b.get("kind", "other")
        colour = _KIND_COLOURS.get(kind, "white")
        sha = b.get("sha256") or ""
        table.add_row(
            f"0x{b.get('offset', 0):08x}",
            f"[{colour}]{kind}[/{colour}]",
            human_size(b.get("size") or 0),
            str(b.get("label", "")),
            f"{sha[:16]}…" if sha else "",
        )

    truncated = len(rows) - limit
    if truncated > 0:
        table.add_section()
        table.add_row("", "", "", f"[dim]+{truncated} more — use -v to expand[/dim]", "")

    console.print()
    console.print(table)


def _nested_tree(data: dict) -> None:
    nested = data.get("nested") or []
    if not nested:
        return

    table = Table(
        title="[bold]OneNote Nested Pipeline Results[/bold]",
        box=box.ROUNDED,
        padding=(0, 1),
    )
    table.add_column("Source offset", no_wrap=True)
    table.add_column("Kind", no_wrap=True)
    table.add_column("Child score", justify="right", no_wrap=True)
    table.add_column("Band", no_wrap=True)

    for child in nested:
        report = child.get("report") or {}
        scoring = report.get("scoring") or {}
        score = scoring.get("final_score")
        band = scoring.get("risk_band") or "-"
        colour = _CLASS_COLOURS.get(band.upper(), "white") if band != "-" else "white"
        offset = child.get("source_offset")
        offset_str = f"0x{offset:08x}" if isinstance(offset, int) else "-"
        table.add_row(
            offset_str,
            str(child.get("kind", "")),
            str(score) if score is not None else "-",
            f"[{colour}]{band}[/{colour}]",
        )

    console.print()
    console.print(table)
