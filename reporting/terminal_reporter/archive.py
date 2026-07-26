"""Archive Indicators — summary rows, dangerous members, embedded
executables, and the nested-archive tree.

``archive_rows`` is pure. It replaces a hand-space-padded ``Panel`` whose
labels were aligned to column 17 with markup baked into the strings.
"""

from rich import box
from rich.table import Table

from reporting.shared import human_size
from reporting.theme import CLASS_SEVERITY, rich_style

from ._common import LIMITS, console
from ._render import Row, more_hint, render_hash_list, render_indicators

#: Kept at detail 0 even though they are ``info`` — they say what was parsed.
_ALWAYS_SHOW = frozenset({"Format", "Classification"})


def archive_rows(data: dict, detail_level: int = 0) -> list[Row]:
    """Build the archive indicator rows from an ``archive_analysis`` data dict."""
    if not data or not data.get("detected_format"):
        return []

    rows: list[Row] = []
    classification = data.get("classification") or "CLEAN"

    rows.append(Row("Format", (data.get("detected_format") or "?").upper(), "info"))
    rows.append(
        Row("Classification", classification, CLASS_SEVERITY.get(classification, "info"))
    )
    rows.append(Row("Entries", str(data.get("entry_count", 0)), "info"))
    rows.append(
        Row("Total size", human_size(data.get("total_uncompressed_size", 0)), "info")
    )

    enc = data.get("encryption") or {}
    if enc.get("header_encrypted"):
        rows.append(Row("Encryption", "header-encrypted", "bad"))
    elif enc.get("is_encrypted"):
        rows.append(Row("Encryption", "per-file encrypted", "warn"))

    bomb = data.get("bomb_guard") or {}
    if bomb.get("triggered"):
        reasons = ", ".join(bomb.get("reasons") or [])
        rows.append(Row("Bomb guard", f"TRIGGERED — {reasons}", "bad"))

    sfx = data.get("sfx") or {}
    if sfx.get("is_sfx"):
        rows.append(
            Row(
                "SFX payload",
                f"{sfx.get('embedded_format')} @ offset {sfx.get('offset')}",
                "bad",
            )
        )

    if data.get("ace_detected"):
        rows.append(Row("ACE archive", "detected — extraction refused", "bad"))
    if data.get("recursion_depth_reached"):
        rows.append(Row("Recursion", "depth cap hit", "warn"))

    for rule in data.get("fired_rules") or []:
        rows.append(Row("Fired rule", rule, "bad"))

    if detail_level >= 1:
        for flag in data.get("indicator_flags") or []:
            rows.append(Row("Flag", flag, "info"))

    for err in data.get("handler_errors") or []:
        rows.append(Row("Handler error", str(err), "warn"))

    return rows


def print_archive_indicators(module_results: list[dict], detail_level: int = 0) -> None:
    """Archive Structure Indicators section."""
    arc = next(
        (r for r in module_results if r.get("module") == "archive_analysis"), None
    )
    if not arc or arc.get("status") != "success":
        return
    data = arc.get("data") or {}
    if not data or not data.get("detected_format"):
        return

    render_indicators(
        "Archive Structure Indicators",
        archive_rows(data, detail_level),
        detail_level,
        always_show=_ALWAYS_SHOW,
        console=console,
    )
    _dangerous_members_table(data, detail_level)
    _embedded_execs(data, detail_level)
    _nested_tree(data)


def _dangerous_members_table(data: dict, detail_level: int) -> None:
    """Members whose extension makes them executable or otherwise risky."""
    members = data.get("dangerous_members") or []
    if not members:
        return

    limit = None if detail_level >= 1 else LIMITS["archive_members"]
    shown = members if limit is None else members[:limit]
    hidden = len(members) - len(shown)

    table = Table(
        title="[bold]Dangerous Members[/bold]",
        box=box.ROUNDED,
        padding=(0, 1),
    )
    table.add_column("Name", overflow="fold")
    table.add_column("Ext", no_wrap=True)
    table.add_column("Size", justify="right", no_wrap=True)
    for m in shown:
        table.add_row(
            str(m.get("name", "")),
            str(m.get("extension", "")),
            human_size(m.get("size") or 0),
        )

    console.print()
    console.print(table)
    if hidden:
        console.print(f"  [dim]{more_hint(hidden)}[/dim]")


def _embedded_execs(data: dict, detail_level: int) -> None:
    """Embedded PE/ELF members, each SHA256 on its own unbroken line."""
    execs = data.get("embedded_executables") or []
    entries = [
        (
            str(e.get("name", "")),
            f"{e.get('type', '')}  {human_size(e.get('size') or 0)}".strip(),
            e.get("sha256") or "",
        )
        for e in execs
    ]
    render_hash_list(
        "Embedded Executables",
        entries,
        limit=None if detail_level >= 1 else LIMITS["archive_execs"],
        console=console,
    )


def _nested_tree(data: dict) -> None:
    """Child archives found inside this one."""
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
        # Colour by classification token (MALICIOUS -> "bold red"), not by
        # severity — "bad" is not a rich style.
        style = rich_style(classification.lower()) or "white"
        score = child.get("score_delta")
        table.add_row(
            str(name),
            fmt,
            f"[{style}]{classification}[/{style}]",
            str(score) if score is not None else "-",
        )

    console.print()
    console.print(table)
