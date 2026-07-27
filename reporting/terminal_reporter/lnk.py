"""Windows Shortcut Indicators — target, command line, padding, provenance.

``lnk_rows`` is pure: same data in, same rows out, no console side effects,
so the HTML reporter reuses it directly rather than re-implementing the
logic (the newer of the two patterns in ``html_reporter/``).

Two presentation decisions worth stating, because they are the difference
between a report that catches ZDI-CAN-25373 and one that hides it:

* **Arguments are rendered with padding made visible.** A 260-space prefix
  is the entire finding, and printing it raw shows an analyst a blank
  column. Runs of whitespace collapse to a ``<N spaces>`` marker.
* **The visible/hidden split gets its own row.** What Explorer's Properties
  dialog would show is printed next to what actually executes.
"""

from rich import box
from rich.table import Table

from reporting.theme import CLASS_SEVERITY

from ._common import LIMITS, console
from ._render import Row, more_hint, render_indicators

#: Kept at detail 0 even when quiet — these say what the shortcut is.
_ALWAYS_SHOW = frozenset({"Classification", "Target"})

#: Longest argument string shown before truncation at detail 0.
_ARG_PREVIEW = 160


def visualise_padding(text: str, *, threshold: int = 4) -> str:
    """Collapse runs of whitespace into a countable marker.

    Without this the padding evasion renders as an empty column — the
    attack works on the terminal report for exactly the reason it works
    on the Properties dialog.
    """
    if not text:
        return ""

    out: list[str] = []
    run_char = ""
    run_len = 0

    def flush() -> None:
        if not run_len:
            return
        if run_len >= threshold:
            name = {
                " ": "spaces", "\t": "tabs", "\n": "newlines", "\r": "CRs",
                "\v": "VT", "\f": "FF", "\x11": "DC1", "\x12": "DC2",
                "\x13": "DC3",
            }.get(run_char, "whitespace")
            out.append(f"<{run_len} {name}>")
        else:
            out.append(run_char * run_len)

    for char in text:
        if char.isspace() or char in "\x11\x12\x13":
            if char == run_char:
                run_len += 1
            else:
                flush()
                run_char, run_len = char, 1
        else:
            flush()
            run_char, run_len = "", 0
            out.append(char)
    flush()
    return "".join(out)


def lnk_rows(data: dict, detail_level: int = 0) -> list[Row]:
    """Build the shortcut indicator rows from an ``lnk_analysis`` data dict."""
    if not data or data.get("target") is None:
        return []

    rows: list[Row] = []
    classification = data.get("classification") or "CLEAN"
    rows.append(
        Row("Classification", classification,
            CLASS_SEVERITY.get(classification, "info"))
    )

    target = data.get("target") or "(none)"
    rows.append(Row("Target", target, "bad" if data.get("is_lolbin") else "info"))

    if data.get("target_disagreement"):
        rows.append(
            Row("Target sources", "candidate paths disagree — displayed target "
                                  "may not be what runs", "bad")
        )

    rows.extend(_argument_rows(data, detail_level))

    if data.get("working_dir"):
        rows.append(Row("Working dir", data["working_dir"], "info"))
    if data.get("name_string"):
        rows.append(Row("Description", data["name_string"], "info"))

    if data.get("double_extension"):
        rows.append(Row("Double extension", data["double_extension"], "bad"))

    rows.extend(_icon_rows(data))

    depth = data.get("traversal_depth") or 0
    if depth:
        severity = "bad" if depth > 4 else "warn"
        rows.append(
            Row("Relative path", f"{data.get('relative_path', '')} "
                                 f"({depth} traversal levels)", severity)
        )

    rows.extend(_payload_rows(data))
    rows.extend(_provenance_rows(data))

    for pattern in data.get("matched_patterns") or []:
        rows.append(Row("Pattern", pattern, "warn"))

    # Show the working before the result: an IOC that only exists after
    # four decode layers needs its provenance, or an analyst cannot tell
    # it from a parser hallucination.
    for chain in data.get("deobfuscation_chains") or []:
        rows.append(Row("Deobfuscation", f"layers undone: {chain}", "warn"))
    for ioc in data.get("deobfuscated_iocs") or []:
        rows.append(Row("Recovered IOC", ioc, "bad"))

    # Anything already shown as a recovered IOC is not repeated here.
    recovered = {i.lower() for i in data.get("deobfuscated_iocs") or []}
    plain = [u for u in (data.get("urls") or []) if u.lower() not in recovered]
    for url in plain[:LIMITS.get("lnk_urls", 10)]:
        severity = "bad" if any(
            host in url.lower() for host in data.get("suspicious_hosts") or []
        ) else "warn"
        rows.append(Row("URL", url, severity))

    for rule in data.get("fired_rules") or []:
        rows.append(Row("Fired rule", rule, "bad"))

    if detail_level >= 1:
        rows.extend(_verbose_rows(data))

    return rows


def _argument_rows(data: dict, detail_level: int) -> list[Row]:
    """The command line, with padding made visible and the split explained."""
    rows: list[Row] = []
    arguments = data.get("arguments") or ""
    if not arguments:
        return rows

    padding = data.get("arg_padding") or {}
    rendered = visualise_padding(arguments)
    if detail_level < 1 and len(rendered) > _ARG_PREVIEW:
        shown = f"{rendered[:_ARG_PREVIEW]}… {more_hint(1)}"
    else:
        shown = rendered
    rows.append(Row("Arguments", shown, "bad" if padding.get("tier") == "strong" else "warn"))

    length = data.get("arguments_length") or 0
    if length > 260:
        rows.append(
            Row("Argument length", f"{length} characters "
                                   f"({data.get('argument_count', 0)} tokens)", "warn")
        )

    if padding.get("zdi_can_25373"):
        rows.append(
            Row(
                "Padding evasion",
                "ZDI-CAN-25373 / CVE-2025-9491 — the first 260 characters are "
                "whitespace, so Explorer's Properties dialog shows an empty "
                "command while the real one executes",
                "bad",
            )
        )
    elif padding.get("tier") in ("strong", "medium"):
        rows.append(
            Row("Padding", f"{padding.get('max_run', 0)} consecutive whitespace "
                           f"characters ({padding.get('tier')})", "warn")
        )

    if padding.get("exotic_chars"):
        rows.append(
            Row("Control chars", ", ".join(padding["exotic_chars"])
                + " — non-printing padding", "bad")
        )
    return rows


def _icon_rows(data: dict) -> list[Row]:
    rows: list[Row] = []
    icon = data.get("icon_location") or ""
    if data.get("icon_masquerade"):
        rows.append(
            Row("Icon masquerade", f"{icon} — document icon over an executable "
                                   "target (T1027.012)", "bad")
        )
    elif icon:
        rows.append(Row("Icon", icon, "info"))
    if data.get("remote_icon"):
        rows.append(
            Row("Remote icon", "icon fetched over the network — payload "
                               "download and NTLM coercion primitive", "bad")
        )
    return rows


def _payload_rows(data: dict) -> list[Row]:
    """Appended data — nothing in the format puts bytes past the terminator."""
    rows: list[Row] = []
    overlay = data.get("overlay")
    if overlay:
        rows.append(
            Row(
                "Overlay",
                f"{overlay.get('description', 'appended data')} — "
                f"{overlay.get('size', 0)} bytes at offset "
                f"0x{overlay.get('offset', 0):X}, entropy "
                f"{overlay.get('entropy', 0)}",
                "bad" if overlay.get("kind") != "unknown" else "warn",
            )
        )
    entropy = data.get("entropy") or 0
    if entropy >= 6.5:
        rows.append(Row("Entropy", f"{entropy} — compressed or encrypted content", "warn"))
    return rows


def _provenance_rows(data: dict) -> list[Row]:
    """TrackerDataBlock attribution — the pivot IOCs."""
    rows: list[Row] = []
    if data.get("machine_id"):
        rows.append(Row("Build machine", data["machine_id"], "warn"))
    mac = data.get("mac_address")
    if mac:
        vendor = data.get("mac_vendor")
        rows.append(
            Row("Build MAC", f"{mac}" + (f"  ({vendor} virtual NIC)" if vendor else ""),
                "warn" if vendor else "info")
        )
    if data.get("drive_serial"):
        rows.append(Row("Volume serial", data["drive_serial"], "info"))
    if data.get("net_name"):
        rows.append(Row("Network path", data["net_name"], "bad"))
    return rows


def _verbose_rows(data: dict) -> list[Row]:
    """Structural detail, shown from -v onward."""
    rows: list[Row] = []
    if data.get("link_flags"):
        rows.append(Row("Link flags", ", ".join(data["link_flags"]), "info"))
    if data.get("file_attributes"):
        rows.append(Row("File attributes", ", ".join(data["file_attributes"]), "info"))
    if data.get("extra_blocks"):
        rows.append(Row("Extra blocks", ", ".join(data["extra_blocks"]), "info"))
    if data.get("show_command"):
        rows.append(Row("Show command", data["show_command"], "info"))
    for label, key in (
        ("Created", "creation_time"), ("Accessed", "access_time"),
        ("Modified", "write_time"),
    ):
        if data.get(key):
            rows.append(Row(label, data[key], "info"))
    if data.get("target_file_size") is not None:
        rows.append(Row("Target size", f"{data['target_file_size']} bytes", "info"))
    if data.get("env_target"):
        rows.append(Row("Environment path", data["env_target"], "info"))
    if data.get("droid_birth_differs"):
        rows.append(
            Row("Droid", "birth and current IDs differ — target was moved or "
                         "copied after creation", "info")
        )
    for anomaly in data.get("anomalies") or []:
        rows.append(Row("Anomaly", anomaly, "warn"))
    for flag in data.get("indicator_flags") or []:
        rows.append(Row("Flag", flag, "info"))
    return rows


# ---------------------------------------------------------------------------
# Section printer
# ---------------------------------------------------------------------------

def print_lnk_indicators(module_results: list[dict], detail_level: int = 0) -> None:
    """Windows Shortcut Indicators section, plus the LECmd-depth tables."""
    result = next(
        (r for r in module_results if r.get("module") == "lnk_analysis"), None
    )
    if not result or result.get("status") != "success":
        return
    data = result.get("data") or {}
    if not data or data.get("target") is None:
        return

    render_indicators(
        "Windows Shortcut Indicators",
        lnk_rows(data, detail_level),
        detail_level,
        always_show=_ALWAYS_SHOW,
        console=console,
    )
    if detail_level >= 1:
        _shell_items(data)
        _property_store(data)


def _shell_items(data: dict) -> None:
    """The decoded IDList, with NTFS file references.

    The MFT entry/sequence pair is what ties this shortcut to one specific
    file on one specific volume. LECmd surfaces it; Python LNK tooling
    generally does not.
    """
    items = data.get("shell_items") or []
    if not items:
        return

    limit = LIMITS.get("lnk_shell_items", 20)
    shown = items[:limit]

    table = Table(
        title="[bold]Shell Items (IDList)[/bold]",
        box=box.ROUNDED,
        padding=(0, 1),
    )
    table.add_column("#", justify="right", no_wrap=True)
    table.add_column("Type", no_wrap=True)
    table.add_column("Name", overflow="fold")
    table.add_column("MFT entry", justify="right", no_wrap=True)
    table.add_column("Seq", justify="right", no_wrap=True)
    table.add_column("Modified", no_wrap=True)

    for index, item in enumerate(shown):
        entry = item.get("mft_entry")
        table.add_row(
            str(index),
            str(item.get("type_name") or "-"),
            str(item.get("long_name") or item.get("name") or "-"),
            str(entry) if entry is not None else "-",
            str(item.get("mft_sequence")) if item.get("mft_sequence") is not None else "-",
            str(item.get("modified") or "-"),
        )

    console.print()
    console.print(table)
    hidden = len(items) - len(shown)
    if hidden > 0:
        console.print(f"  [dim]{more_hint(hidden)}[/dim]")


def _property_store(data: dict) -> None:
    """PropertyStoreDataBlock — original filename, parsing path, owner SID."""
    properties = data.get("property_store") or []
    if not properties:
        return

    table = Table(
        title="[bold]Property Store[/bold]",
        box=box.ROUNDED,
        padding=(0, 1),
    )
    table.add_column("Property", no_wrap=True)
    table.add_column("Value", overflow="fold")

    for prop in properties[:LIMITS.get("lnk_properties", 30)]:
        value = str(prop.get("value") or "")
        if not value:
            continue
        table.add_row(str(prop.get("name") or "-"), value)

    if table.row_count == 0:
        return
    console.print()
    console.print(table)


__all__ = ["lnk_rows", "print_lnk_indicators", "visualise_padding"]
