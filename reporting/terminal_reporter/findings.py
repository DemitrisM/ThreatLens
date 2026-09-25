"""Suspicious strings, capa capabilities, VirusTotal results."""

from datetime import datetime, timezone

from rich import box
from rich.table import Table

from reporting.theme import rich_style

from ._common import LIMITS, console


def print_suspicious_strings(module_results: list[dict], detail_level: int) -> None:
    str_result = next(
        (r for r in module_results if r.get("module") == "string_analysis"), None
    )
    if not str_result or str_result.get("status") != "success":
        return

    data = str_result.get("data", {}) or {}
    _print_extraction_note(data, detail_level)

    matches = data.get("suspicious_matches", [])
    if not matches:
        return

    limit = len(matches) if detail_level >= 1 else LIMITS["suspicious_strings"]
    shown = matches[:limit]
    remaining = len(matches) - limit

    table = Table(
        title="[bold]Suspicious Strings[/bold]",
        box=box.ROUNDED,
        padding=(0, 1),
    )
    table.add_column("Category", style=rich_style("medium"), no_wrap=True)
    table.add_column("String", overflow="fold")

    for m in shown:
        table.add_row(m.get("category", ""), f"[dim]{m.get('string', '')}[/dim]")

    console.print()
    console.print(table)

    if remaining > 0:
        console.print(f"  [dim](+{remaining} more — use -v to show all)[/dim]")


def _print_extraction_note(data: dict, detail_level: int) -> None:
    """Say how the strings were obtained, when that changes their meaning.

    Args:
        data:         ``string_analysis`` module data.
        detail_level: 0 prints only what is load-bearing; 1 and above
                      always name the extractor.

    Returns:
        None, and prints nothing for the common quiet case — a clean file
        extracted with ``--only static`` has nothing to say, and a line on
        every scan announcing that nothing happened is noise.

    Two cases are printed regardless of detail level:

    * A **downgraded** run. If emulation timed out and the retry fell back
      to static strings, the report shows no decoded or stack strings —
      which reads as "this sample does not obfuscate its strings" when
      what actually happened is that ThreatLens stopped looking. That is a
      skip rendering as a finding, the same defect class as the lnk and
      onenote size-cap bypasses.
    * **Hidden strings that scored.** Decoded, stack and tight counts earn
      the +10 obfuscation bonus, so the report has to show the evidence
      the score was built on.

    No colour literals here: ``[dim]`` and ``[warn]`` are a weight and a
    palette token, per design rule 8.
    """
    if data.get("source") != "floss":
        return

    hidden = sum(
        data.get(key, 0) or 0
        for key in ("floss_decoded_strings", "floss_stack_strings",
                    "floss_tight_strings")
    )
    timed_out = bool(data.get("floss_emulation_timed_out"))
    if not (hidden or timed_out or detail_level >= 1):
        return

    if timed_out:
        console.print()
        console.print(
            "  [warn]FLOSS emulation timed out — static strings only[/warn]"
        )
        return

    parts = [
        f"{data.get(key, 0)} {label}"
        for key, label in (("floss_decoded_strings", "decoded"),
                           ("floss_stack_strings", "stack"),
                           ("floss_tight_strings", "tight"))
        if data.get(key, 0)
    ]
    console.print()
    if parts:
        console.print(
            f"  [dim]FLOSS recovered hidden strings: {', '.join(parts)}[/dim]"
        )
    else:
        mode = data.get("floss_mode", "static")
        hint = " — use -p deep to emulate" if mode == "static" else ""
        console.print(f"  [dim]Strings extracted by FLOSS ({mode}){hint}[/dim]")


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

    limit = len(capabilities) if detail_level >= 1 else LIMITS["capabilities"]
    shown = capabilities[:limit]
    remaining = len(capabilities) - limit

    if scored:
        cats = ", ".join(
            f"{c['category']} [bad](+{c['score']})[/bad]"
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


def _print_permalink(data: dict) -> None:
    """Print the VirusTotal link below the table, unbroken.

    Args:
        data: The ``virustotal`` module's ``data`` dict. A missing or
              empty ``permalink`` prints nothing.

    The permalink is 100 characters — a 36-character prefix plus the
    SHA256 — so it does not fit inside a bordered table at any width the
    report supports, and the table's ``overflow="fold"`` broke it across
    two rows. That defeats double-click copy and a terminal's own link
    detection, on the one string in the report whose entire purpose is to
    be opened.

    ``soft_wrap`` leaves it as a single logical line and lets the
    terminal wrap it, which keeps a copy intact. It is the same rule the
    SHA256 already has, applied to the string that contains one.
    """
    permalink = data.get("permalink")
    if not permalink:
        return
    console.print(f"  [dim]{permalink}[/dim]", soft_wrap=True)


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
        table.add_row("Status", "[warn]Hash not found in VirusTotal database[/warn]")
        table.add_row("SHA256", data.get("sha256", "N/A"))
        console.print()
        console.print(table)
        _print_permalink(data)
        return

    detections = data.get("malicious", 0) + data.get("suspicious", 0)
    total = data.get("total_engines", 0)
    ratio = data.get("detection_ratio", f"{detections}/{total}")

    if detections > 10:
        ratio_style = rich_style("critical")
    elif detections >= 1:
        ratio_style = rich_style("warn")
    else:
        ratio_style = rich_style("success")

    table.add_row("Detection", f"[{ratio_style}]{ratio} engines[/{ratio_style}]")

    if data.get("threat_label"):
        table.add_row("Threat Label", f"[critical]{data['threat_label']}[/critical]")

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

    console.print()
    console.print(table)
    _print_permalink(data)
