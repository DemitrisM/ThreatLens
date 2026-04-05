"""Terminal report generator using rich.

Displays colour-coded threat scores, formatted tables for IOCs and
MITRE ATT&CK mappings, progress bars during analysis, and a
human-readable score breakdown in the terminal.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

logger = logging.getLogger(__name__)

console = Console()

# Risk band → rich colour name
_BAND_COLOURS = {
    "CRITICAL": "bold red",
    "HIGH": "bold orange1",
    "MEDIUM": "bold yellow",
    "LOW": "bold green",
}

# Module status → colour
_STATUS_COLOURS = {
    "success": "green",
    "skipped": "dim yellow",
    "error": "red",
}


def print_terminal_report(report: dict, *, detail_level: int = 0) -> None:
    """Render a complete threat report to the terminal using rich.

    Args:
        report:       Complete report dict returned by ``run_pipeline()``.
        detail_level: 0 = summary, 1 = expanded (-v), 2 = full (--debug).
    """
    scoring = report.get("scoring", {})
    module_results = report.get("module_results", [])
    timing = report.get("timing", {})
    file_path = report.get("file", "unknown")

    _print_header()
    _print_file_info(module_results, file_path)
    _print_score_banner(scoring, module_results)
    _print_module_table(module_results, file_path)

    if scoring.get("breakdown"):
        _print_score_breakdown(scoring["breakdown"])

    # ── Detail-dependent sections ──
    _print_attack_table(module_results, detail_level)
    _print_ioc_table(module_results, detail_level)
    _print_suspicious_strings(module_results, detail_level)
    _print_capabilities(module_results, detail_level)

    if detail_level >= 1:
        _print_timing_table(module_results, timing)

    _print_recommendations(module_results, scoring, file_path)
    _print_footer(timing)


# ---------------------------------------------------------------------------
# Header / File Info / Score
# ---------------------------------------------------------------------------


def _print_header() -> None:
    title = Text("ThreatLens", style="bold cyan")
    subtitle = Text("  Static Malware Analysis  ", style="dim")
    console.print()
    console.print(Panel(title + subtitle, style="cyan", padding=(0, 2)))


def _print_file_info(module_results: list[dict], file_path: str) -> None:
    """Print file metadata from the file_intake module result."""
    intake = next(
        (r for r in module_results if r.get("module") == "file_intake"), None
    )

    table = Table(
        title="[bold]File Information[/bold]",
        box=box.ROUNDED,
        show_header=False,
        padding=(0, 1),
    )
    table.add_column("Key", style="bold dim", no_wrap=True)
    table.add_column("Value", overflow="fold")

    if intake and intake.get("status") == "success":
        data = intake.get("data", {})
        hashes = data.get("hashes", {})
        ft = data.get("file_type", {})

        table.add_row("File", data.get("file_name", Path(file_path).name))
        table.add_row("Path", data.get("file_path", file_path))
        table.add_row("Size", _human_size(data.get("file_size", 0)))
        table.add_row("Type", ft.get("description", "Unknown"))
        table.add_row("MIME", ft.get("mime_type", "Unknown"))
        table.add_row("MD5", hashes.get("md5") or "N/A")
        table.add_row("SHA256", hashes.get("sha256") or "N/A")
        if hashes.get("tlsh"):
            table.add_row("TLSH", hashes["tlsh"])
        if hashes.get("ssdeep"):
            table.add_row("ssdeep", hashes["ssdeep"])
    else:
        table.add_row("File", Path(file_path).name)
        table.add_row("Path", str(file_path))
        if intake and intake.get("status") == "error":
            table.add_row("[red]Error[/red]", intake.get("reason", "File intake failed"))

    console.print()
    console.print(table)


def _print_score_banner(scoring: dict, module_results: list[dict]) -> None:
    """Print a large coloured score panel with auto-generated verdict."""
    score = scoring.get("total_score", 0)
    band = scoring.get("risk_band", "LOW")
    colour = _BAND_COLOURS.get(band, "white")

    score_text = Text(f"  {score} / 100  ", style=f"bold {colour} on grey15")
    band_text = Text(f"  {band}  ", style=f"bold {colour}")

    content = Text.assemble(score_text, "   ", band_text)

    # Auto-generate verdict sentence
    verdict = _build_verdict(module_results, scoring)
    if verdict:
        content = Text.assemble(content, "\n\n", Text(verdict, style="dim italic"))

    panel = Panel(
        content,
        title="[bold]Threat Score[/bold]",
        style=colour.replace("bold ", ""),
        padding=(1, 4),
    )
    console.print()
    console.print(panel)


def _build_verdict(module_results: list[dict], scoring: dict) -> str:
    """Build a one-line human-readable verdict from findings."""
    indicators: list[str] = []

    for result in module_results:
        if result.get("status") != "success" or result.get("score_delta", 0) == 0:
            continue

        data = result.get("data", {})
        module = result.get("module", "")

        if module == "pe_analysis":
            if data.get("packers_detected"):
                indicators.append("packed/encrypted binary")
            if data.get("suspicious_imports"):
                count = len(data["suspicious_imports"])
                if count > 15:
                    indicators.append("extensive suspicious API usage")
                elif count > 5:
                    indicators.append("suspicious API imports")
            if not data.get("has_signature"):
                indicators.append("unsigned binary")

        elif module == "capa_analysis":
            for cat in data.get("scored_categories", []):
                name = cat.get("category", "").lower()
                if "injection" in name:
                    indicators.append("process injection capability")
                elif "anti" in name:
                    indicators.append("anti-analysis evasion")
                elif "credential" in name:
                    indicators.append("credential harvesting")
                elif "network" in name:
                    indicators.append("network C2 capability")
                elif "data collection" in name or "recon" in name:
                    indicators.append("data collection/reconnaissance")
                elif "persistence" in name:
                    indicators.append("persistence mechanism")
                elif "encryption" in name or "obfuscation" in name:
                    indicators.append("encryption/obfuscation")
                elif "privilege" in name:
                    indicators.append("privilege escalation")

        elif module == "ioc_extractor":
            iocs = data.get("iocs", {})
            if iocs.get("url") or iocs.get("ipv4"):
                indicators.append("network IOC indicators")

        elif module == "string_analysis":
            for cat in data.get("suspicious_categories", []):
                cat_l = cat.lower()
                if "password" in cat_l or "credential" in cat_l:
                    indicators.append("credential references")
                elif "base64" in cat_l:
                    indicators.append("encoded data")

    # De-duplicate while preserving order
    seen = set()
    unique = []
    for ind in indicators:
        if ind not in seen:
            seen.add(ind)
            unique.append(ind)

    if not unique:
        return ""

    # Build sentence
    if len(unique) == 1:
        body = unique[0]
    elif len(unique) == 2:
        body = f"{unique[0]} and {unique[1]}"
    else:
        body = ", ".join(unique[:4])
        if len(unique) > 4:
            body += f" (+{len(unique) - 4} more)"

    band = scoring.get("risk_band", "LOW")
    if band == "CRITICAL":
        prefix = "High-confidence threat"
    elif band == "HIGH":
        prefix = "Likely malicious"
    elif band == "MEDIUM":
        prefix = "Suspicious binary"
    else:
        prefix = "Low-risk file"

    return f"{prefix} with {body}"


# ---------------------------------------------------------------------------
# Module Results Table
# ---------------------------------------------------------------------------

# Modules that only apply to specific file types
_PE_ONLY_MODULES = {"pe_analysis", "capa_analysis", "string_analysis", "yara_scanner"}
_DOC_ONLY_MODULES = {"doc_analysis"}
_PDF_ONLY_MODULES = {"pdf_analysis"}


def _print_module_table(module_results: list[dict], file_path: str) -> None:
    """Print a table of all module results."""
    if not module_results:
        console.print("\n[dim]No module results.[/dim]")
        return

    # Detect file type for smart skip messages
    mime = ""
    for r in module_results:
        if r.get("module") == "file_intake" and r.get("status") == "success":
            mime = r.get("data", {}).get("file_type", {}).get("mime_type", "")
            break

    is_pe = "executable" in mime or "dosexec" in mime or "portable-executable" in mime
    is_doc = "officedocument" in mime or "msword" in mime or "ms-excel" in mime
    is_pdf = "pdf" in mime

    table = Table(
        title="[bold]Module Results[/bold]",
        box=box.ROUNDED,
        show_lines=False,
        padding=(0, 1),
    )
    table.add_column("Module", style="bold", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Score Δ", justify="right", no_wrap=True)
    table.add_column("Reason", overflow="fold")

    for result in module_results:
        name = result.get("module", "unknown")
        status = result.get("status", "unknown")
        delta = result.get("score_delta", 0)
        reason = result.get("reason", "")

        # Smart skip message for inapplicable modules
        if status == "skipped" and reason == "Module not yet implemented":
            if name in _DOC_ONLY_MODULES and not is_doc:
                reason = "Not applicable — not an Office document"
            elif name in _PDF_ONLY_MODULES and not is_pdf:
                reason = "Not applicable — not a PDF file"
            elif name == "virustotal":
                reason = "Not yet implemented"

        status_colour = _STATUS_COLOURS.get(status, "white")
        status_cell = f"[{status_colour}]{status}[/{status_colour}]"

        if isinstance(delta, (int, float)) and delta != 0:
            sign = "+" if delta > 0 else ""
            delta_cell = f"[{'red' if delta > 0 else 'green'}]{sign}{delta}[/]"
        else:
            delta_cell = "[dim]—[/dim]"

        # Truncate long reason text — 120 chars
        reason_display = reason if len(reason) <= 120 else reason[:117] + "..."

        table.add_row(name, status_cell, delta_cell, f"[dim]{reason_display}[/dim]")

    console.print()
    console.print(table)


# ---------------------------------------------------------------------------
# Score Breakdown
# ---------------------------------------------------------------------------


def _print_score_breakdown(breakdown: list[dict]) -> None:
    """Print score contributors (only shown when there are non-zero deltas)."""
    table = Table(
        title="[bold]Score Breakdown[/bold]",
        box=box.SIMPLE_HEAVY,
        padding=(0, 1),
    )
    table.add_column("Module", style="bold", no_wrap=True)
    table.add_column("Δ", justify="right", no_wrap=True)
    table.add_column("Reason", overflow="fold")

    for item in breakdown:
        delta = item.get("score_delta", 0)
        sign = "+" if delta > 0 else ""
        colour = "red" if delta > 0 else "green"
        table.add_row(
            item.get("module", "unknown"),
            f"[{colour}]{sign}{delta}[/{colour}]",
            item.get("reason", ""),
        )

    console.print()
    console.print(table)


# ---------------------------------------------------------------------------
# MITRE ATT&CK Table
# ---------------------------------------------------------------------------


def _print_attack_table(module_results: list[dict], detail_level: int) -> None:
    """Print MITRE ATT&CK mappings from capa analysis."""
    capa = next(
        (r for r in module_results if r.get("module") == "capa_analysis"), None
    )
    if not capa or capa.get("status") != "success":
        return

    mappings = capa.get("data", {}).get("attack_mappings", [])
    if not mappings:
        return

    # Sort by tactic for grouping
    mappings_sorted = sorted(mappings, key=lambda m: (m.get("tactic", ""), m.get("technique_id", "")))

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
        # Visual separator between tactics
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


# ---------------------------------------------------------------------------
# IOC Table
# ---------------------------------------------------------------------------


def _print_ioc_table(module_results: list[dict], detail_level: int) -> None:
    """Print extracted IOCs in a structured table."""
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

    _TYPE_STYLES = {
        "ipv4": ("IP Address", "red"),
        "url": ("URL", "yellow"),
        "domain": ("Domain", "cyan"),
        "registry_key": ("Registry Key", "magenta"),
        "email": ("Email", "blue"),
        "windows_path": ("File Path", "dim"),
    }

    limit = None if detail_level >= 1 else 5

    for ioc_type, values in iocs.items():
        if not values:
            continue

        label, colour = _TYPE_STYLES.get(ioc_type, (ioc_type, "white"))
        shown = values if limit is None else values[:limit]
        remaining = len(values) - len(shown)

        for val in shown:
            table.add_row(f"[{colour}]{label}[/{colour}]", val)
        if remaining > 0:
            table.add_row("", f"[dim](+{remaining} more — use -v to show all)[/dim]")

    console.print()
    console.print(table)


# ---------------------------------------------------------------------------
# Suspicious Strings Table
# ---------------------------------------------------------------------------


def _print_suspicious_strings(module_results: list[dict], detail_level: int) -> None:
    """Print suspicious string matches."""
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


# ---------------------------------------------------------------------------
# Capa Capabilities
# ---------------------------------------------------------------------------


def _print_capabilities(module_results: list[dict], detail_level: int) -> None:
    """Print detected capa capabilities."""
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

    # Show scored categories first as a summary
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


# ---------------------------------------------------------------------------
# Per-Module Timing
# ---------------------------------------------------------------------------


def _print_timing_table(module_results: list[dict], timing: dict) -> None:
    """Print per-module timing breakdown (shown at -v and above)."""
    timed = [
        r for r in module_results
        if "elapsed_seconds" in r
    ]
    if not timed:
        return

    # Sort by elapsed time descending
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

        # Highlight slow modules
        if elapsed > 60:
            time_str = f"[red]{elapsed:.1f}s[/red]"
        elif elapsed > 10:
            time_str = f"[yellow]{elapsed:.1f}s[/yellow]"
        else:
            time_str = f"[dim]{elapsed:.1f}s[/dim]"

        status_colour = _STATUS_COLOURS.get(status, "white")
        table.add_row(name, time_str, f"[{status_colour}]{status}[/{status_colour}]")

    # Total
    total = timing.get("elapsed_seconds", 0)
    table.add_section()
    table.add_row("[bold]Total[/bold]", f"[bold]{total:.1f}s[/bold]", "")

    console.print()
    console.print(table)


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------


def _print_recommendations(
    module_results: list[dict], scoring: dict, file_path: str
) -> None:
    """Print context-aware recommended next steps."""
    recs: list[str] = []
    sha256 = ""

    for result in module_results:
        module = result.get("module", "")
        status = result.get("status", "")
        data = result.get("data", {})

        if module == "file_intake" and status == "success":
            sha256 = data.get("hashes", {}).get("sha256", "")

        elif module == "ioc_extractor" and status == "success":
            iocs = data.get("iocs", {})
            ips = iocs.get("ipv4", [])
            domains = iocs.get("domain", [])
            if ips:
                recs.append(f"Investigate IP(s): {', '.join(ips[:3])}")
            if domains:
                top = ", ".join(domains[:3])
                recs.append(f"Check network logs for connections to: {top}")

        elif module == "virustotal" and status == "skipped":
            if sha256:
                recs.append(f"Submit SHA256 to VirusTotal: {sha256[:16]}…")

        elif module == "capa_analysis" and status == "skipped":
            reason = result.get("reason", "")
            if "timeout" in reason.lower() or "timed out" in reason.lower():
                recs.append("capa timed out — try --deep for extended timeout (180s)")

        elif module == "pe_analysis" and status == "success":
            if data.get("packers_detected"):
                recs.append("Binary is packed — consider unpacking before re-analysis")

    band = scoring.get("risk_band", "LOW")
    if band in ("HIGH", "CRITICAL"):
        recs.append("Consider dynamic analysis (--dynamic speakeasy) for runtime behaviour")

    if not recs:
        return

    lines = "\n".join(f"  [dim]•[/dim] {r}" for r in recs)
    panel = Panel(
        lines,
        title="[bold]Recommended Next Steps[/bold]",
        style="dim",
        padding=(1, 2),
    )
    console.print()
    console.print(panel)


# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------


def _print_footer(timing: dict) -> None:
    elapsed = timing.get("elapsed_seconds")
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    parts = [f"[dim]Analysis complete[/dim]  [dim]{ts}[/dim]"]
    if elapsed is not None:
        parts.append(f"  [dim]({elapsed:.2f}s)[/dim]")
    console.print()
    console.print("".join(parts))
    console.print()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _human_size(nbytes: int) -> str:
    """Format byte count as a human-readable string."""
    for unit in ("B", "KiB", "MiB", "GiB"):
        if nbytes < 1024:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024
    return f"{nbytes:.1f} TiB"
