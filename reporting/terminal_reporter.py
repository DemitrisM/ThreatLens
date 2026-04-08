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
    _print_pe_indicators(module_results, detail_level)
    _print_attack_table(module_results, detail_level)
    _print_ioc_table(module_results, detail_level)
    _print_suspicious_strings(module_results, detail_level)
    _print_capabilities(module_results, detail_level)
    _print_virustotal(module_results, detail_level)

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
            if data.get("rwx_sections"):
                indicators.append("RWX self-modifying section")
            if len(data.get("hollowing_apis") or []) >= 2:
                indicators.append("process hollowing API combo")
            if data.get("embedded_pe"):
                indicators.append("embedded PE payload")
            if (data.get("resource_types") or {}).get("autoit"):
                indicators.append("AutoIt wrapper")
            footprint = data.get("import_footprint") or {}
            if footprint.get("loader_only") or footprint.get("is_kernel32_only"):
                indicators.append("kernel32-only loader footprint")
            if (data.get("import_footprint") or {}).get("is_kernel32_only"):
                pass
            if (data.get("dynamic_api_resolution") or {}).get("count", 0) >= 5:
                indicators.append("dynamic API resolution")

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

        elif module == "virustotal":
            if data.get("found"):
                detections = data.get("malicious", 0) + data.get("suspicious", 0)
                if detections > 10:
                    label = data.get("threat_label")
                    indicators.append(f"VirusTotal: {detections} engines flagged" + (f" ({label})" if label else ""))
                elif detections >= 1:
                    indicators.append("low VirusTotal detections")

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

        # Smart skip messages are now set by the modules themselves
        # (doc_analysis and pdf_analysis return "Not applicable — ..." directly)

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
# PE Structural Indicators (PEStudio / DIE-style summary)
# ---------------------------------------------------------------------------


def _print_pe_indicators(module_results: list[dict], detail_level: int) -> None:
    """Surface the structural PE indicators we extract beyond the score
    breakdown — DLL characteristics, entry point, Rich header, debug
    info, version info, embedded payloads, dynamic API resolution, etc.

    Hidden when no PE was analysed.
    """
    pe = next(
        (r for r in module_results if r.get("module") == "pe_analysis"), None
    )
    if not pe or pe.get("status") != "success":
        return
    data = pe.get("data", {})

    rows: list[tuple[str, str, str]] = []  # (label, value, severity)

    # Compiled language fingerprint
    lang = data.get("compiled_language")
    if lang:
        rows.append(("Compiled language",
                     {"go": "Go", "rust": "Rust", "nim": "Nim"}.get(lang, lang),
                     "info"))

    # Sections + entropy summary
    sections = data.get("sections", [])
    if sections:
        section_count = data.get("section_count", len(sections))
        high_e = [s for s in sections if s.get("entropy", 0) >= 7.0]
        rows.append(
            (
                "Sections",
                f"{section_count} total"
                + (f" ({len(high_e)} high-entropy ≥7.0)" if high_e else ""),
                "warn" if len(high_e) >= 1 else "info",
            )
        )

    # RWX + TLS callbacks
    rwx = data.get("rwx_sections") or []
    if rwx:
        rows.append(("RWX sections", ", ".join(rwx), "bad"))
    if data.get("has_tls_callbacks"):
        rows.append(("TLS callbacks", "present (pre-main code execution)", "warn"))

    # DLL characteristics — only show if any are missing
    dll = data.get("dll_characteristics_flags") or {}
    if dll:
        missing = [k.upper() for k, v in dll.items() if not v
                   and k in {"aslr", "dep", "cfg"}]
        if missing:
            rows.append(("DLL characteristics",
                         f"missing: {', '.join(missing)}",
                         "bad" if "ASLR" in missing and "DEP" in missing else "warn"))

    # Entry-point validation
    ep = data.get("entry_point_section") or {}
    if ep.get("anomaly"):
        rows.append((
            "Entry point",
            f"in '{ep.get('section') or '<none>'}' (not standard code section)",
            "bad",
        ))

    # Section size mismatch
    sm = data.get("section_size_mismatch") or {}
    if sm.get("count"):
        rows.append((
            "Section size mismatch",
            f"{sm['count']} section(s): {', '.join(sm.get('names', []))}",
            "bad",
        ))

    # Process-injection / hollowing API combo
    hollow = data.get("hollowing_apis") or []
    if len(hollow) >= 2:
        rows.append((
            "Process-injection APIs",
            f"{len(hollow)} hollowing-pattern APIs imported: "
            f"{', '.join(hollow[:4])}",
            "bad",
        ))

    # API category diversity
    cats = data.get("api_categories") or []
    if cats:
        rows.append((
            "API behaviour categories",
            f"{len(cats)}: {', '.join(cats)}",
            "bad" if len(cats) >= 4 else "warn" if len(cats) >= 3 else "info",
        ))

    # Overlay
    overlay = data.get("overlay") or {}
    if overlay.get("size"):
        ent = overlay.get("entropy", 0)
        rows.append((
            "Overlay",
            f"{overlay['size']} bytes, entropy {ent:.2f}",
            "bad" if ent >= 7.0 else "info",
        ))

    # Resources
    rsrc = data.get("resources") or {}
    if rsrc.get("present"):
        ent = rsrc.get("entropy", 0)
        size = rsrc.get("size", 0)
        rows.append((
            "Resources (.rsrc)",
            f"{size} bytes, entropy {ent:.2f}",
            "bad" if rsrc.get("high_entropy") else "info",
        ))

    # Embedded MZ payload
    emb = data.get("embedded_pe")
    if emb:
        rows.append((
            "Embedded PE payload",
            f"{emb.get('where')} @ offset 0x{emb.get('offset', 0):x}",
            "bad",
        ))

    # Rich header / DOS stub
    rich = data.get("rich_header") or {}
    if rich:
        if not rich.get("present"):
            rows.append(("Rich header", "absent (non-MS toolchain)", "info"))
        elif rich.get("corrupted"):
            rows.append(("Rich header", "present but corrupted", "warn"))
    dos = data.get("dos_stub") or {}
    if dos.get("modified"):
        rows.append(("MS-DOS stub", "modified from default", "warn"))

    # PDB debug path
    debug = data.get("debug_info") or {}
    pdb = debug.get("pdb_path") or ""
    if pdb:
        sev = "bad" if debug.get("suspicious_pdb") else "info"
        # Truncate long PDB paths for display.
        pdb_disp = pdb if len(pdb) <= 90 else pdb[:87] + "..."
        rows.append(("PDB debug path", pdb_disp, sev))
        if debug.get("pdb_username"):
            rows.append(("PDB username leak", debug["pdb_username"], "warn"))

    # Version info impersonation / metadata
    vinfo = data.get("version_info") or {}
    if vinfo:
        company = vinfo.get("CompanyName", "").strip()
        product = vinfo.get("ProductName", "").strip()
        if company or product:
            rows.append((
                "Version info",
                f"Company={company!r}, Product={product!r}",
                "info",
            ))

    # Authenticode certificate hint
    cert = data.get("certificate") or {}
    if cert.get("present"):
        cn = cert.get("common_name") or "(unknown CN)"
        issuer = cert.get("issuer_hint") or ""
        rows.append((
            "Authenticode signer",
            f"CN={cn}" + (f" via {issuer}" if issuer else ""),
            "info",
        ))

    # Dynamic API resolution markers
    dyn = data.get("dynamic_api_resolution") or {}
    if dyn.get("count", 0) >= 5:
        sample = ", ".join(dyn.get("apis", [])[:5])
        rows.append((
            "Dynamic API resolution",
            f"{dyn['count']} suspicious APIs as raw strings only "
            f"(GetProcAddress pattern): {sample}",
            "warn",
        ))

    # Section permission anomalies (writable .text, exec .data, …)
    perm = data.get("section_permission_anomalies") or []
    if perm:
        rows.append((
            "Section permissions",
            ", ".join(perm[:4]),
            "bad",
        ))

    # PE OptionalHeader checksum verification
    csum = data.get("pe_checksum") or {}
    if csum.get("mismatch_signed"):
        rows.append((
            "PE checksum",
            f"stored 0x{csum.get('stored', 0):08x} ≠ "
            f"computed 0x{csum.get('computed', 0):08x} (signed binary tampered)",
            "bad",
        ))
    elif csum.get("stored") and csum.get("computed") \
            and csum["stored"] != csum["computed"]:
        rows.append((
            "PE checksum",
            f"stored 0x{csum['stored']:08x} ≠ computed 0x{csum['computed']:08x}",
            "info",
        ))

    # Imported-DLL footprint (kernel32-only / loader-only)
    footprint = data.get("import_footprint") or {}
    if footprint.get("loader_only"):
        rows.append((
            "Import footprint",
            "kernel32 loader-only (LoadLibrary/GetProcAddress) — packer/shellcode loader",
            "bad",
        ))
    elif footprint.get("is_kernel32_only"):
        rows.append((
            "Import footprint",
            "only kernel32.dll imported — packer-style",
            "bad",
        ))

    # Resource type breakdown + AutoIt
    rsrc_types = data.get("resource_types") or {}
    if rsrc_types.get("autoit"):
        rows.append((
            "AutoIt script",
            "AU3! marker found in RT_RCDATA — AutoIt-compiled",
            "bad",
        ))
    if rsrc_types.get("largest_rcdata", 0) >= 256 * 1024:
        rows.append((
            "Large RT_RCDATA",
            f"{rsrc_types['largest_rcdata']} bytes — embedded payload likely",
            "warn",
        ))
    if rsrc_types.get("types") and detail_level >= 1:
        type_summary = ", ".join(
            f"{k}={v}" for k, v in
            sorted(rsrc_types["types"].items(), key=lambda kv: -kv[1])[:6]
        )
        rows.append(("Resource types", type_summary, "info"))

    # Installer wrapper
    installer = data.get("installer")
    if installer:
        rows.append(("Installer wrapper", installer, "warn"))

    # Forwarded exports
    fwd = data.get("forwarded_exports") or 0
    if fwd:
        rows.append((
            "Forwarded exports",
            f"{fwd} entry/entries forward to other DLLs",
            "info",
        ))

    # Imphash + packers
    imphash = data.get("imphash") or ""
    if imphash:
        rows.append(("Imphash", imphash, "info"))
    packers = data.get("packers_detected") or []
    if packers:
        rows.append(("Packer", ", ".join(packers), "bad"))

    if not rows:
        return

    table = Table(
        title="[bold]PE Structural Indicators[/bold]",
        box=box.ROUNDED,
        padding=(0, 1),
    )
    table.add_column("Indicator", style="bold cyan", no_wrap=True)
    table.add_column("Detail", overflow="fold")

    sev_styles = {
        "bad": "red",
        "warn": "yellow",
        "info": "dim",
    }

    # In default mode, hide pure-info rows when there are higher-severity
    # findings, to keep the panel focused. -v shows everything.
    has_serious = any(sev != "info" for _, _, sev in rows)
    if detail_level < 1 and has_serious:
        rows_to_show = [r for r in rows if r[2] != "info"]
        # Always keep imphash + language even at default level for context.
        for r in rows:
            if r[0] in {"Imphash", "Compiled language"} and r not in rows_to_show:
                rows_to_show.append(r)
    else:
        rows_to_show = rows

    for label, value, sev in rows_to_show:
        style = sev_styles.get(sev, "")
        if style:
            table.add_row(label, f"[{style}]{value}[/{style}]")
        else:
            table.add_row(label, value)

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
# VirusTotal Results
# ---------------------------------------------------------------------------


def _print_virustotal(module_results: list[dict], detail_level: int) -> None:
    """Print VirusTotal lookup results."""
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

    # Detection ratio — colour-coded
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
        # VT returns Unix timestamp — convert to readable date
        if isinstance(first_seen, (int, float)):
            from datetime import datetime, timezone
            try:
                first_seen = datetime.fromtimestamp(first_seen, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
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

        elif module == "virustotal":
            if status == "skipped":
                if sha256:
                    recs.append(f"Submit SHA256 to VirusTotal: {sha256[:16]}…")
            elif status == "success" and data.get("found"):
                detections = data.get("malicious", 0) + data.get("suspicious", 0)
                if detections > 10:
                    label = data.get("threat_label", "")
                    recs.append(f"VirusTotal confirms malicious — {detections} engines flagged" + (f" ({label})" if label else ""))
            elif status == "error":
                reason = result.get("reason", "")
                if "rate limit" in reason.lower():
                    recs.append("VirusTotal rate limit hit — wait 60s or use --skip virustotal")
                elif sha256:
                    recs.append(f"VirusTotal lookup failed — manually check: {sha256[:16]}…")

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
