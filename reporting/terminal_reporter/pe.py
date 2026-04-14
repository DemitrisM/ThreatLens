"""PE Structural Indicators panel (PEStudio / DIE / Manalyze-style summary).

Surfaces everything ``pe_analysis`` extracts beyond the raw score:
compiled language, DLL characteristics, entry-point anomalies, Rich
header state, PDB paths, embedded payloads, dynamic API resolution,
etc.  Hidden entirely when no PE was analysed.
"""

from rich import box
from rich.table import Table

from ._common import console


_SEV_STYLES = {"bad": "red", "warn": "yellow", "info": "dim"}


def print_pe_indicators(module_results: list[dict], detail_level: int) -> None:
    pe = next(
        (r for r in module_results if r.get("module") == "pe_analysis"), None
    )
    if not pe or pe.get("status") != "success":
        return
    data = pe.get("data", {})

    rows: list[tuple[str, str, str]] = []  # (label, value, severity)

    lang = data.get("compiled_language")
    if lang:
        rows.append(("Compiled language",
                     {"go": "Go", "rust": "Rust", "nim": "Nim"}.get(lang, lang),
                     "info"))

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

    rwx = data.get("rwx_sections") or []
    if rwx:
        rows.append(("RWX sections", ", ".join(rwx), "bad"))
    if data.get("has_tls_callbacks"):
        rows.append(("TLS callbacks", "present (pre-main code execution)", "warn"))

    dll = data.get("dll_characteristics_flags") or {}
    if dll:
        missing = [k.upper() for k, v in dll.items() if not v
                   and k in {"aslr", "dep", "cfg"}]
        if missing:
            rows.append(("DLL characteristics",
                         f"missing: {', '.join(missing)}",
                         "bad" if "ASLR" in missing and "DEP" in missing else "warn"))

    ep = data.get("entry_point_section") or {}
    if ep.get("anomaly"):
        rows.append((
            "Entry point",
            f"in '{ep.get('section') or '<none>'}' (not standard code section)",
            "bad",
        ))

    sm = data.get("section_size_mismatch") or {}
    if sm.get("count"):
        rows.append((
            "Section size mismatch",
            f"{sm['count']} section(s): {', '.join(sm.get('names', []))}",
            "bad",
        ))

    hollow = data.get("hollowing_apis") or []
    if len(hollow) >= 2:
        rows.append((
            "Process-injection APIs",
            f"{len(hollow)} hollowing-pattern APIs imported: "
            f"{', '.join(hollow[:4])}",
            "bad",
        ))

    cats = data.get("api_categories") or []
    if cats:
        rows.append((
            "API behaviour categories",
            f"{len(cats)}: {', '.join(cats)}",
            "bad" if len(cats) >= 4 else "warn" if len(cats) >= 3 else "info",
        ))

    overlay = data.get("overlay") or {}
    if overlay.get("size"):
        ent = overlay.get("entropy", 0)
        rows.append((
            "Overlay",
            f"{overlay['size']} bytes, entropy {ent:.2f}",
            "bad" if ent >= 7.0 else "info",
        ))

    rsrc = data.get("resources") or {}
    if rsrc.get("present"):
        ent = rsrc.get("entropy", 0)
        size = rsrc.get("size", 0)
        rows.append((
            "Resources (.rsrc)",
            f"{size} bytes, entropy {ent:.2f}",
            "bad" if rsrc.get("high_entropy") else "info",
        ))

    emb = data.get("embedded_pe")
    if emb:
        rows.append((
            "Embedded PE payload",
            f"{emb.get('where')} @ offset 0x{emb.get('offset', 0):x}",
            "bad",
        ))

    rich = data.get("rich_header") or {}
    if rich:
        if not rich.get("present"):
            rows.append(("Rich header", "absent (non-MS toolchain)", "info"))
        elif rich.get("corrupted"):
            rows.append(("Rich header", "present but corrupted", "warn"))
    dos = data.get("dos_stub") or {}
    if dos.get("modified"):
        rows.append(("MS-DOS stub", "modified from default", "warn"))

    debug = data.get("debug_info") or {}
    pdb = debug.get("pdb_path") or ""
    if pdb:
        sev = "bad" if debug.get("suspicious_pdb") else "info"
        pdb_disp = pdb if len(pdb) <= 90 else pdb[:87] + "..."
        rows.append(("PDB debug path", pdb_disp, sev))
        if debug.get("pdb_username"):
            rows.append(("PDB username leak", debug["pdb_username"], "warn"))

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

    cert = data.get("certificate") or {}
    if cert.get("present"):
        cn = cert.get("common_name") or "(unknown CN)"
        issuer = cert.get("issuer_hint") or ""
        rows.append((
            "Authenticode signer",
            f"CN={cn}" + (f" via {issuer}" if issuer else ""),
            "info",
        ))

    dyn = data.get("dynamic_api_resolution") or {}
    if dyn.get("count", 0) >= 5:
        sample = ", ".join(dyn.get("apis", [])[:5])
        rows.append((
            "Dynamic API resolution",
            f"{dyn['count']} suspicious APIs as raw strings only "
            f"(GetProcAddress pattern): {sample}",
            "warn",
        ))

    perm = data.get("section_permission_anomalies") or []
    if perm:
        rows.append((
            "Section permissions",
            ", ".join(perm[:4]),
            "bad",
        ))

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

    installer = data.get("installer")
    if installer:
        rows.append(("Installer wrapper", installer, "warn"))

    fwd = data.get("forwarded_exports") or 0
    if fwd:
        rows.append((
            "Forwarded exports",
            f"{fwd} entry/entries forward to other DLLs",
            "info",
        ))

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

    # In default mode hide pure-info rows when there are higher-severity
    # findings, keeping imphash + language for context.
    has_serious = any(sev != "info" for _, _, sev in rows)
    if detail_level < 1 and has_serious:
        rows_to_show = [r for r in rows if r[2] != "info"]
        for r in rows:
            if r[0] in {"Imphash", "Compiled language"} and r not in rows_to_show:
                rows_to_show.append(r)
    else:
        rows_to_show = rows

    for label, value, sev in rows_to_show:
        style = _SEV_STYLES.get(sev, "")
        if style:
            table.add_row(label, f"[{style}]{value}[/{style}]")
        else:
            table.add_row(label, value)

    console.print()
    console.print(table)
