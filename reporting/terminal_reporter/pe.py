"""PE Structural Indicators panel (PEStudio / DIE / Manalyze-style summary).

Surfaces everything ``pe_analysis`` extracts beyond the raw score:
compiled language, DLL characteristics, entry-point anomalies, Rich
header state, PDB paths, embedded payloads, dynamic API resolution,
etc.  Hidden entirely when no PE was analysed.

``pe_rows`` is pure — it reads the module's ``data`` and returns rows.
All presentation lives in :func:`reporting.terminal_reporter._render.render_indicators`.
"""

from ._common import LIMITS, console
from ._render import Row, render_indicators

#: Kept at detail 0 even though they are ``info``, because they are the
#: two things an analyst pivots on. Previously appended after filtering,
#: which moved them to the end of the table.
_ALWAYS_SHOW = frozenset({"Imphash", "Compiled language"})

_LANGUAGE_NAMES = {"go": "Go", "rust": "Rust", "nim": "Nim"}


def pe_rows(data: dict, detail_level: int = 0) -> list[Row]:
    """Build the PE indicator rows from a ``pe_analysis`` data dict."""
    if not data:
        return []

    rows: list[Row] = []

    lang = data.get("compiled_language")
    if lang:
        rows.append(
            Row("Compiled language", _LANGUAGE_NAMES.get(lang, lang), "info")
        )

    sections = data.get("sections", [])
    if sections:
        section_count = data.get("section_count", len(sections))
        high_e = [s for s in sections if s.get("entropy", 0) >= 7.0]
        rows.append(
            Row(
                "Sections",
                f"{section_count} total"
                + (f" ({len(high_e)} high-entropy ≥7.0)" if high_e else ""),
                "warn" if len(high_e) >= 1 else "info",
            )
        )

    rwx = data.get("rwx_sections") or []
    if rwx:
        rows.append(Row("RWX sections", ", ".join(rwx), "bad"))
    if data.get("has_tls_callbacks"):
        rows.append(Row("TLS callbacks", "present (pre-main code execution)", "warn"))

    dll = data.get("dll_characteristics_flags") or {}
    if dll:
        missing = [
            k.upper() for k, v in dll.items() if not v and k in {"aslr", "dep", "cfg"}
        ]
        if missing:
            rows.append(
                Row(
                    "DLL characteristics",
                    f"missing: {', '.join(missing)}",
                    "bad" if "ASLR" in missing and "DEP" in missing else "warn",
                )
            )

    ep = data.get("entry_point_section") or {}
    if ep.get("anomaly"):
        rows.append(
            Row(
                "Entry point",
                f"in '{ep.get('section') or '<none>'}' (not standard code section)",
                "bad",
            )
        )

    sm = data.get("section_size_mismatch") or {}
    if sm.get("count"):
        rows.append(
            Row(
                "Section size mismatch",
                f"{sm['count']} section(s): {', '.join(sm.get('names', []))}",
                "bad",
            )
        )

    hollow = data.get("hollowing_apis") or []
    if len(hollow) >= 2:
        rows.append(
            Row(
                "Process-injection APIs",
                f"{len(hollow)} hollowing-pattern APIs imported: "
                f"{', '.join(hollow[:4])}",
                "bad",
            )
        )

    cats = data.get("api_categories") or []
    if cats:
        rows.append(
            Row(
                "API behaviour categories",
                f"{len(cats)}: {', '.join(cats)}",
                "bad" if len(cats) >= 4 else "warn" if len(cats) >= 3 else "info",
            )
        )

    overlay = data.get("overlay") or {}
    if overlay.get("size"):
        ent = overlay.get("entropy", 0)
        rows.append(
            Row(
                "Overlay",
                f"{overlay['size']} bytes, entropy {ent:.2f}",
                "bad" if ent >= 7.0 else "info",
            )
        )

    rsrc = data.get("resources") or {}
    if rsrc.get("present"):
        ent = rsrc.get("entropy", 0)
        size = rsrc.get("size", 0)
        rows.append(
            Row(
                "Resources (.rsrc)",
                f"{size} bytes, entropy {ent:.2f}",
                "bad" if rsrc.get("high_entropy") else "info",
            )
        )

    emb = data.get("embedded_pe")
    if emb:
        rows.append(
            Row(
                "Embedded PE payload",
                f"{emb.get('where')} @ offset 0x{emb.get('offset', 0):x}",
                "bad",
            )
        )

    rich = data.get("rich_header") or {}
    if rich:
        if not rich.get("present"):
            rows.append(Row("Rich header", "absent (non-MS toolchain)", "info"))
        elif rich.get("corrupted"):
            rows.append(Row("Rich header", "present but corrupted", "warn"))

    dos = data.get("dos_stub") or {}
    if dos.get("modified"):
        rows.append(Row("MS-DOS stub", "modified from default", "warn"))

    debug = data.get("debug_info") or {}
    pdb = debug.get("pdb_path") or ""
    if pdb:
        sev = "bad" if debug.get("suspicious_pdb") else "info"
        cap = LIMITS["pdb_chars"]
        pdb_disp = pdb if len(pdb) <= cap else pdb[: cap - 3] + "..."
        rows.append(Row("PDB debug path", pdb_disp, sev))
        if debug.get("pdb_username"):
            rows.append(Row("PDB username leak", debug["pdb_username"], "warn"))

    vinfo = data.get("version_info") or {}
    if vinfo:
        company = vinfo.get("CompanyName", "").strip()
        product = vinfo.get("ProductName", "").strip()
        if company or product:
            rows.append(
                Row("Version info", f"Company={company!r}, Product={product!r}", "info")
            )

    cert = data.get("certificate") or {}
    if cert.get("present"):
        cn = cert.get("common_name") or "(unknown CN)"
        issuer = cert.get("issuer_hint") or ""
        rows.append(
            Row(
                "Authenticode signer",
                f"CN={cn}" + (f" via {issuer}" if issuer else ""),
                "info",
            )
        )

    dyn = data.get("dynamic_api_resolution") or {}
    if dyn.get("count", 0) >= 5:
        sample = ", ".join(dyn.get("apis", [])[:5])
        rows.append(
            Row(
                "Dynamic API resolution",
                f"{dyn['count']} suspicious APIs as raw strings only "
                f"(GetProcAddress pattern): {sample}",
                "warn",
            )
        )

    perm = data.get("section_permission_anomalies") or []
    if perm:
        rows.append(Row("Section permissions", ", ".join(perm[:4]), "bad"))

    csum = data.get("pe_checksum") or {}
    if csum.get("mismatch_signed"):
        rows.append(
            Row(
                "PE checksum",
                f"stored 0x{csum.get('stored', 0):08x} ≠ "
                f"computed 0x{csum.get('computed', 0):08x} (signed binary tampered)",
                "bad",
            )
        )
    elif (
        csum.get("stored")
        and csum.get("computed")
        and csum["stored"] != csum["computed"]
    ):
        rows.append(
            Row(
                "PE checksum",
                f"stored 0x{csum['stored']:08x} ≠ computed 0x{csum['computed']:08x}",
                "info",
            )
        )

    footprint = data.get("import_footprint") or {}
    if footprint.get("loader_only"):
        rows.append(
            Row(
                "Import footprint",
                "kernel32 loader-only (LoadLibrary/GetProcAddress) — "
                "packer/shellcode loader",
                "bad",
            )
        )
    elif footprint.get("is_kernel32_only"):
        rows.append(
            Row("Import footprint", "only kernel32.dll imported — packer-style", "bad")
        )

    rsrc_types = data.get("resource_types") or {}
    if rsrc_types.get("autoit"):
        rows.append(
            Row("AutoIt script", "AU3! marker found in RT_RCDATA — AutoIt-compiled", "bad")
        )
    if rsrc_types.get("largest_rcdata", 0) >= 256 * 1024:
        rows.append(
            Row(
                "Large RT_RCDATA",
                f"{rsrc_types['largest_rcdata']} bytes — embedded payload likely",
                "warn",
            )
        )
    if rsrc_types.get("types") and detail_level >= 1:
        type_summary = ", ".join(
            f"{k}={v}"
            for k, v in sorted(rsrc_types["types"].items(), key=lambda kv: -kv[1])[:6]
        )
        rows.append(Row("Resource types", type_summary, "info"))

    installer = data.get("installer")
    if installer:
        rows.append(Row("Installer wrapper", installer, "warn"))

    fwd = data.get("forwarded_exports") or 0
    if fwd:
        rows.append(
            Row("Forwarded exports", f"{fwd} entry/entries forward to other DLLs", "info")
        )

    imphash = data.get("imphash") or ""
    if imphash:
        rows.append(Row("Imphash", imphash, "info"))

    packers = data.get("packers_detected") or []
    if packers:
        rows.append(Row("Packer", ", ".join(packers), "bad"))

    return rows


def print_pe_indicators(module_results: list[dict], detail_level: int) -> None:
    """PE Structural Indicators section."""
    pe = next((r for r in module_results if r.get("module") == "pe_analysis"), None)
    if not pe or pe.get("status") != "success":
        return
    render_indicators(
        "PE Structural Indicators",
        pe_rows(pe.get("data") or {}, detail_level),
        detail_level,
        always_show=_ALWAYS_SHOW,
        console=console,
    )
