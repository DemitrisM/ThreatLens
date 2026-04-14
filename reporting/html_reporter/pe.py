"""PE Structural Indicators table rows for the HTML template.

Mirrors ``reporting.terminal_reporter.pe`` so the HTML and terminal
outputs surface the same set of indicators.  Each row is
``{label, value, severity}`` with severity in {"bad", "warn", "info"}.
"""


def pe_indicators(module_results: list[dict]) -> list[dict]:
    pe = next(
        (r for r in module_results if r.get("module") == "pe_analysis"), None
    )
    if not pe or pe.get("status") != "success":
        return []
    data = pe.get("data", {}) or {}

    rows: list[dict] = []

    def add(label: str, value: str, severity: str) -> None:
        rows.append({"label": label, "value": value, "severity": severity})

    lang = data.get("compiled_language")
    if lang:
        add(
            "Compiled language",
            {"go": "Go", "rust": "Rust", "nim": "Nim"}.get(lang, lang),
            "info",
        )

    sections = data.get("sections", []) or []
    if sections:
        section_count = data.get("section_count", len(sections))
        high_e = [s for s in sections if (s.get("entropy") or 0) >= 7.0]
        add(
            "Sections",
            f"{section_count} total"
            + (f" ({len(high_e)} high-entropy ≥7.0)" if high_e else ""),
            "warn" if high_e else "info",
        )

    rwx = data.get("rwx_sections") or []
    if rwx:
        add("RWX sections", ", ".join(rwx), "bad")
    if data.get("has_tls_callbacks"):
        add("TLS callbacks", "present (pre-main code execution)", "warn")

    dll = data.get("dll_characteristics_flags") or {}
    if dll:
        missing = [
            k.upper()
            for k, v in dll.items()
            if not v and k in {"aslr", "dep", "cfg"}
        ]
        if missing:
            add(
                "DLL characteristics",
                f"missing: {', '.join(missing)}",
                "bad" if "ASLR" in missing and "DEP" in missing else "warn",
            )

    ep = data.get("entry_point_section") or {}
    if ep.get("anomaly"):
        add(
            "Entry point",
            f"in '{ep.get('section') or '<none>'}' (not standard code section)",
            "bad",
        )

    sm = data.get("section_size_mismatch") or {}
    if sm.get("count"):
        add(
            "Section size mismatch",
            f"{sm['count']} section(s): {', '.join(sm.get('names', []))}",
            "bad",
        )

    hollow = data.get("hollowing_apis") or []
    if len(hollow) >= 2:
        add(
            "Process-injection APIs",
            f"{len(hollow)} hollowing-pattern APIs imported: "
            f"{', '.join(hollow[:4])}",
            "bad",
        )

    cats = data.get("api_categories") or []
    if cats:
        if len(cats) >= 4:
            sev = "bad"
        elif len(cats) >= 3:
            sev = "warn"
        else:
            sev = "info"
        add("API behaviour categories", f"{len(cats)}: {', '.join(cats)}", sev)

    overlay = data.get("overlay") or {}
    if overlay.get("size"):
        ent = overlay.get("entropy", 0) or 0
        add(
            "Overlay",
            f"{overlay['size']} bytes, entropy {ent:.2f}",
            "bad" if ent >= 7.0 else "info",
        )

    rsrc = data.get("resources") or {}
    if rsrc.get("present"):
        ent = rsrc.get("entropy", 0) or 0
        size = rsrc.get("size", 0) or 0
        add(
            "Resources (.rsrc)",
            f"{size} bytes, entropy {ent:.2f}",
            "bad" if rsrc.get("high_entropy") else "info",
        )

    emb = data.get("embedded_pe")
    if emb:
        add(
            "Embedded PE payload",
            f"{emb.get('where')} @ offset 0x{(emb.get('offset') or 0):x}",
            "bad",
        )

    rich = data.get("rich_header") or {}
    if rich:
        if not rich.get("present"):
            add("Rich header", "absent (non-MS toolchain)", "info")
        elif rich.get("corrupted"):
            add("Rich header", "present but corrupted", "warn")
    dos = data.get("dos_stub") or {}
    if dos.get("modified"):
        add("MS-DOS stub", "modified from default", "warn")

    debug = data.get("debug_info") or {}
    pdb = debug.get("pdb_path") or ""
    if pdb:
        sev = "bad" if debug.get("suspicious_pdb") else "info"
        add("PDB debug path", pdb, sev)
        if debug.get("pdb_username"):
            add("PDB username leak", debug["pdb_username"], "warn")

    vinfo = data.get("version_info") or {}
    if vinfo:
        company = (vinfo.get("CompanyName") or "").strip()
        product = (vinfo.get("ProductName") or "").strip()
        if company or product:
            add(
                "Version info",
                f"Company={company!r}, Product={product!r}",
                "info",
            )

    cert = data.get("certificate") or {}
    if cert.get("present"):
        cn = cert.get("common_name") or "(unknown CN)"
        issuer = cert.get("issuer_hint") or ""
        add(
            "Authenticode signer",
            f"CN={cn}" + (f" via {issuer}" if issuer else ""),
            "info",
        )

    dyn = data.get("dynamic_api_resolution") or {}
    if (dyn.get("count") or 0) >= 5:
        sample = ", ".join(dyn.get("apis", [])[:5])
        add(
            "Dynamic API resolution",
            f"{dyn['count']} suspicious APIs as raw strings only "
            f"(GetProcAddress pattern): {sample}",
            "warn",
        )

    perm = data.get("section_permission_anomalies") or []
    if perm:
        add("Section permissions", ", ".join(perm[:4]), "bad")

    csum = data.get("pe_checksum") or {}
    if csum.get("mismatch_signed"):
        add(
            "PE checksum",
            f"stored 0x{csum.get('stored', 0):08x} ≠ "
            f"computed 0x{csum.get('computed', 0):08x} (signed binary tampered)",
            "bad",
        )
    elif csum.get("stored") and csum.get("computed") \
            and csum["stored"] != csum["computed"]:
        add(
            "PE checksum",
            f"stored 0x{csum['stored']:08x} ≠ computed 0x{csum['computed']:08x}",
            "info",
        )

    footprint = data.get("import_footprint") or {}
    if footprint.get("loader_only"):
        add(
            "Import footprint",
            "kernel32 loader-only (LoadLibrary/GetProcAddress) — packer/shellcode loader",
            "bad",
        )
    elif footprint.get("is_kernel32_only"):
        add("Import footprint", "only kernel32.dll imported — packer-style", "bad")

    rsrc_types = data.get("resource_types") or {}
    if rsrc_types.get("autoit"):
        add(
            "AutoIt script",
            "AU3! marker found in RT_RCDATA — AutoIt-compiled",
            "bad",
        )
    if rsrc_types.get("largest_rcdata", 0) >= 256 * 1024:
        add(
            "Large RT_RCDATA",
            f"{rsrc_types['largest_rcdata']} bytes — embedded payload likely",
            "warn",
        )
    if rsrc_types.get("types"):
        type_summary = ", ".join(
            f"{k}={v}"
            for k, v in sorted(
                rsrc_types["types"].items(), key=lambda kv: -kv[1]
            )[:6]
        )
        add("Resource types", type_summary, "info")

    installer = data.get("installer")
    if installer:
        add("Installer wrapper", installer, "warn")

    fwd = data.get("forwarded_exports") or 0
    if fwd:
        add(
            "Forwarded exports",
            f"{fwd} entry/entries forward to other DLLs",
            "info",
        )

    imphash = data.get("imphash") or ""
    if imphash:
        add("Imphash", imphash, "info")
    packers = data.get("packers_detected") or []
    if packers:
        add("Packer", ", ".join(packers), "bad")

    return rows
