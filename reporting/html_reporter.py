"""HTML report generator using Jinja2.

Renders a self-contained HTML report (inline CSS, no external deps)
with summary header, score breakdown, MITRE ATT&CK table, IOC table,
suspicious strings, capa capabilities, VirusTotal results, module
timing, recommendations, and collapsible raw module data sections.

Mirrors the structure and section ordering of the terminal reporter
so the two outputs stay in sync.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_TEMPLATE_NAME = "report.html.j2"
_TOOL_VERSION = "0.2.0"

# IOC type → (display label, CSS key)
_IOC_LABELS = {
    "ipv4":         ("IP Address",   "ipv4"),
    "url":          ("URL",          "url"),
    "domain":       ("Domain",       "domain"),
    "registry_key": ("Registry Key", "registry_key"),
    "email":        ("Email",        "email"),
    "windows_path": ("File Path",    "windows_path"),
}


def write_html_report(report: dict, output_dir: Path) -> Path:
    """Render *report* as a self-contained HTML file in *output_dir*.

    Args:
        report:     Complete report dict returned by ``run_pipeline()``.
        output_dir: Directory to write the HTML file into (created if
                    it does not exist).

    Returns:
        Path to the written HTML file.

    Raises:
        ImportError: If Jinja2 is not installed.
    """
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except ImportError as exc:
        logger.error("jinja2 not installed — cannot generate HTML report")
        raise ImportError(
            "jinja2 is required for HTML reports. Install with: pip install jinja2"
        ) from exc

    output_dir.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "j2", "html.j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template(_TEMPLATE_NAME)

    context = _build_context(report)
    html = template.render(**context)

    source_name = Path(report.get("file", "unknown")).stem
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = output_dir / f"{source_name}_{timestamp}.html"

    with out_path.open("w", encoding="utf-8") as fh:
        fh.write(html)

    logger.info("HTML report written to %s", out_path)
    return out_path


# ---------------------------------------------------------------------------
# Context construction
# ---------------------------------------------------------------------------


def _build_context(report: dict) -> dict:
    """Translate the raw pipeline report into the template context dict."""
    module_results = report.get("module_results", [])
    scoring = report.get("scoring", {}) or {}
    timing = report.get("timing", {}) or {}
    file_path = report.get("file", "unknown")

    return {
        "tool_version": _TOOL_VERSION,
        "generated_utc": datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "elapsed_seconds": timing.get("elapsed_seconds", 0.0),
        "file_name": Path(file_path).name,

        "file_info": _file_info(module_results, file_path),
        "scoring": scoring,
        "verdict": _build_verdict(module_results, scoring),
        "module_results": _module_results_for_template(module_results),
        "pe_indicators": _pe_indicators(module_results),
        "doc_indicators": _doc_indicators(module_results),

        "attack_mappings": _attack_mappings(module_results),
        "iocs_flat": _iocs_flat(module_results),
        "ioc_total": _ioc_total(module_results),
        "suspicious_strings": _suspicious_strings(module_results),
        "capabilities": _capabilities(module_results),
        "scored_categories": _scored_categories(module_results),
        "virustotal": _virustotal(module_results),
        "timing_rows": _timing_rows(module_results),
        "recommendations": _recommendations(module_results, scoring),
        "raw_modules": _raw_modules(module_results),
    }


def _file_info(module_results: list[dict], file_path: str) -> dict:
    """Return the flattened file_info dict the template expects."""
    intake = next(
        (r for r in module_results if r.get("module") == "file_intake"), None
    )
    fallback = {
        "file_name": Path(file_path).name,
        "file_path": str(file_path),
        "file_size_human": "—",
        "type_description": "Unknown",
        "mime_type": "Unknown",
        "md5": "N/A",
        "sha256": "N/A",
        "tlsh": "",
        "ssdeep": "",
    }
    if not intake or intake.get("status") != "success":
        return fallback

    data = intake.get("data", {}) or {}
    hashes = data.get("hashes", {}) or {}
    ft = data.get("file_type", {}) or {}

    return {
        "file_name": data.get("file_name") or Path(file_path).name,
        "file_path": data.get("file_path") or str(file_path),
        "file_size_human": _human_size(data.get("file_size", 0)),
        "type_description": ft.get("description", "Unknown"),
        "mime_type": ft.get("mime_type", "Unknown"),
        "md5": hashes.get("md5") or "N/A",
        "sha256": hashes.get("sha256") or "N/A",
        "tlsh": hashes.get("tlsh") or "",
        "ssdeep": hashes.get("ssdeep") or "",
    }


def _module_results_for_template(module_results: list[dict]) -> list[dict]:
    """Slim down module results to just the fields the table needs."""
    rows = []
    for r in module_results:
        rows.append(
            {
                "module": r.get("module", "unknown"),
                "status": r.get("status", "unknown"),
                "score_delta": r.get("score_delta", 0),
                "reason": r.get("reason", ""),
            }
        )
    return rows


def _pe_indicators(module_results: list[dict]) -> list[dict]:
    """Build the PE Structural Indicators rows for the HTML report.

    Mirrors the logic in terminal_reporter._print_pe_indicators so the
    HTML and terminal outputs surface the same set of indicators.
    Each row is ``{label, value, severity}`` with severity in
    {"bad", "warn", "info"}.
    """
    pe = next(
        (r for r in module_results if r.get("module") == "pe_analysis"), None
    )
    if not pe or pe.get("status") != "success":
        return []
    data = pe.get("data", {}) or {}

    rows: list[dict] = []

    def add(label: str, value: str, severity: str) -> None:
        rows.append({"label": label, "value": value, "severity": severity})

    # Compiled language fingerprint
    lang = data.get("compiled_language")
    if lang:
        add(
            "Compiled language",
            {"go": "Go", "rust": "Rust", "nim": "Nim"}.get(lang, lang),
            "info",
        )

    # Sections + entropy summary
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

    # RWX + TLS callbacks
    rwx = data.get("rwx_sections") or []
    if rwx:
        add("RWX sections", ", ".join(rwx), "bad")
    if data.get("has_tls_callbacks"):
        add("TLS callbacks", "present (pre-main code execution)", "warn")

    # DLL characteristics — only show when one of ASLR/DEP/CFG is missing
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

    # Entry-point validation
    ep = data.get("entry_point_section") or {}
    if ep.get("anomaly"):
        add(
            "Entry point",
            f"in '{ep.get('section') or '<none>'}' (not standard code section)",
            "bad",
        )

    # Section size mismatch (VirtualSize >> RawSize → packed code)
    sm = data.get("section_size_mismatch") or {}
    if sm.get("count"):
        add(
            "Section size mismatch",
            f"{sm['count']} section(s): {', '.join(sm.get('names', []))}",
            "bad",
        )

    # Process-injection / hollowing API combo
    hollow = data.get("hollowing_apis") or []
    if len(hollow) >= 2:
        add(
            "Process-injection APIs",
            f"{len(hollow)} hollowing-pattern APIs imported: "
            f"{', '.join(hollow[:4])}",
            "bad",
        )

    # API category diversity
    cats = data.get("api_categories") or []
    if cats:
        if len(cats) >= 4:
            sev = "bad"
        elif len(cats) >= 3:
            sev = "warn"
        else:
            sev = "info"
        add("API behaviour categories", f"{len(cats)}: {', '.join(cats)}", sev)

    # Overlay
    overlay = data.get("overlay") or {}
    if overlay.get("size"):
        ent = overlay.get("entropy", 0) or 0
        add(
            "Overlay",
            f"{overlay['size']} bytes, entropy {ent:.2f}",
            "bad" if ent >= 7.0 else "info",
        )

    # Resources
    rsrc = data.get("resources") or {}
    if rsrc.get("present"):
        ent = rsrc.get("entropy", 0) or 0
        size = rsrc.get("size", 0) or 0
        add(
            "Resources (.rsrc)",
            f"{size} bytes, entropy {ent:.2f}",
            "bad" if rsrc.get("high_entropy") else "info",
        )

    # Embedded MZ payload
    emb = data.get("embedded_pe")
    if emb:
        add(
            "Embedded PE payload",
            f"{emb.get('where')} @ offset 0x{(emb.get('offset') or 0):x}",
            "bad",
        )

    # Rich header / DOS stub
    rich = data.get("rich_header") or {}
    if rich:
        if not rich.get("present"):
            add("Rich header", "absent (non-MS toolchain)", "info")
        elif rich.get("corrupted"):
            add("Rich header", "present but corrupted", "warn")
    dos = data.get("dos_stub") or {}
    if dos.get("modified"):
        add("MS-DOS stub", "modified from default", "warn")

    # PDB debug path
    debug = data.get("debug_info") or {}
    pdb = debug.get("pdb_path") or ""
    if pdb:
        sev = "bad" if debug.get("suspicious_pdb") else "info"
        add("PDB debug path", pdb, sev)
        if debug.get("pdb_username"):
            add("PDB username leak", debug["pdb_username"], "warn")

    # Version info impersonation / metadata
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

    # Authenticode certificate hint
    cert = data.get("certificate") or {}
    if cert.get("present"):
        cn = cert.get("common_name") or "(unknown CN)"
        issuer = cert.get("issuer_hint") or ""
        add(
            "Authenticode signer",
            f"CN={cn}" + (f" via {issuer}" if issuer else ""),
            "info",
        )

    # Dynamic API resolution markers (GetProcAddress pattern)
    dyn = data.get("dynamic_api_resolution") or {}
    if (dyn.get("count") or 0) >= 5:
        sample = ", ".join(dyn.get("apis", [])[:5])
        add(
            "Dynamic API resolution",
            f"{dyn['count']} suspicious APIs as raw strings only "
            f"(GetProcAddress pattern): {sample}",
            "warn",
        )

    # Section permission anomalies (writable .text, exec .data, …)
    perm = data.get("section_permission_anomalies") or []
    if perm:
        add("Section permissions", ", ".join(perm[:4]), "bad")

    # PE OptionalHeader checksum
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

    # Imported-DLL footprint
    footprint = data.get("import_footprint") or {}
    if footprint.get("loader_only"):
        add(
            "Import footprint",
            "kernel32 loader-only (LoadLibrary/GetProcAddress) — packer/shellcode loader",
            "bad",
        )
    elif footprint.get("is_kernel32_only"):
        add("Import footprint", "only kernel32.dll imported — packer-style", "bad")

    # Resource type breakdown + AutoIt
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

    # Installer wrapper
    installer = data.get("installer")
    if installer:
        add("Installer wrapper", installer, "warn")

    # Forwarded exports
    fwd = data.get("forwarded_exports") or 0
    if fwd:
        add(
            "Forwarded exports",
            f"{fwd} entry/entries forward to other DLLs",
            "info",
        )

    # Imphash + packers
    imphash = data.get("imphash") or ""
    if imphash:
        add("Imphash", imphash, "info")
    packers = data.get("packers_detected") or []
    if packers:
        add("Packer", ", ".join(packers), "bad")

    return rows


def _doc_indicators(module_results: list[dict]) -> list[dict]:
    """Build the Office Document Indicators rows for the HTML report.

    Mirrors ``terminal_reporter._print_doc_indicators`` so the HTML and
    terminal outputs surface the same set of indicators. Each row is
    ``{label, value, severity}`` with severity in {"bad", "warn", "info"}.
    """
    doc = next(
        (r for r in module_results if r.get("module") == "doc_analysis"), None
    )
    if not doc or doc.get("status") != "success":
        return []
    data = doc.get("data", {}) or {}
    if not data:
        return []

    rows: list[dict] = []

    def add(label: str, value: str, severity: str) -> None:
        rows.append({"label": label, "value": value, "severity": severity})

    fmt = data.get("format") or "?"
    classification = data.get("classification") or "CLEAN"
    class_sev = {
        "MALICIOUS": "bad",
        "SUSPICIOUS": "warn",
        "INFORMATIONAL": "info",
        "CLEAN": "info",
    }.get(classification, "info")
    add("Format / Classification", f"{fmt.upper()} — {classification}", class_sev)

    vba = (data.get("macros") or {}).get("vba") or {}
    if vba.get("present"):
        count = vba.get("count", 0)
        auto = vba.get("auto_exec_keywords", []) or []
        susp = vba.get("suspicious_keywords", []) or []
        detail = f"{count} stream(s)"
        if auto:
            detail += (
                f", auto-exec: "
                f"{', '.join((a.get('keyword') if isinstance(a, dict) else str(a)) for a in auto[:3])}"
            )
        if susp:
            detail += f", {len(susp)} suspicious keyword(s)"
        add("VBA macros", detail,
            "bad" if auto and susp else "warn" if auto or susp else "info")

        mr = vba.get("mraptor_flags") or {}
        if mr.get("suspicious"):
            add(
                "MacroRaptor",
                f"flagged (A={mr.get('autoexec', False)}, "
                f"W={mr.get('write', False)}, X={mr.get('execute', False)})",
                "bad" if mr.get("execute") else "warn",
            )
        if vba.get("stomping_detected"):
            add("VBA stomping",
                "source/p-code divergence detected (EvilClippy signature)",
                "bad")
        if vba.get("modulestreamname_mismatch"):
            add("MODULESTREAMNAME",
                "ASCII/Unicode mismatch in dir stream", "bad")
        if vba.get("heavy_obfuscation"):
            add("VBA obfuscation",
                "heavy (Chr/hex arithmetic pattern)", "warn")

    xlm = (data.get("macros") or {}).get("xlm") or {}
    if xlm.get("performed") and xlm.get("present"):
        exec_found = xlm.get("exec_call_found", False)
        urls = xlm.get("urls") or []
        cells = xlm.get("cell_count", 0)
        detail = f"{cells} deobfuscated cell(s)"
        if exec_found:
            detail += ", EXEC/CALL/FORMULA.FILL found"
        if urls:
            detail += f", {len(urls)} URL(s)"
        add("XLM (Excel 4.0) macros", detail,
            "bad" if exec_found else "warn" if urls else "info")

    ti = data.get("template_injection") or {}
    ooxml_rels = ti.get("ooxml") or []
    if ooxml_rels:
        high = [r for r in ooxml_rels if str(r.get("severity", "")).lower() == "high"]
        non_ms = [r for r in ooxml_rels if r.get("non_microsoft_url")]
        detail = f"{len(ooxml_rels)} external relationship(s)"
        if high:
            detail += f", {len(high)} HIGH"
        if non_ms:
            detail += f", {len(non_ms)} non-Microsoft"
        add("Template injection (OOXML)", detail,
            "bad" if non_ms or high else "warn")
    alt_chunks = ti.get("alt_chunks") or []
    if alt_chunks:
        add("altChunk relationships",
            f"{len(alt_chunks)} altChunk target(s)", "warn")
    rtf_templates = ti.get("rtf") or []
    if rtf_templates:
        remote = [t for t in rtf_templates if t.get("remote")]
        add("Template injection (RTF)",
            f"{len(rtf_templates)} template ref(s)"
            + (f", {len(remote)} remote" if remote else ""),
            "bad" if remote else "warn")

    ole = data.get("ole_objects") or {}
    eq = ole.get("equation_editor_candidates") or []
    if eq:
        add("Equation Editor OLE",
            "; ".join(sorted(set(eq))[:3]),
            "bad")
    pkg = ole.get("package_objects") or []
    if pkg:
        exec_pkgs = [p for p in pkg if p.get("exec_ext")]
        detail = f"{len(pkg)} Package object(s)"
        if exec_pkgs:
            names = ", ".join(p.get("filename", "") for p in exec_pkgs[:3])
            detail += f" — executable drops: {names}"
        add("OLE Package", detail,
            "bad" if exec_pkgs else "warn")
    if ole.get("raw_objupdate"):
        add("RTF \\objupdate",
            "present — forces object load on open",
            "warn")
    if ole.get("ole_object_count"):
        add("Embedded OLE objects",
            f"{ole['ole_object_count']} object stream(s)", "info")

    oxf = data.get("openxml_findings") or {}
    dangerous = oxf.get("dangerous_embedded") or []
    if dangerous:
        names = [
            (d.get("name") if isinstance(d, dict) else str(d))
            for d in dangerous[:5]
        ]
        add("Dangerous embedded files",
            ", ".join(names),
            "bad")
    if oxf.get("decompression_bomb"):
        add("Decompression bomb",
            "OOXML container tripped ZIP ratio guard",
            "bad")

    oleid_rows = data.get("oleid_indicators") or []
    high_risk = [i for i in oleid_rows if str(i.get("risk", "")).upper() == "HIGH"]
    if high_risk:
        names = ", ".join(i.get("name", "") for i in high_risk[:4])
        add("oleid HIGH-risk", names, "warn")

    return rows


def _attack_mappings(module_results: list[dict]) -> list[dict]:
    capa = next(
        (r for r in module_results if r.get("module") == "capa_analysis"), None
    )
    if not capa or capa.get("status") != "success":
        return []
    mappings = (capa.get("data", {}) or {}).get("attack_mappings", []) or []
    return sorted(
        mappings,
        key=lambda m: (m.get("tactic", ""), m.get("technique_id", "")),
    )


def _iocs_flat(module_results: list[dict]) -> list[dict]:
    """Flatten IOCs into rows: [{type_key, label, value}, ...]."""
    ioc_result = next(
        (r for r in module_results if r.get("module") == "ioc_extractor"), None
    )
    if not ioc_result or ioc_result.get("status") != "success":
        return []
    iocs = (ioc_result.get("data", {}) or {}).get("iocs", {}) or {}
    rows = []
    for ioc_type, values in iocs.items():
        if not values:
            continue
        label, key = _IOC_LABELS.get(ioc_type, (ioc_type, ioc_type))
        for val in values:
            rows.append({"type_key": key, "label": label, "value": val})
    return rows


def _ioc_total(module_results: list[dict]) -> int:
    ioc_result = next(
        (r for r in module_results if r.get("module") == "ioc_extractor"), None
    )
    if not ioc_result or ioc_result.get("status") != "success":
        return 0
    return (ioc_result.get("data", {}) or {}).get("total_iocs", 0)


def _suspicious_strings(module_results: list[dict]) -> list[dict]:
    str_result = next(
        (r for r in module_results if r.get("module") == "string_analysis"), None
    )
    if not str_result or str_result.get("status") != "success":
        return []
    return (str_result.get("data", {}) or {}).get("suspicious_matches", []) or []


def _capabilities(module_results: list[dict]) -> list[str]:
    capa = next(
        (r for r in module_results if r.get("module") == "capa_analysis"), None
    )
    if not capa or capa.get("status") != "success":
        return []
    return (capa.get("data", {}) or {}).get("capabilities", []) or []


def _scored_categories(module_results: list[dict]) -> list[dict]:
    capa = next(
        (r for r in module_results if r.get("module") == "capa_analysis"), None
    )
    if not capa or capa.get("status") != "success":
        return []
    return (capa.get("data", {}) or {}).get("scored_categories", []) or []


def _virustotal(module_results: list[dict]) -> dict | None:
    vt = next(
        (r for r in module_results if r.get("module") == "virustotal"), None
    )
    if not vt or vt.get("status") != "success":
        return None
    data = vt.get("data", {}) or {}

    if not data.get("found"):
        return {
            "found": False,
            "sha256": data.get("sha256", ""),
            "permalink": data.get("permalink", ""),
        }

    malicious = data.get("malicious", 0) or 0
    suspicious = data.get("suspicious", 0) or 0
    detections = malicious + suspicious

    if detections > 10:
        detection_class = "delta-pos"
    elif detections >= 1:
        detection_class = "ioc-url"  # yellow
    else:
        detection_class = "delta-neg"

    first_seen = data.get("first_seen")
    if isinstance(first_seen, (int, float)):
        try:
            first_seen = datetime.fromtimestamp(
                first_seen, tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M UTC")
        except (OSError, ValueError):
            first_seen = str(first_seen)

    return {
        "found": True,
        "detection_ratio": data.get(
            "detection_ratio",
            f"{detections}/{data.get('total_engines', 0)}",
        ),
        "detection_class": detection_class,
        "threat_label": data.get("threat_label") or "",
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": data.get("undetected", 0) or 0,
        "first_seen": first_seen or "",
        "community_score": data.get("community_score"),
        "permalink": data.get("permalink", ""),
    }


def _timing_rows(module_results: list[dict]) -> list[dict]:
    rows = [
        {
            "module": r.get("module", "unknown"),
            "elapsed": r.get("elapsed_seconds", 0.0) or 0.0,
            "status": r.get("status", "unknown"),
        }
        for r in module_results
        if "elapsed_seconds" in r
    ]
    rows.sort(key=lambda r: r["elapsed"], reverse=True)
    return rows


def _recommendations(module_results: list[dict], scoring: dict) -> list[str]:
    """Build context-aware recommendations — mirrors terminal_reporter."""
    recs: list[str] = []
    sha256 = ""

    for result in module_results:
        module = result.get("module", "")
        status = result.get("status", "")
        data = result.get("data", {}) or {}

        if module == "file_intake" and status == "success":
            sha256 = (data.get("hashes", {}) or {}).get("sha256", "")

        elif module == "ioc_extractor" and status == "success":
            iocs = data.get("iocs", {}) or {}
            ips = iocs.get("ipv4", []) or []
            domains = iocs.get("domain", []) or []
            if ips:
                recs.append(f"Investigate IP(s): {', '.join(ips[:3])}")
            if domains:
                recs.append(
                    f"Check network logs for connections to: {', '.join(domains[:3])}"
                )

        elif module == "virustotal":
            if status == "skipped" and sha256:
                recs.append(f"Submit SHA256 to VirusTotal: {sha256[:16]}…")
            elif status == "success" and data.get("found"):
                detections = (data.get("malicious", 0) or 0) + (
                    data.get("suspicious", 0) or 0
                )
                if detections > 10:
                    label = data.get("threat_label", "")
                    suffix = f" ({label})" if label else ""
                    recs.append(
                        f"VirusTotal confirms malicious — {detections} engines flagged{suffix}"
                    )
            elif status == "error":
                reason = result.get("reason", "")
                if "rate limit" in reason.lower():
                    recs.append(
                        "VirusTotal rate limit hit — wait 60s or use --skip virustotal"
                    )
                elif sha256:
                    recs.append(
                        f"VirusTotal lookup failed — manually check: {sha256[:16]}…"
                    )

        elif module == "capa_analysis" and status == "skipped":
            reason = result.get("reason", "")
            if "timeout" in reason.lower() or "timed out" in reason.lower():
                recs.append("capa timed out — try --deep for extended timeout (180s)")

        elif module == "pe_analysis" and status == "success":
            if data.get("packers_detected"):
                recs.append("Binary is packed — consider unpacking before re-analysis")

    band = scoring.get("risk_band", "LOW")
    if band in ("HIGH", "CRITICAL"):
        recs.append(
            "Consider dynamic analysis (--dynamic speakeasy) for runtime behaviour"
        )

    return recs


def _build_verdict(module_results: list[dict], scoring: dict) -> str:
    """Auto-generated verdict sentence — mirrors terminal_reporter._build_verdict."""
    indicators: list[str] = []

    for result in module_results:
        if result.get("status") != "success" or result.get("score_delta", 0) == 0:
            continue
        data = result.get("data", {}) or {}
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
            for cat in data.get("scored_categories", []) or []:
                name = (cat.get("category", "") or "").lower()
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
            iocs = data.get("iocs", {}) or {}
            if iocs.get("url") or iocs.get("ipv4"):
                indicators.append("network IOC indicators")

        elif module == "virustotal":
            if data.get("found"):
                detections = (data.get("malicious", 0) or 0) + (
                    data.get("suspicious", 0) or 0
                )
                if detections > 10:
                    label = data.get("threat_label")
                    indicators.append(
                        f"VirusTotal: {detections} engines flagged"
                        + (f" ({label})" if label else "")
                    )
                elif detections >= 1:
                    indicators.append("low VirusTotal detections")

        elif module == "string_analysis":
            for cat in data.get("suspicious_categories", []) or []:
                cat_l = cat.lower()
                if "password" in cat_l or "credential" in cat_l:
                    indicators.append("credential references")
                elif "base64" in cat_l:
                    indicators.append("encoded data")

    seen = set()
    unique = []
    for ind in indicators:
        if ind not in seen:
            seen.add(ind)
            unique.append(ind)

    if not unique:
        return ""

    if len(unique) == 1:
        body = unique[0]
    elif len(unique) == 2:
        body = f"{unique[0]} and {unique[1]}"
    else:
        body = ", ".join(unique[:4])
        if len(unique) > 4:
            body += f" (+{len(unique) - 4} more)"

    band = scoring.get("risk_band", "LOW")
    prefix = {
        "CRITICAL": "High-confidence threat",
        "HIGH": "Likely malicious",
        "MEDIUM": "Suspicious binary",
    }.get(band, "Low-risk file")
    return f"{prefix} with {body}"


def _raw_modules(module_results: list[dict]) -> list[dict]:
    """Serialise each module's full result as JSON for the collapsible section.

    Strips API keys and other sensitive fields.
    """
    out = []
    for r in module_results:
        sanitised = dict(r)
        data = sanitised.get("data")
        if isinstance(data, dict):
            sanitised["data"] = {
                k: v
                for k, v in data.items()
                if k not in ("api_key", "virustotal_api_key")
            }
        try:
            text = json.dumps(sanitised, indent=2, default=str)
        except (TypeError, ValueError) as exc:
            logger.warning(
                "Could not serialise module %s for HTML raw view: %s",
                r.get("module", "unknown"),
                exc,
            )
            text = f"<unserialisable: {exc}>"
        out.append(
            {
                "module": r.get("module", "unknown"),
                "status": r.get("status", "unknown"),
                "json": text,
            }
        )
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _human_size(nbytes: int) -> str:
    """Format byte count as a human-readable string."""
    n = float(nbytes or 0)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"
