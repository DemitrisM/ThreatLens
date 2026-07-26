"""Office Document Indicators panel — VBA macros, XLM macros,
template injection, OLE objects, oleid flags."""

from reporting.theme import CLASS_SEVERITY

from ._common import console
from ._render import Row, render_indicators

#: Kept at detail 0 even when it is ``info`` — it names what was parsed.
#: Previously inserted at index 0 after filtering, reordering the table.
_ALWAYS_SHOW = frozenset({"Format / Classification"})


def doc_rows(data: dict, detail_level: int = 0) -> list[Row]:
    """Build the Office indicator rows from a ``doc_analysis`` data dict."""
    if not data:
        return []

    rows: list[Row] = []

    fmt = data.get("format") or "?"
    classification = data.get("classification") or "CLEAN"
    class_sev = CLASS_SEVERITY.get(classification, "info")
    rows.append(
        Row("Format / Classification", f"{fmt.upper()} — {classification}", class_sev)
    )

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
        rows.append(Row("VBA macros", detail,
                     "bad" if auto and susp else "warn" if auto or susp else "info"))

        mr = vba.get("mraptor_flags") or {}
        if mr.get("suspicious"):
            rows.append(Row(
                "MacroRaptor",
                f"flagged (A={mr.get('autoexec', False)}, "
                f"W={mr.get('write', False)}, X={mr.get('execute', False)})",
                "bad" if mr.get("execute") else "warn",
            ))
        if vba.get("stomping_detected"):
            rows.append(Row("VBA stomping",
                         "source/p-code divergence detected (EvilClippy signature)",
                         "bad"))
        elif vba.get("stomping_check_performed") and detail_level >= 1:
            rows.append(Row("VBA stomping", "checked — none detected", "info"))
        if vba.get("modulestreamname_mismatch"):
            rows.append(Row("MODULESTREAMNAME",
                         "ASCII/Unicode mismatch in dir stream", "bad"))
        if vba.get("heavy_obfuscation"):
            rows.append(Row("VBA obfuscation",
                         "heavy (Chr/hex arithmetic pattern)", "warn"))

    xlm = (data.get("macros") or {}).get("xlm") or {}
    if xlm.get("performed"):
        if xlm.get("present"):
            exec_found = xlm.get("exec_call_found", False)
            urls = xlm.get("urls") or []
            cells = xlm.get("cell_count", 0)
            detail = f"{cells} deobfuscated cell(s)"
            if exec_found:
                detail += ", EXEC/CALL/FORMULA.FILL found"
            if urls:
                detail += f", {len(urls)} URL(s)"
            rows.append(Row("XLM (Excel 4.0) macros",
                         detail,
                         "bad" if exec_found else "warn" if urls else "info"))
        elif detail_level >= 1:
            rows.append(Row("XLM macros", "none detected", "info"))

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
        rows.append(Row("Template injection (OOXML)",
                     detail,
                     "bad" if non_ms or high else "warn"))
    alt_chunks = ti.get("alt_chunks") or []
    if alt_chunks:
        rows.append(Row("altChunk relationships",
                     f"{len(alt_chunks)} altChunk target(s)", "warn"))
    rtf_templates = ti.get("rtf") or []
    if rtf_templates:
        remote = [t for t in rtf_templates if t.get("remote")]
        rows.append(Row("Template injection (RTF)",
                     f"{len(rtf_templates)} template ref(s)"
                     + (f", {len(remote)} remote" if remote else ""),
                     "bad" if remote else "warn"))

    ole = data.get("ole_objects") or {}
    eq = ole.get("equation_editor_candidates") or []
    if eq:
        rows.append(Row("Equation Editor OLE",
                     "; ".join(sorted(set(eq))[:3]),
                     "bad"))
    pkg = ole.get("package_objects") or []
    if pkg:
        exec_pkgs = [p for p in pkg if p.get("exec_ext")]
        detail = f"{len(pkg)} Package object(s)"
        if exec_pkgs:
            names = ", ".join(p.get("filename", "") for p in exec_pkgs[:3])
            detail += f" — executable drops: {names}"
        rows.append(Row("OLE Package",
                     detail,
                     "bad" if exec_pkgs else "warn"))
    if ole.get("raw_objupdate"):
        rows.append(Row("RTF \\objupdate",
                     "present — forces object load on open",
                     "warn"))
    if ole.get("ole_object_count"):
        rows.append(Row("Embedded OLE objects",
                     f"{ole['ole_object_count']} object stream(s)", "info"))

    oxf = data.get("openxml_findings") or {}
    dangerous = oxf.get("dangerous_embedded") or []
    if dangerous:
        names = [
            (d.get("name") if isinstance(d, dict) else str(d))
            for d in dangerous[:5]
        ]
        rows.append(Row("Dangerous embedded files",
                     ", ".join(names),
                     "bad"))
    if oxf.get("decompression_bomb"):
        rows.append(Row("Decompression bomb",
                     "OOXML container tripped ZIP ratio guard",
                     "bad"))

    oleid_rows = data.get("oleid_indicators") or []
    high_risk = [i for i in oleid_rows if str(i.get("risk", "")).upper() == "HIGH"]
    if high_risk and detail_level >= 1:
        names = ", ".join(i.get("name", "") for i in high_risk[:4])
        rows.append(Row("oleid HIGH-risk", names, "warn"))

    flags = data.get("indicator_flags") or []
    if flags and detail_level >= 1:
        rows.append(Row("Indicator flags",
                     ", ".join(flags),
                     "info"))

    return rows


def print_doc_indicators(module_results: list[dict], detail_level: int) -> None:
    """Office Document Indicators section."""
    doc = next((r for r in module_results if r.get("module") == "doc_analysis"), None)
    if not doc or doc.get("status") != "success":
        return
    data = doc.get("data") or {}
    if not data:
        return

    rows = doc_rows(data, detail_level)
    # Only the Format row means nothing was found — stay quiet unless verbose.
    if len(rows) <= 1 and detail_level < 1:
        return

    render_indicators(
        "Office Document Indicators",
        rows,
        detail_level,
        always_show=_ALWAYS_SHOW,
        console=console,
    )
