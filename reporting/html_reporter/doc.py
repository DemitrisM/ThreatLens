"""Office Document Indicators table rows for the HTML template.

Mirrors ``reporting.terminal_reporter.doc`` so the HTML and terminal
outputs surface the same set of indicators.  Each row is
``{label, value, severity}`` with severity in {"bad", "warn", "info"}.
"""


def doc_indicators(module_results: list[dict]) -> list[dict]:
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
