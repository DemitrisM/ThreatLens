"""OneNote Indicators context builder for the HTML template.

Mirrors ``reporting.terminal_reporter.onenote`` — returns a dict with
summary rows, fired rules, embedded blobs, embedded executables and
nested-pipeline summary rows. Severity values follow the same
convention as ``doc.py`` ({"bad", "warn", "info"}).
"""

from reporting.shared import human_size


_DANGEROUS_KINDS = frozenset({
    "pe", "elf", "macho", "msi", "lnk", "hta", "script", "chm",
})


def onenote_indicators(module_results: list[dict]) -> dict | None:
    on = next(
        (r for r in module_results if r.get("module") == "onenote_analysis"),
        None,
    )
    if not on or on.get("status") != "success":
        return None
    data = on.get("data") or {}
    if not data or data.get("blob_count") is None:
        return None

    classification = data.get("classification") or "CLEAN"
    sev = {
        "MALICIOUS": "bad",
        "SUSPICIOUS": "warn",
        "INFORMATIONAL": "info",
        "CLEAN": "info",
    }.get(classification, "info")

    summary_rows: list[dict] = []

    def _add(label: str, value: str, severity: str = "info") -> None:
        summary_rows.append(
            {"label": label, "value": value, "severity": severity}
        )

    _add("Classification", classification, sev)
    _add("Blob count", str(data.get("blob_count", 0)), "info")

    execs = data.get("embedded_executables") or []
    if execs:
        _add("VT forward-lookup",
             f"{len(execs)} embedded executable(s) queued", "warn")

    if data.get("encrypted_section"):
        _add("Encrypted section",
             "password-protected — content hidden from static triage", "warn")

    if not data.get("onestore_header_present"):
        _add("Header", "ONESTORE GUID absent — matched by extension", "warn")

    blobs = data.get("blobs") or []
    blob_rows = [
        {
            "offset": f"0x{b.get('offset', 0):08x}",
            "kind": b.get("kind", ""),
            "severity": "bad" if b.get("kind") in _DANGEROUS_KINDS else "info",
            "size": human_size(b.get("size") or 0),
            "label": b.get("label", ""),
            "md5": b.get("md5", ""),
            "sha256": b.get("sha256", ""),
        }
        for b in blobs
    ]

    embedded_rows = [
        {
            "name": e.get("name", ""),
            "type": e.get("type", ""),
            "size": human_size(e.get("size") or 0),
            "md5": e.get("md5", ""),
            "sha256": e.get("sha256", ""),
        }
        for e in execs
    ]

    nested_rows: list[dict] = []
    for child in data.get("nested") or []:
        report = child.get("report") or {}
        scoring = report.get("scoring") or {}
        offset = child.get("source_offset")
        nested_rows.append({
            "source_offset": f"0x{offset:08x}" if isinstance(offset, int) else "-",
            "kind": child.get("kind", ""),
            "sha256": child.get("sha256", ""),
            "final_score": scoring.get("final_score"),
            "risk_band": scoring.get("risk_band") or "-",
        })

    return {
        "summary_rows": summary_rows,
        "fired_rules": list(data.get("fired_rules") or []),
        "indicator_flags": list(data.get("indicator_flags") or []),
        "blobs": blob_rows,
        "embedded_executables": embedded_rows,
        "nested": nested_rows,
        "classification": classification,
    }
