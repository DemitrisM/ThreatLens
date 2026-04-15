"""Archive Indicators context builder for the HTML template.

Mirrors ``reporting.terminal_reporter.archive`` — returns a dict with
summary fields, fired-rule list, dangerous members, embedded execs
and nested-archive summary rows. Severity values follow the same
convention as ``doc.py`` ({"bad", "warn", "info"}).
"""

from reporting.shared import human_size


def archive_indicators(module_results: list[dict]) -> dict | None:
    arc = next(
        (r for r in module_results if r.get("module") == "archive_analysis"),
        None,
    )
    if not arc or arc.get("status") != "success":
        return None
    data = arc.get("data") or {}
    if not data or not data.get("detected_format"):
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

    _add("Format", (data.get("detected_format") or "?").upper(), "info")
    _add("Classification", classification, sev)
    _add("Entries", str(data.get("entry_count", 0)), "info")
    _add("Total size",
         human_size(data.get("total_uncompressed_size", 0)), "info")

    enc = data.get("encryption") or {}
    if enc.get("header_encrypted"):
        _add("Encryption", "header-encrypted", "bad")
    elif enc.get("is_encrypted"):
        _add("Encryption", "per-file encrypted", "warn")

    bomb = data.get("bomb_guard") or {}
    if bomb.get("triggered"):
        reasons = ", ".join(bomb.get("reasons") or []) or "triggered"
        _add("Bomb guard", reasons, "bad")

    sfx = data.get("sfx") or {}
    if sfx.get("is_sfx"):
        _add("SFX payload",
             f"{sfx.get('embedded_format')} @ offset {sfx.get('offset')}",
             "bad")

    if data.get("ace_detected"):
        _add("ACE archive", "detected — extraction refused", "bad")

    if data.get("recursion_depth_reached"):
        _add("Recursion", "depth cap reached", "warn")

    dangerous_rows = [
        {
            "name": m.get("name", ""),
            "extension": m.get("extension", ""),
            "size": human_size(m.get("size") or 0),
        }
        for m in (data.get("dangerous_members") or [])[:50]
    ]

    embedded_rows = [
        {
            "name": e.get("name", ""),
            "type": e.get("type", ""),
            "size": human_size(e.get("size") or 0),
            "md5": e.get("md5", ""),
            "sha256": e.get("sha256", ""),
        }
        for e in (data.get("embedded_executables") or [])
    ]

    nested_rows: list[dict] = []
    for child in data.get("nested") or []:
        cdata = child.get("data") or child.get("report") or {}
        nested_rows.append({
            "name": child.get("nested_member_name") or child.get("name") or "?",
            "format": (cdata.get("detected_format") or "").upper(),
            "classification": cdata.get("classification") or "-",
            "score_delta": child.get("score_delta"),
        })

    return {
        "summary_rows": summary_rows,
        "fired_rules": list(data.get("fired_rules") or []),
        "indicator_flags": list(data.get("indicator_flags") or []),
        "dangerous_members": dangerous_rows,
        "embedded_executables": embedded_rows,
        "nested": nested_rows,
        "classification": classification,
    }
