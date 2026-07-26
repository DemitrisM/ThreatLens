"""PDF Indicators — auto-execute triggers, JavaScript, URIs, encryption.

``pdf_analysis`` scored files long before anything rendered its findings.

Note the auto-execute triggers live inside ``raw_keyword_hits``, not as
top-level booleans. Assuming otherwise is what made the triage ``A`` flag
dead code, so this builder reads the dict the module actually emits.
"""

from ._common import LIMITS, console
from ._render import Row, render_indicators

#: Kept at detail 0 even when quiet — it says what was parsed.
_ALWAYS_SHOW = frozenset({"Version"})

#: PDF keys that cause something to run without user action, worst first.
_AUTOEXEC_KEYWORDS: tuple[str, ...] = ("/OpenAction", "/AA", "/Launch")

#: Other keywords worth naming when present.
_NOTABLE_KEYWORDS: tuple[str, ...] = (
    "/JS",
    "/JavaScript",
    "/EmbeddedFile",
    "/RichMedia",
    "/XFA",
    "/AcroForm",
    "/GoToE",
    "/GoToR",
    "/SubmitForm",
    "/ObjStm",
)


def pdf_rows(data: dict, detail_level: int = 0) -> list[Row]:
    """Build PDF indicator rows from a ``pdf_analysis`` data dict."""
    if not data:
        return []

    rows: list[Row] = []
    hits = data.get("raw_keyword_hits") or {}

    if not data.get("parsed", True):
        errors = data.get("peepdf_errors") or []
        rows.append(
            Row(
                "Parse",
                "peepdf could not parse this file"
                + (f" — {'; '.join(str(e) for e in errors[:2])}" if errors else ""),
                "warn",
            )
        )

    if data.get("header_mismatch"):
        rows.append(
            Row(
                "Header mismatch",
                "content is not a PDF despite the extension",
                "bad",
            )
        )

    fired = [(k, hits[k]) for k in _AUTOEXEC_KEYWORDS if hits.get(k)]
    if fired:
        rows.append(
            Row(
                "Auto-execute",
                ", ".join(f"{k} ×{n}" for k, n in fired),
                "bad",
            )
        )

    if data.get("has_javascript"):
        count = data.get("javascript_count") or 0
        snippets = data.get("javascript_code") or []
        detail = f"{count} block(s)" if count else "present"
        if snippets:
            snippet = str(snippets[0]).replace("\n", " ").strip()
            cap = LIMITS["reason_chars"]
            if detail_level < 2 and len(snippet) > cap:
                snippet = snippet[: cap - 3] + "..."
            detail += f" — {snippet}"
        rows.append(Row("JavaScript", detail, "bad"))

    if data.get("encrypted"):
        rows.append(
            Row("Encryption", "document is encrypted — content may be hidden", "warn")
        )

    suspicious = data.get("suspicious_elements") or []
    if suspicious:
        names = [
            (s.get("name") if isinstance(s, dict) else str(s)) for s in suspicious
        ]
        rows.append(Row("Suspicious elements", ", ".join(str(n) for n in names), "bad"))

    other = [(k, hits[k]) for k in _NOTABLE_KEYWORDS if hits.get(k)]
    if other:
        rows.append(
            Row(
                "Keywords",
                ", ".join(f"{k} ×{n}" for k, n in other),
                "warn" if detail_level < 1 else "info",
            )
        )

    uris = data.get("uris") or []
    urls = data.get("urls") or []
    combined = list(dict.fromkeys([*uris, *urls]))
    if combined:
        shown = combined if detail_level >= 1 else combined[: LIMITS["iocs_per_type"]]
        detail = ", ".join(str(u) for u in shown)
        if len(combined) > len(shown):
            detail += f"  (+{len(combined) - len(shown)} more)"
        rows.append(Row("URIs", detail, "warn"))
    elif data.get("num_uris"):
        rows.append(Row("URIs", f"{data['num_uris']} present", "info"))

    if detail_level >= 1:
        if data.get("num_objects"):
            rows.append(Row("Objects", str(data["num_objects"]), "info"))
        if data.get("num_streams"):
            rows.append(Row("Streams", str(data["num_streams"]), "info"))

    if data.get("version"):
        rows.append(Row("Version", str(data["version"]), "info"))

    return rows


def print_pdf_indicators(module_results: list[dict], detail_level: int) -> None:
    """PDF Indicators section."""
    result = next(
        (r for r in module_results if r.get("module") == "pdf_analysis"), None
    )
    if not result or result.get("status") != "success":
        return
    render_indicators(
        "PDF Indicators",
        pdf_rows(result.get("data") or {}, detail_level),
        detail_level,
        always_show=_ALWAYS_SHOW,
        console=console,
    )
