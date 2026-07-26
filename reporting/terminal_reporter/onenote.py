"""OneNote Indicators — summary rows, embedded blobs, and nested-pipeline
results when ``onenote_full_recursion`` is on.

``onenote_rows`` is pure. It replaces a hand-space-padded ``Panel`` whose
labels were aligned to column 17, with two rows padded to 19.
"""

from rich import box
from rich.table import Table

from reporting.shared import human_size
from reporting.theme import CLASS_SEVERITY, rich_style

from ._common import LIMITS, console
from ._render import Row, render_hash_list, render_indicators

#: Kept at detail 0 even though it is ``info`` — it says what was parsed.
_ALWAYS_SHOW = frozenset({"Classification"})

#: Blob kinds that are worth an analyst's attention on sight.
_NOISE_KINDS = frozenset({"image", "other"})


def nested_score(child: dict) -> int | None:
    """Score of a nested pipeline result.

    Reads ``total_score`` — the key ``core/scoring.py`` actually emits.
    This used to read ``final_score``, which no module produces, so the
    column always rendered ``-``.
    """
    report = child.get("report") or {}
    return (report.get("scoring") or {}).get("total_score")


def onenote_rows(data: dict, detail_level: int = 0) -> list[Row]:
    """Build the OneNote indicator rows from an ``onenote_analysis`` data dict."""
    if not data or data.get("blob_count") is None:
        return []

    rows: list[Row] = []
    classification = data.get("classification") or "CLEAN"
    rows.append(
        Row("Classification", classification, CLASS_SEVERITY.get(classification, "info"))
    )
    rows.append(Row("Blob count", str(data.get("blob_count", 0)), "info"))

    execs = data.get("embedded_executables") or []
    if execs:
        rows.append(
            Row(
                "VT forward-lookup",
                f"{len(execs)} embedded executable(s) queued",
                "warn",
            )
        )

    if data.get("encrypted_section"):
        rows.append(
            Row("Encrypted section", "password-protected — content hidden", "warn")
        )

    if not data.get("onestore_header_present"):
        rows.append(
            Row("Header", "ONESTORE GUID absent — parsed by extension", "warn")
        )

    for rule in data.get("fired_rules") or []:
        rows.append(Row("Fired rule", rule, "bad"))

    if detail_level >= 1:
        for flag in data.get("indicator_flags") or []:
            rows.append(Row("Flag", flag, "info"))

    return rows


def print_onenote_indicators(module_results: list[dict], detail_level: int = 0) -> None:
    """OneNote Structure Indicators section."""
    on = next(
        (r for r in module_results if r.get("module") == "onenote_analysis"), None
    )
    if not on or on.get("status") != "success":
        return
    data = on.get("data") or {}
    if not data or data.get("blob_count") is None:
        return

    render_indicators(
        "OneNote Structure Indicators",
        onenote_rows(data, detail_level),
        detail_level,
        always_show=_ALWAYS_SHOW,
        console=console,
    )
    _blobs(data, detail_level)
    _nested_tree(data)


def _blobs(data: dict, detail_level: int) -> None:
    """Embedded blobs, each SHA256 on its own unbroken line.

    At detail 0 the image/other noise is filtered out when anything more
    interesting exists; ``-v`` shows every blob.
    """
    blobs = data.get("blobs") or []
    if not blobs:
        return

    interesting = [b for b in blobs if b.get("kind") not in _NOISE_KINDS]
    selected = interesting if (interesting and detail_level < 1) else blobs

    entries = [
        (
            str(b.get("label") or f"0x{b.get('offset', 0):08x}"),
            f"{b.get('kind', 'other')}  {human_size(b.get('size') or 0)}  "
            f"@ 0x{b.get('offset', 0):08x}",
            b.get("sha256") or "",
        )
        for b in selected
    ]
    render_hash_list(
        "Embedded Blobs",
        entries,
        limit=None if detail_level >= 1 else LIMITS["onenote_blobs"],
        console=console,
    )


def _nested_tree(data: dict) -> None:
    """Children fed back through the full pipeline."""
    nested = data.get("nested") or []
    if not nested:
        return

    table = Table(
        title="[bold]OneNote Nested Pipeline Results[/bold]",
        box=box.ROUNDED,
        padding=(0, 1),
    )
    table.add_column("Source offset", no_wrap=True)
    table.add_column("Kind", no_wrap=True)
    table.add_column("Child score", justify="right", no_wrap=True)
    table.add_column("Band", no_wrap=True)

    for child in nested:
        score = nested_score(child)
        band = ((child.get("report") or {}).get("scoring") or {}).get("risk_band") or "-"
        # Colour by risk band. This used to index a map keyed by
        # MALICIOUS/SUSPICIOUS/..., which a LOW/MEDIUM/HIGH/CRITICAL band
        # could never match, so every row rendered white.
        style = rich_style(band.lower()) or "white"
        offset = child.get("source_offset")
        offset_str = f"0x{offset:08x}" if isinstance(offset, int) else "-"
        table.add_row(
            offset_str,
            str(child.get("kind", "")),
            str(score) if score is not None else "-",
            f"[{style}]{band}[/{style}]",
        )

    console.print()
    console.print(table)
