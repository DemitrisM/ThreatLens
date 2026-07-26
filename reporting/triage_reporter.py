"""Triage sweep output — a score table, not a stack of per-file reports.

Triage is a different output *shape* from ``scan``, not a quieter one:
it selects which file to look at next, then ``scan -v`` investigates it.
The same escalation pdfid → pdf-parser uses.

Rows sort by score descending so the file that matters is the first line.
The legend lists only the flag letters that actually fired in this run —
a fixed legend is noise on a sweep where most letters never appear.
"""

from pathlib import Path
from typing import Final, NamedTuple

from rich import box
from rich.console import Console
from rich.table import Table

from reporting.console import out
from reporting.theme import rich_style


class Flag(NamedTuple):
    """One triage flag letter and what it means."""

    letter: str
    description: str


#: Flag letters in the order they appear in the legend. Derived entirely
#: from module results — triage runs no analysis of its own.
FLAGS: Final[dict[str, Flag]] = {
    "S": Flag("S", "suspicious strings"),
    "I": Flag("I", "network IOCs"),
    "Y": Flag("Y", "YARA rule hit"),
    "M": Flag("M", "macro present"),
    "A": Flag("A", "auto-execute"),
    "P": Flag("P", "packer detected"),
    "V": Flag("V", "VirusTotal detections"),
    "E": Flag("E", "embedded executable"),
}


#: PDF dictionary keys that cause something to run without user action.
#: ``/JS`` alone is not one — JavaScript can sit in a form field and never
#: fire — so it is deliberately absent.
_PDF_AUTOEXEC_KEYWORDS: Final[tuple[str, ...]] = ("/OpenAction", "/AA", "/Launch")

#: Embedded blob kinds that make a container worth opening. Excludes
#: ``image`` and ``other``, which are the ordinary contents of a document.
_DANGEROUS_BLOB_KINDS: Final[frozenset[str]] = frozenset(
    {"pe", "elf", "macho", "msi", "lnk", "hta", "script", "chm", "ole"}
)


def _module(results: list[dict], name: str) -> dict | None:
    for result in results:
        if result.get("module") == name and result.get("status") == "success":
            return result
    return None


def derive_flags(module_results: list[dict]) -> set[str]:
    """Which flag letters this file earns.

    Reads only what the modules already reported — no new analysis.
    """
    flags: set[str] = set()
    if not module_results:
        return flags

    strings = _module(module_results, "string_analysis")
    if strings and (strings.get("score_delta") or 0) > 0:
        flags.add("S")

    ioc = _module(module_results, "ioc_extractor")
    if ioc:
        iocs = (ioc.get("data") or {}).get("iocs") or {}
        if iocs.get("url") or iocs.get("ipv4"):
            flags.add("I")

    yara = _module(module_results, "yara_scanner")
    if yara and (yara.get("data") or {}).get("matches"):
        flags.add("Y")

    doc = _module(module_results, "doc_analysis")
    if doc:
        data = doc.get("data") or {}
        vba = (data.get("macros") or {}).get("vba") or {}
        xlm = (data.get("macros") or {}).get("xlm") or {}
        if vba.get("present") or xlm.get("present"):
            flags.add("M")
        if vba.get("auto_exec_keywords"):
            flags.add("A")

    pdf = _module(module_results, "pdf_analysis")
    if pdf:
        data = pdf.get("data") or {}
        # pdf_analysis reports these inside raw_keyword_hits, not as
        # top-level booleans. Guessing `has_openaction`/`has_launch` here
        # made this branch dead code: booking.pdf carries /OpenAction and
        # embedded JS and still earned no flag.
        hits = data.get("raw_keyword_hits") or {}
        if any(hits.get(k) for k in _PDF_AUTOEXEC_KEYWORDS):
            flags.add("A")

    pe = _module(module_results, "pe_analysis")
    if pe and (pe.get("data") or {}).get("packers_detected"):
        flags.add("P")

    vt = _module(module_results, "virustotal")
    if vt:
        data = vt.get("data") or {}
        detections = (data.get("malicious") or 0) + (data.get("suspicious") or 0)
        if data.get("found") and detections >= 1:
            flags.add("V")

    for name in ("archive_analysis", "onenote_analysis"):
        mod = _module(module_results, name)
        if not mod:
            continue
        data = mod.get("data") or {}
        # A dropper is not always a PE. IcedID ships HTA blobs inside
        # OneNote, which leaves embedded_executables empty while the module
        # still reports contains_embedded_hta — so read the typed blobs and
        # the indicator flags too, or the whole family triages as clean.
        if data.get("embedded_executables"):
            flags.add("E")
        if any(
            b.get("kind") in _DANGEROUS_BLOB_KINDS for b in data.get("blobs") or []
        ):
            flags.add("E")
        if any(
            str(flag).startswith("contains_embedded_")
            for flag in data.get("indicator_flags") or []
        ):
            flags.add("E")

    return flags


def format_flags(flags: set[str]) -> str:
    """Flag letters in canonical order, space-separated."""
    return " ".join(letter for letter in FLAGS if letter in flags)


#: ``(substring of the libmagic description, label)``, first match wins.
#: Order matters — ``PE32+`` must be tested before ``PE32``.
_DESCRIPTION_TYPES: Final[tuple[tuple[str, str], ...]] = (
    ("PE32+", "PE32+"),
    ("PE32", "PE32"),
    ("MS-DOS executable", "DOS"),
    ("ELF", "ELF"),
    ("Mach-O", "MACHO"),
    ("RAR archive", "RAR"),
    ("7-zip", "7Z"),
    ("gzip compressed", "GZ"),
    ("bzip2 compressed", "BZ2"),
    ("XZ compressed", "XZ"),
    ("POSIX tar", "TAR"),
    ("Microsoft Cabinet", "CAB"),
    ("ISO 9660", "ISO"),
    ("PDF document", "PDF"),
    ("HTML document", "HTML"),
    ("Rich Text Format", "RTF"),
    ("Microsoft OneNote", "ONE"),
    ("MS Windows shortcut", "LNK"),
    ("Composite Document File", "OLE"),
)

#: Descriptions that name a family but not the specific format. libmagic
#: reports every macro-enabled workbook as "Microsoft Excel 2007+", so the
#: extension is what separates XLSM from XLSX, and DOCM from DOCX.
_AMBIGUOUS_DESCRIPTIONS: Final[tuple[str, ...]] = (
    "Microsoft Excel",
    "Microsoft Word",
    "Microsoft PowerPoint",
    "Microsoft OOXML",
    "Zip archive",
)


def _file_type(module_results: list[dict]) -> str:
    """Short format label for the TYPE column, e.g. PE32 / XLSM / ONE.

    The libmagic description wins over the extension, so a sample named
    ``invoice.pdf`` that is really HTML reads ``HTML`` — the mismatch is
    itself a finding. The extension is consulted only where the
    description names a family rather than a format.
    """
    intake = _module(module_results, "file_intake")
    if not intake:
        return "?"

    data = intake.get("data") or {}
    description = ((data.get("file_type") or {}).get("description")) or ""
    extension = Path(data.get("file_name") or "").suffix.lstrip(".").upper()

    if any(hint in description for hint in _AMBIGUOUS_DESCRIPTIONS):
        return extension or "OOXML"

    for needle, label in _DESCRIPTION_TYPES:
        if needle in description:
            return label

    return extension or (description.split(",")[0].split() or ["?"])[0][:6].upper()


def print_triage_table(
    reports: list[dict],
    failures: list[tuple[str, str]] | None = None,
    *,
    elapsed: float | None = None,
    console: Console | None = None,
) -> None:
    """Score table for a sweep, highest score first."""
    con = console or out
    failures = failures or []
    if not reports and not failures:
        con.print()
        con.print("  [dim]No files analysed.[/dim]")
        return

    rows = []
    seen_flags: set[str] = set()
    for report in reports:
        scoring = report.get("scoring") or {}
        results = report.get("module_results") or []
        flags = derive_flags(results)
        seen_flags |= flags
        rows.append(
            {
                "score": scoring.get("total_score", 0),
                "band": scoring.get("risk_band", "LOW"),
                "type": _file_type(results),
                "flags": format_flags(flags),
                "name": report.get("file_name")
                or Path(report.get("file", "?")).name,
            }
        )

    rows.sort(key=lambda r: r["score"], reverse=True)

    table = Table(box=box.SIMPLE, padding=(0, 1), pad_edge=False, header_style="dim")
    table.add_column("SCORE", justify="right", no_wrap=True)
    table.add_column("BAND", no_wrap=True)
    table.add_column("TYPE", no_wrap=True)
    table.add_column("FLAGS", no_wrap=True)
    table.add_column("FILE", overflow="fold")

    for row in rows:
        style = rich_style(row["band"].lower()) or "white"
        table.add_row(
            str(row["score"]),
            f"[{style}]{row['band']}[/{style}]",
            row["type"],
            row["flags"],
            row["name"],
        )

    for name, _reason in failures:
        table.add_row("[red]ERR[/red]", "[red]ERROR[/red]", "—", "", name)

    con.print()
    con.print(table)

    if seen_flags:
        con.print("  [bold]FLAGS SEEN[/bold]")
        for letter in FLAGS:
            if letter in seen_flags:
                con.print(f"  [bold]{letter}[/bold]  [dim]{FLAGS[letter].description}[/dim]")

    high = sum(1 for r in rows if r["band"] in ("HIGH", "CRITICAL"))
    summary = f"{len(rows)} file{'s' if len(rows) != 1 else ''}"
    if high:
        summary += f" · {high} at HIGH+"
    if failures:
        summary += f" · {len(failures)} failed"
    if elapsed is not None:
        summary += f" · {elapsed:.1f}s"
    con.print()
    con.print(f"  [dim]{summary}[/dim]")


__all__ = ["FLAGS", "derive_flags", "format_flags", "print_triage_table"]
