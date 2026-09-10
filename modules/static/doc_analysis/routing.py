"""Office document format detection and file-type gating.

Classifies a document by its magic bytes (not the extension) so files
like ``AgentTesla.doc`` — actually RTF behind a .doc name — take the
RTF path instead of crashing olevba on the OLE path.

Design notes
------------
The two questions here are deliberately answered by different means, and
the asymmetry is the point.

*Should the module run at all* (``is_office_file``) is answered
generously: any Office extension is enough, whatever the bytes say. A
file named ``.doc`` that is really RTF, HTML or a PE **must** reach this
module, because the mismatch is itself the finding. Extension is checked
before libmagic so the common case costs no I/O, and a libmagic failure
degrades to False rather than raising.

*Which passes to run* (``detect_format``) is answered strictly, from the
first sixteen bytes only. Nothing downstream may guess from the name.

``is_xlm_candidate`` then narrows further using both, because
XLMMacroDeobfuscator is the slowest thing in a document scan and the
answer for a Word file is always "none". .xlsx is excluded: it cannot
carry macros of either kind, which is the whole reason .xlsm exists.

MAX_ZIP_UNCOMPRESSED and MAX_ZIP_RATIO live here rather than beside the
ZIP walker so that every future container check shares one budget instead
of inventing its own.
"""

from pathlib import Path

# Hard caps — reused by every sub-check to avoid memory blowups.
#
# The ratio guard catches the classic zip bomb, where one entry inflates
# enormously; the cumulative guard catches the flat variant, where a
# thousand modest entries add up. Both are needed — either alone is
# trivially sidestepped by choosing the other shape.
MAX_FILE_SIZE = 100 * 1024 * 1024            # 100 MiB
MAX_ZIP_UNCOMPRESSED = 300 * 1024 * 1024     # 300 MiB cumulative
MAX_ZIP_RATIO = 200                          # per-entry compression ratio

_OFFICE_MIMES = frozenset({
    "application/msword",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.ms-excel.sheet.macroEnabled.12",
    "application/vnd.ms-word.document.macroEnabled.12",
    "text/rtf",
    "application/rtf",
})

_OFFICE_EXTENSIONS = frozenset({
    ".doc", ".docx", ".docm",
    ".xls", ".xlsx", ".xlsm", ".xlsb",
    ".ppt", ".pptx", ".pptm",
    ".rtf",
})

_XLM_CANDIDATE_EXTS = frozenset({".xls", ".xlsm", ".xlsb"})


def is_office_file(file_path: Path) -> bool:
    """True if the file looks like an Office document by extension or MIME.

    Args:
        file_path: Candidate file.

    Returns:
        True if doc_analysis should run. Deliberately generous: the
        extension alone suffices, because a document whose bytes disagree
        with its name is exactly what this module exists to catch.
    """
    # Extension first — no I/O, and it is also the branch that admits the
    # disguised files. A libmagic lookup would reject those.
    if file_path.suffix.lower() in _OFFICE_EXTENSIONS:
        return True
    # libmagic is optional and its failure modes are varied (missing
    # library, unreadable file, unknown type), so the whole call degrades
    # to "not a document" rather than raising into the pipeline.
    try:
        import magic  # noqa: PLC0415
        mime = magic.from_file(str(file_path), mime=True)
        return mime in _OFFICE_MIMES
    except Exception:  # noqa: BLE001
        return False


def detect_format(file_path: Path) -> str:
    """Classify a document by magic bytes. Returns 'rtf' | 'ole' | 'openxml' | 'unknown'.

    Args:
        file_path: The document to classify.

    Returns:
        One of "rtf", "ole", "openxml", "unknown". "unknown" runs no passes
        at all, so a file that reaches it is reported on its file_intake
        metadata alone — which is correct for something merely named .doc.

    Sixteen bytes is enough for all three signatures and cheap enough to
    do unconditionally.
    """
    try:
        with file_path.open("rb") as fh:
            head = fh.read(16)
    except OSError:
        return "unknown"
    # "{\rtf" is the spec signature; the four-byte "{\rt" prefix also
    # admits the truncated and malformed headers that Word still opens and
    # that samples use precisely because parsers reject them.
    if head[:5] == b"{\\rtf" or head[:4] == b"{\\rt":
        return "rtf"
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    # PK\x03\x04 is a local file header, PK\x05\x06 an end-of-central-
    # directory record — the latter matches an empty archive, which is
    # still an OOXML container worth walking.
    if head[:4] == b"PK\x03\x04" or head[:4] == b"PK\x05\x06":
        return "openxml"
    return "unknown"


def is_xlm_candidate(file_path: Path, detected_format: str) -> bool:
    """True if this file should be fed to the XLM deobfuscator.

    Args:
        file_path:       The document.
        detected_format: Result of detect_format(), so the caller's single
                         magic-byte read is reused rather than repeated.

    Returns:
        True only for an Excel extension in a recognised container. Both
        conditions are required: the extension because the deobfuscator is
        the slowest pass and pointless on Word, the format because an .xls
        that is really RTF has nothing for it to read.
    """
    ext = file_path.suffix.lower()
    if ext not in _XLM_CANDIDATE_EXTS:
        return False
    # xlsb uses the OpenXML container; xls/xlsm can be either OLE (xls) or OpenXML (xlsm).
    return detected_format in ("ole", "openxml")
