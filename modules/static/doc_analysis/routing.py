"""Office document format detection and file-type gating.

Classifies a document by its magic bytes (not the extension) so files
like ``AgentTesla.doc`` — actually RTF behind a .doc name — take the
RTF path instead of crashing olevba on the OLE path.
"""

from pathlib import Path

# Hard caps — reused by every sub-check to avoid memory blowups.
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
    """True if the file looks like an Office document by extension or MIME."""
    if file_path.suffix.lower() in _OFFICE_EXTENSIONS:
        return True
    try:
        import magic  # noqa: PLC0415
        mime = magic.from_file(str(file_path), mime=True)
        return mime in _OFFICE_MIMES
    except Exception:  # noqa: BLE001
        return False


def detect_format(file_path: Path) -> str:
    """Classify a document by magic bytes. Returns 'rtf' | 'ole' | 'openxml' | 'unknown'."""
    try:
        with file_path.open("rb") as fh:
            head = fh.read(16)
    except OSError:
        return "unknown"
    if head[:5] == b"{\\rtf" or head[:4] == b"{\\rt":
        return "rtf"
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    if head[:4] == b"PK\x03\x04" or head[:4] == b"PK\x05\x06":
        return "openxml"
    return "unknown"


def is_xlm_candidate(file_path: Path, detected_format: str) -> bool:
    """True if this file should be fed to the XLM deobfuscator."""
    ext = file_path.suffix.lower()
    if ext not in _XLM_CANDIDATE_EXTS:
        return False
    # xlsb uses the OpenXML container; xls/xlsm can be either OLE (xls) or OpenXML (xlsm).
    return detected_format in ("ole", "openxml")
