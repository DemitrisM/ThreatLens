"""File intake module — type detection and hashing.

Uses python-magic for true file-type identification (not extension-based),
generates MD5, SHA256, and TLSH fuzzy hashes, and returns structured
file metadata for downstream modules.
"""

import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Graceful imports — each optional dependency degrades independently.
try:
    import magic

    _HAS_MAGIC = True
except ImportError:
    _HAS_MAGIC = False
    logger.warning("python-magic not available — file type detection disabled")

try:
    import tlsh

    _HAS_TLSH = True
except ImportError:
    _HAS_TLSH = False
    logger.warning("tlsh not available — TLSH fuzzy hashing disabled")

try:
    import ssdeep

    _HAS_SSDEEP = True
except ImportError:
    try:
        import ppdeep as ssdeep  # Pure-python fallback

        _HAS_SSDEEP = True
    except ImportError:
        _HAS_SSDEEP = False
        logger.warning("ssdeep/ppdeep not available — ssdeep fuzzy hashing disabled")


_BUF_SIZE = 65536  # 64 KiB read chunks for hashing


def _compute_hashes(file_path: Path) -> dict:
    """Compute MD5, SHA256, and (optionally) TLSH and ssdeep hashes.

    Returns a dict with keys: md5, sha256, tlsh, ssdeep.
    Unavailable hashes are set to None.
    """
    md5 = hashlib.md5()  # noqa: S324
    sha256 = hashlib.sha256()

    if _HAS_TLSH:
        tlsh_hasher = tlsh.Tlsh()
    else:
        tlsh_hasher = None

    with file_path.open("rb") as fh:
        while True:
            chunk = fh.read(_BUF_SIZE)
            if not chunk:
                break
            md5.update(chunk)
            sha256.update(chunk)
            if tlsh_hasher is not None:
                tlsh_hasher.update(chunk)

    tlsh_digest = None
    if tlsh_hasher is not None:
        try:
            tlsh_hasher.final()
            tlsh_digest = tlsh_hasher.hexdigest()
        except ValueError:
            # TLSH requires a minimum amount of data (~50 bytes).
            logger.debug("File too small for TLSH hashing")

    ssdeep_digest = None
    if _HAS_SSDEEP:
        try:
            # Read file again for ssdeep — avoids holding entire file in
            # memory during the hash loop above.
            raw_bytes = file_path.read_bytes()
            ssdeep_digest = ssdeep.hash(raw_bytes)
        except Exception:  # noqa: BLE001
            logger.debug("ssdeep hashing failed")

    return {
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest(),
        "tlsh": tlsh_digest,
        "ssdeep": ssdeep_digest,
    }


def _detect_file_type(file_path: Path) -> dict:
    """Detect MIME type and human-readable description using libmagic.

    Returns a dict with keys: mime_type, description.
    Falls back to basic extension mapping if python-magic is unavailable.
    """
    if _HAS_MAGIC:
        try:
            mime_type = magic.from_file(str(file_path), mime=True)
            description = magic.from_file(str(file_path))
            return {"mime_type": mime_type, "description": description}
        except Exception as exc:  # noqa: BLE001
            logger.warning("python-magic detection failed: %s", exc)

    # Fallback: extension-based guess (better than nothing).
    suffix = file_path.suffix.lower()
    fallback_map = {
        ".exe": ("application/x-dosexec", "PE32 executable (Windows)"),
        ".dll": ("application/x-dosexec", "PE32 dynamic-link library"),
        ".doc": ("application/msword", "Microsoft Word document"),
        ".docx": (
            "application/vnd.openxmlformats-officedocument"
            ".wordprocessingml.document",
            "Microsoft Word document (OOXML)",
        ),
        ".xls": ("application/vnd.ms-excel", "Microsoft Excel spreadsheet"),
        ".pdf": ("application/pdf", "PDF document"),
        ".js": ("application/javascript", "JavaScript file"),
        ".vbs": ("text/vbscript", "VBScript file"),
        ".ps1": ("text/x-powershell", "PowerShell script"),
    }
    mime_type, description = fallback_map.get(
        suffix, ("application/octet-stream", "Unknown file type")
    )
    return {"mime_type": mime_type, "description": description}


def run(file_path: Path, _config: dict) -> dict:
    """Analyse the target file and return intake metadata.

    This is the first module in the pipeline. It produces no score_delta
    — its purpose is to populate file metadata that downstream modules
    rely on.

    Args:
        file_path: Path to the file under analysis.
        _config:   Pipeline configuration dict (unused by this module,
                   accepted for interface consistency).

    Returns:
        Standard module result dict.
    """
    logger.info("Running file intake on %s", file_path.name)

    if not file_path.is_file():
        logger.error("Target path does not exist or is not a file: %s", file_path)
        return {
            "module": "file_intake",
            "status": "error",
            "data": {},
            "score_delta": 0,
            "reason": f"File not found: {file_path}",
        }

    try:
        file_size = file_path.stat().st_size
        hashes = _compute_hashes(file_path)
        file_type = _detect_file_type(file_path)

        data = {
            "file_name": file_path.name,
            "file_path": str(file_path.resolve()),
            "file_size": file_size,
            "hashes": hashes,
            "file_type": file_type,
        }

        logger.info(
            "Intake complete — %s | %s | SHA256: %s",
            file_type["mime_type"],
            _human_size(file_size),
            hashes["sha256"],
        )

        return {
            "module": "file_intake",
            "status": "success",
            "data": data,
            "score_delta": 0,
            "reason": "File intake provides metadata only — no score contribution.",
        }

    except OSError as exc:
        logger.error("File intake failed (I/O error): %s", exc)
        return {
            "module": "file_intake",
            "status": "error",
            "data": {},
            "score_delta": 0,
            "reason": f"I/O error reading file: {exc}",
        }


def _human_size(nbytes: int) -> str:
    """Format byte count as a human-readable string."""
    for unit in ("B", "KiB", "MiB", "GiB"):
        if nbytes < 1024:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024
    return f"{nbytes:.1f} TiB"
