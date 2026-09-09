"""File intake module — type detection and hashing.

Uses python-magic for true file-type identification (not extension-based),
generates MD5, SHA256, and TLSH fuzzy hashes, and returns structured
file metadata for downstream modules.

Design notes
------------
This is the first module the pipeline runs and the only one that always
returns ``score_delta: 0``. It is a metadata provider, not a detector: every
later module reads the MIME type it publishes to decide whether it applies
at all, so an intake failure degrades the whole scan and is reported as
``status: "error"`` rather than swallowed.

Type detection is content-based on purpose. Malware routinely ships a PE
named ``invoice.pdf``; trusting the extension is exactly the mistake the
tool exists to catch. The extension map at the bottom of ``_detect_file_type``
is a last resort for machines without libmagic, not the primary path.
"""

import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# Optional dependencies.
#
# Each import is guarded separately so the three capabilities degrade
# independently: a box without libmagic still gets SHA256, and a box
# without TLSH still gets type detection. Design rule 2 forbids letting a
# missing dependency abort the pipeline, so these set a flag and warn
# instead of raising.
# ----------------------------------------------------------------------
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
    # ppdeep is a pure-Python reimplementation with the same hash() API.
    # It is slower but needs no C extension, which is what makes the tool
    # installable on a locked-down lab machine.
    try:
        import ppdeep as ssdeep  # Pure-python fallback

        _HAS_SSDEEP = True
    except ImportError:
        _HAS_SSDEEP = False
        logger.warning("ssdeep/ppdeep not available — ssdeep fuzzy hashing disabled")


# 64 KiB read chunks. Large enough to keep syscall overhead negligible,
# small enough that a multi-gigabyte sample never lands in memory.
_BUF_SIZE = 65536  # 64 KiB read chunks for hashing


def _compute_hashes(file_path: Path) -> dict:
    """Compute MD5, SHA256, and (optionally) TLSH and ssdeep hashes.

    Args:
        file_path: Path to the file to hash. Must exist and be readable;
                   the caller is responsible for that check.

    Returns:
        A dict with keys ``md5``, ``sha256``, ``tlsh`` and ``ssdeep``.
        Unavailable or inapplicable hashes are set to None rather than
        omitted, so downstream consumers can index the dict blindly.

    Raises:
        OSError: propagated from the read loop; ``run()`` catches it.
    """
    # ------------------------------------------------------------------
    # Step 1: Prepare the hashers.
    #
    # MD5 is retained despite being cryptographically broken because
    # VirusTotal, MalwareBazaar and most published IOC lists are still
    # keyed on it — the noqa marks it as a deliberate interop choice, not
    # an oversight.
    # ------------------------------------------------------------------
    md5 = hashlib.md5()  # noqa: S324
    sha256 = hashlib.sha256()

    if _HAS_TLSH:
        tlsh_hasher = tlsh.Tlsh()
    else:
        tlsh_hasher = None

    # ------------------------------------------------------------------
    # Step 2: Stream the file once, feeding every hasher from the same
    # chunk. Reading the file three times would triple the I/O on the
    # large samples where it actually matters.
    # ------------------------------------------------------------------
    with file_path.open("rb") as fh:
        while True:
            chunk = fh.read(_BUF_SIZE)
            if not chunk:
                break
            md5.update(chunk)
            sha256.update(chunk)
            if tlsh_hasher is not None:
                tlsh_hasher.update(chunk)

    # ------------------------------------------------------------------
    # Step 3: Finalise TLSH.
    #
    # TLSH is a similarity digest, not a checksum: it needs roughly 50
    # bytes of input with enough variance to produce a value at all, and
    # signals failure by raising from final(). A tiny file is a normal
    # outcome here, so this is a debug line rather than a warning.
    # ------------------------------------------------------------------
    tlsh_digest = None
    if tlsh_hasher is not None:
        try:
            tlsh_hasher.final()
            tlsh_digest = tlsh_hasher.hexdigest()
        except ValueError:
            # TLSH requires a minimum amount of data (~50 bytes).
            logger.debug("File too small for TLSH hashing")

    # ------------------------------------------------------------------
    # Step 4: ssdeep, which has no streaming API in either backend and so
    # needs the whole file in memory. It is deliberately last and
    # separately guarded: a MemoryError or backend quirk on a huge sample
    # costs only the fuzzy hash, not the MD5/SHA256 already computed.
    # ------------------------------------------------------------------
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

    Args:
        file_path: Path to the file to identify.

    Returns:
        A dict with keys ``mime_type`` and ``description``. Always
        populated — an unidentifiable file yields
        ``application/octet-stream``.
    """
    # ------------------------------------------------------------------
    # Preferred path: content-based identification via libmagic.
    #
    # Two calls are needed because python-magic returns either the MIME
    # type or the prose description, never both from one invocation.
    # ------------------------------------------------------------------
    if _HAS_MAGIC:
        try:
            mime_type = magic.from_file(str(file_path), mime=True)
            description = magic.from_file(str(file_path))
            return {"mime_type": mime_type, "description": description}
        except Exception as exc:  # noqa: BLE001
            logger.warning("python-magic detection failed: %s", exc)

    # ------------------------------------------------------------------
    # Fallback path: extension guess, used only when libmagic is absent
    # or threw. Trusting the extension is precisely the weakness this
    # module normally avoids, so the map covers just the nine types the
    # pipeline can route on, and anything unlisted is reported honestly
    # as unknown rather than guessed at.
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # Step 1: Reject anything that is not a regular file.
    #
    # This is an error, not a skip: every later module depends on the
    # metadata produced here, so a scan that cannot read its own target
    # must not go on to report a clean verdict (design rule 10).
    # ------------------------------------------------------------------
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
        # --------------------------------------------------------------
        # Step 2: Gather size, hashes and type.
        #
        # file_path.resolve() is stored rather than the argument as given
        # so the report records an unambiguous absolute path even when
        # the user scanned via a relative path or a symlink.
        # --------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # Step 3: Convert I/O failure into a standard error result.
    #
    # Only OSError is caught. A bug inside this module should surface as
    # a traceback during development rather than be disguised as an
    # unreadable file.
    # ------------------------------------------------------------------
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
    """Format byte count as a human-readable string.

    Args:
        nbytes: Size in bytes.

    Returns:
        The size with a binary unit suffix, e.g. ``"1.5 MiB"``. Binary
        units (KiB/MiB) are used rather than decimal because they match
        what the section-size fields inside a PE actually mean.
    """
    for unit in ("B", "KiB", "MiB", "GiB"):
        if nbytes < 1024:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024
    return f"{nbytes:.1f} TiB"
