"""Zip / RAR archive analysis module — STUB.

Will analyse `.zip` and `.rar` containers commonly used as malware
delivery wrappers. Planned indicators:

- Dangerous extensions inside the archive (.exe / .dll / .scr / .lnk
  / .hta / .js / .vbs / .ps1 / .iso / .img / .msi)
- Password-protected archives (manual key delivered to victim — AV
  bypass technique)
- Embedded PE hashing (MD5 / SHA256 of inner binaries)
- Decompression-bomb guard (per-entry ratio cap, cumulative size cap)
- RAR support via the ``rarfile`` library + system ``unrar`` binary;
  graceful skip when ``unrar`` is not installed

Returns the standard module result dict. Currently a no-op skip so the
pipeline can register the module without crashing.

# TODO: Phase 3 — implement archive_analysis
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def run(file_path: Path, config: dict) -> dict:
    """Stub — returns a standard skipped result."""
    return {
        "module": "archive_analysis",
        "status": "skipped",
        "data": {},
        "score_delta": 0,
        "reason": "archive_analysis not yet implemented (Phase 3 TODO)",
    }
