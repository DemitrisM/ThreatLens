"""HTML smuggling analysis module — STUB.

Will analyse `.html` / `.htm` / `.svg` files used as malware delivery
wrappers (HTML smuggling). Planned indicators:

- Embedded base64 blob + ``atob()`` reconstruction pattern
- Anchor tags with auto-download (`<a download=...>` driven by JS)
- Inline JS exploit patterns (eval, unescape, ActiveXObject)
- Suspicious form actions / external script sources
- Integration with ``ioc_extractor`` for embedded URLs

Returns the standard module result dict. Currently a no-op skip so the
pipeline can register the module without crashing.

# TODO: Phase 3 — implement html_analysis
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def run(file_path: Path, config: dict) -> dict:
    """Stub — returns a standard skipped result."""
    return {
        "module": "html_analysis",
        "status": "skipped",
        "data": {},
        "score_delta": 0,
        "reason": "html_analysis not yet implemented (Phase 3 TODO)",
    }
