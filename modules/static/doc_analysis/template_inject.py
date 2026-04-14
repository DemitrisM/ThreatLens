"""Template injection detection.

OOXML path: parse every ``*.rels`` file inside the ZIP container and
record relationships with ``TargetMode="External"``. Relationship types
known to pull and render untrusted content (``attachedTemplate``,
``oleObject``, ``frame``, ``subDocument``) are tagged HIGH severity;
any other external reference is tagged MEDIUM. Targets whose host is
not a Microsoft/Office domain raise the ``non_microsoft_url`` flag that
feeds the combo scoring engine.

RTF path: regex scan for ``{\\*\\template <URL>}`` — the RTF-specific
template-injection primitive independent of ZIP structure.

Also captures altChunk/aFChunk relationships (classic embed-RTF-inside-
docx template-injection vector) and dangerous embedded file extensions.
"""

import logging
import re
import zipfile
from pathlib import Path
from urllib.parse import urlparse

from .routing import MAX_ZIP_RATIO, MAX_ZIP_UNCOMPRESSED

logger = logging.getLogger(__name__)

_MS_DOMAINS = (
    "microsoft.com",
    "office.com",
    "officeapps.live.com",
    "sharepoint.com",
    "live.com",
)

_HIGH_REL_KEYWORDS = ("attachedtemplate", "oleobject", "frame", "subdocument")

_DANGEROUS_EMBEDDED_EXTS = frozenset({
    ".rtf", ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".hta", ".lnk", ".jar", ".wsf", ".com", ".inf",
})

_RTF_TEMPLATE_RE = re.compile(
    rb"\{\s*\\\*\\template\s+([^}]+)\}", re.IGNORECASE
)
_REL_TAG_RE = re.compile(r"<Relationship[^>]+>")
_ATTR_RE = re.compile(r'{name}="([^"]*)"')


def analyse_openxml_rels(file_path: Path) -> dict:
    """Walk the OOXML ZIP and extract template-injection indicators.

    Returns a dict with:
      - ``alt_chunks`` — altChunk relationship targets
      - ``external_relationships`` — [{type, target, severity, non_microsoft_url}]
      - ``embedded_files``, ``dangerous_embedded`` — any risky files in the ZIP
      - ``ole_objects`` — inline OLE streams in the container
      - ``decompression_bomb`` — guard tripped
      - ``indicator_flags`` — set of scoring flags
    """
    out: dict = {
        "alt_chunks": [],
        "external_relationships": [],
        "embedded_files": [],
        "dangerous_embedded": [],
        "ole_objects": [],
        "decompression_bomb": False,
        "indicator_flags": set(),
    }

    try:
        with zipfile.ZipFile(str(file_path)) as zf:
            infos = zf.infolist()
            total_uncompressed = 0
            for info in infos:
                total_uncompressed += info.file_size
                if info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                    if ratio > MAX_ZIP_RATIO and info.file_size > 1024 * 1024:
                        logger.warning(
                            "doc_analysis: suspicious compression ratio %.1f for %s",
                            ratio, info.filename,
                        )
                        out["decompression_bomb"] = True
                        out["indicator_flags"].add("decompression_bomb")
                        return out
            if total_uncompressed > MAX_ZIP_UNCOMPRESSED:
                logger.warning(
                    "doc_analysis: cumulative zip size %d over cap",
                    total_uncompressed,
                )
                out["decompression_bomb"] = True
                out["indicator_flags"].add("decompression_bomb")
                return out

            # Embedded-file inspection
            for info in infos:
                name_lower = info.filename.lower()
                ext = Path(name_lower).suffix
                if ext in _DANGEROUS_EMBEDDED_EXTS:
                    out["embedded_files"].append(info.filename)
                    out["dangerous_embedded"].append(
                        {"name": info.filename, "ext": ext}
                    )
                    out["indicator_flags"].add("dangerous_embedded_file")
                if "embeddings/" in name_lower or name_lower.endswith(".bin"):
                    out["ole_objects"].append(info.filename)
            if out["ole_objects"]:
                out["indicator_flags"].add("ole_object_in_container")

            # Relationship scan
            for info in infos:
                if not info.filename.endswith(".rels"):
                    continue
                if info.file_size > 512 * 1024:
                    continue
                try:
                    content = zf.read(info.filename).decode("utf-8", errors="replace")
                except Exception:  # noqa: BLE001
                    continue
                _scan_rels_content(content, out)
    except zipfile.BadZipFile:
        logger.info("OpenXML container %s is malformed", file_path.name)
        out["indicator_flags"].add("malformed_openxml")
    except Exception as exc:  # noqa: BLE001
        logger.debug("OpenXML rels inspection failed: %s", exc)

    return out


def _scan_rels_content(content: str, out: dict) -> None:
    for m in _REL_TAG_RE.finditer(content):
        rel = m.group()
        rel_lower = rel.lower()
        target = _extract_attr(rel, "Target")
        rtype = _extract_attr(rel, "Type")

        if "/afchunk" in rel_lower or "/altchunk" in rel_lower:
            out["alt_chunks"].append(target)
            out["indicator_flags"].add("altchunk")
            if target.startswith("/") or target.startswith("\\"):
                out["indicator_flags"].add("altchunk_absolute_path")

        if 'targetmode="external"' in rel_lower:
            severity = "MEDIUM"
            rtype_lower = (rtype or "").lower()
            if any(k in rtype_lower for k in _HIGH_REL_KEYWORDS):
                severity = "HIGH"
            non_ms = _is_non_microsoft(target)
            out["external_relationships"].append({
                "type": rtype,
                "target": target,
                "severity": severity,
                "non_microsoft_url": non_ms,
            })
            if severity == "HIGH":
                out["indicator_flags"].add("template_inject_high")
            if non_ms:
                out["indicator_flags"].add("template_inject_non_ms")

        if "/oleobject" in rel_lower:
            out["ole_objects"].append(target or "<inline>")
            out["indicator_flags"].add("ole_object_in_container")


def _extract_attr(xml_tag: str, name: str) -> str:
    pat = re.compile(rf'{name}="([^"]*)"')
    m = pat.search(xml_tag)
    return m.group(1) if m else ""


def _is_non_microsoft(target: str) -> bool:
    """Return True if the target URL points to a non-Microsoft host."""
    if not target:
        return False
    if target.startswith("\\\\") or target.startswith("//"):
        # UNC / protocol-relative — not a trusted MS host.
        return True
    try:
        parsed = urlparse(target)
    except ValueError:
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    return not any(host == d or host.endswith("." + d) for d in _MS_DOMAINS)


def analyse_rtf_template(raw: bytes) -> dict:
    """Scan raw RTF bytes for ``{\\*\\template <URL>}`` directives."""
    out: dict = {
        "templates": [],
        "indicator_flags": set(),
    }
    for match in _RTF_TEMPLATE_RE.finditer(raw[: 2 * 1024 * 1024]):
        target = match.group(1).decode("latin-1", errors="replace").strip()
        if not target:
            continue
        remote = target.lower().startswith(("http://", "https://", "ftp://", "\\\\"))
        out["templates"].append({"target": target, "remote": remote})
        if remote:
            out["indicator_flags"].add("template_inject_non_ms")
            out["indicator_flags"].add("template_inject_high")
    return out
