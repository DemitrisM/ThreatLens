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

Design notes
------------
Template injection is the technique that outlived the macro block: the
document itself carries no code, only a reference, so it survives content
scanning and mail filtering, and the payload arrives when Word resolves
the reference on open. Detection is therefore about *references*, not
content, which is why this pass reads the relationship graph rather than
the document body.

The OOXML walk is ordered deliberately. Bomb guards run first over the
whole entry list and return immediately if either trips, before a single
byte is decompressed — a container that is a bomb gets no further
analysis by design, since the alternative is analysing it. Embedded-file
inspection then runs over metadata only, and just the ``.rels`` entries
are ever read.

The XML is matched with a regex rather than parsed. That is not laziness:
an XML parser on adversarial input is itself an attack surface (entity
expansion, external entities), and the only fields needed here are two
attributes of a flat tag with no nesting to respect. A malformed
container therefore yields fewer relationships, never an exception.

The RTF path shares nothing with the OOXML path but its flags, and it
raises both template-injection flags for one directive. That is
intentional: ``{\\*\\template http://…}`` is simultaneously a
high-severity relationship *and* an external non-Microsoft target, so it
scores as both. On the OOXML side those two facts are independent — the
relationship type and the host are separate questions — which is why the
flags exist separately at all.
"""

import logging
import re
import zipfile
from pathlib import Path
from urllib.parse import urlparse

from .routing import MAX_ZIP_RATIO, MAX_ZIP_UNCOMPRESSED

logger = logging.getLogger(__name__)

# Hosts treated as trusted template sources. An attachedTemplate pointing
# at SharePoint or Office Online is how the feature is legitimately used;
# anywhere else is the attack. Matched as exact host or parent domain, so
# "evil.com/microsoft.com" and "microsoft.com.evil.com" both fail it.
_MS_DOMAINS = (
    "microsoft.com",
    "office.com",
    "officeapps.live.com",
    "sharepoint.com",
    "live.com",
)

# Relationship types that cause Word to fetch and *render* the target
# rather than merely referencing it. Any other external relationship is
# scored MEDIUM: a hyperlink to a remote host is normal in a document,
# while an attached template on one is not.
_HIGH_REL_KEYWORDS = ("attachedtemplate", "oleobject", "frame", "subdocument")

# Extensions with no legitimate reason to be inside an Office container.
# .rtf leads the list because embedding an RTF inside a .docx via altChunk
# is the standard route to reach the RTF-only exploit surface from a file
# that presents as a modern Word document.
#
# Note .lnk is detected here and scored blind — the container handoff to
# lnk_analysis is a planned follow-up recorded in CLAUDE.md, and this is
# one of the three sites it will change.
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

    Args:
        file_path: An OOXML container, confirmed by magic bytes upstream.


    Returns a dict with:
      - ``alt_chunks`` — altChunk relationship targets
      - ``external_relationships`` — [{type, target, severity, non_microsoft_url}]
      - ``embedded_files``, ``dangerous_embedded`` — any risky files in the ZIP
      - ``ole_objects`` — inline OLE streams in the container
      - ``decompression_bomb`` — guard tripped
      - ``indicator_flags`` — set of scoring flags

    Never raises: a malformed container sets ``malformed_openxml`` and
    returns what it managed to collect, since a .docx that will not open
    cleanly is itself a finding.
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
            # infolist() reads the central directory only — sizes and
            # ratios below are metadata, so the bomb guards run without
            # decompressing anything.
            infos = zf.infolist()
            # Both guards return immediately rather than continuing with
            # what was safe to read. A container that trips them is not a
            # document to be analysed carefully; it is one to be put down.
            total_uncompressed = 0
            for info in infos:
                total_uncompressed += info.file_size
                # The 1 MiB floor keeps small, highly compressible entries
                # — an XML file of repeated whitespace, which every Office
                # document contains — from tripping the ratio guard.
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

            # Embedded-file inspection, still metadata-only: names and
            # extensions from the central directory, nothing extracted.
            for info in infos:
                name_lower = info.filename.lower()
                ext = Path(name_lower).suffix
                if ext in _DANGEROUS_EMBEDDED_EXTS:
                    out["embedded_files"].append(info.filename)
                    out["dangerous_embedded"].append(
                        {"name": info.filename, "ext": ext}
                    )
                    out["indicator_flags"].add("dangerous_embedded_file")
                # word/embeddings/ is where OOXML stores OLE streams, and
                # they are conventionally named oleObject1.bin — hence both
                # tests, since either alone misses a renamed variant.
                if "embeddings/" in name_lower or name_lower.endswith(".bin"):
                    out["ole_objects"].append(info.filename)
            if out["ole_objects"]:
                out["indicator_flags"].add("ole_object_in_container")

            # Relationship scan — the only entries whose contents are
            # read, and the reason the bomb guards had to run first.
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
    # A container that will not open is flagged; any other failure is
    # logged and swallowed, because the passes that already ran have
    # produced findings worth keeping.
    except zipfile.BadZipFile:
        logger.info("OpenXML container %s is malformed", file_path.name)
        out["indicator_flags"].add("malformed_openxml")
    except Exception as exc:  # noqa: BLE001
        logger.debug("OpenXML rels inspection failed: %s", exc)

    return out


def _scan_rels_content(content: str, out: dict) -> None:
    """Extract indicators from one .rels document.

    Args:
        content: Decoded XML text of a single relationship part.
        out:     The result dict, mutated in place — several .rels files
                 contribute to one set of findings, so accumulating in the
                 caller's dict is simpler than merging returns.

    Returns:
        None.

    The three checks are independent and a single relationship may satisfy
    more than one: an external oleObject is both a HIGH-severity external
    relationship and an embedded OLE object, and is recorded as both.
    """
    for m in _REL_TAG_RE.finditer(content):
        rel = m.group()
        rel_lower = rel.lower()
        target = _extract_attr(rel, "Target")
        rtype = _extract_attr(rel, "Type")

        # altChunk imports another document's content wholesale at open
        # time. Both spellings appear in the wild — the relationship type
        # is aFChunk, but the element is altChunk, and samples reference
        # either casing.
        if "/afchunk" in rel_lower or "/altchunk" in rel_lower:
            out["alt_chunks"].append(target)
            out["indicator_flags"].add("altchunk")
            if target.startswith("/") or target.startswith("\\"):
                out["indicator_flags"].add("altchunk_absolute_path")

        # TargetMode="External" is the whole tell: an internal target
        # points inside the container, an external one reaches the network
        # or a UNC path when the document opens.
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
    """Read one double-quoted attribute out of a relationship tag.

    Args:
        xml_tag: The matched ``<Relationship …>`` tag text.
        name:    Attribute name, matched case-sensitively as OOXML writes
                 it ("Target", "Type").

    Returns:
        The attribute value, or "" when absent. An absent Target is normal
        for a malformed or truncated part, and the callers treat "" as
        "nothing to report" rather than as an error.
    """
    pat = re.compile(rf'{name}="([^"]*)"')
    m = pat.search(xml_tag)
    return m.group(1) if m else ""


def _is_non_microsoft(target: str) -> bool:
    """Return True if the target URL points to a non-Microsoft host.

    Args:
        target: The relationship's Target attribute, which may be a URL, a
                UNC path, or a container-relative path.

    Returns:
        True when the target reaches a host that is not Microsoft's. A
        relative path returns False — it points inside the container, so
        there is no host to distrust — and so does an unparseable target,
        since the severity tier has already been recorded separately.
    """
    if not target:
        return False
    # A UNC path is checked before urlparse because it has no scheme for
    # urlparse to work with, and it is the most interesting case here: a
    # \\host\share template also leaks NTLM credentials to that host on
    # open, independently of whatever it serves back.
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
    """Scan raw RTF bytes for ``{\\*\\template <URL>}`` directives.

    Args:
        raw: The document's bytes. Only the first 2 MiB are scanned — the
             control word appears in the header, and an RTF that hides one
             megabytes deep has bigger problems than this pass.

    Returns:
        ``{"templates": [{"target", "remote"}], "indicator_flags": set}``.

    Decoded latin-1 because RTF is a byte format with no declared encoding
    and latin-1 maps every byte, so a target containing arbitrary bytes is
    displayable rather than a decode error. A local template target is
    recorded but not flagged: it is how the feature legitimately works.
    """
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
