"""TLS callbacks, overlay, entry point, embedded MZ payload search.

Design notes
------------
These four checks share a theme: they look at where code and data actually
live, rather than at what the file claims about itself. A packer can rename
sections and forge a timestamp cheaply, but it cannot avoid *putting the
payload somewhere* — appended as overlay, buried in .rsrc, or reached through
an execution path that starts before the entry point.

Every scan here is bounded. These functions run against attacker-controlled
files of arbitrary size, so each one caps how much it reads rather than
trusting a length field in the file.
"""

import struct

from .metadata import _DEFAULT_DOS_STUB
from .sections import _shannon_entropy

# ----------------------------------------------------------------------
# Authenticode certificate table.
#
# Index 4 of the optional header's data directory. Unlike every other
# entry, its VirtualAddress is a FILE OFFSET rather than an RVA: the
# certificate is not mapped into memory, so there is no RVA it could
# carry. Confirmed on real binaries - ShareTargets.dll's reads 838,656,
# which is exactly where its sections end.
#
# The table is a sequence of WIN_CERTIFICATE records, each
# 8-byte aligned: dwLength (u32, covering the 8-byte header too),
# wRevision (u16), wCertificateType (u16).
# ----------------------------------------------------------------------
_SECURITY_DIRECTORY_INDEX = 4
_WIN_CERT_HEADER = struct.Struct("<IHH")
_WIN_CERT_REVISIONS = frozenset({0x0100, 0x0200})
_WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002

#: Records are 8-byte aligned, and so is the table's own offset.
_WIN_CERT_ALIGNMENT = 8

#: A real Authenticode table holds one or two records. The cap exists
#: because the walk is driven by a length field the sample controls: an
#: overlay packed with minimum-size headers would otherwise spin through
#: millions of pure-Python iterations, which is the denial-of-service
#: this module's docstring says every scan here must bound.
_MAX_CERT_RECORDS = 32

#: DER: a constructed SEQUENCE, and the PKCS#7 signedData OID
#: (1.2.840.113549.1.7.2) that WIN_CERT_TYPE_PKCS_SIGNED_DATA promises.
_DER_SEQUENCE = 0x30
_PKCS7_SIGNED_DATA_OID = bytes(
    (0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02)
)

#: Entropy is characterised from a prefix rather than the whole overlay.
_ENTROPY_SAMPLE_BYTES = 1024 * 1024

#: IMAGE_FILE_DLL in FileHeader.Characteristics.
_IMAGE_FILE_DLL = 0x2000
#: IMAGE_SCN_MEM_EXECUTE in a section's Characteristics.
_IMAGE_SCN_MEM_EXECUTE = 0x20000000
#: Index of the TLS directory, whose callbacks the loader runs before
#: and independently of the entry point.
_TLS_DIRECTORY_INDEX = 9


def _has_tls_callbacks(pe: "pefile.PE") -> bool:
    """Detect whether the PE registers TLS callbacks.

    TLS callbacks run before the entry point and are commonly used
    by malware for anti-debugging (the debugger may not have control
    yet) and to defeat naive analysis tools that only look at the EP.

    Args:
        pe: A parsed ``pefile.PE`` object.

    Returns:
        True when a non-empty callback table is registered.
    """
    if not hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        return False
    try:
        tls = pe.DIRECTORY_ENTRY_TLS.struct
        # A TLS directory can exist purely for thread-local storage, with
        # no callbacks at all — that is ordinary and not worth reporting.
        if not getattr(tls, "AddressOfCallBacks", 0):
            return False
        # AddressOfCallBacks is a virtual address, not an RVA, so
        # ImageBase has to come off before pefile can resolve it.
        # Walk the callback array to confirm at least one entry.
        callback_rva = tls.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
        try:
            # The array is NULL-terminated by a single pointer, so the
            # read must be exactly one pointer wide. Reading a fixed 8
            # bytes on a 32-bit image would consume the 4-byte
            # terminator PLUS 4 bytes of whatever follows, and report a
            # callback whenever that trailing data happened to be
            # non-zero. Magic 0x20B is PE32+ (64-bit); anything else,
            # including a missing field, is treated as 32-bit.
            is_64bit = getattr(pe.OPTIONAL_HEADER, "Magic", 0x10B) == 0x20B
            pointer_size = 8 if is_64bit else 4
            data = pe.get_data(callback_rva, pointer_size)
            return any(b != 0 for b in data)
        except Exception:  # noqa: BLE001
            # We saw a callback table pointer — that alone is enough.
            return True
    except Exception:  # noqa: BLE001
        return False


def _der_length(raw: bytes, offset: int, limit: int) -> tuple[int, int] | None:
    """Decode one DER definite-form length.

    Args:
        raw:    The whole file.
        offset: Position of the length byte.
        limit:  One past the last byte that may be read.

    Returns:
        ``(value_length, bytes_consumed)``, or None when the encoding is
        indefinite, over-long or truncated. Indefinite form is rejected
        rather than followed: DER forbids it, so its presence means this
        is not the structure it claims to be.
    """
    if offset >= limit:
        return None
    first = raw[offset]
    if first < 0x80:
        return first, 1
    count = first & 0x7F
    # 0 is the indefinite form; more than four bytes is a length no
    # signature on disk needs and is not worth decoding.
    if count == 0 or count > 4 or offset + 1 + count > limit:
        return None
    return int.from_bytes(raw[offset + 1:offset + 1 + count], "big"), 1 + count


def _is_pkcs7_signature(raw: bytes, offset: int, length: int) -> bool:
    """Check that a WIN_CERTIFICATE body really holds a PKCS#7 signature.

    Args:
        raw:    The whole file.
        offset: Start of the record, at its 8-byte header.
        length: The record's ``dwLength``, header included.

    Returns:
        True when the body is a DER SEQUENCE carrying the signedData
        OID and spanning the record to within its alignment padding.

    Validating the header alone is not enough, and this is the
    difference between a fix and an evasion. The header is eight static
    bytes: an unsigned sample need only prepend
    ``struct.pack("<IHH", len(payload) + 8, 0x0200, 0x0002)`` to an
    encrypted payload and point the directory at it, and the whole
    payload is excised as a "signature". Requiring the body to parse as
    PKCS#7 means a spoof has to carry a real DER structure rather than
    eight bytes.
    """
    body = offset + _WIN_CERT_HEADER.size
    end = offset + length
    if body >= end or raw[body] != _DER_SEQUENCE:
        return False
    decoded = _der_length(raw, body + 1, end)
    if decoded is None:
        return False
    value_length, length_bytes = decoded
    total = 1 + length_bytes + value_length
    # The record is padded to an 8-byte boundary, so the DER structure
    # may fall short of dwLength by up to seven bytes - but never
    # exceed it, and never leave more than padding behind.
    slack = length - (_WIN_CERT_HEADER.size + total)
    if not 0 <= slack < _WIN_CERT_ALIGNMENT:
        return False
    # The OID has to fit inside the SEQUENCE's own value. Without this
    # the comparison below reads past the structure into the record's
    # alignment padding, where it could match adjacent bytes.
    if value_length < len(_PKCS7_SIGNED_DATA_OID):
        return False
    # contentType, the first field of ContentInfo.
    oid_at = body + 1 + length_bytes
    return raw[oid_at:oid_at + len(_PKCS7_SIGNED_DATA_OID)] == _PKCS7_SIGNED_DATA_OID


def _walks_as_certificate_table(raw: bytes, offset: int, size: int) -> bool:
    """Check that a byte range parses as a WIN_CERTIFICATE table.

    Args:
        raw:    The whole file.
        offset: File offset the Security directory points at.
        size:   Byte count the Security directory declares.

    Returns:
        True only when the range is a sequence of well-formed PKCS#7
        certificate records ending exactly on its declared end.

    Bounds checks alone are NOT enough here. The directory is
    attacker-controlled, so an unsigned sample carrying a high-entropy
    payload need only point VirtualAddress at the overlay and set Size
    to exactly the bytes remaining: the region is then inside the file,
    the arithmetic is consistent, every bound passes, and the whole
    payload is excised. Parsing the records, and their contents, is
    what refuses that.
    """
    if size < _WIN_CERT_HEADER.size:
        return False
    # Windows requires the table itself to start on an 8-byte boundary,
    # and the record walk below advances in file offsets - so an
    # unaligned start would make every subsequent alignment step wrong.
    if offset % _WIN_CERT_ALIGNMENT:
        return False

    end = offset + size
    cursor = offset
    records = 0
    while cursor < end:
        # Counted rather than bounded by a for-range: a `for` loop over
        # the cap needs one spare iteration to observe that the cursor
        # has reached the end, so a table of exactly _MAX_CERT_RECORDS
        # valid records fell out of the loop and was rejected.
        records += 1
        if records > _MAX_CERT_RECORDS:
            return False
        if cursor + _WIN_CERT_HEADER.size > end:
            return False
        length, revision, cert_type = _WIN_CERT_HEADER.unpack_from(raw, cursor)
        if length < _WIN_CERT_HEADER.size or cursor + length > end:
            return False
        if revision not in _WIN_CERT_REVISIONS:
            return False
        if cert_type != _WIN_CERT_TYPE_PKCS_SIGNED_DATA:
            return False
        if not _is_pkcs7_signature(raw, cursor, length):
            return False
        following = cursor + length
        aligned = (following + _WIN_CERT_ALIGNMENT - 1) & ~(_WIN_CERT_ALIGNMENT - 1)
        if aligned > end:
            # The final record is not always padded out, but anything
            # other than an exact finish means bytes are unaccounted
            # for. Clamping to `end` here instead would make the
            # closing equality true by construction.
            return following == end
        cursor = aligned
    # Reached only by advancing exactly onto `end`: the overshoot case
    # returns above, so this is not true by construction.
    return cursor == end


def _certificate_region(
    pe: "pefile.PE", raw: bytes, overlay_offset: int
) -> tuple[int, int] | None:
    """Locate the Authenticode certificate table within the overlay.

    Args:
        pe:             A parsed ``pefile.PE`` object.
        raw:            The whole file.
        overlay_offset: Where the overlay begins.

    Returns:
        ``(offset, size)`` of the certificate table, or None when the
        file is unsigned, the directory is absent, or the region does
        not parse as one. None means "measure the overlay whole", which
        is the safe direction: a missed signature over-reports, while a
        wrongly trusted directory hides a payload.

    ``DATA_DIRECTORY`` is checked for length rather than indexed
    directly. pefile builds it by appending in a loop that stops early
    when the offset leaves the optional header, so a PE declaring fewer
    than five directories has no index 4 at all - and an IndexError
    escaping here would abort the whole module, which design rule 2
    forbids.

    Known limitation: data appended INSIDE a well-formed certificate,
    past the signature's own payload, is still excised. Closing that
    needs the ASN.1 length checked against dwLength. It is recorded
    rather than fixed, the same way the REPRO timestamp check records
    that a debug entry is attacker-writable.
    """
    try:
        directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(directories) <= _SECURITY_DIRECTORY_INDEX:
            return None
        entry = directories[_SECURITY_DIRECTORY_INDEX]
        cert_offset = int(getattr(entry, "VirtualAddress", 0) or 0)
        cert_size = int(getattr(entry, "Size", 0) or 0)
    except Exception:  # noqa: BLE001
        return None

    if cert_size < _WIN_CERT_HEADER.size:
        return None
    if cert_offset < overlay_offset or cert_offset + cert_size > len(raw):
        return None
    if not _walks_as_certificate_table(raw, cert_offset, cert_size):
        return None

    # A directory whose Size covers the last record but not its
    # alignment padding would leave one to seven bytes behind, and
    # those bytes would then be measured as an overlay. Rounding up is
    # bounded by the file so a malformed Size cannot reach past its end.
    padded = (cert_size + _WIN_CERT_ALIGNMENT - 1) & ~(_WIN_CERT_ALIGNMENT - 1)
    return cert_offset, min(padded, len(raw) - cert_offset)


def _analyse_overlay(pe: "pefile.PE") -> dict:
    """Inspect any overlay (data appended after the last PE section).

    Overlay data is commonly used to smuggle encrypted payloads,
    second-stage DLLs, or installer archives. We compute the size and
    Shannon entropy of the overlay.

    Args:
        pe: A parsed ``pefile.PE`` object.

    Returns:
        ``{"size", "entropy", "certificate_size"}``. The first two are
        zero when there is no overlay; ``certificate_size`` reports how
        many bytes were excised as a verified Authenticode signature, so
        a reader can see why an overlay shrank or vanished.

        Note that an overlay is not inherently suspicious — every
        self-extracting installer appends its archive. Size and entropy
        together are what make it interesting, and the signature is
        removed first so that being signed cannot itself look like one.
    """
    info = {"size": 0, "entropy": 0.0, "certificate_size": 0}
    try:
        overlay_offset = pe.get_overlay_data_start_offset()
    except Exception:  # noqa: BLE001
        return info
    if overlay_offset is None:
        return info
    raw = pe.__data__

    # ------------------------------------------------------------------
    # Excise the digital signature before measuring anything.
    #
    # On a signed PE the bytes after the last section ARE the
    # certificate table, and a certificate is high-entropy by
    # construction, so measuring them reported "embedded encrypted
    # payload" on every signed binary - in the same breath as reporting
    # that the file was signed. The two statements described the same
    # bytes.
    #
    # Both fragments are kept rather than truncating at the
    # certificate's offset: a signed self-extracting installer carries
    # its archive AND its signature, and truncating would silently
    # discard whichever one came second.
    # ------------------------------------------------------------------
    certificate = _certificate_region(pe, raw, overlay_offset)

    # The overlay is described as byte ranges rather than assembled.
    # Concatenating the two sides would hold a second copy of a 500 MB
    # installer's overlay in memory for no benefit: the size is
    # arithmetic, and the entropy is measured on a bounded prefix.
    if certificate is None:
        # Guarded the same way as the two-fragment case below. pefile
        # only returns an offset strictly inside the file, so this is
        # not reachable through it today — but an inverted span would
        # make `size` NEGATIVE and sail past the `if not size` check,
        # and the asymmetry is the kind of thing a later caller trips
        # over.
        fragments = [
            span for span in ((overlay_offset, len(raw)),)
            if span[1] > span[0]
        ]
    else:
        cert_offset, cert_size = certificate
        info["certificate_size"] = cert_size
        fragments = [
            span for span in (
                (overlay_offset, cert_offset),
                (cert_offset + cert_size, len(raw)),
            ) if span[1] > span[0]
        ]

    size = sum(stop - start for start, stop in fragments)
    if not size:
        return info
    info["size"] = size

    # Entropy on at most _ENTROPY_SAMPLE_BYTES, taken across the
    # fragments in order. Far more than enough to characterise the
    # distribution, and it bounds the cost on a huge installer.
    sample = bytearray()
    for start, stop in fragments:
        remaining = _ENTROPY_SAMPLE_BYTES - len(sample)
        if remaining <= 0:
            break
        sample += raw[start:min(stop, start + remaining)]
    info["entropy"] = round(_shannon_entropy(bytes(sample)), 4)
    return info


def _has_tls_directory(pe: "pefile.PE") -> bool:
    """Report whether the file declares thread-local storage.

    Args:
        pe: A parsed ``pefile.PE`` object.

    Returns:
        True when a TLS directory is present by either reading.

    Both readings are needed. pefile only sets ``DIRECTORY_ENTRY_TLS``
    when the directory parses cleanly, so a deliberately malformed one
    leaves the attribute absent while the data directory still points
    at it — and the loader, not pefile, is what decides whether the
    callbacks run.
    """
    if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        return True
    try:
        directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(directories) <= _TLS_DIRECTORY_INDEX:
            return False
        entry = directories[_TLS_DIRECTORY_INDEX]
        return bool(getattr(entry, "VirtualAddress", 0))
    except Exception:  # noqa: BLE001
        return False


def _classify_importless(pe: "pefile.PE", total_imports: int = 0) -> str | None:
    """Name the benign explanation for a PE with no useful import table.

    Args:
        pe:            A parsed ``pefile.PE`` object.
        total_imports: How many functions the import table names. Part
                       of the question rather than context: a
                       resource-only DLL carries no code, so it has
                       nothing to import with, and zero is part of its
                       definition. A forwarder may legitimately import
                       one or two.

    Returns:
        ``"forwarder"``, ``"resource_only"``, or None when neither
        benign explanation holds and the empty table is worth scoring.

    An empty import table is read as "resolves every API at runtime or
    unpacks itself". Two ordinary Windows structures produce the same
    observation and mean nothing of the sort: a **forwarder** DLL,
    whose exports redirect into another library, and a
    **resource-only** DLL, which carries no code at all. Both are
    common in System32 — two of the seven benign controls measured are
    resource-only, each taking +20 from this and the entry-point check
    together.

    Forwarder is tested first, and resource-only additionally requires
    zero exports. An API-set forwarder (``api-ms-win-core-*``) is a DLL
    with no executable section that still carries ``.rsrc`` for its
    version information, so the other order would have labelled it
    resource-only while it has dozens of forwarded exports. The score
    is the same either way; the reason string would have been false,
    and false reasons about ordinary Windows structures are the defect
    being fixed.

    Known limitation, documented rather than gated: a packed DLL whose
    exports are all forwarders suppresses this score. That is traded
    against a false positive on every forwarder and resource-only DLL
    in System32, which is the measured case.
    """
    try:
        characteristics = getattr(pe.FILE_HEADER, "Characteristics", 0)
        if not characteristics & _IMAGE_FILE_DLL:
            return None

        exports = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        symbols = list(getattr(exports, "symbols", []) or []) if exports else []
        if symbols and all(getattr(sym, "forwarder", None) for sym in symbols):
            return "forwarder"

        # Resource-only: no code, nowhere to run it, nothing to run —
        # and therefore nothing to import with. Without the count a DLL
        # with one to four imports matched every structural test below
        # and was told it had none.
        if total_imports:
            return None

        # "No executable section" alone would not be safe. With
        # NX_COMPAT clear, 32-bit Windows still permits execution from a
        # section lacking IMAGE_SCN_MEM_EXECUTE, so a packer could reach
        # this branch by clearing a section characteristic. Requiring
        # no entry point AND no TLS directory closes it: the loader runs
        # TLS callbacks before and independently of the entry point, so
        # both have to be absent before "nothing starts" is true.
        if symbols:
            return None
        if getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0):
            return None
        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return None
        if _has_tls_directory(pe):
            return None
        if any(section.Characteristics & _IMAGE_SCN_MEM_EXECUTE
               for section in pe.sections):
            return None
        return "resource_only"
    except Exception:  # noqa: BLE001
        return None


def _check_entry_point(pe: "pefile.PE", sections: list[dict]) -> dict:
    """Validate that the entry point lies inside a normal code section.

    Args:
        pe:       A parsed ``pefile.PE`` object.
        sections: Section dicts (unused; uniform submodule signature).

    Returns:
        {
          "section": "<section name containing the EP>",
          "anomaly": True if EP is in a non-code section,
        }

    Most legitimate compilers place the EP inside .text. Packers and
    shellcode loaders frequently move it to .data, .rsrc, or a
    randomly-named section.
    """
    try:
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    except AttributeError:
        return {"section": None, "anomaly": False}

    # A DLL may legitimately have no entry point at all. The PE
    # specification makes the field optional for a DLL and requires it
    # to be zero when absent, which is what a resource-only or
    # forwarder DLL carries — so there is no unpacker stub for it to
    # point at, and "entry point in unusual section 'None'" is a
    # statement about an absent field.
    #
    # Gated on the DLL bit: on an executable, zero is genuinely
    # anomalous, RVA 0 being the MZ header rather than code.
    if ep == 0 and getattr(
        getattr(pe, "FILE_HEADER", None), "Characteristics", 0
    ) & _IMAGE_FILE_DLL:
        return {"section": None, "anomaly": False}

    # ------------------------------------------------------------------
    # Step 1: Find which section contains the entry point RVA.
    #
    # The larger of virtual and raw size is used as the extent because a
    # packed section's real in-memory footprint is the virtual one, and
    # an EP past the raw bytes is exactly the case worth catching.
    # ------------------------------------------------------------------
    ep_section = None
    for section in pe.sections:
        start = section.VirtualAddress
        end = start + max(section.Misc_VirtualSize, section.SizeOfRawData)
        if start <= ep < end:
            ep_section = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            break

    # ------------------------------------------------------------------
    # Step 2: Judge it. An EP outside every section is the strongest form
    # of this anomaly — the file declares an entry point that does not
    # map to any of its own content.
    # ------------------------------------------------------------------
    if ep_section is None:
        return {"section": None, "anomaly": True}
    # Standard code-section names that we treat as benign.
    benign = {".text", "code", ".code", "text", "CODE", "INIT"}
    anomaly = ep_section.strip().lower() not in {b.lower() for b in benign}
    return {"section": ep_section, "anomaly": anomaly}


def _find_embedded_pe(pe: "pefile.PE") -> dict | None:
    """Search the resource section and overlay for embedded MZ payloads.

    A second-stage executable embedded inside .rsrc or appended to the
    file as overlay is a defining trait of droppers / installers /
    AutoIt-compiled malware. We look for the MZ + 'This program' DOS
    stub combo at any offset > 1024 (avoid matching the host file's
    own header).

    Args:
        pe: A parsed ``pefile.PE`` object.

    Returns:
        ``{"where", "offset"}`` for the first payload found, or None.
        "MZ" alone is only two bytes and occurs constantly in compressed
        data, so a match is confirmed by requiring the DOS stub string
        within the following 256 bytes — that pairing is what makes this
        specific rather than noisy.
    """
    raw = pe.__data__

    # ------------------------------------------------------------------
    # Step 1: Sweep each section's raw bytes.
    #
    # Offsets are validated against the real file length first: the
    # section table is attacker-controlled and can point past the end.
    # ------------------------------------------------------------------
    # Search the .rsrc section first.
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        start = section.PointerToRawData
        end = start + section.SizeOfRawData
        if end <= start or end > len(raw):
            continue
        chunk = raw[start:end]
        idx = 0
        while True:
            i = chunk.find(b"MZ", idx)
            # Stop when there is not enough room left for a DOS header —
            # a match in the last 64 bytes cannot be a real executable.
            if i < 0 or i > len(chunk) - 0x40:
                break
            # Quick verification: check for the DOS stub message
            # within the next 256 bytes.
            window = chunk[i : i + 256]
            if _DEFAULT_DOS_STUB in window:
                return {
                    "where": f"section:{name}",
                    "offset": start + i,
                }
            idx = i + 2

    # ------------------------------------------------------------------
    # Step 2: Then the overlay, capped at 4 MiB.
    #
    # Only the first MZ is checked here rather than every occurrence:
    # a dropper puts its payload at the start of the appended data, and
    # scanning an entire multi-gigabyte installer archive for a two-byte
    # sequence would cost far more than the extra coverage is worth.
    # ------------------------------------------------------------------
    # Then the overlay.
    try:
        overlay_offset = pe.get_overlay_data_start_offset()
    except Exception:  # noqa: BLE001
        overlay_offset = None
    if overlay_offset:
        overlay = raw[overlay_offset:overlay_offset + 4 * 1024 * 1024]
        i = overlay.find(b"MZ")
        if i >= 0 and i < len(overlay) - 0x40:
            window = overlay[i : i + 256]
            if _DEFAULT_DOS_STUB in window:
                return {
                    "where": "overlay",
                    "offset": overlay_offset + i,
                }
    return None
