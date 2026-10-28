"""Unit tests for the pe_analysis module.

These exercise the individual indicator functions against hand-built stand-ins
rather than real PE files, so a check's edge cases can be pinned down without
needing a sample that happens to exhibit them.
"""

import pytest

from modules.static.pe_analysis.structure import _has_tls_callbacks


# ----------------------------------------------------------------------
# Minimal stand-ins for the parts of pefile.PE that _has_tls_callbacks
# touches. Building a real 32-bit PE with a TLS directory just to test
# the pointer-width branch would be far more code than the check itself.
# ----------------------------------------------------------------------

class _Struct:
    def __init__(self, address_of_callbacks):
        self.AddressOfCallBacks = address_of_callbacks


class _TlsDir:
    def __init__(self, address_of_callbacks):
        self.struct = _Struct(address_of_callbacks)


class _OptionalHeader:
    def __init__(self, magic, image_base):
        self.Magic = magic
        self.ImageBase = image_base


class _FakePE:
    """Duck-typed stand-in exposing only what the function reads."""

    #: PE32 (32-bit) and PE32+ (64-bit) OptionalHeader.Magic values.
    PE32 = 0x10B
    PE32_PLUS = 0x20B

    def __init__(self, magic, callback_bytes, address_of_callbacks=0x2000,
                 image_base=0x400000):
        self.OPTIONAL_HEADER = _OptionalHeader(magic, image_base)
        self.DIRECTORY_ENTRY_TLS = _TlsDir(image_base + address_of_callbacks)
        self._callback_bytes = callback_bytes
        self.requested_size = None

    def get_data(self, rva, size):
        # Record what the caller asked for so a test can assert on the
        # read width, then honour it the way pefile would.
        self.requested_size = size
        return self._callback_bytes[:size]


def test_empty_callback_array_on_32bit_is_not_a_callback():
    """A 32-bit PE with an empty TLS callback array must not be flagged.

    On PE32 a callback pointer is 4 bytes, so an empty NULL-terminated
    array is four zero bytes. Reading a fixed 8 bytes runs past the
    terminator into whatever data follows; if those bytes are non-zero
    the check reports a callback that does not exist.
    """
    # Four zero bytes (the terminator) followed by unrelated non-zero data.
    data = b"\x00\x00\x00\x00" + b"\x41\x42\x43\x44"
    pe = _FakePE(_FakePE.PE32, data)
    assert _has_tls_callbacks(pe) is False


def test_real_callback_on_32bit_is_detected():
    """A genuine 32-bit callback pointer must still be detected."""
    data = b"\x10\x20\x40\x00" + b"\x00\x00\x00\x00"
    pe = _FakePE(_FakePE.PE32, data)
    assert _has_tls_callbacks(pe) is True


def test_empty_callback_array_on_64bit_is_not_a_callback():
    """The 64-bit equivalent: eight zero bytes is an empty array."""
    data = b"\x00" * 8 + b"\x41\x42\x43\x44\x45\x46\x47\x48"
    pe = _FakePE(_FakePE.PE32_PLUS, data)
    assert _has_tls_callbacks(pe) is False


def test_real_callback_on_64bit_is_detected():
    """A genuine 64-bit callback pointer must still be detected."""
    data = b"\x10\x20\x40\x00\x01\x00\x00\x00" + b"\x00" * 8
    pe = _FakePE(_FakePE.PE32_PLUS, data)
    assert _has_tls_callbacks(pe) is True


def test_pointer_width_follows_the_optional_header_magic():
    """The read width must be chosen from the image's bitness."""
    pe32 = _FakePE(_FakePE.PE32, b"\x00" * 16)
    _has_tls_callbacks(pe32)
    assert pe32.requested_size == 4

    pe64 = _FakePE(_FakePE.PE32_PLUS, b"\x00" * 16)
    _has_tls_callbacks(pe64)
    assert pe64.requested_size == 8


def test_no_tls_directory_is_not_a_callback():
    """A PE with no TLS directory at all reports no callbacks."""

    class _NoTls:
        pass

    assert _has_tls_callbacks(_NoTls()) is False


def test_null_callback_pointer_is_not_a_callback():
    """AddressOfCallBacks of zero means TLS without callbacks."""
    pe = _FakePE(_FakePE.PE32, b"\x01" * 8)
    pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks = 0
    assert _has_tls_callbacks(pe) is False


def test_unreadable_callback_array_still_reports_the_pointer():
    """When the array cannot be read, the table pointer alone counts.

    A crafted file can point AddressOfCallBacks outside every section.
    The pointer being set at all is still worth reporting, so the
    function falls back to True rather than losing the signal.
    """

    class _RaisingPE(_FakePE):
        def get_data(self, rva, size):
            raise ValueError("data at RVA cannot be fetched")

    assert _has_tls_callbacks(_RaisingPE(_FakePE.PE32, b"")) is True


# ----------------------------------------------------------------------
# Packer detection
# ----------------------------------------------------------------------

from modules.static.pe_analysis.packers import _detect_packers


class _FakeSection:
    def __init__(self, name):
        self.Name = name.encode("ascii").ljust(8, b"\x00")


class _PackerPE:
    """Stand-in exposing only what _detect_packers reads."""

    def __init__(self, overlay=b""):
        self.__data__ = b"MZ" + b"\x00" * 512 + overlay
        self._overlay_at = 514 if overlay else None

    def get_overlay_data_start_offset(self):
        return self._overlay_at


def _sections(*names):
    return [{"name": n} for n in names]


@pytest.mark.parametrize(
    "section_name, expected",
    [
        ("UPX0", "UPX"),
        ("UPX1", "UPX"),
        (".mpress1", "MPRESS"),
        (".themida", "Themida"),
        (".vmp0", "VMProtect"),
        (".aspack", "ASPack"),
        (".petite", "Petite"),
        (".nsp0", "NSPack"),
    ],
)
def test_known_packer_sections_are_detected(section_name, expected):
    """Every packer the matcher already handled must keep working."""
    found = _detect_packers(_PackerPE(), _sections(section_name, ".text"))
    assert expected in found


@pytest.mark.parametrize(
    "section_name, expected",
    [
        (".yP", "Y0da"),
        (".packed", "Generic"),
    ],
)
def test_packer_sections_listed_but_never_matched(section_name, expected):
    """Sections named in _PACKER_SECTION_NAMES must actually be matched.

    `.yP` (Y0da Packer) and `.packed` were listed in the signature table
    and never consulted by the matcher, so a binary carrying them was
    reported as unpacked.
    """
    found = _detect_packers(_PackerPE(), _sections(section_name, ".text"))
    assert found, f"{section_name} was not detected as a packer section"
    assert any(expected.lower() in f.lower() for f in found)


def test_pecompact_signature_is_detected():
    """PECompact is in _PACKER_SIGNATURES but was never searched for."""
    found = _detect_packers(_PackerPE(overlay=b"PECompact2" + b"\x00" * 32),
                            _sections(".text", ".data"))
    assert "PECompact" in found


def test_upx_overlay_magic_still_detected_when_sections_renamed():
    """The renamed-section UPX fallback must survive the refactor."""
    found = _detect_packers(_PackerPE(overlay=b"UPX!" + b"\x00" * 32),
                            _sections(".text", ".data"))
    assert "UPX" in found


def test_clean_binary_reports_no_packer():
    """A normal section layout must not produce a false positive."""
    found = _detect_packers(_PackerPE(), _sections(".text", ".rdata", ".data", ".rsrc"))
    assert found == []


def test_packer_names_are_not_duplicated():
    """UPX0/UPX1/UPX2 together must report UPX once."""
    found = _detect_packers(_PackerPE(), _sections("UPX0", "UPX1", "UPX2"))
    assert found.count("UPX") == 1


# ----------------------------------------------------------------------
# Section permission anomalies vs the separate RWX finding
# ----------------------------------------------------------------------

from modules.static.pe_analysis.sections import (
    _detect_section_permission_anomalies,
    _find_rwx_sections,
)

_SCN_MEM_EXECUTE = 0x20000000
_SCN_MEM_READ = 0x40000000
_SCN_MEM_WRITE = 0x80000000


class _PermSection:
    def __init__(self, name, characteristics):
        self.Name = name.encode("ascii").ljust(8, b"\x00")
        self.Characteristics = characteristics


class _PermPE:
    def __init__(self, *sections):
        self.sections = list(sections)


def test_rwx_rdata_is_reported_once_not_three_times():
    """One RWX section must not raise three separate findings.

    An RWX `.rdata` matched both data-section rules ("executable .rdata"
    and "writable .rdata") on top of the dedicated RWX finding, scoring
    one physical section three times.
    """
    rwx = _SCN_MEM_READ | _SCN_MEM_WRITE | _SCN_MEM_EXECUTE
    pe = _PermPE(_PermSection(".rdata", rwx))

    assert _find_rwx_sections(pe) == [".rdata"]
    assert _detect_section_permission_anomalies(pe) == []


def test_rwx_data_is_left_to_the_rwx_check():
    """The same rule applies to `.data`."""
    rwx = _SCN_MEM_READ | _SCN_MEM_WRITE | _SCN_MEM_EXECUTE
    pe = _PermPE(_PermSection(".data", rwx))
    assert _find_rwx_sections(pe) == [".data"]
    assert _detect_section_permission_anomalies(pe) == []


def test_executable_data_without_write_is_still_an_anomaly():
    """A non-RWX anomaly must keep being reported.

    Execute-without-write on a data section is not RWX, so the RWX check
    will not catch it and this one must.
    """
    rx = _SCN_MEM_READ | _SCN_MEM_EXECUTE
    pe = _PermPE(_PermSection(".data", rx))
    assert _find_rwx_sections(pe) == []
    assert _detect_section_permission_anomalies(pe) == ["executable .data"]


def test_writable_rdata_without_execute_is_still_an_anomaly():
    """Write-without-execute on .rdata likewise stays reported."""
    rw = _SCN_MEM_READ | _SCN_MEM_WRITE
    pe = _PermPE(_PermSection(".rdata", rw))
    assert _find_rwx_sections(pe) == []
    assert _detect_section_permission_anomalies(pe) == ["writable .rdata"]


def test_writable_text_without_execute_is_still_an_anomaly():
    """The .text branch already had this exclusion; it must not regress."""
    rw = _SCN_MEM_READ | _SCN_MEM_WRITE
    pe = _PermPE(_PermSection(".text", rw))
    assert _detect_section_permission_anomalies(pe) == ["writable .text"]


def test_normal_section_permissions_produce_no_anomalies():
    """A conventional layout must stay silent."""
    pe = _PermPE(
        _PermSection(".text", _SCN_MEM_READ | _SCN_MEM_EXECUTE),
        _PermSection(".rdata", _SCN_MEM_READ),
        _PermSection(".data", _SCN_MEM_READ | _SCN_MEM_WRITE),
    )
    assert _detect_section_permission_anomalies(pe) == []
    assert _find_rwx_sections(pe) == []


# ----------------------------------------------------------------------
# Import-table scoring at the zero boundary
# ----------------------------------------------------------------------

from modules.static.pe_analysis import _analyse_pe


class _ImportPE:
    """Enough of a PE for _analyse_pe to reach the import-table checks.

    Every indicator _analyse_pe consults is either absent (so the
    hasattr guards short-circuit) or returns a benign value, leaving the
    import-table branch as the only thing that can score.
    """

    class _FileHeader:
        Machine = 0x014C
        TimeDateStamp = 0
        NumberOfSections = 3
        Characteristics = 0x0102

    class _OptHeader:
        Magic = 0x10B
        AddressOfEntryPoint = 0x1000
        ImageBase = 0x400000
        DllCharacteristics = 0x0140  # ASLR + DEP set, so no mitigation score
        Subsystem = 2
        CheckSum = 0
        DATA_DIRECTORY = []

    class _Section:
        def __init__(self, name):
            self.Name = name.encode("ascii").ljust(8, b"\x00")
            self.VirtualAddress = 0x1000
            self.Misc_VirtualSize = 0x200
            self.SizeOfRawData = 0x200
            self.PointerToRawData = 0x400
            self.Characteristics = 0x40000040

        def get_entropy(self):
            return 4.0

    class _DosHeader:
        e_lfanew = 0x80

    def __init__(self, imports=None):
        self.FILE_HEADER = self._FileHeader()
        self.OPTIONAL_HEADER = self._OptHeader()
        self.DOS_HEADER = self._DosHeader()
        self.sections = [self._Section(".text"), self._Section(".rdata"),
                         self._Section(".data")]
        self.__data__ = (b"MZ" + b"\x00" * 62
                         + b"This program cannot be run in DOS mode."
                         + b"\x00" * 512)
        if imports is not None:
            self.DIRECTORY_ENTRY_IMPORT = imports

    def get_imphash(self):
        return ""

    def get_overlay_data_start_offset(self):
        return None

    def parse_rich_header(self):
        return None

    def generate_checksum(self):
        return 0

    def get_data(self, rva, size):
        raise ValueError("no data")


def _reasons_mentioning(reasons, *words):
    return [r for r in reasons if any(w.lower() in r.lower() for w in words)]


def test_native_pe_with_zero_imports_scores():
    """A native PE importing nothing at all must score.

    The tiny-import-table check fired on `0 < total_imports < 5`, so a
    PE with exactly zero imports fell through it, and the zero-DLL
    branch below was a bare `pass`. The most extreme shape scored least.
    """
    _data, score, reasons = _analyse_pe(_ImportPE())
    assert score > 0
    assert _reasons_mentioning(reasons, "import table", "imports"), reasons


def test_zero_import_pe_is_not_scored_twice():
    """The empty-table case must produce one import finding, not two."""
    _data, _score, reasons = _analyse_pe(_ImportPE())
    import_reasons = _reasons_mentioning(reasons, "import table")
    assert len(import_reasons) == 1, import_reasons


# ----------------------------------------------------------------------
# Version-info scoring
# ----------------------------------------------------------------------

from modules.static.pe_analysis.metadata import _score_version_info


def test_missing_version_block_scores_nothing():
    """A missing version block must not score.

    The docstring once promised +5 here and the code never implemented
    it. Go, Rust and MinGW binaries routinely ship without a version
    resource, so the penalty would fire across a large benign
    population. This pins the intended behaviour so the phantom check is
    not "restored" by a future reader.
    """
    assert _score_version_info({}) == (0, "")


def test_ordinary_version_block_scores_nothing():
    """A normal vendor block with a real description is not suspicious."""
    score, reason = _score_version_info({
        "CompanyName": "Some Small Vendor Ltd",
        "ProductName": "Invoice Tool",
        "FileDescription": "Invoice preparation utility",
    })
    assert (score, reason) == (0, "")


def test_impersonated_vendor_with_generic_description_scores():
    """A well-known vendor name over boilerplate is impersonation."""
    score, reason = _score_version_info({
        "CompanyName": "Microsoft Corporation",
        "ProductName": "Windows",
        "FileDescription": "Application",
    })
    assert score == 10
    assert "impersonat" in reason.lower()


def test_impersonated_vendor_with_real_description_is_left_alone():
    """Genuine Microsoft binaries name what they actually are."""
    score, reason = _score_version_info({
        "CompanyName": "Microsoft Corporation",
        "ProductName": "Microsoft Windows Operating System",
        "FileDescription": "Windows Explorer Shell",
    })
    assert (score, reason) == (0, "")


# ----------------------------------------------------------------------
# A1 — the Authenticode certificate is not an encrypted payload
#
# A signed PE carries its certificate table after the last section, so
# the naive "everything past the sections is overlay" read measures the
# signature's entropy and reports an embedded encrypted payload. The
# certificate is cryptographic and therefore high-entropy by
# construction, so every signed binary without a genuine overlay was
# penalised for being signed - while the same reason string also said
# the file was signed.
# ----------------------------------------------------------------------

import struct

from modules.static.pe_analysis.structure import _analyse_overlay

_WIN_CERT = struct.Struct("<IHH")


#: DER encoding of the PKCS#7 signedData OID, 1.2.840.113549.1.7.2.
_SIGNED_DATA_OID = bytes(
    (0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02)
)


def _der_sequence(body):
    """Wrap a body in a DER SEQUENCE with a definite length."""
    if len(body) < 0x80:
        header = bytes((0x30, len(body)))
    else:
        encoded = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
        header = bytes((0x30, 0x80 | len(encoded))) + encoded
    return header + body


def _certificate(payload_len, revision=0x0200, cert_type=0x0002, body=None):
    """A WIN_CERTIFICATE entry, padded to the 8-byte alignment.

    The body is a real DER SEQUENCE carrying the signedData OID, as
    WIN_CERT_TYPE_PKCS_SIGNED_DATA promises, because the module checks
    for one — eight static header bytes in front of arbitrary data is
    precisely the spoof it refuses.
    """
    if body is None:
        body = _der_sequence(_SIGNED_DATA_OID + b"\xC3" * payload_len)
    length = _WIN_CERT.size + len(body)
    blob = _WIN_CERT.pack(length, revision, cert_type) + body
    return blob + b"\x00" * (-len(blob) % 8)


class _Dir:
    def __init__(self, va, size):
        self.VirtualAddress = va
        self.Size = size


class _OptHeaderWithDirs:
    def __init__(self, directories):
        self.DATA_DIRECTORY = directories


class _OverlayPE:
    """Exposes only what _analyse_overlay reads."""

    def __init__(self, raw, overlay_start, cert=None, n_directories=5):
        self.__data__ = raw
        self._overlay_start = overlay_start
        dirs = [_Dir(0, 0) for _ in range(n_directories)]
        if cert is not None and n_directories > 4:
            dirs[4] = _Dir(cert[0], cert[1])
        self.OPTIONAL_HEADER = _OptHeaderWithDirs(dirs)

    def get_overlay_data_start_offset(self):
        return self._overlay_start


#: Stands in for the file's sections. Low entropy, so it cannot be
#: mistaken for the payload the tests are looking for.
_SECTIONS = b"\x00" * 512


def test_a_signature_is_not_reported_as_an_encrypted_payload():
    """The exact ShareTargets.dll / vcamp140.dll shape.

    Both were confirmed byte-exact: file size minus end-of-sections
    equals the Security directory's size, and the directory begins at
    the end of the sections. The overlay IS the signature.
    """
    cert = _certificate(2000)
    raw = _SECTIONS + cert
    pe = _OverlayPE(raw, len(_SECTIONS), cert=(len(_SECTIONS), len(cert)))
    info = _analyse_overlay(pe)
    assert info["size"] == 0
    assert info["certificate_size"] == len(cert)


def test_a_real_overlay_before_the_signature_survives():
    """A signed self-extracting installer carries both.

    Over-applying the fix would delete the archive along with the
    signature.
    """
    junk = bytes(range(256)) * 20          # 5120 bytes, high entropy
    cert = _certificate(2000)
    raw = _SECTIONS + junk + cert
    pe = _OverlayPE(raw, len(_SECTIONS),
                    cert=(len(_SECTIONS) + len(junk), len(cert)))
    info = _analyse_overlay(pe)
    assert info["size"] == len(junk)
    assert info["entropy"] >= 7.0


def test_a_real_overlay_after_the_signature_survives():
    """Truncating at the certificate instead of excising it loses this.

    Without this case an implementation that simply cut the file short
    at the certificate's offset passes every other test here.
    """
    cert = _certificate(2000)
    junk = bytes(range(256)) * 20
    raw = _SECTIONS + cert + junk
    pe = _OverlayPE(raw, len(_SECTIONS), cert=(len(_SECTIONS), len(cert)))
    assert _analyse_overlay(pe)["size"] == len(junk)


def test_overlay_fragments_on_both_sides_are_both_measured():
    before = bytes(range(256)) * 4
    after = bytes(range(256)) * 6
    cert = _certificate(1000)
    raw = _SECTIONS + before + cert + after
    pe = _OverlayPE(raw, len(_SECTIONS),
                    cert=(len(_SECTIONS) + len(before), len(cert)))
    assert _analyse_overlay(pe)["size"] == len(before) + len(after)


def test_a_directory_claiming_the_overlay_without_a_certificate_is_ignored():
    """The evasion the bounds checks alone do not stop.

    An unsigned sample sets VirtualAddress to the overlay's start and
    Size to exactly the bytes remaining. Every bounds check passes - the
    region is inside the file and the arithmetic is consistent - and the
    whole payload is excised without a single certificate byte being
    written. Only parsing the region as a WIN_CERTIFICATE table catches
    it.
    """
    junk = bytes(range(256)) * 20
    raw = _SECTIONS + junk
    pe = _OverlayPE(raw, len(_SECTIONS), cert=(len(_SECTIONS), len(junk)))
    info = _analyse_overlay(pe)
    assert info["size"] == len(junk)
    assert info["certificate_size"] == 0, "nothing was verified, so nothing was excised"


def test_a_certificate_size_running_past_the_file_is_ignored():
    """An oversize Size would otherwise slice the remainder to nothing."""
    junk = bytes(range(256)) * 20
    raw = _SECTIONS + junk
    pe = _OverlayPE(raw, len(_SECTIONS),
                    cert=(len(_SECTIONS), len(junk) + 4096))
    assert _analyse_overlay(pe)["size"] == len(junk)


def test_a_short_data_directory_does_not_raise():
    """pefile appends directory entries in a loop that can stop early.

    A PE declaring NumberOfRvaAndSizes <= 4 has no index 4 at all, and
    an IndexError here would abort the whole module to status "error" -
    a graceful-degradation violation introduced by a false-positive fix.
    """
    junk = bytes(range(256)) * 20
    raw = _SECTIONS + junk
    pe = _OverlayPE(raw, len(_SECTIONS), cert=None, n_directories=4)
    assert _analyse_overlay(pe)["size"] == len(junk)


def test_an_unsigned_binary_is_unaffected():
    """The paired case: no certificate, so nothing is subtracted."""
    junk = bytes(range(256)) * 20
    raw = _SECTIONS + junk
    pe = _OverlayPE(raw, len(_SECTIONS), cert=(0, 0))
    info = _analyse_overlay(pe)
    assert info["size"] == len(junk)
    assert info["entropy"] >= 7.0


def test_a_malformed_certificate_revision_is_not_subtracted():
    """A plausible header with a nonsense revision is not a signature."""
    cert = _certificate(2000, revision=0x0999)
    raw = _SECTIONS + cert
    pe = _OverlayPE(raw, len(_SECTIONS), cert=(len(_SECTIONS), len(cert)))
    assert _analyse_overlay(pe)["size"] == len(cert)


# ----------------------------------------------------------------------
# A2 — a reproducible build is not a forged timestamp
#
# Since VS2015 the Microsoft toolchain ships deterministic builds in
# which TimeDateStamp holds a content hash rather than a date, flagged
# by an IMAGE_DEBUG_TYPE_REPRO (type 16) debug directory entry. Absurd
# far-future values are therefore normal for modern Microsoft binaries.
#
# The check cannot simply be deleted: a genuinely forged timestamp is a
# real anti-analysis technique, so the REPRO entry is what distinguishes
# the two.
# ----------------------------------------------------------------------

from modules.static.pe_analysis.headers import (
    _check_timestamp,
    _extract_headers,
)
from modules.static.pe_analysis.metadata import _has_repro_debug_entry

#: 2048-11-06, the value carried by vcamp140.dll.
_FUTURE_TS = 0x94500285
#: 1994-04-26 — ShareTargets.dll's. A plausible date, and still a hash.
_PLAUSIBLE_TS = 0x2DBB5C60
#: Before the PE format existed.
_ANCIENT_TS = 0x0100_0000


class _DebugStruct:
    def __init__(self, type_):
        self.Type = type_


class _DebugEntry:
    def __init__(self, type_):
        self.struct = _DebugStruct(type_)


class _DebugPE:
    """Exposes only the debug directory, or deliberately none at all."""

    def __init__(self, types=None):
        if types is not None:
            self.DIRECTORY_ENTRY_DEBUG = [_DebugEntry(t) for t in types]


def test_a_repro_entry_is_found_behind_a_codeview_entry():
    """ShareTargets.dll's real debug types are [2, 12, 13, 16, 20].

    The existing PDB extractor returns on the first CodeView entry
    (type 2), so a type-16 check bolted into that loop would never be
    reached on this file - which is one of the two the fix is for.
    """
    assert _has_repro_debug_entry(_DebugPE([2, 12, 13, 16, 20])) is True


def test_a_pe_without_a_debug_directory_is_not_a_repro_build():
    """pefile omits the attribute entirely rather than leaving it empty.

    An unguarded walk raises AttributeError and would degrade every
    debug-less PE to status "error".
    """
    assert _has_repro_debug_entry(_DebugPE()) is False


def test_a_debug_directory_without_type_16_is_not_a_repro_build():
    assert _has_repro_debug_entry(_DebugPE([2, 13, 20])) is False


def test_a_future_timestamp_on_a_reproducible_build_is_not_forged():
    delta, reason = _check_timestamp(
        {"compile_timestamp_raw": _FUTURE_TS, "reproducible_build": True}
    )
    assert delta == 0
    assert "build hash" in reason


def test_a_plausible_timestamp_on_a_reproducible_build_is_still_a_hash():
    """The case a branch-level guard misses, and the reason it matters.

    Roughly 27% of 32-bit hashes land between 1990 and 2026 by chance -
    1990-2026 is ~1.14e9 of 2^32 - so a guard placed inside the
    future-dated and pre-1990 branches leaves them reported as genuine
    compile dates. Measured: all seven benign PE controls carry a REPRO
    entry, yet only four are future-dated.
    """
    delta, reason = _check_timestamp(
        {"compile_timestamp_raw": _PLAUSIBLE_TS, "reproducible_build": True}
    )
    assert delta == 0
    assert "build hash" in reason


def test_a_future_timestamp_without_a_repro_entry_is_still_forged():
    """The paired case — the real anti-analysis technique is retained."""
    delta, reason = _check_timestamp({"compile_timestamp_raw": _FUTURE_TS})
    assert delta == 5
    assert "future" in reason


def test_an_ancient_timestamp_without_a_repro_entry_is_still_forged():
    delta, reason = _check_timestamp({"compile_timestamp_raw": _ANCIENT_TS})
    assert delta == 5
    assert "implausibly old" in reason


def test_an_ancient_timestamp_on_a_reproducible_build_is_not_forged():
    """Suppressed in BOTH directions.

    If the field is a content hash then no reading of it as a date means
    anything, so the pre-1990 branch is as wrong as the future one.
    """
    delta, _reason = _check_timestamp(
        {"compile_timestamp_raw": _ANCIENT_TS, "reproducible_build": True}
    )
    assert delta == 0


def test_a_zeroed_timestamp_is_still_reported_as_nothing():
    """A zeroed field is zeroed, not a hash.

    The existing early return stays ahead of the REPRO guard: calling
    zero a build hash would be a second false statement about the field.
    """
    delta, reason = _check_timestamp(
        {"compile_timestamp_raw": 0, "reproducible_build": True}
    )
    assert delta == 0
    assert reason == ""


def test_eight_header_bytes_in_front_of_a_payload_is_not_a_signature():
    """The spoof that header-only validation lets through.

    Checking dwLength, wRevision and wCertificateType means a sample
    needs exactly eight static bytes in front of its encrypted payload
    to have the whole thing excised as a "signature". Requiring the
    body to parse as PKCS#7 is what raises the cost.
    """
    payload = bytes(range(256)) * 20
    forged = _WIN_CERT.pack(_WIN_CERT.size + len(payload), 0x0200, 0x0002) + payload
    raw = _SECTIONS + forged
    pe = _OverlayPE(raw, len(_SECTIONS), cert=(len(_SECTIONS), len(forged)))
    info = _analyse_overlay(pe)
    assert info["size"] == len(forged)
    assert info["certificate_size"] == 0


def test_a_body_without_the_signed_data_oid_is_not_a_signature():
    """A DER SEQUENCE alone is not a PKCS#7 signature."""
    body = _der_sequence(b"\xC3" * 2000)          # well-formed DER, wrong contents
    cert = _certificate(0, body=body)
    raw = _SECTIONS + cert
    pe = _OverlayPE(raw, len(_SECTIONS), cert=(len(_SECTIONS), len(cert)))
    assert _analyse_overlay(pe)["size"] == len(cert)


def test_an_unaligned_certificate_table_is_rejected():
    """Windows requires the table to start on an 8-byte boundary.

    The record walk advances in file offsets, so an unaligned start
    makes every subsequent alignment step wrong.
    """
    cert = _certificate(2000)
    raw = _SECTIONS + b"\x00" * 4 + cert          # 4 bytes of skew
    offset = len(_SECTIONS) + 4
    assert offset % 8 == 4
    pe = _OverlayPE(raw, len(_SECTIONS), cert=(offset, len(cert)))
    assert _analyse_overlay(pe)["size"] == 4 + len(cert)


def _minimal_certificate():
    """The smallest record that passes every structural check.

    8-byte header plus a DER SEQUENCE holding only the signedData OID,
    padded to the alignment. Records built with dwLength == 8 have an
    empty body and are rejected on the first one, so a table of those
    never exercises the record cap at all.
    """
    return _certificate(0, body=_der_sequence(_SIGNED_DATA_OID))


def test_the_minimal_record_really_is_accepted():
    """Guards the DoS test below from going vacuous again."""
    cert = _minimal_certificate()
    raw = _SECTIONS + cert
    pe = _OverlayPE(raw, len(_SECTIONS), cert=(len(_SECTIONS), len(cert)))
    assert _analyse_overlay(pe)["certificate_size"] == len(cert)


def test_a_table_at_the_record_cap_is_still_accepted():
    """The cap is a ceiling, not a fencepost.

    Walking N records needs N iterations plus one more to notice the
    cursor has arrived, so a loop bounded by `range(cap)` rejected a
    table of exactly `cap` valid records.
    """
    from modules.static.pe_analysis.structure import _MAX_CERT_RECORDS

    table = _minimal_certificate() * _MAX_CERT_RECORDS
    raw = _SECTIONS + table
    pe = _OverlayPE(raw, len(_SECTIONS), cert=(len(_SECTIONS), len(table)))
    info = _analyse_overlay(pe)
    assert info["size"] == 0
    assert info["certificate_size"] == len(table)


def test_a_table_packed_with_minimum_records_is_bounded():
    """A length field the sample controls must not drive an unbounded walk.

    Minimum-size records advance the cursor a couple of dozen bytes at
    a time, so a large overlay of them would otherwise spin through
    millions of iterations in pure Python - the denial of service this
    module's docstring says every scan here has to bound.
    """
    from modules.static.pe_analysis.structure import _MAX_CERT_RECORDS

    table = _minimal_certificate() * (_MAX_CERT_RECORDS + 1)
    raw = _SECTIONS + table
    pe = _OverlayPE(raw, len(_SECTIONS), cert=(len(_SECTIONS), len(table)))
    info = _analyse_overlay(pe)
    assert info["size"] == len(table)
    assert info["certificate_size"] == 0


def test_a_der_value_too_short_to_hold_the_oid_is_rejected():
    """The OID comparison must not read past the SEQUENCE it belongs to.

    A value shorter than the OID puts the read into the record's
    alignment padding, where it could match bytes that are not part of
    the structure at all.
    """
    body = _der_sequence(b"\x01\x02")
    cert = _certificate(0, body=body)
    raw = _SECTIONS + cert
    pe = _OverlayPE(raw, len(_SECTIONS), cert=(len(_SECTIONS), len(cert)))
    assert _analyse_overlay(pe)["certificate_size"] == 0


def test_a_size_omitting_the_final_padding_still_excises_it():
    """A Size covering the record but not its padding left bytes behind.

    Those one-to-seven bytes were then measured as an overlay on a file
    whose only appended data is its signature.
    """
    body = _der_sequence(_SIGNED_DATA_OID + b"\xC3" * 2)   # unaligned length
    unpadded = _WIN_CERT.pack(_WIN_CERT.size + len(body), 0x0200, 0x0002) + body
    padding = b"\x00" * (-len(unpadded) % 8)
    assert padding, "fixture must actually need padding"
    raw = _SECTIONS + unpadded + padding
    pe = _OverlayPE(raw, len(_SECTIONS), cert=(len(_SECTIONS), len(unpadded)))
    info = _analyse_overlay(pe)
    assert info["size"] == 0
    assert info["certificate_size"] == len(unpadded) + len(padding)


def test_trailing_bytes_after_the_last_record_are_not_accepted():
    """The closing equality must be a real check, not true by construction.

    Clamping the cursor to the declared end makes "ended exactly where
    it said" tautological, so a region with bytes belonging to neither
    a record nor its padding would be accepted as a signature.
    """
    cert = _certificate(2000)
    stray = b"\xC3" * 64
    raw = _SECTIONS + cert + stray
    pe = _OverlayPE(raw, len(_SECTIONS),
                    cert=(len(_SECTIONS), len(cert) + len(stray)))
    assert _analyse_overlay(pe)["size"] == len(cert) + len(stray)


def test_two_genuine_records_are_both_excised():
    """Dual-signed binaries carry two records in one table."""
    table = _certificate(800) + _certificate(1200)
    raw = _SECTIONS + table
    pe = _OverlayPE(raw, len(_SECTIONS), cert=(len(_SECTIONS), len(table)))
    info = _analyse_overlay(pe)
    assert info["size"] == 0
    assert info["certificate_size"] == len(table)


# ----------------------------------------------------------------------
# A4 — the Rich header checksum was computed over the wrong bytes
#
# "Rich header present but checksum mismatch — likely tampered" fired on
# all seven benign Microsoft controls. Measured: pefile's own key
# validation passes on every one, and an independent recompute matches
# the stored checksum on every one, so the tool's arithmetic was what
# was wrong.
#
# Two compounded errors: the sum was taken over pefile's `clear_data`,
# which is the DECRYPTED RICH HEADER BODY rather than the DOS header and
# stub the old comment claimed, and it was seeded with e_lfanew rather
# than the offset of the DanS marker.
#
# The oracle below is real linker output — the DOS header, stub,
# comp-ID pairs and stored key of vcamp140.dll, a Microsoft Visual C++
# runtime from System32. Genuine bytes rather than a checksum produced
# by the implementation under test are what stop this being
# tautological. They carry nothing host-identifying.
# ----------------------------------------------------------------------

from modules.static.pe_analysis.metadata import (
    _RICH_DANS,
    _RICH_MARKER_OFFSET,
    _rich_checksum_mismatch,
)

_RICH_KEY = 0x607E2003
_RICH_VALUES = [9664521, 12, 16878155, 8, 17009227, 6, 17074763, 8,
                17140299, 31, 16875892, 13, 65536, 139, 17402443, 12,
                16812619, 1, 16747083, 1, 9895936, 2, 16943691, 1]
_DOS_AND_STUB = bytes.fromhex(
    "4d5a90000300000004000000ffff0000b8000000000000004000000000000000"
    "0000000000000000000000000000000000000000000000000000000008010000"
    "0e1fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f"
    "742062652072756e20696e20444f53206d6f64652e0d0d0a2400000000000000"
)


def _rich_image(stub=None, key=_RICH_KEY):
    """A file prefix carrying a valid DanS marker at 0x80."""
    stub = _DOS_AND_STUB if stub is None else stub
    marker = struct.pack("<4I", _RICH_DANS ^ key, key, key, key)
    return stub + marker


def test_the_rich_stub_fixture_is_the_right_shape():
    """Guards the oracle itself: the marker must land exactly at 0x80."""
    assert len(_DOS_AND_STUB) == _RICH_MARKER_OFFSET


def test_a_genuine_microsoft_rich_header_verifies():
    """The defect, stated as a test: this reported "likely tampered"."""
    assert _rich_checksum_mismatch(
        _rich_image(), _RICH_VALUES, _RICH_KEY) is False


def test_a_flipped_stub_byte_is_still_detected():
    """The paired case — real tampering must not become invisible."""
    stub = bytearray(_DOS_AND_STUB)
    stub[0x50] ^= 0x01
    assert _rich_checksum_mismatch(
        _rich_image(bytes(stub)), _RICH_VALUES, _RICH_KEY) is True


def test_an_altered_comp_id_count_is_detected():
    """The other half of the header is covered too."""
    tampered = list(_RICH_VALUES)
    tampered[1] += 1
    assert _rich_checksum_mismatch(
        _rich_image(), tampered, _RICH_KEY) is True


def test_a_missing_rich_marker_is_not_called_tampered():
    """"Could not determine" is not "tampered"."""
    assert _rich_checksum_mismatch(
        _DOS_AND_STUB + bytes(16), _RICH_VALUES, _RICH_KEY) is None


def test_a_planted_dans_earlier_in_the_stub_does_not_move_the_check():
    """The bypass an offset scan would have opened.

    The marker is a single dword, so searching for the first one that
    XORs to DanS lets a tampered binary plant a decoy earlier in the DOS
    stub and move the computation off its real header. Reading 0x80
    directly — pefile's own constant, and where its comp-ID pairs come
    from — cannot be steered that way.
    """
    stub = bytearray(_DOS_AND_STUB)
    struct.pack_into("<I", stub, 0x40, _RICH_DANS ^ _RICH_KEY)
    assert _rich_checksum_mismatch(
        _rich_image(bytes(stub)), _RICH_VALUES, _RICH_KEY) is True


def test_a_truncated_file_is_not_called_tampered():
    assert _rich_checksum_mismatch(b"MZ", _RICH_VALUES, _RICH_KEY) is None


def test_a_flat_values_list_is_read_as_pairs():
    """pefile returns [comp_id, count, ...], not a list of tuples.

    Unpacking it as pairs raises TypeError, which the handler would turn
    into "not corrupted" for every binary — disabling the check in
    silence rather than failing.
    """
    assert all(isinstance(v, int) for v in _RICH_VALUES)
    assert _rich_checksum_mismatch(
        _rich_image(), _RICH_VALUES, _RICH_KEY) is False


# ----------------------------------------------------------------------
# A5 — a resource-only or forwarder DLL is not packed
#
# "Empty import table — resolves every API at runtime or unpacks itself"
# and "Entry point in unusual section 'None' — likely packed/unpacker
# stub" together score +20. Measured: two of the seven benign PE
# controls are resource-only DLLs — a resource directory, no imports, no
# exports, ep == 0 and no executable section at all — and take the full
# +20 for being ordinary Windows components.
#
# The brief assumed msidntld.dll was a forwarder. It is not: it has zero
# exports, so no forwarder strings exist. Both benign shapes are handled
# because both occur in System32.
# ----------------------------------------------------------------------

from modules.static.pe_analysis.structure import (
    _check_entry_point,
    _classify_importless,
    _has_tls_directory,
)

_DLL_FLAG = 0x2000
_EXEC_FLAG = 0x20000000


class _ShapeSection:
    """Enough of a section for both the classifier and the EP check."""

    def __init__(self, characteristics):
        self.Characteristics = characteristics
        self.VirtualAddress = 0x1000
        self.Misc_VirtualSize = 0x200
        self.SizeOfRawData = 0x200
        self.Name = b".text" + bytes(3)


class _ShapeSym:
    def __init__(self, forwarder=None):
        self.forwarder = forwarder


class _ShapeExports:
    def __init__(self, symbols):
        self.symbols = symbols


class _ShapeFileHeader:
    def __init__(self, characteristics):
        self.Characteristics = characteristics


class _ShapeOptHeader:
    def __init__(self, ep, directories):
        self.AddressOfEntryPoint = ep
        self.DATA_DIRECTORY = directories


class _ShapePE:
    """A PE described by only the properties the classifier reads."""

    def __init__(self, *, dll=True, ep=0, exec_section=False, resources=True,
                 exports=None, tls=False, tls_directory=False,
                 n_directories=16):
        self.FILE_HEADER = _ShapeFileHeader(_DLL_FLAG if dll else 0)
        dirs = [_Dir(0, 0) for _ in range(n_directories)]
        if tls_directory and n_directories > 9:
            dirs[9] = _Dir(0x5000, 24)
        self.OPTIONAL_HEADER = _ShapeOptHeader(ep, dirs)
        self.sections = [
            _ShapeSection(_EXEC_FLAG if exec_section else 0x40000000)
        ]
        if resources:
            self.DIRECTORY_ENTRY_RESOURCE = object()
        if exports is not None:
            self.DIRECTORY_ENTRY_EXPORT = _ShapeExports(exports)
        if tls:
            self.DIRECTORY_ENTRY_TLS = object()


def test_a_resource_only_dll_is_not_packed():
    """The msidntld.dll shape, measured on two of seven controls."""
    assert _classify_importless(_ShapePE()) == "resource_only"


def test_a_forwarder_dll_is_not_packed():
    pe = _ShapePE(exports=[_ShapeSym(b"NTDLL.RtlAlloc"),
                           _ShapeSym(b"NTDLL.RtlFree")])
    assert _classify_importless(pe) == "forwarder"


def test_an_api_set_dll_is_a_forwarder_not_resource_only():
    """Branch order matters even though the score does not.

    An api-ms-win-core-* DLL has no executable section and carries
    .rsrc for its version information, so testing resource-only first
    would label it resource-only while it has dozens of forwarded
    exports — a false statement about an ordinary Windows structure,
    which is the whole defect being fixed.
    """
    pe = _ShapePE(exports=[_ShapeSym(b"KERNELBASE.Sleep")] * 24)
    assert _classify_importless(pe) == "forwarder"


def test_an_importless_exe_is_still_packed():
    """The paired case. Without the DLL bit there is no benign reading."""
    assert _classify_importless(_ShapePE(dll=False)) is None


def test_an_exe_with_forwarded_exports_is_still_packed():
    """A packed EXE carrying one dummy forwarded export must not escape."""
    pe = _ShapePE(dll=False, exports=[_ShapeSym(b"OTHER.Thing")])
    assert _classify_importless(pe) is None


def test_a_dll_with_an_executable_section_is_still_packed():
    assert _classify_importless(_ShapePE(exec_section=True)) is None


def test_a_dll_with_an_entry_point_is_still_packed():
    """Clearing a section characteristic must not buy an exemption.

    With NX_COMPAT clear, 32-bit Windows still executes from a section
    lacking IMAGE_SCN_MEM_EXECUTE, so "no executable section" alone is
    reachable by a packer. An entry point means something starts.
    """
    assert _classify_importless(_ShapePE(ep=0x1000)) is None


def test_a_dll_with_tls_callbacks_is_still_packed():
    """TLS callbacks run before and independently of the entry point."""
    assert _classify_importless(_ShapePE(tls=True)) is None


def test_a_malformed_tls_directory_still_counts_as_tls():
    """pefile only sets DIRECTORY_ENTRY_TLS when the directory parses.

    A deliberately malformed one leaves the attribute absent while the
    data directory still points at it, and the loader rather than
    pefile decides whether the callbacks run.
    """
    assert _has_tls_directory(_ShapePE(tls_directory=True)) is True
    assert _classify_importless(_ShapePE(tls_directory=True)) is None


def test_a_dll_without_resources_is_not_resource_only():
    assert _classify_importless(_ShapePE(resources=False)) is None


def test_a_short_data_directory_does_not_break_the_tls_check():
    assert _has_tls_directory(_ShapePE(n_directories=4)) is False


def test_a_dll_with_no_entry_point_has_no_entry_point_anomaly():
    """ep == 0 is spec-legal for a DLL: the field is optional there."""
    assert _check_entry_point(_ShapePE(), [])["anomaly"] is False


def test_an_exe_with_no_entry_point_is_still_an_anomaly():
    """The paired case — on an EXE, RVA 0 is the MZ header, not code."""
    assert _check_entry_point(_ShapePE(dll=False), [])["anomaly"] is True


def test_an_overlay_offset_past_the_end_reports_no_overlay():
    """An inverted span must not become a negative size.

    Summing fragments replaced a slice, and a slice of a past-the-end
    offset is empty while the arithmetic goes negative — sailing past
    the "no overlay" check and reporting a negative size. pefile does
    not currently produce such an offset; the guard exists because the
    two fragment branches were otherwise inconsistent about it.
    """
    raw = _SECTIONS
    pe = _OverlayPE(raw, len(_SECTIONS) + 64, cert=(0, 0))
    info = _analyse_overlay(pe)
    assert info["size"] == 0
    assert info["entropy"] == 0.0


def test_a_dll_with_a_few_imports_is_not_called_resource_only():
    """A resource-only DLL has no code, so it has no import table.

    Every structural test still matches a DLL with one to four imports,
    so without the count it was told "No imports" while having some —
    and had its small-import score dropped on the strength of it.
    """
    pe = _ShapePE()
    assert _classify_importless(pe, 0) == "resource_only"
    assert _classify_importless(pe, 3) is None


def test_a_forwarder_may_carry_a_couple_of_imports():
    """The paired case: a forwarder legitimately imports one or two."""
    pe = _ShapePE(exports=[_ShapeSym(b"NTDLL.RtlAlloc")])
    assert _classify_importless(pe, 2) == "forwarder"


def test_a_zeroed_timestamp_is_not_rendered_as_a_build_hash():
    """Zero is zero, even on a reproducible build.

    _check_timestamp already refuses to call zero a hash; the rendered
    header string has to agree, or the JSON and HTML reports say
    "Build hash 0x00000000" about a field that holds nothing.
    """
    class _Hdr:
        TimeDateStamp = 0
        Machine = 0x8664
        NumberOfSections = 3
        Characteristics = 0x2022

    class _Opt:
        AddressOfEntryPoint = 0x1000
        ImageBase = 0x140000000
        DllCharacteristics = 0x0160
        Subsystem = 2

    class _PE:
        FILE_HEADER = _Hdr()
        OPTIONAL_HEADER = _Opt()
        DIRECTORY_ENTRY_DEBUG = [_DebugEntry(16)]

    headers = _extract_headers(_PE())
    assert headers["reproducible_build"] is True
    assert "Build hash" not in headers["compile_timestamp"]
    assert _check_timestamp(headers) == (0, "")
