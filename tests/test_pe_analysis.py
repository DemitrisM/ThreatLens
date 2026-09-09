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
