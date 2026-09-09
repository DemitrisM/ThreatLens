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
