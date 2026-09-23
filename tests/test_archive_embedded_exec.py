"""Typed-executable recognition for extracted archive members.

``hash_embedded_executables`` decides, by content rather than by name, which
extracted members are native executables worth hashing and forwarding to
VirusTotal. A type it does not recognise is silently not forwarded, so the
MIME table is the whole reach of the feature.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from modules.static.archive_analysis.embedded_exec import (
    _EXEC_MIME_TO_TYPE,
    hash_embedded_executables,
)
from modules.static.archive_analysis.entries import ArchiveEntry

magic = pytest.importorskip("magic")


def _entry_for(path: Path) -> ArchiveEntry:
    return ArchiveEntry(
        name=path.name,
        size_uncompressed=path.stat().st_size,
        extracted_path=str(path),
    )


def test_a_position_independent_elf_is_recognised(tmp_path):
    """Modern Linux executables are PIE, and PIE had its own MIME type.

    Distributions have compiled executables as position-independent by
    default for years, and libmagic reports those as
    ``application/x-pie-executable`` rather than
    ``application/x-executable``. Only the latter was mapped, so an ELF
    payload carried inside an archive was typed as "not an executable" and
    never hashed or sent to VirusTotal. Checked on this machine: /usr/bin/ls
    and /bin/bash both report the PIE type.
    """
    source = shutil.which("ls")
    assert source, "no /usr/bin/ls to test against"
    target = tmp_path / "member.bin"
    target.write_bytes(Path(source).read_bytes())

    assert magic.from_file(str(target), mime=True) == "application/x-pie-executable"

    found = hash_embedded_executables([_entry_for(target)])

    assert len(found) == 1, found
    assert found[0]["type"] == "ELF"
    assert len(found[0]["sha256"]) == 64


def test_a_shared_object_is_recognised(tmp_path):
    """The libc on this box is x-sharedlib, which was already mapped."""
    source = Path("/lib/x86_64-linux-gnu/libc.so.6")
    if not source.exists():
        pytest.skip("no libc at the expected path")
    target = tmp_path / "member.so"
    target.write_bytes(source.read_bytes())

    found = hash_embedded_executables([_entry_for(target)])

    assert len(found) == 1, found
    assert found[0]["type"] == "ELF"


def test_a_plain_file_is_not_reported(tmp_path):
    """Identification is by content, so a misleading name proves nothing."""
    target = tmp_path / "setup.exe"
    target.write_text("this is not a program\n")

    assert hash_embedded_executables([_entry_for(target)]) == []


def test_every_mapped_mime_resolves_to_a_known_label():
    """The table's values are the labels the report and the row builder use."""
    assert set(_EXEC_MIME_TO_TYPE.values()) <= {"PE", "ELF", "MachO"}
