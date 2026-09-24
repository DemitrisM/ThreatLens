"""archive_analysis indicator tests.

Covers the cross-format indicators in ``indicators.py``, which operate purely
on the normalised ``ArchiveEntry`` list and so need no real archive on disk.
"""

from __future__ import annotations

import pytest

from modules.static.archive_analysis.entries import ArchiveEntry
from modules.static.archive_analysis.indicators import (
    detect_dangerous_members,
    detect_double_extension,
    detect_high_entropy_filenames,
    detect_null_byte_filenames,
    detect_path_traversal,
    detect_persistence_paths,
    detect_rtlo_filenames,
    scan_comments_for_iocs,
)


def _entry(name, raw_name=None):
    return ArchiveEntry(name=name, raw_name=raw_name)


# ----------------------------------------------------------------------
# Persistence paths
#
# The markers are matched against a lowercased member name. Windows paths
# inside archives use single backslashes, so a marker carrying a doubled
# one can never match — which is what shipped.
# ----------------------------------------------------------------------

@pytest.mark.parametrize("member", [
    r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.exe",
    r"AppData\Local\Temp\dropper.exe",
    r"C:\Windows\System32\evil.dll",
    r"C:\Windows\SysWOW64\evil.dll",
    r"Users\victim\AppData\Roaming\payload.scr",
    r"some\path\Startup\run.lnk",
    r"C:\Windows\Temp\stage2.bin",
])
def test_windows_backslash_persistence_paths_are_detected(member):
    assert detect_persistence_paths([_entry(member)]) == [member]


@pytest.mark.parametrize("member", [
    "appdata/roaming/evil.exe",
    "appdata/local/evil.exe",
    "home/user/startup/evil.sh",
    "system32/evil.dll",
    "syswow64/evil.dll",
    "var/temp/evil.bin",
])
def test_forward_slash_persistence_paths_still_detected(member):
    """The POSIX-separator forms were the only ones that ever worked."""
    assert detect_persistence_paths([_entry(member)]) == [member]


@pytest.mark.parametrize("member", [
    "%APPDATA%\\run.exe",
    "%TEMP%\\stage.exe",
    "%SystemRoot%\\evil.dll",
])
def test_environment_variable_persistence_paths_are_detected(member):
    assert detect_persistence_paths([_entry(member)]) == [member]


def test_cve_2025_8088_startup_drop_is_detected_via_raw_name():
    """The flagship sample hides its Startup path in an NTFS ADS suffix.

    ``rarfile`` strips the suffix, so the traversal is only visible on
    ``raw_name``, recovered by the raw RAR5 header walk.
    """
    decoy = "fiyat teklifi.pdf"
    ads = (
        r"..\..\AppData\Roaming\Microsoft\Windows"
        r"\Start Menu\Programs\Startup\Updater.exe"
    )
    entry = _entry(decoy, raw_name=f"{decoy}:{ads}")

    assert detect_persistence_paths([entry]) == [entry.raw_name]
    # The traversal indicator has always caught this one; assert it still does
    # so the two indicators are known to fire together on the real shape.
    assert detect_path_traversal([entry]) == [entry.raw_name]


def test_benign_members_are_not_flagged_as_persistence():
    benign = [
        _entry("readme.txt"),
        _entry("docs/manual.pdf"),
        _entry(r"Program Files\vendor\app.exe"),
        _entry("src/main.py"),
    ]
    assert detect_persistence_paths(benign) == []


def test_every_persistence_marker_is_reachable():
    """A marker that cannot match any input is dead weight, not a rule.

    This is the test that would have caught the shipped defect: each marker
    is exercised against a member built from the marker itself.
    """
    from modules.static.archive_analysis.indicators import (
        _PERSISTENCE_PATH_MARKERS,
    )

    unreachable = []
    for marker in _PERSISTENCE_PATH_MARKERS:
        probe = f"prefix{marker}payload.exe"
        if not detect_persistence_paths([_entry(probe)]):
            unreachable.append(marker)

    assert unreachable == [], f"markers that can never fire: {unreachable}"


# ----------------------------------------------------------------------
# Archive-comment IOC scanning
#
# The raw IOC regexes match anything shaped like `word.word`, so a comment
# naming a file scores as a domain unless the extractor's own
# false-positive filtering is applied.
# ----------------------------------------------------------------------

@pytest.mark.parametrize("comment", [
    "Packed with WinRAR. See readme.txt and setup.exe for details.",
    "Extract config.json then run install.bat",
    "Contents: invoice.pdf, notes.docx",
])
def test_benign_filenames_in_comments_are_not_iocs(comment):
    assert scan_comments_for_iocs([comment]) == []


def test_real_iocs_in_comments_are_still_reported():
    """Filtering must not be so aggressive that it swallows genuine IOCs."""
    found = scan_comments_for_iocs([
        "c2 at http://evil-domain.com/gate.php or 45.61.136.7",
    ])
    assert any("evil-domain.com" in f for f in found)
    assert any("45.61.136.7" in f for f in found)


@pytest.mark.parametrize("comment, why", [
    ("build host 192.168.1.10", "RFC 1918 private"),
    ("internal 172.16.5.4", "RFC 1918 private, the /12 block"),
    ("docker bridge 172.17.0.1", "default Docker bridge"),
    ("loopback 127.0.0.1", "loopback"),
    ("doc example 203.0.113.45", "RFC 5737 TEST-NET-3 documentation space"),
])
def test_non_routable_addresses_in_comments_are_filtered(comment, why):
    """The extractor drops non-routable space; the comment scan must agree."""
    assert scan_comments_for_iocs([comment]) == [], why


def test_empty_and_missing_comments_are_safe():
    assert scan_comments_for_iocs([]) == []
    assert scan_comments_for_iocs([""]) == []


def test_comment_scan_actually_reaches_the_filter(monkeypatch):
    """Guard against a vacuously-passing negative suite.

    Every "benign input yields no IOCs" test above asserts an empty list, so
    a scan that returned [] for the wrong reason — a failed import, a renamed
    helper — would satisfy all of them. Assert the filter is genuinely called.
    """
    from modules.static import ioc_extractor

    seen = []
    real = ioc_extractor._filter_fps

    def _spy(ioc_type, matches):
        seen.append(ioc_type)
        return real(ioc_type, matches)

    monkeypatch.setattr(ioc_extractor, "_filter_fps", _spy)
    scan_comments_for_iocs(["see http://evil-domain.com/x and readme.txt"])

    assert "domain" in seen, "the domain filter was never reached"
    assert "url" in seen, "the url filter was never reached"


def test_missing_filter_helper_fails_loudly(monkeypatch):
    """A renamed helper must raise, not degrade into a silent empty result."""
    from modules.static import ioc_extractor

    monkeypatch.delattr(ioc_extractor, "_filter_fps")
    with pytest.raises(AttributeError):
        scan_comments_for_iocs(["http://evil-domain.com/x"])


# ----------------------------------------------------------------------
# Separator padding must not evade the markers
#
# Windows canonicalises runs of separators away, so `appdata//roaming\x.exe`
# drops to exactly the same place as the plain form. If the matcher does not
# canonicalise too, adding one character defeats the whole table.
# ----------------------------------------------------------------------

@pytest.mark.parametrize("member", [
    "appdata//roaming/evil.exe",
    "appdata///roaming//evil.exe",
    "appdata\\\\roaming\\evil.exe",
    "appdata\\\\\\roaming\\evil.exe",
    "appdata/\\roaming/evil.exe",
    "C:\\\\Windows\\\\System32\\\\evil.dll",
    "some//path//Startup//run.lnk",
])
def test_separator_padding_does_not_evade_persistence_markers(member):
    assert detect_persistence_paths([_entry(member)]) == [member]


# ---------------------------------------------------------------------------
# Extension indicators must read the recovered raw name too
# ---------------------------------------------------------------------------

def _ads_entry(name: str, raw_name: str) -> ArchiveEntry:
    """A member as rar_handler produces it for a CVE-2025-8088 archive."""
    return ArchiveEntry(name=name, raw_name=raw_name, size_uncompressed=4096)


_CVE_DECOY = "1. Why Crypto Investors Believe Digital Assets Will Win.pdf"
_CVE_RAW = (
    "1. Why Crypto Investors Believe Digital Assets Will Win.pdf"
    ":../../0.The_Battle_Decade_Bitcoin_vs_Bricks,txt.lnk"
)


def test_a_dangerous_extension_hidden_in_an_ads_suffix_is_reported():
    """The real payload extension lives in raw_name, where nothing looked.

    Taken from the CVE-2025-8088 sample in the corpus. rarfile reports a
    .pdf; the archive really drops a .lnk two directories up. The path
    indicators read raw_name and fired, but every extension indicator read
    only name, so `dangerous_member` never fired for an archive whose whole
    purpose is dropping a shortcut. That cost the combo rules as well as the
    row in the report: `persistence_path + dangerous_member` and
    `embedded_pe + dangerous_member` both need it.
    """
    entries = [_ads_entry(_CVE_DECOY, _CVE_RAW)]

    found = detect_dangerous_members(entries)

    assert len(found) == 1, found
    assert found[0]["extension"] == ".lnk"
    assert found[0]["name"] == _CVE_RAW


def test_the_sanitised_name_is_still_reported_when_it_is_the_dangerous_one():
    """raw_name is additional evidence, not a replacement for name."""
    entries = [ArchiveEntry(name="payload.exe", size_uncompressed=4096)]

    found = detect_dangerous_members(entries)

    assert len(found) == 1, found
    assert found[0]["extension"] == ".exe"


def test_a_member_dangerous_under_both_names_is_reported_once():
    """One member is one finding, however many spellings implicate it."""
    entries = [_ads_entry("dropper.exe", "dropper.exe:../../startup/run.lnk")]

    found = detect_dangerous_members(entries)

    assert len(found) == 1, found


def test_a_double_extension_hidden_in_an_ads_suffix_is_reported():
    """The decoy-extension trick works just as well inside the suffix."""
    entries = [_ads_entry("report.pdf", "report.pdf:../../holiday.jpg.exe")]

    assert detect_double_extension(entries) == [
        "report.pdf:../../holiday.jpg.exe",
    ]


def test_an_rtlo_character_hidden_in_an_ads_suffix_is_reported():
    """A bidi override in the suffix renders in exactly the same places."""
    entries = [_ads_entry("notes.txt", "notes.txt:../../invoice‮gnp.exe")]

    assert detect_rtlo_filenames(entries) == [
        "notes.txt:../../invoice‮gnp.exe",
    ]


def test_a_null_byte_hidden_in_an_ads_suffix_is_reported():
    """Likewise a NUL, which truncates the name for a C-string consumer."""
    entries = [_ads_entry("notes.txt", "notes.txt:../../safe.txt\x00.exe")]

    assert detect_null_byte_filenames(entries) == [
        "notes.txt:../../safe.txt\x00.exe",
    ]


def test_entries_without_a_raw_name_are_unaffected():
    """The overwhelmingly common case must behave exactly as before."""
    entries = [
        ArchiveEntry(name="readme.txt", size_uncompressed=10),
        ArchiveEntry(name="image.png", size_uncompressed=10),
    ]

    assert detect_dangerous_members(entries) == []
    assert detect_double_extension(entries) == []
    assert detect_rtlo_filenames(entries) == []
    assert detect_null_byte_filenames(entries) == []


def test_an_ads_traversal_path_is_not_itself_a_high_entropy_filename():
    """The path must be measured as a payload name, not as a whole path.

    An ADS suffix is a path, and on POSIX pathlib does not split on
    backslashes, so the unnormalised "stem" of a Windows traversal path is
    the entire string. Measured: that scores 4.728 against the 4.5
    threshold and would fire on the length and variety of the path itself,
    while the payload name inside it, ``a7Fq2xR9mK``, scores 3.322 and
    should not. Separators are normalised first so the second number is
    the one that decides.
    """
    entries = [
        _ads_entry(
            "decoy.pdf",
            "decoy.pdf:..\\..\\Windows\\Start Menu\\a7Fq2xR9mK.exe",
        ),
    ]

    assert detect_high_entropy_filenames(entries) == []


def test_a_long_generated_payload_name_in_an_ads_suffix_is_reported():
    """Once the stem is isolated, a genuinely generated name still fires.

    The threshold needs about 2**4.5 ~ 23 distinct characters, so a short
    random stem cannot reach it however random it is. A long one can, and
    hiding it behind a decoy in the ADS suffix must not be a way out.
    """
    payload = "Qx7fL2pR9zVn4KdW8sYb3TmJ6gHc5uAe"
    entries = [
        _ads_entry("invoice.pdf", f"invoice.pdf:..\\..\\{payload}.exe"),
    ]

    found = detect_high_entropy_filenames(entries)

    assert found == [f"invoice.pdf:..\\..\\{payload}.exe"], found


def test_high_entropy_reports_a_member_once():
    """A member high-entropy under both spellings is still one finding."""
    noisy = "Qx7fL2pR9zVn4KdW8sYb3TmJ6gHc5uAe"
    entries = [_ads_entry(f"{noisy}.dat", f"{noisy}.dat:../../{noisy}.exe")]

    assert len(detect_high_entropy_filenames(entries)) == 1
