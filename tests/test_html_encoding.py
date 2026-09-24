"""HTML decoding in html_analysis.

Every pattern in the module runs against the decoded text, so the choice of
codec decides whether there is anything to match. A page decoded with the
wrong codec does not fail — it produces mojibake, and every indicator
silently finds nothing. That is the worst shape a failure can take here: a
clean report for a malicious page.
"""

from __future__ import annotations

import pytest

from modules.static.html_analysis import _read_html, run

_SCRIPT = '<html><script>eval(atob("QUFB"))</script>'


def _write(tmp_path, raw: bytes, name: str = "page.html"):
    path = tmp_path / name
    path.write_bytes(raw)
    return path


@pytest.mark.parametrize("pad", ["", "x", "xx", "xxx"])
def test_a_windows_1252_page_is_not_decoded_as_utf_16(tmp_path, pad):
    """utf-16 strict accepts almost any even-length bytes, so it won.

    `bytes.decode("utf-16")` with no BOM assumes little-endian and pairs
    the bytes up, which succeeds for essentially any even-length input. A
    Windows-1252 page that failed strict utf-8 — anything with an accented
    character — was therefore claimed by utf-16 whenever its length
    happened to be even, and the whole document became mojibake.

    Measured before the fix: a 50-byte latin-1 page decoded to
    '格浴㹬猼牣灩㹴…' and the eval(atob( ) call vanished, so the module
    reported nothing on a page carrying it.
    """
    raw = (_SCRIPT + "<!--\xe9\xe8-->" + pad).encode("latin-1")

    text, encoding = _read_html(_write(tmp_path, raw))

    assert "utf-16" not in encoding, f"decoded as {encoding}: {text[:40]!r}"
    assert 'eval(atob("QUFB"))' in text


def test_a_genuine_utf_16_page_is_still_decoded(tmp_path):
    """The codec is still needed — it is written with a BOM in practice."""
    raw = _SCRIPT.encode("utf-16")  # utf-16 codec emits a BOM

    text, encoding = _read_html(_write(tmp_path, raw))

    assert "utf-16" in encoding
    assert 'eval(atob("QUFB"))' in text


def test_a_utf_8_page_is_decoded_as_utf_8(tmp_path):
    raw = (_SCRIPT + "<!--café-->").encode("utf-8")

    text, encoding = _read_html(_write(tmp_path, raw))

    assert encoding.startswith("utf-8")
    assert "café" in text


def test_a_utf_8_bom_does_not_leak_into_the_text(tmp_path):
    """A leading U+FEFF would sit in front of <html> and break prefix tests."""
    raw = b"\xef\xbb\xbf" + _SCRIPT.encode("utf-8")

    text, _ = _read_html(_write(tmp_path, raw))

    assert text.startswith("<html>")


def test_the_indicators_survive_a_windows_1252_page(tmp_path):
    """End to end: the mojibake silenced the whole module, not one check."""
    raw = (
        '<html><script>var a=eval(atob("QUFB"));'
        'navigator.clipboard.writeText("powershell -enc AAAA");</script>'
        "<!--\xe9\xe8-->"
    ).encode("latin-1")

    result = run(_write(tmp_path, raw), {})

    assert result["status"] == "success"
    assert result["data"]["has_eval_atob"] is True
    assert result["data"]["clipboard_contains_lolbin"] is True
    assert result["score_delta"] > 0


def test_a_utf_16_bom_does_not_leak_into_the_text(tmp_path):
    """`utf-16-le` does not consume a BOM the way `utf-16` does.

    Naming the endianness explicitly decodes the mark as a literal
    U+FEFF, leaving it in front of `<html>` — which breaks every prefix
    test downstream, including the module's own HTML sniffing. The
    endian-agnostic codec name strips it, which is why it is used.

    UTF-32 is not covered here because it is not supported at all, by
    deliberate choice — see the NUL-prefix test for why listing it was
    an evasion rather than a feature.
    """
    raw = _SCRIPT.encode("utf-16")

    text, _ = _read_html(_write(tmp_path, raw))

    assert text.startswith("<html>"), repr(text[:12])
    assert "\ufeff" not in text


def test_a_bom_less_utf_16_page_is_not_guessed_at(tmp_path):
    """Matching the browser is the contract, not maximal recovery.

    Without a BOM, HTML5 sniffing does not select UTF-16 either, and the
    spec explicitly overrides a `<meta charset="utf-16">` declaration to
    UTF-8 precisely to stop this being an attack surface. So a BOM-less
    UTF-16 page is not something a browser executes as UTF-16, and
    guessing at it here would reintroduce the false positive on
    Windows-1252 that the BOM rule exists to prevent.
    """
    raw = _SCRIPT.encode("utf-16-le")  # no BOM

    _, encoding = _read_html(_write(tmp_path, raw))

    assert "utf-16" not in encoding


def test_a_utf_16_bom_followed_by_a_nul_is_not_read_as_utf_32(tmp_path):
    """Adding UTF-32 to the BOM table created a one-character evasion.

    The UTF-32-LE mark is the UTF-16-LE mark followed by two NULs, so a
    UTF-16 document whose first character is U+0000 matches it. Decoding
    that as UTF-32 produced mojibake and the script vanished.

    HTML5 settles it: the UTF-32 encodings are not supported, and a
    browser handed `ff fe 00 00` decodes UTF-16-LE. Matching the browser
    is the contract, so UTF-32 is not in the table at all.
    """
    raw = b"\xff\xfe" + '\x00<html><script>eval(atob("QQ=="))</script>'.encode("utf-16-le")

    text, encoding = _read_html(_write(tmp_path, raw))

    assert "utf-32" not in encoding
    assert 'eval(atob("QQ=="))' in text


@pytest.mark.parametrize(
    ("label", "raw"),
    [
        ("utf-8 BOM", b"\xef\xbb\xbf<html><script>x</script>"),
        ("utf-16 BOM", '<html><script>x</script>'.encode("utf-16")),
        ("leading whitespace", b"\n\n  <html><script>x</script>"),
        ("uppercase", b"<HTML><SCRIPT>x</SCRIPT>"),
        ("doctype", b"<!DOCTYPE html><html></html>"),
    ],
)
def test_html_is_recognised_behind_a_decoy_extension(tmp_path, label, raw):
    """The magic sniff is what catches a page delivered as .svg or .txt.

    It compared raw bytes, so a byte-order mark sat in front of `<html`
    and the comparison failed — the file was not analysed at all. A
    UTF-16 page failed for the same reason, its `<` followed by a NUL.
    Both are ordinary ways to save an HTML file and both are opened as
    HTML by a browser whatever the extension says.
    """
    from modules.static.html_analysis import _is_html_target

    path = _write(tmp_path, raw, name="invoice.svg")

    assert _is_html_target(path) is True, label


def test_a_non_html_file_is_still_not_claimed(tmp_path):
    """The sniff must stay narrow — mentioning <script> is not enough."""
    from modules.static.html_analysis import _is_html_target

    path = _write(tmp_path, b"a log line mentioning <script> and <html>", name="a.log")

    assert _is_html_target(path) is False
