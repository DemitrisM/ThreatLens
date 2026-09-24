"""External-resource attribution in html_analysis.

The module's job here is to name the domain serving an injected script. A
domain reported wrongly is worse than one not reported at all: it goes into
the report as an IOC, and an analyst blocks or pivots on it.
"""

from __future__ import annotations

import pytest

from modules.static.html_analysis.external import (
    _CDN_ALLOWLIST,
    _CDN_ALLOWLIST_NORMALISED,
    _extract_domain,
    detect_external_resources,
)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://wordpress.com/a.js", "wordpress.com"),
        ("https://wp.com/a.js", "wp.com"),
        ("https://wow.com/a.js", "wow.com"),
        ("https://web.site/a.js", "web.site"),
        ("https://evil.com/a.js", "evil.com"),
        ("https://sub.example.co.uk/a.js", "sub.example.co.uk"),
    ],
)
def test_a_domain_is_not_mangled_by_the_www_strip(url, expected):
    """`lstrip("www.")` removed leading w and . characters, not a prefix.

    str.lstrip takes a set of characters, so every domain beginning with a
    `w` lost it: wordpress.com became ordpress.com, wp.com became p.com,
    web.site became eb.site. That name then travelled into the report as
    the suspicious domain — an IOC an analyst would block, for a host that
    does not exist.
    """
    assert _extract_domain(url) == expected


def test_the_www_prefix_is_actually_stripped():
    """The condition was also inverted, so www. was the one case kept.

    The comment said "strip www. prefix for comparison" while the code
    applied the strip only when the domain did *not* start with www.
    """
    assert _extract_domain("https://www.example.com/a.js") == "example.com"


def test_every_allowlist_entry_can_be_produced_by_the_extractor():
    """An entry the extractor can never emit is a rule that cannot fire.

    wordpress.com and wp.com were both unreachable: the extractor mangled
    them before the comparison, so a script served from either was reported
    as suspicious under a fabricated name.
    """
    unreachable = [
        entry for entry in sorted(_CDN_ALLOWLIST)
        if _extract_domain(f"https://{entry}/x.js") not in _CDN_ALLOWLIST_NORMALISED
    ]

    assert unreachable == [], f"allowlist entries that can never match: {unreachable}"


def test_an_allowlisted_cdn_is_not_reported_as_suspicious():
    """The end-to-end consequence, for the two entries that were dead."""
    result = detect_external_resources(
        ["https://wordpress.com/wp-includes/js/x.js", "https://wp.com/y.js"],
        [],
        [],
    )

    assert result["suspicious_external_domains"] == []
    assert result["suspicious_external_script_urls"] == []


def test_a_genuinely_foreign_domain_is_still_reported():
    """The allowlist must not have been widened into uselessness."""
    result = detect_external_resources(["https://evil-c2.test/abc.js"], [], [])

    assert result["suspicious_external_domains"] == ["evil-c2.test"]


def test_a_www_prefixed_cdn_still_matches_its_allowlist_entry():
    """Normalising one side only would break the entries written with www."""
    result = detect_external_resources(
        ["https://www.googletagmanager.com/gtag/js", "https://www.youtube.com/e.js"],
        [],
        [],
    )

    assert result["suspicious_external_domains"] == []


# ---------------------------------------------------------------------------
# Allowlist matching by domain, not by exact string
# ---------------------------------------------------------------------------

def test_a_subdomain_of_an_allowlisted_domain_is_not_suspicious():
    """Exact matching flagged legitimate CDN subdomains.

    The corpus shows it: WebSocket-backdoors.html serves from `c0.wp.com`
    and `stats.wp.com`, both ordinary WordPress infrastructure and both
    plainly the reason `wp.com` is on the list. Exact matching reported
    them as suspicious external domains.
    """
    result = detect_external_resources(
        ["https://c0.wp.com/c/1.js", "https://stats.wp.com/e.js"],
        [],
        [],
    )

    assert result["suspicious_external_domains"] == []


@pytest.mark.parametrize(
    "hostile",
    [
        "wp.com.evil.test",          # allowlisted name as a leading label
        "notwp.com",                 # allowlisted name as a bare suffix
        "evil-wp.com",               # hyphen-joined
        "cdn.jsdelivr.net.attacker.test",
    ],
)
def test_suffix_matching_respects_label_boundaries(hostile):
    """The obvious loose fix — endswith — is an allowlist bypass.

    `wp.com.evil.test` ends with nothing allowlisted, but `notwp.com` ends
    with `wp.com` as raw text. Matching has to be on whole labels: equal to
    the entry, or ending with a dot followed by it.
    """
    result = detect_external_resources([f"https://{hostile}/a.js"], [], [])

    assert result["suspicious_external_domains"] == [hostile]


# ---------------------------------------------------------------------------
# URL schemes are case-insensitive
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "url",
    [
        "HTTP://evil.test/c2.js",
        "HtTpS://evil.test/c2.js",
        "HTTPS://evil.test/c2.js",
        "//EVIL.TEST/c2.js",
    ],
)
def test_a_mixed_case_scheme_is_still_an_absolute_url(url):
    """One character of case hid an injected script completely.

    `_is_relative` compared against lowercase scheme literals, so
    `HTTP://evil.test/c2.js` did not start with `http://` and was read as
    a same-origin relative path — skipped before any check ran, and absent
    from the report entirely. RFC 3986 defines schemes as
    case-insensitive and browsers fetch them happily.
    """
    from modules.static.html_analysis.external import _is_relative

    assert _is_relative(url) is False

    result = detect_external_resources([url], [], [])
    assert result["suspicious_external_domains"] == ["evil.test"]


@pytest.mark.parametrize(
    "url",
    ["JaVaScRiPt:alert(1)", "DATA:text/html;base64,AAAA", "Blob:https://x/y"],
)
def test_a_mixed_case_local_scheme_is_still_a_local_scheme(url):
    """The same comparison, for the schemes that carry content inline."""
    from modules.static.html_analysis.external import _is_local_scheme

    assert _is_local_scheme(url) is True


def test_a_mixed_case_inline_iframe_scheme_is_not_treated_as_a_url():
    """structure.py filters these by the same case-sensitive comparison.

    An iframe with a `JaVaScRiPt:` source was collected as though it named
    a host, rather than being recognised as inline content.
    """
    from modules.static.html_analysis.structure import parse_structure

    parsed = parse_structure(
        '<iframe src="JaVaScRiPt:alert(1)"></iframe>'
        '<iframe src="DATA:text/html,x"></iframe>'
    )

    assert parsed["iframe_urls"] == []


@pytest.mark.parametrize(
    ("url", "relative"),
    [
        ("/assets/app.js", True),
        ("app.js", True),
        ("./x/app.js", True),
        ("../app.js", True),
        ("?v=2", True),
        ("http://evil.test/a.js", False),
        ("//evil.test/a.js", False),
        ("ftp://evil.test/a.js", False),
        ("ws://evil.test/sock", False),
        ("wss://evil.test/sock", False),
        ("file:///etc/passwd", False),
        ("mailto:x@evil.test", False),
    ],
)
def test_relative_means_no_scheme_rather_than_one_of_four(url, relative):
    """The check was a blocklist of four prefixes, not a scheme test.

    Anything outside http/https/ftp and protocol-relative read as a
    same-origin path and was skipped — `ws://`, `file://` and `mailto:`
    among them. A scheme is any leading `alpha *( alpha / digit / + / - /
    . ) ":"` per RFC 3986, which is also how a browser decides.
    """
    from modules.static.html_analysis.external import _is_relative

    assert _is_relative(url) is relative


def test_a_websocket_url_in_a_script_src_is_attributed():
    """The practical consequence of the gap, end to end."""
    result = detect_external_resources(["ws://evil.test/sock"], [], [])

    assert result["suspicious_external_domains"] == ["evil.test"]


@pytest.mark.parametrize(
    "url",
    [r"\\evil.test/c2.js", r"/\evil.test/c2.js", r"\/evil.test/c2.js"],
)
def test_backslash_forms_of_a_protocol_relative_url_are_absolute(url):
    """Browsers fold backslashes to slashes; the check did not.

    The WHATWG URL parser treats `\\` as `/` for special schemes, so
    `src="\\\\evil.test/c2.js"` fetches from evil.test exactly as
    `//evil.test/c2.js` would. Matching `startswith("//")` on the raw
    string missed every backslash spelling, and the URL was classified as
    a same-origin path and skipped.
    """
    from modules.static.html_analysis.external import _is_relative

    assert _is_relative(url) is False

    result = detect_external_resources([url], [], [])
    assert result["suspicious_external_domains"] == ["evil.test"]


def test_an_entity_encoded_scheme_is_decoded_by_the_parser():
    """Pinned because it looks like a gap and is not.

    `convert_charrefs=False` is set on the structural parser to keep
    obfuscation intact in script *bodies*. It does not affect attribute
    values — html.parser decodes character references there either way —
    so an entity-encoded scheme arrives already decoded and needs no
    unescaping of its own. Adding one would be harmless here but would
    invite the same treatment for handle_data, which would silently
    deobfuscate the script text the obfuscation pass exists to measure.
    """
    from modules.static.html_analysis.structure import parse_structure

    parsed = parse_structure(
        '<script src="h&#116;tp://evil.test/c2.js"></script>'
        '<iframe src="&#106;avascript:alert(1)"></iframe>'
    )

    assert parsed["external_script_urls"] == ["http://evil.test/c2.js"]
    assert parsed["iframe_urls"] == []
