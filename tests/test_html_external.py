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
