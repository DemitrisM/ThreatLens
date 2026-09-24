"""External resource and C2 beacon detection — Pass 6.

Identifies injected external scripts from non-CDN domains (the primary
signal in ClickFix watering-hole attacks), XHR/Fetch beacons, WebSocket
channels, and suspicious external iframes.

Heuristic: a ``<script src>`` URL whose path looks like a random token
(long, no extension, alphanumeric + hyphens only) is flagged as a
probable C2 callback URL regardless of the domain's reputation.

No external dependencies.

Design notes
------------
An allowlist, not a blocklist, and the asymmetry is the point: there is
no enumerable set of malicious hosts, but there is a small, stable set
of CDNs that account for most legitimate third-party script tags. The
cost of an unlisted-but-benign CDN is one noisy row; the cost of a
blocklist would be silence on everything not yet known.

The random-path heuristic exists because reputation is the wrong
question for this attack. A ClickFix injection is usually served from a
compromised legitimate site, so the domain looks fine and the *path*
does not — a long opaque token with no file extension is a callback
identifier, not a resource. It is reported alongside the domain rather
than instead of it.

The beacon checks are matched against script bodies rather than the
whole page so that a URL merely written in prose cannot raise them; the
resource checks run on parsed attribute values for the same reason.
"""

import logging
import re
import urllib.parse

logger = logging.getLogger(__name__)

# Known-benign CDN / infrastructure hostnames — not flagged as suspicious.
_CDN_ALLOWLIST: frozenset[str] = frozenset({
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "ajax.googleapis.com",
    "code.jquery.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com",
    "unpkg.com",
    "ajax.aspnetcdn.com",
    "www.google.com",
    "www.googletagmanager.com",
    "www.google-analytics.com",
    "ssl.google-analytics.com",
    "connect.facebook.net",
    "platform.twitter.com",
    "s.ytimg.com",
    "www.youtube.com",
    "apis.google.com",
    "accounts.google.com",
    "recaptcha.net",
    "www.recaptcha.net",
    # WordPress / common CMS infra
    "wp.com",
    "wordpress.com",
    "gravatar.com",
})

# Random C2 path: a single path segment ≥ 20 chars of [A-Za-z0-9_-] with no
# file extension and no real words — the pattern seen in ClickFix injections.
_RANDOM_PATH_RE = re.compile(r"/([A-Za-z0-9_-]{20,})(?:/|\?|$)")

# XHR beacon patterns in script content.
#: A URL scheme per RFC 3986: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) ":".
#: Anchored in the pattern, not merely by the caller using `.match`, so a
#: later `.search` cannot match a colon further along a path.
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")

_XHR_RE = re.compile(
    r"""\.open\s*\(\s*['"](?:GET|POST)['"]\s*,\s*['"]https?://""",
    re.I,
)
_FETCH_RE = re.compile(r"""\bfetch\s*\(\s*['"]https?://""", re.I)
_WEBSOCKET_RE = re.compile(r"""\bnew\s+WebSocket\s*\(\s*['"]wss?://""", re.I)


def detect_external_resources(
    external_script_urls: list[str],
    iframe_urls: list[str],
    script_blocks: list[str],
) -> dict:
    """Return a dict of external-resource flags and suspicious URL lists.

    Args:
        external_script_urls: ``<script src>`` values from the parse.
        iframe_urls:          ``<iframe src>`` values, local schemes
                              already excluded by the parser.
        script_blocks:        Inline script bodies, for the beacon checks.

    Returns:
        A flat dict suitable for merging into the module data dict.

    Relative URLs are skipped rather than resolved. A relative path is
    same-origin by definition, so it is the page serving itself — and
    there is no base URL available here to resolve one against anyway.
    """
    combined = "\n".join(script_blocks)

    suspicious_script_urls: list[str] = []
    suspicious_domains: list[str] = []

    for url in external_script_urls:
        if _is_relative(url):
            continue
        domain = _extract_domain(url)
        if domain and not _is_allowlisted(domain) \
                and not _is_same_site_url(url):
            suspicious_script_urls.append(url)
            if domain not in suspicious_domains:
                suspicious_domains.append(domain)

    # Random-path C2 indicator: a suspicious URL whose path looks like a
    # callback token rather than a real resource.
    random_path_scripts = [u for u in suspicious_script_urls if _RANDOM_PATH_RE.search(u)]

    suspicious_iframes: list[str] = []
    for url in iframe_urls:
        if not _is_relative(url) and not _is_local_scheme(url):
            domain = _extract_domain(url)
            if domain and not _is_allowlisted(domain):
                suspicious_iframes.append(url)

    has_xhr = bool(_XHR_RE.search(combined))
    has_fetch = bool(_FETCH_RE.search(combined))
    has_websocket = bool(_WEBSOCKET_RE.search(combined))

    return {
        "suspicious_external_domains": suspicious_domains,
        "suspicious_external_script_urls": suspicious_script_urls,
        "suspicious_iframe_urls": suspicious_iframes,
        "random_path_scripts": random_path_scripts,
        "has_xhr_beacon": has_xhr,
        "has_fetch_beacon": has_fetch,
        "has_websocket": has_websocket,
        "num_suspicious_external_scripts": len(suspicious_script_urls),
    }


def _fold_separators(url: str) -> str:
    """Trim a URL and fold backslashes to forward slashes.

    Args:
        url: A raw attribute value.

    Returns:
        The form a browser would resolve.

    The WHATWG URL parser treats ``\\`` as ``/`` for special schemes, so
    ``\\evil.test/c2.js`` fetches from evil.test exactly as
    ``//evil.test/c2.js`` does. Comparing the raw string missed every
    backslash spelling, and those URLs were classified as same-origin
    paths and skipped entirely.
    """
    return url.strip().replace("\\", "/")


def _normalise_host(host: str) -> str:
    """Lowercase a hostname and drop a leading ``www.`` and any port.

    Args:
        host: A hostname, possibly with a port or a ``www.`` prefix.

    Returns:
        The comparison form.

    ``removeprefix``, never ``lstrip``. ``lstrip("www.")`` takes a *set of
    characters*, so it eats every leading ``w`` and ``.``: wordpress.com
    became ordpress.com, wp.com became p.com, web.site became eb.site.
    That name then travelled into the report as the suspicious domain —
    an IOC an analyst would block, for a host that does not exist.

    Both sides of the allowlist comparison go through this, because the
    list is written with and without the prefix. Normalising one side
    only would break whichever spelling the other side used.
    """
    host = host.lower().strip()
    if "@" in host:                 # strip any userinfo
        host = host.rsplit("@", 1)[-1]
    if host.startswith("[") and "]" in host:        # IPv6 literal
        host = host[:host.index("]") + 1]
    elif ":" in host:
        host = host.rsplit(":", 1)[0]
    return host.removeprefix("www.")


#: The allowlist in comparison form, built once. Entries are written both
#: ways above; this is what they are actually matched against.
_CDN_ALLOWLIST_NORMALISED: frozenset[str] = frozenset(
    _normalise_host(entry) for entry in _CDN_ALLOWLIST
)


def _is_allowlisted(domain: str) -> bool:
    """True if ``domain`` is an allowlisted CDN, or a subdomain of one.

    Args:
        domain: A hostname already through :func:`_normalise_host`.

    Returns:
        Whether the domain should be treated as known infrastructure.

    Matched on whole labels — equal to an entry, or ending with a dot
    followed by one. Exact matching alone flagged real CDN subdomains:
    the corpus serves from ``c0.wp.com`` and ``stats.wp.com``, which are
    plainly why ``wp.com`` is on the list, and both were reported as
    suspicious.

    The obvious loose fix is ``endswith``, and it is an allowlist bypass:
    ``notwp.com`` ends with ``wp.com`` as raw text while being an
    unrelated domain, and an attacker registers that in a minute. The dot
    is what makes the comparison about domains rather than strings.
    """
    return any(
        domain == entry or domain.endswith("." + entry)
        for entry in _CDN_ALLOWLIST_NORMALISED
    )


def _extract_domain(url: str) -> str:
    """The hostname a URL points at, in comparison form.

    Args:
        url: An absolute URL, or a protocol-relative ``//host/path``.

    Returns:
        The normalised hostname, or ``""`` when none can be read.
    """
    url = _fold_separators(url)
    if url.startswith("//"):
        url = "https:" + url
    try:
        return _normalise_host(urllib.parse.urlparse(url).netloc)
    except Exception:  # noqa: BLE001
        return ""


def _is_relative(url: str) -> bool:
    """True for a URL with no scheme and no authority.

    Args:
        url: A raw attribute value.

    Returns:
        Whether it resolves against the page's own origin.

    ``//host/path`` counts as absolute: it is protocol-relative, not
    path-relative, and names a different host.

    Tested for a scheme rather than against a list of them. The check was
    once four literal prefixes, which made every other scheme read as a
    same-origin path — ``ws://``, ``file://`` and ``mailto:`` were all
    skipped before any check ran. A scheme is
    ``ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) ":"`` per RFC 3986, and
    that is also how a browser decides, so it is what is matched.

    The pattern is anchored and case-insensitive: schemes are
    case-insensitive per RFC 3986 and browsers fetch ``HTTP://`` without
    complaint, so a literal lowercase comparison meant one character of
    case hid an absolute URL entirely.
    """
    url = _fold_separators(url)
    return not (_SCHEME_RE.match(url) or url.startswith("//"))


def _is_same_site_url(url: str) -> bool:
    """Whether an absolute URL points back at the page's own site.

    Args:
        url: An absolute URL.

    Returns:
        Always False.

    A deliberate stub, kept as a named seam rather than deleted. The
    question is real — a page absolutely-linking its own host is not an
    external resource — but it cannot be answered here: nothing in this
    module knows the page's origin, because a file on disk has none. It
    could be answered if the caller ever passes one down, and the call
    site reads correctly in the meantime.

    Returning False means every absolute URL is treated as external,
    which is the safe direction: the cost is a noisy row for a
    self-referencing page, against a missed injection the other way.
    """
    return False  # conservative — flag everything that's absolute


def _is_local_scheme(url: str) -> bool:
    """True for schemes that name inline content rather than a host.

    Args:
        url: A raw attribute value.

    Returns:
        Whether the URL carries its content instead of fetching it.

    These are excluded from the *external* checks because there is no
    external party involved. They are not benign — a ``data:`` iframe is
    a smuggling primitive — which is why the smuggling pass looks at
    them separately.

    Case-folded, for the same reason as :func:`_is_relative`.
    """
    return url.lower().startswith(("javascript:", "data:", "about:", "blob:"))
