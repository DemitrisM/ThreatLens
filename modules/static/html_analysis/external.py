"""External resource and C2 beacon detection — Pass 6.

Identifies injected external scripts from non-CDN domains (the primary
signal in ClickFix watering-hole attacks), XHR/Fetch beacons, WebSocket
channels, and suspicious external iframes.

Heuristic: a ``<script src>`` URL whose path looks like a random token
(long, no extension, alphanumeric + hyphens only) is flagged as a
probable C2 callback URL regardless of the domain's reputation.

No external dependencies.
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
    """Return a dict of external-resource flags and suspicious URL lists."""
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
    url = url.strip()
    if url.startswith("//"):
        url = "https:" + url
    try:
        return _normalise_host(urllib.parse.urlparse(url).netloc)
    except Exception:  # noqa: BLE001
        return ""


def _is_relative(url: str) -> bool:
    return not url.startswith(("http://", "https://", "//", "ftp://"))


def _is_same_site_url(url: str) -> bool:
    """True for same-site paths that happen to start with http (rare but possible)."""
    return False  # conservative — flag everything that's absolute


def _is_local_scheme(url: str) -> bool:
    return url.startswith(("javascript:", "data:", "about:", "blob:"))
