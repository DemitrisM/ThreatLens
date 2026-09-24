"""HTML structural parse — Pass 1.

Extracts inline script blocks, external script URLs, iframes, download
anchors, form actions, meta-refresh directives, and DNS-prefetch hints
from raw HTML text using the stdlib ``html.parser``.

No external dependencies.

Design notes
------------
``convert_charrefs=False`` affects **text nodes only**. Attribute values
are decoded by ``html.parser`` either way, so an entity-encoded scheme
such as ``src="h&#116;tp://..."`` arrives here already decoded and needs
no unescaping of its own — a test pins that. Adding one would be
harmless for attributes and actively wrong if extended to
``handle_data``, which would deobfuscate the script text the obfuscation
pass exists to measure.

The stdlib parser is used rather than a real HTML5 tree-builder, and the
difference matters for what this module can claim. ``html.parser`` is
lenient and never raises on malformed markup, which is what a malicious
page usually is — but it does not implement HTML5 error recovery, so it
will not always agree with a browser about where a tag ends. The output
is therefore evidence of what is in the file, not a claim about what a
browser would render.

``convert_charrefs=False`` is deliberate. The default rewrites entities
in text nodes, which would silently decode obfuscation — a script body
written with ``&#x65;val`` would arrive already deobfuscated and the
obfuscation pass would find nothing to report. The passes downstream
want the bytes as written.

One parse feeds every later pass. Script blocks in particular are
extracted once here and handed to the smuggling, obfuscation, clickfix
and external analysers, so a page is tokenised a single time no matter
how many indicators run over it.

Partial results are returned on a parse failure rather than nothing. A
page that breaks the parser halfway has usually already yielded the
script block worth looking at.
"""

import logging
from html.parser import HTMLParser

logger = logging.getLogger(__name__)


class _StructureParser(HTMLParser):
    """Single-pass HTML parser that collects structural indicators."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.script_blocks: list[str] = []
        self.external_script_urls: list[str] = []
        self.iframe_urls: list[str] = []
        self.download_anchors: list[dict] = []   # {"href": ..., "download": ...}
        self.form_actions: list[str] = []
        self.meta_refresh_target: str | None = None
        self.dns_prefetch_hints: list[str] = []

        self._in_script = False
        self._current_script: list[str] = []

    # ------------------------------------------------------------------
    # HTMLParser callbacks
    # ------------------------------------------------------------------

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Collect the structural facts carried by one opening tag.

        Args:
            tag:   Lowercased tag name, as HTMLParser supplies it.
            attrs: Attribute pairs; a valueless attribute arrives as None.

        Returns:
            None. Findings are appended to the collector lists.

        Attribute names are lowercased and a missing value becomes ``""``,
        because HTML attribute names are case-insensitive and a page using
        ``SRC=`` or ``Src=`` is ordinary rather than evasive.
        """
        d = {k.lower(): (v or "") for k, v in attrs}

        # A script is either external or inline, never both: `src` wins in
        # every browser and the element's body is ignored. Clearing the
        # in-script state on a src= tag is what keeps an inline block from
        # being credited with a body that will never execute.
        if tag == "script":
            src = d.get("src", "").strip()
            if src:
                self.external_script_urls.append(src)
                self._in_script = False
            else:
                self._in_script = True
                self._current_script = []

        elif tag == "iframe":
            src = d.get("src", "").strip()
            # Case-folded: schemes are case-insensitive per RFC 3986, so
            # a `JaVaScRiPt:` source is inline content that a literal
            # comparison would collect as though it named a host.
            if src and not src.lower().startswith(
                ("data:", "about:", "javascript:")
            ):
                self.iframe_urls.append(src)

        elif tag == "a":
            # Tested for presence, not truth: `download` is a boolean
            # attribute, so `download=""` and a bare `download` both mean
            # "save this rather than navigate to it" — which is the whole
            # mechanism HTML smuggling uses to put a file on disk.
            download_val = d.get("download")
            if download_val is not None:
                self.download_anchors.append(
                    {"href": d.get("href", ""), "download": download_val}
                )

        elif tag == "form":
            action = d.get("action", "").strip()
            if action:
                self.form_actions.append(action)

        elif tag == "meta":
            http_equiv = d.get("http-equiv", "").lower()
            if http_equiv == "refresh":
                content = d.get("content", "")
                lower = content.lower()
                if "url=" in lower:
                    idx = lower.index("url=") + 4
                    target = content[idx:].strip().strip("'\"")
                    if target:
                        self.meta_refresh_target = target

        elif tag == "link":
            rel = d.get("rel", "").lower()
            if "dns-prefetch" in rel:
                href = d.get("href", "").lstrip("/").strip()
                if href:
                    self.dns_prefetch_hints.append(href)

    def handle_endtag(self, tag: str) -> None:
        """Close an inline script block and keep it if it had content.

        Args:
            tag: Lowercased tag name.

        Returns:
            None.
        """
        if tag == "script" and self._in_script:
            text = "".join(self._current_script)
            if text.strip():
                self.script_blocks.append(text)
            self._in_script = False
            self._current_script = []

    def handle_data(self, data: str) -> None:
        """Accumulate text, but only while inside an inline script.

        Args:
            data: A run of character data.

        Returns:
            None.

        Appended in fragments rather than assigned: HTMLParser splits a
        script body at every entity-looking sequence, so a single block
        arrives as many callbacks and joining them at the end is what
        reconstitutes it.
        """
        if self._in_script:
            self._current_script.append(data)

    def error(self, message: str) -> None:  # pragma: no cover
        logger.debug("HTMLParser error: %s", message)


def parse_structure(html_text: str) -> dict:
    """Parse HTML structure and return extracted indicators.

    Returns a dict containing:
      script_blocks, external_script_urls, iframe_urls, download_anchors,
      form_actions, meta_refresh_target, dns_prefetch_hints, and derived counts.

    Never raises — all exceptions are logged and partial results returned.
    """
    parser = _StructureParser()
    try:
        parser.feed(html_text)
        parser.close()
    except Exception as exc:  # noqa: BLE001
        logger.debug("HTML structure parse incomplete: %s", exc)
        # Partial results are still useful.

    return {
        "script_blocks": parser.script_blocks,
        "external_script_urls": parser.external_script_urls,
        "iframe_urls": parser.iframe_urls,
        "download_anchors": parser.download_anchors,
        "form_actions": parser.form_actions,
        "meta_refresh_target": parser.meta_refresh_target,
        "dns_prefetch_hints": parser.dns_prefetch_hints,
        # Derived counts (go into the top-level data dict)
        "num_script_blocks": len(parser.script_blocks),
        "num_external_scripts": len(parser.external_script_urls),
        "num_iframes": len(parser.iframe_urls),
        "num_download_anchors": len(parser.download_anchors),
    }
