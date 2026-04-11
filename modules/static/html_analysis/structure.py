"""HTML structural parse — Pass 1.

Extracts inline script blocks, external script URLs, iframes, download
anchors, form actions, meta-refresh directives, and DNS-prefetch hints
from raw HTML text using the stdlib ``html.parser``.

No external dependencies.
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
        d = {k.lower(): (v or "") for k, v in attrs}

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
            if src and not src.startswith(("data:", "about:", "javascript:")):
                self.iframe_urls.append(src)

        elif tag == "a":
            # Only care about anchors with an explicit download= attribute.
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
        if tag == "script" and self._in_script:
            text = "".join(self._current_script)
            if text.strip():
                self.script_blocks.append(text)
            self._in_script = False
            self._current_script = []

    def handle_data(self, data: str) -> None:
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
