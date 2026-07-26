"""The single source of colour for both reporters.

Before this module the tree held five separate colour maps: ``_SEV_STYLES``
in ``terminal_reporter/pe.py`` and ``doc.py`` (byte-identical),
``_CLASS_COLOURS`` in ``archive.py`` and ``onenote.py`` (byte-identical),
``BAND_COLOURS``/``STATUS_COLOURS`` in ``_common.py``, ``_IOC_TYPE_STYLES``
in ``tables.py``, and the CSS ``:root`` block in ``report.html.j2``.

Each token carries both representations so the terminal and HTML reports
cannot drift apart. CSS values are copied verbatim from the template block
they replace, so switching to :func:`css_root` changes no rendered output.
"""

from typing import Final, TypedDict


class Token(TypedDict):
    """One palette entry: how rich draws it, how CSS draws it."""

    rich: str
    css: str


TOKENS: Final[dict[str, Token]] = {
    # Risk bands — mirror core.scoring._BANDS
    "critical": {"rich": "bold red", "css": "#ff4d4f"},
    "high": {"rich": "bold orange1", "css": "#ff8c1a"},
    "medium": {"rich": "bold yellow", "css": "#ffd93d"},
    "low": {"rich": "bold green", "css": "#5cb85c"},
    # Indicator severities
    "bad": {"rich": "red", "css": "#ff4d4f"},
    "warn": {"rich": "yellow", "css": "#ffd93d"},
    "info": {"rich": "dim", "css": "#6b7280"},
    # Module statuses
    "success": {"rich": "green", "css": "#5cb85c"},
    "skipped": {"rich": "dim yellow", "css": "#d4a017"},
    "error": {"rich": "red", "css": "#ff4d4f"},
    # Per-module classification bands (archive / doc / onenote)
    "malicious": {"rich": "bold red", "css": "#ff4d4f"},
    "suspicious": {"rich": "bold yellow", "css": "#ffd93d"},
    "informational": {"rich": "cyan", "css": "#4cc9f0"},
    "clean": {"rich": "green", "css": "#5cb85c"},
    # IOC types — each keeps the hue it had in _IOC_TYPE_STYLES
    "ioc_ipv4": {"rich": "red", "css": "#ff4d4f"},
    "ioc_url": {"rich": "yellow", "css": "#ffd93d"},
    "ioc_domain": {"rich": "cyan", "css": "#4cc9f0"},
    "ioc_registry_key": {"rich": "magenta", "css": "#c77dff"},
    "ioc_email": {"rich": "blue", "css": "#4d8cff"},
    "ioc_windows_path": {"rich": "dim", "css": "#6b7280"},
    # Chrome — CSS-only, rich has no equivalent for most
    "bg": {"rich": "", "css": "#0f1115"},
    "bg_panel": {"rich": "", "css": "#181b22"},
    "bg_panel_2": {"rich": "", "css": "#1f232c"},
    "border": {"rich": "", "css": "#2a2f3a"},
    "text": {"rich": "", "css": "#e6e8ee"},
    "text_dim": {"rich": "dim", "css": "#9aa3b2"},
    "text_faint": {"rich": "dim", "css": "#6b7280"},
    "accent": {"rich": "cyan", "css": "#4cc9f0"},
    "code_bg": {"rich": "", "css": "#0b0d12"},
}

#: IOC type -> display label. The colour token is ``ioc_<type>``.
#: Replaces ``_IOC_TYPE_STYLES`` in ``terminal_reporter/tables.py``, which
#: paired the same labels with bare colour names.
IOC_TYPE_LABELS: Final[dict[str, str]] = {
    "ipv4": "IP Address",
    "url": "URL",
    "domain": "Domain",
    "registry_key": "Registry Key",
    "email": "Email",
    "windows_path": "File Path",
}


def ioc_style(ioc_type: str) -> tuple[str, str]:
    """``(display label, rich style)`` for an IOC type."""
    label = IOC_TYPE_LABELS.get(ioc_type, ioc_type)
    return label, rich_style(f"ioc_{ioc_type}") or "white"

#: A module's ``data["classification"]`` mapped to an indicator severity.
#: Deliberately holds no risk-band keys: ``onenote.py`` used to look up a
#: risk_band (LOW/MEDIUM/HIGH/CRITICAL) in a map keyed by these names, so
#: it never matched and always fell back to white.
CLASS_SEVERITY: Final[dict[str, str]] = {
    "MALICIOUS": "bad",
    "SUSPICIOUS": "warn",
    "INFORMATIONAL": "info",
    "CLEAN": "info",
}


def rich_style(name: str) -> str:
    """Rich style string for a token, or ``""`` when the name is unknown.

    Returns empty rather than raising: a typo in a colour name must not
    kill a report whose analysis has already completed.
    """
    token = TOKENS.get(name)
    return token["rich"] if token else ""


def css_root() -> str:
    """The ``:root`` block for the HTML template.

    Indentation and column alignment match the literal block this
    replaces, so a rendered report diffs cleanly against one produced
    before this module existed.
    """
    lines = [":root {"]
    for name, token in TOKENS.items():
        var = f"--{name.replace('_', '-')}:"
        lines.append(f"        {var:<16}{token['css']};")
    lines.append("    }")
    return "\n".join(lines)


__all__ = [
    "CLASS_SEVERITY",
    "IOC_TYPE_LABELS",
    "TOKENS",
    "css_root",
    "ioc_style",
    "rich_style",
]
