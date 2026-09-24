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

from typing import TYPE_CHECKING, Final, TypedDict

if TYPE_CHECKING:  # pragma: no cover
    from rich.theme import Theme


class Token(TypedDict):
    """One palette entry: how rich draws it, how CSS draws it.

    ``css`` is ``None`` for an entry the HTML report has no use for —
    a composed rich style such as "bold cyan", where the weight is the
    point and the hue already has a token of its own. :func:`css_root`
    skips those rather than emitting a variable nothing references.

    One table, not two. A second rich-only map was the obvious way to
    keep the CSS block clean, and it would have split the single source
    of colour in half to save three unused variables.
    """

    rich: str
    css: str | None


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
    # Composed rich styles — weight plus hue. CSS has no use for them:
    # the HTML report styles its headings with its own rules, and the
    # hues here already appear above.
    "brand": {"rich": "bold cyan", "css": None},
    "ok_strong": {"rich": "bold green", "css": None},
    "error_dim": {"rich": "dim red", "css": None},
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


#: The style for "no opinion". Not a TOKEN, because it has no CSS half —
#: HTML already expresses this as ``--text`` and a token would put an
#: unused variable in the ``:root`` block.
#:
#: Rich reads ``"default"`` as the terminal's own foreground (SGR 39). The
#: obvious spellings are both wrong: ``"white"`` is ANSI colour 7 and
#: disappears on a light background, and ``""`` is a markup error, since
#: rich has nothing for ``[/]`` to close.
NEUTRAL: Final[str] = "default"


def ioc_style(ioc_type: str) -> tuple[str, str]:
    """``(display label, rich style)`` for an IOC type.

    Args:
        ioc_type: A key of :data:`IOC_TYPE_LABELS`. An unrecognised type
                  is passed through as its own label rather than dropped,
                  so a new IOC category added to ``ioc_extractor`` renders
                  before it is given a colour here.

    Returns:
        ``(label, rich style)``. The style is :data:`NEUTRAL` when the
        type has no token, so an uncoloured row is uncoloured rather than
        assigned a hue that would imply a severity.
    """
    label = IOC_TYPE_LABELS.get(ioc_type, ioc_type)
    return label, rich_style(f"ioc_{ioc_type}") or NEUTRAL

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
        if token["css"] is None:
            continue
        var = f"--{name.replace('_', '-')}:"
        lines.append(f"        {var:<16}{token['css']};")
    lines.append("    }")
    return "\n".join(lines)


def rich_theme() -> "Theme":
    """The palette as a :class:`rich.theme.Theme`.

    Attached to the console singletons in :mod:`reporting.console`, which
    is what lets a reporter write ``[bad]…[/bad]`` instead of ``[red]…``.
    That is the mechanism that makes design rule 8 enforceable rather
    than aspirational: a semantic name in the markup has no hue in it, so
    changing the hue is a one-line edit here and a test can reject any
    bare colour name it finds in the source.

    Tokens with an empty rich half are skipped — they are CSS-only
    chrome, and registering them would shadow nothing useful while
    letting ``[bg]`` parse as a valid style.
    """
    from rich.theme import Theme  # noqa: PLC0415

    return Theme(
        {name: token["rich"] for name, token in TOKENS.items() if token["rich"]},
        inherit=True,
    )


__all__ = [
    "CLASS_SEVERITY",
    "IOC_TYPE_LABELS",
    "NEUTRAL",
    "TOKENS",
    "css_root",
    "ioc_style",
    "rich_style",
    "rich_theme",
]
