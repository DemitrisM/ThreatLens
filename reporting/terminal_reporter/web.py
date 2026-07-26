"""HTML Smuggling Indicators — payload delivery, obfuscation, ClickFix, C2.

``html_analysis`` scored files long before anything rendered its findings:
a ClickFix sample scoring 50 produced one FINDINGS line and no indicators.

Field names here were catalogued from real module output. The module emits
a wide flat dict of ``has_*`` booleans plus a few lists, so this builder
groups them into the four things an analyst acts on: what payload is
smuggled, how it is delivered, how it is hidden, and where it calls out to.
"""

from reporting.shared import human_size

from ._common import console
from ._render import Row, render_indicators

#: Kept at detail 0 even when quiet — it says what was parsed.
_ALWAYS_SHOW = frozenset({"Script blocks"})

#: ``(data key, label)`` for the delivery mechanisms, in chain order.
_DELIVERY_MECHANISMS: tuple[tuple[str, str], ...] = (
    ("has_atob", "atob"),
    ("has_eval_atob", "eval(atob)"),
    ("has_unescape", "unescape"),
    ("has_blob_creation", "Blob"),
    ("has_blob_url", "Blob URL"),
    ("has_window_loc_blob", "window.location=blob"),
    ("has_mssave", "msSaveBlob"),
    ("has_auto_download", "auto-download"),
    ("has_onload_trigger", "onload"),
    ("has_settimeout_exec", "setTimeout exec"),
    ("has_data_uri_link", "data: URI link"),
)

#: Beaconing mechanisms — a page that phones home.
_BEACONS: tuple[tuple[str, str], ...] = (
    ("has_xhr_beacon", "XHR"),
    ("has_fetch_beacon", "fetch"),
    ("has_websocket", "WebSocket"),
)


def html_rows(data: dict, detail_level: int = 0) -> list[Row]:
    """Build HTML indicator rows from an ``html_analysis`` data dict."""
    if not data:
        return []

    rows: list[Row] = []

    blobs = data.get("base64_blobs") or []
    payload_types = data.get("embedded_payload_types") or []
    if blobs or payload_types:
        largest = max((b.get("size") or 0 for b in blobs), default=0)
        kinds = ", ".join(payload_types) if payload_types else "unidentified"
        detail = f"{kinds}"
        if largest:
            detail += f", largest {human_size(largest)}"
        if len(blobs) > 1:
            detail += f", {len(blobs)} base64 blobs"
        rows.append(Row("Smuggled payload", detail, "bad"))

    mechanisms = [label for key, label in _DELIVERY_MECHANISMS if data.get(key)]
    if mechanisms:
        rows.append(
            Row(
                "Delivery chain",
                " → ".join(mechanisms),
                "bad" if len(mechanisms) >= 2 else "warn",
            )
        )

    if data.get("has_clipboard_write"):
        lolbins = data.get("clipboard_lolbins_found") or []
        if data.get("clipboard_contains_lolbin") or lolbins:
            detail = "clipboard poisoned with " + (
                ", ".join(lolbins) if lolbins else "a LOLBin command"
            )
            rows.append(Row("ClickFix clipboard", detail, "bad"))
        else:
            rows.append(Row("ClickFix clipboard", "page writes to clipboard", "warn"))

    preview = data.get("clipboard_payload_preview")
    if preview and detail_level >= 1:
        rows.append(Row("Clipboard payload", str(preview), "bad"))

    obfuscation = data.get("obfuscation_indicators") or []
    if obfuscation:
        rows.append(
            Row(
                "Obfuscation",
                "; ".join(obfuscation),
                "bad" if len(obfuscation) >= 3 else "warn",
            )
        )

    exec_bits = [
        label
        for key, label in (
            ("has_eval", "eval"),
            ("has_function_constructor", "Function()"),
            ("has_fromcharcode", "fromCharCode"),
        )
        if data.get(key)
    ]
    if exec_bits:
        rows.append(Row("Dynamic execution", ", ".join(exec_bits), "warn"))

    suspicious_scripts = data.get("num_suspicious_external_scripts") or 0
    external = data.get("num_external_scripts") or 0
    if external:
        detail = f"{external} external"
        if suspicious_scripts:
            detail += f", {suspicious_scripts} suspicious"
        rows.append(
            Row("External scripts", detail, "bad" if suspicious_scripts else "info")
        )

    random_paths = data.get("random_path_scripts") or []
    if random_paths:
        shown = random_paths if detail_level >= 1 else random_paths[:2]
        detail = ", ".join(shown)
        if len(random_paths) > len(shown):
            detail += f"  (+{len(random_paths) - len(shown)} more)"
        rows.append(Row("Random-path C2", detail, "bad"))

    domains = data.get("suspicious_external_domains") or []
    if domains:
        shown = domains if detail_level >= 1 else domains[:3]
        detail = ", ".join(shown)
        if len(domains) > len(shown):
            detail += f"  (+{len(domains) - len(shown)} more)"
        rows.append(Row("Suspicious domains", detail, "bad"))

    beacons = [label for key, label in _BEACONS if data.get(key)]
    if beacons:
        rows.append(Row("Beaconing", ", ".join(beacons), "warn"))

    forms = data.get("form_actions") or []
    if forms:
        rows.append(Row("Form posts to", ", ".join(forms[:3]), "warn"))

    lures = data.get("social_eng_patterns") or []
    if lures:
        rows.append(Row("Social engineering", "; ".join(lures[:3]), "warn"))

    dangerous = data.get("dangerous_extensions") or []
    if dangerous:
        rows.append(Row("Dangerous extension", ", ".join(dangerous), "bad"))
    if data.get("double_extension"):
        rows.append(Row("Double extension", str(data["double_extension"]), "bad"))

    downloads = data.get("download_filenames") or []
    if downloads:
        rows.append(Row("Download filename", ", ".join(downloads[:3]), "warn"))

    iframes = data.get("num_iframes") or 0
    iframe_urls = data.get("suspicious_iframe_urls") or []
    if iframe_urls:
        rows.append(Row("Suspicious iframes", ", ".join(iframe_urls[:3]), "bad"))
    elif iframes and detail_level >= 1:
        rows.append(Row("Iframes", str(iframes), "info"))

    if data.get("meta_refresh_target"):
        rows.append(Row("Meta refresh", str(data["meta_refresh_target"]), "warn"))

    scripts = data.get("num_script_blocks") or 0
    if scripts or detail_level >= 1:
        rows.append(Row("Script blocks", str(scripts), "info"))

    if detail_level >= 1:
        if data.get("file_size_bytes"):
            rows.append(Row("Size", human_size(data["file_size_bytes"]), "info"))
        if data.get("encoding"):
            rows.append(Row("Encoding", str(data["encoding"]), "info"))

    return rows


def print_html_indicators(module_results: list[dict], detail_level: int) -> None:
    """HTML Smuggling Indicators section."""
    result = next(
        (r for r in module_results if r.get("module") == "html_analysis"), None
    )
    if not result or result.get("status") != "success":
        return
    render_indicators(
        "HTML Smuggling Indicators",
        html_rows(result.get("data") or {}, detail_level),
        detail_level,
        always_show=_ALWAYS_SHOW,
        console=console,
    )
