"""Shared helpers used by both the terminal and HTML reporters.

Kept minimal on purpose — only formatting helpers and the verdict
sentence builder live here.  Rich-specific constants (colour maps,
the ``Console`` instance) stay inside the terminal package; HTML/CSS
classes stay inside the HTML package.
"""


#: Keys whose values are credentials and must never reach a report.
#: Matched case-insensitively at every depth.
SECRET_KEYS: frozenset[str] = frozenset({"api_key", "virustotal_api_key"})


def sanitise_secrets(obj):
    """Recursively drop credential keys from a nested structure.

    The strip used to apply only to the top level of a module's ``data``
    dict, so ``{"request": {"api_key": ...}}`` survived into the report.
    Terminal ``-vv`` now prints raw module data, so every reporter routes
    through this instead.

    Returns a new structure; the input is never mutated.
    """
    if isinstance(obj, dict):
        return {
            key: sanitise_secrets(value)
            for key, value in obj.items()
            if not (isinstance(key, str) and key.lower() in SECRET_KEYS)
        }
    if isinstance(obj, (list, tuple)):
        return [sanitise_secrets(item) for item in obj]
    return obj


IOC_LABELS: dict[str, tuple[str, str]] = {
    "ipv4":         ("IP Address",   "ipv4"),
    "url":          ("URL",          "url"),
    "domain":       ("Domain",       "domain"),
    "registry_key": ("Registry Key", "registry_key"),
    "email":        ("Email",        "email"),
    "windows_path": ("File Path",    "windows_path"),
}


def human_size(nbytes: int | float) -> str:
    """Format byte count as a human-readable string (1.5 MiB, etc.)."""
    n = float(nbytes or 0)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


# Indicator weights, highest first. The sentence lists only four
# indicators, so what wins those slots matters: "unsigned binary" fires for
# every unsigned PE in existence and used to take the first slot on the
# RedLine baseline, ahead of the .NET stealer strings that actually
# identified it.
W_VT = 100
W_YARA = 90
W_CAPA_SEVERE = 80
W_STEALER = 70
W_EXPLOIT = 68
W_PACKER = 60
W_CAPA = 55
W_NETWORK = 50
W_STRUCTURE = 40
W_CONTAINER = 35
W_WEAK = 10


def build_verdict(module_results: list[dict], scoring: dict) -> str:
    """Build a one-line human-readable verdict sentence from module
    findings.  Returns ``""`` when there is nothing worth summarising.

    This is the single source of truth shared by the terminal and HTML
    reporters so both outputs surface the same sentence.

    Indicators carry a weight and are sorted before the four-item slice, so
    the strongest signal leads regardless of module execution order.
    """
    indicators: list[tuple[int, str]] = []

    def add(weight: int, text: str) -> None:
        indicators.append((weight, text))

    for result in module_results:
        if result.get("status") != "success" or result.get("score_delta", 0) == 0:
            continue

        data = result.get("data", {}) or {}
        module = result.get("module", "")

        if module == "pe_analysis":
            if data.get("packers_detected"):
                add(W_PACKER, "packed/encrypted binary")
            if data.get("suspicious_imports"):
                count = len(data["suspicious_imports"])
                if count > 15:
                    add(W_STRUCTURE, "extensive suspicious API usage")
                elif count > 5:
                    add(W_STRUCTURE, "suspicious API imports")
            if not data.get("has_signature"):
                # Near-worthless on its own — most software is unsigned.
                add(W_WEAK, "unsigned binary")
            if data.get("rwx_sections"):
                add(W_STRUCTURE, "RWX self-modifying section")
            if len(data.get("hollowing_apis") or []) >= 2:
                add(W_CAPA_SEVERE, "process hollowing API combo")
            if data.get("embedded_pe"):
                add(W_STEALER, "embedded PE payload")
            if (data.get("resource_types") or {}).get("autoit"):
                add(W_PACKER, "AutoIt wrapper")
            footprint = data.get("import_footprint") or {}
            if footprint.get("loader_only") or footprint.get("is_kernel32_only"):
                add(W_PACKER, "kernel32-only loader footprint")
            if (data.get("dynamic_api_resolution") or {}).get("count", 0) >= 5:
                add(W_STRUCTURE, "dynamic API resolution")

        elif module == "capa_analysis":
            for cat in data.get("scored_categories", []) or []:
                name = (cat.get("category", "") or "").lower()
                if "injection" in name:
                    add(W_CAPA_SEVERE, "process injection capability")
                elif "anti" in name:
                    add(W_CAPA, "anti-analysis evasion")
                elif "credential" in name:
                    add(W_CAPA_SEVERE, "credential harvesting")
                elif "network" in name:
                    add(W_CAPA, "network C2 capability")
                elif "data collection" in name or "recon" in name:
                    add(W_CAPA, "data collection/reconnaissance")
                elif "persistence" in name:
                    add(W_CAPA, "persistence mechanism")
                elif "encryption" in name or "obfuscation" in name:
                    add(W_STRUCTURE, "encryption/obfuscation")
                elif "privilege" in name:
                    add(W_CAPA, "privilege escalation")

        elif module == "ioc_extractor":
            iocs = data.get("iocs", {}) or {}
            if iocs.get("url") or iocs.get("ipv4"):
                add(W_NETWORK, "network IOC indicators")

        elif module == "virustotal":
            if data.get("found"):
                detections = (data.get("malicious", 0) or 0) + (
                    data.get("suspicious", 0) or 0
                )
                if detections > 10:
                    label = data.get("threat_label")
                    add(
                        W_VT,
                        f"VirusTotal: {detections} engines flagged"
                        + (f" ({label})" if label else ""),
                    )
                elif detections >= 1:
                    add(W_NETWORK, "low VirusTotal detections")

        elif module == "string_analysis":
            # Family categories are collapsed into one indicator. RedLine
            # matches both ".NET stealer rule class" and ".NET stealer
            # scan-routine", which as separate entries ate two of the four
            # slots to say the same thing twice.
            families: list[str] = []
            for cat in data.get("suspicious_categories", []) or []:
                cat_l = cat.lower()
                if "password" in cat_l or "credential" in cat_l:
                    add(W_STEALER, "credential references")
                elif "base64" in cat_l:
                    add(W_STRUCTURE, "encoded data")
                elif any(k in cat_l for k in ("stealer", "rat", "c2", "wallet")):
                    families.append(cat)
            if families:
                extra = f" (+{len(families) - 1})" if len(families) > 1 else ""
                add(W_STEALER, f"{families[0]} strings{extra}")

        elif module == "yara_scanner":
            matches = data.get("matches") or []
            if matches:
                first = matches[0]
                name = (
                    first.get("rule") if isinstance(first, dict) else str(first)
                ) or "rule"
                extra = f" (+{len(matches) - 1})" if len(matches) > 1 else ""
                add(W_YARA, f"YARA: {name} matched{extra}")

        elif module == "doc_analysis":
            vba = (data.get("macros") or {}).get("vba") or {}
            xlm = (data.get("macros") or {}).get("xlm") or {}
            if vba.get("auto_exec_keywords"):
                add(W_EXPLOIT, "auto-executing macro")
            elif vba.get("present"):
                add(W_STRUCTURE, "VBA macros")
            if vba.get("stomping_detected"):
                add(W_EXPLOIT, "VBA stomping")
            if xlm.get("present"):
                add(W_EXPLOIT, "XLM 4.0 macros")
            ti = data.get("template_injection") or {}
            if ti.get("ooxml") or ti.get("rtf"):
                add(W_EXPLOIT, "external template injection")
            ole = data.get("ole_objects") or {}
            if ole.get("equation_editor_candidates"):
                add(W_EXPLOIT, "Equation Editor exploit object")
            if any((p or {}).get("exec_ext") for p in ole.get("package_objects") or []):
                add(W_EXPLOIT, "OLE package dropping an executable")

        elif module == "pdf_analysis":
            hits = data.get("raw_keyword_hits") or {}
            if data.get("header_mismatch"):
                add(W_EXPLOIT, "content is not a PDF despite the extension")
            if any(hits.get(k) for k in ("/OpenAction", "/AA", "/Launch")):
                add(W_EXPLOIT, "PDF auto-action")
            if data.get("has_javascript"):
                add(W_STRUCTURE, "embedded JavaScript")
            if hits.get("/EmbeddedFile"):
                add(W_STEALER, "embedded file")
            if data.get("encrypted"):
                add(W_STRUCTURE, "encrypted PDF")

        elif module == "html_analysis":
            if data.get("base64_blobs") or data.get("embedded_payload_types"):
                kinds = ", ".join(data.get("embedded_payload_types") or [])
                add(
                    W_STEALER,
                    f"smuggled {kinds} payload" if kinds else "smuggled payload",
                )
            if data.get("clipboard_contains_lolbin"):
                add(W_EXPLOIT, "clipboard injection (ClickFix)")
            if len(data.get("obfuscation_indicators") or []) >= 2:
                add(W_STRUCTURE, "obfuscated script")
            if data.get("num_suspicious_external_scripts"):
                add(W_NETWORK, "external C2 scripts")

        elif module == "archive_analysis":
            flags = set(data.get("indicator_flags") or [])
            if "path_traversal" in flags:
                add(W_EXPLOIT, "archive path traversal")
            if (data.get("bomb_guard") or {}).get("triggered"):
                add(W_EXPLOIT, "archive bomb")
            if (data.get("sfx") or {}).get("is_sfx"):
                add(W_PACKER, "SFX payload")
            if data.get("embedded_executables"):
                add(W_CONTAINER, "embedded executable in archive")
            elif data.get("dangerous_members"):
                add(W_CONTAINER, "dangerous member types")
            if (data.get("encryption") or {}).get("is_encrypted") or (
                data.get("encryption") or {}
            ).get("header_encrypted"):
                add(W_STRUCTURE, "encrypted archive")

        elif module == "onenote_analysis":
            flags = set(data.get("indicator_flags") or [])
            if any(f.startswith("contains_embedded_") for f in flags):
                add(W_CONTAINER, "embedded payload in OneNote")
            elif data.get("embedded_executables"):
                add(W_CONTAINER, "embedded executable in OneNote")
            if data.get("encrypted_section"):
                add(W_STRUCTURE, "password-protected OneNote section")

    # Strongest signal first, then dedupe. Sorting is stable, so equal
    # weights keep module execution order.
    indicators.sort(key=lambda pair: pair[0], reverse=True)
    seen: set[str] = set()
    unique: list[str] = []
    for _weight, ind in indicators:
        if ind not in seen:
            seen.add(ind)
            unique.append(ind)

    if not unique:
        return ""

    if len(unique) == 1:
        body = unique[0]
    elif len(unique) == 2:
        body = f"{unique[0]} and {unique[1]}"
    else:
        body = ", ".join(unique[:4])
        if len(unique) > 4:
            body += f" (+{len(unique) - 4} more)"

    band = scoring.get("risk_band", "LOW")
    prefix = {
        "CRITICAL": "High-confidence threat",
        "HIGH": "Likely malicious",
        "MEDIUM": "Suspicious file",
    }.get(band, "Low-risk file")
    return f"{prefix} with {body}"
