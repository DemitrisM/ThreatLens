"""Shared helpers used by both the terminal and HTML reporters.

Kept minimal on purpose — only formatting helpers and the verdict
sentence builder live here.  Rich-specific constants (colour maps,
the ``Console`` instance) stay inside the terminal package; HTML/CSS
classes stay inside the HTML package.
"""


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


def build_verdict(module_results: list[dict], scoring: dict) -> str:
    """Build a one-line human-readable verdict sentence from module
    findings.  Returns ``""`` when there is nothing worth summarising.

    This is the single source of truth shared by the terminal and HTML
    reporters so both outputs surface the same sentence.
    """
    indicators: list[str] = []

    for result in module_results:
        if result.get("status") != "success" or result.get("score_delta", 0) == 0:
            continue

        data = result.get("data", {}) or {}
        module = result.get("module", "")

        if module == "pe_analysis":
            if data.get("packers_detected"):
                indicators.append("packed/encrypted binary")
            if data.get("suspicious_imports"):
                count = len(data["suspicious_imports"])
                if count > 15:
                    indicators.append("extensive suspicious API usage")
                elif count > 5:
                    indicators.append("suspicious API imports")
            if not data.get("has_signature"):
                indicators.append("unsigned binary")
            if data.get("rwx_sections"):
                indicators.append("RWX self-modifying section")
            if len(data.get("hollowing_apis") or []) >= 2:
                indicators.append("process hollowing API combo")
            if data.get("embedded_pe"):
                indicators.append("embedded PE payload")
            if (data.get("resource_types") or {}).get("autoit"):
                indicators.append("AutoIt wrapper")
            footprint = data.get("import_footprint") or {}
            if footprint.get("loader_only") or footprint.get("is_kernel32_only"):
                indicators.append("kernel32-only loader footprint")
            if (data.get("dynamic_api_resolution") or {}).get("count", 0) >= 5:
                indicators.append("dynamic API resolution")

        elif module == "capa_analysis":
            for cat in data.get("scored_categories", []) or []:
                name = (cat.get("category", "") or "").lower()
                if "injection" in name:
                    indicators.append("process injection capability")
                elif "anti" in name:
                    indicators.append("anti-analysis evasion")
                elif "credential" in name:
                    indicators.append("credential harvesting")
                elif "network" in name:
                    indicators.append("network C2 capability")
                elif "data collection" in name or "recon" in name:
                    indicators.append("data collection/reconnaissance")
                elif "persistence" in name:
                    indicators.append("persistence mechanism")
                elif "encryption" in name or "obfuscation" in name:
                    indicators.append("encryption/obfuscation")
                elif "privilege" in name:
                    indicators.append("privilege escalation")

        elif module == "ioc_extractor":
            iocs = data.get("iocs", {}) or {}
            if iocs.get("url") or iocs.get("ipv4"):
                indicators.append("network IOC indicators")

        elif module == "virustotal":
            if data.get("found"):
                detections = (data.get("malicious", 0) or 0) + (
                    data.get("suspicious", 0) or 0
                )
                if detections > 10:
                    label = data.get("threat_label")
                    indicators.append(
                        f"VirusTotal: {detections} engines flagged"
                        + (f" ({label})" if label else "")
                    )
                elif detections >= 1:
                    indicators.append("low VirusTotal detections")

        elif module == "string_analysis":
            for cat in data.get("suspicious_categories", []) or []:
                cat_l = cat.lower()
                if "password" in cat_l or "credential" in cat_l:
                    indicators.append("credential references")
                elif "base64" in cat_l:
                    indicators.append("encoded data")

    seen: set[str] = set()
    unique: list[str] = []
    for ind in indicators:
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
        "MEDIUM": "Suspicious binary",
    }.get(band, "Low-risk file")
    return f"{prefix} with {body}"
