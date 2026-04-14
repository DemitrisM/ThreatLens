"""Suspicious strings, capa capabilities, VirusTotal data for the template."""

from datetime import datetime, timezone


def suspicious_strings(module_results: list[dict]) -> list[dict]:
    str_result = next(
        (r for r in module_results if r.get("module") == "string_analysis"), None
    )
    if not str_result or str_result.get("status") != "success":
        return []
    return (str_result.get("data", {}) or {}).get("suspicious_matches", []) or []


def capabilities(module_results: list[dict]) -> list[str]:
    capa = next(
        (r for r in module_results if r.get("module") == "capa_analysis"), None
    )
    if not capa or capa.get("status") != "success":
        return []
    return (capa.get("data", {}) or {}).get("capabilities", []) or []


def scored_categories(module_results: list[dict]) -> list[dict]:
    capa = next(
        (r for r in module_results if r.get("module") == "capa_analysis"), None
    )
    if not capa or capa.get("status") != "success":
        return []
    return (capa.get("data", {}) or {}).get("scored_categories", []) or []


def virustotal(module_results: list[dict]) -> dict | None:
    vt = next(
        (r for r in module_results if r.get("module") == "virustotal"), None
    )
    if not vt or vt.get("status") != "success":
        return None
    data = vt.get("data", {}) or {}

    if not data.get("found"):
        return {
            "found": False,
            "sha256": data.get("sha256", ""),
            "permalink": data.get("permalink", ""),
        }

    malicious = data.get("malicious", 0) or 0
    suspicious = data.get("suspicious", 0) or 0
    detections = malicious + suspicious

    if detections > 10:
        detection_class = "delta-pos"
    elif detections >= 1:
        detection_class = "ioc-url"  # yellow
    else:
        detection_class = "delta-neg"

    first_seen = data.get("first_seen")
    if isinstance(first_seen, (int, float)):
        try:
            first_seen = datetime.fromtimestamp(
                first_seen, tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M UTC")
        except (OSError, ValueError):
            first_seen = str(first_seen)

    return {
        "found": True,
        "detection_ratio": data.get(
            "detection_ratio",
            f"{detections}/{data.get('total_engines', 0)}",
        ),
        "detection_class": detection_class,
        "threat_label": data.get("threat_label") or "",
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": data.get("undetected", 0) or 0,
        "first_seen": first_seen or "",
        "community_score": data.get("community_score"),
        "permalink": data.get("permalink", ""),
    }
