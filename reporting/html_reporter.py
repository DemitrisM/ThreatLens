"""HTML report generator using Jinja2.

Renders a self-contained HTML report (inline CSS, no external deps)
with summary header, score breakdown, MITRE ATT&CK table, IOC table,
suspicious strings, capa capabilities, VirusTotal results, module
timing, recommendations, and collapsible raw module data sections.

Mirrors the structure and section ordering of the terminal reporter
so the two outputs stay in sync.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_TEMPLATE_NAME = "report.html.j2"
_TOOL_VERSION = "0.2.0"

# IOC type → (display label, CSS key)
_IOC_LABELS = {
    "ipv4":         ("IP Address",   "ipv4"),
    "url":          ("URL",          "url"),
    "domain":       ("Domain",       "domain"),
    "registry_key": ("Registry Key", "registry_key"),
    "email":        ("Email",        "email"),
    "windows_path": ("File Path",    "windows_path"),
}


def write_html_report(report: dict, output_dir: Path) -> Path:
    """Render *report* as a self-contained HTML file in *output_dir*.

    Args:
        report:     Complete report dict returned by ``run_pipeline()``.
        output_dir: Directory to write the HTML file into (created if
                    it does not exist).

    Returns:
        Path to the written HTML file.

    Raises:
        ImportError: If Jinja2 is not installed.
    """
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except ImportError as exc:
        logger.error("jinja2 not installed — cannot generate HTML report")
        raise ImportError(
            "jinja2 is required for HTML reports. Install with: pip install jinja2"
        ) from exc

    output_dir.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "j2", "html.j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template(_TEMPLATE_NAME)

    context = _build_context(report)
    html = template.render(**context)

    source_name = Path(report.get("file", "unknown")).stem
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = output_dir / f"{source_name}_{timestamp}.html"

    with out_path.open("w", encoding="utf-8") as fh:
        fh.write(html)

    logger.info("HTML report written to %s", out_path)
    return out_path


# ---------------------------------------------------------------------------
# Context construction
# ---------------------------------------------------------------------------


def _build_context(report: dict) -> dict:
    """Translate the raw pipeline report into the template context dict."""
    module_results = report.get("module_results", [])
    scoring = report.get("scoring", {}) or {}
    timing = report.get("timing", {}) or {}
    file_path = report.get("file", "unknown")

    return {
        "tool_version": _TOOL_VERSION,
        "generated_utc": datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "elapsed_seconds": timing.get("elapsed_seconds", 0.0),
        "file_name": Path(file_path).name,

        "file_info": _file_info(module_results, file_path),
        "scoring": scoring,
        "verdict": _build_verdict(module_results, scoring),
        "module_results": _module_results_for_template(module_results),

        "attack_mappings": _attack_mappings(module_results),
        "iocs_flat": _iocs_flat(module_results),
        "ioc_total": _ioc_total(module_results),
        "suspicious_strings": _suspicious_strings(module_results),
        "capabilities": _capabilities(module_results),
        "scored_categories": _scored_categories(module_results),
        "virustotal": _virustotal(module_results),
        "timing_rows": _timing_rows(module_results),
        "recommendations": _recommendations(module_results, scoring),
        "raw_modules": _raw_modules(module_results),
    }


def _file_info(module_results: list[dict], file_path: str) -> dict:
    """Return the flattened file_info dict the template expects."""
    intake = next(
        (r for r in module_results if r.get("module") == "file_intake"), None
    )
    fallback = {
        "file_name": Path(file_path).name,
        "file_path": str(file_path),
        "file_size_human": "—",
        "type_description": "Unknown",
        "mime_type": "Unknown",
        "md5": "N/A",
        "sha256": "N/A",
        "tlsh": "",
        "ssdeep": "",
    }
    if not intake or intake.get("status") != "success":
        return fallback

    data = intake.get("data", {}) or {}
    hashes = data.get("hashes", {}) or {}
    ft = data.get("file_type", {}) or {}

    return {
        "file_name": data.get("file_name") or Path(file_path).name,
        "file_path": data.get("file_path") or str(file_path),
        "file_size_human": _human_size(data.get("file_size", 0)),
        "type_description": ft.get("description", "Unknown"),
        "mime_type": ft.get("mime_type", "Unknown"),
        "md5": hashes.get("md5") or "N/A",
        "sha256": hashes.get("sha256") or "N/A",
        "tlsh": hashes.get("tlsh") or "",
        "ssdeep": hashes.get("ssdeep") or "",
    }


def _module_results_for_template(module_results: list[dict]) -> list[dict]:
    """Slim down module results to just the fields the table needs."""
    rows = []
    for r in module_results:
        rows.append(
            {
                "module": r.get("module", "unknown"),
                "status": r.get("status", "unknown"),
                "score_delta": r.get("score_delta", 0),
                "reason": r.get("reason", ""),
            }
        )
    return rows


def _attack_mappings(module_results: list[dict]) -> list[dict]:
    capa = next(
        (r for r in module_results if r.get("module") == "capa_analysis"), None
    )
    if not capa or capa.get("status") != "success":
        return []
    mappings = (capa.get("data", {}) or {}).get("attack_mappings", []) or []
    return sorted(
        mappings,
        key=lambda m: (m.get("tactic", ""), m.get("technique_id", "")),
    )


def _iocs_flat(module_results: list[dict]) -> list[dict]:
    """Flatten IOCs into rows: [{type_key, label, value}, ...]."""
    ioc_result = next(
        (r for r in module_results if r.get("module") == "ioc_extractor"), None
    )
    if not ioc_result or ioc_result.get("status") != "success":
        return []
    iocs = (ioc_result.get("data", {}) or {}).get("iocs", {}) or {}
    rows = []
    for ioc_type, values in iocs.items():
        if not values:
            continue
        label, key = _IOC_LABELS.get(ioc_type, (ioc_type, ioc_type))
        for val in values:
            rows.append({"type_key": key, "label": label, "value": val})
    return rows


def _ioc_total(module_results: list[dict]) -> int:
    ioc_result = next(
        (r for r in module_results if r.get("module") == "ioc_extractor"), None
    )
    if not ioc_result or ioc_result.get("status") != "success":
        return 0
    return (ioc_result.get("data", {}) or {}).get("total_iocs", 0)


def _suspicious_strings(module_results: list[dict]) -> list[dict]:
    str_result = next(
        (r for r in module_results if r.get("module") == "string_analysis"), None
    )
    if not str_result or str_result.get("status") != "success":
        return []
    return (str_result.get("data", {}) or {}).get("suspicious_matches", []) or []


def _capabilities(module_results: list[dict]) -> list[str]:
    capa = next(
        (r for r in module_results if r.get("module") == "capa_analysis"), None
    )
    if not capa or capa.get("status") != "success":
        return []
    return (capa.get("data", {}) or {}).get("capabilities", []) or []


def _scored_categories(module_results: list[dict]) -> list[dict]:
    capa = next(
        (r for r in module_results if r.get("module") == "capa_analysis"), None
    )
    if not capa or capa.get("status") != "success":
        return []
    return (capa.get("data", {}) or {}).get("scored_categories", []) or []


def _virustotal(module_results: list[dict]) -> dict | None:
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


def _timing_rows(module_results: list[dict]) -> list[dict]:
    rows = [
        {
            "module": r.get("module", "unknown"),
            "elapsed": r.get("elapsed_seconds", 0.0) or 0.0,
            "status": r.get("status", "unknown"),
        }
        for r in module_results
        if "elapsed_seconds" in r
    ]
    rows.sort(key=lambda r: r["elapsed"], reverse=True)
    return rows


def _recommendations(module_results: list[dict], scoring: dict) -> list[str]:
    """Build context-aware recommendations — mirrors terminal_reporter."""
    recs: list[str] = []
    sha256 = ""

    for result in module_results:
        module = result.get("module", "")
        status = result.get("status", "")
        data = result.get("data", {}) or {}

        if module == "file_intake" and status == "success":
            sha256 = (data.get("hashes", {}) or {}).get("sha256", "")

        elif module == "ioc_extractor" and status == "success":
            iocs = data.get("iocs", {}) or {}
            ips = iocs.get("ipv4", []) or []
            domains = iocs.get("domain", []) or []
            if ips:
                recs.append(f"Investigate IP(s): {', '.join(ips[:3])}")
            if domains:
                recs.append(
                    f"Check network logs for connections to: {', '.join(domains[:3])}"
                )

        elif module == "virustotal":
            if status == "skipped" and sha256:
                recs.append(f"Submit SHA256 to VirusTotal: {sha256[:16]}…")
            elif status == "success" and data.get("found"):
                detections = (data.get("malicious", 0) or 0) + (
                    data.get("suspicious", 0) or 0
                )
                if detections > 10:
                    label = data.get("threat_label", "")
                    suffix = f" ({label})" if label else ""
                    recs.append(
                        f"VirusTotal confirms malicious — {detections} engines flagged{suffix}"
                    )
            elif status == "error":
                reason = result.get("reason", "")
                if "rate limit" in reason.lower():
                    recs.append(
                        "VirusTotal rate limit hit — wait 60s or use --skip virustotal"
                    )
                elif sha256:
                    recs.append(
                        f"VirusTotal lookup failed — manually check: {sha256[:16]}…"
                    )

        elif module == "capa_analysis" and status == "skipped":
            reason = result.get("reason", "")
            if "timeout" in reason.lower() or "timed out" in reason.lower():
                recs.append("capa timed out — try --deep for extended timeout (180s)")

        elif module == "pe_analysis" and status == "success":
            if data.get("packers_detected"):
                recs.append("Binary is packed — consider unpacking before re-analysis")

    band = scoring.get("risk_band", "LOW")
    if band in ("HIGH", "CRITICAL"):
        recs.append(
            "Consider dynamic analysis (--dynamic speakeasy) for runtime behaviour"
        )

    return recs


def _build_verdict(module_results: list[dict], scoring: dict) -> str:
    """Auto-generated verdict sentence — mirrors terminal_reporter._build_verdict."""
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

    seen = set()
    unique = []
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


def _raw_modules(module_results: list[dict]) -> list[dict]:
    """Serialise each module's full result as JSON for the collapsible section.

    Strips API keys and other sensitive fields.
    """
    out = []
    for r in module_results:
        sanitised = dict(r)
        data = sanitised.get("data")
        if isinstance(data, dict):
            sanitised["data"] = {
                k: v
                for k, v in data.items()
                if k not in ("api_key", "virustotal_api_key")
            }
        try:
            text = json.dumps(sanitised, indent=2, default=str)
        except (TypeError, ValueError) as exc:
            logger.warning(
                "Could not serialise module %s for HTML raw view: %s",
                r.get("module", "unknown"),
                exc,
            )
            text = f"<unserialisable: {exc}>"
        out.append(
            {
                "module": r.get("module", "unknown"),
                "status": r.get("status", "unknown"),
                "json": text,
            }
        )
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _human_size(nbytes: int) -> str:
    """Format byte count as a human-readable string."""
    n = float(nbytes or 0)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"
