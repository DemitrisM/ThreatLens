"""Template data for the ATT&CK, IOC, and module-timing tables."""

from reporting.shared import IOC_LABELS


def attack_mappings(module_results: list[dict]) -> list[dict]:
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


def iocs_flat(module_results: list[dict]) -> list[dict]:
    """Flatten IOCs into rows: ``[{type_key, label, value}, ...]``."""
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
        label, key = IOC_LABELS.get(ioc_type, (ioc_type, ioc_type))
        for val in values:
            rows.append({"type_key": key, "label": label, "value": val})
    return rows


def ioc_total(module_results: list[dict]) -> int:
    ioc_result = next(
        (r for r in module_results if r.get("module") == "ioc_extractor"), None
    )
    if not ioc_result or ioc_result.get("status") != "success":
        return 0
    return (ioc_result.get("data", {}) or {}).get("total_iocs", 0)


def timing_rows(module_results: list[dict]) -> list[dict]:
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
