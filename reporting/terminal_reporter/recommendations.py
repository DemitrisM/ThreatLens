"""Context-aware recommended-next-steps panel."""

from rich.panel import Panel

from ._common import console


def print_recommendations(
    module_results: list[dict], scoring: dict, file_path: str
) -> None:
    recs: list[str] = []
    sha256 = ""

    for result in module_results:
        module = result.get("module", "")
        status = result.get("status", "")
        data = result.get("data", {})

        if module == "file_intake" and status == "success":
            sha256 = data.get("hashes", {}).get("sha256", "")

        elif module == "ioc_extractor" and status == "success":
            iocs = data.get("iocs", {})
            ips = iocs.get("ipv4", [])
            domains = iocs.get("domain", [])
            if ips:
                recs.append(f"Investigate IP(s): {', '.join(ips[:3])}")
            if domains:
                top = ", ".join(domains[:3])
                recs.append(f"Check network logs for connections to: {top}")

        elif module == "virustotal":
            if status == "skipped":
                if sha256:
                    recs.append(f"Submit SHA256 to VirusTotal: {sha256[:16]}…")
            elif status == "success" and data.get("found"):
                detections = data.get("malicious", 0) + data.get("suspicious", 0)
                if detections > 10:
                    label = data.get("threat_label", "")
                    recs.append(
                        f"VirusTotal confirms malicious — {detections} engines flagged"
                        + (f" ({label})" if label else "")
                    )
            elif status == "error":
                reason = result.get("reason", "")
                if "rate limit" in reason.lower():
                    recs.append("VirusTotal rate limit hit — wait 60s or use --skip virustotal")
                elif sha256:
                    recs.append(f"VirusTotal lookup failed — manually check: {sha256[:16]}…")

        elif module == "capa_analysis" and status == "skipped":
            reason = result.get("reason", "")
            if reason == "capa timed out":
                recs.append("capa timed out — try --deep for extended timeout (180s)")

        elif module == "pe_analysis" and status == "success":
            if data.get("packers_detected"):
                recs.append("Binary is packed — consider unpacking before re-analysis")

    band = scoring.get("risk_band", "LOW")
    if band in ("HIGH", "CRITICAL"):
        recs.append("Consider dynamic analysis (--dynamic speakeasy) for runtime behaviour")

    if not recs:
        return

    lines = "\n".join(f"  [dim]•[/dim] {r}" for r in recs)
    panel = Panel(
        lines,
        title="[bold]Recommended Next Steps[/bold]",
        style="dim",
        padding=(1, 2),
    )
    console.print()
    console.print(panel)
