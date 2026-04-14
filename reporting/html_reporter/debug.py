"""Serialised raw module data for the collapsible debug section."""

import json
import logging


logger = logging.getLogger(__name__)


def raw_modules(module_results: list[dict]) -> list[dict]:
    """Serialise each module's full result as JSON, stripping API keys
    and other known-sensitive fields.
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
