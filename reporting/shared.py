"""Shared helpers used by both the terminal and HTML reporters.

Kept minimal on purpose — only formatting helpers and the verdict
sentence builder live here.  Rich-specific constants (colour maps,
the ``Console`` instance) stay inside the terminal package; HTML/CSS
classes stay inside the HTML package.

Design notes
------------
:func:`build_verdict` is the only place the two reporters are guaranteed
to agree on what a file *is*. Everything else they share is formatting,
so a divergence there is cosmetic; a divergence here would mean the
terminal and the HTML report named different threats for one scan.

Three properties hold it together, and each replaced a defect:

* **A module that scored is always narrated.** Design rule 1 makes every
  module return a human-readable ``reason``, so a blank sentence under a
  non-zero score never means "nothing to say" — only that no branch
  recognised the shape. Before the fallback existed, 23 of 311 corpus
  samples scored above zero and rendered no verdict at all, including
  eleven Formbook/RemcosRAT ``.docx`` and CVE-2023-36884.docx.
* **Weight decides what leads, not module order.** The sentence lists
  four indicators, so what wins those slots matters more than what is in
  the list. ``unsigned binary`` fires for every unsigned PE in existence
  and used to take the first slot on the RedLine baseline, ahead of the
  .NET stealer strings that identified it.
* **Order is reproducible.** The sort is stable and every collection fed
  into it is ordered, so one file always produces one sentence. An
  earlier version iterated a ``set`` of flags: five ``PYTHONHASHSEED``
  values gave five sentences for one document, each hiding a different
  finding behind ``(+N more)``.

The branches read whatever their module actually publishes, which is not
always the tidiest field. Three read a raw sweep or a flag list in
preference to a parsed structure, because the optional parser behind the
tidy field — peepdf, oleid — is the part that fails on malformed input,
and malicious files are malformed.

``sanitise_secrets`` lives here rather than in either reporter because
``-vv`` prints raw module data to the terminal and the HTML report
embeds it in a collapsible block. Two copies of a credential filter is
one copy that can be forgotten.
"""

import re


#: Keys whose values are credentials and must never reach a report.
#: Matched case-insensitively at every depth.
SECRET_KEYS: frozenset[str] = frozenset({"api_key", "virustotal_api_key"})


def sanitise_secrets(obj):
    """Recursively drop credential keys from a nested structure.

    Args:
        obj: Any JSON-shaped value. Dicts and sequences are walked;
             anything else is returned as-is.

    Returns:
        A new structure with every :data:`SECRET_KEYS` entry removed at
        every depth. The input is never mutated — a reporter must not
        change the results a later reporter will read, and ``scan -f json
        -o`` runs two of them over the same dict.

    A tuple comes back as a list. That is a serialisation change rather
    than a loss: the destination is JSON or a rich table, neither of
    which distinguishes them, and preserving the type would mean
    rebuilding namedtuples this cannot reconstruct.

    The strip used to apply only to the top level of a module's ``data``
    dict, so ``{"request": {"api_key": ...}}`` survived into the report.
    Terminal ``-vv`` now prints raw module data, so every reporter routes
    through this instead.
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


#: IOC type -> ``(display label, CSS class suffix)``, for the HTML report.
#:
#: The labels are the same six strings as ``theme.IOC_TYPE_LABELS``, and
#: the second element is the key repeated — so this whole table is
#: derivable from that one. It stays separate only because the HTML
#: reporter wants the pair, and ``tests/test_theme.py`` pins the two into
#: agreement so they cannot drift the way the five colour maps did.
IOC_LABELS: dict[str, tuple[str, str]] = {
    "ipv4":         ("IP Address",   "ipv4"),
    "url":          ("URL",          "url"),
    "domain":       ("Domain",       "domain"),
    "registry_key": ("Registry Key", "registry_key"),
    "email":        ("Email",        "email"),
    "windows_path": ("File Path",    "windows_path"),
}


def human_size(nbytes: int | float | None) -> str:
    """Format byte count as a human-readable string (1.5 MiB, etc.).

    Binary units, not decimal: the sizes here come from archive members
    and file stats, which every other tool an analyst will cross-check
    against reports the same way.

    ``None`` reads as zero rather than raising. The case is a key that is
    *present and null*, not a missing one — a missing key raises before
    this is ever called. Module data round-trips through JSON, where an
    absent size is ``null``, and ``web.py`` reaches one of these by
    subscript with no default. Six other call sites already write
    ``or 0`` at the call, which is the callers agreeing a size can be
    absent.

    So the annotation said ``int | float`` while the body guarded with
    ``nbytes or 0``: either the guard was dead or the signature was
    wrong. It was the signature.
    """
    n = float(nbytes or 0)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


# ── Indicator weights, highest first ───────────────────────────────────
#
# The sentence lists only four indicators, so what wins those slots
# matters more than what is in the list: "unsigned binary" fires for every
# unsigned PE in existence and used to take the first slot on the RedLine
# baseline, ahead of the .NET stealer strings that actually identified it.
#
# These rank indicators against each other; they are not the scoring
# engine's weights and must not be confused with them. A module's
# score_delta decides the band, this decides the wording. The two can
# legitimately disagree — a YARA hit worth few points still leads the
# sentence, because a named rule tells an analyst more than a number.
#
# The ladder is semantic, so a new indicator picks the rung that describes
# it rather than a number that happens to sort correctly.
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
#: A corroborating detail. Above W_WEAK, which is reserved for signals that
#: fire across a large benign population, and below a structural finding.
#: A hardcoded exfil address or a Run-key string is not proof of anything on
#: its own, but it is not "most software is unsigned" either.
W_HINT = 25
W_WEAK = 10


# ── doc_analysis: scored flag → (weight, wording) ──────────────────────
#
# The archive, onenote and lnk branches all read ``indicator_flags``; the
# doc branch was the only container module that did not, and doc_analysis
# publishes 28 of them. Eleven corpus .docx scored +12 for an altChunk and
# rendered a blank verdict, because the branch read
# ``template_injection["ooxml"]`` while an altChunk lands in
# ``template_injection["alt_chunks"]``.
#
# Keyed off the flag rather than the parsed structure on purpose: the flag
# is what the scoring rules pay for, so a test can walk COMBO_RULES and
# assert this table covers it. The parsed structures cannot be walked that
# way, which is how the gap survived a pass that was explicitly about
# verdict coverage.
_DOC_FLAG_INDICATORS: dict[str, tuple[int, str]] = {
    "altchunk": (W_EXPLOIT, "altChunk import (template-injection vector)"),
    "altchunk_absolute_path": (W_STRUCTURE,
                               "altChunk target resolving outside the document"),
    "template_inject_high": (W_EXPLOIT, "external template injection"),
    "template_inject_non_ms": (W_EXPLOIT,
                               "template injection to a non-Microsoft host"),
    "equation_editor_ole": (W_EXPLOIT, "Equation Editor exploit object"),
    "shell_explorer": (W_EXPLOIT,
                       "embedded WebBrowser control loading remote content"),
    "htmlfile": (W_EXPLOIT, "htmlfile ActiveX script-execution object"),
    "packager_shell": (W_EXPLOIT,
                       "Packager Shell object dropping a bundled file"),
    "rtf_objupdate": (W_EXPLOIT, r"\objupdate forcing object load on open"),
    "ole_package_exec_ext": (W_EXPLOIT, "OLE package dropping an executable"),
    "url_downloader_keyword": (W_NETWORK, "macro downloading a remote payload"),
    "xlm_url": (W_NETWORK, "XLM macro reaching a URL"),
    "xlm_exec_call": (W_EXPLOIT, "XLM macro calling EXEC/CALL"),
    "auto_exec": (W_EXPLOIT, "auto-executing macro"),
    "shell_keyword": (W_EXPLOIT, "macro launching an OS command"),
    "vba_stomping": (W_EXPLOIT, "VBA stomping"),
    "vba_present": (W_STRUCTURE, "VBA macros"),
    "heavy_vba_obfuscation": (W_STRUCTURE, "heavily obfuscated VBA"),
    "dangerous_embedded_file": (W_CONTAINER,
                                "dangerous file extension inside the container"),
    "ole_package": (W_CONTAINER, "OLE package embedding a file"),
    "ole_object_in_container": (W_HINT, "embedded OLE object stream"),
    "oleid_high_risk": (W_HINT, "oleid HIGH-risk indicator"),
    "encryption_only": (W_HINT,
                        "password-protected document with no macros"),
    "decompression_bomb": (W_STRUCTURE, "decompression bomb inside the container"),
    "rels_oversize": (W_EXPLOIT,
                      "relationship part padded past the parse cap"),
    "rels_size_mismatch": (W_STRUCTURE,
                           "relationship part understating its own size"),
}

#: Scored doc flags deliberately left out of the sentence, and why. The
#: completeness test reads this, so leaving one out is a decision that has
#: to be written down rather than an omission that goes unnoticed.
#:
#: Both are parse-failure signals. They say ThreatLens could not read the
#: file cleanly, which is worth a point and worth a row in the module's own
#: table, but it is not a finding about the sample — and a four-slot
#: sentence that spends a slot saying "parsing was untidy" has spent it
#: badly.
_VERDICT_EXEMPT_DOC_FLAGS: frozenset[str] = frozenset({
    "malformed_openxml",
    "rtf_parse_failed",
})

# ── string_analysis: severity tier → weight ────────────────────────────
#
# The branch used to substring-match category names for credentials,
# base64 and the stealer/RAT family words, which left eight scored ``high``
# categories unnarrated — Anti-debug API reference, Code injection API
# string, Encoded command payload, LOLBin reference, PowerShell
# download/exec, PowerShell evasion flag, VM/sandbox check, Analysis tool
# name. The module tags every match with a severity, and that tier is the
# same field its own scoring reads, so it cannot drift from what scored.
#
# ``low`` is absent deliberately, not forgotten: it scores zero points by
# design, and "Crypto algorithm reference" alone fires on 60 of the 311
# corpus samples — any binary that speaks TLS.
_STRING_SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": W_STEALER,
    "high": W_STRUCTURE,
    "medium": W_HINT,
}

#: Social-engineering patterns are the other half of ClickFix. The copied
#: command is built at runtime — ClickFix2 carries the template literal
#: ``Video call link: ${url}`` — so a static page frequently has the
#: clipboard write and the paste lure without a LOLBin yet in the text.
#: Requiring the LOLBin required the one part that is not there, and
#: ClickFix2/3 and unknown.html scored +15 to +30 in silence.
_CLICKFIX_LURE = "clipboard paste lure (ClickFix)"


def _first_clause(reason: str) -> str:
    """The leading finding of a module reason, without its score.

    Modules join findings with ``"; "`` and several append their own
    ``(+N)`` weight to each one. That parenthetical is correct in the
    FINDINGS table, where a column of deltas is the point, and wrong in a
    sentence, where it reads as part of the prose.
    """
    head = reason.split(_REASON_SEP, 1)[0].strip()
    head = _SCORE_SUFFIX.sub("", head).strip()
    if not head:
        return ""
    # The clause follows "… file with ", so a leading capital reads as a
    # sentence starting mid-sentence. Only fold it when the first word is
    # ordinary prose: modules open reasons with "RTF uses \objupdate",
    # "VBA stomping detected" and "AutoExec + Shell call", and lowercasing
    # the first letter of those gives "rTF", "vBA" and "autoExec".
    first = head.split(" ", 1)[0]
    if first[1:].islower() or first[1:] == "":
        return head[:1].lower() + head[1:]
    return head


#: How modules join the findings inside one ``reason``. Shared with
#: ``terminal_reporter._render``, which cuts on the same boundary.
_REASON_SEP = "; "

#: A trailing ``(+6)`` or ``(+12)`` weight appended to a single finding.
_SCORE_SUFFIX = re.compile(r"\s*\(\+\d+\)\s*$")


def build_verdict(module_results: list[dict], scoring: dict) -> str:
    """Build a one-line human-readable verdict sentence from module
    findings.  Returns ``""`` when there is nothing worth summarising.

    This is the single source of truth shared by the terminal and HTML
    reporters so both outputs surface the same sentence.

    Args:
        module_results: Per-module results from the pipeline, in execution
                        order. Only ``success`` results with a non-zero
                        ``score_delta`` are read: a module that scored
                        nothing has no opinion, and one that errored has
                        no findings to report even if it left data behind.
        scoring:        The pipeline's scoring dict. Only ``risk_band`` is
                        used, and only to choose the opening words — the
                        indicators themselves are derived from the module
                        data, so the band cannot talk the sentence into
                        naming something no module found.

    Returns:
        One sentence, or ``""`` when no module scored. Both callers render
        nothing for an empty string, and the terminal layout depends on
        that: an empty line would leave a gap under the score bar.

    Indicators carry a weight and are sorted before the four-item slice, so
    the strongest signal leads regardless of module execution order.
    """
    indicators: list[tuple[int, str]] = []

    def add(weight: int, text: str) -> None:
        indicators.append((weight, text))

    # ── Per-module dispatch ─────────────────────────────────────────────
    # One branch per module, reading that module's own published shape.
    # Duplicate wording between branches is fine and expected — two
    # modules can legitimately find the same thing, and the dedupe below
    # collapses them into one slot rather than letting a document that is
    # both an archive and an OOXML package say "embedded executable"
    # twice.
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
            # Every one of these scores in ioc_extractor.run(); only the
            # first two were read. CVE-2026-21509.doc scored +10 for a
            # domain and an address and rendered a blank verdict line.
            # windows_path is deliberately absent — it is extracted and
            # reported but never scored, so narrating it would spend a slot
            # on a category the scoring engine itself ignores.
            iocs = data.get("iocs", {}) or {}
            if iocs.get("url") or iocs.get("ipv4"):
                add(W_NETWORK, "network IOC indicators")
            if iocs.get("domain"):
                add(W_NETWORK, "suspicious domain references")
            if iocs.get("registry_key"):
                add(W_HINT, "registry key references")
            if iocs.get("email"):
                add(W_HINT, "email addresses")

        elif module == "virustotal":
            # A payload flagged inside a container VirusTotal has never
            # seen. _lookup_embedded_hashes adds its delta onto this same
            # result, including on the 404 path where the primary starts
            # at -5 and `found` is False — so gating the whole branch on
            # `found` hid the only thing VirusTotal did know. This is the
            # shape the archive forward-lookup exists for.
            worst = None
            for inner in data.get("embedded_hash_lookups") or []:
                if not (inner or {}).get("found"):
                    continue
                hits = (inner.get("malicious") or 0) + (inner.get("suspicious") or 0)
                if hits and (worst is None or hits > worst[0]):
                    worst = (hits, inner.get("name") or "an embedded payload")
            if worst:
                hits, name = worst
                add(W_VT if hits > 10 else W_NETWORK,
                    f"VirusTotal: {hits} engines flagged {name}")

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
            # Keyed on the severity the module itself scored by, not on
            # substrings of the category name. The substring map covered
            # credentials, base64 and the family words and missed eight
            # scored `high` categories outright — anti-debug, code
            # injection, encoded command payload, LOLBin, PowerShell
            # download/exec, PowerShell evasion, VM/sandbox check,
            # analysis tool name.
            #
            # One indicator per tier, not per category. RedLine matches
            # both ".NET stealer rule class" and ".NET stealer
            # scan-routine", which as separate entries ate two of the four
            # slots to say the same thing twice.
            by_tier: dict[str, list[str]] = {}
            for match in data.get("suspicious_matches", []) or []:
                tier = (match or {}).get("severity")
                category = (match or {}).get("category")
                if tier not in _STRING_SEVERITY_WEIGHTS or not category:
                    continue
                bucket = by_tier.setdefault(tier, [])
                if category not in bucket:
                    bucket.append(category)
            for tier, weight in _STRING_SEVERITY_WEIGHTS.items():
                # Sorted, not in match order: suspicious_matches is in the
                # order patterns hit the string table, so which of a tier's
                # categories leads would otherwise depend on where in the
                # binary a string happened to sit.
                names = sorted(by_tier.get(tier) or [])
                if not names:
                    continue
                extra = f" (+{len(names) - 1})" if len(names) > 1 else ""
                add(weight, f"{names[0]} strings{extra}")

            # A flat +10 for strings the binary builds on the stack or
            # decodes at runtime — scored on their existence rather than
            # their content, and the module's whole argument for carrying
            # the FLOSS dependency. Invisible to the corpus sweep that
            # found the other gaps here, because bin/floss is not installed
            # on this machine and the keys are absent without it.
            # Truthiness, not a sum. Both keys are counts today
            # (string_analysis.py sets them from len()), so adding them
            # works — but nothing here needs the total, and a shape change
            # upstream would turn a sum into a TypeError inside a reporter,
            # which design rule 2 says must never happen. Raised in review
            # as a live crash; it is not one, and the check is written this
            # way so the question cannot come back.
            if data.get("floss_decoded_strings") or data.get("floss_stack_strings"):
                add(W_STRUCTURE, "runtime-decoded or stack-built strings")

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

            # The flags, which is what doc_analysis actually scores, and
            # what archive/onenote/lnk have always been read through. The
            # parsed structures above stay: they carry detail the flags do
            # not (which macro auto-executes, which OLE class), and the
            # dedupe below collapses the overlap.
            flags = set(data.get("indicator_flags") or [])
            if "auto_exec" in flags:
                # "auto-executing macro" already says macros are present.
                # The structured branch above spells this as an elif; the
                # flag table has no ordering of its own to express it.
                flags.discard("vba_present")
            # Sorted by weight, then by name. Iterating the set directly
            # made the sentence non-reproducible: the sort below is stable,
            # so equal weights keep insertion order, and insertion order was
            # set-iteration order — measured across five PYTHONHASHSEED
            # values, one document produced five different sentences and hid
            # a different finding behind "(+1 more)" each time.
            mapped = [
                _DOC_FLAG_INDICATORS[f] for f in flags if f in _DOC_FLAG_INDICATORS
            ]
            for weight, text in sorted(mapped, key=lambda m: (-m[0], m[1])):
                add(weight, text)

        elif module == "pdf_analysis":
            hits = data.get("raw_keyword_hits") or {}
            if data.get("header_mismatch"):
                add(W_EXPLOIT, "content is not a PDF despite the extension")
            if any(hits.get(k) for k in ("/OpenAction", "/AA", "/Launch")):
                add(W_EXPLOIT, "PDF auto-action")
            # has_javascript is peepdf's answer, and peepdf is optional and
            # fails on malformed files — which malicious PDFs are. On
            # pdf-zeroday.pdf it reported parse errors and False while the
            # raw sweep held /JavaScript and /JS, and the file scored +20
            # with a blank verdict. The `encrypted: false` defect fixed in
            # 0.5.x was this same misplaced trust.
            #
            # /EmbeddedFile stays singular on the next line. The plural is
            # the name tree, and reporting an attachment from the tree alone
            # is exactly the false positive pdf_analysis had removed.
            if data.get("has_javascript") or any(
                hits.get(k) for k in ("/JavaScript", "/JS")
            ):
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
            elif data.get("has_clipboard_write") and data.get("social_eng_patterns"):
                add(W_EXPLOIT, _CLICKFIX_LURE)
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

        elif module == "lnk_analysis":
            flags = set(data.get("indicator_flags") or [])
            target = data.get("target_basename") or "a LOLBin"

            # The padding evasion leads whenever it fires — it is the one
            # finding an analyst cannot see in Explorer's own UI.
            if "args_padding_zdi" in flags:
                add(W_EXPLOIT, "shortcut arguments padded past the visible field "
                               "(ZDI-CAN-25373)")
            if "encoded_powershell" in flags:
                add(W_STEALER, f"{target} launching encoded PowerShell")
            elif "download_cradle" in flags:
                add(W_STEALER, f"{target} running a download cradle")
            elif data.get("is_lolbin"):
                add(W_STRUCTURE, f"shortcut targets {target}")
            if "overlay_executable" in flags:
                add(W_STEALER, "payload appended to the shortcut")
            elif "overlay_present" in flags:
                add(W_CONTAINER, "data appended after the shortcut structure")
            if "icon_masquerade" in flags:
                add(W_EXPLOIT, "document icon disguising an executable target")
            if "remote_icon_location" in flags:
                add(W_NETWORK, "shortcut icon fetched from a remote host")
            if data.get("suspicious_hosts"):
                add(W_NETWORK, "known malware-hosting infrastructure")
            if "unc_or_webdav_target" in flags:
                add(W_NETWORK, "UNC/WebDAV shortcut target")
            if data.get("machine_id"):
                add(W_WEAK, f"built on host '{data['machine_id']}'")

    # ── Rank, then dedupe ───────────────────────────────────────────────
    # Sort before dedupe, not after: deduping first would keep whichever
    # copy a module happened to emit earliest and could drop the
    # higher-weighted spelling of the same finding. Sorting is stable, so
    # equal weights keep module execution order — which is why every
    # collection feeding `add` is itself ordered.
    indicators.sort(key=lambda pair: pair[0], reverse=True)
    seen: set[str] = set()
    unique: list[str] = []
    for _weight, ind in indicators:
        if ind not in seen:
            seen.add(ind)
            unique.append(ind)

    # ── Floor: a module that scored must always be narrated ─────────────
    # Design rule 1 makes every module return a `reason` defined as "a
    # human-readable explanation of score contribution", so a scoring
    # module can always be described — a blank line under a non-zero score
    # never means "nothing to say", only that no branch above recognised
    # the shape. Measured before this existed: 23 of 311 corpus samples
    # scored above zero and rendered no verdict at all, including eleven
    # Formbook/RemcosRAT .docx and CVE-2023-36884.docx.
    #
    # The module's own reason rather than a phrase table here, because a
    # second vocabulary is a second thing to drift: this one cannot fall
    # behind a module it does not know about, including the Phase 5
    # providers that do not exist yet.
    if not unique:
        scored = [
            r for r in module_results
            if r.get("status") == "success" and (r.get("score_delta") or 0) > 0
        ]
        if scored:
            top = max(scored, key=lambda r: r.get("score_delta") or 0)
            clause = _first_clause(top.get("reason") or "")
            if clause:
                unique = [clause]

    if not unique:
        return ""

    # ── Assemble ────────────────────────────────────────────────────────
    # Three joins rather than one, because "a, b" reads as a truncated
    # list where "a and b" reads as a complete one, and the whole value of
    # this line is that it can be read at a glance. Past four the count is
    # printed instead: the cap is what makes the weights matter.
    if len(unique) == 1:
        body = unique[0]
    elif len(unique) == 2:
        body = f"{unique[0]} and {unique[1]}"
    else:
        body = ", ".join(unique[:4])
        if len(unique) > 4:
            body += f" (+{len(unique) - 4} more)"

    # The prefix is band vocabulary, not file vocabulary. It used to read
    # "Suspicious binary", which is wrong on a .docx — and doc, pdf and
    # html findings have reached this sentence since Pass 4.
    band = scoring.get("risk_band", "LOW")
    prefix = {
        "CRITICAL": "High-confidence threat",
        "HIGH": "Likely malicious",
        "MEDIUM": "Suspicious file",
    }.get(band, "Low-risk file")
    return f"{prefix} with {body}"
