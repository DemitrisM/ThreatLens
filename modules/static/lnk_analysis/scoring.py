"""Weighted combo scoring engine for lnk_analysis.

Same shape as :mod:`modules.static.onenote_analysis.scoring` — a list of
``(frozenset, weight, reason)`` triples, a rule firing when its flag set
is a subset of the observed flags, and the same four-band vocabulary and
thresholds. Reusing onenote's bands rather than inventing a fourth set is
deliberate: the project already carries a known issue about competing
band vocabularies, and this must not make it worse.

Classification bands (computed on the **uncapped** total):

* ``>= 25`` → MALICIOUS
* ``10 - 24`` → SUSPICIOUS
* ``1 - 9`` → INFORMATIONAL
* ``0`` → CLEAN

**On ``lolbin_target`` alone being worth only 5.** The Windows Start Menu
ships ``Windows PowerShell.lnk``, whose target is ``powershell.exe``. A
module that calls that SUSPICIOUS is worthless in a SOC. The score has to
come from combinations — a LOLBin *plus* encoded arguments, *plus*
padding, *plus* an overlay — which is also how the format is actually
abused. Weights are provisional and get calibrated against the full
corpus in the end-of-project sweep.
"""

from __future__ import annotations

SCORE_CAP = 60


COMBO_RULES: list[tuple[frozenset[str], int, str]] = [
    # --- the modern evasion, and the reason this module exists ----------
    (frozenset({"lolbin_target", "args_padding_zdi"}), 40,
     "ZDI-CAN-25373 argument padding — real command hidden past the "
     "Properties dialog's visible window, in front of a LOLBin target"),

    (frozenset({"lolbin_target", "encoded_powershell"}), 35,
     "LOLBin target launching a Base64-encoded PowerShell command"),

    (frozenset({"overlay_present", "overlay_extraction_command"}), 35,
     "Appended payload plus the command that carves it out — "
     "self-extracting shortcut"),

    (frozenset({"overlay_executable"}), 30,
     "Executable or script payload appended to the shortcut"),

    (frozenset({"lolbin_target", "download_cradle"}), 30,
     "LOLBin target with a download-and-execute cradle"),

    (frozenset({"lolbin_target", "remote_url_in_args"}), 28,
     "LOLBin target fetching a remote URL"),

    (frozenset({"webdav_remote_exec"}), 30,
     "WebDAV-over-HTTPS remote path — executes a payload off an attacker "
     "share without ever downloading a file to disk"),

    (frozenset({"args_smuggled_in_target"}), 25,
     "Command-line arguments hidden in the target field rather than the "
     "arguments field"),

    (frozenset({"unc_in_arguments"}), 18,
     "Command line references a UNC network path"),

    (frozenset({"icon_masquerade"}), 25,
     "Document icon in front of a LOLBin target (MITRE T1027.012)"),

    (frozenset({"remote_icon_location"}), 25,
     "Icon fetched from a remote host — payload download and NTLM "
     "coercion primitive"),

    (frozenset({"suspicious_host"}), 22,
     "Command line references known malware-hosting infrastructure"),

    (frozenset({"unc_or_webdav_target"}), 20,
     "Target is a UNC or WebDAV path"),

    (frozenset({"env_path_override_mismatch"}), 20,
     "EnvironmentVariableDataBlock overrides the displayed target"),

    (frozenset({"args_padding_heavy"}), 20,
     "Heavy whitespace padding in the arguments"),

    (frozenset({"lolbin_target", "hidden_window"}), 18,
     "LOLBin target launched with a hidden window"),

    (frozenset({"lolbin_target", "exec_bypass"}), 16,
     "LOLBin target with execution-policy or profile bypass flags"),

    (frozenset({"args_over_1024_chars"}), 15,
     "Argument string far longer than any legitimate shortcut carries"),

    (frozenset({"long_relative_path_traversal"}), 15,
     "Deep relative-path traversal in RELATIVE_PATH"),

    (frozenset({"double_extension_name"}), 15,
     "Double extension — the name claims a document"),

    (frozenset({"no_tracker_block", "has_arguments", "lolbin_target"}), 15,
     "No TrackerDataBlock on a LOLBin shortcut with arguments — "
     "built programmatically, not by Explorer"),

    (frozenset({"sanitised_machine_id"}), 14,
     "TrackerDataBlock present but MachineID blanked — deliberate "
     "sanitisation"),

    (frozenset({"obfuscation"}), 13,
     "Obfuscated command line"),

    (frozenset({"timestamp_source_mismatch"}), 12,
     "Header timestamps disagree with the shell items' own timestamps"),

    (frozenset({"high_entropy"}), 12,
     "File entropy above 6.5 — compressed or encrypted content embedded"),

    (frozenset({"large_file"}), 12,
     "Shortcut larger than 100 KiB"),

    (frozenset({"overlay_present"}), 10,
     "Data appended after the end of the shell-link structure"),

    (frozenset({"target_in_user_dir"}), 10,
     "Target lives in a user-writable directory"),

    (frozenset({"filesize_zero"}), 10,
     "Header claims a zero-byte target while carrying arguments"),

    (frozenset({"vm_oui_mac"}), 10,
     "Creating machine's MAC belongs to a virtual-machine vendor"),

    (frozenset({"header_anomaly"}), 10,
     "Structural anomalies against the [MS-SHLLINK] specification"),

    (frozenset({"script_payload"}), 9,
     "Script file extension referenced in the command line"),

    (frozenset({"timestamps_fabricated"}), 8,
     "Header timestamps are zeroed, identical, or out of order"),

    (frozenset({"many_arguments"}), 6,
     "More than four command-line arguments"),

    (frozenset({"args_padding_light"}), 5,
     "Runs of whitespace in the arguments"),

    # Deliberately low — see the module docstring.
    (frozenset({"lolbin_target"}), 5,
     "Target is a living-off-the-land binary"),
]


def score_lnk(flags: frozenset[str]) -> tuple[int, str, list[str], str]:
    """Compute the module's score contribution.

    Returns ``(score_delta, reason, fired_rules, classification)``.
    """
    total = 0
    fired: list[str] = []

    for required, weight, reason in COMBO_RULES:
        if required.issubset(flags):
            total += weight
            fired.append(f"{reason} (+{weight})")

    if total >= 25:
        classification = "MALICIOUS"
    elif total >= 10:
        classification = "SUSPICIOUS"
    elif total >= 1:
        classification = "INFORMATIONAL"
    else:
        classification = "CLEAN"

    capped = min(total, SCORE_CAP)
    reason_text = "; ".join(fired) if fired else "No LNK indicators fired"
    return capped, reason_text, fired, classification
