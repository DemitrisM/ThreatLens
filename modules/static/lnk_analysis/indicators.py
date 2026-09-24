"""Turn a parsed shortcut into a flat set of indicator flags.

This module knows the domain types (``ParsedLnk``, ``CommandAnalysis``);
``scoring.py`` only ever sees a ``frozenset[str]``. Same purity contract
as ``onenote_analysis.indicators``, and for the same reason — it keeps
the weights readable and lets the scoring engine be tested against
literal flag sets with no parsing involved.

Design notes
------------
The flag vocabulary is a **superset** of what ``scoring.py`` has rules
for. Every command category is forwarded wholesale, so names like
``lolbin_reference`` and ``overlay_extraction`` reach the flag set
without a rule of their own. That is deliberate: a flag with no rule
scores nothing but still lands in the report's indicator list, which
keeps a new detection visible before it is weighted, and keeps adding a
weight a one-line change in one file.

Nothing here reads a threshold from config. Every constant is a
published figure with a citation next to it, and pushing them into
config.yaml would invite tuning against a single sample — the
end-of-project calibration sweep is where they move, together, against
the whole corpus.

Two pairs are deliberately exclusive where it would be easy to make
them additive. A shortcut with no TrackerDataBlock at all and one whose
block has a blanked MachineID are different claims — absence is how a
builder writes a file, blanking is a deliberate act on a file that was
built normally — so they are an if/elif and score differently. The
padding tiers work the same way: ``strong`` and the lesser tiers are
mutually exclusive, because grading the same string twice would double
a single observation.
"""

from __future__ import annotations

from .command import LONG_ARG_THRESHOLD, CommandAnalysis
from .parser import ParsedLnk

#: bartblaze's ``Large_filesize_LNK`` threshold. A real desktop shortcut
#: is 500 B - 2 KB; 2-4 KB with a rich property store; past 100 KB the
#: file is carrying something.
LARGE_FILE_BYTES = 100 * 1024

#: bartblaze's ``High_Entropy_LNK`` threshold — benign shortcuts sit below 6.0.
HIGH_ENTROPY = 6.5

#: Intezer's soft "more than four arguments" heuristic.
MANY_ARGS = 4

#: Deep ``..\`` chains push the meaningful part of a path out of the UI.
#: Four is already odd for a real shortcut; campaign samples run 10-20+.
TRAVERSAL_DEPTH = 4


def derive_flags(
    parsed: ParsedLnk,
    cmd: CommandAnalysis,
    *,
    overlay_kind: str = "",
) -> frozenset[str]:
    """Map one shortcut onto the flag vocabulary used by ``scoring.py``.

    Args:
        parsed:       The parsed shortcut.
        cmd:          Its command-line analysis; the target must already
                      be resolved.
        overlay_kind: What the carved overlay typed as, or ``""`` when
                      there is no overlay. ``"unknown"`` is treated as
                      no identification rather than as a type, so an
                      unrecognised blob raises ``overlay_present`` but
                      not ``overlay_executable``.

    Returns:
        A frozenset of flag names. Frozen because ``scoring.py`` tests
        subset containment against it and must not be able to mutate the
        caller's evidence.

    The function is a flat sequence of independent checks by design.
    Every condition reads only ``parsed`` and ``cmd``, never another
    flag, so the flag set cannot depend on the order the checks run in
    — which is what lets the scoring rules be written as combinations
    without worrying about how a combination came to be.
    """
    flags: set[str] = set()

    # --- what it runs ---------------------------------------------------
    if cmd.is_lolbin:
        flags.add("lolbin_target")
    if cmd.target_in_user_dir:
        flags.add("target_in_user_dir")
    if cmd.target_is_remote:
        flags.add("unc_or_webdav_target")
    if parsed.link_info and parsed.link_info.net_name:
        flags.add("unc_or_webdav_target")
    if cmd.args_smuggled_in_target:
        flags.add("args_smuggled_in_target")

    # A target the environment block overrides is not the target the user
    # sees in the Properties dialog.
    if cmd.target_disagreement and parsed.header.has("PreferEnvironmentPath"):
        flags.add("env_path_override_mismatch")

    # --- the command line -----------------------------------------------
    for category in cmd.categories:
        flags.add(category)             # encoded_powershell, download_cradle, ...

    if parsed.header.has("HasArguments") and parsed.arguments:
        flags.add("has_arguments")
    if cmd.urls:
        flags.add("remote_url_in_args")
    if cmd.suspicious_hosts:
        flags.add("suspicious_host")
    if cmd.argument_count > MANY_ARGS:
        flags.add("many_arguments")
    if len(parsed.arguments or "") > LONG_ARG_THRESHOLD:
        flags.add("args_over_1024_chars")

    # --- padding evasion --------------------------------------------------
    if cmd.arg_padding.zdi_can_25373 or cmd.path_padding.zdi_can_25373:
        flags.add("args_padding_zdi")
    if cmd.arg_padding.tier == "strong" or cmd.path_padding.tier == "strong":
        flags.add("args_padding_heavy")
    elif cmd.arg_padding.tier in ("medium", "weak"):
        flags.add("args_padding_light")

    # --- presentation deception ------------------------------------------
    if cmd.icon_masquerade:
        flags.add("icon_masquerade")
    if cmd.remote_icon:
        flags.add("remote_icon_location")
    if cmd.double_extension:
        flags.add("double_extension_name")
    if cmd.traversal_depth > TRAVERSAL_DEPTH:
        flags.add("long_relative_path_traversal")

    # --- payload carriage --------------------------------------------------
    if parsed.overlay_size > 0:
        flags.add("overlay_present")
    if overlay_kind and overlay_kind != "unknown":
        flags.add("overlay_executable")
    if "overlay_extraction" in cmd.categories:
        flags.add("overlay_extraction_command")
    if parsed.file_size > LARGE_FILE_BYTES:
        flags.add("large_file")
    if parsed.entropy >= HIGH_ENTROPY:
        flags.add("high_entropy")

    # --- structural forgery -------------------------------------------------
    if parsed.anomalies:
        flags.add("header_anomaly")
    if not parsed.machine_id and "TrackerDataBlock" not in parsed.extra_blocks:
        flags.add("no_tracker_block")
    elif "TrackerDataBlock" in parsed.extra_blocks and not parsed.machine_id:
        flags.add("sanitised_machine_id")
    if parsed.mac_vendor:
        flags.add("vm_oui_mac")
    if _timestamps_fabricated(parsed):
        flags.add("timestamps_fabricated")
    if _timestamp_sources_disagree(parsed):
        flags.add("timestamp_source_mismatch")
    if parsed.header.target_file_size == 0 and parsed.header.has("HasArguments"):
        flags.add("filesize_zero")

    return frozenset(flags)


def _timestamps_fabricated(parsed: ParsedLnk) -> bool:
    """Header FILETIMEs that no real filesystem would produce.

    Zero is spec-legal ("no time set") but an Explorer-created shortcut
    essentially always populates all three, so all-zero means a builder
    wrote the header. Three identical values to the 100-nanosecond tick
    means one programmatic assignment.

    Both conditions describe states a filesystem does not produce. A
    third once sat beside them — a write time earlier than the creation
    time — on the reasoning that it is impossible. It is not: Windows
    produces exactly that ordering every time a file is copied, since
    the copy takes a fresh creation time and keeps the original's write
    time. APT28.lnk in the corpus showed it, with creation and access at
    the Windows 7 RTM date and a write time a month earlier, and was
    flagged as fabricated on that basis alone.

    Args:
        parsed: The parsed shortcut.

    Returns:
        True if any of the three conditions holds.

    The raw integers are compared rather than the rendered strings.
    Rendering returns None for both a zero and an out-of-range value, so
    comparing the strings would make "no time set" and "nonsense time"
    indistinguishable — and they are different findings.
    """
    header = parsed.header
    times = (header.creation_time_raw, header.access_time_raw, header.write_time_raw)

    if all(t == 0 for t in times):
        return True
    if len(set(times)) == 1 and times[0] != 0:
        return True
    return False


def _timestamp_sources_disagree(parsed: ParsedLnk) -> bool:
    """Header FILETIMEs versus the shell items' own DOS timestamps.

    The two are independent recordings of the same target file, and a
    builder that populates one rarely gets the other consistent. Compared
    at day resolution because DOS timestamps have 2-second granularity
    and carry no timezone, so anything finer would fire on real files.

    Args:
        parsed: The parsed shortcut.

    Returns:
        True when both sources exist and disagree on the date. Absence
        of either is not a mismatch — plenty of legitimate shortcuts
        carry only one.

    Day resolution is generous and still leaves a structural false
    positive that is larger than it first looks. DOS timestamps are
    local time and FILETIMEs are UTC, so the two disagree for a window
    each day equal to the host's UTC offset — not merely around
    midnight. On a machine at UTC+9 every file written before 09:00
    local time carries the previous UTC date.

    Its real rate is unmeasured, because measuring it needs benign
    shortcuts and there are none in the corpus. On the 30 malicious
    samples it fires zero times, so it currently contributes nothing in
    either direction. Both facts belong with the benign-control gap
    recorded in the project notes; do not read the zero as accuracy.
    """
    header_write = parsed.header.write_time
    if not header_write:
        return False
    item_dates = [
        item.modified[:10] for item in parsed.shell_items
        if item.modified and item.name
    ]
    if not item_dates:
        return False
    # The last named item is the target itself; earlier ones are its
    # parent directories, whose mtimes legitimately differ.
    return item_dates[-1] != header_write[:10]
