"""PE resource section analysis — entropy + per-RT_* type tally + AutoIt.

Design notes
------------
The resource directory is the most convenient hiding place in a PE: it is a
structured, arbitrarily large data area that every normal program also uses,
so a payload stored there raises no structural alarm on its own. What
distinguishes a hidden payload is the combination of *type*, *size* and
*entropy* — a multi-megabyte high-entropy RT_RCDATA blob is not an icon.

RT_RCDATA gets special attention because it is the generic "application
defined" type, which makes it where droppers, AutoIt scripts and encrypted
second stages actually land.
"""


def _analyse_resources(pe: "pefile.PE", sections: list[dict]) -> dict:
    """Compute size + entropy of the .rsrc section if present.

    Large, high-entropy .rsrc sections frequently hide embedded
    payloads — AutoIt scripts, second-stage executables, encrypted
    blobs. We flag entropy >= 7.0 with a non-trivial size.

    Args:
        pe:       A parsed ``pefile.PE`` object.
        sections: Section dicts (unused; accepted for a uniform
                  submodule signature).

    Returns:
        ``{"present", "size", "entropy", "high_entropy"}``, all keys
        always populated so the caller needs no guards.
    """
    info = {
        "present": False,
        "size": 0,
        "entropy": 0.0,
        "high_entropy": False,
    }
    for section in pe.sections:
        # Section names are a fixed 8-byte field, NUL-padded rather than
        # NUL-terminated, and are not guaranteed valid UTF-8 in a crafted
        # file — hence the strip and the replacement error handler.
        name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        if name.lower() != ".rsrc":
            continue
        info["present"] = True
        info["size"] = section.SizeOfRawData
        try:
            entropy = section.get_entropy()
            info["entropy"] = round(entropy, 4)
            # Both conditions are required. Entropy alone is unreliable
            # on small sections: a few hundred bytes of compressed icon
            # can reach 7.0 by chance, so the size floor is what keeps
            # this from firing on ordinary programs.
            # Only flag entropy spikes on resource sections that are big
            # enough to plausibly hide a payload (>= 4 KiB).
            if entropy >= 7.0 and info["size"] >= 4096:
                info["high_entropy"] = True
        except Exception:  # noqa: BLE001
            pass
        break
    return info


def _analyse_resource_types(pe: "pefile.PE") -> dict:
    """Walk the resource directory and tally per-type sizes.

    Args:
        pe: A parsed ``pefile.PE`` object.

    Returns:
        {
          "types": {"RT_ICON": 1234, "RT_RCDATA": 56789, ...},
          "largest_rcdata": <bytes>,
          "large_rcdata": <bytes>,    # alias for the largest blob
          "autoit": True/False,
        }
    """
    info: dict = {
        "types": {},
        "largest_rcdata": 0,
        "large_rcdata": 0,
        "autoit": False,
    }
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return info
    # Standard RT_* type IDs from winnt.h. Unlisted IDs render as
    # "TYPE_<n>" rather than being dropped — a custom type is itself
    # worth seeing in the report.
    rt_names = {
        1: "RT_CURSOR", 2: "RT_BITMAP", 3: "RT_ICON", 4: "RT_MENU",
        5: "RT_DIALOG", 6: "RT_STRING", 7: "RT_FONTDIR", 8: "RT_FONT",
        9: "RT_ACCELERATOR", 10: "RT_RCDATA", 11: "RT_MESSAGETABLE",
        12: "RT_GROUP_CURSOR", 14: "RT_GROUP_ICON", 16: "RT_VERSION",
        17: "RT_DLGINCLUDE", 19: "RT_PLUGPLAY", 20: "RT_VXD",
        21: "RT_ANICURSOR", 22: "RT_ANIICON", 23: "RT_HTML",
        24: "RT_MANIFEST",
    }
    rcdata_blobs: list[tuple[int, bytes]] = []  # (size, sample)
    try:
        # --------------------------------------------------------------
        # Walk the three-level resource tree: type -> name/ID -> language.
        #
        # Every level is guarded with hasattr because a crafted file can
        # truncate the tree at any depth, and pefile represents a missing
        # child by simply not setting the attribute. `continue` rather
        # than `break` so one malformed branch does not discard the
        # types already tallied.
        # --------------------------------------------------------------
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            try:
                type_id = entry.id if entry.id is not None else 0
            except AttributeError:
                continue
            type_name = rt_names.get(type_id, f"TYPE_{type_id}")
            total = 0
            if not hasattr(entry, "directory"):
                continue
            for sub in entry.directory.entries:
                if not hasattr(sub, "directory"):
                    continue
                for leaf in sub.directory.entries:
                    data_entry = getattr(leaf, "data", None)
                    if not data_entry or not hasattr(data_entry, "struct"):
                        continue
                    size = data_entry.struct.Size
                    total += size
                    # Sample only RT_RCDATA blobs over 1 KiB, and only
                    # the first 256 bytes: enough for the AutoIt marker
                    # below without copying a multi-megabyte payload.
                    if type_name == "RT_RCDATA" and size > 1024:
                        try:
                            rva = data_entry.struct.OffsetToData
                            sample = pe.get_data(rva, min(size, 256))
                        except Exception:  # noqa: BLE001
                            sample = b""
                        rcdata_blobs.append((size, sample))
            # Accumulate rather than assign: the same RT_* type can
            # appear more than once across the directory.
            if total:
                info["types"][type_name] = info["types"].get(type_name, 0) + total
    except Exception:  # noqa: BLE001
        # Partial tallies are still useful, so return what was collected.
        return info

    if rcdata_blobs:
        # --------------------------------------------------------------
        # Largest blob first, then check the top five for the AutoIt
        # marker. Aut2Exe stores the compiled script as the biggest
        # RT_RCDATA entry, so five is generous headroom without scanning
        # every resource in a large installer.
        # --------------------------------------------------------------
        rcdata_blobs.sort(key=lambda x: -x[0])
        info["largest_rcdata"] = rcdata_blobs[0][0]
        info["large_rcdata"] = rcdata_blobs[0][0]
        # AutoIt scripts compiled with Aut2Exe carry the "AU3!" marker.
        for _size, sample in rcdata_blobs[:5]:
            if b"AU3!" in sample or b"AutoIt v3" in sample:
                info["autoit"] = True
                break

    return info
