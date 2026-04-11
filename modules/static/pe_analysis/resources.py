"""PE resource section analysis — entropy + per-RT_* type tally + AutoIt."""


def _analyse_resources(pe: "pefile.PE", sections: list[dict]) -> dict:
    """Compute size + entropy of the .rsrc section if present.

    Large, high-entropy .rsrc sections frequently hide embedded
    payloads — AutoIt scripts, second-stage executables, encrypted
    blobs. We flag entropy >= 7.0 with a non-trivial size.
    """
    info = {
        "present": False,
        "size": 0,
        "entropy": 0.0,
        "high_entropy": False,
    }
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        if name.lower() != ".rsrc":
            continue
        info["present"] = True
        info["size"] = section.SizeOfRawData
        try:
            entropy = section.get_entropy()
            info["entropy"] = round(entropy, 4)
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
                    if type_name == "RT_RCDATA" and size > 1024:
                        try:
                            rva = data_entry.struct.OffsetToData
                            sample = pe.get_data(rva, min(size, 256))
                        except Exception:  # noqa: BLE001
                            sample = b""
                        rcdata_blobs.append((size, sample))
            if total:
                info["types"][type_name] = info["types"].get(type_name, 0) + total
    except Exception:  # noqa: BLE001
        return info

    if rcdata_blobs:
        rcdata_blobs.sort(key=lambda x: -x[0])
        info["largest_rcdata"] = rcdata_blobs[0][0]
        info["large_rcdata"] = rcdata_blobs[0][0]
        # AutoIt scripts compiled with Aut2Exe carry the "AU3!" marker.
        for _size, sample in rcdata_blobs[:5]:
            if b"AU3!" in sample or b"AutoIt v3" in sample:
                info["autoit"] = True
                break

    return info
