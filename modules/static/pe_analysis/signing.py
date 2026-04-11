"""Authenticode signature presence + certificate hint + checksum integrity."""

import re

import pefile


def _check_signature(pe: "pefile.PE") -> bool:
    """Check whether the PE has a digital signature (Authenticode).

    Only checks for the presence of the security directory entry,
    not whether the signature is valid (that requires OS-level verification).
    """
    # IMAGE_DIRECTORY_ENTRY_SECURITY = 4
    security_dir_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= security_dir_index:
        return False

    security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_dir_index]
    return security_dir.VirtualAddress != 0 and security_dir.Size != 0


def _extract_certificate_info(pe: "pefile.PE") -> dict:
    """Best-effort extraction of the Authenticode certificate subject.

    We do not validate the signature; we just pull the WIN_CERTIFICATE
    blob and try to extract a printable subject CN. This is enough for
    spotting binaries signed with stolen / abused certificates from
    well-known issuers (Comodo, DigiCert, Sectigo, GlobalSign).
    """
    info: dict = {"present": False}
    try:
        sec_idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_idx]
        if not (sec_dir.VirtualAddress and sec_dir.Size):
            return info
        cert_blob = pe.__data__[
            sec_dir.VirtualAddress : sec_dir.VirtualAddress + sec_dir.Size
        ]
        info["present"] = True
        info["size"] = len(cert_blob)
        # Heuristic CN extraction — find any "CN=" or printable
        # CommonName-style sequences in the blob.
        text = cert_blob.decode("latin-1", errors="replace")
        m = re.search(r"CN\s*=\s*([^,/\x00\r\n]{3,80})", text)
        if m:
            info["common_name"] = m.group(1).strip()
        # Look for issuer-like substrings.
        for issuer in ("Sectigo", "Comodo", "DigiCert", "GlobalSign",
                       "Let's Encrypt", "VeriSign", "GoDaddy",
                       "Certum", "SSL.com", "Entrust"):
            if issuer in text:
                info["issuer_hint"] = issuer
                break
    except Exception:  # noqa: BLE001
        return info
    return info


def _check_pe_checksum(pe: "pefile.PE", has_signature: bool) -> dict:
    """Compare the OptionalHeader.CheckSum against a recomputed value.

    A mismatch is only meaningful for signed binaries — Microsoft signs
    with a valid checksum, so a mismatch indicates the binary was
    altered after signing. For unsigned binaries it's noise (most
    compilers leave the field zero).
    """
    info: dict = {
        "stored": 0,
        "computed": 0,
        "mismatch_signed": False,
    }
    try:
        stored = pe.OPTIONAL_HEADER.CheckSum
    except AttributeError:
        return info
    info["stored"] = stored
    try:
        computed = pe.generate_checksum()
    except Exception:  # noqa: BLE001
        return info
    info["computed"] = computed
    if has_signature and stored != 0 and computed != 0 and stored != computed:
        info["mismatch_signed"] = True
    return info
