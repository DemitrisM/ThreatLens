"""Authenticode signature presence + certificate hint + checksum integrity.

Design notes
------------
Nothing here validates a signature. Real Authenticode verification means
walking a certificate chain to a trust root, checking revocation and
confirming the signed hash matches the file — an OS-level operation that
needs a trust store this tool cannot assume exists on a Linux analysis box.

So the module answers a narrower, honestly-stated question: is a signature
*present*, who does it claim to be from, and was the file altered after it
was signed. A present-but-invalid signature is still a useful signal, because
malware frequently ships with stolen, expired or self-signed certificates and
a checksum that no longer matches.

Every function swallows its own errors and returns a partial dict. The
certificate blob is attacker-controlled data, and a malformed one must
degrade the report rather than abort the scan.
"""

import re

import pefile


def _check_signature(pe: "pefile.PE") -> bool:
    """Check whether the PE has a digital signature (Authenticode).

    Only checks for the presence of the security directory entry,
    not whether the signature is valid (that requires OS-level verification).

    Args:
        pe: A parsed ``pefile.PE`` object.

    Returns:
        True when the security directory names a non-empty blob.
    """
    # The directory table is variable-length; a crafted file can declare
    # fewer entries than the security index, so the bound is checked
    # before indexing.
    # IMAGE_DIRECTORY_ENTRY_SECURITY = 4
    security_dir_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= security_dir_index:
        return False

    # Both fields must be non-zero: a zero size with a set address is how
    # a stripped signature leaves the header behind.
    security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_dir_index]
    return security_dir.VirtualAddress != 0 and security_dir.Size != 0


def _extract_certificate_info(pe: "pefile.PE") -> dict:
    """Best-effort extraction of the Authenticode certificate subject.

    We do not validate the signature; we just pull the WIN_CERTIFICATE
    blob and try to extract a printable subject CN. This is enough for
    spotting binaries signed with stolen / abused certificates from
    well-known issuers (Comodo, DigiCert, Sectigo, GlobalSign).

    Args:
        pe: A parsed ``pefile.PE`` object.

    Returns:
        ``{"present": False}`` when there is no signature, otherwise that
        key plus ``size`` and, when recoverable, ``common_name`` and
        ``issuer_hint``. Keys are absent rather than None when extraction
        failed, so a caller can distinguish "not found" from "empty".
    """
    info: dict = {"present": False}
    try:
        # --------------------------------------------------------------
        # Step 1: Locate and slice the WIN_CERTIFICATE blob.
        #
        # Unlike every other data directory, the security directory's
        # VirtualAddress is a *file offset*, not an RVA — which is why
        # this indexes pe.__data__ directly instead of mapping an RVA.
        # --------------------------------------------------------------
        sec_idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_idx]
        if not (sec_dir.VirtualAddress and sec_dir.Size):
            return info
        cert_blob = pe.__data__[
            sec_dir.VirtualAddress : sec_dir.VirtualAddress + sec_dir.Size
        ]
        info["present"] = True
        info["size"] = len(cert_blob)

        # --------------------------------------------------------------
        # Step 2: Scrape the subject CN out of the DER.
        #
        # A regex over latin-1 rather than a real ASN.1 parse: the goal is
        # a display hint, and adding a certificate-parsing dependency for
        # one string is not worth the install surface. latin-1 because it
        # maps every byte to a character and so cannot raise mid-blob.
        # --------------------------------------------------------------
        # Heuristic CN extraction — find any "CN=" or printable
        # CommonName-style sequences in the blob.
        text = cert_blob.decode("latin-1", errors="replace")
        m = re.search(r"CN\s*=\s*([^,/\x00\r\n]{3,80})", text)
        if m:
            info["common_name"] = m.group(1).strip()

        # --------------------------------------------------------------
        # Step 3: Note a recognised issuer. Stolen code-signing certs are
        # overwhelmingly issued by these CAs, so naming the issuer helps
        # an analyst decide whether the signature is worth chasing.
        # --------------------------------------------------------------
        # Look for issuer-like substrings.
        for issuer in ("Sectigo", "Comodo", "DigiCert", "GlobalSign",
                       "Let's Encrypt", "VeriSign", "GoDaddy",
                       "Certum", "SSL.com", "Entrust"):
            if issuer in text:
                info["issuer_hint"] = issuer
                break
    except Exception:  # noqa: BLE001
        # Deliberately broad: the blob is attacker-controlled, and a
        # partial dict is a better outcome than a failed scan.
        return info
    return info


def _check_pe_checksum(pe: "pefile.PE", has_signature: bool) -> dict:
    """Compare the OptionalHeader.CheckSum against a recomputed value.

    A mismatch is only meaningful for signed binaries — Microsoft signs
    with a valid checksum, so a mismatch indicates the binary was
    altered after signing. For unsigned binaries it's noise (most
    compilers leave the field zero).

    Args:
        pe:            A parsed ``pefile.PE`` object.
        has_signature: Result of ``_check_signature``; gates the flag
                       because the comparison is meaningless without it.

    Returns:
        ``{"stored", "computed", "mismatch_signed"}``. Both values are
        returned even when no flag is raised, so ``-vv`` can show the
        numbers that led to the conclusion.
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
        # Recomputing walks the whole image and can fail on a truncated
        # or overlapping-section file, which is itself common in malware.
        computed = pe.generate_checksum()
    except Exception:  # noqa: BLE001
        return info
    info["computed"] = computed
    # All four conditions matter: unsigned files are noise, and a zero on
    # either side means "not populated" rather than "does not match".
    if has_signature and stored != 0 and computed != 0 and stored != computed:
        info["mismatch_signed"] = True
    return info
