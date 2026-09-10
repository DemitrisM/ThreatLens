"""Tests for the IOC extractor.

The module is mostly false-positive filtering, not matching — a naive regex
sweep over a binary produces hundreds of "domains" that are really Go symbol
names and "IPs" that are really version numbers. So these tests concentrate on
what gets *rejected*, which is where the value and the risk both sit.
"""

import pytest

from modules.static.ioc_extractor import (
    _MAX_IOCS_PER_CATEGORY,
    _REAL_TLDS,
    _SOURCE_PSEUDO_TLDS,
    _filter_domain_fps,
    _filter_ip_fps,
    _filter_url_fps,
    run,
)


def _scan(tmp_path, text, name="sample.bin"):
    """Write *text* to a file and run the extractor over it."""
    p = tmp_path / name
    p.write_bytes(text.encode("utf-8") if isinstance(text, str) else text)
    return run(p, {})


def _iocs(result, kind):
    data = result["data"]
    bucket = data.get("iocs", data)
    return set(bucket.get(kind, []) or [])


# ----------------------------------------------------------------------
# Module contract
# ----------------------------------------------------------------------

def test_returns_the_standard_module_result_dict(tmp_path):
    out = _scan(tmp_path, "nothing interesting here")
    assert out["module"] == "ioc_extractor"
    assert out["status"] in {"success", "skipped", "error"}
    assert isinstance(out["data"], dict)
    assert isinstance(out["score_delta"], (int, float))
    assert isinstance(out["reason"], str)


def test_missing_file_does_not_raise(tmp_path):
    """Design rule 2 — a bad path degrades, it does not explode.

    NOTE: the module currently reports ``status: "success"`` here with a
    reason of "No strings extracted", rather than "error". That is
    arguably wrong — it did not succeed, it could not read the file —
    but file_intake already errors on a missing path, so the scan as a
    whole is not misled. Asserted as the real requirement (no raise,
    no score) rather than pinning the questionable status.
    """
    out = run(tmp_path / "does_not_exist.bin", {})
    assert out["score_delta"] == 0
    assert out["data"].get("iocs", {}) == {}


def test_empty_file_yields_no_iocs(tmp_path):
    out = _scan(tmp_path, "")
    assert out["score_delta"] == 0


# ----------------------------------------------------------------------
# Extraction of each type
# ----------------------------------------------------------------------

def test_public_ip_is_extracted(tmp_path):
    assert "45.137.22.19" in _iocs(_scan(tmp_path, "beacon to 45.137.22.19 now"), "ipv4")


def test_url_is_extracted(tmp_path):
    urls = _iocs(_scan(tmp_path, "GET http://evil-c2-domain.com/panel/gate.php"), "url")
    assert any("evil-c2-domain.com" in u for u in urls)


def test_email_is_extracted(tmp_path):
    out = _scan(tmp_path, "exfil to operator@protonmail.com always")
    assert "operator@protonmail.com" in _iocs(out, "email")


def test_windows_path_is_extracted(tmp_path):
    out = _scan(tmp_path, r"drops C:\Users\Public\svchost.exe on disk")
    assert any("svchost.exe" in p for p in _iocs(out, "windows_path"))


def test_registry_key_is_extracted(tmp_path):
    text = r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"
    assert _iocs(_scan(tmp_path, text), "registry_key")


# ----------------------------------------------------------------------
# IP filtering
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "ip",
    ["10.0.0.1", "192.168.1.1", "172.16.0.5", "127.0.0.1", "0.0.0.0",
     "255.255.255.255", "169.254.1.1"],
)
def test_private_and_reserved_ips_are_rejected(ip):
    """Internal addresses are not indicators — they are everywhere."""
    assert _filter_ip_fps({ip}) == set()


def test_public_ip_survives_filtering():
    assert _filter_ip_fps({"45.137.22.19"}) == {"45.137.22.19"}


@pytest.mark.parametrize("candidate", ["1.0.0.0", "4.0.30319.0", "2.0.50727"])
def test_version_like_strings_are_not_ips(candidate):
    """.NET runtime versions look exactly like dotted quads."""
    assert candidate not in _filter_ip_fps({candidate})


# ----------------------------------------------------------------------
# Domain filtering
# ----------------------------------------------------------------------

def test_real_domain_survives_filtering():
    assert "malicious-c2-panel.top" in _filter_domain_fps({"malicious-c2-panel.top"})


@pytest.mark.parametrize(
    "pseudo",
    ["runtime.gcWriteBarrier", "strconv.ParseFloat", "sync.RWMutex",
     "os.FileMode", "reflect.Value"],
)
def test_go_stdlib_symbols_are_not_domains(pseudo):
    """A Go binary's symbol table is full of things shaped like domains."""
    assert _filter_domain_fps({pseudo}) == set()


def test_unknown_tld_is_rejected():
    assert _filter_domain_fps({"something.notarealtld"}) == set()


def test_camelcase_pseudo_domain_is_rejected():
    """Source-language identifiers, not hostnames."""
    assert _filter_domain_fps({"System.Reflection.Assembly"}) == set()


def test_pseudo_tld_and_real_tld_sets_are_disjoint():
    """A label in both sets is unreachable in whichever is checked second.

    _filter_domain_fps consults _SOURCE_PSEUDO_TLDS first, so anything
    listed in both never reaches the _REAL_TLDS test — the entry there is
    dead, and the loss is silent. Each label has to be resolved one way or
    the other, in one set only.
    """
    assert _SOURCE_PSEUDO_TLDS & _REAL_TLDS == set()


def test_freenom_ccTLD_domain_is_reported():
    """.ml is a heavily abused free ccTLD; it also names OCaml sources."""
    assert "malicious-panel.ml" in _filter_domain_fps({"malicious-panel.ml"})


def test_python_source_filename_is_not_a_domain():
    """.py resolves the other way — PyInstaller samples carry hundreds."""
    assert _filter_domain_fps({"threading.py"}) == set()


def test_common_benign_domain_is_whitelisted():
    """Noise from linked libraries and manifests, not an indicator."""
    assert _filter_domain_fps({"www.w3.org"}) == set()


# ----------------------------------------------------------------------
# URL filtering
# ----------------------------------------------------------------------

def test_schema_urls_are_rejected():
    """XML/manifest namespace URLs appear in nearly every signed binary."""
    kept = _filter_url_fps({"http://www.w3.org/2000/09/xmldsig#"})
    assert kept == set()


def test_c2_url_survives_filtering():
    url = "http://45.137.22.19/gate.php"
    assert url in _filter_url_fps({url})


def test_benign_substring_in_query_does_not_suppress_a_url():
    """The allow-list describes hosts, so a query parameter cannot claim it.

    Matching the benign list against the whole URL made the filter an
    evasion primitive: appending ?ref=www.w3.org to a C2 URL removed it
    from the IOC list entirely.
    """
    url = "http://evil-c2-domain.top/gate.php?ref=www.w3.org"
    assert url in _filter_url_fps({url})


def test_lookalike_host_suffix_does_not_claim_the_allow_list():
    """www.w3.org.evil.tld is attacker-controlled, not W3C."""
    url = "http://www.w3.org.evil.tld/beacon"
    assert url in _filter_url_fps({url})


def test_subdomain_of_a_benign_host_is_still_rejected():
    """Only the real owner can create a subdomain of their own host."""
    assert _filter_url_fps({"http://svc.tempuri.org/x"}) == set()


def test_path_scoped_entry_only_matches_that_path():
    """go.microsoft.com/fwlink is benign; the rest of the host is not."""
    assert _filter_url_fps({"https://go.microsoft.com/fwlink/?LinkId=99"}) == set()
    live = "https://go.microsoft.com/download/payload.exe"
    assert live in _filter_url_fps({live})


def test_url_with_port_and_credentials_still_resolves_its_host():
    """Userinfo and port must not hide the host from the allow-list."""
    assert _filter_url_fps({"http://user:pw@tempuri.org:8080/x"}) == set()


# ----------------------------------------------------------------------
# Caps
# ----------------------------------------------------------------------

def test_per_category_cap_is_enforced(tmp_path):
    """A packed binary can yield thousands of matches; the report caps them."""
    ips = " ".join(f"45.137.{a}.{b}" for a in range(1, 12) for b in range(1, 12))
    out = _scan(tmp_path, ips)
    assert len(_iocs(out, "ipv4")) <= _MAX_IOCS_PER_CATEGORY


def test_cap_constant_matches_the_documented_fifty():
    assert _MAX_IOCS_PER_CATEGORY == 50
