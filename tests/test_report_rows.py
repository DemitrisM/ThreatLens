"""Section modules expose pure row builders."""

import copy

from reporting.terminal_reporter._render import Row
from reporting.terminal_reporter.pe import pe_rows

VALID_SEVERITIES = {"bad", "warn", "info"}


def module_data(report: dict, module: str) -> dict:
    return next(r for r in report["module_results"] if r["module"] == module)["data"]


# --------------------------------------------------------------- pe_analysis


def test_pe_rows_returns_rows(report_redline):
    rows = pe_rows(module_data(report_redline, "pe_analysis"), 0)
    assert rows
    assert all(isinstance(r, Row) for r in rows)


def test_pe_rows_is_pure(report_redline):
    """Calling it must not mutate the module data."""
    data = module_data(report_redline, "pe_analysis")
    before = copy.deepcopy(data)
    pe_rows(data, 0)
    pe_rows(data, 1)
    assert data == before


def test_pe_rows_severities_are_valid(report_redline):
    data = module_data(report_redline, "pe_analysis")
    assert all(r.severity in VALID_SEVERITIES for r in pe_rows(data, 1))


def test_pe_rows_empty_data_is_safe():
    assert pe_rows({}, 0) == []
    assert pe_rows({}, 2) == []


def test_pe_rows_detail_one_is_a_superset_of_detail_zero(report_redline):
    """Higher verbosity may only add rows, never remove them."""
    data = module_data(report_redline, "pe_analysis")
    assert set(pe_rows(data, 0)) <= set(pe_rows(data, 1))


def test_pe_rows_carries_the_known_redline_indicators(report_redline):
    """Pinned against the real sample so a conversion cannot drop rows."""
    rows = pe_rows(module_data(report_redline, "pe_analysis"), 1)
    labels = {r.label for r in rows}
    assert "Imphash" in labels
    assert "DLL characteristics" in labels


def test_pe_rows_imphash_value_is_the_full_hash(report_redline):
    rows = pe_rows(module_data(report_redline, "pe_analysis"), 0)
    imphash = next(r for r in rows if r.label == "Imphash")
    assert imphash.value == module_data(report_redline, "pe_analysis")["imphash"]
    assert "…" not in imphash.value


def test_pe_packer_row_is_bad_severity():
    rows = pe_rows({"packers_detected": ["UPX"]}, 0)
    assert Row("Packer", "UPX", "bad") in rows


def test_pe_rwx_row_is_bad_severity():
    rows = pe_rows({"rwx_sections": [".text"]}, 0)
    assert Row("RWX sections", ".text", "bad") in rows


def test_pe_resource_types_only_at_detail_one():
    data = {"resource_types": {"types": {"RT_ICON": 3}}}
    assert not any(r.label == "Resource types" for r in pe_rows(data, 0))
    assert any(r.label == "Resource types" for r in pe_rows(data, 1))


# -------------------------------------------------------------- doc_analysis


def test_doc_rows_returns_rows(report_xlsm):
    from reporting.terminal_reporter.doc import doc_rows

    rows = doc_rows(module_data(report_xlsm, "doc_analysis"), 0)
    assert rows
    assert all(isinstance(r, Row) for r in rows)


def test_doc_rows_is_pure(report_xlsm):
    from reporting.terminal_reporter.doc import doc_rows

    data = module_data(report_xlsm, "doc_analysis")
    before = copy.deepcopy(data)
    doc_rows(data, 0)
    doc_rows(data, 1)
    assert data == before


def test_doc_rows_empty_data_is_safe():
    from reporting.terminal_reporter.doc import doc_rows

    assert doc_rows({}, 0) == []


def test_doc_rows_leads_with_format_and_classification(report_xlsm):
    """The whitelist row was inserted at index 0 after filtering, which
    reordered it relative to the source list. It is built first now."""
    from reporting.terminal_reporter.doc import doc_rows

    rows = doc_rows(module_data(report_xlsm, "doc_analysis"), 0)
    assert rows[0].label == "Format / Classification"
    assert "MALICIOUS" in rows[0].value


def test_doc_rows_classification_uses_shared_severity_map():
    from reporting.terminal_reporter.doc import doc_rows

    rows = doc_rows({"format": "ooxml", "classification": "MALICIOUS"}, 0)
    assert rows[0].severity == "bad"
    rows = doc_rows({"format": "ooxml", "classification": "CLEAN"}, 0)
    assert rows[0].severity == "info"


def test_doc_rows_severities_are_valid(report_xlsm):
    from reporting.terminal_reporter.doc import doc_rows

    data = module_data(report_xlsm, "doc_analysis")
    assert all(r.severity in VALID_SEVERITIES for r in doc_rows(data, 1))


def test_doc_rows_detail_one_is_a_superset_of_detail_zero(report_xlsm):
    from reporting.terminal_reporter.doc import doc_rows

    data = module_data(report_xlsm, "doc_analysis")
    assert set(doc_rows(data, 0)) <= set(doc_rows(data, 1))


def test_doc_rows_finds_the_giftedcrook_macro_signal(report_xlsm):
    """Pinned against the real sample: AutoExec + VBA present."""
    from reporting.terminal_reporter.doc import doc_rows

    rows = doc_rows(module_data(report_xlsm, "doc_analysis"), 1)
    labels = {r.label for r in rows}
    assert "VBA macros" in labels


# ---------------------------------------------------------- archive_analysis


def test_archive_rows_from_real_sample(report_rar):
    from reporting.terminal_reporter.archive import archive_rows

    rows = archive_rows(module_data(report_rar, "archive_analysis"), 1)
    labels = [r.label for r in rows]
    assert labels[0] == "Format"
    assert labels[1] == "Classification"
    assert any(r.value == "MALICIOUS" and r.severity == "bad" for r in rows)


def test_archive_rows_is_pure(report_rar):
    from reporting.terminal_reporter.archive import archive_rows

    data = module_data(report_rar, "archive_analysis")
    before = copy.deepcopy(data)
    archive_rows(data, 0)
    archive_rows(data, 1)
    assert data == before


def test_archive_fired_rules_each_get_a_row(report_rar):
    from reporting.terminal_reporter.archive import archive_rows

    data = module_data(report_rar, "archive_analysis")
    rows = archive_rows(data, 1)
    assert sum(1 for r in rows if r.label == "Fired rule") == len(
        data.get("fired_rules") or []
    )


def test_archive_rows_without_format_is_empty():
    from reporting.terminal_reporter.archive import archive_rows

    assert archive_rows({}, 0) == []
    assert archive_rows({"entry_count": 3}, 0) == []


def test_archive_rows_severities_are_valid(report_rar):
    from reporting.terminal_reporter.archive import archive_rows

    data = module_data(report_rar, "archive_analysis")
    assert all(r.severity in VALID_SEVERITIES for r in archive_rows(data, 1))


def test_archive_encryption_severity_ranks_header_above_per_file():
    from reporting.terminal_reporter.archive import archive_rows

    header = archive_rows(
        {"detected_format": "zip", "encryption": {"header_encrypted": True}}, 0
    )
    per_file = archive_rows(
        {"detected_format": "zip", "encryption": {"is_encrypted": True}}, 0
    )
    assert next(r for r in header if r.label == "Encryption").severity == "bad"
    assert next(r for r in per_file if r.label == "Encryption").severity == "warn"


def test_archive_bomb_guard_row_lists_reasons():
    from reporting.terminal_reporter.archive import archive_rows

    rows = archive_rows(
        {
            "detected_format": "zip",
            "bomb_guard": {"triggered": True, "reasons": ["ratio 900:1"]},
        },
        0,
    )
    bomb = next(r for r in rows if r.label == "Bomb guard")
    assert "ratio 900:1" in bomb.value
    assert bomb.severity == "bad"


def test_archive_every_sha256_renders_in_full_at_80_cols(report_rar):
    """The whole point of the flat layout."""
    from tests.conftest import render_report

    output = render_report(report_rar, 0, width=80)
    data = module_data(report_rar, "archive_analysis")
    for e in data["embedded_executables"]:
        assert e["sha256"] in output, f"{e['name']} hash was split or dropped"


def test_archive_no_member_is_silently_dropped(report_rar):
    """Old code capped at [:20]/[:10] and printed no hint."""
    from tests.conftest import render_report

    output = render_report(report_rar, 0, width=100)
    for m in module_data(report_rar, "archive_analysis")["dangerous_members"]:
        assert m["name"] in output


# ---------------------------------------------------------- onenote_analysis


def test_onenote_rows_from_real_sample(report_onenote):
    from reporting.terminal_reporter.onenote import onenote_rows

    rows = onenote_rows(module_data(report_onenote, "onenote_analysis"), 1)
    assert rows[0].label == "Classification"
    assert all(isinstance(r, Row) for r in rows)


def test_onenote_rows_is_pure(report_onenote):
    from reporting.terminal_reporter.onenote import onenote_rows

    data = module_data(report_onenote, "onenote_analysis")
    before = copy.deepcopy(data)
    onenote_rows(data, 0)
    onenote_rows(data, 1)
    assert data == before


def test_onenote_rows_empty_data_is_safe():
    from reporting.terminal_reporter.onenote import onenote_rows

    assert onenote_rows({}, 0) == []
    assert onenote_rows({"classification": "MALICIOUS"}, 0) == []


def test_onenote_nested_score_reads_total_score():
    """BUG FIX: this read scoring['final_score'], which no module emits,
    so the Child score column always rendered '-'."""
    from reporting.terminal_reporter.onenote import nested_score

    assert nested_score({"report": {"scoring": {"total_score": 42}}}) == 42
    assert nested_score({"report": {"scoring": {}}}) is None
    assert nested_score({}) is None


def test_onenote_nested_score_ignores_the_old_key():
    from reporting.terminal_reporter.onenote import nested_score

    assert nested_score({"report": {"scoring": {"final_score": 42}}}) is None


def test_risk_bands_have_their_own_theme_tokens():
    """BUG FIX: the nested band was coloured via a map keyed by
    MALICIOUS/SUSPICIOUS/..., which a risk band can never match."""
    from reporting.theme import rich_style

    for band in ("low", "medium", "high", "critical"):
        assert rich_style(band), f"no token for risk band {band}"


def test_onenote_every_blob_sha256_renders_in_full(report_onenote):
    from tests.conftest import render_report

    data = module_data(report_onenote, "onenote_analysis")
    blobs = [b for b in (data.get("blobs") or []) if b.get("sha256")]
    if not blobs:
        import pytest

        pytest.skip("fixture has no hashed blobs")
    output = render_report(report_onenote, 1, width=80)
    for b in blobs:
        assert b["sha256"] in output, f"blob at {b.get('offset')} hash split/dropped"


def test_onenote_rows_severities_are_valid(report_onenote):
    from reporting.terminal_reporter.onenote import onenote_rows

    data = module_data(report_onenote, "onenote_analysis")
    assert all(r.severity in VALID_SEVERITIES for r in onenote_rows(data, 1))
