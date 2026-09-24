"""Module name resolution for --modules / --skip.

Before Pass 3 the documented example `--modules pe,capa,yara` ran
`file_intake` alone and reported `total_score: 0`, band LOW, exit 0 — a
confident clean verdict on a scan that never happened.
"""

import pytest

from core.pipeline import (
    _MODULE_REGISTRY,
    MODULE_ALIASES,
    module_names,
    resolve_module_name,
)


# ------------------------------------------------------------------ resolution


def test_canonical_names_resolve_to_themselves():
    for name in _MODULE_REGISTRY:
        assert resolve_module_name(name) == name


def test_every_documented_alias_resolves():
    for alias, target in MODULE_ALIASES.items():
        assert resolve_module_name(alias) == target


def test_every_alias_target_is_a_real_module():
    """An alias pointing at a non-existent module would silently disable it."""
    for alias, target in MODULE_ALIASES.items():
        assert target in _MODULE_REGISTRY, f"{alias} -> {target} is not a module"


def test_no_alias_shadows_a_canonical_name():
    """An alias equal to a registry key would be unreachable or ambiguous."""
    assert not set(MODULE_ALIASES) & set(_MODULE_REGISTRY)


def test_every_module_is_reachable_by_at_least_one_short_alias():
    reachable = set(MODULE_ALIASES.values())
    missing = set(_MODULE_REGISTRY) - reachable
    assert not missing, f"no alias for: {sorted(missing)}"


def test_resolution_is_case_and_space_insensitive():
    assert resolve_module_name("  PE  ") == "pe_analysis"
    assert resolve_module_name("YARA") == "yara_scanner"
    assert resolve_module_name("Capa_Analysis") == "capa_analysis"


def test_unknown_names_return_none():
    assert resolve_module_name("nosuch") is None
    assert resolve_module_name("") is None
    assert resolve_module_name("pe_analysis_v2") is None


def test_module_names_lists_every_registry_key():
    assert module_names() == sorted(_MODULE_REGISTRY)


def test_the_documented_example_resolves():
    """docs/usage.md documents these short forms."""
    assert [resolve_module_name(n) for n in ("pe", "capa", "yara")] == [
        "pe_analysis",
        "capa_analysis",
        "yara_scanner",
    ]


# ------------------------------------------------------------------- overrides


def apply(config, modules=None, skip=None):
    from cli._helpers import _apply_module_overrides

    return _apply_module_overrides(config, modules, skip)


def base():
    return {"enabled_modules": list(_MODULE_REGISTRY)}


def test_modules_flag_accepts_aliases():
    config = apply(base(), modules="pe,capa,yara")
    assert config["enabled_modules"] == [
        "file_intake",
        "pe_analysis",
        "capa_analysis",
        "yara_scanner",
    ]


def test_skip_flag_accepts_aliases():
    config = apply(base(), skip="capa,vt")
    assert "capa_analysis" not in config["enabled_modules"]
    assert "virustotal" not in config["enabled_modules"]
    assert "pe_analysis" in config["enabled_modules"]


def test_file_intake_is_always_present():
    """Every module reads its metadata, so it is never optional."""
    assert apply(base(), modules="pe")["enabled_modules"][0] == "file_intake"


def test_file_intake_cannot_be_skipped():
    """Skipping it strips hashes and file type from the whole report."""
    assert "file_intake" in apply(base(), skip="file_intake")["enabled_modules"]
    assert "file_intake" in apply(base(), skip="intake")["enabled_modules"]


def test_unknown_module_name_is_a_usage_error():
    import click

    with pytest.raises(click.UsageError) as exc:
        apply(base(), modules="nosuch")
    assert "nosuch" in str(exc.value)


def test_unknown_skip_name_is_a_usage_error():
    """A typo'd --skip virustotl silently leaving VT enabled is the same
    class of bug as the alias failure."""
    import click

    with pytest.raises(click.UsageError):
        apply(base(), skip="virustotl")


def test_usage_error_lists_the_valid_names():
    import click

    with pytest.raises(click.UsageError) as exc:
        apply(base(), modules="nosuch")
    message = str(exc.value)
    assert "pe_analysis" in message and "virustotal" in message


def test_empty_modules_string_is_a_usage_error():
    """--modules '' used to run file_intake alone and report score 0."""
    import click

    with pytest.raises(click.UsageError):
        apply(base(), modules="")

    with pytest.raises(click.UsageError):
        apply(base(), modules="  , ,")


def test_skipping_everything_is_a_usage_error():
    """A scan with nothing left to run must not report a clean verdict."""
    import click

    with pytest.raises(click.UsageError):
        apply(base(), modules="pe", skip="pe")


def test_duplicates_are_collapsed_preserving_order():
    config = apply(base(), modules="pe,exe,pe_analysis,yara")
    assert config["enabled_modules"] == ["file_intake", "pe_analysis", "yara_scanner"]


def test_skip_applies_after_modules():
    """-p deep --skip capa_analysis must work, so order is fixed."""
    config = apply(base(), modules="pe,capa,yara", skip="capa")
    assert config["enabled_modules"] == ["file_intake", "pe_analysis", "yara_scanner"]


def test_no_overrides_leaves_the_list_untouched():
    config = base()
    before = list(config["enabled_modules"])
    assert apply(config)["enabled_modules"] == before


# ------------------------------------------------------------ execution order


def test_modules_run_in_pipeline_order_not_the_order_typed():
    """`--modules vt,onenote` must not run the lookup before the producer.

    The pipeline executes `enabled_modules` in sequence and hands each
    module its predecessors' results through `_module_results_so_far`.
    `virustotal` reads that list to look up hashes the container modules
    surfaced, so running it first means it finds none — the forward
    lookup for every embedded payload is silently skipped and the scan
    still reports success.

    Nothing about a comma-separated allowlist suggests to a user that its
    order is a correctness constraint, so the order typed is discarded in
    favour of the pipeline's own.
    """
    config = apply(base(), modules="vt,onenote")

    assert config["enabled_modules"] == [
        "file_intake",
        "onenote_analysis",
        "virustotal",
    ]


def test_the_canonical_order_covers_every_registered_module():
    """A module missing from the order table would sort to the end.

    That is the safe direction for an unknown name, but for a registered
    one it is a silent demotion past `virustotal` — so the table has to
    stay complete as modules are added.
    """
    from core.config_loader import DEFAULTS

    assert set(DEFAULTS["enabled_modules"]) == set(_MODULE_REGISTRY)


def test_file_intake_leads_however_it_was_typed():
    """It is force-added at the front; ordering must not move it."""
    config = apply(base(), modules="vt,file_intake")

    assert config["enabled_modules"][0] == "file_intake"


# ---------------------------------------------------------------- profiles


def test_deep_runs_at_least_what_standard_runs():
    """`deep` is `standard` plus a longer capa timeout, so it cannot run less.

    `standard` fills `enabled_modules` from DEFAULTS when the config
    supplied none; `deep` only applied its timeout override, so the same
    config gave standard the full thirteen modules and deep an empty
    list — a usage error for asking for the *more* thorough profile.
    """
    from cli._helpers import _apply_scan_profile

    standard = _apply_scan_profile({"enabled_modules": []}, "standard")
    deep = _apply_scan_profile({"enabled_modules": []}, "deep")

    assert deep["enabled_modules"] == standard["enabled_modules"]
    assert deep["capa_timeout_seconds"] == 180


def test_deep_keeps_a_configured_module_list():
    """Filling in must not mean overwriting what a user enabled."""
    from cli._helpers import _apply_scan_profile

    config = _apply_scan_profile(
        {"enabled_modules": ["file_intake", "pe_analysis"]}, "deep"
    )

    assert config["enabled_modules"] == ["file_intake", "pe_analysis"]


def test_an_unrecognised_profile_is_a_no_op():
    """click.Choice guards the CLI; the library path must not mutate.

    The `deep` fix un-indented the fill-in out of its `elif`, which made
    it run for every profile that was not `quick` — so an unknown name
    silently behaved like `standard` while the function documented itself
    as leaving the config alone.
    """
    from cli._helpers import _apply_scan_profile

    config = _apply_scan_profile({"enabled_modules": []}, "nonsense")

    assert config["enabled_modules"] == []
