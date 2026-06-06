"""
Tests for the rule-ID alias mapping.

A single detector function can be registered under multiple rule_ids
(L2-OBFS-001 through L2-OBFS-004 all map to `detect_obfuscation`, etc.).
The `RULE_ID_ALIASES` constant in `picosentry/scan/rules/__init__.py`
is the canonical documentation for that mapping — it's the one place
docs, the README, and the validation harness agree on when explaining
why one function emits findings under many rule_ids.

These tests pin down:
  1. The alias mapping is non-empty and covers the three known cases
     (detect_obfuscation, detect_manifest_issues, detect_pypi_obfuscation).
  2. Every rule_id listed in the alias mapping is actually registered in
     the default engine — drift between the doc constant and the engine
     is a real risk this test catches.
  3. The `all_rule_ids()` helper returns the union of RULE_INFO +
     RULE_ID_ALIASES, with no duplicate rule_ids.
  4. Each alias group preserves the primary-first ordering convention:
     the first rule_id in the list is the "general" / primary one, and
     the rest are sub-rules with a finer-grained taxonomy.
"""

from __future__ import annotations

from picosentry.scan.engine import create_default_engine
from picosentry.scan.rules import RULE_ID_ALIASES, RULE_INFO, all_rule_ids

# ── Shape of the alias mapping ──────────────────────────────────────────


def test_rule_id_aliases_is_non_empty() -> None:
    """The mapping must document at least one aliased function."""
    assert RULE_ID_ALIASES, "RULE_ID_ALIASES is empty — the doc table has lost its content"
    for fn_name, ids in RULE_ID_ALIASES.items():
        assert ids, f"RULE_ID_ALIASES[{fn_name!r}] is an empty list"
        # Each alias group must have a primary (first) + at least one sub.
        assert len(ids) >= 2, (
            f"RULE_ID_ALIASES[{fn_name!r}] has only {len(ids)} id — "
            "single-ID entries belong in RULE_INFO, not here"
        )


def test_rule_id_aliases_cover_known_multi_id_functions() -> None:
    """The three known multi-ID registrations must all be documented."""
    # These are the three detector functions that fan out to multiple rule_ids.
    expected_keys = {
        "detect_obfuscation",
        "detect_manifest_issues",
        "detect_pypi_obfuscation",
    }
    actual_keys = set(RULE_ID_ALIASES.keys())
    assert expected_keys.issubset(actual_keys), (
        f"Missing alias entries for: {expected_keys - actual_keys}"
    )


def test_aliases_preserve_primary_first_convention() -> None:
    """For each alias group, the first id is the primary (general) and
    the rest are sub-rules. This is the convention the docs and the
    engine code follow when explaining why a function emits many rule_ids.
    """
    for fn_name, ids in RULE_ID_ALIASES.items():
        primary = ids[0]
        subs = ids[1:]
        # Primary must exist in RULE_INFO (sub-rules may not — they sometimes
        # live only in the alias doc).
        assert primary in RULE_INFO, (
            f"Primary rule_id {primary!r} for {fn_name!r} missing from RULE_INFO"
        )
        # Subs should share the same prefix family (e.g. L2-OBFS-*).
        prefix = "-".join(primary.split("-")[:-1])  # "L2-OBFS"
        for sub in subs:
            assert sub.startswith(prefix + "-"), (
                f"Sub-rule {sub!r} under {fn_name!r} does not share prefix "
                f"{prefix!r} with primary {primary!r}"
            )


# ── The alias mapping matches what the engine actually registers ───────


def test_every_aliased_rule_id_is_registered_in_default_engine() -> None:
    """Every rule_id listed in RULE_ID_ALIASES must be present in the
    default engine's registered rules. This is the drift canary: if a
    future change drops a sub-rule from `engine.register(...)` but
    leaves the alias doc pointing to it, this test fails.
    """
    engine = create_default_engine()
    registered = set(engine.list_rules())
    for fn_name, ids in RULE_ID_ALIASES.items():
        for rid in ids:
            assert rid in registered, (
                f"Alias for {fn_name!r} lists {rid!r} but the default engine "
                "does not register it. Either register it in "
                "create_default_engine() or remove it from RULE_ID_ALIASES."
            )


# ── all_rule_ids() helper ───────────────────────────────────────────────


def test_all_rule_ids_returns_union_of_info_and_aliases() -> None:
    """The helper covers both the canonical catalog and the alias
    sub-rules. Campaigns (L2-CAMP-*) are NOT in the static catalog —
    they self-describe via iocs.json.
    """
    ids = all_rule_ids()
    assert ids, "all_rule_ids() returned an empty set"
    # Every RULE_INFO key must be in the result.
    for key in RULE_INFO:
        assert key in ids, f"all_rule_ids() missing RULE_INFO key {key!r}"
    # Every alias sub-rule must be in the result.
    for alias_list in RULE_ID_ALIASES.values():
        for rid in alias_list:
            assert rid in ids, f"all_rule_ids() missing alias rule_id {rid!r}"


def test_aliases_and_rule_info_are_consistent() -> None:
    """The alias mapping and RULE_INFO are two views of the same rule_ids.
    The alias table is the structural source of truth (which function
    fans out to which rule_ids); RULE_INFO is the documentation view
    (description, severity, helpUri). The two MUST agree on which rule_ids
    belong to which function.

    This is the canary for the L2-OBF-001/L2-PYPI-OBFS-* drift that
    motivated Phase 5: if a future change adds a rule_id to one view
    but not the other, the test fails.
    """
    # For every function in RULE_ID_ALIASES, every rule_id must also be
    # in RULE_INFO (otherwise consumers reading the catalog would miss it).
    for fn_name, ids in RULE_ID_ALIASES.items():
        for rid in ids:
            assert rid in RULE_INFO, (
                f"Rule_id {rid!r} is in RULE_ID_ALIASES[{fn_name!r}] but "
                "missing from RULE_INFO. Add a doc entry or remove the alias."
            )

    # Conversely, every sub-rule under a known alias prefix must be in
    # the alias table — otherwise it would be a "naked" rule_id with
    # no documentation of which function it belongs to.
    for rid in RULE_INFO:
        # Heuristic: ids ending in -002..-099 are typically sub-rules.
        if "-" in rid and rid.split("-")[-1].isdigit():
            suffix = int(rid.split("-")[-1])
            if 2 <= suffix <= 99:
                # Check whether this sub-rule is in any alias group
                # (e.g. "L2-OBFS-002" is in the "detect_obfuscation" group).
                in_any_alias = any(
                    rid in ids
                    for ids in RULE_ID_ALIASES.values()
                )
                if not in_any_alias:
                    # Allow if the rule is a primary (suffix 001) of its family.
                    assert suffix == 1, (
                        f"Rule {rid!r} is in RULE_INFO but is a sub-rule "
                        "(suffix > 1) and is not in any RULE_ID_ALIASES group. "
                        "Either add it to an alias group or rename it to a primary."
                    )
