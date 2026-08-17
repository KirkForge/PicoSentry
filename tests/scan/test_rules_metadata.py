"""Metadata invariants for the rule registry (RULE_INFO / DISPATCHED_RULE_IDS).

Keeps `picosentry doctor` honest: every rule id a scan can emit must be
represented in RULE_INFO (or be an L2-CAMP-* campaign detector), and the
cross-ecosystem dispatch map must stay in sync with the RULE_INFO keys it
is derived from.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from picosentry.scan.engine import create_default_engine
from picosentry.scan.rules import DISPATCHED_RULE_IDS, RULE_INFO

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "validation" / "positive"

# One representative fixture per non-npm ecosystem plus a campaign fixture:
# each exercises a code path that emits ecosystem-dispatched or L2-CAMP ids.
# (No rubygems fixture currently fires an L2-RUBYGEMS-* rule — see the
# model-card recall gap — so that ecosystem has no emitting representative.)
REPRESENTATIVE_FIXTURES = (
    "cargo_typo_cla_9727",
    "go_typo_beegoo_4258",
    "maven_typo_commons_langg_8177",
    "nuget_typo_EntityFrameork_4510",
    "pypi_depc_company-auth_5462",
    "camp_trapdoor_npm",
)


@pytest.fixture(scope="module")
def engine():
    return create_default_engine()


class TestDispatchedRuleIds:
    def test_dispatchers_are_core_rules(self) -> None:
        for dispatcher in DISPATCHED_RULE_IDS:
            assert dispatcher in RULE_INFO, f"dispatcher {dispatcher} missing from RULE_INFO"

    def test_dispatched_ids_are_core_rules(self) -> None:
        for dispatcher, dispatched in DISPATCHED_RULE_IDS.items():
            for rule_id in dispatched:
                assert rule_id in RULE_INFO, f"{rule_id} (dispatched by {dispatcher}) missing from RULE_INFO"

    def test_cross_ecosystem_dispatchers_present(self) -> None:
        assert set(DISPATCHED_RULE_IDS) == {"L2-TYPO-001", "L2-DEPC-001", "L2-ADV-001"}
        for dispatcher, dispatched in DISPATCHED_RULE_IDS.items():
            assert len(dispatched) == 6, f"{dispatcher} should cover 6 ecosystems, got {dispatched}"


class TestEmittedRuleIdsRegistered:
    def test_every_emitted_rule_id_is_in_rule_info(self, engine) -> None:
        """Scans must only emit ids that exist in RULE_INFO (or the L2-CAMP-*
        campaign namespace) — otherwise doctor's cross-reference and the
        rule docs drift from what scans actually detect."""
        for name in REPRESENTATIVE_FIXTURES:
            target = FIXTURES / name
            assert target.is_dir(), f"fixture {name} not found"
            result = engine.scan(target)
            for finding in result.findings:
                assert finding.rule_id in RULE_INFO or finding.rule_id.startswith("L2-CAMP-"), (
                    f"{name} emitted unregistered rule id {finding.rule_id}"
                )
