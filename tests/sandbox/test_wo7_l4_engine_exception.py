"""WO7.0.0-020: L4Engine.analyze catches KeyError without killing the scan."""

from __future__ import annotations

from picosentry.sandbox.l4.engine import L4Engine
from picosentry.sandbox.l4.models import BehavioralProfile, BehavioralVerdict, SandboxFinding
from picosentry.sandbox.models import Severity


def _profile() -> BehavioralProfile:
    return BehavioralProfile(package="test")


def test_key_error_in_rule_recorded_not_crash():
    good_findings: list[SandboxFinding] = [
        SandboxFinding(rule_id="L4-OK", severity=Severity.LOW, message="ok"),
    ]

    def good_rule(profile):
        return good_findings

    def key_error_rule(profile):
        raise KeyError("missing-rule-info")

    engine = L4Engine()
    engine.register("L4-OK", good_rule)
    engine.register("L4-KEY", key_error_rule)

    result = engine.analyze(_profile(), baselines={}, deterministic=True)

    assert result.overall_verdict == BehavioralVerdict.CLEAN
    ids = {f.rule_id for f in result.findings}
    assert "L4-OK" in ids
    assert "L4-KEY" not in ids


def test_index_error_in_rule_does_not_crash():
    def index_error_rule(profile):
        raise IndexError("out of range")

    engine = L4Engine()
    engine.register("L4-IDX", index_error_rule)

    result = engine.analyze(_profile(), baselines={}, deterministic=True)

    assert result.overall_verdict == BehavioralVerdict.CLEAN
    assert len(result.findings) == 0
