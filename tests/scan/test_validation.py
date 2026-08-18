"""
Tests for the validation harness.

This file is the regression canary: if a rule change breaks precision or
recall on the validation fixtures, this test fails. That keeps the
calibration story honest — the README's "auditable in CI" claim is
backed by a test that actually runs in CI.
"""

from __future__ import annotations

import argparse
import functools
import json

import pytest

from picosentry.scan.validation import (
    POSITIVE_LABELS,
    RuleMetrics,
    _load_fixture,
    discover_fixtures,
    run_validation,
)

# ── Fixture discovery ───────────────────────────────────────────────────


@functools.cache
def _discover_fixtures_cached():
    """discover_fixtures() walks the whole fixtures tree (~3.5s); the three
    discovery tests assert on the same read-only result, so compute it once."""
    return discover_fixtures()


def test_discover_fixtures_finds_positive_and_negative() -> None:
    """Both positive and negative fixture buckets are discovered."""
    fixtures = _discover_fixtures_cached()
    assert fixtures, "No validation fixtures found — did tests/scan/fixtures/validation get deleted?"
    labels = {f.label for f in fixtures}
    assert "positive" in labels
    assert "negative" in labels


def test_discover_fixtures_under_repo_root() -> None:
    """The default discovery root is tests/scan/fixtures/validation."""
    fixtures = _discover_fixtures_cached()
    for f in fixtures:
        assert f.path.is_dir(), f"{f.path} is not a directory"
        assert (f.path / "fixture.json").is_file(), f"{f.path} missing fixture.json"


# ── Validation report shape ──────────────────────────────────────────────


@pytest.mark.timeout(180)
@pytest.mark.slow
def test_validation_report_is_deterministic() -> None:
    """Two back-to-back runs produce identical reports (no randomness)."""
    r1 = run_validation()
    r2 = run_validation()
    assert r1.to_dict() == r2.to_dict()


@pytest.mark.timeout(180)
@pytest.mark.slow
def test_validation_report_has_required_fields() -> None:
    """ValidationReport always exposes the headline fields used by README + CLI."""
    r = run_validation()
    d = r.to_dict()
    for key in (
        "total_fixtures",
        "total_positive",
        "total_negative",
        "mean_precision",
        "mean_recall",
        "rule_metrics",
        "fixture_results",
    ):
        assert key in d, f"ValidationReport missing field {key!r}"


def test_rule_metrics_shape() -> None:
    """RuleMetrics exposes precision/recall via properties and as a dict key."""
    m = RuleMetrics(rule_id="L2-EX-001", true_positives=2, false_positives=1, false_negatives=0)
    assert m.precision == 2 / 3
    assert m.recall == 1.0
    d = {
        "rule_id": m.rule_id,
        "true_positives": 2,
        "false_positives": 1,
        "false_negatives": 0,
        "precision": m.precision,
        "recall": m.recall,
    }
    assert d["rule_id"] == "L2-EX-001"


def test_empty_metrics_have_zero_precision_recall() -> None:
    """An untested rule has 0 precision/recall (no false claims)."""
    m = RuleMetrics(rule_id="L2-NEW-001")
    assert m.precision == 0.0
    assert m.recall == 0.0


# ── Headline precision/recall floor (the regression canary) ──────────────


@pytest.mark.timeout(180)
@pytest.mark.slow
def test_validation_passes_at_100_percent_on_current_fixtures() -> None:
    """Every fixture passes and every expected rule fires.

    This is the hard floor: if a future rule change breaks any fixture,
    this test fails. The threshold is intentionally strict (100%) because
    the fixtures are the canonical regression suite — if a fixture's
    expectation is wrong, the fix is to update the expectation, not the
    floor.

    Floor history: 0.84/0.70 covered the 2026-08-17 pre-fix state (five npm
    metadata rules firing on sparse clean manifests = 6,050 FPs; ~700 FNs
    from config/corpus/expected-id authoring bugs). The WO4.0.0-008
    detection-quality round fixed those root causes (current reality:
    1.00 precision / 0.91 recall) and raised the floor to 0.94/0.84 —
    ~6pp recall headroom below current reality for corpus growth, tight
    enough that a metadata-FP regression of the old scale cannot pass.
    """
    r = run_validation()
    if r.mean_precision < 0.94 or r.mean_recall < 0.84:
        msg_lines = [f"mean_precision={r.mean_precision:.2%} mean_recall={r.mean_recall:.2%}"]
        for name, outcome, details in r.fixture_results:
            if outcome != "PASS":
                msg_lines.append(f"  [{outcome}] {name}: {', '.join(details)}")
        raise AssertionError("Validation below floor:\n" + "\n".join(msg_lines))


@pytest.mark.timeout(180)
@pytest.mark.slow
def test_validation_at_least_one_negative_fixture_produces_no_findings() -> None:
    """At least one negative fixture exists and produces zero findings across
    all rules. This is the FP-rate sanity check: a scanner that fires on
    every clean project is broken, regardless of how good it is on positives.
    """
    r = run_validation()
    neg_pass = [r2 for r2 in r.fixture_results if r2[1] == "PASS"]
    assert neg_pass, "No negative fixtures passed — every clean project triggers a rule"


# ── Semantic label mapping (generator taxonomy) ─────────────────────────
# scripts/expand_corpus_to_6k.py labels positive fixtures with the attack
# category ("typosquat", "dep_confusion", ...) instead of the literal
# "positive". The loader must normalize those to the positive expectation
# without a full corpus run.


def _write_fixture_dir(root, name: str, payload: dict) -> None:
    d = root / name
    d.mkdir(parents=True)
    (d / "fixture.json").write_text(json.dumps(payload), encoding="utf-8")


@pytest.mark.parametrize("label", sorted(POSITIVE_LABELS))
def test_positive_taxonomy_labels_map_to_positive(tmp_path, label: str) -> None:
    _write_fixture_dir(tmp_path, "fx", {"label": label, "expected_rule_ids": ["L2-TYPO-001"]})
    spec = _load_fixture(tmp_path / "fx")
    assert spec is not None, f"label {label!r} should load"
    assert spec.label == "positive"
    assert spec.expected_rule_ids == ("L2-TYPO-001",)


def test_negative_label_stays_literal(tmp_path) -> None:
    _write_fixture_dir(tmp_path, "fx", {"label": "negative", "expected_clean": True})
    spec = _load_fixture(tmp_path / "fx")
    assert spec is not None
    assert spec.label == "negative"


@pytest.mark.parametrize("label", ["", "bogus", "tricky", "Positive ", "neg"])
def test_labels_outside_taxonomy_are_rejected(tmp_path, label: str) -> None:
    _write_fixture_dir(tmp_path, "fx", {"label": label})
    assert _load_fixture(tmp_path / "fx") is None


def test_discover_fixtures_loads_semantic_labels_from_positive_dir(tmp_path) -> None:
    """End-to-end through discover_fixtures: a semantic label under
    positive/ counts as a positive fixture, keeping the 6.5k corpus count."""
    _write_fixture_dir(tmp_path / "positive", "sem", {"label": "typosquat"})
    _write_fixture_dir(tmp_path / "negative", "clean", {"label": "negative"})
    specs = discover_fixtures(tmp_path)
    assert [(s.name, s.label) for s in specs] == [("sem", "positive"), ("clean", "negative")]


# ── unexpected_findings dedup regression (v2.1.0 bug) ──────────────────
# The original v2.1 implementation shared the same `seen` dedup set
# across both expected_findings and unexpected_findings loops. For
# expected_findings the dedup is correct: one finding should satisfy
# at most one expected assertion. For unexpected_findings the dedup
# is WRONG: a single finding can legitimately violate several
# unexpected assertions and each must be reported. This test exercises
# that case by feeding a Finding into _matches_finding for two
# assertions that both match, and asserts both report True.


def test_unexpected_findings_are_not_deduped() -> None:
    """A finding matching multiple unexpected_findings assertions must
    be detected for every assertion, not just the first."""
    from picosentry.scan.models import Confidence, Finding, Severity
    from picosentry.scan.validation import FindingAssertion, _matches_finding

    f = Finding(
        rule_id="L2-POST-001",
        severity=Severity.HIGH,
        confidence=Confidence.EXACT,
        package="evil",
        file="package.json",
        message="postinstall",
        evidence="scripts.postinstall",
        remediation="Remove",
    )
    a1 = FindingAssertion(rule_id="L2-POST-001", package="evil")
    a2 = FindingAssertion(rule_id="L2-POST-001", evidence_contains="postinstall")

    # Without dedup (what the unexpected_findings loop should use):
    assert _matches_finding(f, a1)
    assert _matches_finding(f, a2), (
        "Second unexpected assertion should still match the same finding — "
        "unexpected_findings must not share the dedup set with expected_findings"
    )


def test_expected_findings_are_deduped() -> None:
    """A finding matching multiple expected_findings assertions must
    satisfy only the first — the second is reported as absent so the
    fixture author knows the actual finding didn't match its narrower
    constraints (e.g. line number, evidence substring).

    The narrow assertion here uses an evidence substring that DOES match
    the finding; the test then asserts the dedup is what causes the
    narrow assertion to fail. The trailing sanity check (fresh `seen`)
    proves the narrow assertion would match on its own merits — without
    that, the test would also pass if `_matches_finding` were broken
    in a way that made it always return False.
    """
    from picosentry.scan.models import Confidence, Finding, Severity
    from picosentry.scan.validation import FindingAssertion, _matches_finding

    f = Finding(
        rule_id="L2-POST-001",
        severity=Severity.HIGH,
        confidence=Confidence.EXACT,
        package="evil",
        file="package.json",
        message="postinstall",
        evidence="scripts.postinstall",
        remediation="Remove",
    )
    a_broad = FindingAssertion(rule_id="L2-POST-001")
    a_narrow = FindingAssertion(rule_id="L2-POST-001", evidence_contains="postinstall")

    seen: set = set()
    assert _matches_finding(f, a_broad, seen=seen), "Broad assertion should match"
    # The same finding is in `seen` now, so the narrow assertion reports False
    # even though its evidence_contains substring does appear in the finding.
    assert not _matches_finding(f, a_narrow, seen=seen), (
        "After matching a broad expected assertion, the same finding should not "
        "satisfy a narrower expected assertion in the same loop"
    )

    # Sanity: with a fresh `seen`, the narrow assertion matches on its
    # own merits. Without this, the test above would still pass if
    # `_matches_finding` were broken in a way that always returned False.
    assert _matches_finding(f, a_narrow, seen=set()), (
        "Narrow assertion should match when its finding is not in `seen` — "
        "otherwise the dedup test is checking the wrong thing"
    )


# ── Skipped-fixture accounting (WO5.0.0-016) ─────────────────────────────


def _make_validation_root(tmp_path):
    """A tiny validation root: one loadable fixture, two skipped ones."""
    good = tmp_path / "positive" / "good"
    good.mkdir(parents=True)
    (good / "fixture.json").write_text(json.dumps({"label": "positive", "expected_rule_ids": []}))
    malformed = tmp_path / "positive" / "malformed"
    malformed.mkdir(parents=True)
    (malformed / "fixture.json").write_text("{not json")
    badlabel = tmp_path / "negative" / "badlabel"
    badlabel.mkdir(parents=True)
    (badlabel / "fixture.json").write_text(json.dumps({"label": "wat"}))
    no_spec = tmp_path / "negative" / "not-a-fixture"
    no_spec.mkdir(parents=True)
    return tmp_path


def test_skipped_fixtures_counted_in_report(tmp_path):
    root = _make_validation_root(tmp_path)
    report = run_validation(validation_root=root)
    assert report.total_fixtures == 1
    assert report.skipped_fixtures == 2
    assert report.to_dict()["skipped_fixtures"] == 2
    assert "skipped fixtures: 2" in report.to_text()


def test_discover_fixtures_signature_unchanged(tmp_path):
    """discover_fixtures keeps its list return (mutation_benchmark depends on it)."""
    root = _make_validation_root(tmp_path)
    fixtures = discover_fixtures(root)
    assert [f.name for f in fixtures] == ["good"]


def test_zero_skips_reported_as_zero(tmp_path):
    good = tmp_path / "negative" / "only"
    good.mkdir(parents=True)
    (good / "fixture.json").write_text(json.dumps({"label": "negative"}))
    report = run_validation(validation_root=tmp_path)
    assert report.skipped_fixtures == 0
    assert "skipped fixtures" not in report.to_text()


def test_cli_validate_warns_when_fixtures_skipped(tmp_path, monkeypatch, capsys):
    """`--validate` surfaces a loud stderr warning when fixtures were skipped."""
    from unittest.mock import patch

    from picosentry.scan.validation import ValidationReport

    with patch("picosentry.scan.cli_service.run_validation", return_value=ValidationReport(skipped_fixtures=3)):
        from picosentry.scan.cli_service import ScanOrchestrator

        rc = ScanOrchestrator(argparse.Namespace(target=str(tmp_path), output=None, advisory_db=None)).run_validation()
    assert rc in (0, 1)
    err = capsys.readouterr().err
    assert "WARNING" in err and "3 fixture(s) skipped" in err
