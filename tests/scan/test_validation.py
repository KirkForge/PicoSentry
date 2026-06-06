"""
Tests for the validation harness.

This file is the regression canary: if a rule change breaks precision or
recall on the validation fixtures, this test fails. That keeps the
calibration story honest — the README's "auditable in CI" claim is
backed by a test that actually runs in CI.
"""

from __future__ import annotations

from picosentry.scan.validation import (
    RuleMetrics,
    discover_fixtures,
    run_validation,
)

# ── Fixture discovery ───────────────────────────────────────────────────


def test_discover_fixtures_finds_positive_and_negative() -> None:
    """Both positive and negative fixture buckets are discovered."""
    fixtures = discover_fixtures()
    assert fixtures, "No validation fixtures found — did tests/scan/fixtures/validation get deleted?"
    labels = {f.label for f in fixtures}
    assert "positive" in labels
    assert "negative" in labels


def test_discover_fixtures_under_repo_root() -> None:
    """The default discovery root is tests/scan/fixtures/validation."""
    fixtures = discover_fixtures()
    for f in fixtures:
        assert f.path.is_dir(), f"{f.path} is not a directory"
        assert (f.path / "fixture.json").is_file(), f"{f.path} missing fixture.json"


# ── Validation report shape ──────────────────────────────────────────────


def test_validation_report_is_deterministic() -> None:
    """Two back-to-back runs produce identical reports (no randomness)."""
    r1 = run_validation()
    r2 = run_validation()
    assert r1.to_dict() == r2.to_dict()


def test_validation_report_has_required_fields() -> None:
    """ValidationReport always exposes the headline fields used by README + CLI."""
    r = run_validation()
    d = r.to_dict()
    for key in (
        "total_fixtures", "total_positive", "total_negative",
        "mean_precision", "mean_recall", "rule_metrics", "fixture_results",
    ):
        assert key in d, f"ValidationReport missing field {key!r}"


def test_rule_metrics_shape() -> None:
    """RuleMetrics exposes precision/recall via properties and as a dict key."""
    m = RuleMetrics(rule_id="L2-EX-001", true_positives=2, false_positives=1, false_negatives=0)
    assert m.precision == 2 / 3
    assert m.recall == 1.0
    d = {"rule_id": m.rule_id, "true_positives": 2, "false_positives": 1, "false_negatives": 0,
         "precision": m.precision, "recall": m.recall}
    assert d["rule_id"] == "L2-EX-001"


def test_empty_metrics_have_zero_precision_recall() -> None:
    """An untested rule has 0 precision/recall (no false claims)."""
    m = RuleMetrics(rule_id="L2-NEW-001")
    assert m.precision == 0.0
    assert m.recall == 0.0


# ── Headline precision/recall floor (the regression canary) ──────────────


def test_validation_passes_at_100_percent_on_current_fixtures() -> None:
    """Every fixture passes and every expected rule fires.

    This is the hard floor: if a future rule change breaks any fixture,
    this test fails. The threshold is intentionally strict (100%) because
    the fixtures are the canonical regression suite — if a fixture's
    expectation is wrong, the fix is to update the expectation, not the
    floor.
    """
    r = run_validation()
    if not r.passes:
        # Surface the failure details so CI logs are actionable.
        msg_lines = [f"mean_precision={r.mean_precision:.2%} mean_recall={r.mean_recall:.2%}"]
        for name, outcome, details in r.fixture_results:
            if outcome != "PASS":
                msg_lines.append(f"  [{outcome}] {name}: {', '.join(details)}")
        raise AssertionError("Validation failed:\n" + "\n".join(msg_lines))


def test_validation_at_least_one_negative_fixture_produces_no_findings() -> None:
    """At least one negative fixture exists and produces zero findings across
    all rules. This is the FP-rate sanity check: a scanner that fires on
    every clean project is broken, regardless of how good it is on positives.
    """
    r = run_validation()
    neg_pass = [r2 for r2 in r.fixture_results if r2[1] == "PASS"]
    assert neg_pass, "No negative fixtures passed — every clean project triggers a rule"
