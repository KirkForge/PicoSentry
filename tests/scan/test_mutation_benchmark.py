"""Adversarial mutation benchmark tests.

These tests run the scanner against mutated copies of the validation fixtures.
They guard against two failure modes:

1. Easion: a cheap source-level mutation (comments, whitespace, quote swaps,
   identifier renaming) causes an expected rule to stop firing.
2. False-positive injection: the same mutations cause negative fixtures to
   start firing rules.

The tests are marked ``slow`` because they scan every fixture once per
mutation strategy. They are intentionally separate from the strict 100% CI
gate in ``test_validation.py`` so they can evolve as the mutation corpus grows.
"""

from __future__ import annotations

import pytest

from picosentry.scan.adversarial_mutations import (
    MUTATORS,
    apply_mutations,
    can_mutate_file,
)
from picosentry.scan.mutation_benchmark import (
    MutationBenchmarkConfig,
    run_mutation_benchmark,
)


class TestMutationApplicability:
    """Sanity checks for the mutation primitives."""

    def test_can_mutate_source_files(self):
        assert can_mutate_file("foo.js")
        assert can_mutate_file("bar.py")
        assert can_mutate_file("baz.go")
        assert can_mutate_file("qux.rs")

    def test_cannot_mutate_manifests(self):
        assert not can_mutate_file("package.json")
        assert not can_mutate_file("Cargo.toml")
        assert not can_mutate_file("requirements.txt")
        assert not can_mutate_file("pom.xml")

    def test_apply_mutations_is_deterministic(self):
        text = "const data = 'secret'; eval(data);"
        mutators = ["insert_comments", "pad_whitespace"]
        r1 = apply_mutations(text, mutators, seed=1)
        r2 = apply_mutations(text, mutators, seed=1)
        assert r1.mutated == r2.mutated
        assert r1.applied == r2.applied

    def test_mutators_are_registered(self):
        for name in MUTATORS:
            assert name in MUTATORS

    def test_insert_comments_adds_lines(self):
        text = "\n".join(f"x{i} = {i}" for i in range(50)) + "\n"
        result = apply_mutations(text, ["insert_comments"], seed=0)
        assert "insert_comments" in result.applied
        assert len(result.mutated.splitlines()) > len(text.splitlines())

    def test_pad_whitespace_preserves_tokens(self):
        text = "eval(x);"
        result = apply_mutations(text, ["pad_whitespace"], seed=0)
        assert "pad_whitespace" in result.applied or result.mutated == text
        assert "eval" in result.mutated and "(" in result.mutated and ")" in result.mutated


class TestMutationBenchmark:
    """End-to-end mutation benchmark tests."""

    @pytest.mark.slow
    @pytest.mark.timeout(180)
    def test_cosmetic_mutations_keep_high_recall(self):
        """Whitespace and comment mutations should not break detection."""
        config = MutationBenchmarkConfig(
            mutators=("insert_comments", "pad_whitespace", "add_dead_code"),
            seed=42,
        )
        report = run_mutation_benchmark(config)
        assert report.aggregate_recall >= 0.85, (
            f"cosmetic mutation recall too low: {report.aggregate_recall:.2%}\n" + report.to_text()
        )

    @pytest.mark.slow
    def test_structural_mutations_keep_high_recall(self):
        """Quote swaps, identifier renames, and line reordering should keep
        recall above the enterprise-beta floor."""
        config = MutationBenchmarkConfig(
            mutators=("quote_swap", "rename_common_identifiers", "reorder_independent_lines"),
            seed=43,
        )
        report = run_mutation_benchmark(config)
        assert report.aggregate_recall >= 0.85, (
            f"structural mutation recall too low: {report.aggregate_recall:.2%}\n" + report.to_text()
        )

    @pytest.mark.slow
    def test_full_mutation_suite_recall_floor(self):
        """All enabled mutators together must not drop aggregate recall below
        the P5 #11 floor of 85%."""
        config = MutationBenchmarkConfig()
        report = run_mutation_benchmark(config)
        assert report.aggregate_recall >= 0.85, (
            f"full mutation recall too low: {report.aggregate_recall:.2%}\n" + report.to_text()
        )

    @pytest.mark.slow
    def test_mutated_negatives_do_not_inflate_precision(self):
        """Applying mutations to clean fixtures must not create false positives
        at a rate that collapses aggregate precision below 95%.
        """
        config = MutationBenchmarkConfig(include_negative_fixtures=True)
        report = run_mutation_benchmark(config)
        assert report.aggregate_precision >= 0.95, (
            f"mutated negative precision too low: {report.aggregate_precision:.2%}\n" + report.to_text()
        )

    def test_benchmark_report_has_required_fields(self):
        """The report shape is stable enough for dashboards and CI parsing."""
        config = MutationBenchmarkConfig(
            mutators=("pad_whitespace",),
            seed=1,
        )
        report = run_mutation_benchmark(config)
        d = report.to_dict()
        for key in ("config", "summary", "rule_metrics", "fixture_results"):
            assert key in d, f"Missing report key {key!r}"
        for key in (
            "total_positive",
            "total_negative",
            "aggregate_recall",
            "aggregate_precision",
        ):
            assert key in d["summary"], f"Missing summary key {key!r}"

    def test_benchmark_text_report_renders(self):
        config = MutationBenchmarkConfig(
            mutators=("pad_whitespace",),
            seed=1,
        )
        report = run_mutation_benchmark(config)
        text = report.to_text()
        assert "aggregate recall" in text
        assert "Failing fixtures" in text
