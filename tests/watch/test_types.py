"""PicoWatch types tests."""

import pytest

from picosentry.watch.types import PromptScanResult, Rule, ValidationResult, Verdict


class TestVerdict:
    @pytest.mark.parametrize("member,value", [("PASS", "pass"), ("WARN", "warn"), ("BLOCK", "block")])
    def test_values(self, member, value):
        assert Verdict[member].value == value


class TestPromptScanResult:
    def test_score_rounding(self) -> None:
        """Scores are rounded to 6 decimal places for determinism."""
        result = PromptScanResult(
            blocked=True,
            score=0.9123456789,
            rules_matched=["inj_override_ignore"],
            corpus_hash="abc123",
            corpus_version="2026.05.1",
            duration_ms=1.5,
        )
        assert result.score == 0.912346

    @pytest.mark.parametrize(
        "blocked,score,rules,expected",
        [
            (True, 0.9, ["inj_override_ignore"], Verdict.BLOCK),
            (False, 0.5, ["inj_multiturn_game"], Verdict.WARN),
            (False, 0.1, [], Verdict.PASS),
        ],
    )
    def test_verdict(self, blocked, score, rules, expected) -> None:
        result = PromptScanResult(
            blocked=blocked,
            score=score,
            rules_matched=rules,
            corpus_hash="abc",
            corpus_version="1.0",
            duration_ms=1.0,
        )
        assert result.verdict == expected

    def test_frozen(self) -> None:
        result = PromptScanResult(
            blocked=False,
            score=0.1,
            rules_matched=[],
            corpus_hash="abc",
            corpus_version="1.0",
            duration_ms=1.0,
        )
        try:
            result.blocked = True  # type: ignore
            raise AssertionError("Should raise FrozenInstanceError")
        except AttributeError:
            pass


class TestRule:
    def test_weight_validation(self) -> None:
        try:
            Rule(
                id="test_rule",
                category="test",
                weight=1.5,
                pattern="test",
                description="test",
            )
            raise AssertionError("Should raise ValueError")
        except ValueError:
            pass

    def test_weight_rounding(self) -> None:
        rule = Rule(
            id="test_rule",
            category="test",
            weight=0.85123,
            pattern="test",
            description="test",
        )
        assert rule.weight == 0.8512


class TestValidationResult:
    def test_score_rounding(self) -> None:
        result = ValidationResult(
            valid=True,
            score=0.7123456789,
            violations=[],
            corpus_hash="abc",
            corpus_version="1.0",
            duration_ms=1.0,
        )
        assert result.score == 0.712346

    def test_verdict_block_from_invalid(self) -> None:
        result = ValidationResult(
            valid=False,
            score=0.1,
            violations=["out_pii_ssn"],
            corpus_hash="abc",
            corpus_version="1.0",
            duration_ms=1.0,
        )
        assert result.verdict == Verdict.BLOCK
