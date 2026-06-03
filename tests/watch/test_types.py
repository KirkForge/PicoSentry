"""PicoWatch types tests."""

from picosentry.watch.types import PromptScanResult, Rule, ValidationResult, Verdict


class TestVerdict:
    def test_values(self) -> None:
        assert Verdict.PASS.value == "pass"
        assert Verdict.WARN.value == "warn"
        assert Verdict.BLOCK.value == "block"


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

    def test_verdict_block(self) -> None:
        result = PromptScanResult(
            blocked=True,
            score=0.9,
            rules_matched=["inj_override_ignore"],
            corpus_hash="abc",
            corpus_version="1.0",
            duration_ms=1.0,
        )
        assert result.verdict == Verdict.BLOCK

    def test_verdict_warn(self) -> None:
        result = PromptScanResult(
            blocked=False,
            score=0.5,
            rules_matched=["inj_multiturn_game"],
            corpus_hash="abc",
            corpus_version="1.0",
            duration_ms=1.0,
        )
        assert result.verdict == Verdict.WARN

    def test_verdict_pass(self) -> None:
        result = PromptScanResult(
            blocked=False,
            score=0.1,
            rules_matched=[],
            corpus_hash="abc",
            corpus_version="1.0",
            duration_ms=1.0,
        )
        assert result.verdict == Verdict.PASS

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
