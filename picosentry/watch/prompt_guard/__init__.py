from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from picosentry.watch.config import PicoWatchConfig
from picosentry.watch.prompt_guard.classifier import PromptClassifier
from picosentry.watch.prompt_guard.normalize import Normalizer
from picosentry.watch.prompt_guard.rules import RuleEngine
from picosentry.watch.prompt_guard.scorer import Scorer
from picosentry.watch.types import PromptScanResult, Rule

__all__ = ["Normalizer", "PromptClassifier", "PromptGuard", "RuleEngine", "Scorer"]


class PromptGuard:
    def __init__(
        self,
        rules_dir: Path | None = None,
        config: PicoWatchConfig | None = None,
    ) -> None:
        self._config = config or PicoWatchConfig()

        self._rules_dir = rules_dir or self._config.rules_dir / "prompt_injection"
        self._normalizer = Normalizer()
        self._engine = RuleEngine(rules_dir=self._rules_dir)
        self._scorer = Scorer(
            threshold_block=self._config.threshold_block,
            threshold_warn=self._config.threshold_warn,
        )
        self._classifier = PromptClassifier(
            blend_factor=self._config.classifier_blend_factor,
        )
        self._classifier_enabled = self._config.classifier_enabled

    @property
    def rules(self) -> list[Rule]:
        return self._engine.rules

    @property
    def corpus_hash(self) -> str:
        return self._engine.corpus_hash

    @property
    def corpus_version(self) -> str:
        return self._config.corpus_version

    @property
    def rules_loaded(self) -> int:
        return self._engine.rules_loaded

    @property
    def rules_expected(self) -> int:
        return self._engine.rules_expected

    def check(self, text: str, context: dict[str, Any] | None = None) -> PromptScanResult:
        start = time.perf_counter()

        if len(text) > self._config.max_prompt_size:
            return PromptScanResult(
                blocked=True,
                score=1.0,
                rules_matched=["input_oversized"],
                corpus_hash=self.corpus_hash,
                corpus_version=self.corpus_version,
                duration_ms=0.0,
                normalized_input=None,
                details={"error": f"Input exceeds maximum size ({self._config.max_prompt_size} bytes)"},
            )

        normalized = self._normalizer.normalize(text)

        matches = self._engine.evaluate(normalized)

        decoded_texts = self._normalizer.decode_and_rescan(text)
        for decoded in decoded_texts:
            decoded_normalized = self._normalizer.normalize(decoded)
            decoded_matches = self._engine.evaluate(decoded_normalized)
            matches.extend(decoded_matches)

        regex_score, matched_ids = self._scorer.score(matches)

        classifier_score = 0.0
        classifier_features: dict[str, float] = {}
        if self._classifier_enabled and regex_score < self._config.threshold_block:
            matched_categories = {rule.category for rule, _ in matches}
            classifier_score, classifier_features = self._classifier.classify(normalized, matched_categories)
            for decoded in decoded_texts:
                decoded_score, decoded_features = self._classifier.classify(decoded, matched_categories)
                if decoded_score > classifier_score:
                    classifier_score = decoded_score
                    classifier_features = decoded_features

        final_score = self._classifier.blend(regex_score, classifier_score)

        duration_ms = round((time.perf_counter() - start) * 1000, 3)

        details: dict[str, Any] = dict(context or {})
        if self._classifier_enabled:
            details["regex_score"] = regex_score
            details["classifier_score"] = classifier_score
            details["classifier_features"] = classifier_features

        return PromptScanResult(
            blocked=final_score >= self._config.threshold_block,
            score=final_score,
            rules_matched=matched_ids,
            corpus_hash=self.corpus_hash,
            corpus_version=self.corpus_version,
            duration_ms=duration_ms,
            normalized_input=normalized,
            details=details,
            threshold_block=self._config.threshold_block,
            threshold_warn=self._config.threshold_warn,
        )
