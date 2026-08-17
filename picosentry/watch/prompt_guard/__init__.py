from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Any

from picosentry.watch.config import PicoWatchConfig
from picosentry.watch.prompt_guard.classifier import PromptClassifier
from picosentry.watch.prompt_guard.normalize import Normalizer
from picosentry.watch.prompt_guard.rules import RuleEngine
from picosentry.watch.prompt_guard.scorer import Scorer
from picosentry.watch.types import PromptScanResult, Rule

logger = logging.getLogger("picowatch.guard")

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

        # Fail-closed: a guard with zero rules is never healthy — whether the
        # corpus dir is missing, empty, or every file failed to parse. Gate on
        # rules_loaded alone (not rules_expected) so a missing dir cannot
        # silently disable the guard.
        if self._config.fail_closed and self._engine.rules_loaded == 0:
            return PromptScanResult(
                blocked=True,
                score=1.0,
                rules_matched=["fail_closed_no_rules"],
                corpus_hash=self.corpus_hash,
                corpus_version=self.corpus_version,
                duration_ms=0.0,
                normalized_input=None,
                details={"error": "No rules loaded (corpus missing/empty/all failed); fail-closed mode is active"},
            )

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

        try:
            normalized = self._normalizer.normalize(text)

            matches = self._engine.evaluate(normalized)

            # Zero-width chars are stripped by normalize() before evaluation,
            # so inj_zwnj can only ever fire on the raw text — evaluate it too,
            # gated on actual zero-width presence so clean input pays nothing.
            if self._normalizer.has_zero_width(text):
                matches.extend(self._engine.evaluate(text))

            marker_neutral = self._normalizer.neutralize_comment_markers(text)
            if marker_neutral != text:
                matches.extend(self._engine.evaluate(self._normalizer.normalize(marker_neutral)))

            # Decode the raw text AND the NFKC-normalized variant: fullwidth-
            # or zero-width-wrapped base64/hex only becomes decodable after
            # normalization.
            decoded_texts = self._normalizer.decode_and_rescan(text)
            if normalized != text:
                decoded_texts.extend(self._normalizer.decode_and_rescan(normalized))
                decoded_texts = list(dict.fromkeys(decoded_texts))
            for decoded in decoded_texts:
                decoded_normalized = self._normalizer.normalize(decoded)
                decoded_matches = self._engine.evaluate(decoded_normalized)
                matches.extend(decoded_matches)

            deduped: list[tuple[Rule, re.Match[str]]] = []
            seen_rule_ids: set[str] = set()
            for rule, match in matches:
                if rule.id not in seen_rule_ids:
                    seen_rule_ids.add(rule.id)
                    deduped.append((rule, match))
            matches = deduped

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
                if marker_neutral != text:
                    neutral_score, neutral_features = self._classifier.classify(marker_neutral, matched_categories)
                    if neutral_score > classifier_score:
                        classifier_score = neutral_score
                        classifier_features = neutral_features

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
        except Exception as exc:
            if not self._config.fail_closed:
                raise
            logger.exception("PromptGuard.check failed in fail-closed mode")
            return PromptScanResult(
                blocked=True,
                score=1.0,
                rules_matched=["fail_closed_error"],
                corpus_hash=self.corpus_hash,
                corpus_version=self.corpus_version,
                duration_ms=round((time.perf_counter() - start) * 1000, 3),
                normalized_input=None,
                details={"error": f"Evaluation failed and fail-closed mode is active: {exc}"},
            )
