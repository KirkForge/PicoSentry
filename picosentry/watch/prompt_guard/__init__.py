from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from picosentry.watch.config import PicoWatchConfig
from picosentry.watch.prompt_guard.normalize import Normalizer
from picosentry.watch.prompt_guard.rules import RuleEngine
from picosentry.watch.prompt_guard.scorer import Scorer
from picosentry.watch.types import PromptScanResult, Rule

__all__ = ["Normalizer", "PromptGuard", "RuleEngine", "Scorer"]


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

        score, matched_ids = self._scorer.score(matches, self._engine.rules)

        duration_ms = round((time.perf_counter() - start) * 1000, 3)

        return PromptScanResult(
            blocked=score >= self._config.threshold_block,
            score=score,
            rules_matched=matched_ids,
            corpus_hash=self.corpus_hash,
            corpus_version=self.corpus_version,
            duration_ms=duration_ms,
            normalized_input=normalized,
            details=context or {},
            threshold_block=self._config.threshold_block,
            threshold_warn=self._config.threshold_warn,
        )
