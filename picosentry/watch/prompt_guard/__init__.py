"""L5 Prompt Guard — deterministic prompt injection detection.

Same input + same rules + same config = same score. Always.
"""

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
    """L5 Prompt Guard: deterministic injection detection.

    Usage:
        guard = PromptGuard()
        result = guard.check("ignore all previous instructions")
        print(result.blocked, result.score, result.rules_matched)
    """

    def __init__(
        self,
        rules_dir: Path | None = None,
        config: PicoWatchConfig | None = None,
    ) -> None:
        self._config = config or PicoWatchConfig()
        # PromptGuard loads from prompt_injection subdirectory
        self._rules_dir = rules_dir or self._config.rules_dir / "prompt_injection"
        self._normalizer = Normalizer()
        self._engine = RuleEngine(rules_dir=self._rules_dir)
        self._scorer = Scorer(
            threshold_block=self._config.threshold_block,
            threshold_warn=self._config.threshold_warn,
        )

    @property
    def rules(self) -> list[Rule]:
        """Loaded rules, sorted by ID for determinism."""
        return self._engine.rules

    @property
    def corpus_hash(self) -> str:
        """SHA-256 hash of all rule files for corpus versioning."""
        return self._engine.corpus_hash

    @property
    def corpus_version(self) -> str:
        """Corpus version string."""
        return self._config.corpus_version

    @property
    def rules_loaded(self) -> int:
        """Number of rules successfully loaded (vs expected from YAML files)."""
        return self._engine.rules_loaded

    @property
    def rules_expected(self) -> int:
        """Number of rules expected from YAML files (before filtering)."""
        return self._engine.rules_expected

    def check(self, text: str, context: dict[str, Any] | None = None) -> PromptScanResult:
        """Scan a prompt for injection patterns.

        Args:
            text: The prompt text to scan.
            context: Optional context dict (e.g., user_id, model).

        Returns:
            PromptScanResult with blocked, score, rules_matched, etc.
        """
        start = time.perf_counter()

        # Enforce size limit
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

        # Normalize input
        normalized = self._normalizer.normalize(text)

        # Run rule engine on normalized text
        matches = self._engine.evaluate(normalized)

        # Decode encoded payloads and re-scan for deeper analysis
        decoded_texts = self._normalizer.decode_and_rescan(text)
        for decoded in decoded_texts:
            decoded_normalized = self._normalizer.normalize(decoded)
            decoded_matches = self._engine.evaluate(decoded_normalized)
            matches.extend(decoded_matches)

        # Score results
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
