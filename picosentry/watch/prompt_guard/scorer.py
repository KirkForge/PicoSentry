"""Scoring engine: weighted scoring for rule matches.

Final score = max(individual_rule_score, weighted_average).
Thresholds are configurable via Scorer.__init__ (defaults: block >= 0.7, warn >= 0.4).
"""

from __future__ import annotations

import re

from picosentry.watch.types import Rule


class Scorer:
    """Deterministic scoring engine.

    Same matches + same rules = same score. Always.

    Determinism guard (ADR-006): PicoWatch guarantees same input + same rules
    = same score. The Scorer uses no randomness, so no seed is needed. The
    module-level random.seed(0) from earlier versions has been removed — it was
    a global side effect that could interfere with callers' own random state.
    """

    def __init__(
        self,
        threshold_block: float = 0.7,
        threshold_warn: float = 0.4,
    ) -> None:
        self.threshold_block = threshold_block
        self.threshold_warn = threshold_warn

    def score(
        self,
        matches: list[tuple[Rule, re.Match[str]]],
        all_rules: list[Rule],
    ) -> tuple[float, list[str]]:
        """Score rule matches and return (score, matched_rule_ids).

        Uses two scoring methods and takes the maximum:
        1. Maximum individual rule weight (any single strong match)
        2. Weighted average of matched rules (multiple weak signals)

        This ensures both a single strong match and multiple weak matches
        can trigger a block.
        """
        if not matches:
            return 0.0, []

        # Method 1: max individual score
        max_score = max(rule.weight for rule, _ in matches)

        # Method 2: weighted average of matched rules
        total_weight = sum(rule.weight for rule, _ in matches)
        count = len(matches)
        avg_score = total_weight / count if count > 0 else 0.0

        # Take the maximum of both methods
        final_score = round(max(max_score, avg_score), 6)

        # Collect matched rule IDs in sorted order for determinism
        matched_ids = sorted({rule.id for rule, _ in matches})

        return final_score, matched_ids
