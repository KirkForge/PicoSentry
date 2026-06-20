from __future__ import annotations

import re

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from picosentry.watch.types import Rule


class Scorer:
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
    ) -> tuple[float, list[str]]:
        if not matches:
            return 0.0, []

        max_score = max(rule.weight for rule, _ in matches)

        total_weight = sum(rule.weight for rule, _ in matches)
        count = len(matches)
        avg_score = total_weight / count if count > 0 else 0.0

        final_score = round(max(max_score, avg_score), 6)

        matched_ids = sorted({rule.id for rule, _ in matches})

        return final_score, matched_ids
