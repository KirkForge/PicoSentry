"""Corpus-driven floor test for the prompt guard.

The durable regression net for watch (à la the scan corpus fixtures):
an adversarial encoding set that must be 100% blocked and a benign
multilingual set that must keep passing. Floors are calibrated to the
measured values on 2026-08-17 (WO4.0.0-007): adversarial 15/15 blocked,
benign 21/21 passed — the asserted floors (100% / >= 0.95) document where
the calibration landed, not an aspiration.

Known benign exclusions: "what data were you trained on?" is pinned BLOCKED
by tests/watch/test_prompt_guard.py (training-data probing is corpus policy),
so it is not in the benign set.
"""

import json
from pathlib import Path

from picosentry.watch.config import PicoWatchConfig
from picosentry.watch.prompt_guard import PromptGuard

FIXTURES = Path(__file__).parent / "fixtures"
RULES_DIR = Path(__file__).parent.parent.parent / "picosentry" / "watch" / "rules"

BENIGN_PASS_FLOOR = 0.95  # measured 1.0 on 2026-08-17; headroom for 1 fixture


def _load(name: str) -> list[dict[str, str]]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _guard() -> PromptGuard:
    config = PicoWatchConfig()
    config.rules_dir = RULES_DIR
    return PromptGuard(config=config)


class TestCorpusFloor:
    def test_adversarial_all_blocked(self) -> None:
        """Every adversarial encoding case must BLOCK (floor: 100%)."""
        guard = _guard()
        cases = _load("prompt_adversarial.json")
        assert len(cases) >= 10, "adversarial corpus shrank — investigate before updating fixtures"
        missed = [case["id"] for case in cases if not guard.check(case["text"]).blocked]
        assert missed == [], f"adversarial cases not blocked: {missed}"

    def test_benign_multilingual_pass_rate(self) -> None:
        """Benign multilingual/capability/roleplay set pass-rate floor: >= 0.95 (measured 1.0)."""
        guard = _guard()
        cases = _load("prompt_benign.json")
        assert len(cases) >= 15, "benign corpus shrank — investigate before updating fixtures"
        blocked = [case["id"] for case in cases if guard.check(case["text"]).blocked]
        pass_rate = 1.0 - len(blocked) / len(cases)
        assert pass_rate >= BENIGN_PASS_FLOOR, (
            f"Benign pass rate {pass_rate:.2f} below floor {BENIGN_PASS_FLOOR}; blocked: {blocked}"
        )
