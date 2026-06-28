"""Duplicate rule ids must not silently cross-wire compiled patterns.

`_compiled` is keyed by rule.id, so before the dedup fix two rules sharing an
id left both entries in `self._rules` but only one compiled pattern — the
second rule would evaluate with the first's regex (or vice versa).
"""

from __future__ import annotations

from pathlib import Path

from picosentry.watch.prompt_guard.rules import RuleEngine

TWO_WITH_SAME_ID = """\
- id: DUP-1
  category: prompt_injection
  pattern: "alpha"
- id: DUP-1
  category: prompt_injection
  pattern: "omega"
- id: UNIQUE-1
  category: prompt_injection
  pattern: "solo"
"""


def test_duplicate_id_is_dropped(tmp_path: Path) -> None:
    (tmp_path / "rules.yaml").write_text(TWO_WITH_SAME_ID)
    engine = RuleEngine(rules_dir=tmp_path)

    ids = [r.id for r in engine.rules]
    assert ids.count("DUP-1") == 1, f"duplicate id not deduped: {ids}"
    assert "UNIQUE-1" in ids
    # The surviving DUP-1 keeps the FIRST pattern ("alpha"), and the loader
    # recorded the collision instead of swallowing it.
    survivor = next(r for r in engine.rules if r.id == "DUP-1")
    assert survivor.pattern == "alpha"
    assert any("Duplicate rule id" in e for e in engine.load_errors)
    # The compiled table matches "alpha", not the overwriting "omega".
    matched = [r.id for r, _ in engine.evaluate("alpha")]
    assert "DUP-1" in matched
    assert [r.id for r, _ in engine.evaluate("omega")] == []
