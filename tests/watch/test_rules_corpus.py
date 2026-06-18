"""PicoWatch rules corpus validation tests."""

import re
from pathlib import Path

import pytest
import yaml

from picosentry.watch.prompt_guard.rules import RuleEngine

RULES_DIR = Path(__file__).parent.parent.parent / "picosentry" / "watch" / "rules"


class TestRulesCorpus:
    """Validate all default rule YAML files."""

    def test_prompt_rules_load(self) -> None:
        """All prompt injection rules load without errors."""
        engine = RuleEngine(rules_dir=RULES_DIR / "prompt_injection")
        assert len(engine.rules) >= 20, f"Expected 20+ prompt rules, got {len(engine.rules)}"

    def test_output_rules_load(self) -> None:
        """All output policy rules load without errors."""
        engine = RuleEngine(rules_dir=RULES_DIR / "output_policy")
        assert len(engine.rules) >= 10, f"Expected 10+ output rules, got {len(engine.rules)}"

    def test_all_rules_have_valid_regex(self) -> None:
        """All rule patterns compile as valid regex."""
        all_rules_dirs = [
            RULES_DIR / "prompt_injection",
            RULES_DIR / "output_policy",
        ]
        for rules_dir in all_rules_dirs:
            if not rules_dir.exists():
                continue
            yaml_files = list(rules_dir.rglob("*.yaml")) + list(rules_dir.rglob("*.yml"))
            for yaml_file in yaml_files:
                data = yaml.safe_load(yaml_file.read_text())
                if data is None:
                    continue
                rule_dicts = data if isinstance(data, list) else [data]
                for rd in rule_dicts:
                    if not isinstance(rd, dict):
                        continue
                    try:
                        re.compile(rd["pattern"], re.IGNORECASE | re.DOTALL)
                    except re.error as e:
                        pytest.fail(f"Invalid regex in {rd['id']}: {e}")

    def test_all_rules_have_required_fields(self) -> None:
        """All rules have id, category, weight, pattern, description."""
        all_rules_dirs = [
            RULES_DIR / "prompt_injection",
            RULES_DIR / "output_policy",
        ]
        for rules_dir in all_rules_dirs:
            if not rules_dir.exists():
                continue
            yaml_files = list(rules_dir.rglob("*.yaml")) + list(rules_dir.rglob("*.yml"))
            for yaml_file in yaml_files:
                data = yaml.safe_load(yaml_file.read_text())
                if data is None:
                    continue
                rule_dicts = data if isinstance(data, list) else [data]
                for rd in rule_dicts:
                    if not isinstance(rd, dict):
                        continue
                    assert "id" in rd, f"Missing id in {yaml_file}"
                    assert "category" in rd, f"Missing category in {rd.get('id', 'unknown')}"
                    assert "weight" in rd, f"Missing weight in {rd.get('id', 'unknown')}"
                    assert "pattern" in rd, f"Missing pattern in {rd.get('id', 'unknown')}"
                    assert "description" in rd, f"Missing description in {rd.get('id', 'unknown')}"
                    assert 0.0 <= rd["weight"] <= 1.0, f"Weight out of range in {rd['id']}"

    def test_rule_ids_are_unique(self) -> None:
        """All rule IDs across all files are unique."""
        all_ids: list[str] = []
        all_rules_dirs = [
            RULES_DIR / "prompt_injection",
            RULES_DIR / "output_policy",
        ]
        for rules_dir in all_rules_dirs:
            if not rules_dir.exists():
                continue
            yaml_files = list(rules_dir.rglob("*.yaml")) + list(rules_dir.rglob("*.yml"))
            for yaml_file in yaml_files:
                data = yaml.safe_load(yaml_file.read_text())
                if data is None:
                    continue
                rule_dicts = data if isinstance(data, list) else [data]
                all_ids.extend(rd["id"] for rd in rule_dicts if isinstance(rd, dict))
        assert len(all_ids) == len(set(all_ids)), f"Duplicate rule IDs: {[x for x in all_ids if all_ids.count(x) > 1]}"

    def test_corpus_hash_reproducible(self) -> None:
        """Corpus hash is the same across loads."""
        engine1 = RuleEngine(rules_dir=RULES_DIR / "prompt_injection")
        engine2 = RuleEngine(rules_dir=RULES_DIR / "prompt_injection")
        assert engine1.corpus_hash == engine2.corpus_hash
