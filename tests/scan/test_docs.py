"""Tests for rule documentation completeness."""

import os
from pathlib import Path

from picosentry.scan.rules import RULE_COUNT, RULE_INFO

RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "picosentry",
    "scan",
    "docs",
    "rules",
)


class TestRuleDocs:
    """Verify every rule has documentation and documentation has a rule."""

    def test_all_rules_have_docs(self):
        """Every rule in RULE_INFO should have a corresponding .md file."""
        for rule_id, info in RULE_INFO.items():
            doc_path = os.path.join(RULES_DIR, f"{rule_id}.md")
            assert os.path.exists(doc_path), f"Rule {rule_id} ({info['name']}) has no documentation at {doc_path}"

    def test_all_docs_have_rules(self):
        """Every .md file in docs/rules/ should correspond to a RULE_INFO entry."""
        md_files = [f for f in os.listdir(RULES_DIR) if f.endswith(".md") and f != "README.md"]
        for md_file in sorted(md_files):
            rule_id = md_file.replace(".md", "")
            if rule_id.startswith("L2-"):
                assert rule_id in RULE_INFO, f"Doc file {md_file} has no corresponding RULE_INFO entry"

    def test_rule_count_matches(self):
        """RULE_COUNT should match the number of RULE_INFO entries."""
        assert len(RULE_INFO) == RULE_COUNT, f"RULE_COUNT={RULE_COUNT} but RULE_INFO has {len(RULE_INFO)} entries"

    def test_docs_index_exists(self):
        """There should be a README.md index in docs/rules/."""
        index_path = os.path.join(RULES_DIR, "README.md")
        assert os.path.exists(index_path), "docs/rules/README.md index not found"

    def test_docs_not_empty(self):
        """Each rule doc should have substantive content (>200 chars)."""
        for rule_id in RULE_INFO:
            doc_path = os.path.join(RULES_DIR, f"{rule_id}.md")
            if os.path.exists(doc_path):
                with Path(doc_path).open() as f:
                    content = f.read()
                assert len(content) > 200, f"Rule {rule_id} doc is too short ({len(content)} chars)"
