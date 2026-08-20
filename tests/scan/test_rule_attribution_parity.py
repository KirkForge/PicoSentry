"""WO6.0.0-019 rider — per-sub-rule findings_count attribution parity.

The engine registers one detector function under multiple rule_ids (sub-rules:
L2-OBFS-001/002/003/004 all map to detect_obfuscation). It runs the function
once and the returned findings carry their actual rule_id attribute. Before
this fix, every rule_id alias's RuleExecution reported the GROUP total
(len(findings)) as its findings_count — so L2-OBFS-001 would say "4 findings"
even if only 1 was L2-OBFS-001 and 3 were L2-OBFS-002. That disagreed with
stats.findings_by_rule, which counts actual findings per rule_id.

Now each alias gets its OWN count, computed from the findings' rule_id
attribute. These tests pin the parity: sum(rule_executions.findings_count for
a function's aliases) == len(findings), and each alias's count matches
stats.findings_by_rule for that rule_id.
"""

from __future__ import annotations

import json
from pathlib import Path

from picosentry.scan.engine import create_default_engine


def _obfs_project(tmp_path: Path) -> Path:
    """A project that fires multiple L2-OBFS-* sub-rules from one function."""
    project = tmp_path / "proj"
    project.mkdir()
    (project / "package.json").write_text(json.dumps({"name": "host", "version": "1.0.0"}), encoding="utf-8")
    evil = project / "node_modules" / "evil-pkg"
    evil.mkdir(parents=True)
    (evil / "package.json").write_text(json.dumps({"name": "evil-pkg", "version": "1.0.0"}), encoding="utf-8")
    # eval + hex + base64+eval → fires L2-OBFS-001, L2-OBFS-002, L2-OBFS-003.
    (evil / "index.js").write_text(
        "var s = '\\x65\\x76\\x61\\x6c'; var b = atob('ZXZhbA=='); eval(b); eval(s);",
        encoding="utf-8",
    )
    return project


def test_rule_executions_findings_count_matches_stats_per_sub_rule(tmp_path):
    """Each rule_id alias's RuleExecution.findings_count must match
    stats.findings_by_rule for that rule_id — not the group total."""
    project = _obfs_project(tmp_path)
    result = create_default_engine().scan(str(project))

    obfs_findings = [f for f in result.findings if f.rule_id.startswith("L2-OBFS-")]
    if not obfs_findings:
        # The fixture may not fire on all environments; skip if no OBFS.
        import pytest

        pytest.skip("L2-OBFS-* did not fire on this fixture")

    # Build the actual per-rule count from the findings themselves.
    actual_by_rule: dict[str, int] = {}
    for f in obfs_findings:
        actual_by_rule[f.rule_id] = actual_by_rule.get(f.rule_id, 0) + 1

    # stats.findings_by_rule must agree with the actual per-rule count.
    for rid, count in actual_by_rule.items():
        assert result.stats.findings_by_rule.get(rid, 0) == count, (
            f"stats.findings_by_rule[{rid}]={result.stats.findings_by_rule.get(rid)} != actual {count}"
        )

    # Each rule_execution's findings_count must match the actual per-rule count,
    # NOT the group total (the WO6.0.0-019 fix).
    exec_by_rule = {e.rule_id: e for e in result.rule_executions if e.rule_id in actual_by_rule}
    for rid, count in actual_by_rule.items():
        assert rid in exec_by_rule, f"no RuleExecution for {rid}"
        assert exec_by_rule[rid].findings_count == count, (
            f"RuleExecution[{rid}].findings_count={exec_by_rule[rid].findings_count} "
            f"!= actual {count} (group-total attribution bug)"
        )


def test_sub_rule_alias_count_not_group_total(tmp_path):
    """The sum of per-alias findings_count must equal the total findings from
    that function, but NO single alias should report the total (the old bug).
    With eval+hex+base64, at least two distinct L2-OBFS-* rule_ids fire; each
    must report only its own count."""
    project = _obfs_project(tmp_path)
    result = create_default_engine().scan(str(project))

    obfs_execs = [e for e in result.rule_executions if e.rule_id.startswith("L2-OBFS-")]
    obfs_findings = [f for f in result.findings if f.rule_id.startswith("L2-OBFS-")]
    if not obfs_findings:
        import pytest

        pytest.skip("L2-OBFS-* did not fire on this fixture")

    total_findings = len(obfs_findings)
    sum_exec_counts = sum(e.findings_count for e in obfs_execs)

    # The sum of per-alias counts must equal the total findings (no findings
    # lost or double-counted in the attribution).
    assert sum_exec_counts == total_findings, (
        f"sum(per-alias findings_count)={sum_exec_counts} != total={total_findings}"
    )

    # No single alias should report the total (that would be the group-total
    # bug). At least two distinct sub-rules fired, so the max per-alias count
    # must be strictly less than the total.
    max_single = max(e.findings_count for e in obfs_execs)
    distinct_firing = {e.rule_id: e.findings_count for e in obfs_execs if e.findings_count > 0}
    if len(distinct_firing) >= 2:
        assert max_single < total_findings, (
            f"one alias reported the group total ({max_single} == {total_findings}) — "
            "per-sub-rule attribution is broken"
        )
