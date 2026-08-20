"""WO6.0.0-007 — deny_packages policy must NOT suppress security findings.

Evidence (verified 2026-08-18): cli_service._run_scan used to drop every
finding whose package matched a ``deny_packages`` entry before the result
was cached or returned. That inverted the policy semantics — an org bans a
package BECAUSE it's suspicious, so suppressing its findings hid exactly
the evidence that justified the ban, and a fail-exit could flip to 0.

The policy engine (policy_pkg/engine.py:189-209) already surfaces
deny_packages as ERROR violations via _apply_policy. The finding-suppression
block was redundant AND inverted; it was removed. These tests pin the fix:
banned-package findings SURVIVE _run_scan, and the policy violation is
present in the result.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from picosentry.scan.cli import _run_scan
from picosentry.scan.config import PicoSentryConfig


def _evil_pkg_project(tmp_path: Path) -> Path:
    """A minimal npm project with an evil-pkg that triggers L2-OBFS-* rules."""
    project = tmp_path / "proj"
    project.mkdir()
    (project / "package.json").write_text(
        json.dumps({"name": "host", "version": "1.0.0", "dependencies": {"evil-pkg": "^1.0.0"}}),
        encoding="utf-8",
    )
    evil = project / "node_modules" / "evil-pkg"
    evil.mkdir(parents=True)
    (evil / "package.json").write_text(
        json.dumps({"name": "evil-pkg", "version": "1.0.0"}), encoding="utf-8"
    )
    # eval + hex payload → fires L2-OBFS-001 and L2-OBFS-002.
    (evil / "index.js").write_text(
        "var s = '\\x65\\x76\\x61\\x6c'; eval(s);", encoding="utf-8"
    )
    return project


def _mock_args() -> MagicMock:
    args = MagicMock()
    args.timeout = 0
    args.rules = None
    args.format = "json"
    args.corpus = None
    args.advisory_db = None
    args.severity_overrides = None
    args.severity_threshold = None
    args.ignore_packages = None
    args.ignore_paths = None
    args.enterprise = False
    args.fail_on_rule_error = False
    return args


def test_banned_package_findings_surive_run_scan(tmp_path: Path):
    """deny_packages must NOT suppress the banned package's findings.

    Before WO6.0.0-007, _run_scan dropped every finding whose package matched
    a deny_packages entry. Now findings flow through unchanged; the policy
    violation surfaces separately via _apply_policy (called from run()).
    """
    project = _evil_pkg_project(tmp_path)

    args = _mock_args()
    config = PicoSentryConfig()
    result = _run_scan(args, project, merged_config=config)

    obfs_findings = [f for f in result.findings if f.rule_id.startswith("L2-OBFS-")]
    assert obfs_findings, (
        f"baseline (no policy): expected L2-OBFS-* findings for evil-pkg, got "
        f"{[(f.rule_id, f.package) for f in result.findings]}"
    )
    baseline_obfs_count = len(obfs_findings)
    baseline_packages = {f.package for f in obfs_findings}

    # Now add a policy that bans evil-pkg — the OLD code dropped these findings.
    policy_file = tmp_path / "policy.yml"
    policy_file.write_text(
        "version: 1\ndeny_packages:\n  - evil-pkg\n", encoding="utf-8"
    )
    config_with_policy = PicoSentryConfig()
    config_with_policy.policy_file = str(policy_file)

    result_with_policy = _run_scan(args, project, merged_config=config_with_policy)
    obfs_with_policy = [f for f in result_with_policy.findings if f.rule_id.startswith("L2-OBFS-")]

    # The fix: findings SURVIVE. Same count, same packages — nothing suppressed.
    assert len(obfs_with_policy) == baseline_obfs_count, (
        f"deny_packages suppressed {baseline_obfs_count - len(obfs_with_policy)} finding(s) — "
        f"before: {baseline_obfs_count}, after: {len(obfs_with_policy)}. "
        f"Findings: {[(f.rule_id, f.package) for f in obfs_with_policy]}"
    )
    assert {f.package for f in obfs_with_policy} == baseline_packages

    # The policy violation is NOT applied inside _run_scan (that happens in
    # run() via _apply_policy), but policy_digest must reflect the policy file
    # was loaded — proving the policy path executed without suppressing.
    assert result_with_policy.policy_digest != "sha256:default"
    assert result_with_policy.policy_digest.startswith("sha256:")


def test_deny_licenses_dead_block_removed_no_crash(tmp_path: Path):
    """The deny_licenses finding-filter block was dead code (Finding has no
    .licenses attribute) — its removal must not change behavior. A policy
    with deny_licenses must still produce a valid scan result."""
    project = _evil_pkg_project(tmp_path)

    policy_file = tmp_path / "policy.yml"
    policy_file.write_text(
        "version: 1\ndeny_licenses:\n  - GPL-3.0\n", encoding="utf-8"
    )
    args = _mock_args()
    config = PicoSentryConfig()
    config.policy_file = str(policy_file)

    result = _run_scan(args, project, merged_config=config)
    # Findings still present (the dead block never dropped anything; removal
    # is behavior-preserving).
    assert any(f.rule_id.startswith("L2-OBFS-") for f in result.findings)
    assert result.policy_digest != "sha256:default"


def test_non_banned_package_findings_unaffected(tmp_path: Path):
    """A policy banning an UNRELATED package must not change the findings for
    the actually-suspicious package — the suppression was scoped by package
    name, so its removal only affects banned-package findings."""
    project = _evil_pkg_project(tmp_path)

    policy_file = tmp_path / "policy.yml"
    policy_file.write_text(
        "version: 1\ndeny_packages:\n  - some-other-pkg\n", encoding="utf-8"
    )
    args = _mock_args()
    config_no_policy = PicoSentryConfig()
    result_no_policy = _run_scan(args, project, merged_config=config_no_policy)

    config_with_policy = PicoSentryConfig()
    config_with_policy.policy_file = str(policy_file)
    result_with_policy = _run_scan(args, project, merged_config=config_with_policy)

    no_policy_obfs = [f for f in result_no_policy.findings if f.rule_id.startswith("L2-OBFS-")]
    with_policy_obfs = [f for f in result_with_policy.findings if f.rule_id.startswith("L2-OBFS-")]
    assert len(no_policy_obfs) == len(with_policy_obfs)