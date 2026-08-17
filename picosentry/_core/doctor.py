"""Self-verify and self-repair module for PicoSentry.

Runs a battery of structural and consistency checks against the codebase
and optional auto-repairs for fixable drift.  Usable as:

    >>> from picosentry._core.doctor import verify, DoctorReport
    >>> report = verify()
    >>> report.summary()
    '3 pass, 1 fail, 0 warn'

Or from the CLI:

    picosentry doctor
    python -m picosentry._core.doctor
"""

from __future__ import annotations

import importlib
import json
import re
import shutil
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

_ROOT = Path(__file__).resolve().parent.parent.parent
_SRC = _ROOT / "picosentry"

CheckStatus = Literal["pass", "fail", "warn"]


@dataclass
class CheckResult:
    name: str
    status: CheckStatus
    detail: str
    repaired: bool = False
    repair_detail: str = ""


@dataclass
class DoctorReport:
    checks: list[CheckResult] = field(default_factory=list)
    elapsed: float = 0.0
    timestamp: str = ""

    def summary(self) -> str:
        passed = sum(1 for c in self.checks if c.status == "pass")
        failed = sum(1 for c in self.checks if c.status == "fail")
        warned = sum(1 for c in self.checks if c.status == "warn")
        return f"{passed} pass, {failed} fail, {warned} warn"

    def all_passed(self) -> bool:
        return all(c.status != "fail" for c in self.checks)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, default=str)

    @classmethod
    def from_json(cls, text: str) -> DoctorReport:
        data = json.loads(text)
        checks = [CheckResult(**c) for c in data.get("checks", [])]
        return cls(checks=checks, elapsed=data.get("elapsed", 0.0), timestamp=data.get("timestamp", ""))


def _check_rule_info_count() -> CheckResult:
    from picosentry.scan.rules import RULE_INFO, RULE_COUNT

    actual = len(RULE_INFO)
    if actual != RULE_COUNT:
        return CheckResult(
            "rule_info_count",
            "fail",
            f"RULE_COUNT={RULE_COUNT} but len(RULE_INFO)={actual}",
        )
    return CheckResult("rule_info_count", "pass", f"{actual} rules in RULE_INFO")


def _check_rule_aliases_consistency() -> CheckResult:
    from picosentry.scan.rules import RULE_INFO, RULE_ID_ALIASES

    all_ids = set(RULE_INFO.keys())
    orphans: list[str] = []
    for func_name, aliases in RULE_ID_ALIASES.items():
        for alias in aliases:
            if alias not in all_ids:
                orphans.append(f"{func_name}: {alias}")
    if orphans:
        return CheckResult(
            "rule_aliases_consistency",
            "fail",
            f"Aliased rule_ids not in RULE_INFO: {', '.join(orphans)}",
        )
    return CheckResult("rule_aliases_consistency", "pass", "All aliased rule_ids exist in RULE_INFO")


def _check_detector_implementations() -> CheckResult:
    from picosentry.scan.rules import DISPATCHED_RULE_IDS, RULE_INFO
    from picosentry.scan.engine import create_default_engine

    engine = create_default_engine()
    registered = set(engine.list_rules())
    rule_ids = set(RULE_INFO.keys())
    # A registered cross-ecosystem dispatcher (e.g. L2-TYPO-001) covers the
    # ecosystem-specific rule ids it emits at scan time (L2-CARGO-TYPO-001, ...).
    covered = set(registered)
    for dispatcher, dispatched in DISPATCHED_RULE_IDS.items():
        if dispatcher in registered:
            covered.update(dispatched)
    # L2-CAMP-* campaign detectors are a separate rule class registered on
    # top of the core RULE_INFO set (picosentry/scan/campaigns/_base.py
    # enforces the prefix), not part of the core rule count.
    campaign = {r for r in registered if r.startswith("L2-CAMP-")}
    missing = rule_ids - covered
    extra = registered - rule_ids - campaign
    parts: list[str] = []
    if missing:
        parts.append(f"Missing detectors: {', '.join(sorted(missing))}")
    if extra:
        parts.append(f"Extra detectors: {', '.join(sorted(extra))}")
    if parts:
        return CheckResult("detector_implementations", "fail", "; ".join(parts))
    detail = f"All {len(rule_ids)} rule_ids have detector implementations"
    if campaign:
        detail += f" (+{len(campaign)} L2-CAMP campaign detectors)"
    return CheckResult("detector_implementations", "pass", detail)


def _check_fixture_count() -> CheckResult:
    fixtures_dir = _ROOT / "tests" / "scan" / "fixtures" / "validation"
    if not fixtures_dir.exists():
        return CheckResult("fixture_count", "fail", f"Fixtures directory not found: {fixtures_dir}")
    subdirs = [d for d in fixtures_dir.iterdir() if d.is_dir()]
    total = len(subdirs)
    return CheckResult("fixture_count", "pass", f"{total} validation fixture directories")


def _check_corpus_files() -> CheckResult:
    corpus_dir = _SRC / "scan" / "corpus"
    if not corpus_dir.exists():
        return CheckResult("corpus_files", "fail", f"Corpus directory not found: {corpus_dir}")
    errors: list[str] = []
    count = 0
    for json_file in corpus_dir.rglob("*.json"):
        count += 1
        try:
            json.loads(json_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            errors.append(f"{json_file.relative_to(corpus_dir)}: {exc}")
    msg = f"{count} corpus JSON files"
    if errors:
        return CheckResult("corpus_files", "fail", f"{msg}; invalid: {', '.join(errors[:5])}")
    return CheckResult("corpus_files", "pass", f"{msg}, all valid JSON")


def _check_imports_healthy() -> CheckResult:
    packages = [
        "picosentry",
        "picosentry._core",
        "picosentry._core.config",
        "picosentry._core.models",
        "picosentry._core.guards",
        "picosentry._core.policy",
        "picosentry.scan",
        "picosentry.scan.rules",
        "picosentry.scan.engine",
        "picosentry.sandbox",
        "picosentry.watch",
    ]
    failed: list[str] = []
    for pkg in packages:
        try:
            importlib.import_module(pkg)
        except ImportError as exc:
            failed.append(f"{pkg}: {exc}")
    if failed:
        return CheckResult("imports_healthy", "fail", f"Import failures: {', '.join(failed)}")
    return CheckResult("imports_healthy", "pass", f"All {len(packages)} top-level packages importable")


def _check_picodome_not_tracked() -> CheckResult:
    picodome = _ROOT / ".picodome"
    if picodome.exists():
        from subprocess import run

        result = run(
            ["git", "ls-files", "--error-unmatch", ".picodome"],
            capture_output=True,
            cwd=str(_ROOT),
            check=False,
        )
        if result.returncode == 0:
            return CheckResult("picodome_not_tracked", "fail", ".picodome/ is tracked in git (security risk)")
    return CheckResult("picodome_not_tracked", "pass", ".picodome/ not tracked in git")


def _check_no_secrets_in_source() -> CheckResult:
    secret_patterns = [
        re.compile(r"(?i)(?:api_key|secret_key|private_key|access_token|auth_token)\s*=\s*['\"][^'\"]{8,}['\"]"),
        re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        re.compile(r"ghp_[0-9a-zA-Z]{36}"),
        re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    ]
    findings: list[str] = []
    skip_dirs = {".git", "__pycache__", ".picodome", "node_modules", ".venv", ".mypy_cache"}
    for py_file in _SRC.rglob("*.py"):
        if any(part in skip_dirs for part in py_file.parts):
            continue
        try:
            text = py_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pat in secret_patterns:
            for m in pat.finditer(text):
                findings.append(f"{py_file.relative_to(_ROOT)}:{m.start()}")
    if findings:
        return CheckResult("no_secrets_in_source", "fail", f"Potential secrets found: {', '.join(findings[:5])}")
    return CheckResult("no_secrets_in_source", "pass", "No secrets or credentials found in source")


def _check_experimental_claims() -> CheckResult:
    from picosentry.experimental import COMPONENT_STATUS
    from picosentry.scan.rules import RULE_INFO

    mismatches: list[str] = []
    actual_rule_count = len(RULE_INFO)
    for cs in COMPONENT_STATUS:
        notes = cs.notes
        m = re.search(r"(\d+)\s+rules", notes)
        if m:
            claimed = int(m.group(1))
            if claimed != actual_rule_count:
                mismatches.append(f"{cs.name}: claims {claimed} rules, actual {actual_rule_count}")
    if mismatches:
        return CheckResult("experimental_claims", "fail", f"Mismatched claims: {'; '.join(mismatches)}")
    return CheckResult("experimental_claims", "pass", f"All rule-count claims match actual ({actual_rule_count})")


def _check_version_consistency() -> CheckResult:
    top_version: str | None = None
    core_version: str | None = None
    pyproject_version: str | None = None

    top_init = _SRC / "__init__.py"
    if top_init.exists():
        m = re.search(r'__version__\s*=\s*["\']([^"\']+)', top_init.read_text())
        if m:
            top_version = m.group(1)

    core_init = _SRC / "_core" / "__init__.py"
    if core_init.exists():
        m = re.search(r'__version__\s*=\s*["\']([^"\']+)', core_init.read_text())
        if m:
            core_version = m.group(1)

    pyproject = _ROOT / "pyproject.toml"
    if pyproject.exists():
        m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject.read_text(), re.MULTILINE)
        if m:
            pyproject_version = m.group(1)

    versions = {
        "picosentry/__init__.py": top_version,
        "picosentry/_core/__init__.py": core_version,
        "pyproject.toml": pyproject_version,
    }
    non_none = {k: v for k, v in versions.items() if v is not None}
    unique = set(non_none.values())
    if len(unique) > 1:
        return CheckResult("version_consistency", "fail", f"Version mismatch: {non_none}")
    if not unique:
        return CheckResult("version_consistency", "warn", "No version strings found")
    return CheckResult("version_consistency", "pass", f"All versions match: {unique.pop()}")


def _repair_pycache() -> CheckResult:
    cleaned = 0
    for cache_dir in _ROOT.rglob("__pycache__"):
        if ".picodome" in cache_dir.parts or ".venv" in cache_dir.parts:
            continue
        try:
            shutil.rmtree(cache_dir)
            cleaned += 1
        except OSError:
            pass
    if cleaned:
        return CheckResult(
            "clean_pycache",
            "pass",
            f"Removed {cleaned} stale __pycache__ directories",
            repaired=True,
            repair_detail=f"Deleted {cleaned} directories",
        )
    return CheckResult("clean_pycache", "pass", "No stale __pycache__ directories found")


def verify(repair: bool = False) -> DoctorReport:
    """Run all self-verification checks and optionally auto-repair.

    Parameters
    ----------
    repair:
        If True, run repair actions (clean pycache, fix version drift, etc.)
        before verification checks.
    """
    start = time.monotonic()
    checks: list[CheckResult] = []

    if repair:
        checks.append(_repair_pycache())

    check_fns = [
        _check_rule_info_count,
        _check_rule_aliases_consistency,
        _check_detector_implementations,
        _check_fixture_count,
        _check_corpus_files,
        _check_imports_healthy,
        _check_picodome_not_tracked,
        _check_no_secrets_in_source,
        _check_experimental_claims,
        _check_version_consistency,
    ]
    for fn in check_fns:
        try:
            checks.append(fn())
        except Exception as exc:
            checks.append(CheckResult(fn.__name__.replace("_check_", ""), "fail", f"Exception: {exc}"))

    elapsed = time.monotonic() - start
    return DoctorReport(
        checks=checks,
        elapsed=round(elapsed, 3),
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for ``python -m picosentry._core.doctor``."""
    repair = "--repair" in (argv or sys.argv[1:])
    report = verify(repair=repair)

    icon = {"pass": "\u2713", "fail": "\u2717", "warn": "\u2605"}
    for check in report.checks:
        sym = icon.get(check.status, "?")
        line = f"  {sym} {check.status:4} {check.name:35} {check.detail}"
        if check.repaired:
            line += f"  [REPAIRED: {check.repair_detail}]"
        print(line)

    print("=" * 70)
    print(f"  {report.summary()}  ({report.elapsed:.1f}s)")

    if not report.all_passed():
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
