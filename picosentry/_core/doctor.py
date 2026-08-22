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
    """Fixture population: validation dirs (positive + negative) + tricky dirs.

    One definition, three surfaces that must agree: the on-disk fixture
    directories, the validation REPORT.json totals, and the fixture-count
    claims in picosentry.experimental.COMPONENT_STATUS.
    """
    from picosentry.experimental import COMPONENT_STATUS

    fixtures_dir = _ROOT / "tests" / "scan" / "fixtures" / "validation"
    if not fixtures_dir.exists():
        return CheckResult("fixture_count", "fail", f"Fixtures directory not found: {fixtures_dir}")
    problems: list[str] = []
    counts: dict[str, int] = {}
    for name in ("positive", "negative", "_tricky"):
        sub = fixtures_dir / name
        if not sub.is_dir():
            problems.append(f"missing fixture directory: {name}/")
            counts[name] = 0
        else:
            counts[name] = sum(1 for e in sub.iterdir() if e.is_dir())
    pos, neg, tricky = counts["positive"], counts["negative"], counts["_tricky"]
    total = pos + neg + tricky

    report_path = fixtures_dir / "REPORT.json"
    if not report_path.exists():
        problems.append("REPORT.json not found")
    else:
        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            problems.append(f"REPORT.json unparseable: {exc}")
            data = {}
        if data.get("total_fixtures") != pos + neg:
            problems.append(f"REPORT.json total_fixtures={data.get('total_fixtures')} != {pos}+{neg} fixture dirs")
        if data.get("total_positive") != pos:
            problems.append(f"REPORT.json total_positive={data.get('total_positive')} != {pos} positive dirs")
        if data.get("total_negative") != neg:
            problems.append(f"REPORT.json total_negative={data.get('total_negative')} != {neg} negative dirs")
        if len(data.get("fixture_results", [])) != data.get("total_fixtures"):
            problems.append("REPORT.json fixture_results length != total_fixtures")

    for cs in COMPONENT_STATUS:
        m = re.search(r"(\d+) fixtures \((\d+) pos / (\d+) neg", cs.notes)
        if m and (int(m.group(1)), int(m.group(2)), int(m.group(3))) != (total, pos, neg):
            problems.append(
                f"{cs.name}: claims {m.group(1)} fixtures ({m.group(2)} pos / {m.group(3)} neg), "
                f"actual {total} ({pos} pos / {neg} neg / {tricky} tricky)"
            )
        m = re.search(r"(\d+) rules, (\d+) fixtures", cs.notes)
        if m and int(m.group(2)) != total:
            problems.append(f"{cs.name}: claims {m.group(2)} fixtures, actual {total}")

    if problems:
        return CheckResult("fixture_count", "fail", "; ".join(problems))
    detail = f"{total} fixtures ({pos} pos / {neg} neg / {tricky} tricky); matches REPORT.json and claims"
    return CheckResult("fixture_count", "pass", detail)


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


def _check_watch_rules() -> CheckResult:
    """The watch rule corpora must load through the REAL loader with zero errors."""
    from picosentry.watch.config import DEFAULT_RULES_DIR
    from picosentry.watch.prompt_guard.rules import RuleEngine

    problems: list[str] = []
    loaded = 0
    for sub in ("prompt_injection", "output_policy"):
        engine = RuleEngine(rules_dir=DEFAULT_RULES_DIR / sub)
        loaded += engine.rules_loaded
        errors = engine.load_errors
        if errors:
            problems.append(f"{sub}: {errors[0]}" + (f" (+{len(errors) - 1} more)" if len(errors) > 1 else ""))
        if engine.rules_loaded == 0:
            problems.append(f"{sub}: no rules loaded")
    if problems:
        return CheckResult("watch_rules", "fail", "; ".join(problems))
    return CheckResult("watch_rules", "pass", f"{loaded} watch rules loaded cleanly (prompt_injection + output_policy)")


# Import names used to verify each runtime extra is actually installable in
# the current environment. Meta-extras (`all`, `dev`) only reference others.
_EXTRA_IMPORTS: dict[str, tuple[str, ...]] = {
    "scan": ("requests",),
    "watch-server": ("fastapi", "uvicorn"),
    "serve": (
        "fastapi",
        "uvicorn",
        "pydantic",
        "jwt",
        "cryptography",
        "bcrypt",
        "pyotp",
        "multipart",
        "croniter",
        "webauthn",
        "nacl",
    ),
    "otel": ("opentelemetry",),
    "sigstore": ("sigstore",),
    "grpc": ("grpc", "google.protobuf"),
}
_META_EXTRAS = {"all", "dev"}


def _declared_extras() -> set[str]:
    pyproject = _ROOT / "pyproject.toml"
    if not pyproject.exists():
        return set()
    text = pyproject.read_text(encoding="utf-8")
    section = re.search(r"^\[project\.optional-dependencies\](.*?)(?=^\[)", text, re.MULTILINE | re.DOTALL)
    if not section:
        return set()
    return set(re.findall(r"^([A-Za-z0-9_.-]+)\s*=\s*\[", section.group(1), re.MULTILINE))


def _check_optional_extras() -> CheckResult:
    """Declared extras must be mapped here and importable in this environment.

    Catches the silent-degrade class (e.g. pynacl missing makes Ed25519 plugin
    signature verification quietly skip) and pyproject/doctor drift on renames.
    """
    declared = _declared_extras() - _META_EXTRAS
    problems: list[str] = []
    for extra in sorted(declared):
        mods = _EXTRA_IMPORTS.get(extra)
        if mods is None:
            problems.append(f"{extra}: declared in pyproject but unmapped in doctor._EXTRA_IMPORTS")
            continue
        for mod in mods:
            try:
                importlib.import_module(mod)
            except ImportError as exc:
                problems.append(f"{extra}: '{mod}' not importable ({exc})")
    for extra in sorted(set(_EXTRA_IMPORTS) - declared):
        problems.append(f"{extra}: mapped in doctor._EXTRA_IMPORTS but not declared in pyproject")
    if problems:
        return CheckResult("optional_extras", "fail", "; ".join(problems))
    return CheckResult("optional_extras", "pass", f"all {len(declared)} runtime extras importable")


def _check_detection_metric_claims() -> CheckResult:
    """Precision/recall % claims must match REPORT.json's mean_* fields.

    The experimental honesty table, README, and manual all quote fixed
    precision/recall percentages; nothing pinned them to the validation
    report, so a scanner change with a forgotten regen shipped stale
    numbers (the WO5-028 recall move proved they drift). This check reads
    REPORT.json and asserts every documented percentage matches.
    """
    from picosentry.experimental import COMPONENT_STATUS

    report_path = _ROOT / "tests" / "scan" / "fixtures" / "validation" / "REPORT.json"
    if not report_path.exists():
        return CheckResult("detection_metric_claims", "fail", f"REPORT.json not found: {report_path}")
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return CheckResult("detection_metric_claims", "fail", f"REPORT.json unparseable: {exc}")
    mean_prec = data.get("mean_precision")
    mean_recall = data.get("mean_recall")
    if mean_prec is None or mean_recall is None:
        return CheckResult("detection_metric_claims", "fail", "REPORT.json missing mean_precision/mean_recall")

    # Build the (percentage_string, expected_value) pairs the surfaces claim.
    expected_prec_pct = f"{mean_prec * 100:.2f}%"
    expected_recall_pct = f"{mean_recall * 100:.2f}%"
    problems: list[str] = []

    # experimental.py COMPONENT_STATUS — the "Detection benchmarks" row.
    for cs in COMPONENT_STATUS:
        if "prec" not in cs.notes or "recall" not in cs.notes:
            continue
        m = re.search(r"(\d+\.\d+)%\s*prec,\s*(\d+\.\d+)%\s*recall", cs.notes)
        if not m:
            continue
        claim_prec, claim_recall = m.group(1) + "%", m.group(2) + "%"
        if claim_prec != expected_prec_pct:
            problems.append(f"{cs.name}: claims {claim_prec} prec, REPORT.json = {expected_prec_pct}")
        if claim_recall != expected_recall_pct:
            problems.append(f"{cs.name}: claims {claim_recall} recall, REPORT.json = {expected_recall_pct}")

    # README + manual quote the same numbers under "Mean precision/recall".
    for doc_path in (Path("README.md"), Path("docs") / "manual.md"):
        path = _ROOT / doc_path
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for label, expected in (("precision", expected_prec_pct), ("recall", expected_recall_pct)):
            for m in re.finditer(rf"Mean\s+{label}\s*\|\s*(\d+\.\d+)%", text):
                if m.group(1) + "%" != expected:
                    problems.append(f"{doc_path}: claims {m.group(1)}% mean {label}, REPORT.json = {expected}")

    if problems:
        return CheckResult("detection_metric_claims", "fail", "; ".join(problems))
    return CheckResult(
        "detection_metric_claims",
        "pass",
        f"prec {expected_prec_pct} / recall {expected_recall_pct} match REPORT.json",
    )


def _check_version_consistency() -> CheckResult:
    versions: dict[str, str | None] = {}

    _version_re = r'__version__\s*=\s*["\']([^"\']+)'
    for label, path, pattern in (
        ("picosentry/__init__.py", _SRC / "__init__.py", _version_re),
        ("picosentry/_core/__init__.py", _SRC / "_core" / "__init__.py", _version_re),
        ("picosentry/serve/config/version.py", _SRC / "serve" / "config" / "version.py", _version_re),
        ("pyproject.toml", _ROOT / "pyproject.toml", r'^version\s*=\s*"([^"]+)"'),
    ):
        if path.exists():
            m = re.search(pattern, path.read_text(), re.MULTILINE)
            if m:
                versions[label] = m.group(1)

    helm_chart = _ROOT / "deploy" / "helm" / "picodome" / "Chart.yaml"
    helm_version: str | None = None
    if helm_chart.exists():
        m = re.search(r'^appVersion:\s*"([^"]+)"', helm_chart.read_text(), re.MULTILINE)
        if m:
            helm_version = m.group(1)
            versions["deploy/helm/picodome/Chart.yaml appVersion"] = helm_version.removeprefix("v")

    k8s_deploy = _ROOT / "deploy" / "kubernetes" / "deployment.yaml"
    k8s_version: str | None = None
    if k8s_deploy.exists():
        m = re.search(r"^\s+version:\s*(v[0-9][^\s]+)", k8s_deploy.read_text(), re.MULTILINE)
        if m:
            k8s_version = m.group(1).strip().strip('"').strip("'")
            versions["deploy/kubernetes/deployment.yaml version"] = k8s_version.removeprefix("v")

    non_none = {k: v for k, v in versions.items() if v is not None}
    unique = set(non_none.values())
    problems: list[str] = []
    if len(unique) > 1:
        problems.append(f"Version mismatch: {non_none}")
    if not unique:
        return CheckResult("version_consistency", "warn", "No version strings found")
    if helm_version is not None and not helm_version.startswith("v"):
        problems.append(f"helm appVersion {helm_version!r} must be v-prefixed")
    if problems:
        return CheckResult("version_consistency", "fail", "; ".join(problems))
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
        _check_detection_metric_claims,
        _check_version_consistency,
        _check_watch_rules,
        _check_optional_extras,
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
