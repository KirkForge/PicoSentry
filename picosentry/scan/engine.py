from __future__ import annotations

import hashlib
import inspect
import json
import logging
import os
import threading
import time
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .policy import Policy

from .models import Finding, RuleExecution, ScanResult, ScanStats


DEFAULT_RULE_TIMEOUT_SECONDS = 5.0

RULE_TIMEOUT_SECONDS = DEFAULT_RULE_TIMEOUT_SECONDS


_RULE_POOL_SIZE = 64
_rule_executor: ThreadPoolExecutor | None = None
_rule_executor_lock = threading.Lock()


def _get_rule_executor() -> ThreadPoolExecutor:
    global _rule_executor
    if _rule_executor is None:
        with _rule_executor_lock:
            if _rule_executor is None:
                _rule_executor = ThreadPoolExecutor(max_workers=_RULE_POOL_SIZE, thread_name_prefix="picosentry-rule")
    return _rule_executor


def _resolve_effective_policy(policy_path: str | Path | None = None, config: Any = None) -> Policy | None:
    if policy_path is None and config is None:
        return None
    try:
        from picosentry.scan.policy import Policy
        from picosentry.scan.policy_lifecycle import InheritedPolicy, PolicyStack

        stack = PolicyStack()
        if policy_path and Path(policy_path).exists():
            policy = Policy.from_file(Path(policy_path))
            stack.add(InheritedPolicy(policy=policy, layer="repo", source=str(policy_path)))
        if config and hasattr(config, "policy_file") and config.policy_file:
            p = Policy.from_file(Path(config.policy_file))
            stack.add(InheritedPolicy(policy=p, layer="pipeline", source=config.policy_file))
        if stack.layers():
            return stack.effective_policy()
    except Exception as exc:
        logger.warning("Could not resolve effective policy: %s", exc)
    return None


logger = logging.getLogger("picosentry.engine")


def user_corpus_dir() -> Path:
    explicit = os.environ.get("PICOSENTRY_CORPUS_DIR") or os.environ.get("PICOCORPUS_DIR")
    if explicit:
        return Path(explicit)
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "picosentry" / "corpus"
    return Path.home() / ".local" / "share" / "picosentry" / "corpus"


def _get_version() -> str:
    # Prefer the in-tree source version: when running from a checkout (tests,
    # local dev, or an editable install) the source `__init__.py` is the
    # ground truth. Installed wheel metadata can lag behind during version-bump
    # commits, so falling back to it only after reading the source avoids
    # test failures like `test_engine_version_in_scan_result` when the editable
    # install has not been refreshed.
    import re

    init_path = Path(__file__).parent / "__init__.py"
    try:
        source = init_path.read_text(encoding="utf-8")
        match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', source)
        if match:
            return match.group(1)
    except OSError:
        pass

    try:
        from importlib.metadata import version

        return version("picosentry")
    except Exception:
        pass

    return "0.0.0"


_VERSION = _get_version()


DetectorRule = Callable[..., list[Finding]]


class ScanEngine:
    def __init__(
        self,
        corpus_dir: Path | None = None,
        advisory_db_path: str | Path | None = None,
    ) -> None:
        self._rules: dict[str, DetectorRule] = {}
        self._corpus_dir = self._resolve_corpus_dir(corpus_dir)
        self._corpus_version = self._compute_corpus_version()
        self._advisory_db_path = str(advisory_db_path) if advisory_db_path is not None else None

    @staticmethod
    def _resolve_corpus_dir(explicit: Path | None) -> Path:
        if explicit:
            return explicit
        user_dir = user_corpus_dir()

        for eco_file in (
            "npm_top_packages.json",
            "pypi_top_packages.json",
            "go_top_packages.json",
            "cargo_top_packages.json",
            "maven_top_packages.json",
            "rubygems_top_packages.json",
            "nuget_top_packages.json",
        ):
            if (user_dir / eco_file).is_file():
                logger.info("Using user corpus: %s", user_dir)
                return user_dir

        return Path(__file__).parent / "corpus"

    def _compute_corpus_version(self) -> str:
        h = hashlib.sha256()
        corpus_files = sorted(self._corpus_dir.rglob("*.json"))
        if not corpus_files:
            return "0.1.0-empty"
        for f in corpus_files:
            if f.is_symlink():
                logger.warning("Skipping symlink in corpus: %s — symlink corpus files are a security risk", f)
                continue  # Skip symlinks for security
            try:
                h.update(f.read_bytes())
            except OSError:
                continue

        # Include the corpus manifest so version changes when update metadata changes.
        self._warn_if_corpus_stale()
        return h.hexdigest()[:12]

    def _warn_if_corpus_stale(self) -> None:
        manifest_path = self._corpus_dir / "corpus.json"
        if not manifest_path.is_file():
            return
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return

        ecosystems = data.get("ecosystems", {})
        if not isinstance(ecosystems, dict):
            return

        now = datetime.now(timezone.utc)
        for ecosystem, entry in ecosystems.items():
            fetched_at = entry.get("fetched_at")
            if not isinstance(fetched_at, str):
                continue
            try:
                fetched = datetime.fromisoformat(fetched_at)
                if fetched.tzinfo is None:
                    fetched = fetched.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            if now - fetched > timedelta(days=30):
                logger.warning(
                    "Corpus '%s' was last fetched on %s. Run 'picosentry update --ecosystem %s' to refresh it.",
                    ecosystem,
                    fetched.date().isoformat(),
                    ecosystem,
                )

    def register(self, rule_id: str, rule: DetectorRule) -> ScanEngine:
        self._rules[rule_id] = rule
        return self

    def unregister(self, rule_id: str) -> None:
        self._rules.pop(rule_id, None)

    def list_rules(self) -> list[str]:
        return sorted(self._rules.keys())

    def scan(
        self,
        target: str | Path,
        rules: Sequence[str] | None = None,
        advisory_db_path: str | Path | None = None,
        rule_timeout: float | None = None,
    ) -> ScanResult:
        raw_target = Path(target)
        if raw_target.is_symlink():
            logger.error("Scan target is a symlink and will not be followed: %s", raw_target)
            return ScanResult(target=str(raw_target))

        try:
            target_path = raw_target.resolve()
        except (OSError, RuntimeError) as exc:
            logger.error("Scan target path resolution failed: %s", exc)
            return ScanResult(target=str(raw_target))

        if advisory_db_path is not None:
            advisory_db_path = str(advisory_db_path)
        if not target_path.exists():
            logger.error("Scan target does not exist: %s", target_path)
            return ScanResult(target=str(target_path))

        _effective_rule_timeout = DEFAULT_RULE_TIMEOUT_SECONDS if rule_timeout is None else float(rule_timeout)

        _detected_npm = (target_path / "package.json").is_file() or (target_path / "node_modules").is_dir()
        _detected_pypi = (
            (target_path / "pyproject.toml").is_file()
            or (target_path / "setup.py").is_file()
            or (target_path / "requirements.txt").is_file()
            or (target_path / ".venv").is_dir()
        )
        _detected_go = (target_path / "go.mod").is_file()
        _detected_cargo = (target_path / "Cargo.toml").is_file()
        _detected_maven = (target_path / "pom.xml").is_file() or (target_path / "build.gradle").is_file()
        _detected_rubygems = (target_path / "Gemfile").is_file() or (target_path / "Gemfile.lock").is_file()
        _detected_nuget = bool(list(target_path.glob("*.csproj"))) or (target_path / "packages.config").is_file()

        selected_rules = {k: v for k, v in self._rules.items() if k in rules} if rules else dict(self._rules)

        if not _detected_pypi:
            selected_rules = {k: v for k, v in selected_rules.items() if not k.startswith("L2-PYPI-")}
        if not _detected_go:
            selected_rules = {k: v for k, v in selected_rules.items() if not k.startswith("L2-GO-")}
        if not _detected_cargo:
            selected_rules = {k: v for k, v in selected_rules.items() if not k.startswith("L2-CARGO-")}
        if not _detected_maven:
            selected_rules = {k: v for k, v in selected_rules.items() if not k.startswith("L2-MAVEN-")}
        if not _detected_rubygems:
            selected_rules = {k: v for k, v in selected_rules.items() if not k.startswith("L2-RUBYGEMS-")}
        if not _detected_nuget:
            selected_rules = {k: v for k, v in selected_rules.items() if not k.startswith("L2-NUGET-")}

        if not selected_rules:
            logger.warning("No detector rules selected for scan")
            return ScanResult(target=str(target_path))

        logger.info(
            "Starting scan: target=%s rules=%s corpus=%s",
            target_path,
            list(selected_rules.keys()),
            self._corpus_dir,
        )

        from datetime import datetime, timezone

        wall_started = datetime.now(timezone.utc)
        start_ms = _now_ms()
        all_findings: list[Finding] = []
        rule_executions: list[RuleExecution] = []
        packages_scanned = 0
        rule_timings: dict[str, int] = {}

        nm_path = target_path / "node_modules"
        if nm_path.is_dir():
            packages_scanned = 0
            for d in nm_path.iterdir():
                if not d.is_dir() or d.name.startswith("."):
                    continue
                if d.name.startswith("@"):
                    packages_scanned += sum(1 for s in d.iterdir() if s.is_dir())
                else:
                    packages_scanned += 1

        if not packages_scanned:
            for sp_path in target_path.glob(".venv/lib/python*/site-packages"):
                if sp_path.is_dir():
                    packages_scanned = sum(
                        1 for d in sp_path.iterdir() if d.is_dir() and d.name.endswith((".dist-info", ".egg-info"))
                    )

        fn_to_rule_ids: dict[int, list[str]] = {}
        for rule_id in selected_rules:
            fn_id = id(selected_rules[rule_id])
            fn_to_rule_ids.setdefault(fn_id, []).append(rule_id)

        from concurrent.futures import TimeoutError as FuturesTimeoutError

        rule_executor = _get_rule_executor()

        def _invoke_rule(fn: Callable[..., list[Finding]]) -> list[Finding]:
            if fn.__name__ == "detect_all_advisory_vulnerabilities":
                return fn(target_path, self._corpus_dir, advisory_db_path=advisory_db_path or self._advisory_db_path)
            param_count = len(inspect.signature(fn).parameters)
            if param_count >= 2:
                return fn(target_path, self._corpus_dir)
            return fn(target_path)

        for fn_id in sorted(fn_to_rule_ids, key=lambda fid: fn_to_rule_ids[fid][0]):
            rule_fn = selected_rules[fn_to_rule_ids[fn_id][0]]
            rule_ids_for_fn = fn_to_rule_ids[fn_id]
            primary_rule_id = rule_ids_for_fn[0]
            rule_start = _now_ms()
            try:
                future = rule_executor.submit(_invoke_rule, rule_fn)
                try:
                    findings = future.result(timeout=_effective_rule_timeout)
                except FuturesTimeoutError:
                    elapsed = int(_now_ms() - rule_start)
                    logger.warning(
                        "Rule %s exceeded %ss timebox — skipping",
                        primary_rule_id,
                        _effective_rule_timeout,
                    )
                    for rid in rule_ids_for_fn:
                        rule_timings[rid] = elapsed
                        rule_executions.append(
                            RuleExecution(
                                rule_id=rid,
                                status="timeout",
                                duration_ms=elapsed,
                                findings_count=0,
                                error=f"exceeded {_effective_rule_timeout}s timebox",
                            )
                        )
                    continue
                all_findings.extend(findings)
                logger.debug("Rules %s: %d findings", rule_ids_for_fn, len(findings))
                elapsed = int(_now_ms() - rule_start)
                for rid in rule_ids_for_fn:
                    rule_timings[rid] = elapsed
                    rule_executions.append(
                        RuleExecution(
                            rule_id=rid,
                            status="ok",
                            duration_ms=elapsed,
                            findings_count=len(findings),
                        )
                    )
            except Exception as exc:
                logger.exception("Rule %s raised an exception", primary_rule_id)
                logger.debug("Rule %s traceback", primary_rule_id, exc_info=True)
                elapsed = int(_now_ms() - rule_start)
                for rid in rule_ids_for_fn:
                    rule_timings[rid] = elapsed
                    rule_executions.append(
                        RuleExecution(
                            rule_id=rid,
                            status="failed",
                            duration_ms=elapsed,
                            findings_count=0,
                            error=f"{type(exc).__name__}: {exc}",
                        )
                    )

        if rules is not None:
            selected_set = set(selected_rules.keys())
            all_findings = [f for f in all_findings if f.rule_id in selected_set]

        target_prefix = str(target_path)
        if not target_prefix.endswith("/") and not target_prefix.endswith("\\"):
            target_prefix += "/"
        for f in all_findings:
            if f.file.startswith(target_prefix):
                object.__setattr__(f, "file", f.file[len(target_prefix) :])

        duration = _now_ms() - start_ms

        _SKIP_DIRS = frozenset({".git", "__pycache__", ".cache", ".hg", ".svn", "node_modules/.cache"})
        _RELEVANT_EXTENSIONS = frozenset(
            {
                ".json",
                ".js",
                ".mjs",
                ".cjs",
                ".ts",
                ".tsx",
                ".jsx",
                ".yaml",
                ".yml",
                ".lock",
                ".npmrc",
                ".env",
                ".py",
                ".toml",
                ".cfg",
                ".ini",
                ".go",
                ".xml",
                ".gradle",
                ".rb",
                ".gemspec",
                ".csproj",
                ".sln",
            }
        )
        if target_path.is_dir():
            files_scanned = 0
            for file in target_path.rglob("*"):
                if not file.is_file() or file.is_symlink():
                    continue

                if any(part in _SKIP_DIRS for part in file.parts):
                    continue
                if file.suffix in _RELEVANT_EXTENSIONS or file.name in {
                    "package.json",
                    "package-lock.json",
                    "pnpm-lock.yaml",
                    "yarn.lock",
                    ".npmrc",
                    "pnpm-workspace.yaml",
                    "requirements.txt",
                    "pyproject.toml",
                    "setup.cfg",
                    "setup.py",
                    "poetry.lock",
                    "uv.lock",
                    "Pipfile",
                    "Pipfile.lock",
                    "METADATA",
                    "PKG-INFO",
                    "go.mod",
                    "go.sum",
                    "go.env",
                    "pom.xml",
                    "build.gradle",
                    "Gemfile",
                    "Gemfile.lock",
                    "packages.config",
                    "packages.lock.json",
                    "nuget.config",
                }:
                    files_scanned += 1
        else:
            files_scanned = 1

        by_severity: dict[str, int] = {}
        by_rule: dict[str, int] = {}
        for f in all_findings:
            sev = f.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1

        stats = ScanStats(
            packages_scanned=packages_scanned,
            files_scanned=files_scanned,
            duration_ms=int(duration),
            findings_by_severity=by_severity,
            findings_by_rule=by_rule,
            rule_timings_ms=rule_timings,
        )

        wall_completed = datetime.now(timezone.utc)
        result = ScanResult(
            target=str(target_path),
            engine_version=_VERSION,
            corpus_version=self._corpus_version,
            findings=all_findings,
            stats=stats,
            rule_executions=rule_executions,
            started_at=wall_started.isoformat(),
            completed_at=wall_completed.isoformat(),
            scanner_version=_VERSION,
        )

        logger.info(
            "Scan complete: %d findings in %dms",
            len(all_findings),
            int(duration),
        )

        try:
            from .metrics import increment, observe, set_gauge

            increment("scans.total")
            observe("scans.duration_ms", int(duration))
            increment("findings.total", len(all_findings))
            increment("packages.scanned", packages_scanned)
            for sev, count in by_severity.items():
                increment("findings.by_severity", count, {"severity": sev})
            for rule_id, count in by_rule.items():
                increment("scans.by_rule", count, {"rule_id": rule_id})
            set_gauge("scans.last_duration_ms", float(duration))
        except ImportError:
            pass

        return result


def create_default_engine(
    corpus_dir: Path | None = None,
    advisory_db_path: str | None = None,
) -> ScanEngine:
    from .rules.advisory_check import detect_all_advisory_vulnerabilities
    from .rules.bundled_shadow import detect_bundled_shadows
    from .rules.credential_read import detect_credential_reading
    from .rules.dangerous_build_hooks import detect_dangerous_build_hooks
    from .rules.dep_confusion import detect_all_dep_confusion
    from .rules.engine import detect_engine_issues
    from .rules.fork_drift import detect_fork_drift
    from .rules.ioc_detection import detect_custom_iocs
    from .rules.license import detect_license_issues
    from .rules.lockfile_drift import detect_lockfile_drift
    from .rules.maintainer_change import detect_maintainer_changes
    from .rules.manifest import detect_manifest_issues
    from .rules.network_exfil import detect_network_exfiltration
    from .rules.obfuscation import detect_obfuscation
    from .rules.pnpm_config import detect_pnpm_config
    from .rules.post_install import detect_post_install_scripts
    from .rules.provenance import detect_provenance_issues
    from .rules.pypi_obfuscation import detect_pypi_obfuscation
    from .rules.pypi_post_install import detect_pypi_post_install
    from .rules.sideloading import detect_sideloading
    from .rules.typosquat import detect_all_typosquat
    from .rules.worm_propagation import detect_worm_propagation

    engine = ScanEngine(corpus_dir=corpus_dir, advisory_db_path=advisory_db_path)

    engine.register("L2-DEPC-001", detect_all_dep_confusion)
    engine.register("L2-TYPO-001", detect_all_typosquat)
    engine.register("L2-ADV-001", detect_all_advisory_vulnerabilities)

    engine.register("L2-POST-001", detect_post_install_scripts)
    engine.register("L2-OBFS-001", detect_obfuscation)
    engine.register("L2-OBFS-002", detect_obfuscation)  # sub-rule: hex obfuscation
    engine.register("L2-OBFS-003", detect_obfuscation)  # sub-rule: base64+eval
    engine.register("L2-OBFS-004", detect_obfuscation)  # sub-rule: unicode escapes
    engine.register("L2-MANI-001", detect_manifest_issues)
    engine.register("L2-MANI-002", detect_manifest_issues)  # sub-rule: optional deps w/ scripts
    engine.register("L2-FORK-001", detect_fork_drift)
    engine.register("L2-CRED-001", detect_credential_reading)
    engine.register("L2-LOCK-001", detect_lockfile_drift)
    engine.register("L2-BUND-001", detect_bundled_shadows)
    engine.register("L2-BUILD-001", detect_dangerous_build_hooks)
    engine.register("L2-PROV-001", detect_provenance_issues)
    engine.register("L2-MAINT-001", detect_maintainer_changes)
    engine.register("L2-PNPM-001", detect_pnpm_config)
    engine.register("L2-LICENSE-001", detect_license_issues)
    engine.register("L2-ENGIN-001", detect_engine_issues)
    engine.register("L2-SIDELOAD-001", detect_sideloading)
    engine.register("L2-IOC-001", detect_custom_iocs)
    engine.register("L2-WORM-001", detect_worm_propagation)
    engine.register("L2-NETEX-001", detect_network_exfiltration)

    engine.register("L2-PYPI-POST-001", detect_pypi_post_install)
    engine.register("L2-PYPI-OBFS-001", detect_pypi_obfuscation)
    engine.register("L2-PYPI-OBFS-002", detect_pypi_obfuscation)
    engine.register("L2-PYPI-OBFS-003", detect_pypi_obfuscation)
    engine.register("L2-PYPI-OBFS-004", detect_pypi_obfuscation)
    engine.register("L2-PYPI-OBFS-005", detect_pypi_obfuscation)
    engine.register("L2-PYPI-OBFS-006", detect_pypi_obfuscation)
    engine.register("L2-PYPI-OBFS-007", detect_pypi_obfuscation)

    from .campaigns import iter_campaigns

    for campaign in iter_campaigns():
        try:
            campaign.register(engine)
        except Exception as exc:
            logger.warning(
                "Failed to register campaign %s: %s",
                campaign.campaign_id,
                exc,
            )

    return engine


def _now_ms() -> float:
    return time.monotonic() * 1000
