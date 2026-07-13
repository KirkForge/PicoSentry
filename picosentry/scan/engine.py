from __future__ import annotations

import hashlib
import inspect
import json
import logging
import os
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .policy import Policy

from picosentry import __version__ as _VERSION
from ._engine_scan_helpers import _now_ms, count_installed_packages, count_relevant_files
from .models import Finding, RuleExecution, ScanResult, ScanStats


DEFAULT_RULE_TIMEOUT_SECONDS = 5.0

RULE_TIMEOUT_SECONDS = DEFAULT_RULE_TIMEOUT_SECONDS

logger = logging.getLogger("picosentry.engine")


class PolicyNotFoundError(Exception):
    """A configured policy file is missing or unreadable."""


class PolicyParseError(Exception):
    """A policy file is readable but syntactically/semantically invalid."""


class PolicyRuntimeError(Exception):
    """An unexpected internal error occurred while resolving a policy."""


def _resolve_effective_policy(policy_path: str | Path | None = None, config: Any = None) -> Policy | None:
    if policy_path is None and config is None:
        return None

    from picosentry.scan.policy import Policy
    from picosentry.scan.policy_lifecycle import InheritedPolicy, PolicyStack

    stack = PolicyStack()

    if policy_path:
        policy_file = Path(policy_path)
        if not policy_file.exists():
            raise PolicyNotFoundError(f"Policy file not found: {policy_path}")
        if not policy_file.is_file():
            raise PolicyNotFoundError(f"Policy path is not a file: {policy_path}")
        try:
            policy = Policy.from_file(policy_file)
        except (OSError, ValueError, KeyError) as exc:
            raise PolicyParseError(f"Could not parse policy file {policy_path}: {exc}") from exc
        stack.add(InheritedPolicy(policy=policy, layer="repo", source=str(policy_path)))

    if config and hasattr(config, "policy_file") and config.policy_file:
        cfg_policy_file = Path(config.policy_file)
        if not cfg_policy_file.exists():
            raise PolicyNotFoundError(f"Pipeline policy file not found: {config.policy_file}")
        if not cfg_policy_file.is_file():
            raise PolicyNotFoundError(f"Pipeline policy path is not a file: {config.policy_file}")
        try:
            p = Policy.from_file(cfg_policy_file)
        except (OSError, ValueError, KeyError) as exc:
            raise PolicyParseError(f"Could not parse pipeline policy file {config.policy_file}: {exc}") from exc
        stack.add(InheritedPolicy(policy=p, layer="pipeline", source=config.policy_file))

    if stack.layers():
        try:
            return stack.effective_policy()
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            raise PolicyRuntimeError(f"Could not compute effective policy: {exc}") from exc
    return None


def user_corpus_dir() -> Path:
    explicit = os.environ.get("PICOSENTRY_CORPUS_DIR") or os.environ.get("PICOCORPUS_DIR")
    if explicit:
        return Path(explicit)
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "picosentry" / "corpus"
    return Path.home() / ".local" / "share" / "picosentry" / "corpus"


DetectorRule = Callable[..., list[Finding]]


class ScanEngine:
    def __init__(
        self,
        corpus_dir: Path | None = None,
        advisory_db_path: str | Path | None = None,
        max_workers: int | None = None,
    ) -> None:
        self._rules: dict[str, DetectorRule] = {}
        self._corpus_dir = self._resolve_corpus_dir(corpus_dir)
        self._corpus_version = self._compute_corpus_version()
        self._advisory_db_path = str(advisory_db_path) if advisory_db_path is not None else None
        if max_workers is None:
            cpus = os.cpu_count() or 1
            max_workers = min(32, cpus * 2)
        self._max_workers = max(1, max_workers)

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

    def is_corpus_stale(self, max_age_days: int = 30) -> tuple[bool, list[str]]:
        """Return (is_stale, list of stale ecosystem names) based on corpus.json.

        If no corpus.json manifest exists, the corpus is considered stale so that
        CI surfaces a missing freshness record rather than silently accepting it.
        """
        manifest_path = self._corpus_dir / "corpus.json"
        stale: list[str] = []
        if not manifest_path.is_file():
            return True, stale
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return True, stale

        ecosystems = data.get("ecosystems", {})
        if not isinstance(ecosystems, dict):
            return True, stale

        now = datetime.now(timezone.utc)
        for ecosystem, entry in ecosystems.items():
            fetched_at = entry.get("fetched_at")
            if not isinstance(fetched_at, str):
                stale.append(ecosystem)
                continue
            try:
                fetched = datetime.fromisoformat(fetched_at)
                if fetched.tzinfo is None:
                    fetched = fetched.replace(tzinfo=timezone.utc)
            except ValueError:
                stale.append(ecosystem)
                continue
            if now - fetched > timedelta(days=max_age_days):
                stale.append(ecosystem)

        return bool(stale), stale

    def _warn_if_corpus_stale(self) -> None:
        is_stale, stale = self.is_corpus_stale()
        if not is_stale:
            return
        for ecosystem in stale:
            logger.warning(
                "Corpus '%s' is stale. Run 'picosentry update --ecosystem %s' to refresh it.",
                ecosystem,
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

        packages_scanned = count_installed_packages(target_path)

        fn_to_rule_ids: dict[int, list[str]] = {}
        for rule_id in selected_rules:
            fn_id = id(selected_rules[rule_id])
            fn_to_rule_ids.setdefault(fn_id, []).append(rule_id)

        from concurrent.futures import TimeoutError as FuturesTimeoutError

        def _invoke_rule(fn: Callable[..., list[Finding]]) -> list[Finding]:
            if fn.__name__ == "detect_all_advisory_vulnerabilities":
                return fn(target_path, self._corpus_dir, advisory_db_path=advisory_db_path or self._advisory_db_path)
            param_count = len(inspect.signature(fn).parameters)
            if param_count >= 2:
                return fn(target_path, self._corpus_dir)
            return fn(target_path)

        with ThreadPoolExecutor(
            max_workers=min(self._max_workers, len(selected_rules) or 1),
            thread_name_prefix="picosentry-rule",
        ) as rule_executor:
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
                except BaseException as exc:
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
        # Frozen dataclass findings must not be mutated in place.  Re-create
        # each finding with the target prefix stripped from the file path.
        stripped_findings: list[Finding] = []
        for f in all_findings:
            if f.file.startswith(target_prefix):
                stripped_findings.append(replace(f, file=f.file[len(target_prefix) :]))
            else:
                stripped_findings.append(f)
        all_findings = stripped_findings

        duration = _now_ms() - start_ms

        files_scanned = count_relevant_files(target_path)

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
    max_workers: int | None = None,
) -> ScanEngine:
    """Create a default scan engine with the bundled rule set."""
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

    engine = ScanEngine(
        corpus_dir=corpus_dir,
        advisory_db_path=advisory_db_path,
        max_workers=max_workers,
    )

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
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            logger.warning(
                "Failed to register campaign %s: %s",
                campaign.campaign_id,
                exc,
            )

    return engine
