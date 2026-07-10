"""Scan orchestration service used by the CLI.

This module holds the non-argument-parsing logic that was previously inlined
in ``picosentry/scan/cli_commands/scan.py``: path validation, cache handling,
scan execution, baseline/policy application, formatting, and exit-code
calculation.  Keeping it separate makes the CLI command file a thin dispatcher
and makes the orchestration testable without argparse.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import multiprocessing
import os
import sys
import tempfile
import traceback
from pathlib import Path
from typing import TYPE_CHECKING, Any

from picosentry.scan import __version__
from picosentry.scan.config import PicoSentryConfig, load_config
from picosentry.scan.engine import (
    PolicyNotFoundError,
    PolicyParseError,
    PolicyRuntimeError,
    _resolve_effective_policy,
    create_default_engine,
)
from picosentry.scan.formatters import (
    format_cyclonedx,
    format_json,
    format_ml_context,
    format_sarif,
    format_table,
)
from picosentry.scan.formatters.table import _PINCH_LABELS
from picosentry.scan.guards import verify_determinism
from picosentry.scan.models import Finding, ScanResult, ScanStats, Severity, apply_baseline, load_baseline
from picosentry.scan.validation import run_validation

if TYPE_CHECKING:
    import argparse

logger = logging.getLogger(__name__)


class ScanTimeout(Exception):
    """Raised when a scan exceeds its ``--timeout`` budget."""


class ScanError(Exception):
    """Raised when the scan worker process reports an error."""

    def __init__(self, message: str, exc_type: str | None = None, exc_traceback: str | None = None) -> None:
        super().__init__(message)
        self.exc_type = exc_type
        self.exc_traceback = exc_traceback


def _workspace_root() -> Path:
    """Return the workspace root for validating external file paths.

    Defaults to the current working directory so relative paths behave as users
    expect. Override with ``PICOSENTRY_SCANS_WORKSPACE_ROOT`` for CI/monorepo
    layouts where inputs and outputs live outside the project directory.
    """
    env_root = os.environ.get("PICOSENTRY_SCANS_WORKSPACE_ROOT")
    if env_root:
        return Path(env_root).resolve()
    return Path.cwd()


def _secure_realpath(path_str: str, description: str = "path") -> Path:
    """Return the canonical path of an existing file/directory without following
    symlinks, using an open file descriptor.

    This narrows the TOCTOU window between ``resolve()`` and the eventual open:
    the returned path is read from ``/proc/self/fd/<n>`` for the descriptor we
    actually opened.  If ``path_str`` is a symlink the open fails with
    ``O_NOFOLLOW``.
    """
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(path_str, flags)
    except IsADirectoryError:
        fd = os.open(path_str, flags | os.O_DIRECTORY)
    except OSError as exc:
        raise ValueError(f"{description}: cannot open {path_str}: {exc}") from exc

    try:
        proc_path = f"/proc/self/fd/{fd}"
        real = Path(os.path.realpath(proc_path))
        return real
    finally:
        with contextlib.suppress(OSError):
            os.close(fd)


def _resolve_external_path(
    path_str: str,
    workspace_root: Path,
    *,
    must_exist: bool = False,
    description: str = "path",
) -> Path:
    """Resolve a CLI path argument and reject traversal/symlink surprises.

    Relative paths are resolved against the current working directory, matching
    the behavior of the underlying filesystem calls.  Absolute paths must still
    lie inside the workspace root.  Symlinks are rejected to avoid ambiguous
    resolution.
    """
    if not isinstance(path_str, str) or not path_str:
        raise ValueError(f"{description} must be a non-empty string")
    if path_str.startswith(("http://", "https://")):
        raise ValueError(f"{description} cannot be a remote URL: {path_str}")

    candidate = Path(path_str)

    if candidate.is_symlink():
        raise ValueError(f"{description} cannot be a symlink: {path_str}")

    resolved = candidate.resolve(strict=False)
    if not resolved.is_relative_to(workspace_root):
        raise ValueError(f"{description} must be inside the workspace root ({workspace_root}): {path_str}")

    if must_exist:
        if not resolved.exists():
            raise ValueError(f"{description} does not exist: {resolved}")
        # Re-open the path to obtain the canonical location of the inode we
        # will actually use, closing the symlink/traversal TOCTOU window.
        resolved = _secure_realpath(str(resolved), description=description)
        if not resolved.is_relative_to(workspace_root):
            raise ValueError(f"{description} resolves outside the workspace root ({workspace_root}): {path_str}")

    return resolved


def _format_summary(result: ScanResult) -> str:
    if not result.findings:
        return "PicoSentry: No pinches. All clear. 🦞"

    parts = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        count = result.stats.findings_by_severity.get(sev.value, 0)
        if count > 0:
            pinch = _PINCH_LABELS.get(sev, sev.value)
            parts.append(f"{count} {pinch}")

    return f"PicoSentry: {', '.join(parts)}"


def _format_quiet(result: ScanResult) -> str:
    if not result.findings:
        return "🦞 No pinches. All clear."

    lines = []
    lines.append(f"🦞 PicoSentry: {len(result.findings)} finding(s)")
    lines.append(f"  Target: {result.target}")
    lines.append(f"  Engine: v{result.engine_version} | Corpus: v{result.corpus_version}")
    lines.append(f"  Duration: {result.stats.duration_ms}ms")
    lines.append("")

    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        count = result.stats.findings_by_severity.get(sev.value, 0)
        if count > 0:
            pinch = _PINCH_LABELS.get(sev, sev.value)
            lines.append(f"  {pinch}: {count}")

    lines.append("")
    for rule_id in sorted(result.stats.findings_by_rule):
        count = result.stats.findings_by_rule[rule_id]
        lines.append(f"  {rule_id}: {count}")

    return "\n".join(lines)


def _scan_worker(
    target_path: str,
    rules: list[str] | None,
    corpus_dir: str | None,
    advisory_db_path: str | None,
    result_queue: multiprocessing.Queue,
) -> None:
    try:
        from pathlib import Path

        from picosentry.scan.engine import create_default_engine

        eng = create_default_engine(
            corpus_dir=Path(corpus_dir) if corpus_dir else None,
            advisory_db_path=advisory_db_path,
        )
        r = eng.scan(target_path, rules=rules, advisory_db_path=advisory_db_path)
        result_queue.put(("ok", r))
    except (OSError, RuntimeError, ValueError, TypeError, ImportError, TimeoutError) as e:
        result_queue.put(
            (
                "error",
                {
                    "type": type(e).__name__,
                    "message": str(e),
                    "traceback": traceback.format_exc(),
                },
            )
        )


class ScanOrchestrator:
    """High-level scan orchestration used by ``picosentry scan``."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.workspace_root = _workspace_root()
        # Import the scan command module here (not at module top) to avoid a
        # circular import, and capture its worker reference so tests that patch
        # ``picosentry.scan.cli_commands.scan._scan_worker`` are honoured.
        from picosentry.scan.cli_commands import scan as scan_command_mod

        self._scan_worker = scan_command_mod._scan_worker

    def _resolve_paths(self, config: PicoSentryConfig) -> None:
        """Validate external file paths referenced by the merged config."""
        if config.corpus:
            config.corpus = str(
                _resolve_external_path(config.corpus, self.workspace_root, must_exist=True, description="--corpus")
            )
        if config.advisory_db:
            config.advisory_db = str(
                _resolve_external_path(
                    config.advisory_db, self.workspace_root, must_exist=True, description="--advisory-db"
                )
            )
        if config.baseline:
            config.baseline = str(
                _resolve_external_path(config.baseline, self.workspace_root, must_exist=True, description="--baseline")
            )
        if config.sarif_file:
            config.sarif_file = str(
                _resolve_external_path(config.sarif_file, self.workspace_root, description="--sarif-file")
            )
        if config.output:
            config.output = str(_resolve_external_path(config.output, self.workspace_root, description="--output"))

    def _load_cache(self, target: Path, config: PicoSentryConfig) -> tuple[ScanResult | None, Any, str]:
        """Attempt to load a cached result.

        Returns ``(cached_result, cache, lockfile_hash)``.  ``cache`` is the
        cache store instance (or ``None`` if caching is disabled or failed).
        """
        if getattr(self.args, "verify_determinism", False) or getattr(self.args, "no_cache", False):
            return None, None, ""
        try:
            from picosentry.scan.cache import ScanCache

            cache = ScanCache.from_config(config)
            lockfile_hash = ""
            for lockfile_name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"):
                lf = target / lockfile_name
                if lf.is_file():
                    lockfile_hash = hashlib.sha256(lf.read_bytes()).hexdigest()[:16]
                    break
            if not lockfile_hash:
                return None, cache, ""

            corpus_dir = Path(config.corpus) if config.corpus else None
            temp_engine = create_default_engine(corpus_dir=corpus_dir, advisory_db_path=config.advisory_db)
            corpus_hash = temp_engine._corpus_version
            cached_data = cache.get(lockfile_hash, corpus_hash, __version__)
            if cached_data and "scan_id" in cached_data:
                cached_result = self._scan_result_from_cache(cached_data, target)
                if cached_result:
                    logger.info("Cache hit: lockfile=%s corpus=%s", lockfile_hash[:8], corpus_hash[:8])
                    try:
                        from picosentry.scan.metrics import increment

                        increment("cache.hits")
                    except ImportError:
                        pass
                    return cached_result, cache, lockfile_hash
            return None, cache, lockfile_hash
        except Exception as exc:
            logger.warning("Cache read failed for %s, disabling cache: %s", target, exc)
            return None, None, ""

    @staticmethod
    def _scan_result_from_cache(cached_data: dict, target: Path) -> ScanResult | None:
        if hasattr(ScanResult, "from_dict"):
            return ScanResult.from_dict(cached_data)

        try:
            stats_data = cached_data.get("stats", {})
            return ScanResult(
                target=cached_data.get("target", str(target)),
                engine_version=cached_data.get("engine_version", __version__),
                corpus_version=cached_data.get("corpus_version", ""),
                findings=[Finding(**f) for f in cached_data.get("findings", [])] if "findings" in cached_data else [],
                stats=ScanStats(**stats_data) if stats_data else ScanStats(),
            )
        except Exception as exc:
            logger.warning("Cache entry for %s is corrupted, ignoring: %s", target, exc)
            return None

    def _save_cache(self, cache: Any, lockfile_hash: str, result: ScanResult, config: PicoSentryConfig) -> None:
        if not cache or not lockfile_hash:
            return
        try:
            corpus_dir = Path(config.corpus) if config.corpus else None
            te = create_default_engine(corpus_dir=corpus_dir, advisory_db_path=config.advisory_db)
            corpus_hash = te._corpus_version
            cache.put(lockfile_hash, corpus_hash, __version__, result.to_dict())
            logger.info("Cached scan result: lockfile=%s", lockfile_hash[:8])
            try:
                from picosentry.scan.metrics import increment

                increment("cache.misses")
            except ImportError:
                pass
        except Exception as exc:
            logger.warning("Cache write failed for %s: %s", result.target, exc)

    def _run_scan(
        self,
        target: Path,
        file_config: PicoSentryConfig | None = None,
        merged_config: PicoSentryConfig | None = None,
    ) -> ScanResult:
        if merged_config is not None:
            config = merged_config
        else:
            if file_config is None:
                file_config = load_config(target)
            config = file_config.merge_cli(self.args)

        corpus_dir = Path(config.corpus) if config.corpus else None
        engine = create_default_engine(corpus_dir=corpus_dir, advisory_db_path=config.advisory_db)

        if self.args.timeout and self.args.timeout > 0:
            result_queue: multiprocessing.Queue = multiprocessing.Queue()

            worker = multiprocessing.Process(
                target=self._scan_worker,
                args=(target, config.rules, str(corpus_dir) if corpus_dir else None, config.advisory_db, result_queue),
            )
            worker.start()
            worker.join(timeout=self.args.timeout)

            if worker.is_alive():
                worker.terminate()
                worker.join(timeout=1)
                raise ScanTimeout

            try:
                status, data = result_queue.get(timeout=1)
            except (OSError, ValueError, TypeError) as e:
                raise ScanError("failed to retrieve scan result from worker") from e
            if status == "error":
                if isinstance(data, dict):
                    raise ScanError(
                        data.get("message", "worker error"),
                        exc_type=data.get("type"),
                        exc_traceback=data.get("traceback"),
                    )
                raise ScanError(str(data))
            result = data
        else:
            result = engine.scan(target, rules=config.rules, advisory_db_path=config.advisory_db)

        try:
            effective_policy = _resolve_effective_policy(config=config)
        except (PolicyNotFoundError, PolicyParseError, PolicyRuntimeError) as exc:
            raise ScanError(f"policy error: {exc}") from exc
        if effective_policy is not None:
            if hasattr(effective_policy, "deny_packages") and effective_policy.deny_packages:
                denied_set = set(effective_policy.deny_packages)
                result.apply_overrides([f for f in result.findings if f.package not in denied_set])

            if hasattr(effective_policy, "deny_licenses") and effective_policy.deny_licenses:
                denied_licenses = set(effective_policy.deny_licenses)
                result.apply_overrides(
                    [
                        f
                        for f in result.findings
                        if not any(lic in denied_licenses for lic in getattr(f, "licenses", []))
                    ]
                )

        if config.severity_overrides:
            result.apply_overrides(config.apply_severity_overrides(result.findings))

        if config.ignore_packages or config.ignore_paths:
            result.apply_overrides(
                [
                    f
                    for f in result.findings
                    if not config.should_ignore_package(f.package) and not config.should_ignore_path(f.file)
                ]
            )

        from picosentry.scan.models import SEVERITY_ORDER

        if config.severity_threshold:
            threshold = config.severity_threshold
            min_level = SEVERITY_ORDER.get(threshold.lower(), 0)
            result.apply_overrides(
                [f for f in result.findings if SEVERITY_ORDER.get(f.severity.value.lower(), 4) <= min_level]
            )

        config_str = json.dumps(
            {k: v for k, v in sorted(config.__dict__.items()) if v is not None and v not in ([], {}, "")},
            sort_keys=True,
        )
        result.config_digest = "sha256:" + hashlib.sha256(config_str.encode()).hexdigest()[:32]
        if (
            hasattr(result, "policy_result")
            and result.policy_result is not None
            and hasattr(result.policy_result, "to_dict")
        ):
            policy_str = json.dumps(result.policy_result.to_dict(), sort_keys=True)
            result.policy_digest = "sha256:" + hashlib.sha256(policy_str.encode()).hexdigest()[:32]
        elif hasattr(config, "policy_file") and config.policy_file:
            from pathlib import Path as _Path

            pf = _Path(config.policy_file)
            if pf.is_file():
                result.policy_digest = "sha256:" + hashlib.sha256(pf.read_bytes()).hexdigest()[:32]
        else:
            result.policy_digest = "sha256:default"
        result.scanner_version = __version__

        return result

    def _apply_policy(self, result: ScanResult, config: PicoSentryConfig) -> None:
        policy_file = getattr(self.args, "policy", None) or getattr(config, "policy_file", None)
        if not policy_file:
            return

        from picosentry.scan.policy import Policy
        from picosentry.scan.rules.utils import iter_node_modules, load_package_json

        policy_path = Path(policy_file)
        if not policy_path.is_file():
            raise PolicyNotFoundError(f"Policy file not found: {policy_file}")

        policy = Policy.from_file(policy_path)

        pkg_licenses: dict[str, str] = {}
        installed_pkgs: set[str] = set()
        root_pkg = Path(result.target) / "package.json"
        if root_pkg.is_file():
            root_data = load_package_json(root_pkg)
            root_name = root_data.get("name", "")
            if root_name:
                installed_pkgs.add(root_name)
        for pkg_json_path, pkg_data in iter_node_modules(Path(result.target)):
            pkg_name = pkg_data.get("name", pkg_json_path.parent.name)
            if (
                not pkg_name.startswith("@")
                and pkg_json_path.parent.name
                and pkg_json_path.parent.parent.name.startswith("@")
            ):
                pkg_name = f"{pkg_json_path.parent.parent.name}/{pkg_name}"
            installed_pkgs.add(pkg_name)

        for f in result.findings:
            if f.rule_id == "L2-LICENSE-001" and "license =" in f.evidence:
                lic_extract = f.evidence.split("license = ")[-1].strip("'\"")
                pkg_licenses[f.package] = lic_extract

        policy_result = policy.apply(
            result, Path(result.target), package_licenses=pkg_licenses, installed_packages=installed_pkgs
        )
        result.policy_result = policy_result

    def _format_output(self, result: ScanResult, config: PicoSentryConfig) -> str:
        if config.summary:
            return _format_summary(result)
        if config.quiet and config.format == "table":
            return _format_quiet(result)
        if config.format == "json":
            return format_json(result, deterministic_output=config.deterministic_output)
        if config.format == "sarif":
            return format_sarif(result)
        if config.format == "ml-context":
            return format_ml_context(result, token_budget=config.token_budget)
        if config.format == "cyclonedx":
            return format_cyclonedx(result)
        if config.format == "github":
            from picosentry.scan.formatters.github import format_github

            return format_github(result, sarif_path=config.sarif_file or "sarif.json")
        return format_table(result, color=not config.no_color)

    def _print_verbose_details(self, result: ScanResult) -> None:
        print("\n--- Scan Details ---", file=sys.stderr)
        print(f"Engine: v{result.engine_version}", file=sys.stderr)
        print(f"Corpus: v{result.corpus_version}", file=sys.stderr)
        print(f"Scan ID: {result.scan_id}", file=sys.stderr)
        print(f"Duration: {result.stats.duration_ms}ms", file=sys.stderr)
        print(f"Packages: {result.stats.packages_scanned}", file=sys.stderr)
        print(f"Files: {result.stats.files_scanned}", file=sys.stderr)
        if result.stats.rule_timings_ms:
            print("\nRule Timings:", file=sys.stderr)
            for rule_id in sorted(result.stats.rule_timings_ms):
                ms = result.stats.rule_timings_ms[rule_id]
                count = result.stats.findings_by_rule.get(rule_id, 0)
                print(f"  {rule_id:<18s} {ms:>5d}ms  ({count} findings)", file=sys.stderr)
        if result.stats.findings_by_severity:
            print("\nSeverity Summary:", file=sys.stderr)
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                count = result.stats.findings_by_severity.get(sev, 0)
                if count > 0:
                    pinch = _PINCH_LABELS.get(Severity(sev), sev)
                    print(f"  {sev:<10s} ({pinch}): {count}", file=sys.stderr)

    def run(self) -> int:
        """Execute a normal scan command and return an exit code."""
        target = Path(self.args.target).resolve()
        if not target.exists():
            print(f"Error: target does not exist: {target}", file=sys.stderr)
            return 2

        if self.args.verbose:
            temp_engine = create_default_engine()
            print(f"🦞 PicoSentry v{__version__}", file=sys.stderr)
            print(f"Target: {target}", file=sys.stderr)
            print(f"Corpus: {temp_engine._corpus_dir} (v{temp_engine._corpus_version})", file=sys.stderr)
            print(f"Rules: {', '.join(temp_engine.list_rules())}", file=sys.stderr)
            print("Scanning...", file=sys.stderr)

        file_config = load_config(target)
        config = file_config.merge_cli(self.args)

        if getattr(self.args, "offline", False) or os.environ.get("PICOSENTRY_OFFLINE", "").strip().lower() in {
            "1",
            "true",
            "yes",
        }:
            config.updates_enabled = False

        try:
            self._resolve_paths(config)
            policy_file = getattr(self.args, "policy", None) or getattr(config, "policy_file", None)
            if policy_file:
                policy_path = _resolve_external_path(
                    policy_file, self.workspace_root, must_exist=True, description="--policy"
                )
                config.policy_file = str(policy_path)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        except (PolicyNotFoundError, PolicyParseError) as exc:
            print(f"Error: policy error: {exc}", file=sys.stderr)
            return 2

        cached_result, cache, lockfile_hash = self._load_cache(target, config)

        try:
            result = cached_result or self._run_scan(target, merged_config=config)
        except ScanTimeout:
            print(f"Error: scan timed out after {self.args.timeout}s", file=sys.stderr)
            return 3
        except ScanError as e:
            print(f"Error: {e}", file=sys.stderr)
            if self.args.verbose and e.exc_traceback:
                print(e.exc_traceback, file=sys.stderr)
            return 1

        if cache is not None and lockfile_hash and not cached_result:
            self._save_cache(cache, lockfile_hash, result, config)

        from picosentry.scan.enterprise import is_enterprise_mode

        enterprise = is_enterprise_mode() or getattr(self.args, "enterprise", False)
        fail_closed = getattr(self.args, "fail_on_rule_error", False) or enterprise
        if fail_closed:
            failed_rules = [r for r in result.rule_executions if r.status == "failed"]
            if failed_rules:
                for r in failed_rules:
                    print(f"Rule {r.rule_id} FAILED: {r.error}", file=sys.stderr)
                print(f"Scan aborted: {len(failed_rules)} rule(s) failed. Exiting with code 4.", file=sys.stderr)
                return 4

        pre_baseline_findings = list(result.findings)
        baseline_info = None
        if config.baseline:
            baseline_path = Path(config.baseline)
            if not baseline_path.is_file():
                print(f"Error: baseline file not found: {baseline_path}", file=sys.stderr)
                return 2
            baseline_fingerprints = load_baseline(baseline_path)
            baseline_info = apply_baseline(result, baseline_fingerprints)
            result.apply_overrides(baseline_info.remaining)

            if not config.quiet and not config.summary:
                print(
                    f"Baseline: {baseline_info.suppressed_count} known, "
                    f"{baseline_info.new_count} new (of {baseline_info.original_count} total)",
                    file=sys.stderr,
                )

        if getattr(self.args, "policy", None) or getattr(config, "policy_file", None):
            try:
                self._apply_policy(result, config)
            except (PolicyNotFoundError, PolicyParseError, PolicyRuntimeError) as exc:
                print(f"Error: policy error: {exc}", file=sys.stderr)
                return 2

        output = self._format_output(result, config)
        if config.output:
            Path(config.output).write_text(output, encoding="utf-8")
            print(f"Output written to {config.output}")
        else:
            print(output)

        if self.args.verbose:
            self._print_verbose_details(result)

        if config.baseline and config.baseline_update:
            baseline_path = Path(config.baseline)
            from picosentry.scan.models import ScanStats

            baseline_result = ScanResult(
                target=result.target,
                engine_version=result.engine_version,
                corpus_version=result.corpus_version,
                findings=pre_baseline_findings,
                stats=ScanStats(),
            )
            baseline_result.recompute_stats()
            baseline_path.write_text(baseline_result.to_json(indent=2), encoding="utf-8")
            print(f"Baseline updated: {baseline_path} ({len(pre_baseline_findings)} findings)", file=sys.stderr)

        from picosentry.scan.models import SEVERITY_ORDER

        fail_on = config.fail_on
        use_exit_code = config.exit_code or fail_on is not None
        if use_exit_code:
            if fail_on:
                min_level = SEVERITY_ORDER[fail_on.lower()]
                has_fail_findings = any(
                    SEVERITY_ORDER.get(f.severity.value.lower(), 4) <= min_level for f in result.findings
                )
                return 1 if has_fail_findings else 0
            return 1 if result.findings else 0
        return 0

    def verify_determinism(self) -> int:
        """Run the scan twice and compare SHA-256 hashes."""
        target = Path(self.args.target).resolve()
        if not target.exists():
            print(f"Error: target does not exist: {target}", file=sys.stderr)
            return 2

        self.args.format = "json"
        self.args.output = None
        self.args.summary = False
        self.args.quiet = True

        print(f"🦞 PicoSentry v{__version__} — determinism verification", file=sys.stderr)
        print(f"Target: {target}", file=sys.stderr)
        print("Running scan twice and comparing SHA-256...", file=sys.stderr)

        print("  Run 1...", file=sys.stderr)
        result_a = self._run_scan(target)

        print("  Run 2...", file=sys.stderr)
        result_b = self._run_scan(target)

        is_match, hash_a, hash_b = verify_determinism(result_a, result_b)

        print("\n--- Determinism Verification ---", file=sys.stderr)
        print(f"  Run 1: sha256={hash_a}", file=sys.stderr)
        print(f"  Run 2: sha256={hash_b}", file=sys.stderr)

        if is_match:
            print("\n✓ DETERMINISM VERIFIED — scans are deterministic", file=sys.stderr)
            print(f"  scan_id: {result_a.scan_id}", file=sys.stderr)
            print(f"  findings: {len(result_a.findings)}", file=sys.stderr)
            print(f"  duration: {result_a.stats.duration_ms}ms / {result_b.stats.duration_ms}ms", file=sys.stderr)
            return 0

        print("\n✗ DETERMINISM VIOLATION — scans differ", file=sys.stderr)
        print("  This is a bug. Please report at:", file=sys.stderr)
        print("  https://github.com/KirkForge/PicoSentry/issues", file=sys.stderr)

        json_a = format_json(result_a, deterministic_output=True)
        json_b = format_json(result_b, deterministic_output=True)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", prefix="picosentry_a_", delete=False) as fa:
            fa.write(json_a)
            path_a = fa.name
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", prefix="picosentry_b_", delete=False) as fb:
            fb.write(json_b)
            path_b = fb.name

        print(f"  Diff: picosentry diff {path_a} {path_b}", file=sys.stderr)

        if len(result_a.findings) != len(result_b.findings):
            print(f"  findings: {len(result_a.findings)} vs {len(result_b.findings)}", file=sys.stderr)
        else:
            print(f"  findings: {len(result_a.findings)} (same count, different content)", file=sys.stderr)

        return 4

    def run_validation(self) -> int:
        """Run the validation harness against built-in fixtures."""
        output_path: Path | None = None
        if getattr(self.args, "output", None):
            output_path = Path(self.args.output)

        target = Path(self.args.target).resolve()
        print(f"🦞 PicoSentry v{__version__} — validation harness", file=sys.stderr)
        print(f"Target arg ignored: {target}", file=sys.stderr)
        print("Running validation against built-in fixtures...", file=sys.stderr)

        advisory_db = getattr(self.args, "advisory_db", None)
        report = run_validation(output_path=output_path, advisory_db_path=advisory_db)

        header = f"{'rule_id':<24} {'tp':>4} {'fp':>4} {'fn':>4} {'prec':>8} {'recall':>8}"
        print(header)
        print("-" * len(header))
        rule_metrics_by_id = {m.rule_id: m for m in report.rule_metrics}
        for rule_id in sorted(rule_metrics_by_id):
            m = rule_metrics_by_id[rule_id]
            print(
                f"{rule_id:<24} {m.true_positives:>4} {m.false_positives:>4} "
                f"{m.false_negatives:>4} {m.precision:>7.2%} {m.recall:>7.2%}"
            )

        failed_fixtures = [r for r in report.fixture_results if r[1] == "FAIL"]
        precision_ok = report.mean_precision >= 0.95
        recall_ok = report.mean_recall >= 0.80
        passes = (not failed_fixtures) and precision_ok and recall_ok

        print(
            f"\nfixtures: {report.total_fixtures} "
            f"({report.total_positive} pos / {report.total_negative} neg) | "
            f"mean precision: {report.mean_precision:.2%} | "
            f"mean recall: {report.mean_recall:.2%} | "
            f"fixture failures: {len(failed_fixtures)} | "
            f"passes: {passes}",
            file=sys.stderr,
        )

        return 0 if passes else 1


def _run_scan(
    args: argparse.Namespace,
    target: Path,
    file_config: PicoSentryConfig | None = None,
    merged_config: PicoSentryConfig | None = None,
) -> ScanResult:
    """Module-level wrapper around ``ScanOrchestrator._run_scan`` for tests."""
    return ScanOrchestrator(args)._run_scan(target, file_config=file_config, merged_config=merged_config)


def _verify_determinism(args: argparse.Namespace, _target: Path) -> int:
    """Module-level wrapper around ``ScanOrchestrator.verify_determinism`` for tests.

    ``_target`` is accepted for API compatibility with the original module-level
    helper, but the orchestrator reads the target from ``args.target``.
    """
    return ScanOrchestrator(args).verify_determinism()
