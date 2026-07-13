"""Helpers and low-level primitives for the scan CLI service.

These functions were extracted from ``picosentry.scan.cli_service`` to keep the
orchestrator class focused on command flow.  Public names remain re-exported
from ``cli_service`` and ``cli_commands.scan`` for backward compatibility.
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
from typing import Any

from picosentry.scan import __version__
from picosentry.scan.config import PicoSentryConfig
from picosentry.scan.engine import create_default_engine
from picosentry.scan.formatters import format_json
from picosentry.scan.formatters.table import _PINCH_LABELS
from picosentry.scan.models import Finding, ScanResult, ScanStats, Severity
from picosentry.scan.policy import Policy
from picosentry.scan.rules.utils import iter_node_modules, load_package_json

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


def _apply_policy(result: ScanResult, policy_file: str | None) -> None:
    if not policy_file:
        return

    policy_path = Path(policy_file)
    if not policy_path.is_file():
        from picosentry.scan.engine import PolicyNotFoundError

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


def _print_verbose_details(result: ScanResult) -> None:
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
