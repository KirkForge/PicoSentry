"""
Scanner engine — deterministic, offline, pure-function rules.

Orchestrates detector rules, collects findings, produces ScanResult.
Same input + same corpus = same output. No global state. No HTTP at scan time.
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .policy import Policy

from .models import Finding, RuleExecution, ScanResult, ScanStats


# PolicyStack integration — lazy import to avoid circular dependency
def _resolve_effective_policy(policy_path: str | Path | None = None, config: Any = None) -> Policy | None:
    """Resolve the effective policy using PolicyStack inheritance.

    If a policy file or config is provided, builds a PolicyStack from
    global → org → repo → pipeline layers and returns the merged Policy.
    Returns None if no policy layers are available.

    Called from the CLI scan flow to apply policy-based filtering
    (deny_packages, deny_licenses, fail_on_severity) to findings.
    """
    if policy_path is None and config is None:
        return None
    try:
        from picosentry.scan.policy import Policy
        from picosentry.scan.policy_lifecycle import InheritedPolicy, PolicyStack
        stack = PolicyStack()
        if policy_path and Path(policy_path).exists():
            policy = Policy.from_file(policy_path)
            stack.add(InheritedPolicy(policy=policy, layer="repo", source=str(policy_path)))
        if config and hasattr(config, "policy_file") and config.policy_file:
            p = Policy.from_file(config.policy_file)
            stack.add(InheritedPolicy(policy=p, layer="pipeline", source=config.policy_file))
        if stack.layers:
            return stack.effective_policy()
    except Exception:
        pass
    return None

logger = logging.getLogger("picosentry.engine")


def user_corpus_dir() -> Path:
    """Return the user corpus directory (XDG data dir).

    Preference order:
        1. $PICOSENTRY_CORPUS_DIR (canonical)
        2. $PICOCORPUS_DIR (backward compat)
        3. $XDG_DATA_HOME/picosentry/corpus
        4. ~/.local/share/picosentry/corpus

    This directory is writable by the user and separate from the
    installed package, so `picosentry update` works without root.
    """
    explicit = os.environ.get("PICOSENTRY_CORPUS_DIR") or os.environ.get("PICOCORPUS_DIR")
    if explicit:
        return Path(explicit)
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "picosentry" / "corpus"
    return Path.home() / ".local" / "share" / "picosentry" / "corpus"


# Version resolution: importlib.metadata primary, source fallback
def _get_version() -> str:
    """Read version — prefer importlib.metadata, fall back to source parsing."""
    # Primary: importlib.metadata (standard, robust)
    try:
        from importlib.metadata import version

        return version("picosentry")
    except Exception:
        pass
    # Fallback: parse __init__.py source (works for editable installs without metadata)
    import re

    init_path = Path(__file__).parent / "__init__.py"
    try:
        source = init_path.read_text(encoding="utf-8")
        match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', source)
        if match:
            return match.group(1)
    except OSError:
        pass
    return "0.0.0"


_VERSION = _get_version()

# A detector rule is a pure function: (target_path, corpus_dir) → List[Finding]
DetectorRule = Callable[[Path, Path], list[Finding]]


class ScanEngine:
    """
    Deterministic supply chain scanner engine.

    Register detector rules, then scan a target path.
    Each rule runs independently — composable, no side-effects between rules.
    Rules receive (target_path, corpus_dir) — no HTTP, no global state.
    """

    def __init__(self, corpus_dir: Path | None = None, advisory_db_path: str | None = None) -> None:
        self._rules: dict[str, DetectorRule] = {}
        self._corpus_dir = self._resolve_corpus_dir(corpus_dir)
        self._corpus_version = self._compute_corpus_version()
        self._advisory_db_path = advisory_db_path

    @staticmethod
    def _resolve_corpus_dir(explicit: Path | None) -> Path:
        """Resolve corpus directory with priority: explicit > user > built-in.

        1. If caller passed a corpus_dir (CLI --corpus), use that.
        2. If user corpus dir has npm_top_packages.json, use that.
        3. Fall back to built-in corpus (shipped with the package).
        """
        if explicit:
            return explicit
        user_dir = user_corpus_dir()
        user_corpus = user_dir / "npm_top_packages.json"
        if user_corpus.is_file():
            logger.info("Using user corpus: %s", user_dir)
            return user_dir
        # Built-in corpus (shipped with the package)
        return Path(__file__).parent / "corpus"

    def _compute_corpus_version(self) -> str:
        """Compute deterministic corpus version from corpus file hashes.

        sha256 of all corpus files (sorted by path) → first 12 hex chars.
        Same corpus content = same version. Corpus changes = different version.
        """
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
        return h.hexdigest()[:12]

    def register(self, rule_id: str, rule: DetectorRule) -> ScanEngine:
        """Register a detector rule. Returns self for chaining."""
        self._rules[rule_id] = rule
        return self

    def unregister(self, rule_id: str) -> None:
        """Remove a detector rule."""
        self._rules.pop(rule_id, None)

    def list_rules(self) -> list[str]:
        """Return sorted list of registered rule IDs."""
        return sorted(self._rules.keys())

    def scan(
        self,
        target: str | Path,
        rules: Sequence[str] | None = None,
        advisory_db_path: str | None = None,
    ) -> ScanResult:
        """
        Run a deterministic scan on target path.

        Args:
            target: Filesystem path to scan (project root, node_modules, etc.)
            rules: Optional subset of rule IDs to run. None = all rules.

        Returns:
            ScanResult with sorted findings and aggregate stats.
        """
        target_path = Path(target).resolve()
        if not target_path.exists():
            logger.error("Scan target does not exist: %s", target_path)
            return ScanResult(target=str(target_path))

        selected_rules = {k: v for k, v in self._rules.items() if k in rules} if rules else dict(self._rules)

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

        # Count packages if node_modules or similar structure
        # Includes scoped packages (@scope/pkg) as individual packages
        nm_path = target_path / "node_modules"
        if nm_path.is_dir():
            packages_scanned = 0
            for d in nm_path.iterdir():
                if not d.is_dir() or d.name.startswith("."):
                    continue
                if d.name.startswith("@"):
                    # Scoped package directory: count each sub-directory
                    packages_scanned += sum(1 for s in d.iterdir() if s.is_dir())
                else:
                    packages_scanned += 1

        # Deduplicate: multiple rule_ids may map to the same function (sub-rules).
        # Call each unique function once, then filter findings by requested rule_ids.
        fn_to_rule_ids: dict[int, list[str]] = {}
        for rule_id in selected_rules:
            fn_id = id(selected_rules[rule_id])
            fn_to_rule_ids.setdefault(fn_id, []).append(rule_id)

        for fn_id in sorted(fn_to_rule_ids, key=lambda fid: fn_to_rule_ids[fid][0]):
            rule_fn = selected_rules[fn_to_rule_ids[fn_id][0]]
            rule_ids_for_fn = fn_to_rule_ids[fn_id]
            primary_rule_id = rule_ids_for_fn[0]
            rule_start = _now_ms()
            try:
                if rule_fn.__name__ == "detect_advisory_vulnerabilities":
                    findings = rule_fn(
                        target_path, self._corpus_dir, advisory_db_path=advisory_db_path or self._advisory_db_path
                    )
                else:
                    findings = rule_fn(target_path, self._corpus_dir)
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
                logger.error("Rule %s raised an exception: %s", primary_rule_id, exc)
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
                            error_type=type(exc).__name__,
                            error_message=str(exc),
                        )
                    )

        # Filter findings: only include findings whose rule_id was in the selected set
        if rules is not None:
            selected_set = set(selected_rules.keys())
            all_findings = [f for f in all_findings if f.rule_id in selected_set]

        # Normalize finding paths: make them relative to target for portable,
        # path-independent determinism. Same project content at different
        # filesystem locations should produce the same scan_id and output.
        # Using str(target_path) as prefix to strip, with trailing separator
        # to avoid partial path matches (e.g., /foo/bar vs /foo/barbaz).
        target_prefix = str(target_path)
        if not target_prefix.endswith("/") and not target_prefix.endswith("\\"):
            target_prefix += "/"
        for f in all_findings:
            if f.file.startswith(target_prefix):
                # dataclass is frozen — we need to use object.__setattr__
                object.__setattr__(f, "file", f.file[len(target_prefix) :])

        duration = _now_ms() - start_ms

        # Count files traversed (best-effort, relevant file types only)
        # Excludes .git, __pycache__, node_modules/.cache, etc.
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
            }
        )
        if target_path.is_dir():
            files_scanned = 0
            for f in target_path.rglob("*"):
                if not f.is_file() or f.is_symlink():
                    continue
                # Skip files in irrelevant directories
                if any(part in _SKIP_DIRS for part in f.parts):
                    continue
                if f.suffix in _RELEVANT_EXTENSIONS or f.name in {
                    "package.json",
                    "package-lock.json",
                    "pnpm-lock.yaml",
                    "yarn.lock",
                    ".npmrc",
                    "pnpm-workspace.yaml",
                }:
                    files_scanned += 1
        else:
            files_scanned = 1

        # Build stats
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

        # Record metrics for observability
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


def create_default_engine(corpus_dir: Path | None = None, advisory_db_path: str | None = None) -> ScanEngine:
    """Create a ScanEngine with all built-in detector rules registered."""
    from .rules.advisory_check import detect_advisory_vulnerabilities
    from .rules.bundled_shadow import detect_bundled_shadows
    from .rules.credential_read import detect_credential_reading
    from .rules.dep_confusion import detect_dep_confusion
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
    from .rules.sideloading import detect_sideloading
    from .rules.typosquat import detect_typosquat
    from .rules.worm_propagation import detect_worm_propagation

    engine = ScanEngine(corpus_dir=corpus_dir, advisory_db_path=advisory_db_path)
    engine.register("L2-POST-001", detect_post_install_scripts)
    engine.register("L2-OBFS-001", detect_obfuscation)
    engine.register("L2-OBFS-002", detect_obfuscation)  # sub-rule: hex obfuscation
    engine.register("L2-OBFS-003", detect_obfuscation)  # sub-rule: base64+eval
    engine.register("L2-OBFS-004", detect_obfuscation)  # sub-rule: unicode escapes
    engine.register("L2-DEPC-001", detect_dep_confusion)
    engine.register("L2-TYPO-001", detect_typosquat)
    engine.register("L2-MANI-001", detect_manifest_issues)
    engine.register("L2-MANI-002", detect_manifest_issues)  # sub-rule: optional deps w/ scripts
    engine.register("L2-FORK-001", detect_fork_drift)
    engine.register("L2-CRED-001", detect_credential_reading)
    engine.register("L2-LOCK-001", detect_lockfile_drift)
    engine.register("L2-BUND-001", detect_bundled_shadows)
    engine.register("L2-PROV-001", detect_provenance_issues)
    engine.register("L2-MAINT-001", detect_maintainer_changes)
    engine.register("L2-PNPM-001", detect_pnpm_config)
    engine.register("L2-LICENSE-001", detect_license_issues)
    engine.register("L2-ENGIN-001", detect_engine_issues)
    engine.register("L2-SIDELOAD-001", detect_sideloading)
    engine.register("L2-IOC-001", detect_custom_iocs)
    engine.register("L2-ADV-001", detect_advisory_vulnerabilities)
    engine.register("L2-WORM-001", detect_worm_propagation)
    engine.register("L2-NETEX-001", detect_network_exfiltration)
    return engine


def _now_ms() -> float:
    return time.monotonic() * 1000


# Note: SIGALRM-based timeout in cli.py is Unix-only.
# For cross-platform determinism, use subprocess isolation:
#   timeout_cmd = ["timeout", str(seconds), "picosentry", "scan", target]
# Or the multiprocessing module with join(timeout).
# This stub documents the enterprise approach — the CLI already handles
# timeout via SIGALRM (Unix) and warns on Windows.
