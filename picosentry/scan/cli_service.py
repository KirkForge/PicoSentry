"""Scan orchestration service used by the CLI.

This module holds the non-argument-parsing logic that was previously inlined
in ``picosentry/scan/cli_commands/scan.py``: path validation, cache handling,
scan execution, baseline/policy application, formatting, and exit-code
calculation.  Keeping it separate makes the CLI command file a thin dispatcher
and makes the orchestration testable without argparse.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import multiprocessing
import os
import sys
import tempfile
from pathlib import Path
from queue import Empty
from typing import Any

from picosentry.scan import __version__
from picosentry.scan._cli_service_formatters import (
    _format_quiet,
    _format_summary,
    _print_verbose_details,
)
from picosentry.scan._cli_service_paths import _resolve_external_path, _workspace_root
from picosentry.scan._cli_service_policy import _apply_policy
from picosentry.scan._cli_service_worker import ScanError, ScanTimeout
from picosentry.scan._engine_scan_helpers import _RELEVANT_EXTENSIONS, _RELEVANT_FILE_NAMES, _SKIP_DIRS
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
from picosentry.scan.guards import verify_determinism
from picosentry.scan.models import Confidence, Finding, ScanResult, ScanStats, Severity, apply_baseline, load_baseline
from picosentry.scan.rules.dangerous_build_hooks import BUILD_HOOK_READ_NAMES, BUILD_HOOK_READ_SUFFIXES
from picosentry.scan.validation import run_validation

logger = logging.getLogger(__name__)

# Bounded input hashing: at most this many relevant files / bytes feed the
# cache key. Sorted paths make the truncated subset deterministic.
_MAX_INPUT_FILES = 2048
_MAX_INPUT_BYTES = 64 * 1024 * 1024

# WO6.0.0-008 — node_modules JS-family content the L2-OBFS/NETEX/CRED/WORM
# rules scan. The rules cap at MAX_FILES_PER_PACKAGE=200 per installed package
# (sorted walk, deterministic); the cache key mirrors that so a payload
# injected into node_modules/*/index.js invalidates the cache without the key
# hashing every byte of a giant monorepo's deps. _NM_CONTENT_BUDGET_BYTES
# bounds the total node_modules-content contribution so it can't starve the
# manifest/lockfile half of the key on huge trees.
_NM_JS_EXTENSIONS = frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx"})
_NM_MAX_FILES_PER_PKG = 200
_NM_CONTENT_BUDGET_BYTES = 32 * 1024 * 1024
# Vendored/build dirs to skip WITHIN a node_modules package. Note: this does
# NOT include "node_modules" itself — we are already inside it. The rules'
# own SKIP_DIRS (obfuscation.py:38) match this set; _SKIP_DIRS above includes
# "node_modules" for the outer manifest walk, which would wrongly reject every
# file here.
_NM_INNER_SKIP_DIRS = frozenset({".git", ".hg", ".svn", "__pycache__", ".cache", "dist", "build", "out"})

# Config dimensions that shape the cached (post-filter) payload — see
# _run_scan: policy deny-lists, severity overrides, ignore lists and the
# severity threshold are all applied BEFORE the result is cached. Baseline and
# waivers are applied on every read (post-cache) and are deliberately NOT keyed.
_CACHE_SHAPE_FIELDS = (
    "rules",
    "severity_threshold",
    "severity_overrides",
    "ignore_packages",
    "ignore_paths",
    "intelligence",
)

# The L2-BUILD-001 read-surface (WO5.0.0-010), declared once in the rule and
# imported here so the cache key can never drift from what the rule reads.
# Lowercased — hashed with a case-insensitive match (over-inclusive is the
# safe direction for a cache key).
_BUILD_HOOK_MARKERS = tuple(sorted(m.lower() for m in BUILD_HOOK_READ_SUFFIXES | BUILD_HOOK_READ_NAMES))


def _hash_node_modules_content(target: Path, sha: hashlib._Hash) -> int:
    """Fold a bounded sample of node_modules JS-family file content into ``sha``.

    Mirrors the L2-OBFS/NETEX/CRED/WORM rules' read-surface: each installed
    package under node_modules is walked (sorted, skipping vendored/VCS dirs)
    and up to ``_NM_MAX_FILES_PER_PKG`` JS-family files per package are hashed.
    A ``nm-content:`` separator + per-package path prefix keeps this distinct
    from the manifest/lockfile half of the key. Returns the bytes hashed.

    ponytail: ceiling — an in-place same-size edit past the per-package file
    cap (200 files) or the total budget (_NM_CONTENT_BUDGET_BYTES) stays
    invisible to the key. The rules themselves cap at the same 200 files, so
    a payload the rules WILL scan is always in the first 200 files (sorted)
    and thus in the key. Upgrade path: hash every file when budget allows.
    """
    nm = target / "node_modules"
    if not nm.is_dir():
        return 0
    sha.update(b"nm-content:\0")
    total = 0
    budget_left = _NM_CONTENT_BUDGET_BYTES

    def _walk_pkg(pkg_dir: Path) -> None:
        nonlocal total, budget_left
        if budget_left <= 0:
            return
        count = 0
        for f in sorted(pkg_dir.rglob("*")):
            if count >= _NM_MAX_FILES_PER_PKG or budget_left <= 0:
                break
            if f.is_symlink() or not f.is_file():
                continue
            if f.suffix not in _NM_JS_EXTENSIONS:
                continue
            if any(part in _NM_INNER_SKIP_DIRS for part in f.parts):
                continue
            try:
                data = f.read_bytes()
            except OSError:
                continue
            try:
                rel = f.relative_to(target).as_posix()
            except ValueError:
                continue
            sha.update(rel.encode("utf-8"))
            sha.update(b"\0")
            sha.update(hashlib.sha256(data).digest())
            total += len(data)
            budget_left -= len(data)
            count += 1

    for child in sorted(nm.iterdir()):
        if budget_left <= 0:
            break
        if not child.is_dir() or child.name.startswith("."):
            continue
        if child.name.startswith("@"):
            for scoped in sorted(child.iterdir()):
                if scoped.is_dir():
                    _walk_pkg(scoped)
        else:
            _walk_pkg(child)
    if total >= _NM_CONTENT_BUDGET_BYTES:
        sha.update(f"nm-truncated:{total}".encode())
    return total


def _hash_target_inputs(target: Path) -> str:
    """Content hash over every scan-relevant input file, all ecosystems.

    Covers manifests, lockfiles, install scripts (.js/.py) and setup.py for
    npm, pnpm, yarn, PyPI, Go, Cargo, Maven, RubyGems and NuGet — not just the
    npm-family locks — plus the L2-BUILD-001 read-surface (build.rs, Rakefile,
    extconf.rb, .rs/.ps1/.nuspec/… via the shared BUILD_HOOK_READ_* constants)
    and node_modules package.json manifests (what the campaign rules read).
    WO6.0.0-008: also folds a bounded sample of node_modules JS-family CONTENT
    (what L2-OBFS/NETEX/CRED/WORM scan) — see ``_hash_node_modules_content``.
    WO7-011: folds the detected ecosystem set into the key so a scan whose
    ecosystem markers change (e.g. .venv added) does not hit a stale cache row
    from a previous scan with a different ecosystem set.
    Content-based (mtime changes alone never invalidate — determinism
    contract). Returns "" when the target has no relevant files and no
    detected ecosystems.
    """

    def _is_scan_input(file: Path) -> bool:
        try:
            rel_parts = file.relative_to(target).parts
        except ValueError:
            return False
        if "node_modules" in rel_parts:
            # Campaigns/advisory reads descend into installed package
            # manifests, which the _SKIP_DIRS walk would otherwise exclude.
            # JS-family CONTENT under node_modules is hashed separately by
            # _hash_node_modules_content (bounded per-package sample).
            return file.name == "package.json"
        if any(part in _SKIP_DIRS for part in rel_parts):
            return False
        return (
            file.suffix in _RELEVANT_EXTENSIONS
            or file.name in _RELEVANT_FILE_NAMES
            or file.name.lower().endswith(_BUILD_HOOK_MARKERS)
        )

    sha = hashlib.sha256()
    files: list[Path] = []
    if target.is_file():
        files = [target]
    else:
        for file in target.rglob("*"):
            if not file.is_file() or file.is_symlink():
                continue
            if _is_scan_input(file):
                files.append(file)
    if not files:
        # Still hash node_modules content if present — a project with only
        # node_modules (no root manifest) is a valid scan target.
        nm_bytes = _hash_node_modules_content(target, sha) if target.is_dir() else 0
        if nm_bytes == 0:
            return _ecosystem_hash(target, sha)
        sha.update(f"nm-only:{nm_bytes}".encode())
        return _ecosystem_hash(target, sha, _has_content=True)
    total = 0
    truncated = len(files) > _MAX_INPUT_FILES
    for file in sorted(files, key=lambda p: p.relative_to(target).as_posix())[:_MAX_INPUT_FILES]:
        try:
            data = file.read_bytes()
        except OSError:
            continue
        sha.update(file.relative_to(target).as_posix().encode("utf-8"))
        sha.update(b"\0")
        sha.update(hashlib.sha256(data).digest())
        total += len(data)
        if total > _MAX_INPUT_BYTES:
            truncated = True
            break
    if truncated:
        # ceiling: folding count+bytes catches add/remove past the file-count
        # cut and size changes inside the hashed prefix past the byte cut, but
        # an in-place same-size edit past either cut stays invisible to the
        # key. Upgrade path: full-tree manifest hash when truncation fires.
        sha.update(f"truncated:{len(files)}:{total}".encode())
    # WO6.0.0-008 — fold node_modules JS-family content (what L2-OBFS/NETEX/
    # CRED/WORM scan) so a payload injected into node_modules/*/index.js
    # invalidates the cache. Bounded per-package; see _hash_node_modules_content.
    if target.is_dir():
        _hash_node_modules_content(target, sha)
    return _ecosystem_hash(target, sha, _has_content=True)


def _ecosystem_hash(target: Path, sha: hashlib._Hash, _has_content: bool = False) -> str:
    """Fold the detected ecosystem set into the hash and return the digest.

    WO7-011: ecosystem marker dirs (.venv, .tox) flip detection without changing
    file content. Without this, a stale cache row from a scan with a different
    ecosystem set survives. Returns "" when no files hashed AND no ecosystems.
    """
    from picosentry.scan.engine import _detect_ecosystems

    detected = []
    if target.is_dir():
        detected = sorted(_detect_ecosystems(target))
        if detected:
            sha.update(b"ecosystems:\0")
            sha.update(",".join(detected).encode("utf-8"))
    if not detected and not _has_content:
        return ""
    return sha.hexdigest()[:16]


def _file_digest(path: str | None) -> str:
    if not path:
        return ""
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()[:16]
    except OSError:
        return "missing"


def _dir_digest(path: Path) -> str:
    """Content digest of a directory's JSON files (sorted, stat-only fallback).

    Used for the default advisory dir so ``picosentry advisories fetch``
    (which updates that dir) invalidates the scan cache. Reads every *.json
    file under ``path`` recursively, sorted by relative path for determinism.
    Returns ``""`` when the dir is empty/missing and ``"missing"`` on read
    errors — the same sentinel contract as ``_file_digest``.
    """
    if not path.is_dir():
        return ""
    sha = hashlib.sha256()
    count = 0
    for f in sorted(path.rglob("*.json")):
        if f.is_symlink():
            continue
        try:
            data = f.read_bytes()
        except OSError:
            continue
        sha.update(f.relative_to(path).as_posix().encode("utf-8"))
        sha.update(b"\0")
        sha.update(hashlib.sha256(data).digest())
        count += 1
    if count == 0:
        return ""
    return sha.hexdigest()[:16]


def _cache_config_digest(config: PicoSentryConfig) -> str:
    """Digest of every config/policy dimension that shapes the cached payload."""
    parts: dict = {name: getattr(config, name, None) for name in _CACHE_SHAPE_FIELDS}
    # Policy paths alone are not identity — the file content is what filtered the findings.
    parts["policy_file_digest"] = _file_digest(getattr(config, "policy_file", None))
    # Advisory DB: an explicit --advisory-db path is digested directly. When
    # no explicit path is given the scan uses the default advisory dir
    # (default_advisory_dir()), so ``picosentry advisories fetch`` updates
    # MUST invalidate the cache — fold the default dir's content digest in
    # (WO6.0.0-019 rider). Without this, a fetched advisory set was invisible
    # to the key and the cache served stale clean verdicts until TTL expiry.
    explicit_adv = getattr(config, "advisory_db", None)
    if explicit_adv:
        parts["advisory_db_digest"] = _file_digest(explicit_adv)
    else:
        from picosentry.scan.advisory import default_advisory_dir

        parts["advisory_db_digest"] = _dir_digest(default_advisory_dir())
    return hashlib.sha256(json.dumps(parts, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]


class ScanOrchestrator:
    """High-level scan orchestration used by ``picosentry scan``."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.workspace_root = _workspace_root()
        self._sbom_tmpdir: tempfile.TemporaryDirectory | None = None
        self._unscannable_components = 0
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

        Returns ``(cached_result, cache, input_hash)``.  ``cache`` is the
        cache store instance (or ``None`` if caching is disabled or failed).
        """
        if getattr(self.args, "verify_determinism", False) or getattr(self.args, "no_cache", False):
            return None, None, ""
        try:
            from picosentry.scan.cache import ScanCache

            cache = ScanCache.from_config(config)
            input_hash = _hash_target_inputs(target)
            if not input_hash:
                return None, cache, ""

            corpus_dir = Path(config.corpus) if config.corpus else None
            temp_engine = create_default_engine(
                corpus_dir=corpus_dir,
                advisory_db_path=config.advisory_db,
                intelligence_mode=config.intelligence,
            )
            corpus_hash = temp_engine._corpus_version
            cached_data = cache.get(input_hash, corpus_hash, __version__, _cache_config_digest(config))
            if cached_data and "scan_id" in cached_data:
                cached_result = self._scan_result_from_cache(cached_data, target)
                if cached_result:
                    logger.info("Cache hit: input=%s corpus=%s", input_hash[:8], corpus_hash[:8])
                    try:
                        from picosentry.scan.metrics import increment

                        increment("cache.hits")
                    except ImportError:
                        pass
                    return cached_result, cache, input_hash
            return None, cache, input_hash
        except (OSError, ValueError, TypeError, KeyError) as exc:
            logger.warning("Cache read failed for %s, disabling cache: %s", target, exc)
            return None, None, ""

    @staticmethod
    def _scan_result_from_cache(cached_data: dict, target: Path) -> ScanResult | None:
        if hasattr(ScanResult, "from_dict"):
            return ScanResult.from_dict(cached_data)

        try:
            stats_data = cached_data.get("stats", {})
            findings = [
                Finding(**{**f, "severity": Severity(f["severity"]), "confidence": Confidence(f["confidence"])})
                for f in cached_data.get("findings", [])
            ]
            from picosentry.scan.models import RuleExecution

            rule_executions = [RuleExecution(**r) for r in cached_data.get("rule_status", {}).values()]
            audit = cached_data.get("audit", {})
            # Faithful restore — a cache hit must produce the same output shape
            # as a fresh scan (contract: cache skips recompute, never reshapes).
            return ScanResult(
                target=cached_data.get("target", str(target)),
                engine_version=cached_data.get("engine_version", __version__),
                corpus_version=cached_data.get("corpus_version", ""),
                findings=findings,
                stats=ScanStats(**stats_data) if stats_data else ScanStats(),
                rule_executions=rule_executions,
                started_at=audit.get("started_at", ""),
                completed_at=audit.get("completed_at", ""),
                config_digest=audit.get("config_digest", ""),
                policy_digest=audit.get("policy_digest", ""),
                scanner_version=audit.get("scanner_version", cached_data.get("engine_version", __version__)),
                package_intel=cached_data.get("package_intel", {}),
                behavioral_evidence=cached_data.get("behavioral_evidence"),
                unscannable_components=cached_data.get("unscannable_components", 0),
            )
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            logger.warning("Cache entry for %s is corrupted, ignoring: %s", target, exc)
            return None

    def _save_cache(self, cache: Any, input_hash: str, result: ScanResult, config: PicoSentryConfig) -> None:
        if not cache or not input_hash:
            return
        try:
            corpus_dir = Path(config.corpus) if config.corpus else None
            te = create_default_engine(
                corpus_dir=corpus_dir,
                advisory_db_path=config.advisory_db,
                intelligence_mode=config.intelligence,
            )
            corpus_hash = te._corpus_version
            cache.put(input_hash, corpus_hash, __version__, result.to_dict(), _cache_config_digest(config))
            logger.info("Cached scan result: input=%s", input_hash[:8])
            try:
                from picosentry.scan.metrics import increment

                increment("cache.misses")
            except ImportError:
                pass
        except (OSError, ValueError, TypeError) as exc:
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
        engine = create_default_engine(
            corpus_dir=corpus_dir,
            advisory_db_path=config.advisory_db,
            intelligence_mode=config.intelligence,
        )

        if self.args.timeout and self.args.timeout > 0:
            result_queue: multiprocessing.Queue = multiprocessing.Queue()

            worker = multiprocessing.Process(
                target=self._scan_worker,
                args=(target, config.rules, str(corpus_dir) if corpus_dir else None, config.advisory_db, result_queue),
                kwargs={"intelligence_mode": config.intelligence},
            )
            worker.start()
            worker.join(timeout=self.args.timeout)

            if worker.is_alive():
                worker.terminate()
                worker.join(timeout=1)
                raise ScanTimeout

            try:
                status, data = result_queue.get(timeout=1)
            except (Empty, OSError, ValueError, TypeError) as e:
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
            _effective_policy = _resolve_effective_policy(config=config)
        except (PolicyNotFoundError, PolicyParseError, PolicyRuntimeError) as exc:
            raise ScanError(f"policy error: {exc}") from exc
        # ponytail: WO6.0.0-007 — the deny_packages/deny_licenses finding
        # suppression block that lived here was deleted: it inverted policy
        # semantics (banning a pkg suppressed its findings, hiding the evidence
        # that justified the ban). The policy engine surfaces deny_packages
        # violations via _apply_policy (run() calls it after this returns); the
        # deny_licenses block was dead code (Finding has no .licenses attr).
        del _effective_policy  # resolved only for its raise-on-error side effect

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
        if config.format == "markdown":
            from picosentry.scan.formatters.markdown import format_markdown

            return format_markdown(result)
        if config.format == "github":
            from picosentry.scan.formatters.github import format_github

            return format_github(result, sarif_path=config.sarif_file or "sarif.json")
        return format_table(result, color=not config.no_color)

    def _prepare_sbom_target(self, sbom_path: str, original_target: Path) -> Path:
        from picosentry.scan.sbom import parse_sbom

        sbom = Path(sbom_path)
        if not sbom.is_file():
            print(f"Error: SBOM file not found: {sbom}", file=sys.stderr)
            raise SystemExit(2)
        try:
            refs = parse_sbom(sbom)
        except ValueError as exc:
            print(f"Error: invalid SBOM file: {exc}", file=sys.stderr)
            raise SystemExit(2) from exc
        if not refs:
            print(f"Error: SBOM contains no packages: {sbom}", file=sys.stderr)
            raise SystemExit(2)
        self._unscannable_components = sum(1 for ref in refs if ref.ecosystem == "unknown")
        tmpdir = tempfile.TemporaryDirectory(prefix="picosentry-sbom-")
        self._sbom_tmpdir = tmpdir
        scan_dir = Path(tmpdir.name)
        ecosystem_manifests: dict[str, list[dict]] = {}
        for ref in refs:
            ecosystem_manifests.setdefault(ref.ecosystem, []).append({"name": ref.name, "version": ref.version})
        manifest_map = {
            "npm": "package.json",
            "pypi": "requirements.txt",
            "golang": "go.mod",
            "cargo": "Cargo.toml",
            "maven": "pom.xml",
            "rubygems": "Gemfile",
            "nuget": "packages.config",
        }
        for eco, packages in ecosystem_manifests.items():
            filename = manifest_map.get(eco, f"{eco}-packages.json")
            filepath = scan_dir / filename
            if eco == "npm":
                deps = {p["name"]: p["version"] for p in packages}
                filepath.write_text(json.dumps({"name": "sbom-scan", "version": "0.0.0", "dependencies": deps}))
            elif eco == "pypi":
                lines = [f"{p['name']}=={p['version']}" for p in packages]
                filepath.write_text("\n".join(lines))
            elif eco == "golang":
                lines = ["module sbom-scan", "", "require ("]
                for p in packages:
                    lines.append(f"\t{p['name']} v{p['version']}")
                lines.append(")")
                filepath.write_text("\n".join(lines))
            elif eco == "cargo":
                lines = [
                    "[package]",
                    'name = "sbom-scan"',
                    'version = "0.0.0"',
                    "",
                    "[dependencies]",
                ]
                for p in packages:
                    lines.append(f'{p["name"]} = "{p["version"]}"')
                filepath.write_text("\n".join(lines))
            elif eco == "maven":
                lines = [
                    '<?xml version="1.0" encoding="UTF-8"?>',
                    "<project>",
                    "  <dependencies>",
                ]
                for p in packages:
                    coords = p["name"]
                    # SBOM maven names carry 'group:artifact' coordinates (sbom.py
                    # _maven_display_name); both elements are required or the pom
                    # parsers drop the dependency (WO4.0.0-015).
                    if ":" in coords:
                        gid, aid = coords.split(":", 1)
                    else:
                        gid, aid = coords, coords
                    ver = p["version"]
                    lines.append(
                        f"    <dependency><groupId>{gid}</groupId>"
                        f"<artifactId>{aid}</artifactId><version>{ver}</version></dependency>"
                    )
                lines.append("  </dependencies>")
                lines.append("</project>")
                filepath.write_text("\n".join(lines))
            elif eco == "rubygems":
                lines = ['source "https://rubygems.org"', ""]
                for p in packages:
                    lines.append(f'gem "{p["name"]}", "{p["version"]}"')
                filepath.write_text("\n".join(lines))
            elif eco == "nuget":
                lines = ['<?xml version="1.0" encoding="utf-8"?>', "<packages>"]
                for p in packages:
                    lines.append(f'  <package id="{p["name"]}" version="{p["version"]}" />')
                lines.append("</packages>")
                filepath.write_text("\n".join(lines))
            else:
                filepath.write_text(json.dumps(packages, indent=2))
        if original_target.is_dir():
            existing = {f.name for f in scan_dir.iterdir()}
            for item in original_target.iterdir():
                if item.name not in existing and item.is_file():
                    (scan_dir / item.name).write_bytes(item.read_bytes())
        return scan_dir

    def run(self) -> int:
        """Execute a normal scan command and return an exit code."""
        target = Path(self.args.target).resolve()
        if not target.exists():
            print(f"Error: target does not exist: {target}", file=sys.stderr)
            return 2

        sbom_path = getattr(self.args, "sbom", None)
        if sbom_path:
            target = self._prepare_sbom_target(sbom_path, target)

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

        cached_result, cache, input_hash = self._load_cache(target, config)

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

        if cache is not None and input_hash and not cached_result:
            self._save_cache(cache, input_hash, result, config)

        # SBOM components no fallback could map must not vanish silently
        # (WO5.0.0-016): count them in the result and say so on stderr.
        if self._unscannable_components:
            result.unscannable_components = self._unscannable_components
            print(
                f"Warning: {self._unscannable_components} SBOM component(s) have no recognizable "
                "ecosystem — not scanned (see unscannable_components in the result)",
                file=sys.stderr,
            )

        # Explicitly requested rules that ecosystem detection dropped must not
        # surface as a clean scan (WO5.0.0-015) — exit 2 (input error) when
        # NOTHING ran. Partial runs keep normal exit codes; the skipped
        # executions stay visible in the result for scan_completeness.
        if config.rules is not None and not any(r.status == "ok" for r in result.rule_executions):
            skipped = [r for r in result.rule_executions if r.status == "skipped"]
            if skipped:
                print(
                    "Error: no rules ran — requested rules are not applicable to this target: "
                    + ", ".join(f"{r.rule_id} ({r.error})" for r in skipped),
                    file=sys.stderr,
                )
                return 2

        from picosentry.scan.enterprise import is_enterprise_mode

        enterprise = is_enterprise_mode() or getattr(self.args, "enterprise", False)
        fail_closed = getattr(self.args, "fail_on_rule_error", False) or enterprise
        if fail_closed:
            # "timeout" must fail closed too — a rule whose timebox expired saw
            # at most part of the target, which is an error for fail-closed use.
            failed_rules = [r for r in result.rule_executions if r.status != "ok"]
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
                _apply_policy(result, getattr(self.args, "policy", None) or getattr(config, "policy_file", None))
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
            _print_verbose_details(result)

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
        # Floors raised 2026-08-17 (WO4.0.0-008): reality is 1.00/0.91 after
        # the FP gating + FN root-cause fixes; keep ~6pp recall headroom.
        precision_ok = report.mean_precision >= 0.94
        recall_ok = report.mean_recall >= 0.84
        passes = precision_ok and recall_ok

        if report.unknown_rule_expectations:
            print(
                f"\nunknown expected_rule_ids: {len(report.unknown_rule_expectations)} "
                "(fixtures expect rule ids that do not exist — recall loss by construction)",
                file=sys.stderr,
            )
            for name, rid in report.unknown_rule_expectations[:20]:
                print(f"  {name}: expects nonexistent rule {rid}", file=sys.stderr)

        if report.skipped_fixtures:
            print(
                f"WARNING: {report.skipped_fixtures} fixture(s) skipped (malformed fixture.json "
                "or unknown label) — precision/recall computed over the loaded fixtures only",
                file=sys.stderr,
            )

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
