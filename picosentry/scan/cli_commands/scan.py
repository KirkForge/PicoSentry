from __future__ import annotations

import argparse
import hashlib
import json
import logging
import multiprocessing
import sys
import tempfile
from pathlib import Path

from picosentry.scan import __version__
from picosentry.scan.config import PicoSentryConfig, load_config
from picosentry.scan.engine import _resolve_effective_policy, create_default_engine
from picosentry.scan.formatters import (
    format_cyclonedx,
    format_json,
    format_ml_context,
    format_sarif,
    format_table,
)
from picosentry.scan.formatters.table import _PINCH_LABELS
from picosentry.scan.guards import verify_determinism
from picosentry.scan.models import Finding, ScanResult, Severity, apply_baseline, load_baseline
from picosentry.scan.validation import run_validation

NAME = "scan"


logger = logging.getLogger(__name__)


class ScanTimeout(Exception):
    """Raised when a scan exceeds its ``--timeout`` budget."""


class ScanError(Exception):
    """Raised when the scan worker process reports an error."""


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
    except Exception as e:
        result_queue.put(("error", str(e)))


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


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    scan_parser = subparsers.add_parser(NAME, help="Scan a project directory for supply chain risks")
    scan_parser.add_argument("target", type=str, help="Path to project directory to scan")
    scan_parser.add_argument(
        "--format",
        "-f",
        choices=["json", "sarif", "table", "ml-context", "github", "cyclonedx"],
        default=None,
        help="Output format (default: table). 'github' writes SARIF file + prints markdown summary.",
    )
    scan_parser.add_argument(
        "--output", "-o", type=str, default=None, help="Write output to file instead of stdout"
    )
    scan_parser.add_argument("--rules", "-r", nargs="+", default=None, help="Run only specific rules (e.g., L2-POST-001 L2-OBFS-001)")
    scan_parser.add_argument("--corpus", "-c", type=str, default=None, help="Path to corpus directory (default: built-in)")
    scan_parser.add_argument("--advisory-db", type=str, default=None, help="Path to OSV-format advisory database for vulnerability checking")
    scan_parser.add_argument("--no-color", action="store_true", help="Disable colored output (table format only)")
    scan_parser.add_argument("--token-budget", type=int, default=None, help="Token budget for ml-context format (default: 4096)")
    scan_parser.add_argument("--exit-code", action="store_true", help="Exit with code 1 if findings found, 0 if clean")
    scan_parser.add_argument(
        "--severity-threshold",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Minimum severity to include in output (default: show all)",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Exit with code 1 only if findings at or above this severity (implies --exit-code)",
    )
    scan_parser.add_argument("--quiet", "-q", action="store_true", help="Only show summary line (findings count by severity). No detailed findings.")
    scan_parser.add_argument("--summary", action="store_true", help="One-line summary for CI notifications. Implies --quiet.")
    scan_parser.add_argument("--baseline", "-b", type=str, default=None, help="Path to baseline JSON file or ignore file. Known findings are suppressed.")
    scan_parser.add_argument("--baseline-update", action="store_true", help="Write updated baseline file (with new findings added) after filtering. Use with --baseline.")
    scan_parser.add_argument("--verbose", "-v", action="store_true", help="Show per-rule timing and detailed scan progress.")
    scan_parser.add_argument("--timeout", type=int, default=0, help="Timeout in seconds for the entire scan (0 = no timeout). Exits with code 3 on timeout.")
    scan_parser.add_argument("--fail-on-rule-error", action="store_true", help="Exit with code 4 if any detector rule raises an exception. Fail-closed for CI. Implied by --enterprise.")
    scan_parser.add_argument("--enterprise", action="store_true", help="Enable enterprise mode. Equivalent to PICOSENTRY_ENTERPRISE_MODE=1.")
    scan_parser.add_argument("--policy", "-p", type=str, default=None, help="Path to .picosentry-policy.yml for enterprise policy enforcement")
    scan_parser.add_argument("--sarif-file", type=str, default=None, help="Path for SARIF output file when using --format github (default: sarif.json)")
    scan_parser.add_argument("--verify-determinism", action="store_true", help="Run scan twice and verify SHA-256 determinism. Exit 0 if identical, 4 if different. Implies --format json.")
    scan_parser.add_argument(
        "--validate",
        action="store_true",
        help="Run the validation harness against built-in fixtures. Prints per-rule precision/recall; "
        "exit 0 if mean precision >= 0.95 and mean recall >= 0.80. "
        "Ignores <target> (the harness uses its own fixtures).",
    )
    scan_parser.add_argument(
        "--deterministic-output",
        action="store_true",
        help="Omit timestamps, timing, and audit metadata from output for byte-stable JSON.",
    )


def cmd(args: argparse.Namespace) -> int:
    target = Path(args.target).resolve()
    if not target.exists():
        print(f"Error: target does not exist: {target}", file=sys.stderr)
        return 2


    if args.verify_determinism:
        args.deterministic_output = True
        return _verify_determinism(args, target)


    if getattr(args, "validate", False):
        return _handle_validate(args, target)


    if args.verbose:
        from picosentry.scan.engine import create_default_engine

        temp_engine = create_default_engine()
        print(f"🦞 PicoSentry v{__version__}", file=sys.stderr)
        print(f"Target: {target}", file=sys.stderr)
        print(f"Corpus: {temp_engine._corpus_dir} (v{temp_engine._corpus_version})", file=sys.stderr)
        print(f"Rules: {', '.join(temp_engine.list_rules())}", file=sys.stderr)
        print("Scanning...", file=sys.stderr)


    file_config = load_config(target)
    config = file_config.merge_cli(args)


    cached_result = None
    cache = None
    lockfile_hash = ""
    if not args.verify_determinism and not getattr(args, "no_cache", False):
        try:
            from picosentry.scan.cache import ScanCache

            cache = ScanCache.from_config(config)

            for lockfile_name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"):
                lf = target / lockfile_name
                if lf.is_file():
                    lockfile_hash = hashlib.sha256(lf.read_bytes()).hexdigest()[:16]
                    break
            if lockfile_hash:
                corpus_dir = Path(config.corpus) if config.corpus else None
                temp_engine = create_default_engine(corpus_dir=corpus_dir, advisory_db_path=config.advisory_db)
                corpus_hash = temp_engine._corpus_version
                rule_version = __version__
                cached_data = cache.get(lockfile_hash, corpus_hash, rule_version)
                if cached_data and "scan_id" in cached_data:
                    from picosentry.scan.models import ScanResult, ScanStats

                    cached_result = ScanResult.from_dict(cached_data) if hasattr(ScanResult, "from_dict") else None
                    if cached_result is None:
                        try:
                            stats_data = cached_data.get("stats", {})
                            cached_result = ScanResult(
                                target=cached_data.get("target", str(target)),
                                engine_version=cached_data.get("engine_version", __version__),
                                corpus_version=cached_data.get("corpus_version", ""),
                                findings=[Finding(**f) for f in cached_data.get("findings", [])] if "findings" in cached_data else [],
                                stats=ScanStats(**stats_data) if stats_data else ScanStats(),
                            )
                        except Exception:
                            cached_result = None
                    if cached_result:
                        logger.info("Cache hit: lockfile=%s corpus=%s", lockfile_hash[:8], corpus_hash[:8])
                        try:
                            from picosentry.scan.metrics import increment

                            increment("cache.hits")
                        except ImportError:
                            pass
        except Exception:
            cache = None  # Cache errors should not block scanning


    try:
        result = cached_result or _run_scan(args, target, merged_config=config)
    except ScanTimeout:
        print(f"Error: scan timed out after {args.timeout}s", file=sys.stderr)
        return 3
    except ScanError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


    if cache and lockfile_hash and not cached_result:
        try:
            corpus_dir = Path(config.corpus) if config.corpus else None
            if not hasattr(cache, "_corpus_version_cache"):
                te = create_default_engine(corpus_dir=corpus_dir, advisory_db_path=config.advisory_db)
                corpus_hash = te._corpus_version
            cache.put(lockfile_hash, corpus_hash, __version__, result.to_dict())
            logger.info("Cached scan result: lockfile=%s", lockfile_hash[:8])
            try:
                from picosentry.scan.metrics import increment

                increment("cache.misses")
            except ImportError:
                pass
        except Exception:
            pass  # Cache write errors should not block the scan result


    from picosentry.scan.enterprise import is_enterprise_mode

    enterprise = is_enterprise_mode() or getattr(args, "enterprise", False)
    fail_closed = getattr(args, "fail_on_rule_error", False) or enterprise
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
                f"Baseline: {baseline_info.suppressed_count} known, {baseline_info.new_count} new (of {baseline_info.original_count} total)",
                file=sys.stderr,
            )


    policy_file = getattr(args, "policy", None) or getattr(config, "policy_file", None)
    policy_result = None
    if policy_file:
        from picosentry.scan.policy import Policy

        policy_path = Path(policy_file)
        if policy_path.is_file():
            policy = Policy.from_file(policy_path)

            pkg_licenses: dict[str, str] = {}
            installed_pkgs: set[str] = set()
            from picosentry.scan.rules.utils import iter_node_modules, load_package_json


            root_pkg = target / "package.json"
            if root_pkg.is_file():
                root_data = load_package_json(root_pkg)
                if root_data:
                    root_name = root_data.get("name", "")
                    if root_name:
                        installed_pkgs.add(root_name)
            for pkg_json_path, pkg_data in iter_node_modules(target):
                pkg_name = pkg_data.get("name", pkg_json_path.parent.name)

                if not pkg_name.startswith("@") and pkg_json_path.parent.name and pkg_json_path.parent.parent.name.startswith("@"):
                    pkg_name = f"{pkg_json_path.parent.parent.name}/{pkg_name}"
                installed_pkgs.add(pkg_name)

            for f in result.findings:
                if f.rule_id == "L2-LICENSE-001" and "license =" in f.evidence:
                    lic_extract = f.evidence.split("license = ")[-1].strip("'\"")
                    pkg_licenses[f.package] = lic_extract
            policy_result = policy.apply(
                result, target, package_licenses=pkg_licenses, installed_packages=installed_pkgs
            )

            result.policy_result = policy_result


    if config.summary:
        output = _format_summary(result)
    elif config.quiet and config.format == "table":
        output = _format_quiet(result)
    elif config.format == "json":
        output = format_json(result, deterministic_output=config.deterministic_output)
    elif config.format == "sarif":
        output = format_sarif(result)
    elif config.format == "ml-context":
        output = format_ml_context(result, token_budget=config.token_budget)
    elif config.format == "cyclonedx":
        output = format_cyclonedx(result)
    elif config.format == "github":
        from picosentry.scan.formatters.github import format_github

        output = format_github(result, sarif_path=config.sarif_file)
    else:
        output = format_table(result, color=not config.no_color)


    if config.output:
        Path(config.output).write_text(output, encoding="utf-8")
        print(f"Output written to {config.output}")
    else:
        print(output)


    if args.verbose:
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
        updated_json = baseline_result.to_json(indent=2)
        baseline_path.write_text(updated_json, encoding="utf-8")
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


def _run_scan(
    args: argparse.Namespace,
    target: Path,
    file_config: PicoSentryConfig | None = None,
    merged_config: PicoSentryConfig | None = None,
) -> ScanResult:

    if merged_config is not None:
        config = merged_config
    else:
        if file_config is None:
            file_config = load_config(target)
        config = file_config.merge_cli(args)
    corpus_dir = Path(config.corpus) if config.corpus else None
    engine = create_default_engine(corpus_dir=corpus_dir, advisory_db_path=config.advisory_db)


    if args.timeout and args.timeout > 0:
        result_queue: multiprocessing.Queue = multiprocessing.Queue()

        worker = multiprocessing.Process(
            target=_scan_worker,
            args=(target, config.rules, str(corpus_dir) if corpus_dir else None, config.advisory_db, result_queue),
        )
        worker.start()
        worker.join(timeout=args.timeout)

        if worker.is_alive():
            worker.terminate()
            worker.join(timeout=1)
            raise ScanTimeout

        try:
            status, data = result_queue.get(timeout=1)
        except Exception:
            raise ScanError("failed to retrieve scan result from worker") from None
        if status == "error":
            raise ScanError(data)
        result = data
    else:
        result = engine.scan(target, rules=config.rules, advisory_db_path=config.advisory_db)


    effective_policy = _resolve_effective_policy(config=config)
    if effective_policy is not None:

        if hasattr(effective_policy, "deny_packages") and effective_policy.deny_packages:
            denied_set = set(effective_policy.deny_packages)
            result.apply_overrides(
                [f for f in result.findings if f.package not in denied_set]
            )

        if hasattr(effective_policy, "deny_licenses") and effective_policy.deny_licenses:
            denied_licenses = set(effective_policy.deny_licenses)
            result.apply_overrides(
                [f for f in result.findings if not any(lic in denied_licenses for lic in getattr(f, "licenses", []))]
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
        {k: v for k, v in sorted(config.__dict__.items()) if v is not None and v != [] and v != {} and v != ""},
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


def _verify_determinism(args: argparse.Namespace, target: Path) -> int:

    args.format = "json"
    args.output = None
    args.summary = False
    args.quiet = True  # suppress table output for both runs

    print(f"🦞 PicoSentry v{__version__} — determinism verification", file=sys.stderr)
    print(f"Target: {target}", file=sys.stderr)
    print("Running scan twice and comparing SHA-256...", file=sys.stderr)


    print("  Run 1...", file=sys.stderr)
    result_a = _run_scan(args, target)


    print("  Run 2...", file=sys.stderr)
    result_b = _run_scan(args, target)


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
    else:
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


def _handle_validate(args: argparse.Namespace, target: Path) -> int:
    output_path: Path | None = None
    if getattr(args, "output", None):
        output_path = Path(args.output)

    print(f"🦞 PicoSentry v{__version__} — validation harness", file=sys.stderr)
    print(f"Target arg ignored: {target}", file=sys.stderr)
    print("Running validation against built-in fixtures...", file=sys.stderr)

    advisory_db = getattr(args, "advisory_db", None)
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


__all__ = [
    "NAME",
    "ScanError",
    "ScanTimeout",
    "_format_quiet",
    "_format_summary",
    "_handle_validate",
    "_run_scan",
    "_scan_worker",
    "_verify_determinism",
    "add_arguments",
    "cmd",
]
