#!/usr/bin/env python3
"""
PicoSentry — CLI entry point.

Usage:
    picosentry scan ./my-project [--format json|sarif|table|ml-context]
    picosentry scan ./my-project --format ml-context --token-budget 2048
    picosentry scan ./my-project --quiet              # CI-friendly summary only
    picosentry scan ./my-project --summary            # One-line for notifications
    picosentry rules
    picosentry update
    picosentry version
    picosentry diff scan_a.json scan_b.json

Deterministic: same target + same corpus = same output. Every time.
"""

import argparse
import contextlib
import hashlib
import json
import logging
import multiprocessing
import sys
import tempfile
from pathlib import Path
from typing import Any

from picosentry.scan import __version__
from picosentry.scan.config import PicoSentryConfig, load_config
from picosentry.scan.corpus_share import (
    export_corpus_pack,
    import_corpus_pack,
    list_available_packs,
    validate_corpus_pack,
)
from picosentry.scan.engine import _resolve_effective_policy, create_default_engine
from picosentry.scan.enterprise import is_enterprise_mode
from picosentry.scan.formatters import format_cyclonedx, format_json, format_ml_context, format_sarif, format_table
from picosentry.scan.formatters.table import _PINCH_LABELS
from picosentry.scan.guards import diff_scans, verify_determinism
from picosentry.scan.logging import configure_logging
from picosentry.scan.models import Finding, ScanResult, Severity, apply_baseline, load_baseline
from picosentry.scan.workspace import scan_workspace

logger = logging.getLogger(__name__)


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
            corpus_dir=Path(corpus_dir) if corpus_dir else None, advisory_db_path=advisory_db_path
        )
        r = eng.scan(target_path, rules=rules, advisory_db_path=advisory_db_path)
        result_queue.put(("ok", r))
    except Exception as e:
        result_queue.put(("error", str(e)))


class ScanTimeout(Exception):
    pass


class ScanError(Exception):
    pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="picosentry",
        description="PicoSentry — deterministic supply-chain scanner for npm/pnpm",
    )
    parser.add_argument(
        "--log-format",
        choices=["text", "json"],
        default=None,
        help="Log output format: text (default) or json for SIEM integration",
    )
    parser.add_argument(
        "--version",
        "-V",
        action="store_true",
        help="Show PicoSentry version and exit",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a project directory for supply chain risks")
    scan_parser.add_argument("target", type=str, help="Path to project directory to scan")
    scan_parser.add_argument(
        "--format",
        "-f",
        choices=["json", "sarif", "table", "ml-context", "github", "cyclonedx"],
        default=None,
        help="Output format (default: table). 'github' writes SARIF file + prints markdown summary.",
    )
    scan_parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Write output to file instead of stdout",
    )
    scan_parser.add_argument(
        "--rules",
        "-r",
        nargs="+",
        default=None,
        help="Run only specific rules (e.g., L2-POST-001 L2-OBFS-001)",
    )
    scan_parser.add_argument(
        "--corpus",
        "-c",
        type=str,
        default=None,
        help="Path to corpus directory (default: built-in)",
    )
    scan_parser.add_argument(
        "--advisory-db",
        type=str,
        default=None,
        help="Path to OSV-format advisory database for vulnerability checking",
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output (table format only)",
    )
    scan_parser.add_argument(
        "--token-budget",
        type=int,
        default=None,
        help="Token budget for ml-context format (default: 4096)",
    )
    scan_parser.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit with code 1 if findings found, 0 if clean",
    )
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
    scan_parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Only show summary line (findings count by severity). No detailed findings.",
    )
    scan_parser.add_argument(
        "--summary",
        action="store_true",
        help="One-line summary for CI notifications (e.g. 'PicoSentry: 3 HARD PINCH, 1 SOFT PINCH'). Implies --quiet.",
    )
    scan_parser.add_argument(
        "--baseline",
        "-b",
        type=str,
        default=None,
        help="Path to baseline JSON file (previous scan output) or ignore file. Known findings are suppressed.",
    )
    scan_parser.add_argument(
        "--baseline-update",
        action="store_true",
        help="Write updated baseline file (with new findings added) after filtering. Use with --baseline.",
    )
    scan_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show per-rule timing and detailed scan progress.",
    )
    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=0,
        help="Timeout in seconds for the entire scan (0 = no timeout). Exits with code 3 on timeout.",
    )
    scan_parser.add_argument(
        "--fail-on-rule-error",
        action="store_true",
        help="Exit with code 4 if any detector rule raises an exception. Fail-closed for CI. Implied by --enterprise.",
    )
    scan_parser.add_argument(
        "--enterprise",
        action="store_true",
        help="Enable enterprise mode: fail-closed on rule errors, require auth, reject insecure defaults. Equivalent to PICOSENTRY_ENTERPRISE_MODE=1.",
    )
    scan_parser.add_argument(
        "--policy",
        "-p",
        type=str,
        default=None,
        help="Path to .picosentry-policy.yml for enterprise policy enforcement",
    )
    scan_parser.add_argument(
        "--sarif-file",
        type=str,
        default=None,
        help="Path for SARIF output file when using --format github (default: sarif.json)",
    )
    scan_parser.add_argument(
        "--verify-determinism",
        action="store_true",
        help="Run scan twice and verify SHA-256 determinism. Exit 0 if identical, 4 if different. Implies --format json.",
    )
    scan_parser.add_argument(
        "--deterministic-output",
        action="store_true",
        help="Omit timestamps, timing, and audit metadata from output for byte-stable JSON. Required for --verify-determinism and reproducible CI artifacts.",
    )

    # check command — CI-optimized health check
    check_parser = subparsers.add_parser("check", help="Quick health check for CI (exit-code only)")
    check_parser.add_argument("target", type=str, nargs="?", default=".", help="Path to project directory (default: .)")
    check_parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default="medium",
        help="Minimum severity to fail on (default: medium)",
    )
    check_parser.add_argument(
        "--rules",
        "-r",
        nargs="+",
        default=None,
        help="Run only specific rules",
    )
    check_parser.add_argument(
        "--fail-on-rule-error",
        action="store_true",
        help="Exit with code 4 if any detector rule raises an exception. Implied by --enterprise.",
    )
    check_parser.add_argument(
        "--enterprise",
        action="store_true",
        help="Enable enterprise mode: fail-closed on rule errors, require auth, reject insecure defaults.",
    )
    check_parser.add_argument(
        "--advisory-db",
        type=str,
        default=None,
        help="Path to OSV-format advisory database for vulnerability checking",
    )

    # rules command
    rules_parser = subparsers.add_parser("rules", help="List available detector rules")
    rules_parser.add_argument(
        "--json",
        "-j",
        action="store_true",
        dest="json_output",
        help="Output rules as JSON",
    )

    # version command
    subparsers.add_parser("version", help="Show PicoSentry version")

    # diff command
    diff_parser = subparsers.add_parser(
        "diff",
        help="Compare two scan JSON files for determinism verification",
    )
    diff_parser.add_argument(
        "scan_a",
        type=str,
        help="First scan JSON file (baseline)",
    )
    diff_parser.add_argument(
        "scan_b",
        type=str,
        help="Second scan JSON file (comparison)",
    )
    diff_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed diff of findings",
    )

    # init command
    init_parser = subparsers.add_parser(
        "init",
        help="Generate a .picosentry.yml configuration template in the target directory",
    )
    init_parser.add_argument(
        "target",
        type=str,
        nargs="?",
        default=".",
        help="Directory to create config file in (default: current directory)",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing config file",
    )

    # update command
    update_parser = subparsers.add_parser(
        "update",
        help="Download latest package corpus from npm registry (requires network)",
    )
    update_parser.add_argument(
        "--top",
        "-n",
        type=int,
        default=1000,
        help="Number of top packages to download (default: 1000)",
    )
    update_parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Output path for corpus JSON (default: built-in corpus)",
    )

    # workspace command
    workspace_parser = subparsers.add_parser("workspace", help="Scan entire monorepo/workspace for all npm projects")
    workspace_parser.add_argument("root", type=str, nargs="?", default=".", help="Root of monorepo (default: .)")
    workspace_parser.add_argument(
        "--format", "-f", choices=["json", "table", "summary"], default="table", help="Output format (default: table)"
    )
    workspace_parser.add_argument("--output", "-o", type=str, default=None, help="Write results to file")
    workspace_parser.add_argument("--rules", "-r", nargs="+", default=None, help="Run only specific rules")
    workspace_parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default="medium",
        help="Minimum severity to fail CI (default: medium)",
    )
    workspace_parser.add_argument("--timeout", type=int, default=0, help="Per-project timeout in seconds")
    workspace_parser.add_argument("--max-depth", type=int, default=8, help="Max directory depth for discovery")
    workspace_parser.add_argument("--quiet", "-q", action="store_true", help="Summary only")
    workspace_parser.add_argument(
        "--advisory-db",
        type=str,
        default=None,
        help="Path to OSV-format advisory database for vulnerability checking",
    )

    # corpus command
    corpus_parser = subparsers.add_parser("corpus", help="Manage custom IoC corpus packs (export/import/list)")
    corpus_sub = corpus_parser.add_subparsers(dest="corpus_action", help="Corpus actions")

    export_parser = corpus_sub.add_parser("export", help="Export custom IoCs as a shareable pack")
    export_parser.add_argument("output", type=str, help="Output file path (.json)")
    export_parser.add_argument("--name", type=str, default="my-iocs", help="Pack name")
    export_parser.add_argument("--description", type=str, default="", help="Pack description")
    export_parser.add_argument("--author", type=str, default="", help="Pack author")
    export_parser.add_argument(
        "--sign", choices=["sigstore", "minisign"], default=None, help="Cryptographically sign the pack"
    )
    export_parser.add_argument(
        "--sign-key", type=str, default="", help="Path to minisign secret key (for --sign minisign)"
    )

    import_parser = corpus_sub.add_parser("import", help="Import a corpus pack into your IoC registry")
    import_parser.add_argument("path", type=str, help="Path to corpus pack .json file")
    import_parser.add_argument("--force", action="store_true", help="Overwrite existing IoCs")
    import_parser.add_argument("--dry-run", action="store_true", help="Validate only, don't import")
    import_parser.add_argument(
        "--verify-crypto", action="store_true", help="Verify cryptographic signature (Sigstore/minisign)"
    )
    import_parser.add_argument(
        "--no-verify-crypto", action="store_true", help="Skip cryptographic signature verification"
    )
    import_parser.add_argument(
        "--public-key", type=str, default="", help="Path to minisign public key (for minisign verification)"
    )
    import_parser.add_argument("--offline", action="store_true", help="Use offline Sigstore verification")

    validate_parser = corpus_sub.add_parser("validate", help="Validate a corpus pack without importing")
    validate_parser.add_argument("path", type=str, help="Path to corpus pack .json file")

    corpus_sub.add_parser("list", help="List available corpus packs (built-in + user)")

    # corpus sign subcommand
    corpus_sign_parser = corpus_sub.add_parser("sign", help="Sign a corpus pack with cryptographic signature")
    corpus_sign_parser.add_argument("path", type=str, help="Path to corpus pack .json file to sign")
    corpus_sign_parser.add_argument(
        "--method",
        choices=["sigstore", "minisign", "digest"],
        default="digest",
        help="Signing method (default: digest-only)",
    )
    corpus_sign_parser.add_argument(
        "--secret-key", type=str, default="", help="Path to minisign secret key (for minisign method)"
    )
    corpus_sign_parser.add_argument(
        "--output", "-o", type=str, default="", help="Output path for signature file (default: <path>.sig)"
    )

    # ioc command
    ioc_parser = subparsers.add_parser("ioc", help="Manage custom IoC indicators (register/list/remove)")
    ioc_sub = ioc_parser.add_subparsers(dest="ioc_action", help="IoC actions")

    register_parser = ioc_sub.add_parser("register", help="Register a new custom IoC from a JSON file")
    register_parser.add_argument("path", type=str, help="Path to IoC .json file")
    register_parser.add_argument("--force", "-f", action="store_true", help="Overwrite existing IoC with same ID")

    ioc_sub.add_parser("list", help="List all user-registered custom IoCs")

    remove_parser = ioc_sub.add_parser("remove", help="Remove a custom IoC by ID")
    remove_parser.add_argument("id", type=str, help="IoC ID to remove")

    # policy command
    policy_parser = subparsers.add_parser("policy", help="Manage enterprise policy bundles (fetch/push/init)")
    policy_sub = policy_parser.add_subparsers(dest="policy_action", help="Policy actions")

    fetch_parser = policy_sub.add_parser("fetch", help="Fetch signed policy bundle from central URL")
    fetch_parser.add_argument("url", type=str, help="URL to fetch policy from")
    fetch_parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=".picosentry-policy.yml",
        help="Output path (default: .picosentry-policy.yml)",
    )
    fetch_parser.add_argument("--no-verify", action="store_true", help="Skip digest verification")
    fetch_parser.add_argument(
        "--verify-crypto", action="store_true", help="Verify cryptographic signature on policy bundle"
    )
    fetch_parser.add_argument(
        "--public-key", type=str, default="", help="Path to minisign public key (for minisign verification)"
    )
    fetch_parser.add_argument("--offline", action="store_true", help="Use offline Sigstore verification")

    push_parser = policy_sub.add_parser("push", help="Push policy bundle to central server")
    push_parser.add_argument("url", type=str, help="Upload endpoint URL")
    push_parser.add_argument(
        "--file", "-f", type=str, default=".picosentry-policy-bundle.json", help="Policy bundle file to push"
    )
    push_parser.add_argument("--api-key", type=str, default="", help="API key for authentication")

    policy_sub.add_parser("init", help="Generate .picosentry-org.yml template for central management")

    # advisories command
    adv_parser = subparsers.add_parser("advisories", help="Manage advisory database (fetch)")
    adv_sub = adv_parser.add_subparsers(dest="adv_action", help="Advisory actions")

    adv_fetch = adv_sub.add_parser("fetch", help="Download advisory database from central URL")
    adv_fetch.add_argument("url", type=str, help="URL to advisory database (zip or JSON)")
    adv_fetch.add_argument(
        "--output", "-o", type=str, default=None, help="Output directory (default: $PICOADVISORY_DIR)"
    )
    adv_fetch.add_argument(
        "--verify-crypto", action="store_true", help="Verify cryptographic signature on advisory bundle"
    )
    adv_fetch.add_argument(
        "--public-key", type=str, default="", help="Path to minisign public key (for minisign verification)"
    )
    adv_fetch.add_argument("--offline", action="store_true", help="Use offline Sigstore verification")

    # daemon command
    daemon_parser = subparsers.add_parser("daemon", help="Start HTTP daemon for health checks and metrics")
    daemon_parser.add_argument("--port", "-p", type=int, default=9090, help="Listen port (default: 9090)")
    daemon_parser.add_argument("--host", "-H", type=str, default="127.0.0.1", help="Listen host (default: 127.0.0.1)")
    daemon_parser.add_argument(
        "--auth-mode",
        type=str,
        choices=["off", "token", "oidc"],
        default=None,
        help="Auth mode: off (default), token, or oidc",
    )
    daemon_parser.add_argument("--auth-token", type=str, default=None, help="Static bearer token (token auth mode)")
    daemon_parser.add_argument(
        "--rate-limit", type=float, default=None, help="Max requests per second per IP (0=unlimited)"
    )
    daemon_parser.add_argument(
        "--enterprise",
        action="store_true",
        help="Enable enterprise mode: refuse auth=off, require explicit host binding, fail-closed defaults.",
    )
    daemon_parser.add_argument(
        "--tls-cert",
        type=str,
        default=None,
        help="Path to TLS certificate file (PEM format) for HTTPS daemon.",
    )
    daemon_parser.add_argument(
        "--tls-key",
        type=str,
        default=None,
        help="Path to TLS private key file (PEM format) for HTTPS daemon.",
    )
    daemon_parser.add_argument(
        "--mtls-ca",
        type=str,
        default=None,
        help="Path to CA certificate for mutual TLS client verification.",
    )

    # cache command
    cache_parser = subparsers.add_parser("cache", help="Manage scan result cache")
    cache_sub = cache_parser.add_subparsers(dest="cache_command", help="Cache commands")

    cache_sub.add_parser("stats", help="Show cache statistics")
    cache_purge = cache_sub.add_parser("purge", help="Purge cache entries by age or hash")
    cache_purge.add_argument("--age-days", type=int, default=0, help="Purge entries older than N days")
    cache_purge.add_argument("--corpus-hash", type=str, default="", help="Purge entries matching corpus hash")
    cache_purge.add_argument("--lockfile-hash", type=str, default="", help="Purge entries matching lockfile hash")
    cache_sub.add_parser("wipe", help="Wipe the entire cache")

    # metrics command
    metrics_parser = subparsers.add_parser("metrics", help="Print current metrics as JSON")
    metrics_parser.add_argument(
        "--format", choices=["json", "prometheus"], default="json", help="Output format (default: json)"
    )

    # benchmark command — detection quality metrics
    benchmark_parser = subparsers.add_parser("benchmark", help="Show detection quality metrics and known limitations")
    benchmark_parser.add_argument(
        "--rule", type=str, default="", help="Show metrics for a specific rule ID (default: all rules)"
    )
    benchmark_parser.add_argument(
        "--family", type=str, default="", help="Filter by rule family (e.g. typosquat, obfuscation)"
    )
    benchmark_parser.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")
    benchmark_parser.add_argument("--limitations", action="store_true", help="Show known limitations per detector")
    benchmark_parser.add_argument("--noisy", action="store_true", help="Show only noisy rules (high FP rate)")

    args = parser.parse_args(argv)

    # Configure structured logging for SIEM integration
    if hasattr(args, "log_format") and args.log_format == "json":
        configure_logging(log_format="json")

    if args.version:
        from picosentry.scan.rules import RULE_INFO

        engine = create_default_engine()
        print(f"picosentry v{__version__}")
        print(f"corpus: {engine._corpus_version}")
        print(f"rules:  {len(RULE_INFO)} ({len(engine.list_rules())} detector functions)")
        return 0

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "version":
        from picosentry.scan.rules import RULE_INFO

        engine = create_default_engine()
        print(f"picosentry v{__version__}")
        print(f"corpus: {engine._corpus_version}")
        print(f"rules:  {len(RULE_INFO)} ({len(engine.list_rules())} detector functions)")
        return 0

    if args.command == "diff":
        return _cmd_diff(args)

    if args.command == "check":
        return _cmd_check(args)
    elif args.command == "rules":
        from picosentry.scan.rules import RULE_INFO

        # Show ALL rule IDs from RULE_INFO (includes sub-rules like OBFS-002/003/004)
        # not just engine-registered detector functions
        rule_ids = sorted(RULE_INFO.keys())
        if args.json_output:
            rules_data = []
            for rule_id in rule_ids:
                info = RULE_INFO[rule_id]
                rules_data.append(
                    {
                        "rule_id": rule_id,
                        "name": info.get("name", ""),
                        "description": info.get("description", ""),
                        "severity": info.get("severity", ""),
                        "category": info.get("category", ""),
                        "helpUri": info.get("helpUri", ""),
                    }
                )
            print(json.dumps(rules_data, indent=2, sort_keys=False))
        else:
            print(f"Available detector rules ({len(rule_ids)}):\n")
            for rule_id in rule_ids:
                info = RULE_INFO[rule_id]
                desc = info.get("description", "No description")
                sev = info.get("severity", "?")
                cat = info.get("category", "?")
                name = info.get("name", "?")
                print(f"  {rule_id}  {name:<25} [{sev:>8}]  {desc}  ({cat})")
        return 0

    if args.command == "init":
        return _cmd_init(args)

    if args.command == "daemon":
        from picosentry.scan.auth import AuthConfig
        from picosentry.scan.daemon import run_daemon
        from picosentry.scan.enterprise import is_enterprise_mode

        # Build auth config from CLI flags + env
        auth_config = AuthConfig.from_env()
        if getattr(args, "auth_mode", None) is not None:
            auth_config.mode = args.auth_mode
        if getattr(args, "auth_token", None) is not None:
            auth_config.token = args.auth_token
        if getattr(args, "rate_limit", None) is not None:
            auth_config.rate_limit_rps = args.rate_limit

        # Enterprise mode: --enterprise flag or env var
        if getattr(args, "enterprise", False) and not is_enterprise_mode():
            import os

            os.environ["PICOSENTRY_ENTERPRISE_MODE"] = "1"

        # Resolve TLS configuration
        from picosentry.scan.daemon import TLSConfig

        tls_config = TLSConfig(
            cert_file=getattr(args, "tls_cert", None) or "",
            key_file=getattr(args, "tls_key", None) or "",
            mtls_ca=getattr(args, "mtls_ca", None) or "",
        )
        run_daemon(args.host, args.port, auth_config=auth_config, tls_config=tls_config)
        return 0
    if args.command == "cache":
        from picosentry.scan.cache import ScanCache
        from picosentry.scan.config import load_config

        cache_config = load_config(Path(args.target) if hasattr(args, "target") and args.target else Path.cwd())
        cache = ScanCache(
            cache_dir=Path(cache_config.cache_dir) if cache_config.cache_dir else None,
            max_entries=cache_config.cache_max_entries,
            max_size_mb=cache_config.cache_max_size_mb,
            ttl=cache_config.cache_ttl_seconds,
        )
        subcmd = getattr(args, "cache_command", None)

        if subcmd == "stats":
            stats = cache.stats()
            print(f"Cache directory: {stats['cache_dir']}")
            print(f"Entries: {stats['entries']}")
            print(f"Size: {stats['size_mb']} MB ({stats['size_bytes']} bytes)")
            print(f"TTL: {stats['ttl_seconds']}s")
            print(f"Max entries: {stats['max_entries']} (0=unlimited)")
            print(f"Max size: {stats['max_size_mb']} MB (0=unlimited)")
        elif subcmd == "purge":
            removed = cache.purge(
                age_days=getattr(args, "age_days", 0),
                corpus_hash=getattr(args, "corpus_hash", ""),
                lockfile_hash=getattr(args, "lockfile_hash", ""),
            )
            print(f"Purged {removed} cache entries")
        elif subcmd == "wipe":
            removed = cache.wipe()
            print(f"Wiped {removed} cache entries")
        else:
            cache_parser.print_help()
        return 0
    if args.command == "metrics":
        from picosentry.scan.metrics import get_metrics

        snapshot = get_metrics().snapshot()
        if args.format == "prometheus":
            print(snapshot.to_prometheus())
        else:
            print(snapshot.to_json())
        return 0

    if args.command == "benchmark":
        from picosentry.scan.detection_quality import DetectionBenchmark

        bench = DetectionBenchmark()
        rule_id = getattr(args, "rule", "")
        family = getattr(args, "family", "")
        json_output = getattr(args, "json_output", False)
        show_limitations = getattr(args, "limitations", False)
        noisy_only = getattr(args, "noisy", False)

        if json_output:
            print(bench.to_json())
            return 0

        # Show noisy rules
        if noisy_only:
            noisy = bench.get_noisy_rules()
            if not noisy:
                print("No noisy rules found.")
                return 0
            print(f"Noisy rules ({len(noisy)}):\n")
            for m in noisy:
                print(
                    f"  {m.rule_id:<18} {m.rule_family:<15} P={m.precision:.2f}  R={m.recall:.2f}  FP_rate={m.fp_rate:.2f}"
                )
                print(f"    Suppressed by default: {m.suppressed_by_default}")
            return 0

        # Show limitations
        if show_limitations:
            limitations = bench.get_limitations(rule_id=rule_id)
            if not limitations:
                print("No known limitations found.")
                return 0
            print(f"Known limitations ({len(limitations)}):\n")
            for lim in limitations:
                print(f"  {lim.rule_id:<18} [{lim.category}] {lim.description}")
                if lim.workaround:
                    print(f"    Workaround: {lim.workaround}")
            return 0

        # Show specific rule
        if rule_id:
            metrics = bench.get_metrics(rule_id)
            if not metrics:
                print(f"No metrics found for rule {rule_id}")
                return 1
            for _, m in metrics.items():
                print(f"Rule:       {m.rule_id}")
                print(f"Family:     {m.rule_family}")
                print(f"Precision:  {m.precision:.4f}")
                print(f"Recall:     {m.recall:.4f}")
                print(f"F1:         {m.f1:.4f}")
                print(f"TP/FP/FN:   {m.true_positives}/{m.false_positives}/{m.false_negatives}")
                print(f"Noisy:      {m.noisy}")
                print(f"Suppressed: {m.suppressed_by_default}")
            return 0

        # Show family filter
        if family:
            families = bench.get_metrics_by_family()
            fam_rules = families.get(family, [])
            if not fam_rules:
                print(f"No rules found for family '{family}'")
                return 1
            print(f"\nDetection quality - {family} family ({len(fam_rules)} rules):\n")
            print(f"{'Rule ID':<18} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Noisy':>6}")
            print("-" * 58)
            for m in fam_rules:
                print(
                    f"{m.rule_id:<18} {m.precision:>10.4f} {m.recall:>10.4f} {m.f1:>10.4f} {'Yes' if m.noisy else 'No':>6}"
                )
            return 0

        # Show overall benchmark
        quality = bench.overall_quality()
        print("\nPicoSentry Detection Quality Benchmark")
        print("=" * 45)
        print(f"  Version:       {quality['version']}")
        print(f"  Rules:         {quality['rules']}")
        print(f"  Overall P:     {quality['overall_precision']:.4f}")
        print(f"  Overall R:     {quality['overall_recall']:.4f}")
        print(f"  Overall F1:    {quality['overall_f1']:.4f}")
        print(f"  Noisy rules:   {quality['noisy_rules']}")
        print(f"  Limitations:   {quality['known_limitations']}")
        print()
        print("Per-rule metrics:")
        print(f"  {'Rule ID':<18} {'Family':<15} {'P':>6} {'R':>6} {'F1':>6} {'Noisy':>6}")
        print("  " + "-" * 62)
        metrics = bench.get_metrics()
        for _rid, m in sorted(metrics.items()):
            noisy_flag = "Yes" if m.noisy else ""
            print(
                f"  {m.rule_id:<18} {m.rule_family:<15} {m.precision:>6.2f} {m.recall:>6.2f} {m.f1:>6.2f} {noisy_flag:>6}"
            )
        return 0
    if args.command == "corpus":
        return _cmd_corpus(args)

    if args.command == "ioc":
        return _cmd_ioc(args)

    if args.command == "workspace":
        return _cmd_workspace(args)

    if args.command == "policy":
        return _cmd_policy(args)

    if args.command == "advisories":
        return _cmd_advisories(args)

    if args.command == "update":
        return _cmd_update(args)

    if args.command == "scan":
        return _cmd_scan(args)

    return 0


def _cmd_corpus(args: argparse.Namespace) -> int:
    """Manage custom IoC corpus packs."""
    if not args.corpus_action:
        print("Usage: picosentry corpus {export|import|validate|list}")
        return 2

    if args.corpus_action == "list":
        packs = list_available_packs()
        if not packs:
            print("No corpus packs found.")
            return 0
        print("Available corpus packs:")
        print()
        for p in packs:
            source_tag = "[built-in]" if p["source"] == "built-in" else "[user]"
            print("  {:<25s} {}  {} IoC(s)".format(p["name"], source_tag, p["ioc_count"]))
            if p.get("description"):
                print("    {}".format(p["description"]))
            if p.get("file"):
                print("    {}".format(p["file"]))
        return 0

    elif args.corpus_action == "export":
        output = Path(args.output)
        try:
            pack = export_corpus_pack(
                output,
                name=args.name,
                description=args.description,
                author=args.author,
                sign_method=args.sign or "",
                sign_secret_key=args.sign_key,
            )
        except OSError as e:
            print(f"Error exporting corpus pack: {e}", file=sys.stderr)
            return 1
        print(f"Exported {len(pack.iocs)} IoC(s) to {output}")
        print(f"Pack ID: {pack.pack_id}")
        print(f"Format: v{pack.version}")
        print()
        print("Share this file with your team or organization.")
        print(f"Import with: picosentry corpus import {output}")
        return 0

    elif args.corpus_action == "import":
        path = Path(args.path)
        if not path.exists():
            print(f"Error: file not found: {path}", file=sys.stderr)
            return 2
        try:
            stats = import_corpus_pack(
                path,
                allow_overwrite=args.force,
                dry_run=args.dry_run,
                verify_crypto=args.verify_crypto and not args.no_verify_crypto,
                public_key=args.public_key,
                offline=args.offline,
            )
        except (ValueError, OSError, FileNotFoundError) as e:
            print(f"Error importing corpus pack: {e}", file=sys.stderr)
            return 1
        print("Import results for: {}".format(stats["pack_name"]))
        print("  Total IoCs in pack: {}".format(stats["total"]))
        print("  Imported: {}".format(stats["imported"]))
        print("  Skipped (already exists): {}".format(stats["skipped"]))
        if stats["errors"] > 0:
            print("  Errors: {}".format(stats["errors"]))
            for err in stats["error_details"]:
                print(f"    - {err}")
        return 1 if stats["errors"] else 0

    elif args.corpus_action == "validate":
        path = Path(args.path)
        if not path.exists():
            print(f"Error: file not found: {path}", file=sys.stderr)
            return 2
        result = validate_corpus_pack(path)
        if result["valid"]:
            print("Corpus pack is VALID")
            print("  Name: {}".format(result["pack_name"]))
            print("  IoCs: {}".format(result["ioc_count"]))
            if result["warnings"]:
                for w in result["warnings"]:
                    print(f"  Warning: {w}")
            return 0
        else:
            print("Corpus pack is INVALID")
            for err in result["errors"]:
                print(f"  Error: {err}")
            return 1

    elif args.corpus_action == "sign":
        from picosentry.scan.crypto import content_digest, sign_content, write_detached_signature

        path = Path(args.path)
        if not path.exists():
            print(f"Error: file not found: {path}", file=sys.stderr)
            return 2

        method = args.method
        output = Path(args.output) if args.output else path.with_suffix(path.suffix + ".sig")

        content_bytes = path.read_bytes()
        print(f"Signing {path} ({len(content_bytes)} bytes) using {method} method...")

        if method == "digest":
            digest = content_digest(content_bytes)
            print(f"Content digest: sha256:{digest}")
            print(f"Digest-only signature written to {output}")
            # Write a digest-only signature bundle
            import json

            sig_bundle = {
                "provider": "digest",
                "digest": f"sha256:{digest}",
                "signed_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
                "content_path": str(path.name),
            }
            output.write_text(json.dumps(sig_bundle, indent=2, sort_keys=True), encoding="utf-8")
            return 0

        try:
            signature = sign_content(
                content_bytes,
                method=method,
                secret_key=args.secret_key or "",
            )
            sig_path = write_detached_signature(signature, path)
            print(f"Signed: {path}")
            print(f"Signature: {sig_path}")
            print(f"Provider: {signature.provider}")
            print(f"Signer: {signature.signer_identity}")
            print(f"Digest: sha256:{signature.digest[:16]}")
            return 0
        except Exception as e:
            print(f"Error signing corpus pack: {e}", file=sys.stderr)
            return 1

    return 0


def _cmd_ioc(args: argparse.Namespace) -> int:
    """Manage custom IoC indicators."""
    from picosentry.scan.ioc_registry import list_custom_iocs, register_ioc, remove_ioc

    if not args.ioc_action:
        print("Usage: picosentry ioc {register|list|remove}")
        return 1

    if args.ioc_action == "list":
        iocs = list_custom_iocs()
        if not iocs:
            print("No custom IoCs registered.")
            return 0
        print(f"Custom IoCs ({len(iocs)}):")
        for ioc in iocs:
            print(f"  {ioc.id}  {ioc.package_name:30s}  [{ioc.severity}]  {ioc.name}")
        return 0

    elif args.ioc_action == "register":
        path = Path(args.path)
        if not path.exists():
            print(f"Error: IoC file not found: {path}", file=sys.stderr)
            return 2
        if path.suffix.lower() != ".json":
            print(f"Error: IoC file must be JSON, got: {path.suffix}", file=sys.stderr)
            return 2
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            record = register_ioc(data, allow_overwrite=args.force)
            print(f"Registered IoC: {record.id} ({record.name})")
            print(f"  Package: {record.package_name}")
            print(f"  Type:    {record.ioc_type}")
            print(f"  Severity: {record.severity}")
        except (json.JSONDecodeError, FileExistsError, ValueError) as e:
            print(f"Error registering IoC: {e}", file=sys.stderr)
            return 1
        return 0

    elif args.ioc_action == "remove":
        try:
            found = remove_ioc(args.id)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        if found:
            print(f"Removed IoC: {args.id}")
        else:
            print(f"IoC not found: {args.id}")
            return 1
        return 0

    return 0


def _cmd_policy(args: argparse.Namespace) -> int:
    """Manage enterprise policy bundles."""
    if not args.policy_action:
        print("Usage: picosentry policy {fetch|push|init}")
        return 1

    if args.policy_action == "init":
        from picosentry.scan.management import org_config_template

        org_path = Path(".picosentry-org.yml")
        if org_path.exists():
            print(f"Error: {org_path} already exists. Remove it first or edit it directly.", file=sys.stderr)
            return 1
        org_path.write_text(org_config_template(), encoding="utf-8")
        print(f"Created {org_path}")
        print("Edit this file to configure central policy and advisory URLs for your organization.")
        return 0

    elif args.policy_action == "fetch":
        from picosentry.scan.management import fetch_policy

        output = Path(args.output)
        try:
            fetch_policy(args.url, output, verify=not args.no_verify)
            if args.verify_crypto:
                from picosentry.scan.policy import import_policy_bundle

                import_policy_bundle(
                    output, verify=True, verify_crypto=True, public_key=args.public_key, offline=args.offline
                )
                print("Cryptographic signature verified.")
            print(f"Policy bundle saved to {output}")
            print(f"Apply with: picosentry scan . --policy {output}")
        except Exception as e:
            print(f"Error fetching policy: {e}", file=sys.stderr)
            return 1
        return 0

    elif args.policy_action == "push":
        from picosentry.scan.management import push_policy

        policy_path = Path(args.file)
        if not policy_path.exists():
            print(f"Error: policy bundle not found: {policy_path}", file=sys.stderr)
            return 2
        try:
            push_policy(args.url, policy_path, api_key=args.api_key)
            print("Policy bundle pushed successfully.")
        except Exception as e:
            print(f"Error pushing policy: {e}", file=sys.stderr)
            return 1
        return 0

    return 0


def _cmd_advisories(args: argparse.Namespace) -> int:
    """Manage advisory database."""
    if not args.adv_action:
        print("Usage: picosentry advisories {fetch}")
        return 1

    if args.adv_action == "fetch":
        from picosentry.scan.advisory import default_advisory_dir
        from picosentry.scan.management import fetch_advisories

        output_dir = Path(args.output) if args.output else default_advisory_dir()
        try:
            count = fetch_advisories(
                args.url,
                output_dir,
                verify_crypto=args.verify_crypto,
                public_key=args.public_key,
                offline=args.offline,
            )
            print(f"Loaded {count} advisories into {output_dir}")
            print(f"Scan with: picosentry scan . --advisory-db {output_dir}")
        except Exception as e:
            print(f"Error fetching advisories: {e}", file=sys.stderr)
            return 1
        return 0

    return 0


def _cmd_workspace(args: argparse.Namespace) -> int:
    """Scan an entire monorepo workspace."""
    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"Error: {root} is not a directory", file=sys.stderr)
        return 2

    if not args.quiet:
        if args.format == "json":
            print(f"Scanning workspace: {root}", file=sys.stderr)
            print("Discovering projects...", file=sys.stderr)
        else:
            print(f"Scanning workspace: {root}")
            print("Discovering projects...")

    from picosentry.scan.workspace import discover_pnpm_workspace, discover_projects

    projects = discover_pnpm_workspace(root)
    if not projects:
        projects = discover_projects(root, max_depth=args.max_depth)

    if not projects:
        print("No npm/pnpm projects found in workspace.")
        return 1

    if args.format == "json" and not args.quiet:
        print(f"Found {len(projects)} project(s)", file=sys.stderr)
    elif not args.quiet:
        print(f"Found {len(projects)} project(s)")

    advisory_db = getattr(args, "advisory_db", None)
    engine = create_default_engine(advisory_db_path=advisory_db)
    config = load_config(root)

    wr = scan_workspace(
        root,
        engine=engine,
        config=config,
        rules=args.rules,
        fail_on=args.fail_on,
        timeout=args.timeout,
    )

    if args.format == "json":
        data = {
            "workspace_root": str(root),
            "summary": wr.to_dict(),
            "projects": wr.results,
        }
        output = json.dumps(data, indent=2, sort_keys=True)
    elif args.format == "summary" or args.quiet:
        output = f"Workspace: {wr.scanned_projects}/{wr.total_projects} projects, {wr.total_findings} findings, {wr.failed_projects} failed ({wr.duration_ms}ms)"
    else:
        lines = ["PicoSentry Workspace Scan"]
        lines.append(f"Root: {root}")
        lines.append(
            f"Projects: {wr.total_projects} discovered, {wr.scanned_projects} scanned, {wr.failed_projects} failed"
        )
        lines.append(f"Total findings: {wr.total_findings} | Duration: {wr.duration_ms}ms")
        lines.append("")
        header = "{:<45s} {:>8s}  {:<12s}".format("Project", "Findings", "Status")
        lines.append(header)
        lines.append("-" * 67)
        for proj_path in sorted(wr.results.keys()):
            result: Any = wr.results[proj_path]
            findings = len(result.get("findings", []))
            status = "OK" if findings == 0 else f"{findings} finding(s)"
            proj_name = str(Path(proj_path).name) if "/" in proj_path else proj_path
            lines.append(f"{proj_name[:45]:<45s} {findings:>8d}  {status:<12s}")
        if wr.errors:
            lines.append("")
            lines.append("Errors:")
            for err in wr.errors:
                lines.append(f"  * {err}")
        output = "\n".join(lines)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Output written to {args.output}")
    else:
        print(output)

    # Return non-zero on scan failures (projects that errored out)
    if wr.failed_projects > 0:
        return 2

    # Apply fail_on logic to exit code
    if args.fail_on:
        severity_order = __import__("picosentry.scan.models", fromlist=["SEVERITY_ORDER"]).SEVERITY_ORDER
        min_level = severity_order[args.fail_on.lower()]
        all_findings: list[dict] = []
        for proj_result in wr.results.values():
            proj_result_typed: Any = proj_result
            all_findings.extend(proj_result_typed.get("findings", []))
        has_fail_findings = any(
            severity_order.get(f.get("severity", "info").lower(), 4) <= min_level for f in all_findings
        )
        return 1 if has_fail_findings else 0
    return 1 if wr.total_findings > 0 else 0


def _cmd_diff(args: argparse.Namespace) -> int:
    """Compare two scan JSON files for determinism verification.

    Delegates to guards.diff_scans for the actual comparison logic.
    Exits 0 if identical, 1 if different. Prints summary of differences.
    """
    path_a = Path(args.scan_a)
    path_b = Path(args.scan_b)
    verbose = getattr(args, "verbose", False)

    exit_code, output = diff_scans(path_a, path_b, verbose=verbose)
    print(output)
    return exit_code


def _cmd_init(args: argparse.Namespace) -> int:
    """Generate a .picosentry.yml configuration template.

    Creates a well-documented config file with all available options
    commented out, so users can uncomment what they need.
    """
    target = Path(args.target).resolve()

    if not target.is_dir():
        print(f"Error: {target} is not a directory", file=sys.stderr)
        return 2

    config_path = target / ".picosentry.yml"

    if config_path.exists() and not args.force:
        print(f"Error: {config_path} already exists. Use --force to overwrite.", file=sys.stderr)
        return 1

    template = """# PicoSentry configuration file
# https://github.com/KirkForge/PicoSentry/blob/main/picosentry/README.md
#
# Config file values are defaults; CLI flags override them.
# Deterministic: same config + same target + same corpus = same output.

version: 1

# Output format: json, sarif, table, ml-context, github
# 'github' writes SARIF file + prints markdown summary for GitHub Actions
# format: json

# Disable colored output
# no_color: false

# Exit with code 1 if findings found
# exit_code: true

# Only fail CI on HIGH or above
# fail_on: high

# Suppress known findings from previous scan
# baseline: baseline.json

# Token budget for ml-context format (default: 4096)
# token_budget: 4096

# SARIF output path for --format github (default: sarif.json)
# sarif_file: sarif.json

# Severity overrides — downgrade/upgrade rule severity
# severity_overrides:
#   L2-PROV-001: INFO
#   L2-FORK-001: LOW

# Ignore specific packages (skip all findings for these)
# ignore_packages:
#   - left-pad
#   - core-js

# Ignore paths matching glob patterns
# ignore_paths:
#   - 'vendor/**'
#   - '**/test/**'

# Run only specific rules
# rules:
#   - L2-POST-001
#   - L2-TYPO-001
#   - L2-OBFS-001
"""

    config_path.write_text(template, encoding="utf-8")
    print(f"Created {config_path}")

    # Also generate policy template if requested or if --policy flag
    policy_path = target / ".picosentry-policy.yml"
    if not policy_path.exists() or args.force:
        from picosentry.scan.policy import default_policy_template

        policy_path.write_text(default_policy_template(), encoding="utf-8")
        print(f"Created {policy_path}")

    print("Edit the files to configure PicoSentry for this project.")
    return 0


def _cmd_update(args: argparse.Namespace) -> int:
    """Download latest top-N npm packages for the typosquat corpus.

    This is the ONLY command that makes network requests.
    The corpus is saved to the user data directory (not inside the
    installed package), so it works without root/venv write access.
    """
    import urllib.request

    from picosentry.scan._network import InsecureURLError, ResponseTooLargeError, safe_urlopen
    from picosentry.scan.engine import user_corpus_dir

    top_n = args.top
    default_output = user_corpus_dir() / "npm_top_packages.json"
    output_path = Path(args.output) if args.output else default_output

    print(f"Fetching top {top_n} npm packages from registry...")

    try:
        # Use npm registry search API to get most depended-on packages
        # Paginate through results
        all_packages = set()
        page_size = 250
        seen = 0

        while seen < top_n:
            url = f"https://registry.npmjs.org/-/v1/search?size={page_size}&from={seen}&text=not:unpopular"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            try:
                resp, body = safe_urlopen(req, timeout=30)
            except (InsecureURLError, ResponseTooLargeError) as e:
                print(f"Error: {e}", file=sys.stderr)
                return 1
            try:
                data = json.loads(body.decode("utf-8"))
            finally:
                resp.close()

            if not isinstance(data, dict) or "objects" not in data:
                print("Error: unexpected registry response format", file=sys.stderr)
                return 1

            for pkg in data.get("objects", []):
                name = pkg.get("package", {}).get("name", "")
                if name and not name.startswith("@"):
                    all_packages.add(name)

            total = data.get("total", 0)
            seen += page_size
            if seen >= total or seen >= top_n:
                break

        packages = sorted(all_packages)[:top_n]

        # Merge with existing corpus
        existing = set()
        if output_path.is_file():
            with contextlib.suppress(json.JSONDecodeError, OSError):
                existing = set(json.loads(output_path.read_text(encoding="utf-8")))

        merged = sorted(existing | set(packages))

        # Write
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(merged, indent=4, ensure_ascii=False), encoding="utf-8")

        print(f"Corpus updated: {len(merged)} packages ({len(packages)} new from npm, {len(existing)} existing)")
        print(f"Saved to: {output_path}")
        print(f"Corpus version hash: {hashlib.sha256(json.dumps(merged, sort_keys=True).encode()).hexdigest()[:16]}")
        return 0

    except Exception as e:
        print(f"Error updating corpus: {e}", file=sys.stderr)
        print("Falling back to built-in corpus.", file=sys.stderr)
        return 1


def _format_summary(result: ScanResult) -> str:
    """One-line summary for CI notifications.

    Example: PicoSentry: 3 HARD PINCH, 1 SOFT PINCH, 2 NUDGE
    Or:      PicoSentry: No pinches. All clear.
    """
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
    """Quiet mode — summary + finding count per rule, no details.

    Designed for CI logs where you want a quick overview without the full table.
    """
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


def _verify_determinism(args: argparse.Namespace, target: Path) -> int:
    """Run scan twice and verify SHA-256 determinism.

    Delegates to guards.verify_determinism for the actual comparison.
    Exit 0 if deterministic, 4 if not.
    """
    # Override format to json for deterministic comparison
    args.format = "json"
    args.output = None
    args.summary = False
    args.quiet = True  # suppress table output for both runs

    print(f"🦞 PicoSentry v{__version__} — determinism verification", file=sys.stderr)
    print(f"Target: {target}", file=sys.stderr)
    print("Running scan twice and comparing SHA-256...", file=sys.stderr)

    # First scan
    print("  Run 1...", file=sys.stderr)
    result_a = _run_scan(args, target)

    # Second scan
    print("  Run 2...", file=sys.stderr)
    result_b = _run_scan(args, target)

    # Compare using guards module
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

        # Write both JSONs to temp files for diff
        json_a = format_json(result_a, deterministic_output=True)
        json_b = format_json(result_b, deterministic_output=True)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", prefix="picosentry_a_", delete=False) as fa:
            fa.write(json_a)
            path_a = fa.name
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", prefix="picosentry_b_", delete=False) as fb:
            fb.write(json_b)
            path_b = fb.name

        print(f"  Diff: picosentry diff {path_a} {path_b}", file=sys.stderr)

        # Show finding count diff
        if len(result_a.findings) != len(result_b.findings):
            print(f"  findings: {len(result_a.findings)} vs {len(result_b.findings)}", file=sys.stderr)
        else:
            print(f"  findings: {len(result_a.findings)} (same count, different content)", file=sys.stderr)

        return 4


def _run_scan(
    args: argparse.Namespace,
    target: Path,
    file_config: PicoSentryConfig | None = None,
    merged_config: PicoSentryConfig | None = None,
) -> ScanResult:
    """Run a single scan and return the ScanResult (no output formatting).

    Applies severity overrides, ignore filters, and severity threshold.
    Does NOT apply baseline filtering — the caller handles baseline
    since it needs pre-baseline findings for --baseline-update.
    """

    # Use pre-merged config if provided, otherwise load and merge
    if merged_config is not None:
        config = merged_config
    else:
        if file_config is None:
            file_config = load_config(target)
        config = file_config.merge_cli(args)
    corpus_dir = Path(config.corpus) if config.corpus else None
    engine = create_default_engine(corpus_dir=corpus_dir, advisory_db_path=config.advisory_db)

    # Cross-platform timeout using multiprocessing (works on Windows, macOS, Linux)
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

    # Resolve effective policy via PolicyStack (global → org → repo → pipeline)
    effective_policy = _resolve_effective_policy(config=config)
    if effective_policy is not None:
        # Apply policy deny_packages filter
        if hasattr(effective_policy, "deny_packages") and effective_policy.deny_packages:
            denied_set = set(effective_policy.deny_packages)
            result.apply_overrides(
                [f for f in result.findings if f.package not in denied_set]
            )
        # Apply policy deny_licenses filter
        if hasattr(effective_policy, "deny_licenses") and effective_policy.deny_licenses:
            denied_licenses = set(effective_policy.deny_licenses)
            result.apply_overrides(
                [f for f in result.findings if not any(lic in denied_licenses for lic in getattr(f, "licenses", []))]
            )

    # Apply severity overrides
    if config.severity_overrides:
        result.apply_overrides(config.apply_severity_overrides(result.findings))

    # Apply ignore filters
    if config.ignore_packages or config.ignore_paths:
        result.apply_overrides(
            [
                f
                for f in result.findings
                if not config.should_ignore_package(f.package) and not config.should_ignore_path(f.file)
            ]
        )

    # Severity filtering
    from picosentry.scan.models import SEVERITY_ORDER
    if config.severity_threshold:
        threshold = config.severity_threshold
        min_level = SEVERITY_ORDER.get(threshold.lower(), 0)
        result.apply_overrides(
            [f for f in result.findings if SEVERITY_ORDER.get(f.severity.value.lower(), 4) <= min_level]
        )

    # Populate config and policy digests for enterprise evidence
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


def _cmd_check(args: argparse.Namespace) -> int:
    """Execute the 'check' subcommand — CI-optimized health check.

    Returns 0 if clean, 1 if findings at or above fail-on severity.
    No output except on failure (stderr). Designed for CI gates.
    """
    from pathlib import Path

    target = Path(args.target).resolve()

    if not target.exists():
        print(f"picosentry check: target not found: {target}", file=sys.stderr)
        return 2

    advisory_db = getattr(args, "advisory_db", None)
    engine = create_default_engine(advisory_db_path=advisory_db)
    result = engine.scan(str(target), rules=args.rules, advisory_db_path=advisory_db)

    from picosentry.scan.models import SEVERITY_ORDER
    severity_order = dict(SEVERITY_ORDER)
    fail_level = severity_order[args.fail_on.lower()]

    # Check for rule failures — check ALWAYS fails closed
    failed_rules = [r for r in result.rule_executions if r.status == "failed"]
    if failed_rules:
        for r in failed_rules:
            print(f"Rule {r.rule_id} FAILED: {r.error}", file=sys.stderr)
        return 4

    violations = [f for f in result.findings if severity_order.get(f.severity.value.lower(), 4) <= fail_level]

    if violations:
        sev_counts: dict[str, int] = {}
        for f in violations:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
        summary = ", ".join(f"{c} {s}" for s, c in sorted(sev_counts.items()))
        print(f"picosentry check: {len(violations)} finding(s) at {args.fail_on}+ ({summary})", file=sys.stderr)
        return 1

    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    """Execute the 'scan' subcommand."""
    target = Path(args.target).resolve()
    if not target.exists():
        print(f"Error: target does not exist: {target}", file=sys.stderr)
        return 2

    # --verify-determinism: run scan twice, compare SHA-256
    if args.verify_determinism:
        args.deterministic_output = True
        return _verify_determinism(args, target)

    # Verbose output — show scan details before running
    if args.verbose:
        from picosentry.scan.engine import create_default_engine

        temp_engine = create_default_engine()
        print(f"🦞 PicoSentry v{__version__}", file=sys.stderr)
        print(f"Target: {target}", file=sys.stderr)
        print(f"Corpus: {temp_engine._corpus_dir} (v{temp_engine._corpus_version})", file=sys.stderr)
        print(f"Rules: {', '.join(temp_engine.list_rules())}", file=sys.stderr)
        print("Scanning...", file=sys.stderr)

    # Load config and merge CLI args once — used for both scanning and formatting
    file_config = load_config(target)
    config = file_config.merge_cli(args)

    # Check cache before scanning
    cached_result = None
    cache = None
    lockfile_hash = ""
    if not args.verify_determinism and not getattr(args, "no_cache", False):
        try:
            from picosentry.scan.cache import ScanCache
            cache = ScanCache.from_config(config)
            # Compute lockfile hash for cache key
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

    # Run the scan (handles config, filtering, timeout) — or use cached result
    try:
        result = cached_result or _run_scan(args, target, merged_config=config)
    except ScanTimeout:
        print(f"Error: scan timed out after {args.timeout}s", file=sys.stderr)
        return 3
    except ScanError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Store result in cache after successful scan
    if cache and lockfile_hash and not cached_result:
        try:
            corpus_dir = Path(config.corpus) if config.corpus else None
            if not hasattr(cache, '_corpus_version_cache'):
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

    # Check for rule failures
    enterprise = is_enterprise_mode() or getattr(args, "enterprise", False)
    fail_closed = getattr(args, "fail_on_rule_error", False) or enterprise
    if fail_closed:
        failed_rules = [r for r in result.rule_executions if r.status == "failed"]
        if failed_rules:
            for r in failed_rules:
                print(f"Rule {r.rule_id} FAILED: {r.error}", file=sys.stderr)
            print(f"Scan aborted: {len(failed_rules)} rule(s) failed. Exiting with code 4.", file=sys.stderr)
            return 4

    # Save pre-baseline findings for --baseline-update
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
        # Log baseline info (not in quiet/summary mode)
        if not config.quiet and not config.summary:
            print(
                f"Baseline: {baseline_info.suppressed_count} known, {baseline_info.new_count} new (of {baseline_info.original_count} total)",
                file=sys.stderr,
            )

    # Apply enterprise policy (if configured)
    policy_file = getattr(args, "policy", None) or getattr(config, "policy_file", None)
    policy_result = None
    if policy_file:
        from picosentry.scan.policy import Policy

        policy_path = Path(policy_file)
        if policy_path.is_file():
            policy = Policy.from_file(policy_path)
            # Collect license info from findings
            pkg_licenses: dict[str, str] = {}
            installed_pkgs: set[str] = set()
            from picosentry.scan.rules.utils import iter_node_modules, load_package_json

            # Build inventory from actual installed packages, not just findings
            root_pkg = target / "package.json"
            if root_pkg.is_file():
                root_data = load_package_json(root_pkg)
                if root_data:
                    root_name = root_data.get("name", "")
                    if root_name:
                        installed_pkgs.add(root_name)
            for pkg_json_path, pkg_data in iter_node_modules(target):
                pkg_name = pkg_data.get("name", pkg_json_path.parent.name)
                # For scoped packages, reconstruct full name from directory when missing
                if not pkg_name.startswith("@") and pkg_json_path.parent.name and pkg_json_path.parent.parent.name.startswith("@"):
                    pkg_name = f"{pkg_json_path.parent.parent.name}/{pkg_name}"
                installed_pkgs.add(pkg_name)
            # Extract licenses from findings
            for f in result.findings:
                if f.rule_id == "L2-LICENSE-001" and "license =" in f.evidence:
                    lic_extract = f.evidence.split("license = ")[-1].strip("'\"")
                    pkg_licenses[f.package] = lic_extract
            policy_result = policy.apply(
                result, target, package_licenses=pkg_licenses, installed_packages=installed_pkgs
            )
            # Attach policy result to scan result for formatters
            result.policy_result = policy_result

    # Format output
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

    # Write output
    if config.output:
        Path(config.output).write_text(output, encoding="utf-8")
        print(f"Output written to {config.output}")
    else:
        print(output)

    # Verbose output — per-rule timing and scan details on stderr
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

    # Baseline update — write new baseline with current findings added
    if config.baseline and config.baseline_update:
        baseline_path = Path(config.baseline)
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

    # Exit code
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


if __name__ == "__main__":
    sys.exit(main())
