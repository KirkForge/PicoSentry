"""PicoDome CLI — deterministic runtime sandbox and behavioral analysis.

Supports multiple output formats, deterministic mode, verification,
and a full guard stack for CI/CD pipelines.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from picosentry.sandbox import __version__
from picosentry.sandbox.formatters.cyclonedx import format_cyclonedx
from picosentry.sandbox.formatters.github import format_github
from picosentry.sandbox.formatters.json_fmt import format_json, format_pipeline_json
from picosentry.sandbox.formatters.ml_context import format_ml_context
from picosentry.sandbox.formatters.sarif import format_sarif
from picosentry.sandbox.formatters.table import format_table
from picosentry.sandbox.guards import (
    DeterministicGuard,
    diff_results,
    validate_findings_deterministic,
    verify_determinism,
)
from picosentry.sandbox.l3.engine import sandbox_run
from picosentry.sandbox.l3.models import SandboxResult
from picosentry.sandbox.l3.policy import load_policy
from picosentry.sandbox.l4.engine import create_default_engine
from picosentry.sandbox.l4.models import AnalysisResult
from picosentry.sandbox.l4.profiler import profile_from_sandbox_result

# Severity levels for --fail-on
_SEVERITY_LEVELS = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


# Default HMAC key for CLI notary commands — warns if used without env var
_DEFAULT_CLI_HMAC_KEY = "picodome-notary-cli-default"

# Exit codes that trigger --exit-code
_BAD_VERDICTS = {"DENY", "KILL", "MALICIOUS", "SUSPICIOUS"}


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="picodome",
        description="PicoDome — deterministic runtime sandbox and behavioral analysis",
    )
    parser.add_argument("--version", action="version", version=f"picodome {__version__}")

    sub = parser.add_subparsers(dest="subcommand", help="sub-commands")

    # ── version ─────────────────────────────────────────────────────
    _version_parser = sub.add_parser("version", help="Print version and exit")

    # ── sandbox ──────────────────────────────────────────────────────
    sandbox_parser = sub.add_parser("sandbox", help="Run a command under L3 sandbox policy")
    sandbox_parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to execute")
    sandbox_parser.add_argument("--policy", "-p", type=Path, help="Policy file (default: built-in)")
    sandbox_parser.add_argument("--timeout", "-t", type=float, default=30.0, help="Timeout in seconds")
    sandbox_parser.add_argument(
        "--backend",
        "-b",
        choices=["auto", "seccomp-bpf", "seccomp-trace", "seatbelt", "subprocess"],
        default="auto",
        help="Sandbox backend: auto (default), seccomp-bpf, seccomp-trace, seatbelt, subprocess",
    )
    sandbox_parser.add_argument(
        "--allow-degraded",
        action="store_true",
        help="Allow fallback to subprocess if requested backend is unavailable",
    )
    sandbox_parser.add_argument(
        "--allow-runtime",
        choices=["node", "python"],
        help="Use a runtime-friendly policy (node or python) that allows common package manager operations",
    )
    sandbox_parser.add_argument("--cwd", "-C", help="Working directory")
    sandbox_parser.add_argument(
        "--format",
        "-f",
        choices=["json", "sarif", "table", "ml-context", "github", "cyclonedx"],
        default="table",
    )
    _add_common_flags(sandbox_parser)
    sandbox_parser.add_argument(
        "--verify-determinism",
        action="store_true",
        help="Run twice and compare SHA-256 hashes to verify determinism",
    )

    # ── analyze ──────────────────────────────────────────────────────
    analyze_parser = sub.add_parser("analyze", help="Run L4 behavioral analysis on L3 output")
    analyze_parser.add_argument("--input", "-i", type=Path, help="JSON file from 'picodome sandbox --format json'")
    analyze_parser.add_argument(
        "--format",
        "-f",
        choices=["json", "sarif", "table", "ml-context", "github", "cyclonedx"],
        default="table",
    )
    analyze_parser.add_argument("--rules", "-r", nargs="*", help="Specific rule IDs to run")
    _add_common_flags(analyze_parser)

    # ── pipeline ─────────────────────────────────────────────────────
    pipeline_parser = sub.add_parser("pipeline", help="Run full L3+L4 pipeline on a command")
    pipeline_parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to execute")
    pipeline_parser.add_argument("--policy", "-p", type=Path, help="Policy file")
    pipeline_parser.add_argument("--timeout", "-t", type=float, default=30.0, help="Timeout in seconds")
    pipeline_parser.add_argument(
        "--backend",
        "-b",
        choices=["auto", "seccomp-bpf", "seccomp-trace", "seatbelt", "subprocess"],
        default="auto",
        help="Sandbox backend: auto (default), seccomp-bpf, seccomp-trace, seatbelt, subprocess",
    )
    pipeline_parser.add_argument(
        "--allow-degraded",
        action="store_true",
        help="Allow fallback to subprocess if requested backend is unavailable",
    )
    pipeline_parser.add_argument(
        "--allow-runtime",
        choices=["node", "python"],
        help="Use a runtime-friendly policy (node or python) that allows common package manager operations",
    )
    pipeline_parser.add_argument("--cwd", "-C", help="Working directory")
    pipeline_parser.add_argument(
        "--format",
        "-f",
        choices=["json", "sarif", "table", "ml-context", "github", "cyclonedx"],
        default="table",
    )
    pipeline_parser.add_argument("--rules", "-r", nargs="*", help="Specific L4 rule IDs to run")
    _add_common_flags(pipeline_parser)

    # ── rules ────────────────────────────────────────────────────────
    rules_parser = sub.add_parser("rules", help="List available L4 detector rules")
    rules_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # ── daemon ────────────────────────────────────────────────────────
    daemon_parser = sub.add_parser("daemon", help="Start PicoDome daemon (HTTP API server)")
    daemon_parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    daemon_parser.add_argument("--port", type=int, default=8443, help="Bind port (default: 8443)")
    daemon_parser.add_argument("--background", action="store_true", help="Run in background")
    daemon_parser.add_argument(
        "--transport",
        choices=["http", "grpc"],
        default="http",
        help="Transport protocol: http (default) or grpc",
    )
    daemon_parser.add_argument(
        "--grpc-port", type=int, default=50051, help="gRPC port (default: 50051, only used with --transport grpc)"
    )
    daemon_parser.add_argument(
        "--store-backend",
        choices=["jsonl", "sqlite"],
        default=None,
        help="Job store backend: jsonl (default) or sqlite",
    )
    daemon_parser.add_argument(
        "--metrics-port",
        type=int,
        default=None,
        help="Separate port for /metrics endpoint (default: same as API port)",
    )

    # ── scan-grpc ─────────────────────────────────────────────────────
    scan_grpc_parser = sub.add_parser("scan-grpc", help="Scan via gRPC client")
    scan_grpc_parser.add_argument("target", nargs=argparse.REMAINDER, help="Command to scan")
    scan_grpc_parser.add_argument(
        "--address", default="localhost:50051", help="gRPC server address (default: localhost:50051)"
    )
    scan_grpc_parser.add_argument("--policy", "-p", help="Policy name")
    scan_grpc_parser.add_argument("--timeout", "-t", type=float, default=30.0, help="Timeout in seconds")
    scan_grpc_parser.add_argument("--cwd", "-C", help="Working directory")
    scan_grpc_parser.add_argument("--tls-cert", help="Client TLS certificate path")
    scan_grpc_parser.add_argument("--tls-key", help="Client TLS key path")
    scan_grpc_parser.add_argument("--tls-ca", help="CA certificate path for mTLS")
    scan_grpc_parser.add_argument("--retries", type=int, default=3, help="Max retry attempts (default: 3)")

    # ── health ────────────────────────────────────────────────────────
    health_parser = sub.add_parser("health", help="Run health checks")
    health_parser.add_argument("--format", "-f", choices=["json", "table"], default="table", help="Output format")

    # ── audit-query ───────────────────────────────────────────────────
    audit_parser = sub.add_parser("audit", help="Query the audit log")
    audit_parser.add_argument("--event-type", help="Filter by event type")
    audit_parser.add_argument("--actor", help="Filter by actor")
    audit_parser.add_argument("--target", help="Filter by target")
    audit_parser.add_argument("--since", help="Events after this ISO timestamp")
    audit_parser.add_argument("--until", help="Events before this ISO timestamp")
    audit_parser.add_argument("--limit", type=int, default=100, help="Max results")
    audit_parser.add_argument("--verify", action="store_true", help="Verify chain integrity")
    audit_parser.add_argument("--stats", action="store_true", help="Show audit log statistics")

    # ── retention ──────────────────────────────────────────────────────
    retention_parser = sub.add_parser("retention", help="Manage data retention")
    retention_parser.add_argument("action", choices=["cleanup", "stats", "export"], help="Retention action")
    retention_parser.add_argument("--output", type=Path, help="Output file for export")

    # ── policy-versioned ──────────────────────────────────────────────
    policy_v_parser = sub.add_parser("policy-versions", help="Manage versioned policies")
    policy_v_parser.add_argument("action", choices=["list", "show", "diff", "rollback", "verify"], help="Policy action")
    policy_v_parser.add_argument("--name", help="Policy name")
    policy_v_parser.add_argument("--version", type=int, help="Policy version")
    policy_v_parser.add_argument("--version-a", type=int, help="First version for diff")
    policy_v_parser.add_argument("--version-b", type=int, help="Second version for diff")
    policy_v_parser.add_argument("--author", default="cli-user", help="Author for rollback")

    # ── diff ──────────────────────────────────────────────────────────
    diff_parser = sub.add_parser("diff", help="Compare two result JSON files")
    diff_parser.add_argument("file_a", type=Path, help="First result JSON file")
    diff_parser.add_argument("file_b", type=Path, help="Second result JSON file")
    diff_parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed diff")

    # ── notary ────────────────────────────────────────────────────────
    notary_parser = sub.add_parser("notary", help="Audit transparency notary (Rekor/Sigstore)")
    notary_sub = notary_parser.add_subparsers(dest="notary_command", help="notary sub-commands")

    notary_submit = notary_sub.add_parser("submit", help="Submit an audit entry to the notary")
    notary_submit.add_argument("--entry", type=Path, required=True, help="JSON file with the entry to notarize")
    notary_submit.add_argument(
        "--notary",
        choices=["null", "rekor"],
        default="null",
        help="Notary backend (default: null)",
    )
    notary_submit.add_argument("--rekor-url", default="https://rekor.sigstore.dev", help="Rekor API URL")
    notary_submit.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds")
    notary_submit.add_argument("--hmac-key", default=None, help="HMAC key (default: built-in)")

    notary_verify = notary_sub.add_parser("verify", help="Verify an audit entry against the notary")
    notary_verify.add_argument("--uuid", required=True, help="UUID of the entry to verify")
    notary_verify.add_argument("--entry", type=Path, required=True, help="JSON file with the entry to verify")
    notary_verify.add_argument(
        "--notary",
        choices=["null", "rekor"],
        default="null",
        help="Notary backend (default: null)",
    )
    notary_verify.add_argument("--rekor-url", default="https://rekor.sigstore.dev", help="Rekor API URL")
    notary_verify.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds")
    notary_verify.add_argument("--hmac-key", default=None, help="HMAC key (default: built-in)")

    # ── cluster ─────────────────────────────────────────────────────
    cluster_parser = sub.add_parser("cluster", help="Manage daemon cluster mode")
    cluster_sub = cluster_parser.add_subparsers(dest="cluster_action", help="cluster sub-commands")

    # cluster join
    cluster_join = cluster_sub.add_parser("join", help="Join a cluster via peer address")
    cluster_join.add_argument("peer_address", help="Peer address (host:port)")
    cluster_join.add_argument("--port", type=int, default=8444, help="Local cluster port (default: 8444)")
    cluster_join.add_argument("--node-id", help="Custom node ID (default: auto-generated)")
    cluster_join.add_argument(
        "--backend",
        choices=["memory", "sqlite"],
        default="memory",
        help="State backend (default: memory)",
    )
    cluster_join.add_argument(
        "--heartbeat-interval", type=int, default=10, help="Heartbeat interval in seconds (default: 10)"
    )
    cluster_join.add_argument(
        "--heartbeat-timeout", type=int, default=30, help="Heartbeat timeout in seconds (default: 30)"
    )

    # cluster status
    cluster_status = cluster_sub.add_parser("status", help="Show cluster node status")
    cluster_status.add_argument(
        "--format", "-", choices=["json", "table"], default="table", help="Output format (default: table)"
    )

    # cluster leave
    _cluster_leave = cluster_sub.add_parser("leave", help="Gracefully leave the cluster")

    # ── sign-policy ───────────────────────────────────────────────────
    sign_parser = sub.add_parser("sign-policy", help="Sign or verify a policy file")
    sign_sub = sign_parser.add_subparsers(dest="sign_action", help="sign-policy sub-commands")

    sign_sign = sign_sub.add_parser("sign", help="Sign a policy file with HMAC-SHA256")
    sign_sign.add_argument("policy_file", type=Path, help="Policy file to sign")
    sign_sign.add_argument("--key", help="HMAC key (hex-encoded). Uses PICODOME_POLICY_KEY env if omitted")
    sign_sign.add_argument("--key-file", type=Path, help="File containing hex-encoded HMAC key")
    sign_sign.add_argument("--key-id", default="default", help="Key identifier for rotation (default: default)")
    sign_sign.add_argument(
        "--companion",
        action="store_true",
        help="Write signature to a companion .sig file instead of inline",
    )

    sign_verify = sign_sub.add_parser("verify", help="Verify a signed policy file")
    sign_verify.add_argument("policy_file", type=Path, help="Policy file to verify")
    sign_verify.add_argument("--key", help="HMAC key (hex-encoded). Uses PICODOME_POLICY_KEY env if omitted")
    sign_verify.add_argument("--key-file", type=Path, help="File containing hex-encoded HMAC key")
    sign_verify.add_argument("--key-id", default="default", help="Expected key identifier (default: default)")
    sign_verify.add_argument(
        "--companion",
        action="store_true",
        help="Verify companion .sig file instead of inline signature",
    )

    sign_genkey = sign_sub.add_parser("generate-key", help="Generate a new HMAC-SHA256 key")
    sign_genkey.add_argument("--output", type=Path, help="Write key to file (otherwise stdout)")

    # ── init ──────────────────────────────────────────────────────────
    init_parser = sub.add_parser("init", help="Initialize PicoDome configuration")
    init_parser.add_argument("target", nargs="?", default=".", help="Target directory (default: current)")

    args = parser.parse_args(argv)

    if args.subcommand == "version":
        print(f"picodome {__version__}")
        return 0
    elif args.subcommand == "sandbox":
        return _cmd_sandbox(args)
    elif args.subcommand == "analyze":
        return _cmd_analyze(args)
    elif args.subcommand == "pipeline":
        return _cmd_pipeline(args)
    elif args.subcommand == "rules":
        return _cmd_rules(args)
    elif args.subcommand == "diff":
        return _cmd_diff(args)
    elif args.subcommand == "init":
        return _cmd_init(args)

    elif args.subcommand == "cluster":
        return _cmd_cluster(args)
    elif args.subcommand == "daemon":
        return _cmd_daemon(args)
    elif args.subcommand == "scan-grpc":
        return _cmd_scan_grpc(args)
    elif args.subcommand == "health":
        return _cmd_health(args)
    elif args.subcommand == "audit":
        return _cmd_audit(args)
    elif args.subcommand == "retention":
        return _cmd_retention(args)
    elif args.subcommand == "policy-versions":
        return _cmd_policy_versions(args)
    elif args.subcommand == "sign-policy":
        return _cmd_sign_policy(args)
    elif args.subcommand == "notary":
        return _cmd_notary(args)
    else:
        parser.print_help()
        return 1


def _add_common_flags(parser: argparse.ArgumentParser) -> None:
    """Add common flags to a subcommand parser."""
    parser.add_argument(
        "--deterministic-output",
        "-D",
        action="store_true",
        help="Produce deterministic output (no timestamps, random IDs, or timing)",
    )
    parser.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit 1 on DENY/KILL/MALICIOUS/SUSPICIOUS verdict",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info"],
        help="Exit 1 if any finding at or above this severity",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress all output except exit code",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="One-line summary output",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output with full details",
    )
    parser.add_argument(
        "--log-format",
        choices=["text", "json"],
        default="text",
        help="Log output format (default: text)",
    )


def _cmd_sandbox(args) -> int:
    """Run L3 sandbox."""
    # Strip leading '--' separator (common CLI convention: 'picodome sandbox -- command args')
    if args.command and args.command[0] == '--':
        args.command = args.command[1:]
    if not args.command:
        print("Error: no command specified", file=sys.stderr)
        return 1

    # --allow-runtime takes precedence over --policy
    if getattr(args, "allow_runtime", None) and not args.policy:
        from picosentry.sandbox.l3.policy import load_policy as _lp
        policy = _lp(name=args.allow_runtime)
    elif args.policy:
        policy = load_policy(args.policy)
    else:
        policy = None
    deterministic = args.deterministic_output

    # Resolve backend
    from picosentry.sandbox.l3.engine import BackendUnavailableError, _detect_backend

    backend_name = getattr(args, "backend", "auto") or "auto"
    allow_degraded = getattr(args, "allow_degraded", False)

    try:
        if backend_name == "auto":
            backend = None  # use get_backend() via sandbox_run
        else:
            backend = _detect_backend(
                requested=backend_name,
                allow_degraded=allow_degraded,
            )
    except BackendUnavailableError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    result = sandbox_run(
        command=args.command,
        policy=policy,
        timeout=args.timeout,
        cwd=args.cwd,
        backend=backend,
        deterministic=deterministic,
    )

    # Run determinism guard check if in deterministic mode
    if deterministic:
        guard = DeterministicGuard()
        violations = guard.check(result)
        if violations:
            for v in violations:
                print(f"DETERMINISM VIOLATION: {v}", file=sys.stderr)

    # Verify determinism if requested
    if hasattr(args, "verify_determinism") and args.verify_determinism:
        is_match, hash_a, hash_b = verify_determinism(
            args.command,
            policy=policy,
            timeout=args.timeout,
            cwd=args.cwd,
        )
        if not args.quiet:
            if is_match:
                print(f"✓ Determinism verified: {hash_a}", file=sys.stderr)
            else:
                print(f"✗ Determinism FAILED: {hash_a} != {hash_b}", file=sys.stderr)
        if not is_match:
            return 4

    # Output
    if not args.quiet:
        _output(result, args)

    # Exit code logic
    return _compute_exit_code_sandbox(result, args)


def _cmd_analyze(args) -> int:
    """Run L4 analysis on L3 output."""
    if not args.input or not args.input.exists():
        print("Error: --input file required and must exist", file=sys.stderr)
        return 1

    with open(args.input) as f:
        data = json.load(f)

    # Reconstruct SandboxResult from JSON
    from picosentry.sandbox.l3.models import SandboxEvent, Verdict

    events = [
        SandboxEvent(
            rule_id=e["rule_id"],
            verdict=Verdict(e["verdict"]),
            operation=e["operation"],
            detail=e["detail"],
            path=e.get("path", ""),
            address=e.get("address", ""),
        )
        for e in data.get("events", [])
    ]
    from picosentry.sandbox.l3.models import SandboxResult

    sandbox = SandboxResult(
        run_id=data.get("run_id", ""),
        command=data.get("command", []),
        overall_verdict=Verdict(data.get("overall_verdict", "ALLOW")),
        exit_code=data.get("exit_code", 0),
        duration_ms=data.get("duration_ms", 0),
        events=events,
        policy_name=data.get("policy_name", ""),
        stdout=data.get("stdout", ""),
        stderr=data.get("stderr", ""),
    )

    profile = profile_from_sandbox_result(sandbox)
    engine = create_default_engine()
    deterministic = args.deterministic_output
    result = engine.analyze(profile, rules=args.rules, deterministic=deterministic)

    # Run determinism guard check if in deterministic mode
    if deterministic:
        guard = DeterministicGuard()
        violations = guard.check(result)
        if violations:
            for v in violations:
                print(f"DETERMINISM VIOLATION: {v}", file=sys.stderr)
        # Also validate individual findings for determinism
        finding_violations = validate_findings_deterministic(result.findings)
        for v in finding_violations:
            print(f"DETERMINISM VIOLATION (findings): {v}", file=sys.stderr)

    # Output
    if not args.quiet:
        _output(result, args)

    return _compute_exit_code_analysis(result, args)


def _auto_detect_policy(command: list[str]):
    """Auto-detect runtime from command and return appropriate policy.

    If the command looks like npm/node, return node policy.
    If the command looks like pip/python, return python policy.
    Otherwise return None (use default).
    """
    from picosentry.sandbox.l3.policy import load_policy as _lp

    if not command:
        return None

    exe = command[0].split("/")[-1].lower() if command[0] else ""

    node_commands = {"npm", "npx", "node", "yarn", "pnpm", "bun"}
    python_commands = {"pip", "pip3", "python", "python3", "uv", "poetry", "pdm", "conda"}

    if exe in node_commands:
        return _lp(name="node")
    elif exe in python_commands:
        return _lp(name="python")
    return None


def _cmd_pipeline(args) -> int:
    """Run full L3+L4 pipeline."""
    # Strip leading '--' separator (common CLI convention: 'picodome pipeline -- command args')
    if args.command and args.command[0] == '--':
        args.command = args.command[1:]
    if not args.command:
        print("Error: no command specified", file=sys.stderr)
        return 1

    # --allow-runtime takes precedence over --policy
    if getattr(args, "allow_runtime", None) and not args.policy:
        policy = load_policy(name=args.allow_runtime)
    elif args.policy:
        policy = load_policy(args.policy)
    else:
        # Auto-detect runtime from command
        policy = _auto_detect_policy(args.command)
    deterministic = args.deterministic_output

    # Resolve backend
    from picosentry.sandbox.l3.engine import BackendUnavailableError, _detect_backend

    backend_name = getattr(args, "backend", "auto") or "auto"
    allow_degraded = getattr(args, "allow_degraded", False)

    try:
        if backend_name == "auto":
            backend = None  # use get_backend() via sandbox_run
        else:
            backend = _detect_backend(
                requested=backend_name,
                allow_degraded=allow_degraded,
            )
    except BackendUnavailableError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # L3
    sandbox = sandbox_run(
        command=args.command,
        policy=policy,
        timeout=args.timeout,
        cwd=args.cwd,
        backend=backend,
        deterministic=deterministic,
    )

    # L4
    profile = profile_from_sandbox_result(sandbox)
    engine = create_default_engine()
    analysis = engine.analyze(profile, rules=args.rules, deterministic=deterministic)

    # Run determinism guard check if in deterministic mode
    if deterministic:
        guard = DeterministicGuard()
        violations = guard.check(sandbox) + guard.check(analysis)
        if violations:
            for v in violations:
                print(f"DETERMINISM VIOLATION: {v}", file=sys.stderr)

    # Output
    if not args.quiet:
        fmt = args.format
        if args.summary:
            _output_summary_pipeline(sandbox, analysis)
        elif fmt == "json":
            print(format_pipeline_json(sandbox, analysis, deterministic=deterministic))
        elif fmt == "sarif":
            print(format_sarif(sandbox))
            print(format_sarif(analysis))
        elif fmt == "ml-context":
            print(format_ml_context(sandbox))
            print(format_ml_context(analysis))
        elif fmt == "github":
            print(format_github(sandbox))
            print(format_github(analysis))
        elif fmt == "cyclonedx":
            print(format_cyclonedx(sandbox))
            print(format_cyclonedx(analysis))
        else:  # table
            print(format_table(sandbox))
            print()
            print(format_table(analysis))

    return _compute_exit_code_pipeline(sandbox, analysis, args)


def _cmd_rules(args) -> int:
    """List available L4 rules."""
    engine = create_default_engine()
    rules = engine.list_rules()
    if args.json:
        print(json.dumps({"rules": rules}))
    else:
        for r in rules:
            print(r)
    return 0


def _cmd_diff(args) -> int:
    """Compare two result JSON files."""
    exit_code, message = diff_results(args.file_a, args.file_b, verbose=args.verbose)
    print(message)
    return exit_code


def _cmd_init(args) -> int:
    """Initialize PicoDome configuration."""
    target = Path(args.target).resolve()
    config_dir = target / ".picodome"
    config_file = config_dir / "policy.json"

    if config_file.exists():
        print(f"PicoDome config already exists: {config_file}")
        return 0

    config_dir.mkdir(parents=True, exist_ok=True)

    default_config = {
        "name": "picodome-default",
        "version": "1.0",
        "default_action": "deny",
        "rules": [
            {
                "rule_id": "L3-FILE-R-001",
                "target": "file_read",
                "action": "allow",
                "paths": ["/usr/lib/**", "/lib/**", "/usr/share/**"],
                "description": "Read system libraries",
            },
            {
                "rule_id": "L3-NET-OUT-001",
                "target": "network_out",
                "action": "deny",
                "description": "Block all outbound network",
            },
        ],
    }

    config_file.write_text(json.dumps(default_config, indent=2, sort_keys=True) + "\n")
    print(f"Created PicoDome config: {config_file}")
    return 0


def _cmd_daemon(args) -> int:
    """Start the PicoDome daemon."""
    transport = getattr(args, "transport", "http")

    if transport == "grpc":
        from picosentry.sandbox.grpc_transport import PicoDomeGRPCServer, is_grpc_available

        if not is_grpc_available():
            print("Error: grpcio is not installed. Install with: pip install grpcio", file=sys.stderr)
            return 1

        grpc_port = getattr(args, "grpc_port", 50051)
        host = args.host

        # Check for mTLS config
        mtls_config = None
        try:
            from picosentry.sandbox.mtls.context import MTLSConfig

            mtls_config = MTLSConfig.from_env()
            if not mtls_config.is_configured:
                mtls_config = None
        except Exception:
            pass

        server = PicoDomeGRPCServer(
            host=host,
            port=grpc_port,
            mtls_config=mtls_config,
        )
        try:
            print(f"Starting PicoDome gRPC daemon on {host}:{grpc_port}")
            server.start()
            return 0
        except KeyboardInterrupt:
            server.stop()
            return 0
        except Exception as e:
            print(f"gRPC daemon error: {e}", file=sys.stderr)
            return 1
    else:
        # HTTP daemon (default)
        from picosentry.sandbox.daemon import PicoDomeDaemon

        store_backend = getattr(args, "store_backend", None) or "jsonl"
        metrics_port = getattr(args, "metrics_port", None)

        daemon = PicoDomeDaemon(
            host=args.host,
            port=args.port,
            metrics_port=metrics_port,
            store_backend=store_backend,
        )

        # Install signal handlers for graceful shutdown (foreground only)
        if not args.background:
            daemon.install_signal_handlers()

        try:
            daemon.start(background=args.background)
            if args.background:
                print(f"PicoDome daemon started on {args.host}:{args.port}")
            return 0
        except KeyboardInterrupt:
            daemon.stop()
            return 0
        except Exception as e:
            print(f"Daemon error: {e}", file=sys.stderr)
            return 1


def _cmd_scan_grpc(args) -> int:
    """Scan via gRPC client."""
    from picosentry.sandbox.grpc_transport import is_grpc_available

    if not is_grpc_available():
        print("Error: grpcio is not installed. Install with: pip install grpcio", file=sys.stderr)
        return 1

    from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient

    command = args.target
    if not command:
        print("Error: no command specified", file=sys.stderr)
        return 1

    # Build mTLS config if cert paths provided
    mtls_config = None
    if args.tls_cert or args.tls_key or args.tls_ca:
        try:
            from picosentry.sandbox.mtls.context import MTLSConfig

            mtls_config = MTLSConfig(
                cert_path=args.tls_cert or "",
                key_path=args.tls_key or "",
                ca_path=args.tls_ca or "",
                verify_client=bool(args.tls_ca),
            )
        except Exception as e:
            print(f"Error configuring mTLS: {e}", file=sys.stderr)
            return 1

    client = PicoDomeGRPCClient(
        target=args.address,
        mtls_config=mtls_config,
        timeout=args.timeout,
        max_retries=args.retries,
    )

    try:
        result = client.scan(
            command=command,
            policy=args.policy,
            timeout=args.timeout,
            cwd=args.cwd,
        )

        # Output result
        if result.result_json:
            try:
                data = json.loads(result.result_json)
                print(json.dumps(data, sort_keys=True, indent=2))
            except json.JSONDecodeError:
                print(result.result_json)
        else:
            print(f"Verdict: {result.verdict}")
            print(f"Exit code: {result.exit_code}")
            if result.l3_verdict:
                print(f"L3 verdict: {result.l3_verdict}")
            if result.l4_verdict:
                print(f"L4 verdict: {result.l4_verdict}")
            print(f"Findings: {result.findings_count}")

        # Exit code based on verdict
        bad_verdicts = {"DENY", "KILL", "MALICIOUS", "SUSPICIOUS"}
        if result.verdict in bad_verdicts:
            return 1
        return 0

    except ConnectionError as e:
        print(f"Connection error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Scan error: {e}", file=sys.stderr)
        return 1
    finally:
        client.close()


def _cmd_health(args) -> int:
    """Run health checks."""
    from picosentry.sandbox.health import check_health

    checks = check_health()
    all_healthy = all(c.healthy for c in checks)

    if args.format == "json":
        data = {
            "healthy": all_healthy,
            "checks": [c.to_dict() for c in checks],
        }
        print(json.dumps(data, sort_keys=True, indent=2))
    else:
        icon = "✓" if all_healthy else "✗"
        print(f"\n{icon} PicoDome Health: {'HEALTHY' if all_healthy else 'UNHEALTHY'}\n")
        for c in checks:
            icon = "✓" if c.healthy else "✗"
            print(f"  {icon} {c.component}: {c.detail}")

    return 0 if all_healthy else 1


def _cmd_audit(args) -> int:
    """Query the audit log."""
    from picosentry.sandbox.audit import AuditEventType, get_audit_logger

    audit = get_audit_logger()

    if args.verify:
        violations = audit.verify_chain()
        if violations:
            print("✗ Audit log chain integrity VIOLATED:")
            for v in violations:
                print(f"  - {v}")
            return 1
        else:
            print("✓ Audit log chain integrity verified")
            return 0

    if args.stats:
        stats = audit.get_stats()
        print(json.dumps(stats, sort_keys=True, indent=2))
        return 0

    event_type = None
    if args.event_type:
        try:
            event_type = AuditEventType(args.event_type)
        except ValueError:
            print(f"Unknown event type: {args.event_type}", file=sys.stderr)
            return 1

    events = audit.query(
        event_type=event_type,
        actor=args.actor,
        target=args.target,
        since=args.since,
        until=args.until,
        limit=args.limit,
    )

    for evt in events:
        print(f"[{evt.timestamp}] {evt.event_type.value} actor={evt.actor} target={evt.target}")
        if evt.detail:
            print(f"  {evt.detail}")

    return 0


def _cmd_retention(args) -> int:
    """Manage data retention."""
    from picosentry.sandbox.retention import get_retention_manager

    rm = get_retention_manager()

    if args.action == "cleanup":
        stats = rm.run_cleanup()
        print(f"Cleanup: removed {stats['files_removed']} files, freed {stats['bytes_freed']} bytes")
        if stats["errors"]:
            for err in stats["errors"]:
                print(f"  Error: {err}")
        return 0
    elif args.action == "stats":
        stats = rm.get_storage_stats()
        print(json.dumps(stats, sort_keys=True, indent=2))
        return 0
    elif args.action == "export":
        output = args.output or Path("picodome-export.json")
        rm.export_data(output)
        print(f"Exported to {output}")
        return 0
    return 1


def _cmd_policy_versions(args) -> int:
    """Manage versioned policies."""
    from picosentry.sandbox.policy_versioned import get_policy_store

    store = get_policy_store()

    if args.action == "list":
        names = store.list_policies()
        for name in names:
            versions = store.list_versions(name)
            latest = max(v.version for v in versions) if versions else 0
            print(f"  {name} (v{latest}, {len(versions)} versions)")
        return 0
    elif args.action == "show":
        if not args.name:
            print("--name is required for 'show'", file=sys.stderr)
            return 1
        pv = store.load(args.name, version=args.version)
        if pv is None:
            print(f"Policy '{args.name}' not found", file=sys.stderr)
            return 1
        print(json.dumps(pv.to_dict(), sort_keys=True, indent=2))
        return 0
    elif args.action == "diff":
        if not args.name or args.version_a is None or args.version_b is None:
            print("--name, --version-a, and --version-b are required for 'diff'", file=sys.stderr)
            return 1
        diff = store.diff(args.name, args.version_a, args.version_b)
        print(json.dumps(diff, sort_keys=True, indent=2))
        return 0
    elif args.action == "rollback":
        if not args.name or args.version is None:
            print("--name and --version are required for 'rollback'", file=sys.stderr)
            return 1
        pv = store.rollback(args.name, args.version, author=args.author)
        if pv is None:
            print("Rollback failed", file=sys.stderr)
            return 1
        print(f"Rolled back '{args.name}' to v{args.version} → new v{pv.version}")
        return 0
    elif args.action == "verify":
        if not args.name:
            print("--name is required for 'verify'", file=sys.stderr)
            return 1
        violations = store.verify_integrity(args.name)
        if violations:
            print(f"✗ Integrity violations for '{args.name}':")
            for v in violations:
                print(f"  - {v}")
            return 1
        else:
            print(f"✓ Policy '{args.name}' integrity verified")
            return 0
    return 1


def _cmd_notary(args) -> int:
    """Handle notary subcommands (submit, verify)."""
    from picosentry.sandbox.notary import AuditNotary, NullNotary, RekorNotary, sign_entry

    notary: AuditNotary

    if args.notary_command == "submit":
        if not args.entry or not args.entry.exists():
            print(f"Error: entry file not found: {args.entry}", file=sys.stderr)
            return 1

        try:
            with open(args.entry) as f:
                entry = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"Error: failed to read entry file: {exc}", file=sys.stderr)
            return 1

        if not args.hmac_key and not os.environ.get("PICODOME_NOTARY_HMAC_KEY"):
            print("Using default HMAC key. Set PICODOME_NOTARY_HMAC_KEY env var for persistent verification.")
        hmac_key = args.hmac_key or os.environ.get("PICODOME_NOTARY_HMAC_KEY") or _DEFAULT_CLI_HMAC_KEY

        if args.notary == "rekor":
            notary = RekorNotary(
                rekor_url=args.rekor_url,
                timeout=args.timeout,
                hmac_key=hmac_key,
            )
        else:
            notary = NullNotary(hmac_key=hmac_key)

        # Sign locally first
        signature = sign_entry(entry, key=hmac_key)
        print(f"HMAC-SHA256 signature: {signature}")

        # Submit to notary
        try:
            uuid = notary.submit_entry(entry)
            print(f"Entry submitted: {uuid}")
            print(f"Notary backend: {args.notary}")
        except Exception as exc:
            print(f"Error: notary submission failed: {exc}", file=sys.stderr)
            return 1

        return 0

    elif args.notary_command == "verify":
        if not args.entry or not args.entry.exists():
            print(f"Error: entry file not found: {args.entry}", file=sys.stderr)
            return 1

        try:
            with open(args.entry) as f:
                entry = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"Error: failed to read entry file: {exc}", file=sys.stderr)
            return 1

        if not args.hmac_key and not os.environ.get("PICODOME_NOTARY_HMAC_KEY"):
            print("Using default HMAC key. Set PICODOME_NOTARY_HMAC_KEY env var for persistent verification.")
        hmac_key = args.hmac_key or os.environ.get("PICODOME_NOTARY_HMAC_KEY") or _DEFAULT_CLI_HMAC_KEY

        if args.notary == "rekor":
            notary = RekorNotary(
                rekor_url=args.rekor_url,
                timeout=args.timeout,
                hmac_key=hmac_key,
            )
        else:
            notary = NullNotary(hmac_key=hmac_key)

        try:
            verified = notary.verify_entry(args.uuid, entry)
            if verified:
                print(f"✓ Entry {args.uuid} verified successfully")
                return 0
            else:
                print(f"✗ Entry {args.uuid} verification FAILED", file=sys.stderr)
                return 1
        except Exception as exc:
            print(f"Error: verification failed: {exc}", file=sys.stderr)
            return 1

    else:
        print("Usage: picodome notary {submit|verify}", file=sys.stderr)
        return 1


def _cmd_cluster(args) -> int:
    """Manage daemon cluster mode."""
    from picosentry.sandbox.cluster import (
        ClusterManager,
        ClusterNode,
        MemoryStateBackend,
        NodeStatus,
        SQLiteStateBackend,
    )

    action = getattr(args, "cluster_action", None)

    if action == "join":
        # Parse peer address
        peer = args.peer_address
        if ":" in peer:
            peer_host, peer_port_str = peer.rsplit(":", 1)
            try:
                peer_port = int(peer_port_str)
            except ValueError:
                print(f"Error: invalid peer address: {peer}", file=sys.stderr)
                return 1
        else:
            peer_host = peer
            peer_port = 8444

        # Select backend
        backend = MemoryStateBackend() if args.backend == "memory" else SQLiteStateBackend()

        manager = ClusterManager(
            address="127.0.0.1",
            port=args.port,
            node_id=args.node_id,
            backend=backend,
            heartbeat_interval=args.heartbeat_interval,
            heartbeat_timeout=args.heartbeat_timeout,
        )
        manager.start()

        # Register the peer node
        peer_node = ClusterNode(
            node_id=f"peer-{peer_host}-{peer_port}",
            address=peer_host,
            port=peer_port,
            status=NodeStatus.ONLINE,
            last_heartbeat="",
            load=0,
        )
        manager.state.add_node(peer_node)

        # Re-elect leader
        manager.state.elect_leader()

        status = manager.get_status()
        print(f"✓ Joined cluster as node {manager.node_id}")
        print(f"  Peer: {peer_host}:{peer_port}")
        print(f"  Leader: {status['leader_id'] or 'none'}")
        print(f"  Nodes: {status['nodes_online']} online, {status['nodes_total']} total")
        print(f"  Backend: {args.backend}")
        return 0

    elif action == "status":
        # Try to get running cluster manager, or create a read-only one
        try:
            from picosentry.sandbox.cluster.manager import _cluster_manager

            manager = _cluster_manager or ClusterManager()
        except Exception:
            manager = ClusterManager()

        status = manager.get_status()

        if args.format == "json":
            print(json.dumps(status, sort_keys=True, indent=2))
        else:
            print("\n  Cluster Status")
            print("  ─────────────")
            print(f"  Self:       {status['self_id']}")
            print(f"  Leader:     {status['leader_id'] or 'none'}")
            print(f"  Nodes:      {status['nodes_online']} online / {status['nodes_total']} total")
            print(f"  Draining:   {status['nodes_draining']}")
            print(
                f"  Scans:      {status['scans_pending']} pending /"
                f" {status['scans_running']} running /"
                f" {status['scans_completed']} completed"
            )
            print()
            if status["nodes"]:
                print(f"  {'Node ID':<30} {'Address':<20} {'Port':<6} {'Status':<10} {'Load':<5} {'Last HB'}")
                print(f"  {'─' * 30} {'─' * 20} {'─' * 6} {'─' * 10} {'─' * 5} {'─' * 20}")
                for n in status["nodes"]:
                    print(
                        f"  {n['node_id']:<30} "
                        f"{n['address']:<20} "
                        f"{n['port']:<6} "
                        f"{n['status']:<10} "
                        f"{n['load']:<5} "
                        f"{n['last_heartbeat']}"
                    )
            print()
        return 0

    elif action == "leave":
        try:
            from picosentry.sandbox.cluster.manager import _cluster_manager

            manager = _cluster_manager or ClusterManager()
        except Exception:
            manager = ClusterManager()

        manager.stop()
        print(f"✓ Left cluster (node {manager.node_id})")
        return 0

    else:
        print("Usage: picodome cluster {join|status|leave}", file=sys.stderr)
        return 1


def _output(result, args) -> None:
    """Output a result in the requested format."""
    if args.summary:
        _output_summary(result)
        return

    fmt = args.format
    deterministic = args.deterministic_output

    if fmt == "json":
        print(format_json(result, deterministic=deterministic))
    elif fmt == "sarif":
        print(format_sarif(result))
    elif fmt == "ml-context":
        print(format_ml_context(result))
    elif fmt == "github":
        print(format_github(result))
    elif fmt == "cyclonedx":
        print(format_cyclonedx(result))
    else:  # table
        print(format_table(result))


def _output_summary(result) -> None:
    """One-line summary output."""
    if isinstance(result, SandboxResult):
        verdict = result.overall_verdict.value
        events = len(result.events)
        cmd = " ".join(result.command)
        print(f"L3: {verdict} | {events} events | {cmd}")
    elif isinstance(result, AnalysisResult):
        verdict = result.overall_verdict.value
        findings = len(result.findings)
        print(f"L4: {verdict} | {findings} findings | {result.target}")


def _output_summary_pipeline(sandbox: SandboxResult, analysis: AnalysisResult) -> None:
    """One-line summary for pipeline."""
    l3_verdict = sandbox.overall_verdict.value
    l4_verdict = analysis.overall_verdict.value
    events = len(sandbox.events)
    findings = len(analysis.findings)
    cmd = " ".join(sandbox.command)
    print(f"L3: {l3_verdict} ({events} events) → L4: {l4_verdict} ({findings} findings) | {cmd}")


def _compute_exit_code_sandbox(result: SandboxResult, args) -> int:
    """Compute exit code for sandbox command based on flags."""
    # --exit-code: exit 1 on bad verdicts
    if args.exit_code and result.overall_verdict.value in _BAD_VERDICTS:
        return 1

    # --fail-on: check severity levels
    if args.fail_on:
        _SEVERITY_LEVELS.get(args.fail_on, 99)
        # Sandbox events don't have severity, but DENY/KILL are bad
        if result.overall_verdict.value in ("DENY", "KILL"):
            return 1

    # Default: exit 0 on ALLOW, 1 otherwise
    return 0 if result.overall_verdict.value == "ALLOW" else 1


def _compute_exit_code_analysis(result: AnalysisResult, args) -> int:
    """Compute exit code for analyze command based on flags."""
    # --exit-code: exit 1 on bad verdicts
    if args.exit_code and result.overall_verdict.value in _BAD_VERDICTS:
        return 1

    # --fail-on: check severity levels
    if args.fail_on:
        threshold = _SEVERITY_LEVELS.get(args.fail_on, 99)
        for f in result.findings:
            finding_level = _SEVERITY_LEVELS.get(f.severity.value.lower(), 99)
            if finding_level <= threshold:
                return 1

    # Default: exit 0 on CLEAN, 1 otherwise
    return 0 if result.overall_verdict.value == "CLEAN" else 1


def _compute_exit_code_pipeline(sandbox: SandboxResult, analysis: AnalysisResult, args) -> int:
    """Compute exit code for pipeline command."""
    # Check L4 verdict first (it's the final arbiter)
    if args.exit_code and analysis.overall_verdict.value in _BAD_VERDICTS:
        return 1

    if args.fail_on:
        threshold = _SEVERITY_LEVELS.get(args.fail_on, 99)
        for f in analysis.findings:
            finding_level = _SEVERITY_LEVELS.get(f.severity.value.lower(), 99)
            if finding_level <= threshold:
                return 1

    # Default: exit 0 on CLEAN, 1 otherwise
    return 0 if analysis.overall_verdict.value == "CLEAN" else 1


def _cmd_sign_policy(args) -> int:
    """Handle sign-policy subcommands (sign, verify, generate-key)."""
    from picosentry.sandbox.policy_versioned.signing import (
        generate_key,
        key_to_hex,
        sign_policy_companion,
        sign_policy_file,
        verify_policy_companion,
        verify_policy_file,
    )

    if not args.sign_action:
        print("Usage: picodome sign-policy {sign|verify|generate-key}", file=sys.stderr)
        return 1

    if args.sign_action == "sign":
        policy_path = args.policy_file
        if not policy_path.is_file():
            print(f"Error: policy file not found: {policy_path}", file=sys.stderr)
            return 1

        # Resolve key
        key = _resolve_signing_key(args)
        if key is None:
            return 1

        try:
            if args.companion:
                sig_path = sign_policy_companion(policy_path, key, key_id=args.key_id)
                print(f"✓ Signed policy (companion): {policy_path} -> {sig_path}")
            else:
                sign_policy_file(policy_path, key, key_id=args.key_id)
                print(f"✓ Signed policy: {policy_path}")
            return 0
        except Exception as exc:
            print(f"Error signing policy: {exc}", file=sys.stderr)
            return 1

    elif args.sign_action == "verify":
        policy_path = args.policy_file
        if not policy_path.is_file():
            print(f"Error: policy file not found: {policy_path}", file=sys.stderr)
            return 1

        # Resolve key
        key = _resolve_signing_key(args)
        if key is None:
            return 1

        if args.companion:
            result = verify_policy_companion(policy_path, key, key_id=args.key_id)
        else:
            result = verify_policy_file(policy_path, key, key_id=args.key_id)

        if result.valid:
            print(f"✓ Policy signature VALID: {policy_path}")
            print(f"  Algorithm: {result.algorithm}")
            print(f"  Key ID:    {result.key_id}")
            print(f"  Timestamp: {result.timestamp}")
            return 0
        else:
            print(f"✗ Policy signature INVALID: {policy_path}", file=sys.stderr)
            print(f"  Error: {result.error}", file=sys.stderr)
            return 1

    elif args.sign_action == "generate-key":
        key = generate_key()
        hex_key = key_to_hex(key)

        if args.output:
            args.output.write_text(hex_key)
            print(f"✓ Key written to: {args.output}")
            print(f"  Set PICODOME_POLICY_KEY={hex_key}")
            print(f"  Or set PICODOME_POLICY_KEY_FILE={args.output}")
        else:
            print(hex_key)

        return 0

    else:
        print(f"Unknown sign-policy action: {args.sign_action}", file=sys.stderr)
        return 1


def _resolve_signing_key(args) -> bytes | None:
    """Resolve HMAC key from args, env, or key file."""
    if hasattr(args, "key") and args.key:
        try:
            return bytes.fromhex(args.key)
        except ValueError:
            print("Error: --key must be hex-encoded", file=sys.stderr)
            return None

    if hasattr(args, "key_file") and args.key_file:
        if not args.key_file.is_file():
            print(f"Error: key file not found: {args.key_file}", file=sys.stderr)
            return None
        try:
            return bytes.fromhex(args.key_file.read_text().strip())
        except ValueError:
            print("Error: key file must contain hex-encoded key", file=sys.stderr)
            return None

    # Fall back to env
    from picosentry.sandbox.policy_versioned.signing import _load_key

    key = _load_key()
    if key is None:
        print("Error: no signing key provided. Use --key, --key-file, or set PICODOME_POLICY_KEY", file=sys.stderr)
        return None

    return key
