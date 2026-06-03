#!/usr/bin/env python3
"""
PicoSentry — unified CLI for the Pico Security Series.

Subcommands:
    scan      Supply-chain scanner (npm/pnpm) [from PicoSentry]
    sandbox   Runtime sandbox and behavioral analysis [from PicoDome]
    watch     LLM prompt injection detection and output validation [from PicoWatch]
    serve     API server, dashboard, and orchestration [from PicoShogun]

Usage:
    picosentry scan ./node_modules [--format json|sarif|table]
    picosentry sandbox ./package
    picosentry sandbox pipeline ./build.sh
    picosentry watch scan-prompt --text "..."
    picosentry watch validate-output --schema schema.yaml --output out.yaml
    picosentry serve [--host 127.0.0.1] [--port 8765]
    picosentry version
    picosentry health
    picosentry diff scan_a.json scan_b.json
    picosentry init
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="picosentry",
        description="Unified Pico Security Series — scan, sandbox, watch, orchestrate.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-V", "--version", action="store_true", help="Show version and exit")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # -- scan (PicoSentry) --
    scan_parser = subparsers.add_parser("scan", help="Supply-chain scanner for npm/pnpm")
    scan_parser.add_argument("target", nargs="*", type=str, help="Project directory to scan")
    scan_parser.add_argument("--format", choices=["json", "sarif", "table", "ml-context", "cyclonedx", "github"], default="table")
    scan_parser.add_argument("--quiet", "-q", action="store_true", help="CI-friendly summary only")
    scan_parser.add_argument("--summary", action="store_true", help="One-line summary for notifications")
    scan_parser.add_argument("--deterministic-output", "-D", action="store_true", help="Enable deterministic output")
    scan_parser.add_argument("--exit-code", action="store_true", help="Exit non-zero on findings")
    scan_parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"], default=None)
    scan_parser.add_argument("--token-budget", type=int, default=4096, help="Token budget for ML-context format")
    scan_parser.add_argument("--corpus", type=str, default=None, help="Path to corpus data")
    scan_parser.add_argument("--output", "-o", type=str, default=None, help="Write output to file")
    scan_parser.add_argument("--verbose", "-v", action="store_true", help="Show per-rule timing")
    scan_parser.add_argument("--timeout", type=int, default=0, help="Timeout in seconds")
    scan_parser.add_argument("--severity-threshold", choices=["low", "medium", "high", "critical"], default=None)
    scan_parser.add_argument("--baseline", "-b", type=str, default=None, help="Baseline JSON path")
    scan_parser.add_argument("--baseline-update", action="store_true", help="Write updated baseline")
    scan_parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    scan_parser.add_argument("--verify-determinism", action="store_true", help="Verify SHA-256 determinism")
    scan_parser.add_argument("--sarif-file", type=str, default=None, help="SARIF output path")
    scan_parser.add_argument("--policy", "-p", type=str, default=None, help="Policy file path")
    scan_parser.add_argument("--fail-on-rule-error", action="store_true", help="Fail on rule errors")
    scan_parser.add_argument("--enterprise", action="store_true", help="Enterprise mode")
    scan_parser.add_argument("--advisory-db", type=str, default=None, help="Advisory database path")
    scan_parser.add_argument("--rules", "-r", nargs="+", default=None, help="Run only specific rules")

    # -- sandbox (PicoDome) --
    sandbox_parser = subparsers.add_parser("sandbox", help="Runtime sandbox and behavioral analysis")
    sandbox_parser.add_argument("command", nargs="*", type=str, help="Command to run under sandbox")
    sandbox_parser.add_argument("--format", choices=["json", "sarif", "table", "ml-context", "cyclonedx", "github"], default="table")
    sandbox_parser.add_argument("--deterministic-output", "-D", action="store_true", help="Enable deterministic output")
    sandbox_parser.add_argument("--exit-code", action="store_true", help="Exit non-zero on findings")
    sandbox_parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"], default=None)
    sandbox_parser.add_argument("--quiet", "-q", action="store_true")
    sandbox_parser.add_argument("--summary", action="store_true")
    sandbox_parser.add_argument("--backend", choices=["auto", "seccomp-bpf", "seatbelt", "subprocess"], default="auto")
    sandbox_parser.add_argument("--policy", type=str, default=None, help="Path to sandbox policy file")
    sandbox_parser.add_argument("--timeout", type=int, default=None, help="Sandbox timeout in seconds")

    sandbox_sub = sandbox_parser.add_subparsers(dest="sandbox_command")
    analyze_p = sandbox_sub.add_parser("analyze", help="Run L4 behavioral analysis on sandbox output")
    analyze_p.add_argument("input", type=str, help="Sandbox result JSON to analyze")
    pipeline_p = sandbox_sub.add_parser("pipeline", help="Run full L3+L4 pipeline on a command")
    pipeline_p.add_argument("command", nargs="+", type=str, help="Command to sandbox and analyze")
    _ = sandbox_sub.add_parser("rules", help="List available L4 detector rules")
    _ = sandbox_sub.add_parser("init", help="Initialize sandbox configuration")

    # -- watch (PicoWatch) --
    watch_parser = subparsers.add_parser("watch", help="LLM prompt injection detection and output validation")
    watch_sub = watch_parser.add_subparsers(dest="watch_command")

    scan_prompt_p = watch_sub.add_parser("scan-prompt", help="Scan a prompt for injection attempts")
    scan_prompt_p.add_argument("--text", "-t", type=str, default=None, help="Prompt text to scan")
    scan_prompt_p.add_argument("--file", "-f", type=str, default=None, help="File containing prompt text")

    validate_p = watch_sub.add_parser("validate-output", help="Validate LLM output against a schema")
    validate_p.add_argument("--schema", "-s", type=str, required=True, help="Schema file path")
    validate_p.add_argument("--output", "-o", type=str, required=True, help="Output file to validate")

    _ = watch_sub.add_parser("rules", help="List available watch rules")
    health_p = watch_sub.add_parser("health", help="Check watch health")
    serve_watch_p = watch_sub.add_parser("serve", help="Start PicoWatch HTTP daemon")
    serve_watch_p.add_argument("--host", type=str, default="127.0.0.1")
    serve_watch_p.add_argument("--port", "-p", type=int, default=8766)

    # -- serve (PicoShogun) --
    serve_parser = subparsers.add_parser("serve", help="Start API server, dashboard, and orchestration")
    serve_parser.add_argument("--host", type=str, default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8765)
    serve_parser.add_argument("--reload", action="store_true", help="Enable hot reload")
    serve_parser.add_argument("--workers", type=int, default=1)

    # -- top-level subcommands --
    subparsers.add_parser("version", help="Show version and exit")
    subparsers.add_parser("health", help="Run health checks")
    init_parser = subparsers.add_parser("init", help="Generate configuration template")
    init_parser.add_argument("target", type=str, nargs="?", default=".", help="Directory to create config in")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing config file")
    rules_parser = subparsers.add_parser("rules", help="List available scanner rules")
    rules_parser.add_argument("--json", "-j", action="store_true", dest="json_output", help="Output as JSON")
    subparsers.add_parser("update", help="Download latest npm corpus")
    diff_parser = subparsers.add_parser("diff", help="Compare two scan result JSONs")
    diff_parser.add_argument("path_a", type=str, help="First scan result")
    diff_parser.add_argument("path_b", type=str, help="Second scan result")
    diff_parser.add_argument("--verbose", action="store_true", help="Show detailed diff")

    args = parser.parse_args(argv)

    # --version flag
    if args.version or (hasattr(args, "command") and args.command == "version"):
        _show_version()
        return

    # Verbose
    if args.verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG)

    # Delegate to subcommand handlers
    exit_code = 0
    if args.command == "scan":
        exit_code = _handle_scan(args)
    elif args.command == "sandbox":
        _handle_sandbox(args)
    elif args.command == "watch":
        _handle_watch(args)
    elif args.command == "serve":
        _handle_serve(args)
    elif args.command == "health":
        exit_code = _handle_health()
    elif args.command == "init":
        exit_code = _handle_init(args)
    elif args.command == "rules":
        exit_code = _handle_rules(args)
    elif args.command == "update":
        exit_code = _handle_update()
    elif args.command == "diff":
        _handle_diff(args)
    elif args.command == "version":
        _show_version()
    else:
        parser.print_help()
        sys.exit(0)

    if exit_code:
        sys.exit(exit_code)


def _show_version() -> None:
    """Print version info for all components and exit."""
    try:
        from picosentry.scan import __version__ as scan_version
    except ImportError:
        scan_version = "N/A"
    try:
        from picosentry.sandbox import __version__ as sandbox_version
    except ImportError:
        sandbox_version = "N/A"
    try:
        from picosentry.watch import __version__ as watch_version
    except ImportError:
        watch_version = "N/A"
    try:
        from picosentry.serve.config.version import __version__ as serve_version
    except ImportError:
        serve_version = "N/A"

    print(f"PicoSentry (unified) v{_get_unified_version()}")
    print(f"  scan:    v{scan_version}")
    print(f"  sandbox: v{sandbox_version}")
    print(f"  watch:   v{watch_version}")
    print(f"  serve:   v{serve_version}")


def _get_unified_version() -> str:
    """Return the unified package version."""
    try:
        from picosentry import __version__
        return __version__
    except ImportError:
        return "0.0.0"


def _forward_flag(argv: list[str], args: argparse.Namespace, *flags: str, boolean: bool = False, default=None) -> None:
    """Forward a CLI flag from parsed args to the target argv list if set.

    Usage: _forward_flag(argv, args, '--format')
           _forward_flag(argv, args, '--quiet', '-q', boolean=True)
    """
    name = flags[0]  # use the long form for the flag name
    dest = name.lstrip("-").replace("-", "_")

    val = getattr(args, dest, None)
    # Also check short-form dest
    if val is None and len(flags) > 1:
        short_dest = flags[1].lstrip("-").replace("-", "_")
        val = getattr(args, short_dest, None)

    if val is None or val == default or val == ():
        return

    if boolean:
        # Only forward True boolean flags
        if val is True:
            argv.append(name)
    elif isinstance(val, list):
        argv.extend([name] + list(val))
    else:
        argv.extend([name, str(val)])


def _handle_scan(args: argparse.Namespace) -> int:
    """Delegate to the scan CLI."""
    from picosentry.scan.cli import main as scan_main

    # Build argv for the scan CLI (target is nargs="*" = list)
    # Prepend 'scan' subcommand since the scan CLI has its own subparsers
    scan_argv: list[str] = ["scan"]
    if args.target:
        scan_argv.extend(args.target)

    # Forward all scan CLI flags (must match scan_parser def above)
    _forward_flag(scan_argv, args, "--format")
    _forward_flag(scan_argv, args, "--quiet", "-q", boolean=True)
    _forward_flag(scan_argv, args, "--summary", boolean=True)
    _forward_flag(scan_argv, args, "--deterministic-output", "-D", boolean=True)
    _forward_flag(scan_argv, args, "--exit-code", boolean=True)
    _forward_flag(scan_argv, args, "--fail-on")
    _forward_flag(scan_argv, args, "--token-budget")
    _forward_flag(scan_argv, args, "--corpus")
    _forward_flag(scan_argv, args, "--output", "-o")
    _forward_flag(scan_argv, args, "--verbose", "-v", boolean=True)
    _forward_flag(scan_argv, args, "--timeout")
    _forward_flag(scan_argv, args, "--severity-threshold")
    _forward_flag(scan_argv, args, "--baseline", "-b")
    _forward_flag(scan_argv, args, "--baseline-update", boolean=True)
    _forward_flag(scan_argv, args, "--no-color", boolean=True)
    _forward_flag(scan_argv, args, "--verify-determinism", boolean=True)
    _forward_flag(scan_argv, args, "--sarif-file")
    _forward_flag(scan_argv, args, "--policy", "-p")
    _forward_flag(scan_argv, args, "--fail-on-rule-error", boolean=True)
    _forward_flag(scan_argv, args, "--enterprise", boolean=True)
    _forward_flag(scan_argv, args, "--advisory-db")
    _forward_flag(scan_argv, args, "--rules", "-r")

    return scan_main(argv=scan_argv)


def _handle_rules(args: argparse.Namespace) -> int:
    """List available scanner rules."""
    from picosentry.scan.cli import main as scan_main
    scan_argv = ["rules"]
    if getattr(args, "json_output", False):
        scan_argv.append("--json")
    return scan_main(argv=scan_argv)


def _handle_update() -> int:
    """Update the npm corpus."""
    from picosentry.scan.cli import main as scan_main
    return scan_main(argv=["update"])


def _handle_diff(args: argparse.Namespace) -> None:
    """Compare two scan result JSONs."""
    from picosentry.scan.guards import diff_scans
    result = diff_scans(Path(args.path_a), Path(args.path_b), verbose=args.verbose)
    print(result[1])
    sys.exit(result[0])


def _handle_scan_subcommand(args: argparse.Namespace) -> None:
    """Handle scan sub-subcommands: rules, update, init, diff."""
    if args.scan_command == "rules":
        from picosentry.scan.rules import RULE_INFO
        print(f"Available scanner rules ({len(RULE_INFO)}):")
        for rule_id, info in sorted(RULE_INFO.items()):
            desc = info.get("description", "")
            print(f"  {rule_id}: {desc}")
    elif args.scan_command == "update":
        from picosentry.scan.cli import main as scan_main
        scan_main(argv=["update"])
    elif args.scan_command == "init":
        from picosentry.scan.cli import main as scan_main
        scan_main(argv=["init"])
    elif args.scan_command == "diff":
        from picosentry.scan.guards import diff_scans
        result = diff_scans(Path(args.path_a), Path(args.path_b), verbose=args.verbose)
        print(result[1])
        sys.exit(result[0])


def _handle_sandbox(args: argparse.Namespace) -> None:
    """Delegate to the sandbox (PicoDome) CLI."""
    if hasattr(args, "sandbox_command") and args.sandbox_command:
        _handle_sandbox_subcommand(args)
        return

    from picosentry.sandbox.cli import main as sandbox_main

    sandbox_argv: list[str] = []
    if args.command:
        sandbox_argv.extend(args.command)
    if args.format:
        sandbox_argv.extend(["--format", args.format])
    if args.deterministic_output:
        sandbox_argv.append("--deterministic-output")
    if args.exit_code:
        sandbox_argv.append("--exit-code")
    if args.fail_on:
        sandbox_argv.extend(["--fail-on", args.fail_on])
    if args.quiet:
        sandbox_argv.append("--quiet")
    if args.summary:
        sandbox_argv.append("--summary")
    if args.backend:
        sandbox_argv.extend(["--backend", args.backend])
    if args.policy:
        sandbox_argv.extend(["--policy", args.policy])
    if args.timeout:
        sandbox_argv.extend(["--timeout", str(args.timeout)])

    sandbox_main(argv=sandbox_argv if sandbox_argv else None)


def _handle_sandbox_subcommand(args: argparse.Namespace) -> None:
    """Handle sandbox sub-subcommands: analyze, pipeline, rules, init."""
    from picosentry.sandbox.cli import main as sandbox_main

    if args.sandbox_command in ("analyze", "pipeline"):
        cmd: list[str] = []
        if args.sandbox_command == "analyze":
            cmd.append(args.input)
        elif args.sandbox_command == "pipeline":
            cmd.extend(args.command)
        sandbox_main(argv=cmd if cmd else None)
    elif args.sandbox_command == "rules":
        sandbox_main(argv=["rules"])
    elif args.sandbox_command == "init":
        sandbox_main(argv=["init"])


def _handle_watch(args: argparse.Namespace) -> None:
    """Delegate to the watch (PicoWatch) CLI."""
    from picosentry.watch.cli import main as watch_main

    watch_argv: list[str] = []
    if hasattr(args, "watch_command") and args.watch_command:
        if args.watch_command == "scan-prompt":
            watch_argv.append("scan-prompt")
            if args.text:
                watch_argv.extend(["--text", args.text])
            if args.file:
                watch_argv.extend(["--file", args.file])
        elif args.watch_command == "validate-output":
            watch_argv.append("validate-output")
            watch_argv.extend(["--schema", args.schema, "--output", args.output])
        elif args.watch_command == "rules":
            watch_argv.append("rules")
        elif args.watch_command == "health":
            watch_argv.append("health")
        elif args.watch_command == "serve":
            watch_argv.append("serve")
            watch_argv.extend(["--host", args.host, "--port", str(args.port)])
    else:
        watch_argv.append("--help")

    watch_main(argv=watch_argv if watch_argv else None)


def _handle_serve(args: argparse.Namespace) -> None:
    """Start the API server (PicoShogun)."""
    import os
    # Override settings via env for CLI args
    if args.host:
        os.environ["PICOSHOGUN_API_HOST"] = args.host
    if args.port:
        os.environ["PICOSHOGUN_API_PORT"] = str(args.port)
    if args.reload:
        os.environ["PICOSHOGUN_API_RELOAD"] = "true"
    if args.workers:
        os.environ["PICOSHOGUN_API_WORKERS"] = str(args.workers)

    from picosentry.serve.api.server import main as serve_main
    serve_main()


def _handle_health() -> int:
    """Run health checks."""
    print("PicoSentry Health Check")
    print("=" * 40)

    checks = []

    # Check scan module
    try:
        from picosentry.scan.engine import create_default_engine
        checks.append(("scan", "ok", "engine importable"))
    except ImportError as e:
        checks.append(("scan", "FAIL", str(e)))

    # Check sandbox module
    try:
        from picosentry.sandbox import __version__
        checks.append(("sandbox", "ok", f"v{__version__} importable"))
    except ImportError as e:
        checks.append(("sandbox", "FAIL", str(e)))

    # Check watch module
    try:
        from picosentry.watch import __version__
        checks.append(("watch", "ok", f"v{__version__} importable"))
    except ImportError as e:
        checks.append(("watch", "FAIL", str(e)))

    # Check serve module
    try:
        from picosentry.serve.config.version import __version__ as sv
        checks.append(("serve", "ok", f"v{sv} importable"))
    except ImportError as e:
        checks.append(("serve", "FAIL", str(e)))

    all_ok = all(s == "ok" for _, s, _ in checks)
    for name, status, msg in checks:
        icon = "✓" if status == "ok" else "✗"
        print(f"  {icon} {name}: {msg}")

    if all_ok:
        print("All components healthy.")
        return 0
    else:
        print("Some components failed to load.")
        return 1


def _handle_init(args: argparse.Namespace) -> int:
    """Generate a configuration template by delegating to scan CLI."""
    from picosentry.scan.cli import main as scan_main
    scan_argv = ["init"]
    if getattr(args, "target", None):
        scan_argv.append(args.target)
    if getattr(args, "force", False):
        scan_argv.append("--force")
    return scan_main(argv=scan_argv)


if __name__ == "__main__":
    main()