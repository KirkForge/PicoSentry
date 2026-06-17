

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from pathlib import Path


_COMMAND_MATURITY: dict[str, tuple[str, str]] = {

    "scan": ("STABLE", "Core supply-chain scanner (7 ecosystems)."),
    "sandbox": (
        "BETA",
        "Runtime sandbox + behavioral analysis. Works but may have rough edges; "
        "seccomp-bpf backend is Linux-only.",
    ),
    "watch": (
        "BETA",
        "LLM prompt-injection detection. CLI works; HTTP server is also beta.",
    ),
    "serve": (
        "EXPERIMENTAL",
        "API server, dashboard, and orchestration are in active development. "
        "Do not expose to untrusted networks without additional review.",
    ),
    "daemon": (
        "BETA",
        "Sandbox daemon (HTTP API + optional gRPC). Works but may have rough edges; "
        "seccomp-bpf backend is Linux-only.",
    ),
    "admission": (
        "BETA",
        "K8s admission webhook server. Validates pod security contexts and "
        "optionally scans container images via the daemon.",
    ),
    "corpus": (
        "BETA",
        "Corpus marketplace — export, import, validate, sign, and list IoC packs.",
    ),
}


def _emit_maturity_warning(command: str, quiet: bool = False) -> None:
    if command not in _COMMAND_MATURITY:
        return
    badge, summary = _COMMAND_MATURITY[command]
    if badge == "STABLE":
        return
    if os.environ.get("PICOSENTRY_MATURITY_ACK") == "1":
        return
    if quiet and badge == "BETA":
        return
    icon = "⚠️" if badge == "BETA" else "🔬"
    print(
        f"{icon}  picosentry {command} is {badge}. {summary}",
        file=sys.stderr,
    )
    print(
        "    Set PICOSENTRY_MATURITY_ACK=1 to suppress this warning.",
        file=sys.stderr,
    )


_EXTRA_HINTS: dict[str, str] = {
    "fastapi": "serve",
    "uvicorn": "watch-server",
    "pydantic": "serve",
    "jwt": "serve",  # PyJWT
    "passlib": "serve",
    "python_multipart": "serve",
    "multipart": "serve",
    "croniter": "serve",
    "requests": "scan",
    "opentelemetry": "otel",
    "sigstore": "sigstore",
}


def _extra_for_missing_module(modname: str) -> str | None:
    root = modname.split(".", 1)[0].lower().replace("-", "_")
    return _EXTRA_HINTS.get(root)


def _require_extra(extra: str, what: str) -> Callable[[], None]:
    def _fail() -> None:
        print(
            f"picosentry: {what} requires the optional '{extra}' extra.\n"
            f"  Install it with:  pip install 'picosentry[{extra}]'\n"
            f"  Or install everything:  pip install 'picosentry[all]'",
            file=sys.stderr,
        )
        sys.exit(2)
    return _fail


def _import_or_warn(import_fn: Callable[[], object], extra: str, what: str):
    try:
        return import_fn()
    except ImportError as e:


        missing = getattr(e, "name", None)
        if not missing:
            msg = str(e)
            for sep in ("No module named '", "No module named "):
                if sep in msg:
                    tail = msg.split(sep, 1)[1]
                    missing = tail.split("'", 1)[0].split()[0]
                    break
        detected = _extra_for_missing_module(missing) if missing else None
        if detected is not None:


            _require_extra(detected or extra, what)()
        raise


def main(argv: list[str] | None = None) -> None:


    if argv is None:
        argv = sys.argv[1:]


    if len(argv) >= 2 and argv[0] == "sandbox" and argv[1] in {
        "analyze",
        "pipeline",
        "rules",
        "init",
    }:
        _emit_maturity_warning("sandbox")
        sub_cmd = argv[1]
        if sub_cmd == "analyze":
            _handle_sandbox_subcommand(
                argparse.Namespace(
                    cmd=[sub_cmd, *argv[2:]],  # cmd[0] is the subcommand name
                    input=argv[2] if len(argv) > 2 and not argv[2].startswith("-") else None,
                )
            )
        elif sub_cmd == "pipeline":
            _handle_sandbox_subcommand(
                argparse.Namespace(
                    cmd=[sub_cmd, *argv[2:]],
                )
            )
        elif sub_cmd in {"rules", "init"}:
            _handle_sandbox_subcommand(argparse.Namespace(cmd=[sub_cmd]))
        return

    parser = argparse.ArgumentParser(
        prog="picosentry",
        description="Unified Pico Security Series — scan, sandbox, watch, orchestrate.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-V", "--version", action="store_true", help="Show version and exit")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")


    scan_parser = subparsers.add_parser("scan", help="Supply-chain scanner for 7 ecosystems (npm, PyPI, Go, Cargo, Maven, RubyGems, NuGet)")
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
    scan_parser.add_argument("--validate", action="store_true", help="Run validation harness against built-in fixtures (ignores <target>)")
    scan_parser.add_argument("--sarif-file", type=str, default=None, help="SARIF output path")
    scan_parser.add_argument("--policy", "-p", type=str, default=None, help="Policy file path")
    scan_parser.add_argument("--fail-on-rule-error", action="store_true", help="Fail on rule errors")
    scan_parser.add_argument("--enterprise", action="store_true", help="Enterprise mode")
    scan_parser.add_argument("--advisory-db", type=str, default=None, help="Advisory database path")
    scan_parser.add_argument("--rules", "-r", nargs="+", default=None, help="Run only specific rules")


    sandbox_parser = subparsers.add_parser("sandbox", help="Runtime sandbox and behavioral analysis")
    # Named "cmd" (not "command") to avoid colliding with the top-level
    # subparser's dest="command".  argparse stores both under args.<dest>,
    # and the subparser's value ("sandbox") would overwrite the positional's
    # list if they shared the same dest name.
    sandbox_parser.add_argument("cmd", nargs="*", type=str, help="Command to run under sandbox")
    sandbox_parser.add_argument("--format", choices=["json", "sarif", "table", "ml-context", "cyclonedx", "github"], default="table")
    sandbox_parser.add_argument("--deterministic-output", "-D", action="store_true", help="Enable deterministic output")
    sandbox_parser.add_argument("--exit-code", action="store_true", help="Exit non-zero on findings")
    sandbox_parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"], default=None)
    sandbox_parser.add_argument("--quiet", "-q", action="store_true")
    sandbox_parser.add_argument("--summary", action="store_true")
    sandbox_parser.add_argument(
        "--backend",
        choices=["auto", "seccomp-bpf", "seccomp-trace", "seatbelt", "subprocess"],
        default="auto",
        help=(
            "Sandbox backend: auto (default), seccomp-bpf (enforcement), "
            "seccomp-trace (observability, emits per-syscall events via "
            "SCMP_ACT_LOG; needs CONFIG_SECCOMP_LOG=y), seatbelt (macOS), "
            "subprocess (unconfined, last-resort)."
        ),
    )
    sandbox_parser.add_argument(
        "--allow-degraded",
        action="store_true",
        help="Allow fallback to subprocess if the requested backend is unavailable (default: fail closed).",
    )
    sandbox_parser.add_argument(
        "--allow-runtime",
        choices=["node", "python"],
        default=None,
        help="Use a runtime-friendly policy (node or python) that allows common package-manager operations.",
    )
    sandbox_parser.add_argument(
        "--verify-determinism",
        action="store_true",
        help="Run twice and compare SHA-256 hashes to verify determinism.",
    )
    sandbox_parser.add_argument("--policy", type=str, default=None, help="Path to sandbox policy file")
    sandbox_parser.add_argument("--timeout", type=int, default=None, help="Sandbox timeout in seconds")
    # --input is used by the `analyze` subcommand (routed manually in
    # _handle_sandbox).  It's harmless on the top-level sandbox parser
    # because it's only consumed when the first positional is "analyze".
    sandbox_parser.add_argument("--input", type=str, default=None, help=argparse.SUPPRESS)


    watch_parser = subparsers.add_parser("watch", help="LLM prompt injection detection and output validation")
    watch_sub = watch_parser.add_subparsers(dest="watch_command")

    scan_prompt_p = watch_sub.add_parser("scan-prompt", help="Scan a prompt for injection attempts")
    scan_prompt_p.add_argument("--text", "-t", type=str, default=None, help="Prompt text to scan")
    scan_prompt_p.add_argument("--file", "-f", type=str, default=None, help="File containing prompt text")

    validate_p = watch_sub.add_parser("validate-output", help="Validate LLM output against a schema")
    validate_p.add_argument("--schema", "-s", type=str, required=True, help="Schema file path")
    validate_p.add_argument("--output", "-o", type=str, required=True, help="Output file to validate")

    _ = watch_sub.add_parser("rules", help="List available watch rules")
    watch_sub.add_parser("health", help="Check watch health")
    serve_watch_p = watch_sub.add_parser("serve", help="Start PicoWatch HTTP daemon")
    serve_watch_p.add_argument("--host", type=str, default="127.0.0.1")
    serve_watch_p.add_argument("--port", "-p", type=int, default=8766)


    serve_parser = subparsers.add_parser("serve", help="Start API server, dashboard, and orchestration")
    serve_parser.add_argument("--host", type=str, default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8765)
    serve_parser.add_argument("--reload", action="store_true", help="Enable hot reload")
    serve_parser.add_argument("--workers", type=int, default=1)
    serve_parser.add_argument(
        "--plugin-dir",
        action="append",
        default=[],
        dest="plugin_dirs",
        metavar="PATH",
        help="Additional plugin directory to scan (repeatable). The bundled "
             "picosentry/serve/plugins/ is always scanned; this adds extras. "
             "Takes precedence over the PICOSHOGUN_PLUGIN_DIR env var.",
    )


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

    daemon_parser = subparsers.add_parser(
        "daemon",
        help="Start PicoDome sandbox daemon (HTTP API + optional gRPC transport)",
    )
    daemon_parser.add_argument("--host", default="127.0.0.1", help="HTTP bind address (default: 127.0.0.1)")
    daemon_parser.add_argument("--port", type=int, default=8443, help="HTTP bind port (default: 8443)")
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

    # -- admission subcommand -------------------------------------------------
    admission_parser = subparsers.add_parser(
        "admission",
        help="Start PicoDome K8s admission webhook server (TLS required)",
    )
    admission_parser.add_argument(
        "--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)"
    )
    admission_parser.add_argument(
        "--port", type=int, default=8443, help="Bind port (default: 8443)"
    )
    admission_parser.add_argument(
        "--cert-file",
        required=True,
        help="Path to TLS certificate file (PEM, required — K8s requires TLS)",
    )
    admission_parser.add_argument(
        "--key-file",
        required=True,
        help="Path to TLS private key file (PEM, required — K8s requires TLS)",
    )
    admission_parser.add_argument(
        "--background", action="store_true", help="Run in background"
    )
    admission_parser.add_argument(
        "--scan-enabled",
        action="store_true",
        default=None,
        help="Enable container image scanning via the daemon",
    )
    admission_parser.add_argument(
        "--scan-min-severity",
        choices=["info", "low", "medium", "high", "critical"],
        default="high",
        help="Minimum severity for image-scan blocking (default: high)",
    )
    admission_parser.add_argument(
        "--daemon-url",
        default=None,
        help="PicoDome daemon URL for image scanning (default: http://127.0.0.1:8443)",
    )

    # -- corpus subcommand ----------------------------------------------------
    # Delegates to picosentry/scan/cli_commands/corpus.py via add_arguments().
    # The corpus module has its own sub-subparsers (export/import/validate/list/sign).
    from picosentry.scan.cli_commands import corpus as _corpus_mod
    _corpus_mod.add_arguments(subparsers)

    args = parser.parse_args(argv)


    if getattr(args, "command", None) == "scan" and (
        getattr(args, "quiet", False) or getattr(args, "summary", False)
    ):
        os.environ.setdefault("PICOSENTRY_QUIET", "1")


    if args.version or (hasattr(args, "command") and args.command == "version"):
        _show_version()
        return


    if args.verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG)


    exit_code = 0
    if args.command == "scan":
        exit_code = _handle_scan(args)
    elif args.command == "sandbox":
        _emit_maturity_warning("sandbox", quiet=getattr(args, "quiet", False))
        _handle_sandbox(args)
    elif args.command == "watch":
        _emit_maturity_warning("watch")
        _handle_watch(args)
    elif args.command == "serve":
        _emit_maturity_warning("serve")
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
    elif args.command == "daemon":
        _emit_maturity_warning("daemon")
        from picosentry.sandbox.cli_commands import daemon as _daemon_mod
        exit_code = _daemon_mod.cmd(args)
    elif args.command == "admission":
        _emit_maturity_warning("admission")
        from picosentry.sandbox.cli_commands import admission as _admission_mod
        exit_code = _admission_mod.cmd(args)
    elif args.command == "corpus":
        _emit_maturity_warning("corpus")
        from picosentry.scan.cli_commands import corpus as _corpus_mod
        exit_code = _corpus_mod.cmd(args)
    elif args.command == "version":
        _show_version()
    else:
        parser.print_help()
        sys.exit(0)

    if exit_code:
        sys.exit(exit_code)


def _show_version() -> None:
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
    try:
        from picosentry import __version__
        return __version__
    except ImportError:
        return "0.0.0"


def _forward_flag(argv: list[str], args: argparse.Namespace, *flags: str, boolean: bool = False, default=None) -> None:
    name = flags[0]  # use the long form for the flag name
    dest = name.lstrip("-").replace("-", "_")

    val = getattr(args, dest, None)

    if val is None and len(flags) > 1:
        short_dest = flags[1].lstrip("-").replace("-", "_")
        val = getattr(args, short_dest, None)

    if val is None or val == default or val == ():
        return

    if boolean:

        if val is True:
            argv.append(name)
    elif isinstance(val, list):
        argv.extend([name, *list(val)])
    else:
        argv.extend([name, str(val)])


def _handle_scan(args: argparse.Namespace) -> int:
    from picosentry.scan.cli import main as scan_main


    scan_argv: list[str] = ["scan"]
    if args.target:
        scan_argv.extend(args.target)
    elif getattr(args, "validate", False):


        scan_argv.append(".")


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
    _forward_flag(scan_argv, args, "--validate", boolean=True)
    _forward_flag(scan_argv, args, "--sarif-file")
    _forward_flag(scan_argv, args, "--policy", "-p")
    _forward_flag(scan_argv, args, "--fail-on-rule-error", boolean=True)
    _forward_flag(scan_argv, args, "--enterprise", boolean=True)
    _forward_flag(scan_argv, args, "--advisory-db")
    _forward_flag(scan_argv, args, "--rules", "-r")

    return scan_main(argv=scan_argv)


def _handle_rules(args: argparse.Namespace) -> int:
    from picosentry.scan.cli import main as scan_main
    scan_argv = ["rules"]
    if getattr(args, "json_output", False):
        scan_argv.append("--json")
    return scan_main(argv=scan_argv)


def _handle_update() -> int:
    scan_main = _import_or_warn(
        lambda: __import__("picosentry.scan.cli", fromlist=["main"]).main,
        extra="scan",
        what="'picosentry update' (online corpus download)",
    )
    return scan_main(argv=["update"])


def _handle_diff(args: argparse.Namespace) -> None:
    from picosentry.scan.guards import diff_scans
    result = diff_scans(Path(args.path_a), Path(args.path_b), verbose=args.verbose)
    print(result[1])
    sys.exit(result[0])


def _handle_scan_subcommand(args: argparse.Namespace) -> None:
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
    # Manual subcommand routing.  We removed the argparse subparser
    # because it conflicted with the `cmd` positional (nargs="*"):
    # argparse tried to match the first positional against subparser
    # choices and rejected anything that wasn't analyze/pipeline/rules/init.
    # Now we check the first positional ourselves.
    _KNOWN_SUBCOMMANDS = {"analyze", "pipeline", "rules", "init"}

    if args.cmd and args.cmd[0] in _KNOWN_SUBCOMMANDS:
        _handle_sandbox_subcommand(args)
        return

    from picosentry.sandbox.cli import main as sandbox_main

    # Prepend "sandbox" — the sandbox CLI's own subcommand that actually
    # runs commands under the sandbox.  Without it, sandbox_main() would
    # see "echo" as its subcommand and reject it.
    sandbox_argv: list[str] = ["sandbox"]
    if args.cmd:
        sandbox_argv.extend(args.cmd)
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
    if getattr(args, "allow_degraded", False):
        sandbox_argv.append("--allow-degraded")
    if getattr(args, "allow_runtime", None):
        sandbox_argv.extend(["--allow-runtime", args.allow_runtime])
    if getattr(args, "verify_determinism", False):
        sandbox_argv.append("--verify-determinism")
    if args.policy:
        sandbox_argv.extend(["--policy", args.policy])
    if args.timeout:
        sandbox_argv.extend(["--timeout", str(args.timeout)])

    sandbox_main(argv=sandbox_argv if sandbox_argv else None)


def _handle_sandbox_subcommand(args: argparse.Namespace) -> None:
    from picosentry.sandbox.cli import main as sandbox_main

    sub_cmd = args.cmd[0]  # first positional is the subcommand name
    rest = args.cmd[1:]    # remaining positionals are the subcommand's args

    if sub_cmd == "analyze":
        # --input can come from --input flag or from the second positional
        input_path = getattr(args, "input", None) or (rest[0] if rest else None)
        if input_path:
            sandbox_main(argv=["analyze", "--input", input_path])
        else:
            sandbox_main(argv=["analyze"])
    elif sub_cmd == "pipeline":
        sandbox_main(argv=["pipeline", *rest])
    elif sub_cmd == "rules":
        sandbox_main(argv=["rules"])
    elif sub_cmd == "init":
        sandbox_main(argv=["init"])


def _handle_watch(args: argparse.Namespace) -> None:


    wants_http = getattr(args, "watch_command", None) == "serve"
    what = (
        "the 'watch serve' subcommand (HTTP daemon)"
        if wants_http
        else "the 'watch' subcommand"
    )
    if wants_http:
        watch_main = _import_or_warn(
            lambda: __import__("picosentry.watch.cli", fromlist=["main"]).main,
            extra="watch-server",
            what=what,
        )
    else:
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
    import os

    if args.host:
        os.environ["PICOSHOGUN_API_HOST"] = args.host
    if args.port:
        os.environ["PICOSHOGUN_API_PORT"] = str(args.port)
    if args.reload:
        os.environ["PICOSHOGUN_API_RELOAD"] = "true"
    if args.workers:
        os.environ["PICOSHOGUN_API_WORKERS"] = str(args.workers)

    # Plugin dirs: CLI flag list wins over the env var. We join into the
    # same comma-separated format `PICOSHOGUN_PLUGIN_DIR` expects so
    # that any subprocess workers (uvicorn with --workers > 1) see the
    # same list as the parent process. The plugin_manager singleton
    # was already constructed at module import time, so we also call
    # `reload()` to fold the extra dirs in immediately.
    plugin_dirs = list(getattr(args, "plugin_dirs", []) or [])
    if plugin_dirs:
        existing = os.environ.get("PICOSHOGUN_PLUGIN_DIR", "").strip()
        merged = [p for p in (existing.split(",") if existing else []) if p]
        merged.extend(plugin_dirs)
        os.environ["PICOSHOGUN_PLUGIN_DIR"] = ",".join(merged)

    serve_main = _import_or_warn(
        lambda: __import__("picosentry.serve.api.server", fromlist=["main"]).main,
        extra="serve",
        what="the 'serve' subcommand (API server + dashboard)",
    )

    # Re-discover plugins with the CLI dirs (the singleton was
    # constructed at module import time, before the env var was set).
    # Done before `serve_main()` so the /plugins router sees the new
    # plugins when the server first starts.
    if plugin_dirs:
        try:
            from picosentry.serve.services.plugin_manager import plugin_manager
            plugin_manager.reload(plugin_dirs)
        except ImportError:
            pass  # serve extra not installed; nothing to do

    serve_main()


def _handle_health() -> int:
    print("PicoSentry Health Check")
    print("=" * 40)

    checks = []


    try:
        from picosentry.scan.engine import ScanEngine  # noqa: F401

        checks.append(("scan", "ok", "engine importable"))
    except ImportError as e:
        checks.append(("scan", "FAIL", str(e)))


    try:
        from picosentry.sandbox import __version__
        checks.append(("sandbox", "ok", f"v{__version__} importable"))
    except ImportError as e:
        checks.append(("sandbox", "FAIL", str(e)))


    try:
        from picosentry.watch import __version__
        checks.append(("watch", "ok", f"v{__version__} importable"))
    except ImportError as e:
        checks.append(("watch", "FAIL", str(e)))


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
    from picosentry.scan.cli import main as scan_main
    scan_argv = ["init"]
    if getattr(args, "target", None):
        scan_argv.append(args.target)
    if getattr(args, "force", False):
        scan_argv.append("--force")
    return scan_main(argv=scan_argv)


if __name__ == "__main__":
    main()
