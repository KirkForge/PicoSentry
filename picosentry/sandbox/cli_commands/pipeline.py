from __future__ import annotations

import argparse
import sys
from pathlib import Path

from picosentry.sandbox.cli_commands._common import (
    _add_common_flags,
    _auto_detect_policy,
    _compute_exit_code_pipeline,
    _resolve_external_path,
    _workspace_root,
)
from picosentry.sandbox.formatters.cyclonedx import format_cyclonedx
from picosentry.sandbox.formatters.github import format_github
from picosentry.sandbox.formatters.json_fmt import format_pipeline_json
from picosentry.sandbox.formatters.ml_context import format_ml_context
from picosentry.sandbox.formatters.sarif import format_sarif
from picosentry.sandbox.formatters.table import format_table
from picosentry.sandbox.guards import DeterministicGuard
from picosentry.sandbox.l3.engine import sandbox_run
from picosentry.sandbox.l3.policy import load_policy
from picosentry.sandbox.l4.engine import create_default_engine
from picosentry.sandbox.l4.profiler import profile_from_sandbox_result

NAME = "pipeline"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="Run full L3+L4 pipeline on a command")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to execute")
    parser.add_argument("--policy", "-p", type=Path, help="Policy file")
    parser.add_argument("--timeout", "-t", type=float, default=30.0, help="Timeout in seconds")
    parser.add_argument(
        "--backend",
        "-b",
        choices=["auto", "seccomp-bpf", "seccomp-trace", "seatbelt", "subprocess"],
        default="auto",
        help="Sandbox backend: auto (default), seccomp-bpf, seccomp-trace, seatbelt, subprocess",
    )
    parser.add_argument(
        "--allow-degraded",
        action="store_true",
        help="Allow fallback to subprocess if requested backend is unavailable",
    )
    parser.add_argument(
        "--allow-runtime",
        choices=["node", "python"],
        help="Use a runtime-friendly policy (node or python) that allows common package manager operations",
    )
    parser.add_argument("--cwd", "-C", help="Working directory")
    parser.add_argument(
        "--format",
        "-f",
        choices=["json", "sarif", "table", "ml-context", "github", "cyclonedx"],
        default="table",
    )
    parser.add_argument("--rules", "-r", nargs="*", help="Specific L4 rule IDs to run")
    _add_common_flags(parser)


def cmd(args: argparse.Namespace) -> int:

    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        print("Error: no command specified", file=sys.stderr)
        return 1

    workspace_root = _workspace_root()

    if args.policy is not None:
        policy_path = _resolve_external_path(
            str(args.policy),
            workspace_root,
            must_exist=True,
            description="--policy",
        )
        if policy_path is None:
            return 2
        policy = load_policy(policy_path, verify_signature=True)
    elif getattr(args, "allow_runtime", None):
        policy = load_policy(name=args.allow_runtime)
    else:
        policy = _auto_detect_policy(args.command)

    cwd: str | None = None
    if args.cwd is not None:
        cwd_path = _resolve_external_path(
            args.cwd,
            workspace_root,
            must_exist=True,
            description="--cwd",
        )
        if cwd_path is None:
            return 2
        cwd = str(cwd_path)

    deterministic = args.deterministic_output

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

    sandbox = sandbox_run(
        command=args.command,
        policy=policy,
        timeout=args.timeout,
        cwd=cwd,
        backend=backend,
        deterministic=deterministic,
    )

    profile = profile_from_sandbox_result(sandbox)
    engine = create_default_engine()
    analysis = engine.analyze(profile, rules=args.rules, deterministic=deterministic)

    if deterministic:
        guard = DeterministicGuard()
        violations = guard.check(sandbox) + guard.check(analysis)
        if violations:
            for v in violations:
                print(f"DETERMINISM VIOLATION: {v}", file=sys.stderr)

    if not args.quiet:
        from picosentry.sandbox.cli_commands._common import _output_summary_pipeline

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

    return _compute_exit_code_pipeline(analysis, args)


__all__ = ["NAME", "add_arguments", "cmd"]
