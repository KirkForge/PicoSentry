from __future__ import annotations

import argparse
import sys
from pathlib import Path

from picosentry.sandbox.cli_commands._common import (
    _add_common_flags,
    _compute_exit_code_sandbox,
    _output,
    _resolve_external_path,
    _workspace_root,
)
from picosentry.sandbox.guards import DeterministicGuard, verify_determinism
from picosentry.sandbox.l3.engine import sandbox_run
from picosentry.sandbox.l3.policy import load_policy

NAME = "sandbox"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="Run a command under L3 sandbox policy")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to execute")
    parser.add_argument("--policy", "-p", type=Path, help="Policy file (default: built-in)")
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
    _add_common_flags(parser)
    parser.add_argument(
        "--verify-determinism",
        action="store_true",
        help="Run twice and compare SHA-256 hashes to verify determinism",
    )


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
        policy = load_policy(policy_path)
    elif getattr(args, "allow_runtime", None):
        from picosentry.sandbox.l3.policy import load_policy as _lp

        policy = _lp(name=args.allow_runtime)
    else:
        policy = None

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

    result = sandbox_run(
        command=args.command,
        policy=policy,
        timeout=args.timeout,
        cwd=cwd,
        backend=backend,
        deterministic=deterministic,
    )

    if deterministic:
        guard = DeterministicGuard()
        violations = guard.check(result)
        if violations:
            for v in violations:
                print(f"DETERMINISM VIOLATION: {v}", file=sys.stderr)

    if hasattr(args, "verify_determinism") and args.verify_determinism:
        is_match, hash_a, hash_b = verify_determinism(
            args.command,
            policy=policy,
            timeout=args.timeout,
            cwd=cwd,
        )
        if not args.quiet:
            if is_match:
                print(f"✓ Determinism verified: {hash_a}", file=sys.stderr)
            else:
                print(f"✗ Determinism FAILED: {hash_a} != {hash_b}", file=sys.stderr)
        if not is_match:
            return 4

    if not args.quiet:
        _output(result, args)

    return _compute_exit_code_sandbox(result, args)


__all__ = ["NAME", "add_arguments", "cmd"]
