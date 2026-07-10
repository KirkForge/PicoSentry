"""`picosentry sandbox` top-level command wiring.

The implementation lives in ``picosentry.sandbox.cli``; this module registers
it with the unified CLI and forwards arguments.
"""

from __future__ import annotations

import argparse

from picosentry.cli_commands import register
from picosentry.cli_commands._common import forward_flag
from picosentry.cli_commands._maturity import emit_maturity_warning


_KNOWN_SUBCOMMANDS = {"analyze", "pipeline", "rules", "init"}


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    sandbox_parser = subparsers.add_parser("sandbox", help="Runtime sandbox and behavioral analysis")
    # Use dest "sandbox_cmd" so the top-level "command" attribute remains "sandbox".
    sandbox_parser.add_argument("sandbox_cmd", nargs="*", type=str, help="Command to run under sandbox")
    sandbox_parser.add_argument(
        "--format",
        choices=["json", "sarif", "table", "ml-context", "cyclonedx", "github"],
        default="table",
    )
    sandbox_parser.add_argument("--deterministic-output", "-D", action="store_true")
    sandbox_parser.add_argument("--exit-code", action="store_true")
    sandbox_parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"], default=None)
    sandbox_parser.add_argument("--quiet", "-q", action="store_true")
    sandbox_parser.add_argument("--summary", action="store_true")
    sandbox_parser.add_argument(
        "--backend",
        choices=["auto", "seccomp-bpf", "seccomp-trace", "seatbelt", "subprocess"],
        default="auto",
        help=(
            "Sandbox backend: auto (default), seccomp-bpf (enforcement), "
            "seccomp-trace (observability), seatbelt (macOS), subprocess (unconfined)."
        ),
    )
    sandbox_parser.add_argument("--allow-degraded", action="store_true")
    sandbox_parser.add_argument("--allow-runtime", choices=["node", "python"], default=None)
    sandbox_parser.add_argument("--verify-determinism", action="store_true")
    sandbox_parser.add_argument("--policy", type=str, default=None)
    sandbox_parser.add_argument("--timeout", type=int, default=None)
    # Hidden flag consumed when the first positional is "analyze".
    sandbox_parser.add_argument("--input", type=str, default=None, help=argparse.SUPPRESS)


def _handle_sandbox_subcommand(args: argparse.Namespace) -> int:
    from picosentry.sandbox.cli import main as sandbox_main

    sub_cmd = args.sandbox_cmd[0]
    rest = args.sandbox_cmd[1:]

    if sub_cmd == "analyze":
        input_path = getattr(args, "input", None) or (rest[0] if rest else None)
        if input_path:
            return sandbox_main(["analyze", "--input", input_path])
        return sandbox_main(["analyze"])
    if sub_cmd == "pipeline":
        return sandbox_main(["pipeline", *rest])
    if sub_cmd == "rules":
        return sandbox_main(["rules"])
    if sub_cmd == "init":
        return sandbox_main(["init"])
    raise RuntimeError(f"Unexpected sandbox subcommand: {sub_cmd}")


def cmd(args: argparse.Namespace) -> int:
    emit_maturity_warning("sandbox", quiet=getattr(args, "quiet", False))

    if args.sandbox_cmd and args.sandbox_cmd[0] in _KNOWN_SUBCOMMANDS:
        return _handle_sandbox_subcommand(args)

    from picosentry.sandbox.cli import main as sandbox_main

    sandbox_argv: list[str] = ["sandbox"]
    if args.sandbox_cmd:
        sandbox_argv.extend(args.sandbox_cmd)
    forward_flag(sandbox_argv, args, "--format")
    forward_flag(sandbox_argv, args, "--deterministic-output", "-D", boolean=True)
    forward_flag(sandbox_argv, args, "--exit-code", boolean=True)
    forward_flag(sandbox_argv, args, "--fail-on")
    forward_flag(sandbox_argv, args, "--quiet", "-q", boolean=True)
    forward_flag(sandbox_argv, args, "--summary", boolean=True)
    forward_flag(sandbox_argv, args, "--backend")
    forward_flag(sandbox_argv, args, "--allow-degraded", boolean=True)
    forward_flag(sandbox_argv, args, "--allow-runtime")
    forward_flag(sandbox_argv, args, "--verify-determinism", boolean=True)
    forward_flag(sandbox_argv, args, "--policy")
    forward_flag(sandbox_argv, args, "--timeout")

    return sandbox_main(sandbox_argv or None)


register("sandbox", add_arguments, cmd)
