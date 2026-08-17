"""`picosentry sandbox` top-level command wiring.

The implementation lives in ``picosentry.sandbox.cli``; this module registers
it with the unified CLI and forwards arguments.
"""

from __future__ import annotations

import argparse
import os
import sys

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
        choices=["auto", "seccomp-bpf", "seccomp-trace", "seatbelt", "landlock", "subprocess"],
        default="auto",
        help=(
            "Sandbox backend: auto (default), seccomp-bpf (enforcement), "
            "seccomp-trace (observability), seatbelt (macOS), landlock (explicit-only, "
            "Linux >= 5.13 with landlock LSM), subprocess (unconfined)."
        ),
    )
    sandbox_parser.add_argument("--allow-degraded", action="store_true")
    sandbox_parser.add_argument("--allow-runtime", choices=["node", "python"], default=None)
    sandbox_parser.add_argument("--verify-determinism", action="store_true")
    sandbox_parser.add_argument("--policy", type=str, default=None)
    sandbox_parser.add_argument("--timeout", type=int, default=None)
    # Hidden flag consumed when the first positional is "analyze".
    sandbox_parser.add_argument("--input", type=str, default=None, help=argparse.SUPPRESS)


_FLAG_SPECS: tuple[tuple[str, bool, object], ...] = (
    ("--format", False, "table"),
    ("--deterministic-output", True, False),
    ("--exit-code", True, False),
    ("--fail-on", False, None),
    ("--quiet", True, False),
    ("--summary", True, False),
    ("--backend", False, "auto"),
    ("--allow-degraded", True, False),
    ("--allow-runtime", False, None),
    ("--verify-determinism", True, False),
    ("--policy", False, None),
    ("--timeout", False, None),
    ("--input", False, None),
)

_SUBCOMMAND_FLAGS: dict[str, frozenset[str]] = {
    "analyze": frozenset(
        {
            "--input",
            "--format",
            "--deterministic-output",
            "--exit-code",
            "--fail-on",
            "--quiet",
            "--summary",
        }
    ),
    "pipeline": frozenset(
        {
            "--format",
            "--deterministic-output",
            "--exit-code",
            "--fail-on",
            "--quiet",
            "--summary",
            "--policy",
            "--timeout",
            "--backend",
            "--allow-degraded",
            "--allow-runtime",
        }
    ),
    "rules": frozenset(),
    "init": frozenset(),
}


def _handle_sandbox_subcommand(args: argparse.Namespace) -> int:
    from picosentry.sandbox.cli import main as sandbox_main

    sub_cmd = args.sandbox_cmd[0]
    rest = args.sandbox_cmd[1:]
    allowed = _SUBCOMMAND_FLAGS.get(sub_cmd)
    if allowed is None:
        raise RuntimeError(f"Unexpected sandbox subcommand: {sub_cmd}")

    flag_argv: list[str] = []
    for flag, boolean, default in _FLAG_SPECS:
        if flag in allowed:
            forward_flag(flag_argv, args, flag, boolean=boolean, default=default)
            continue
        dest = flag.lstrip("-").replace("-", "_")
        if getattr(args, dest, None) != default:
            print(f"Error: {flag} is not supported by 'sandbox {sub_cmd}'", file=sys.stderr)
            return 2

    argv: list[str] = [sub_cmd, *flag_argv]
    if sub_cmd == "analyze":
        if not getattr(args, "input", None) and rest:
            argv.extend(["--input", rest[0]])
    elif rest:
        argv.extend(["--", *rest])

    return sandbox_main(argv)


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


# ─── `picosentry cluster` — forwards to `picosentry.sandbox cluster` ─────


def add_cluster_arguments(subparsers: argparse._SubParsersAction) -> None:
    cluster_parser = subparsers.add_parser("cluster", help="Manage daemon cluster mode")
    cluster_sub = cluster_parser.add_subparsers(dest="cluster_action", help="cluster sub-commands")

    join = cluster_sub.add_parser("join", help="Join a cluster via peer address")
    join.add_argument("peer_address", help="Peer address (host:port)")
    join.add_argument("--port", type=int, default=8444, help="Local cluster port (default: 8444)")
    join.add_argument("--node-id", default=None, help="Custom node ID (default: auto-generated)")
    join.add_argument(
        "--backend", choices=["memory", "sqlite"], default="memory", help="State backend (default: memory)"
    )
    join.add_argument("--heartbeat-interval", type=int, default=10, help="Heartbeat interval in seconds (default: 10)")
    join.add_argument("--heartbeat-timeout", type=int, default=30, help="Heartbeat timeout in seconds (default: 30)")
    join.add_argument(
        "--cluster-token",
        default=os.environ.get("PICODOME_CLUSTER_TOKEN", ""),
        help="Shared secret required for gossip membership (also PICODOME_CLUSTER_TOKEN env)",
    )
    join.add_argument(
        "--tls-cert",
        default=os.environ.get("PICODOME_CLUSTER_TLS_CERT", ""),
        help="Client certificate path for TLS/mTLS gossip (also PICODOME_CLUSTER_TLS_CERT env)",
    )
    join.add_argument(
        "--tls-key",
        default=os.environ.get("PICODOME_CLUSTER_TLS_KEY", ""),
        help="Client private key path for TLS/mTLS gossip (also PICODOME_CLUSTER_TLS_KEY env)",
    )
    join.add_argument(
        "--tls-ca",
        default=os.environ.get("PICODOME_CLUSTER_TLS_CA", ""),
        help="CA bundle path to verify peer certificates (also PICODOME_CLUSTER_TLS_CA env)",
    )

    status = cluster_sub.add_parser("status", help="Show cluster node status")
    status.add_argument("--format", "-f", choices=["json", "table"], default="table", help="Output format")

    cluster_sub.add_parser("leave", help="Gracefully leave the cluster")

    rotate = cluster_sub.add_parser("rotate-token", help="Rotate the cluster gossip token")
    rotate.add_argument("--new-token", default=None, help="New token value (default: auto-generated)")
    rotate.add_argument(
        "--retire-after", type=int, default=300, help="Seconds after which old tokens are retired (default: 300)"
    )


def _cmd_cluster(args: argparse.Namespace) -> int:
    emit_maturity_warning("cluster")
    from picosentry.sandbox.cli import main as sandbox_main

    argv = ["cluster"]
    action = getattr(args, "cluster_action", None)
    if action:
        argv.append(action)
        if action == "join":
            forward_flag(argv, args, "--port", default=8444)
            forward_flag(argv, args, "--node-id", default=None)
            forward_flag(argv, args, "--backend", default="memory")
            forward_flag(argv, args, "--heartbeat-interval", default=10)
            forward_flag(argv, args, "--heartbeat-timeout", default=30)
            forward_flag(argv, args, "--cluster-token", default=os.environ.get("PICODOME_CLUSTER_TOKEN", ""))
            forward_flag(argv, args, "--tls-cert", default=os.environ.get("PICODOME_CLUSTER_TLS_CERT", ""))
            forward_flag(argv, args, "--tls-key", default=os.environ.get("PICODOME_CLUSTER_TLS_KEY", ""))
            forward_flag(argv, args, "--tls-ca", default=os.environ.get("PICODOME_CLUSTER_TLS_CA", ""))
            argv.append(args.peer_address)
        elif action == "status":
            forward_flag(argv, args, "--format", "-f", default="table")
        elif action == "rotate-token":
            forward_flag(argv, args, "--new-token", default=None)
            forward_flag(argv, args, "--retire-after", default=300)
    return sandbox_main(argv)


register("cluster", add_cluster_arguments, _cmd_cluster)


register("sandbox", add_arguments, cmd)
