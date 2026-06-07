"""PicoDome CLI subcommands — split in v2.1.0 (refactor) from ``sandbox/cli.py``.

Each submodule exposes ``add_arguments(subparsers)`` and ``cmd(args) -> int``.
The orchestrator in :mod:`picosentry.sandbox.cli` dispatches to the matching
module's ``cmd`` based on the parsed subcommand name.
"""
from picosentry.sandbox.cli_commands import (
    analyze,
    audit,
    cluster,
    daemon,
    diff,
    health,
    init,
    notary,
    pipeline,
    policy_versions,
    retention,
    rules,
    sandbox,
    scan_grpc,
    sign_policy,
    version,
)

__all__ = [
    "analyze",
    "audit",
    "cluster",
    "daemon",
    "diff",
    "health",
    "init",
    "notary",
    "pipeline",
    "policy_versions",
    "retention",
    "rules",
    "sandbox",
    "scan_grpc",
    "sign_policy",
    "version",
]
