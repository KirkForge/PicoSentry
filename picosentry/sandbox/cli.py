from __future__ import annotations

import argparse
import sys

from picosentry.sandbox import __version__
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


_REGISTRY = (
    sandbox,
    analyze,
    pipeline,
    rules,
    diff,
    init,
    cluster,
    daemon,
    scan_grpc,
    health,
    audit,
    retention,
    policy_versions,
    sign_policy,
    notary,
    version,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="picodome",
        description="PicoDome — deterministic runtime sandbox and behavioral analysis",
    )
    parser.add_argument("--version", action="version", version=f"picodome {__version__}")

    sub = parser.add_subparsers(dest="subcommand", help="sub-commands")

    for mod in _REGISTRY:
        mod.add_arguments(sub)

    args = parser.parse_args(argv)

    if args.subcommand is None:
        parser.print_help()
        return 0

    for mod in _REGISTRY:
        if args.subcommand == mod.NAME:
            return mod.cmd(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
