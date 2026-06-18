from __future__ import annotations

import argparse
import sys
from pathlib import Path

NAME = "advisories"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="Manage advisory database (fetch)")
    sub = parser.add_subparsers(dest="adv_action", help="Advisory actions")

    fetch = sub.add_parser("fetch", help="Download advisory database from central URL")
    fetch.add_argument("url", type=str, help="URL to advisory database (zip or JSON)")
    fetch.add_argument("--output", "-o", type=str, default=None, help="Output directory (default: $PICOADVISORY_DIR)")
    fetch.add_argument("--verify-crypto", action="store_true", help="Verify cryptographic signature on advisory bundle")
    fetch.add_argument(
        "--public-key",
        type=str,
        default="",
        help="Path to minisign public key (for minisign verification)",
    )
    fetch.add_argument("--offline", action="store_true", help="Use offline Sigstore verification")


def cmd(args: argparse.Namespace) -> int:
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


_cmd_advisories = cmd

__all__ = ["NAME", "_cmd_advisories", "add_arguments", "cmd"]
