from __future__ import annotations

import argparse
import sys
from pathlib import Path

NAME = "policy"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="Manage enterprise policy bundles (fetch/push/init)")
    sub = parser.add_subparsers(dest="policy_action", help="Policy actions")

    fetch = sub.add_parser("fetch", help="Fetch signed policy bundle from central URL")
    fetch.add_argument("url", type=str, help="URL to fetch policy from")
    fetch.add_argument(
        "--output",
        "-o",
        type=str,
        default=".picosentry-policy.yml",
        help="Output path (default: .picosentry-policy.yml)",
    )
    fetch.add_argument("--no-verify", action="store_true", help="Skip digest verification")
    fetch.add_argument("--verify-crypto", action="store_true", help="Verify cryptographic signature on policy bundle")
    fetch.add_argument("--public-key", type=str, default="", help="Path to minisign public key (for minisign verification)")
    fetch.add_argument("--offline", action="store_true", help="Use offline Sigstore verification")

    push = sub.add_parser("push", help="Push policy bundle to central server")
    push.add_argument("url", type=str, help="Upload endpoint URL")
    push.add_argument("--file", "-f", type=str, default=".picosentry-policy-bundle.json", help="Policy bundle file to push")
    push.add_argument("--api-key", type=str, default="", help="API key for authentication")

    sub.add_parser("init", help="Generate .picosentry-org.yml template for central management")


def cmd(args: argparse.Namespace) -> int:
    if not args.policy_action:
        print("Usage: picosentry policy {fetch|push|init}")
        return 1

    if args.policy_action == "init":
        from picosentry.scan.management import org_config_template

        org_path = Path(".picosentry-org.yml")
        if org_path.exists():
            print(
                f"Error: {org_path} already exists. Remove it first or edit it directly.",
                file=sys.stderr,
            )
            return 1
        org_path.write_text(org_config_template(), encoding="utf-8")
        print(f"Created {org_path}")
        print("Edit this file to configure central policy and advisory URLs for your organization.")
        return 0

    elif args.policy_action == "fetch":
        from picosentry.scan.management import fetch_policy

        output = Path(args.output)
        try:
            fetch_policy(args.url, output, verify=not args.no_verify)
            if args.verify_crypto:
                from picosentry.scan.policy import import_policy_bundle

                import_policy_bundle(
                    output, verify=True, verify_crypto=True, public_key=args.public_key, offline=args.offline
                )
                print("Cryptographic signature verified.")
            print(f"Policy bundle saved to {output}")
            print(f"Apply with: picosentry scan . --policy {output}")
        except Exception as e:
            print(f"Error fetching policy: {e}", file=sys.stderr)
            return 1
        return 0

    elif args.policy_action == "push":
        from picosentry.scan.management import push_policy

        policy_path = Path(args.file)
        if not policy_path.exists():
            print(f"Error: policy bundle not found: {policy_path}", file=sys.stderr)
            return 2
        try:
            push_policy(args.url, policy_path, api_key=args.api_key)
            print("Policy bundle pushed successfully.")
        except Exception as e:
            print(f"Error pushing policy: {e}", file=sys.stderr)
            return 1
        return 0

    return 0


_cmd_policy = cmd

__all__ = ["NAME", "_cmd_policy", "add_arguments", "cmd"]
