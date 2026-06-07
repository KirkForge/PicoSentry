"""`policy-versions` subcommand — manage versioned policies.

Extracted in v2.1.0 (refactor) from ``picosentry/sandbox/cli.py``.
"""
from __future__ import annotations

import argparse
import json
import sys

NAME = "policy_versions"  # Python identifier; argparse subcommand is "policy-versions"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("policy-versions", help="Manage versioned policies")
    parser.add_argument("action", choices=["list", "show", "diff", "rollback", "verify"], help="Policy action")
    parser.add_argument("--name", help="Policy name")
    parser.add_argument("--version", type=int, help="Policy version")
    parser.add_argument("--version-a", type=int, help="First version for diff")
    parser.add_argument("--version-b", type=int, help="Second version for diff")
    parser.add_argument("--author", default="cli-user", help="Author for rollback")


def cmd(args: argparse.Namespace) -> int:
    """Manage versioned policies."""
    from picosentry.sandbox.policy_versioned import get_policy_store

    store = get_policy_store()

    if args.action == "list":
        names = store.list_policies()
        for name in names:
            versions = store.list_versions(name)
            latest = max(v.version for v in versions) if versions else 0
            print(f"  {name} (v{latest}, {len(versions)} versions)")
        return 0
    elif args.action == "show":
        if not args.name:
            print("--name is required for 'show'", file=sys.stderr)
            return 1
        pv = store.load(args.name, version=args.version)
        if pv is None:
            print(f"Policy '{args.name}' not found", file=sys.stderr)
            return 1
        print(json.dumps(pv.to_dict(), sort_keys=True, indent=2))
        return 0
    elif args.action == "diff":
        if not args.name or args.version_a is None or args.version_b is None:
            print("--name, --version-a, and --version-b are required for 'diff'", file=sys.stderr)
            return 1
        diff = store.diff(args.name, args.version_a, args.version_b)
        print(json.dumps(diff, sort_keys=True, indent=2))
        return 0
    elif args.action == "rollback":
        if not args.name or args.version is None:
            print("--name and --version are required for 'rollback'", file=sys.stderr)
            return 1
        pv = store.rollback(args.name, args.version, author=args.author)
        if pv is None:
            print("Rollback failed", file=sys.stderr)
            return 1
        print(f"Rolled back '{args.name}' to v{args.version} → new v{pv.version}")
        return 0
    elif args.action == "verify":
        if not args.name:
            print("--name is required for 'verify'", file=sys.stderr)
            return 1
        violations = store.verify_integrity(args.name)
        if violations:
            print(f"✗ Integrity violations for '{args.name}':")
            for v in violations:
                print(f"  - {v}")
            return 1
        else:
            print(f"✓ Policy '{args.name}' integrity verified")
            return 0
    return 1


__all__ = ["NAME", "add_arguments", "cmd"]
