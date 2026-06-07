"""`notary` subcommand — audit transparency notary (Rekor/Sigstore).

Extracted in v2.1.0 (refactor) from ``picosentry/sandbox/cli.py``.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

NAME = "notary"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    notary_parser = subparsers.add_parser(NAME, help="Audit transparency notary (Rekor/Sigstore)")
    notary_sub = notary_parser.add_subparsers(dest="notary_command", help="notary sub-commands")

    notary_submit = notary_sub.add_parser("submit", help="Submit an audit entry to the notary")
    notary_submit.add_argument("--entry", type=Path, required=True, help="JSON file with the entry to notarize")
    notary_submit.add_argument(
        "--notary",
        choices=["null", "rekor"],
        default="null",
        help="Notary backend (default: null)",
    )
    notary_submit.add_argument("--rekor-url", default="https://rekor.sigstore.dev", help="Rekor API URL")
    notary_submit.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds")
    notary_submit.add_argument(
        "--hmac-key",
        default=None,
        help=(
            "HMAC key (required: pass --hmac-key explicitly, or set "
            "PICODOME_NOTARY_HMAC_KEY in the environment). Hard-error if "
            "neither is provided — a built-in default would let any "
            "third party with the source code forge entries."
        ),
    )

    notary_verify = notary_sub.add_parser("verify", help="Verify an audit entry against the notary")
    notary_verify.add_argument("--uuid", required=True, help="UUID of the entry to verify")
    notary_verify.add_argument("--entry", type=Path, required=True, help="JSON file with the entry to verify")
    notary_verify.add_argument(
        "--notary",
        choices=["null", "rekor"],
        default="null",
        help="Notary backend (default: null)",
    )
    notary_verify.add_argument("--rekor-url", default="https://rekor.sigstore.dev", help="Rekor API URL")
    notary_verify.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds")
    notary_verify.add_argument(
        "--hmac-key",
        default=None,
        help=(
            "HMAC key (required: pass --hmac-key explicitly, or set "
            "PICODOME_NOTARY_HMAC_KEY in the environment). Hard-error if "
            "neither is provided — see `notary submit` for rationale."
        ),
    )


def cmd(args: argparse.Namespace) -> int:
    """Handle notary subcommands (submit, verify)."""
    from picosentry.sandbox.notary import AuditNotary, NullNotary, RekorNotary, sign_entry

    notary: AuditNotary

    if args.notary_command == "submit":
        if not args.entry or not args.entry.exists():
            print(f"Error: entry file not found: {args.entry}", file=sys.stderr)
            return 1

        try:
            with open(args.entry) as f:
                entry = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"Error: failed to read entry file: {exc}", file=sys.stderr)
            return 1

        # v2.0.11: hard-error if no HMAC key is provided. A built-in default
        # (the previous behavior) signed/verified entries with a public
        # constant in this file's source code, which means anyone with
        # the source could forge entries. For a feature marketed as a
        # transparency log / Rekor integration, that's a real integrity
        # hole. Users must set PICODOME_NOTARY_HMAC_KEY or pass --hmac-key.
        hmac_key = args.hmac_key or os.environ.get("PICODOME_NOTARY_HMAC_KEY")
        if not hmac_key:
            print(
                "Error: PICODOME_NOTARY_HMAC_KEY or --hmac-key is required. "
                "Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'",
                file=sys.stderr,
            )
            return 1

        if args.notary == "rekor":
            notary = RekorNotary(
                rekor_url=args.rekor_url,
                timeout=args.timeout,
                hmac_key=hmac_key,
            )
        else:
            notary = NullNotary(hmac_key=hmac_key)

        # Sign locally first
        signature = sign_entry(entry, key=hmac_key)
        print(f"HMAC-SHA256 signature: {signature}")

        # Submit to notary
        try:
            uuid = notary.submit_entry(entry)
            print(f"Entry submitted: {uuid}")
            print(f"Notary backend: {args.notary}")
        except Exception as exc:
            print(f"Error: notary submission failed: {exc}", file=sys.stderr)
            return 1

        return 0

    elif args.notary_command == "verify":
        if not args.entry or not args.entry.exists():
            print(f"Error: entry file not found: {args.entry}", file=sys.stderr)
            return 1

        try:
            with open(args.entry) as f:
                entry = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"Error: failed to read entry file: {exc}", file=sys.stderr)
            return 1

        # v2.0.11: hard-error if no HMAC key is provided. See submit for rationale.
        hmac_key = args.hmac_key or os.environ.get("PICODOME_NOTARY_HMAC_KEY")
        if not hmac_key:
            print(
                "Error: PICODOME_NOTARY_HMAC_KEY or --hmac-key is required. "
                "Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'",
                file=sys.stderr,
            )
            return 1

        if args.notary == "rekor":
            notary = RekorNotary(
                rekor_url=args.rekor_url,
                timeout=args.timeout,
                hmac_key=hmac_key,
            )
        else:
            notary = NullNotary(hmac_key=hmac_key)

        try:
            verified = notary.verify_entry(args.uuid, entry)
            if verified:
                print(f"✓ Entry {args.uuid} verified successfully")
                return 0
            else:
                print(f"✗ Entry {args.uuid} verification FAILED", file=sys.stderr)
                return 1
        except Exception as exc:
            print(f"Error: verification failed: {exc}", file=sys.stderr)
            return 1

    else:
        print("Usage: picodome notary {submit|verify}", file=sys.stderr)
        return 1


__all__ = ["NAME", "add_arguments", "cmd"]
