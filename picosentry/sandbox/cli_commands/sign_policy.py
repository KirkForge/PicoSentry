from __future__ import annotations

import argparse
import sys
from pathlib import Path

from picosentry.sandbox.cli_commands._common import _resolve_signing_key

NAME = "sign_policy"  # Python identifier; argparse subcommand is "sign-policy"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    sign_parser = subparsers.add_parser("sign-policy", help="Sign or verify a policy file")
    sign_sub = sign_parser.add_subparsers(dest="sign_action", help="sign-policy sub-commands")

    sign_sign = sign_sub.add_parser("sign", help="Sign a policy file with HMAC-SHA256")
    sign_sign.add_argument("policy_file", type=Path, help="Policy file to sign")
    sign_sign.add_argument("--key", help="HMAC key (hex-encoded). Uses PICODOME_POLICY_KEY env if omitted")
    sign_sign.add_argument("--key-file", type=Path, help="File containing hex-encoded HMAC key")
    sign_sign.add_argument("--key-id", default="default", help="Key identifier for rotation (default: default)")
    sign_sign.add_argument(
        "--companion",
        action="store_true",
        help="Write signature to a companion .sig file instead of inline",
    )

    sign_verify = sign_sub.add_parser("verify", help="Verify a signed policy file")
    sign_verify.add_argument("policy_file", type=Path, help="Policy file to verify")
    sign_verify.add_argument("--key", help="HMAC key (hex-encoded). Uses PICODOME_POLICY_KEY env if omitted")
    sign_verify.add_argument("--key-file", type=Path, help="File containing hex-encoded HMAC key")
    sign_verify.add_argument("--key-id", default="default", help="Expected key identifier (default: default)")
    sign_verify.add_argument(
        "--companion",
        action="store_true",
        help="Verify companion .sig file instead of inline signature",
    )

    sign_genkey = sign_sub.add_parser("generate-key", help="Generate a new HMAC-SHA256 key")
    sign_genkey.add_argument("--output", type=Path, help="Write key to file (otherwise stdout)")


def cmd(args: argparse.Namespace) -> int:
    from picosentry.sandbox.policy_versioned.signing import (
        generate_key,
        key_to_hex,
        sign_policy_companion,
        sign_policy_file,
        verify_policy_companion,
        verify_policy_file,
    )

    if not args.sign_action:
        print("Usage: picodome sign-policy {sign|verify|generate-key}", file=sys.stderr)
        return 1

    if args.sign_action == "sign":
        policy_path = args.policy_file
        if not policy_path.is_file():
            print(f"Error: policy file not found: {policy_path}", file=sys.stderr)
            return 1


        key = _resolve_signing_key(args)
        if key is None:
            return 1

        try:
            if args.companion:
                sig_path = sign_policy_companion(policy_path, key, key_id=args.key_id)
                print(f"✓ Signed policy (companion): {policy_path} -> {sig_path}")
            else:
                sign_policy_file(policy_path, key, key_id=args.key_id)
                print(f"✓ Signed policy: {policy_path}")
            return 0
        except Exception as exc:
            print(f"Error signing policy: {exc}", file=sys.stderr)
            return 1

    elif args.sign_action == "verify":
        policy_path = args.policy_file
        if not policy_path.is_file():
            print(f"Error: policy file not found: {policy_path}", file=sys.stderr)
            return 1


        key = _resolve_signing_key(args)
        if key is None:
            return 1

        if args.companion:
            result = verify_policy_companion(policy_path, key, key_id=args.key_id)
        else:
            result = verify_policy_file(policy_path, key, key_id=args.key_id)

        if result.valid:
            print(f"✓ Policy signature VALID: {policy_path}")
            print(f"  Algorithm: {result.algorithm}")
            print(f"  Key ID:    {result.key_id}")
            print(f"  Timestamp: {result.timestamp}")
            return 0
        print(f"✗ Policy signature INVALID: {policy_path}", file=sys.stderr)
        print(f"  Error: {result.error}", file=sys.stderr)
        return 1

    elif args.sign_action == "generate-key":
        key = generate_key()
        hex_key = key_to_hex(key)

        if args.output:
            args.output.write_text(hex_key)
            print(f"✓ Key written to: {args.output}")
            print(f"  Set PICODOME_POLICY_KEY={hex_key}")
            print(f"  Or set PICODOME_POLICY_KEY_FILE={args.output}")
        else:
            print(hex_key)

        return 0

    else:
        print(f"Unknown sign-policy action: {args.sign_action}", file=sys.stderr)
        return 1


__all__ = ["NAME", "add_arguments", "cmd"]
