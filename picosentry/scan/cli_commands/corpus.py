from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from picosentry.scan.corpus_share import (
    export_corpus_pack,
    import_corpus_pack,
    list_available_packs,
    validate_corpus_pack,
)

NAME = "corpus"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="Manage custom IoC corpus packs (export/import/list)")
    sub = parser.add_subparsers(dest="corpus_action", help="Corpus actions")


    export = sub.add_parser("export", help="Export custom IoCs as a shareable pack")
    export.add_argument("output", type=str, help="Output file path (.json)")
    export.add_argument("--name", type=str, default="my-iocs", help="Pack name")
    export.add_argument("--description", type=str, default="", help="Pack description")
    export.add_argument("--author", type=str, default="", help="Pack author")
    export.add_argument("--sign", choices=["sigstore", "minisign"], default=None, help="Cryptographically sign the pack")
    export.add_argument("--sign-key", type=str, default="", help="Path to minisign secret key (for --sign minisign)")


    import_ = sub.add_parser("import", help="Import a corpus pack into your IoC registry")
    import_.add_argument("path", type=str, help="Path to corpus pack .json file")
    import_.add_argument("--force", action="store_true", help="Overwrite existing IoCs")
    import_.add_argument("--dry-run", action="store_true", help="Validate only, don't import")
    import_.add_argument("--verify-crypto", action="store_true", help="Verify cryptographic signature (Sigstore/minisign)")
    import_.add_argument("--no-verify-crypto", action="store_true", help="Skip cryptographic signature verification")
    import_.add_argument("--public-key", type=str, default="", help="Path to minisign public key (for minisign verification)")
    import_.add_argument("--offline", action="store_true", help="Use offline Sigstore verification")


    validate = sub.add_parser("validate", help="Validate a corpus pack without importing")
    validate.add_argument("path", type=str, help="Path to corpus pack .json file")


    sub.add_parser("list", help="List available corpus packs (built-in + user)")


    sign = sub.add_parser("sign", help="Sign a corpus pack with cryptographic signature")
    sign.add_argument("path", type=str, help="Path to corpus pack .json file to sign")
    sign.add_argument("--method", choices=["sigstore", "minisign", "digest"], default="digest", help="Signing method (default: digest-only)")
    sign.add_argument("--secret-key", type=str, default="", help="Path to minisign secret key (for minisign method)")
    sign.add_argument("--output", "-o", type=str, default="", help="Output path for signature file (default: <path>.sig)")


def cmd(args: argparse.Namespace) -> int:
    if not args.corpus_action:
        print("Usage: picosentry corpus {export|import|validate|list}")
        return 2

    if args.corpus_action == "list":
        packs = list_available_packs()
        if not packs:
            print("No corpus packs found.")
            return 0
        print("Available corpus packs:")
        print()
        for p in packs:
            source_tag = "[built-in]" if p["source"] == "built-in" else "[user]"
            print("  {:<25s} {}  {} IoC(s)".format(p["name"], source_tag, p["ioc_count"]))
            if p.get("description"):
                print("    {}".format(p["description"]))
            if p.get("file"):
                print("    {}".format(p["file"]))
        return 0

    elif args.corpus_action == "export":
        output = Path(args.output)
        try:
            pack = export_corpus_pack(
                output,
                name=args.name,
                description=args.description,
                author=args.author,
                sign_method=args.sign or "",
                sign_secret_key=args.sign_key,
            )
        except OSError as e:
            print(f"Error exporting corpus pack: {e}", file=sys.stderr)
            return 1
        print(f"Exported {len(pack.iocs)} IoC(s) to {output}")
        print(f"Pack ID: {pack.pack_id}")
        print(f"Format: v{pack.version}")
        print()
        print("Share this file with your team or organization.")
        print(f"Import with: picosentry corpus import {output}")
        return 0

    elif args.corpus_action == "import":
        path = Path(args.path)
        if not path.exists():
            print(f"Error: file not found: {path}", file=sys.stderr)
            return 2
        try:
            stats = import_corpus_pack(
                path,
                allow_overwrite=args.force,
                dry_run=args.dry_run,
                verify_crypto=args.verify_crypto and not args.no_verify_crypto,
                public_key=args.public_key,
                offline=args.offline,
            )
        except (ValueError, OSError, FileNotFoundError) as e:
            print(f"Error importing corpus pack: {e}", file=sys.stderr)
            return 1
        print("Import results for: {}".format(stats["pack_name"]))
        print("  Total IoCs in pack: {}".format(stats["total"]))
        print("  Imported: {}".format(stats["imported"]))
        print("  Skipped (already exists): {}".format(stats["skipped"]))
        if stats["errors"] > 0:
            print("  Errors: {}".format(stats["errors"]))
            for err in stats["error_details"]:
                print(f"    - {err}")
        return 1 if stats["errors"] else 0

    elif args.corpus_action == "validate":
        path = Path(args.path)
        if not path.exists():
            print(f"Error: file not found: {path}", file=sys.stderr)
            return 2
        result = validate_corpus_pack(path)
        if result["valid"]:
            print("Corpus pack is VALID")
            print("  Name: {}".format(result["pack_name"]))
            print("  IoCs: {}".format(result["ioc_count"]))
            if result["warnings"]:
                for w in result["warnings"]:
                    print(f"  Warning: {w}")
            return 0
        else:
            print("Corpus pack is INVALID")
            for err in result["errors"]:
                print(f"  Error: {err}")
            return 1

    elif args.corpus_action == "sign":
        from picosentry.scan.crypto import content_digest, sign_content, write_detached_signature

        path = Path(args.path)
        if not path.exists():
            print(f"Error: file not found: {path}", file=sys.stderr)
            return 2

        method = args.method
        output = Path(args.output) if args.output else path.with_suffix(path.suffix + ".sig")

        content_bytes = path.read_bytes()
        print(f"Signing {path} ({len(content_bytes)} bytes) using {method} method...")

        if method == "digest":
            digest = content_digest(content_bytes)
            print(f"Content digest: sha256:{digest}")
            print(f"Digest-only signature written to {output}")
            sig_bundle = {
                "provider": "digest",
                "digest": f"sha256:{digest}",
                "signed_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
                "content_path": str(path.name),
            }
            output.write_text(json.dumps(sig_bundle, indent=2, sort_keys=True), encoding="utf-8")
            return 0

        try:
            signature = sign_content(
                content_bytes,
                method=method,
                secret_key=args.secret_key or "",
            )
            sig_path = write_detached_signature(signature, path)
            print(f"Signed: {path}")
            print(f"Signature: {sig_path}")
            print(f"Provider: {signature.provider}")
            print(f"Signer: {signature.signer_identity}")
            print(f"Digest: sha256:{signature.digest[:16]}")
            return 0
        except Exception as e:
            print(f"Error signing corpus pack: {e}", file=sys.stderr)
            return 1

    return 0


_cmd_corpus = cmd

__all__ = ["NAME", "_cmd_corpus", "add_arguments", "cmd"]
