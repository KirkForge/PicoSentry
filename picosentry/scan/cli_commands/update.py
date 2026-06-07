from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

from picosentry.scan.engine import user_corpus_dir
from picosentry.scan._network import InsecureURLError, ResponseTooLargeError, safe_urlopen

NAME = "update"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        NAME, help="Download latest package corpus from npm registry (requires network)"
    )
    parser.add_argument("--top", "-n", type=int, default=1000, help="Number of top packages to download (default: 1000)")
    parser.add_argument("--output", "-o", type=str, default=None, help="Output path for corpus JSON (default: built-in corpus)")


def cmd(args: argparse.Namespace) -> int:
    top_n = args.top
    default_output = user_corpus_dir() / "npm_top_packages.json"
    output_path = Path(args.output) if args.output else default_output

    print(f"Fetching top {top_n} npm packages from registry...")

    try:
        all_packages = set()
        page_size = 250
        seen = 0

        while seen < top_n:
            url = f"https://registry.npmjs.org/-/v1/search?size={page_size}&from={seen}&text=not:unpopular"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            try:
                resp, body = safe_urlopen(req, timeout=30)
            except (InsecureURLError, ResponseTooLargeError) as e:
                print(f"Error: {e}", file=sys.stderr)
                return 1
            try:
                data = json.loads(body.decode("utf-8"))
            finally:
                resp.close()

            if not isinstance(data, dict) or "objects" not in data:
                print("Error: unexpected registry response format", file=sys.stderr)
                return 1

            for pkg in data.get("objects", []):
                name = pkg.get("package", {}).get("name", "")
                if name and not name.startswith("@"):
                    all_packages.add(name)

            total = data.get("total", 0)
            seen += page_size
            if seen >= total or seen >= top_n:
                break

        packages = sorted(all_packages)[:top_n]


        existing = set()
        if output_path.is_file():
            with contextlib.suppress(json.JSONDecodeError, OSError):
                existing = set(json.loads(output_path.read_text(encoding="utf-8")))

        merged = sorted(existing | set(packages))


        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(merged, indent=4, ensure_ascii=False), encoding="utf-8")

        print(
            f"Corpus updated: {len(merged)} packages "
            f"({len(packages)} new from npm, {len(existing)} existing)"
        )
        print(f"Saved to: {output_path}")
        print(
            f"Corpus version hash: {hashlib.sha256(json.dumps(merged, sort_keys=True).encode()).hexdigest()[:16]}"
        )
        return 0

    except Exception as e:
        print(f"Error updating corpus: {e}", file=sys.stderr)
        print("Falling back to built-in corpus.", file=sys.stderr)
        return 1


_cmd_update = cmd

__all__ = ["NAME", "_cmd_update", "add_arguments", "cmd"]
