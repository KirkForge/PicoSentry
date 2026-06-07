from __future__ import annotations

import argparse
from pathlib import Path

from picosentry.scan.config import load_config

NAME = "cache"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="Manage scan result cache")
    sub = parser.add_subparsers(dest="cache_command", help="Cache commands")

    sub.add_parser("stats", help="Show cache statistics")

    purge = sub.add_parser("purge", help="Purge cache entries by age or hash")
    purge.add_argument("--age-days", type=int, default=0, help="Purge entries older than N days")
    purge.add_argument("--corpus-hash", type=str, default="", help="Purge entries matching corpus hash")
    purge.add_argument("--lockfile-hash", type=str, default="", help="Purge entries matching lockfile hash")

    sub.add_parser("wipe", help="Wipe the entire cache")


def cmd(args: argparse.Namespace) -> int:
    from picosentry.scan.cache import ScanCache

    cache_config = load_config(Path(args.target) if hasattr(args, "target") and args.target else Path.cwd())
    cache = ScanCache(
        cache_dir=Path(cache_config.cache_dir) if cache_config.cache_dir else None,
        max_entries=cache_config.cache_max_entries,
        max_size_mb=cache_config.cache_max_size_mb,
        ttl=cache_config.cache_ttl_seconds,
    )
    subcmd = getattr(args, "cache_command", None)

    if subcmd == "stats":
        stats = cache.stats()
        print(f"Cache directory: {stats['cache_dir']}")
        print(f"Entries: {stats['entries']}")
        print(f"Size: {stats['size_mb']} MB ({stats['size_bytes']} bytes)")
        print(f"TTL: {stats['ttl_seconds']}s")
        print(f"Max entries: {stats['max_entries']} (0=unlimited)")
        print(f"Max size: {stats['max_size_mb']} MB (0=unlimited)")
    elif subcmd == "purge":
        removed = cache.purge(
            age_days=getattr(args, "age_days", 0),
            corpus_hash=getattr(args, "corpus_hash", ""),
            lockfile_hash=getattr(args, "lockfile_hash", ""),
        )
        print(f"Purged {removed} cache entries")
    elif subcmd == "wipe":
        removed = cache.wipe()
        print(f"Wiped {removed} cache entries")
    else:

        stats = cache.stats()
        print(f"Cache directory: {stats['cache_dir']}")
        print(f"Entries: {stats['entries']}")
    return 0


__all__ = ["NAME", "add_arguments", "cmd"]
