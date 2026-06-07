"""`init` subcommand — initialize PicoDome configuration.

Extracted in v2.1.0 (refactor) from ``picosentry/sandbox/cli.py``.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

NAME = "init"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="Initialize PicoDome configuration")
    parser.add_argument("target", nargs="?", default=".", help="Target directory (default: current)")


def cmd(args: argparse.Namespace) -> int:
    """Initialize PicoDome configuration."""
    target = Path(args.target).resolve()
    config_dir = target / ".picodome"
    config_file = config_dir / "policy.json"

    if config_file.exists():
        print(f"PicoDome config already exists: {config_file}")
        return 0

    config_dir.mkdir(parents=True, exist_ok=True)

    default_config = {
        "name": "picodome-default",
        "version": "1.0",
        "default_action": "deny",
        "rules": [
            {
                "rule_id": "L3-FILE-R-001",
                "target": "file_read",
                "action": "allow",
                "paths": ["/usr/lib/**", "/lib/**", "/usr/share/**"],
                "description": "Read system libraries",
            },
            {
                "rule_id": "L3-NET-OUT-001",
                "target": "network_out",
                "action": "deny",
                "description": "Block all outbound network",
            },
        ],
    }

    config_file.write_text(json.dumps(default_config, indent=2, sort_keys=True) + "\n")
    print(f"Created PicoDome config: {config_file}")
    return 0


__all__ = ["NAME", "add_arguments", "cmd"]
