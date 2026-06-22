from __future__ import annotations

import argparse
import sys
from pathlib import Path

NAME = "init"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        NAME, help="Generate a .picosentry.yml configuration template in the target directory"
    )
    parser.add_argument(
        "target",
        type=str,
        nargs="?",
        default=".",
        help="Directory to create config file in (default: current directory)",
    )
    parser.add_argument("--force", action="store_true", help="Overwrite existing config file")


def cmd(args: argparse.Namespace) -> int:
    target = Path(args.target).resolve()

    if not target.is_dir():
        print(f"Error: {target} is not a directory", file=sys.stderr)
        return 2

    config_path = target / ".picosentry.yml"

    if config_path.exists() and not args.force:
        print(f"Error: {config_path} already exists. Use --force to overwrite.", file=sys.stderr)
        return 1

    template = """# PicoSentry configuration file
# https://github.com/KirkForge/PicoSentry/blob/main/picosentry/README.md
#
# Config file values are defaults; CLI flags override them.
# Deterministic: same config + same target + same corpus = same output.

version: 1

# Output format: json, sarif, table, ml-context, github
# 'github' writes SARIF file + prints markdown summary for GitHub Actions
# format: json

# Disable colored output
# no_color: false

# Exit with code 1 if findings found
# exit_code: true

# Only fail CI on HIGH or above
# fail_on: high

# Suppress known findings from previous scan
# baseline: baseline.json

# Token budget for ml-context format (default: 4096)
# token_budget: 4096

# SARIF output path for --format github (default: sarif.json)
# sarif_file: sarif.json

# Severity overrides — downgrade/upgrade rule severity
# severity_overrides:
#   L2-PROV-001: INFO
#   L2-FORK-001: LOW

# Ignore specific packages (skip all findings for these)
# ignore_packages:
#   - left-pad
#   - core-js

# Ignore paths matching glob patterns
# ignore_paths:
#   - 'vendor/**'
#   - '**/test/**'

# Run only specific rules
# rules:
#   - L2-POST-001
#   - L2-TYPO-001
#   - L2-OBFS-001
"""

    config_path.write_text(template, encoding="utf-8")
    print(f"Created {config_path}")

    policy_path = target / ".picosentry-policy.yml"
    if not policy_path.exists() or args.force:
        from picosentry.scan.policy import default_policy_template

        policy_path.write_text(default_policy_template(), encoding="utf-8")
        print(f"Created {policy_path}")

    print("Edit the files to configure PicoSentry for this project.")
    return 0


__all__ = ["NAME", "add_arguments", "cmd"]
