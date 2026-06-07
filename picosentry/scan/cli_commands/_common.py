"""Shared argparse helpers and constants for the cli_commands subpackage.

Kept intentionally small — only the most-duplicated argument patterns
get extracted here. Per-subcommand bespoke args stay in each module.
"""
from __future__ import annotations

import argparse
import logging

logger = logging.getLogger(__name__)

NAME = ""  # placeholder; subcommand modules override


# Standard output format choices, used by `scan` and `workspace`.
OUTPUT_FORMAT_CHOICES = ["json", "sarif", "table", "ml-context", "github", "cyclonedx"]


def add_output_args(parser: argparse.ArgumentParser) -> None:
    """Add ``--format/-f`` and ``--output/-o`` to a subparser.

    Used by `scan`, `workspace`, and any other subcommand that writes a
    structured report to stdout or a file.
    """
    parser.add_argument(
        "--format",
        "-f",
        choices=OUTPUT_FORMAT_CHOICES,
        default=None,
        help="Output format (default: table). 'github' writes SARIF file + prints markdown summary.",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Write output to file instead of stdout",
    )


__all__ = ["NAME", "OUTPUT_FORMAT_CHOICES", "add_output_args"]
