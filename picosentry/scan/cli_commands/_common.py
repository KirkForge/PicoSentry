from __future__ import annotations

import argparse
import logging

logger = logging.getLogger(__name__)

NAME = ""  # placeholder; subcommand modules override


OUTPUT_FORMAT_CHOICES = ["json", "sarif", "table", "ml-context", "github", "cyclonedx"]


def add_output_args(parser: argparse.ArgumentParser) -> None:
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
