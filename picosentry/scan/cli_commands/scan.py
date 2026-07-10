"""`picosentry scan` argument parsing and dispatch.

The actual orchestration logic lives in ``picosentry.scan.cli_service`` so that
this file stays focused on CLI wiring.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from picosentry.scan.cli_service import (
    ScanError,
    ScanOrchestrator,
    ScanTimeout,
    _format_quiet,
    _format_summary,
    _resolve_external_path,
    _run_scan,
    _scan_worker,
    _verify_determinism,
    _workspace_root,
)

NAME = "scan"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    scan_parser = subparsers.add_parser(NAME, help="Scan a project directory for supply chain risks")
    scan_parser.add_argument("target", type=str, help="Path to project directory to scan")
    scan_parser.add_argument(
        "--format",
        "-f",
        choices=["json", "sarif", "table", "ml-context", "github", "cyclonedx"],
        default=None,
        help="Output format (default: table). 'github' writes SARIF file + prints markdown summary.",
    )
    scan_parser.add_argument("--output", "-o", type=str, default=None, help="Write output to file instead of stdout")
    scan_parser.add_argument(
        "--rules",
        "-r",
        nargs="+",
        default=None,
        help="Run only specific rules (e.g., L2-POST-001 L2-OBFS-001)",
    )
    scan_parser.add_argument(
        "--corpus",
        "-c",
        type=str,
        default=None,
        help="Path to corpus directory (default: built-in)",
    )
    scan_parser.add_argument(
        "--advisory-db",
        type=str,
        default=None,
        help="Path to OSV-format advisory database for vulnerability checking",
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output (table format only)",
    )
    scan_parser.add_argument(
        "--token-budget",
        type=int,
        default=None,
        help="Token budget for ml-context format (default: 4096)",
    )
    scan_parser.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit with code 1 if findings found, 0 if clean",
    )
    scan_parser.add_argument(
        "--severity-threshold",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Minimum severity to include in output (default: show all)",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Exit with code 1 only if findings at or above this severity (implies --exit-code)",
    )
    scan_parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Only show summary line (findings count by severity). No detailed findings.",
    )
    scan_parser.add_argument(
        "--summary",
        action="store_true",
        help="One-line summary for CI notifications. Implies --quiet.",
    )
    scan_parser.add_argument(
        "--baseline",
        "-b",
        type=str,
        default=None,
        help="Path to baseline JSON file or ignore file. Known findings are suppressed.",
    )
    scan_parser.add_argument(
        "--baseline-update",
        action="store_true",
        help="Write updated baseline file (with new findings added) after filtering. Use with --baseline.",
    )
    scan_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show per-rule timing and detailed scan progress.",
    )
    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=0,
        help="Timeout in seconds for the entire scan (0 = no timeout). Exits with code 3 on timeout.",
    )
    scan_parser.add_argument(
        "--fail-on-rule-error",
        action="store_true",
        help="Exit with code 4 if any detector rule raises an exception. Fail-closed for CI. Implied by --enterprise.",
    )
    scan_parser.add_argument(
        "--enterprise",
        action="store_true",
        help="Enable enterprise mode. Equivalent to PICOSENTRY_ENTERPRISE_MODE=1.",
    )
    scan_parser.add_argument(
        "--policy",
        "-p",
        type=str,
        default=None,
        help="Path to .picosentry-policy.yml for enterprise policy enforcement",
    )
    scan_parser.add_argument(
        "--sarif-file",
        type=str,
        default=None,
        help="Path for SARIF output file when using --format github (default: sarif.json)",
    )
    scan_parser.add_argument(
        "--verify-determinism",
        action="store_true",
        help="Run scan twice and verify SHA-256 determinism. "
        "Exit 0 if identical, 4 if different. Implies --format json.",
    )
    scan_parser.add_argument(
        "--validate",
        action="store_true",
        help="Run the validation harness against built-in fixtures. Prints per-rule precision/recall; "
        "exit 0 if mean precision >= 0.95 and mean recall >= 0.80. "
        "Ignores <target> (the harness uses its own fixtures).",
    )
    scan_parser.add_argument(
        "--deterministic-output",
        action="store_true",
        help="Omit timestamps, timing, and audit metadata from output for byte-stable JSON.",
    )
    scan_parser.add_argument(
        "--offline",
        action="store_true",
        help="Run in offline mode (no network). Also enabled by PICOSENTRY_OFFLINE=1.",
    )


def cmd(args: argparse.Namespace) -> int:
    target = Path(args.target).resolve()
    if not target.exists():
        print(f"Error: target does not exist: {target}", file=sys.stderr)
        return 2

    orchestrator = ScanOrchestrator(args)

    if args.verify_determinism:
        args.deterministic_output = True
        return orchestrator.verify_determinism()

    if getattr(args, "validate", False):
        return orchestrator.run_validation()

    return orchestrator.run()


# Re-export orchestration helpers for backward-compatible tests and scripts.
__all__ = [
    "NAME",
    "ScanError",
    "ScanTimeout",
    "_format_quiet",
    "_format_summary",
    "_resolve_external_path",
    "_run_scan",
    "_scan_worker",
    "_verify_determinism",
    "_workspace_root",
    "add_arguments",
    "cmd",
]
