from __future__ import annotations

import argparse
import os
import sys
from typing import Any

from picosentry.sandbox.formatters.cyclonedx import format_cyclonedx
from picosentry.sandbox.formatters.github import format_github
from picosentry.sandbox.formatters.json_fmt import format_json, format_pipeline_json
from picosentry.sandbox.formatters.ml_context import format_ml_context
from picosentry.sandbox.formatters.sarif import format_sarif
from picosentry.sandbox.formatters.table import format_table
from picosentry.sandbox.l3.models import SandboxResult
from picosentry.sandbox.l4.models import AnalysisResult


_SEVERITY_LEVELS = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


_BAD_VERDICTS = {"DENY", "KILL", "MALICIOUS", "SUSPICIOUS"}


def _add_common_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--deterministic-output",
        "-D",
        action="store_true",
        help="Produce deterministic output (no timestamps, random IDs, or timing)",
    )
    parser.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit 1 on DENY/KILL/MALICIOUS/SUSPICIOUS verdict",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info"],
        help="Exit 1 if any finding at or above this severity",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress all output except exit code",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="One-line summary output",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output with full details",
    )
    parser.add_argument(
        "--log-format",
        choices=["text", "json"],
        default="text",
        help="Log output format (default: text)",
    )


def _auto_detect_policy(command: list[str]):
    from picosentry.sandbox.l3.policy import load_policy as _lp

    if not command:
        return None

    exe = command[0].split("/")[-1].lower() if command[0] else ""

    node_commands = {"npm", "npx", "node", "yarn", "pnpm", "bun"}
    python_commands = {"pip", "pip3", "python", "python3", "uv", "poetry", "pdm", "conda"}

    if exe in node_commands:
        return _lp(name="node")
    elif exe in python_commands:
        return _lp(name="python")
    return None


def _output(result: Any, args: argparse.Namespace) -> None:
    if args.summary:
        _output_summary(result)
        return

    fmt = args.format
    deterministic = args.deterministic_output

    if fmt == "json":
        print(format_json(result, deterministic=deterministic))
    elif fmt == "sarif":
        print(format_sarif(result))
    elif fmt == "ml-context":
        print(format_ml_context(result))
    elif fmt == "github":
        print(format_github(result))
    elif fmt == "cyclonedx":
        print(format_cyclonedx(result))
    else:  # table
        print(format_table(result))


def _output_summary(result: Any) -> None:
    if isinstance(result, SandboxResult):
        verdict = result.overall_verdict.value
        events = len(result.events)
        cmd = " ".join(result.command)
        print(f"L3: {verdict} | {events} events | {cmd}")
    elif isinstance(result, AnalysisResult):
        verdict = result.overall_verdict.value
        findings = len(result.findings)
        print(f"L4: {verdict} | {findings} findings | {result.target}")


def _output_summary_pipeline(sandbox: SandboxResult, analysis: AnalysisResult) -> None:
    l3_verdict = sandbox.overall_verdict.value
    l4_verdict = analysis.overall_verdict.value
    events = len(sandbox.events)
    findings = len(analysis.findings)
    cmd = " ".join(sandbox.command)
    print(f"L3: {l3_verdict} ({events} events) → L4: {l4_verdict} ({findings} findings) | {cmd}")


def _compute_exit_code_sandbox(result: SandboxResult, args: argparse.Namespace) -> int:

    if args.exit_code and result.overall_verdict.value in _BAD_VERDICTS:
        return 1


    if args.fail_on:
        _SEVERITY_LEVELS.get(args.fail_on, 99)

        if result.overall_verdict.value in ("DENY", "KILL"):
            return 1


    return 0 if result.overall_verdict.value == "ALLOW" else 1


def _compute_exit_code_analysis(result: AnalysisResult, args: argparse.Namespace) -> int:

    if args.exit_code and result.overall_verdict.value in _BAD_VERDICTS:
        return 1


    if args.fail_on:
        threshold = _SEVERITY_LEVELS.get(args.fail_on, 99)
        for f in result.findings:
            finding_level = _SEVERITY_LEVELS.get(f.severity.value.lower(), 99)
            if finding_level <= threshold:
                return 1


    return 0 if result.overall_verdict.value == "CLEAN" else 1


def _compute_exit_code_pipeline(
    sandbox: SandboxResult, analysis: AnalysisResult, args: argparse.Namespace
) -> int:

    if args.exit_code and analysis.overall_verdict.value in _BAD_VERDICTS:
        return 1

    if args.fail_on:
        threshold = _SEVERITY_LEVELS.get(args.fail_on, 99)
        for f in analysis.findings:
            finding_level = _SEVERITY_LEVELS.get(f.severity.value.lower(), 99)
            if finding_level <= threshold:
                return 1


    return 0 if analysis.overall_verdict.value == "CLEAN" else 1


def _resolve_signing_key(args: argparse.Namespace) -> bytes | None:
    if hasattr(args, "key") and args.key:
        try:
            return bytes.fromhex(args.key)
        except ValueError:
            print("Error: --key must be hex-encoded", file=sys.stderr)
            return None

    if hasattr(args, "key_file") and args.key_file:
        if not args.key_file.is_file():
            print(f"Error: key file not found: {args.key_file}", file=sys.stderr)
            return None
        try:
            return bytes.fromhex(args.key_file.read_text().strip())
        except ValueError:
            print("Error: key file must contain hex-encoded key", file=sys.stderr)
            return None


    from picosentry.sandbox.policy_versioned.signing import _load_key

    key = _load_key()
    if key is None:
        print("Error: no signing key provided. Use --key, --key-file, or set PICODOME_POLICY_KEY", file=sys.stderr)
        return None

    return key


__all__ = [
    "_add_common_flags",
    "_auto_detect_policy",
    "_compute_exit_code_analysis",
    "_compute_exit_code_pipeline",
    "_compute_exit_code_sandbox",
    "_output",
    "_output_summary",
    "_output_summary_pipeline",
    "_resolve_signing_key",
]
