from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from picosentry.sandbox.cli_commands._common import (
    _add_common_flags,
    _compute_exit_code_analysis,
    _output,
)
from picosentry.sandbox.guards import (
    DeterministicGuard,
    validate_findings_deterministic,
)
from picosentry.sandbox.l4.engine import create_default_engine
from picosentry.sandbox.l4.profiler import profile_from_sandbox_result

NAME = "analyze"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="Run L4 behavioral analysis on L3 output")
    parser.add_argument("--input", "-i", type=Path, help="JSON file from 'picodome sandbox --format json'")
    parser.add_argument(
        "--format",
        "-f",
        choices=["json", "sarif", "table", "ml-context", "github", "cyclonedx"],
        default="table",
    )
    parser.add_argument("--rules", "-r", nargs="*", help="Specific rule IDs to run")
    _add_common_flags(parser)


def cmd(args: argparse.Namespace) -> int:
    if not args.input or not args.input.exists():
        print("Error: --input file required and must exist", file=sys.stderr)
        return 1

    with args.input.open() as f:
        data = json.load(f)

    from picosentry.sandbox.l3.models import SandboxEvent, Verdict

    events = [
        SandboxEvent(
            rule_id=e["rule_id"],
            verdict=Verdict(e["verdict"]),
            operation=e["operation"],
            detail=e["detail"],
            path=e.get("path", ""),
            address=e.get("address", ""),
        )
        for e in data.get("events", [])
    ]
    from picosentry.sandbox.l3.models import SandboxResult

    sandbox = SandboxResult(
        run_id=data.get("run_id", ""),
        command=data.get("command", []),
        overall_verdict=Verdict(data.get("overall_verdict", "ALLOW")),
        exit_code=data.get("exit_code", 0),
        duration_ms=data.get("duration_ms", 0),
        events=events,
        policy_name=data.get("policy_name", ""),
        stdout=data.get("stdout", ""),
        stderr=data.get("stderr", ""),
    )

    profile = profile_from_sandbox_result(sandbox)
    engine = create_default_engine()
    deterministic = args.deterministic_output
    result = engine.analyze(profile, rules=args.rules, deterministic=deterministic)

    if deterministic:
        guard = DeterministicGuard()
        violations = guard.check(result)
        if violations:
            for v in violations:
                print(f"DETERMINISM VIOLATION: {v}", file=sys.stderr)

        finding_violations = validate_findings_deterministic(result.findings)
        for v in finding_violations:
            print(f"DETERMINISM VIOLATION (findings): {v}", file=sys.stderr)

    if not args.quiet:
        _output(result, args)

    return _compute_exit_code_analysis(result, args)


__all__ = ["NAME", "add_arguments", "cmd"]
