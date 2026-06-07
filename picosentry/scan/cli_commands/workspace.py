"""`workspace` subcommand — scan a monorepo/workspace for all npm projects.

Extracted in v2.1.0 (refactor) from the monolithic ``picosentry/scan/cli.py``.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from picosentry.scan.config import load_config
from picosentry.scan.engine import create_default_engine
from picosentry.scan.workspace import scan_workspace

NAME = "workspace"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="Scan entire monorepo/workspace for all npm projects")
    parser.add_argument("root", type=str, nargs="?", default=".", help="Root of monorepo (default: .)")
    parser.add_argument(
        "--format",
        "-f",
        choices=["json", "table", "summary"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument("--output", "-o", type=str, default=None, help="Write results to file")
    parser.add_argument("--rules", "-r", nargs="+", default=None, help="Run only specific rules")
    parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default="medium",
        help="Minimum severity to fail CI (default: medium)",
    )
    parser.add_argument("--timeout", type=int, default=0, help="Per-project timeout in seconds")
    parser.add_argument("--max-depth", type=int, default=8, help="Max directory depth for discovery")
    parser.add_argument("--quiet", "-q", action="store_true", help="Summary only")
    parser.add_argument("--advisory-db", type=str, default=None, help="Path to OSV-format advisory database")


def cmd(args: argparse.Namespace) -> int:
    """Scan an entire monorepo workspace."""
    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"Error: {root} is not a directory", file=sys.stderr)
        return 2

    if not args.quiet:
        if args.format == "json":
            print(f"Scanning workspace: {root}", file=sys.stderr)
            print("Discovering projects...", file=sys.stderr)
        else:
            print(f"Scanning workspace: {root}")
            print("Discovering projects...")

    from picosentry.scan.workspace import discover_pnpm_workspace, discover_projects

    projects = discover_pnpm_workspace(root)
    if not projects:
        projects = discover_projects(root, max_depth=args.max_depth)

    if not projects:
        print("No npm/pnpm projects found in workspace.")
        return 1

    if args.format == "json" and not args.quiet:
        print(f"Found {len(projects)} project(s)", file=sys.stderr)
    elif not args.quiet:
        print(f"Found {len(projects)} project(s)")

    advisory_db = getattr(args, "advisory_db", None)
    engine = create_default_engine(advisory_db_path=advisory_db)
    config = load_config(root)

    wr = scan_workspace(
        root,
        engine=engine,
        config=config,
        rules=args.rules,
        fail_on=args.fail_on,
        timeout=args.timeout,
    )

    if args.format == "json":
        data = {
            "workspace_root": str(root),
            "summary": wr.to_dict(),
            "projects": wr.results,
        }
        output = json.dumps(data, indent=2, sort_keys=True)
    elif args.format == "summary" or args.quiet:
        output = (
            f"Workspace: {wr.scanned_projects}/{wr.total_projects} projects, "
            f"{wr.total_findings} findings, {wr.failed_projects} failed ({wr.duration_ms}ms)"
        )
    else:
        lines = ["PicoSentry Workspace Scan"]
        lines.append(f"Root: {root}")
        lines.append(
            f"Projects: {wr.total_projects} discovered, {wr.scanned_projects} scanned, {wr.failed_projects} failed"
        )
        lines.append(f"Total findings: {wr.total_findings} | Duration: {wr.duration_ms}ms")
        lines.append("")
        header = "{:<45s} {:>8s}  {:<12s}".format("Project", "Findings", "Status")
        lines.append(header)
        lines.append("-" * 67)
        for proj_path in sorted(wr.results.keys()):
            result: Any = wr.results[proj_path]
            findings = len(result.get("findings", []))
            status = "OK" if findings == 0 else f"{findings} finding(s)"
            proj_name = str(Path(proj_path).name) if "/" in proj_path else proj_path
            lines.append(f"{proj_name[:45]:<45s} {findings:>8d}  {status:<12s}")
        if wr.errors:
            lines.append("")
            lines.append("Errors:")
            for err in wr.errors:
                lines.append(f"  * {err}")
        output = "\n".join(lines)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Output written to {args.output}")
    else:
        print(output)

    if wr.failed_projects > 0:
        return 2

    if args.fail_on:
        severity_order = __import__("picosentry.scan.models", fromlist=["SEVERITY_ORDER"]).SEVERITY_ORDER
        min_level = severity_order[args.fail_on.lower()]
        all_findings: list[dict] = []
        for proj_result in wr.results.values():
            proj_result_typed: Any = proj_result
            all_findings.extend(proj_result_typed.get("findings", []))
        has_fail_findings = any(
            severity_order.get(f.get("severity", "info").lower(), 4) <= min_level for f in all_findings
        )
        return 1 if has_fail_findings else 0
    return 1 if wr.total_findings > 0 else 0


# Back-compat alias for the historic name in the monolithic cli.py.
_cmd_workspace = cmd

__all__ = ["NAME", "_cmd_workspace", "add_arguments", "cmd"]
