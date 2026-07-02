from __future__ import annotations

import argparse
import sys
from pathlib import Path

from picosentry.scan.engine import create_default_engine

NAME = "check"


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(NAME, help="Quick health check for CI (exit-code only)")
    parser.add_argument("target", type=str, nargs="?", default=".", help="Path to project directory (default: .)")
    parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default="medium",
        help="Minimum severity to fail on (default: medium)",
    )
    parser.add_argument("--rules", "-r", nargs="+", default=None, help="Run only specific rules")
    parser.add_argument(
        "--fail-on-rule-error",
        action="store_true",
        help="Exit with code 4 if any detector rule raises an exception. Implied by --enterprise.",
    )
    parser.add_argument("--enterprise", action="store_true", help="Enable enterprise mode.")
    parser.add_argument("--advisory-db", type=str, default=None, help="Path to OSV-format advisory database")
    parser.add_argument(
        "--check-corpus-age",
        type=int,
        nargs="?",
        const=30,
        default=None,
        metavar="DAYS",
        help="Exit with code 5 if the corpus is older than DAYS (default: 30).",
    )


def cmd(args: argparse.Namespace) -> int:
    target = Path(args.target).resolve()

    if not target.exists():
        print(f"picosentry check: target not found: {target}", file=sys.stderr)
        return 2

    advisory_db = getattr(args, "advisory_db", None)
    engine = create_default_engine(advisory_db_path=advisory_db)

    corpus_age_days = getattr(args, "check_corpus_age", None)
    if corpus_age_days is not None:
        is_stale, stale = engine.is_corpus_stale(max_age_days=corpus_age_days)
        if is_stale:
            print(
                f"picosentry check: corpus is stale "
                f"(older than {corpus_age_days} day(s); stale ecosystems: {', '.join(stale) or 'unknown'})",
                file=sys.stderr,
            )
            return 5

    result = engine.scan(str(target), rules=args.rules, advisory_db_path=advisory_db)

    from picosentry.scan.models import SEVERITY_ORDER

    severity_order = dict(SEVERITY_ORDER)
    fail_level = severity_order[args.fail_on.lower()]

    failed_rules = [r for r in result.rule_executions if r.status == "failed"]
    if failed_rules:
        for r in failed_rules:
            print(f"Rule {r.rule_id} FAILED: {r.error}", file=sys.stderr)
        return 4

    violations = [f for f in result.findings if severity_order.get(f.severity.value.lower(), 4) <= fail_level]

    if violations:
        sev_counts: dict[str, int] = {}
        for f in violations:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
        summary = ", ".join(f"{c} {s}" for s, c in sorted(sev_counts.items()))
        print(f"picosentry check: {len(violations)} finding(s) at {args.fail_on}+ ({summary})", file=sys.stderr)
        return 1

    return 0


__all__ = ["NAME", "add_arguments", "cmd"]
